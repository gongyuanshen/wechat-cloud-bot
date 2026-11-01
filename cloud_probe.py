"""Read-only cloud WeChat diagnostics. No client connection, clicks or writes."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

TARGET_GROUP = "Example group"
PROBE_BUILD = "2026-11-01.4"
CURRENT_CHAT_TITLE_ID = ("content_view.top_content_view.title_h_view.left_v_view.left_content_v_view."
                         "left_ui_.big_title_line_h_view.current_chat_name_label")
MAX_UIA_DEPTH = 32
MAX_UIA_NODES = 2000


class WindowDiscoveryError(RuntimeError):
    def __init__(self, message: str, discovery: dict):
        super().__init__(message)
        self.discovery = discovery


def check_target_host(expected: str, actual: str) -> None:
    if not expected or expected.casefold() != actual.casefold():
        raise RuntimeError(f"Wrong host: expected {expected!r}, actual {actual!r}; native probe blocked")


def unique_window(windows: list[dict]) -> dict:
    if len(windows) != 1:
        raise RuntimeError(f"Expected one visible WeChat main window, found {len(windows)}: {windows!r}")
    return windows[0]


def sanitize_control(raw: dict, target_group: str) -> dict:
    name = raw["name"]
    identifier = raw["automation_id"]
    title_pattern = re.escape(target_group) + r"(?:\s*(?:\(\d+\)|（\d+）))?"
    target_name_matches = re.fullmatch(title_pattern, name) is not None
    return {
        key: raw[key] for key in (
            "automation_id", "control_type", "class_name", "bounds",
            "runtime_id", "depth", "parent_index",
        )
    } | {
        "name_length": len(name),
        "target_group_name_match": target_name_matches,
        "target_group_match": (identifier == CURRENT_CHAT_TITLE_ID and target_name_matches
                               and raw["control_type"] == "TextControl"
                               and raw["class_name"] == "mmui::XTextView"),
        "send_control": raw["control_type"] == "ButtonControl" and name in ("发送", "Send"),
    }


def ancestor_indices(records: list[dict], index: int):
    parent = records[index]["parent_index"]
    while parent is not None:
        yield parent
        parent = records[parent]["parent_index"]


def assess_controls(records: list[dict], target_group: str) -> dict:
    paths = [list(ancestor_indices(records, i)) for i in range(len(records))]
    titles = [i for i, r in enumerate(records) if r["target_group_match"]
              and any(records[a]["class_name"] == "mmui::ChatTitleBarChatRoomView" for a in paths[i])
              and any(records[a]["automation_id"] == "chat_message_page" for a in paths[i])]
    indices = {"target_group": titles, "message_list": [], "input_field": [], "send_control": []}
    if len(titles) == 1:
        page = next(a for a in paths[titles[0]] if records[a]["automation_id"] == "chat_message_page")
        for i, record in enumerate(records):
            if page not in paths[i]:
                continue
            if record["automation_id"] == "chat_message_list" and record["control_type"] == "ListControl":
                indices["message_list"].append(i)
            if record["automation_id"] == "chat_input_field" and record["control_type"] == "EditControl":
                indices["input_field"].append(i)
            if record["send_control"]:
                indices["send_control"].append(i)
    capabilities = {name: len(candidates) == 1 for name, candidates in indices.items()}
    missing = [name for name, present in capabilities.items() if not present]
    return {
        **capabilities, "target_group_name": target_group, "missing": missing, "control_indices": indices,
        "candidate_ready": not missing,
        "scope": "Control candidates only; message direction, new-message detection and delivery unverified",
    }


def error_details(exc: Exception) -> dict:
    details = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    if isinstance(exc, WindowDiscoveryError):
        details["discovery"] = exc.discovery
    return details


def _output_text(output: str | bytes | None) -> str:
    if output is None:
        return ""
    if isinstance(output, bytes):
        return output.decode("utf-8", errors="backslashreplace")
    return output


def run_child(stage: str, expected_host: str, target_group: str, timeout: float, *, message_token: str | None = None) -> dict:
    command = [sys.executable, "-X", "utf8", str(Path(__file__).resolve()),
               "--stage", stage, "--expected-host", expected_host, "--target-group", target_group]
    if message_token is not None:
        command.extend(["--message-token", message_token])
    stdout, stderr, returncode = "", "", None
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        stdout, stderr, returncode = result.stdout, result.stderr, result.returncode
        payload = json.loads(stdout)
        if not isinstance(payload, dict) or payload.get("status") not in ("ok", "failed"):
            raise RuntimeError(f"Invalid child report for {stage}; returncode={result.returncode}")
        if payload["status"] == "ok" and result.returncode != 0:
            raise RuntimeError(f"Child {stage} claimed success but exited {result.returncode}")
        payload["returncode"] = result.returncode
        payload["stderr"] = stderr
        return payload
    except Exception as exc:
        if isinstance(exc, subprocess.TimeoutExpired):
            stdout, stderr = _output_text(exc.stdout), _output_text(exc.stderr)
        return {"status": "failed", "error": error_details(exc),
                "stdout": stdout, "stderr": stderr, "returncode": returncode}


def _session_id(pid: int) -> int:
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel.ProcessIdToSessionId
    query.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    session = wintypes.DWORD()
    if not query(pid, ctypes.byref(session)):
        raise ctypes.WinError(ctypes.get_last_error())
    return session.value


def _file_version(path: str) -> str:
    import win32api

    info = win32api.GetFileVersionInfo(path, "\\")
    ms, ls = info["FileVersionMS"], info["FileVersionLS"]
    return ".".join(str(value) for value in (ms >> 16, ms & 65535, ls >> 16, ls & 65535))


def _desktop_context() -> dict:
    from ctypes import wintypes

    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentThreadId.argtypes = []
    kernel.GetCurrentThreadId.restype = wintypes.DWORD
    user.GetProcessWindowStation.argtypes = []
    user.GetProcessWindowStation.restype = wintypes.HANDLE
    user.GetThreadDesktop.argtypes = [wintypes.DWORD]
    user.GetThreadDesktop.restype = wintypes.HANDLE
    query = user.GetUserObjectInformationW
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    station = user.GetProcessWindowStation()
    if not station:
        raise ctypes.WinError(ctypes.get_last_error())
    desktop = user.GetThreadDesktop(kernel.GetCurrentThreadId())
    if not desktop:
        raise ctypes.WinError(ctypes.get_last_error())
    handles = {"window_station": station, "thread_desktop": desktop}
    names = {}
    # Both handles are borrowed; Microsoft explicitly says not to close them.
    for key, handle in handles.items():
        buffer = ctypes.create_unicode_buffer(1024)
        needed = wintypes.DWORD()
        if not query(handle, 2, ctypes.byref(buffer), ctypes.sizeof(buffer), ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        names[key] = buffer.value
    return names


def read_windows() -> dict:
    import win32api
    import win32gui
    import win32process

    if os.name != "nt" or sys.maxsize <= 2**32:
        raise RuntimeError("The cloud probe requires 64-bit Windows Python")
    discovery = {
        "enumerated_count": 0, "visible_count": 0, "observed_windows": [],
        "main_title_filters": ["微信", "WeChat", "Weixin"],
        "native_modules": {"win32gui": win32gui.__file__, "win32process": win32process.__file__,
                           "win32api": win32api.__file__},
    }
    candidates = []
    try:
        current_session = _session_id(os.getpid())
        discovery.update(python_pid=os.getpid(), python_session_id=current_session,
                         desktop=_desktop_context())

        def visit(hwnd, _):
            discovery["enumerated_count"] += 1
            title = win32gui.GetWindowText(hwnd)
            cls = win32gui.GetClassName(hwnd)
            visible = bool(win32gui.IsWindowVisible(hwnd))
            title_matches = title in ("微信", "WeChat", "Weixin")
            class_matches = cls.startswith("Qt") or "WeChat" in cls
            if visible:
                discovery["visible_count"] += 1
            if not visible and not title_matches and not class_matches:
                return
            record = {"hwnd": hwnd, "class_name": cls, "visible": visible,
                      "known_main_title": title if title_matches else None,
                      "title_length": len(title)}
            discovery["observed_windows"].append(record)
            if not visible:
                record["rejection"] = "not_visible"
                return
            if not title_matches:
                record["rejection"] = "title"
                return
            if not class_matches:
                record["rejection"] = "class"
                return
            bounds = list(win32gui.GetWindowRect(hwnd))
            record["bounds"] = bounds
            if bounds[2] <= bounds[0] or bounds[3] <= bounds[1]:
                record["rejection"] = "zero_area"
                return
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            record.update(pid=pid, minimized=bool(win32gui.IsIconic(hwnd)))
            candidates.append(record)

        win32gui.EnumWindows(visit, None)
        discovery["candidate_count"] = len(candidates)
        windows = []
        for candidate in candidates:
            # Query + read rights only; no write-memory, VM-operation or injection rights.
            handle = win32api.OpenProcess(0x0400 | 0x0010, False, candidate["pid"])
            try:
                image = win32process.GetModuleFileNameEx(handle, 0)
                candidate.update(image_path=image, image_basename=Path(image).name.casefold())
                if candidate["image_basename"] not in ("weixin.exe", "wechat.exe"):
                    candidate["rejection"] = "process_image"
                    continue
                modules = []
                for module in win32process.EnumProcessModules(handle):
                    path = win32process.GetModuleFileNameEx(handle, module)
                    if Path(path).name.casefold() == "weixin.dll":
                        modules.append({"path": path, "base": hex(module), "version": _file_version(path)})
                candidate.update(eligible=True)
                windows.append({**candidate, "version": _file_version(image),
                                "session_id": _session_id(candidate["pid"]), "weixin_modules": modules})
            finally:
                handle.Close()

        discovery["eligible_count"] = len(windows)
        window = unique_window(windows)
        if current_session != window["session_id"]:
            raise RuntimeError(f"Desktop session mismatch: Python={current_session}, WeChat={window['session_id']}")
        if not window["weixin_modules"]:
            raise RuntimeError(f"No loaded Weixin.dll found for PID={window['pid']}")
        return {"window": window, "python_session_id": current_session, "discovery": discovery}
    except Exception as exc:
        raise WindowDiscoveryError(str(exc), discovery) from exc


def read_message_trial(controls, records: list[dict], capabilities: dict, token: str, uia) -> dict:
    from cloud_uia_trial import read_patterns

    indices = capabilities["control_indices"]
    patterns = {role: read_patterns(controls[indices[role][0]], uia, export_text=False)
                for role in ("input_field", "send_control")}
    samples = {"IN": [], "OUT": []}
    for index, record in enumerate(records):
        if (record["parent_index"] != indices["message_list"][0]
                or record["control_type"] != "ListItemControl"
                or record["class_name"] not in ("mmui::ChatTextItemView", "mmui::ChatBubbleItemView")):
            continue
        name = controls[index].Name
        for role in samples:
            if re.search(r"(?<![A-Za-z0-9_])" + re.escape(token + "_" + role) + r"(?![A-Za-z0-9_])", name):
                samples[role].append({"control_index": index, "name": name,
                                      "runtime_id": record["runtime_id"], "class_name": record["class_name"],
                                      "bounds": record["bounds"],
                                      "patterns": read_patterns(controls[index], uia, export_text=True)})
    ready = (all(len(items) == 1 for items in samples.values())
             and samples["IN"][0]["control_index"] != samples["OUT"][0]["control_index"])
    return {"token": token, "samples": samples, "samples_ready": ready, "control_patterns": patterns,
            "scope": "Read-only synthetic samples; IN/OUT are manual preparation labels, not detected direction or sender"}


def read_uia(target_group: str, *, message_token: str | None = None) -> dict:
    # Set the apartment before importing wx4py/comtypes. Controls stay on this thread.
    sys.coinit_flags = 0
    from wx4py.core import uiautomation as uia

    data = read_windows()
    window = data["window"]
    if window["minimized"]:
        raise RuntimeError("WeChat is minimized; restore it manually before probing")
    uia.InitializeUIAutomationInCurrentThread()
    try:
        root = uia.ControlFromHandle(window["hwnd"])
        if root is None:
            raise RuntimeError("ControlFromHandle returned no root")
        records = []
        controls = []
        ancestors = {}
        limit_reached = False
        depth_limit_reached = False
        max_observed_depth = 0
        for index, (control, depth) in enumerate(uia.WalkControl(root, includeTop=True, maxDepth=MAX_UIA_DEPTH)):
            if index >= MAX_UIA_NODES:
                limit_reached = True
                break
            max_observed_depth = max(max_observed_depth, depth)
            if depth == MAX_UIA_DEPTH and control.GetFirstChildControl() is not None:
                depth_limit_reached = True
            rect = control.BoundingRectangle
            raw = {
                "automation_id": control.AutomationId, "control_type": control.ControlTypeName,
                "class_name": control.ClassName, "name": control.Name,
                "bounds": [rect.left, rect.top, rect.right, rect.bottom],
                "runtime_id": list(control.GetRuntimeId()), "depth": depth,
                "parent_index": ancestors[depth - 1] if depth else None,
            }
            records.append(sanitize_control(raw, target_group))
            controls.append(control)
            ancestors[depth] = index
        scan_complete = not limit_reached and not depth_limit_reached
        capabilities = assess_controls(records, target_group)
        capabilities["candidate_ready"] = capabilities["candidate_ready"] and scan_complete
        data.update({"controls": records, "node_count": len(records),
                     "node_limit_reached": limit_reached, "max_nodes": MAX_UIA_NODES,
                     "depth_limit_reached": depth_limit_reached, "max_depth": MAX_UIA_DEPTH,
                     "max_observed_depth": max_observed_depth, "scan_complete": scan_complete,
                     "capabilities": capabilities})
        if message_token is not None and capabilities["candidate_ready"]:
            data["message_trial"] = read_message_trial(controls, records, capabilities, message_token, uia)
        return data
    finally:
        uia.UninitializeUIAutomationInCurrentThread()


def save_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        shutil.copy2(path, path.with_name(f"{path.stem}.{stamp}.bak{path.suffix}"))
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-host", required=True)
    parser.add_argument("--target-group", default=TARGET_GROUP)
    parser.add_argument("--report", type=Path, default=Path(__file__).with_name("probe_report.json"))
    parser.add_argument("--stage", choices=("windows", "uia"), help=argparse.SUPPRESS)
    parser.add_argument("--message-trial", action="store_true", help="Prepare two unique manual test messages, then read only matching samples")
    parser.add_argument("--message-token", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    report = {"schema_version": 4, "probe_build": PROBE_BUILD, "status": "failed", "scope": "read-only",
              "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "expected_host": args.expected_host, "actual_host": platform.node()}
    try:
        check_target_host(args.expected_host, report["actual_host"])
        if args.message_token is not None and (args.stage != "uia" or re.fullmatch(r"WXPROBE_[0-9a-f]{8}", args.message_token) is None):
            raise ValueError("Message token requires the UIA child stage and WXPROBE_<8 lowercase hex> format")
        if args.message_trial and args.stage:
            raise ValueError("Interactive message trial is only available in the parent process")
        script_path = Path(__file__).resolve()
        report["probe_source"] = {"path": str(script_path),
                                  "sha256": hashlib.sha256(script_path.read_bytes()).hexdigest(),
                                  "dependencies": {"cloud_uia_trial.py": hashlib.sha256(
                                      script_path.with_name("cloud_uia_trial.py").read_bytes()).hexdigest()}}
        if args.stage:
            # Dependency diagnostics go to stderr; stdout is the JSON protocol.
            with contextlib.redirect_stdout(sys.stderr):
                data = (read_windows() if args.stage == "windows" else
                        read_uia(args.target_group, message_token=args.message_token))
            report.update(status="ok", data=data)
            if args.stage == "uia":
                if not data["scan_complete"]:
                    report.update(status="failed", error={"type": "IncompleteTraversal",
                                  "message": "UIA traversal reached a node or depth limit; inspect the partial structure"})
                elif not data["capabilities"]["candidate_ready"]:
                    report.update(status="failed", error={"type": "MissingCapabilities",
                                  "message": f"Missing controls: {data['capabilities']['missing']}"})
                elif args.message_token is not None and not data["message_trial"]["samples_ready"]:
                    report.update(status="failed", error={"type": "MissingOrAmbiguousTestMessages",
                                  "message": "Expected one distinct IN bubble and one OUT bubble for this token; inspect message_trial.samples"})
        else:
            print(f"Probe build: {PROBE_BUILD}", flush=True)
            report["environment"] = {"python": sys.version, "python_path": sys.executable,
                                     "system": platform.platform(), "packages": {}}
            for package in ("wx4py", "pywin32", "comtypes"):
                try:
                    report["environment"]["packages"][package] = importlib.metadata.version(package)
                except importlib.metadata.PackageNotFoundError:
                    report["environment"]["packages"][package] = {"status": "missing"}
            print("[1/2] Reading WeChat process and desktop session (15-second limit)...", flush=True)
            report["windows"] = run_child("windows", args.expected_host, args.target_group, 15)
            if report["windows"]["status"] == "ok":
                token = None
                if args.message_trial:
                    token = "WXPROBE_" + secrets.token_hex(4)
                    report["message_token"] = token
                    print(f"保持云端微信打开群：{args.target_group}", flush=True)
                    print(f"1. 用手机上的其他账号在该群发：@~ {token}_IN", flush=True)
                    print(f"2. 用云端微信账号在该群手动发：{token}_OUT", flush=True)
                    print("只导出这两条测试气泡；不会自动发送或调用模型。", flush=True)
                    input("两条消息均已发送且在云端群内可见后，回到这里按 Enter 开始采集：")
                print("[2/2] Reading UIA control structure (30-second limit)...", flush=True)
                report["uia"] = run_child("uia", args.expected_host, args.target_group, 30, message_token=token)
                if report["uia"]["status"] == "ok":
                    report["status"] = "ok"
            else:
                report["uia"] = {"status": "skipped", "reason": "Window/process stage failed"}
    except Exception as exc:
        report["error"] = error_details(exc)

    code = 0 if report["status"] == "ok" else 1
    if args.stage:
        print(json.dumps(report, ensure_ascii=False))
        return code
    for name in ("error", "windows", "uia"):
        section = report.get(name, {})
        error = section if name == "error" else section.get("error", {})
        if error:
            print(f"{name}: {error['type']}: {error['message']}", flush=True)
    try:
        save_report(args.report.resolve(), report)
    except Exception:
        traceback.print_exc()
        print("FAILED: report could not be saved", flush=True)
        return 1
    print(f"Result: {report['status'].upper()} (diagnostics only, not a messaging test)", flush=True)
    print(f"Report: {args.report.resolve()}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
