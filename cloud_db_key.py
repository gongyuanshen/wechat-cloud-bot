"""Recover and verify the guarded cloud WeChat process's database key in memory."""

import importlib
import math
from pathlib import Path
import time


def recover_verified_key(window: dict, databases: dict[str, Path], *, timeout_seconds=120.0) -> bytes:
    """Caller must enforce the cloud host guard before invoking this native boundary."""
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("Database key timeout must be finite positive seconds")
    deadline = time.monotonic() + timeout_seconds

    def remaining():
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("Cloud database key recovery timed out")
        return seconds

    modules = window["weixin_modules"]
    if len(modules) != 1:
        raise RuntimeError(f"Expected exactly one loaded Weixin.dll, found {len(modules)}")
    module = modules[0]
    pages = {}
    for role in ("session", "contact", "message"):
        remaining()
        with databases[role].open("rb") as source:
            page = source.read(4096)
        if len(page) != 4096 or page.startswith(b"SQLite format 3\0"):
            raise ValueError(f"{role} key verification requires an encrypted complete 4096-byte page")
        pages[role] = page

    key_v4 = importlib.import_module("vendor.xwechat.key_v4")
    scanner = importlib.import_module("vendor.xwechat.dll_key_scan")
    remaining()
    # The caller's worker timeout interrupts a blocked native call; never accept an over-budget result.
    matches = scanner.extract_xor_keys_from_dll(module["path"], max_workers=1)
    remaining()
    if not matches:
        raise RuntimeError(f"Unsupported Weixin.dll version {module['version']}: no supported DLL key signature")

    seen_masks = set()
    for match in matches:
        mask = bytes.fromhex(match["key_hex"])
        if len(mask) != 32:
            raise ValueError("DLL signature did not yield a 32-byte internal key")
        if mask in seen_masks:
            continue
        seen_masks.add(mask)
        raw_hex = key_v4.recover_key(
            window["pid"], databases["session"], mask, timeout_seconds=remaining()
        )
        remaining()
        if raw_hex is None:
            continue
        raw = bytes.fromhex(raw_hex)
        if len(raw) != 32:
            raise ValueError("Memory recovery did not yield a 32-byte raw key")
        candidate = key_v4.xor_raw_key(raw, mask)
        for role, page in pages.items():
            remaining()
            verified = key_v4.is_ok(candidate, page)
            remaining()
            if not verified:
                raise RuntimeError(f"{role} database HMAC verification failed for the recovered key")
        return candidate

    raise RuntimeError("No database key passed encrypted-page HMAC verification")
