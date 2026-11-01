"""Guarded cloud entry and supervisor. This module imports no native/runtime code."""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout
import json
import logging
import math
import os
from pathlib import Path
import platform
import queue
import struct
import subprocess
import sys
import threading
import time
import uuid

def load_deployment(path: Path) -> dict:
    deployment = json.loads(path.read_text(encoding='utf-8-sig'))
    required = {'expected_host', 'account', 'self_id', 'group_id', 'group_name',
                'data_root', 'maas_base'}
    if not isinstance(deployment, dict) or set(deployment) != required:
        raise ValueError('Deployment config must contain exactly the fields in cloud-deployment.example.json')
    if any(not isinstance(value, str) or not value.strip() or value != value.strip()
           for value in deployment.values()):
        raise ValueError('Deployment config fields must be nonempty strings without outer whitespace')
    if not Path(deployment['data_root']).is_absolute():
        raise ValueError('Deployment data_root must be an absolute path')
    return deployment


BUILD = '2026-11-01.bot7'
_deployment = load_deployment(Path(__file__).with_name('cloud-deployment.private.json'))
EXPECTED_HOST = _deployment['expected_host']
ACCOUNT = _deployment['account']
SELF_ID = _deployment['self_id']
GROUP_ID = _deployment['group_id']
GROUP_NAME = _deployment['group_name']
DATA_ROOT = Path(_deployment['data_root'])
MAAS_BASE = _deployment['maas_base']
PUBLIC_FIELDS = {'state', 'account', 'group', 'model', 'completed', 'needs_review',
                 'last_attempt_id', 'error_code', 'last_outgoing'}
FRAME_FIELDS = PUBLIC_FIELDS | {'build', 'worker_pid', 'heartbeat', 'operations'}


def check_environment() -> None:
    if platform.node().casefold() != EXPECTED_HOST.casefold():
        raise RuntimeError(f'Wrong host: expected {EXPECTED_HOST}; native bot blocked')
    if (platform.python_implementation() != 'CPython'
            or sys.version_info[:2] != (3, 11) or struct.calcsize('P') != 8):
        raise RuntimeError('Requires CPython3.11 x64')


def load_config(path: Path) -> dict:
    config = json.loads(path.read_text(encoding='utf-8-sig'))
    required = {'api_key', 'base_url', 'model', 'system_prompt'}
    if not isinstance(config, dict) or set(config) != required:
        raise ValueError('Private config must contain only api_key, base_url, model and system_prompt')
    if any(not isinstance(config[key], str) for key in required):
        raise ValueError('Private config fields must be strings')
    if any(not config[key].strip() or config[key] != config[key].strip()
           for key in ('api_key', 'base_url', 'model')):
        raise ValueError('Private config requires nonempty API credentials, endpoint and exact model')
    return config


def load_settings(path: Path) -> dict:
    settings = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(settings, dict) or set(settings) != {'mention_name'}:
        raise ValueError('bot-settings.json must contain only mention_name')
    name = settings['mention_name']
    if (not isinstance(name, str) or not name.strip() or name != name.strip() or '@' in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise ValueError('mention_name requires a nonempty name without @, outer whitespace or control characters')
    return settings


class ActivityRegistry:
    def __init__(self, sink):
        self.sink, self.lock = sink, threading.RLock()
        self.values = {'state': 'starting'}
        self.operations = {}
        self.emit()

    def emit(self):
        with self.lock:
            self.sink({'build': BUILD, 'worker_pid': os.getpid(), 'heartbeat': time.monotonic(),
                       'operations': list(self.operations.values()), **self.values})

    def update(self, **values):
        if values.keys() - PUBLIC_FIELDS:
            raise ValueError('Only public runner metadata can enter status')
        with self.lock:
            self.values.update(values)
            self.emit()

    @contextmanager
    def operation(self, name, timeout_seconds):
        token = uuid.uuid4().hex
        with self.lock:
            self.operations[token] = {'name': name, 'started': time.monotonic(), 'timeout': timeout_seconds}
            self.emit()
        try:
            yield
        finally:
            with self.lock:
                del self.operations[token]
                self.emit()


def _write_status(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def _validate_frame(payload, pid):
    if (not isinstance(payload, dict) or payload.keys() - FRAME_FIELDS
            or payload.get('worker_pid') != pid
            or not isinstance(payload.get('operations'), list)
            or type(payload.get('heartbeat')) not in (float, int)
            or not math.isfinite(payload['heartbeat']) or payload['heartbeat'] < 0):
        raise ValueError('Invalid worker metadata protocol')
    for operation in payload['operations']:
        if (not isinstance(operation, dict) or operation.keys() != {'name', 'started', 'timeout'}
                or not isinstance(operation['name'], str) or not operation['name']
                or any(type(operation[key]) not in (float, int) or not math.isfinite(operation[key])
                       for key in ('started', 'timeout'))
                or operation['started'] < 0 or operation['timeout'] <= 0):
            raise ValueError('Invalid worker operation metadata')


def supervise(command, status_path: Path, *, startup_timeout=60.0, heartbeat_timeout=30.0) -> int:
    if command[0] != sys.executable:
        raise ValueError('Supervisor accepts only this runtime interpreter')
    # CPython's Windows venv redirector would create an unowned grandchild.
    environment = os.environ.copy()
    environment['__PYVENV_LAUNCHER__'] = sys.executable
    child = subprocess.Popen([sys._base_executable, *command[1:]], env=environment,
                             stdout=subprocess.PIPE, text=True, encoding='utf-8', bufsize=1)
    events = queue.Queue()
    eof = object()

    def receive():
        try:
            for line in child.stdout:
                payload = json.loads(line)
                _validate_frame(payload, child.pid)
                events.put(payload)
        except Exception as exc:
            events.put(exc)
        finally:
            events.put(eof)

    reader = threading.Thread(target=receive, daemon=True)
    reader.start()
    started = time.monotonic()
    latest = {'build': BUILD, 'worker_pid': child.pid, 'state': 'starting', 'automatic_restart': False}
    failure = None
    stream_closed = False

    def consume(item):
        nonlocal failure, stream_closed
        if isinstance(item, Exception):
            if failure is None:
                failure = {'error_code': 'CLOUD_WORKER_PROTOCOL'}
        elif item is eof:
            stream_closed = True
        else:
            latest.update(item)
            _write_status(status_path, latest)

    try:
        while True:
            try:
                consume(events.get(timeout=.2))
            except queue.Empty:
                pass
            while not events.empty():
                consume(events.get_nowait())
            if failure is not None:
                break
            now = time.monotonic()
            overdue = next((op for op in latest.get('operations', [])
                            if now - op['started'] > op['timeout']), None)
            if overdue:
                failure = {'error_code': 'CLOUD_OPERATION_TIMEOUT', 'failed_operation': overdue['name']}
                break
            heartbeat = latest.get('heartbeat')
            if (heartbeat is None and now - started > startup_timeout
                    or heartbeat is not None and now - heartbeat > heartbeat_timeout):
                failure = {'error_code': 'CLOUD_HEARTBEAT_TIMEOUT'}
                break
            code = child.poll()
            if code is not None and stream_closed and events.empty():
                break
    except KeyboardInterrupt:
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            failure = {'error_code': 'CLOUD_STOP_TIMEOUT'}
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        reader.join(timeout=1)
        child.stdout.close()
    while not events.empty():
        consume(events.get_nowait())
    latest.update(worker_exit_code=child.returncode, automatic_restart=False)
    if failure is not None:
        latest.update(state='failed', **failure)
        result = 1
    elif child.returncode != 0 or latest.get('state') not in {'stopped', 'off', 'needs_review'}:
        latest.update(state='failed', error_code=latest.get('error_code') or 'CLOUD_WORKER_EXIT')
        result = child.returncode or 1
    else:
        result = 0
    _write_status(status_path, latest)
    if result:
        print(f"FAILED: {latest['error_code']}; worker stopped, no automatic restart or resend.", file=sys.stderr)
    return result


def worker(config_path, runtime_root):
    import asyncio
    output = sys.stdout
    registry = ActivityRegistry(lambda value: print(json.dumps(value, ensure_ascii=False), file=output, flush=True))
    stop = threading.Event()

    def heartbeat():
        while not stop.wait(.5):
            registry.emit()

    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        with redirect_stdout(sys.stderr):
            config = {**load_config(config_path), **load_settings(config_path.with_name('bot-settings.json'))}
            logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
            with registry.operation('runtime_import', 60):
                from cloud_bot_runtime import run_worker
            asyncio.run(run_worker(config, runtime_root, registry))
        return 0
    except KeyboardInterrupt:
        registry.update(state='stopped')
        return 0
    except Exception as exc:
        registry.update(state='failed', error_code=getattr(exc, 'code', type(exc).__name__))
        logging.exception('Cloud worker failed; no automatic resend')
        return 1
    finally:
        stop.set()
        thread.join(timeout=1)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        check_environment()
        root = Path(__file__).resolve().parent
        runtime_root = root / 'runtime'
        config_path = root / 'cloud-bot.private.json'
        if args.worker:
            return worker(config_path, runtime_root)
        import msvcrt
        runtime_root.mkdir(exist_ok=True)
        with (runtime_root / 'runner.lock').open('a+b') as lock:
            lock.seek(0)
            if lock.read(1) == b'':
                lock.write(b'0')
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            print(f'Cloud bot build: {BUILD}', flush=True)
            return supervise([sys.executable, '-X', 'utf8', str(Path(__file__).resolve()), '--worker'],
                             runtime_root / 'bot-status.json')
    except Exception as exc:
        print(f'FAILED: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
