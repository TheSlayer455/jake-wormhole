"""Dedicated bounded capture for the fixed stock-inventory helper command.

The old stage executor and its 64 KiB contract are unchanged. No public function
accepts argv, an endpoint or a source path. A timeout remains an uncertain exec.
"""
import base64
import math
import os
import re
import signal
import subprocess
import time

from . import images
from .runs import RunError, SOURCE_ROOT
from fleet_inventory import runtime

LIMIT = 262144


def _capture(arguments, *, timeout):
    """Private fixed-adapter engine; tests may use credential-free local leaves."""
    environment = {key: os.environ[key] for key in ('PATH',) if key in os.environ}
    environment['PYTHONIOENCODING'] = 'utf-8'
    began = time.monotonic()
    try:
        process = subprocess.Popen(arguments, cwd=SOURCE_ROOT, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, start_new_session=True, bufsize=0)
    except OSError:
        return {'status': 'error', 'returncode': None, 'duration_seconds': time.monotonic() - began,
                'log': b'', 'log_truncated': False}
    result, seen, eof, timed_out, failed = bytearray(), 0, False, False, False
    deadline = began + timeout

    def terminate():
        try: os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait(timeout=5)

    try:
        fd = process.stdout.fileno(); os.set_blocking(fd, False)
        while True:
            try:
                chunk = os.read(fd, 4096)
                if chunk:
                    seen += len(chunk); result.extend(chunk[:max(0, LIMIT - len(result))])
                else: eof = True
            except BlockingIOError: chunk = None
            if time.monotonic() >= deadline:
                timed_out = True; terminate(); break
            if process.poll() is not None and eof: break
            if not chunk: time.sleep(min(.005, max(0, deadline - time.monotonic())))
        try: os.killpg(process.pid, 0)
        except ProcessLookupError: pass
        else:
            failed = not timed_out; terminate()
    except (OSError, subprocess.SubprocessError):
        failed = True; terminate()
    finally:
        process.stdout.close()
    status = 'timeout' if timed_out else 'error' if failed else 'pass' if process.returncode == 0 else 'fail'
    return {'status': status, 'returncode': process.returncode, 'duration_seconds': time.monotonic() - began,
            'log': bytes(result), 'log_truncated': seen > LIMIT}


def capture_inventory(helper_id, encoded_request, *, timeout):
    """Only the exact existing helper and fixed readonly inventory program."""
    if (os.name != 'posix' or type(helper_id) is not str or not re.fullmatch('[a-f0-9]{64}', helper_id) or
            type(encoded_request) is not str or len(encoded_request) > 11000 or
            type(timeout) not in (int, float) or not math.isfinite(timeout) or not .1 <= timeout <= 27):
        raise RunError('fleet_inventory_capture_scope', 'The fixed inventory adapter requires bounded Linux input.')
    try: runtime.decode(base64.b64decode(encoded_request, validate=True))
    except Exception:
        raise RunError('fleet_inventory_capture_scope', 'The fixed inventory request is malformed.') from None
    return _capture(('docker', '--config', images.docker_configuration(), '--host', images.SOCKET,
        'exec', '--user', '10001:10001', helper_id, '/opt/wormhole/venv/bin/python', '-I', '-B',
        '/opt/wormhole/fleet-inventory.py', encoded_request), timeout=timeout)
