#!/bin/sh
# CI-only: grant this runner the KVM group, without root guests or world permissions.
set -eu
if [ ! -c /dev/kvm ]; then
  echo 'KVM is not exposed on this runner; the appliance CI requires a KVM-capable host.' >&2
  exit 1
fi
sudo usermod -a -G kvm "$(id -un)"
sudo -u "$(id -un)" -g kvm -- python3 -I - <<'PY'
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

require(os.access('/dev/kvm', os.R_OK | os.W_OK), 'runner cannot access KVM')
# Confirm QMP reports an initialized KVM CPU before sending quit. Sending quit
# immediately on stdin can exit before accelerator initialization is checked.
with tempfile.TemporaryDirectory(prefix='regalia-kvm-', dir='/tmp') as directory:
    monitor = Path(directory) / 'qmp.sock'
    process = subprocess.Popen(['qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-cpu', 'host',
                                '-m', '128', '-nodefaults', '-display', 'none', '-S',
                                '-qmp', f'unix:{monitor},server=on,wait=off'], stdout=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            while True:
                if process.poll() is not None:
                    raise RuntimeError('QEMU exited before KVM initialization')
                try:
                    connection.connect(str(monitor))
                    break
                except (FileNotFoundError, ConnectionRefusedError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError('KVM initialization timed out')
                    time.sleep(.1)
            with connection.makefile('rwb') as stream:
                require('QMP' in json.loads(stream.readline(65536)), 'missing QMP greeting')
                def query(command):
                    stream.write(json.dumps({'execute': command}).encode() + b'\n')
                    stream.flush()
                    while True:
                        message = json.loads(stream.readline(65536))
                        if 'event' not in message:
                            require('error' not in message, 'QMP command failed')
                            return message['return']
                query('qmp_capabilities')
                status = query('query-kvm')
                require(status['enabled'] is True and status['present'] is True, 'KVM is not active')
                require(len(query('query-cpus-fast')) == 1, 'KVM CPU was not initialized')
                require(query('query-status')['status'] == 'prelaunch', 'empty machine is not paused')
                query('quit')
        require(process.wait(timeout=10) == 0, 'KVM preflight shutdown failed')
        print('KVM initialized CPU, paused-machine status and clean shutdown passed')
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
PY
