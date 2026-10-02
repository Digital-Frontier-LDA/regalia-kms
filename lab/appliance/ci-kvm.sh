#!/bin/sh
# CI-only: give this ephemeral runner access to KVM, without world permissions.
set -eu
if [ ! -c /dev/kvm ]; then
  echo 'KVM is not exposed on this runner; the appliance CI requires a KVM-capable host.' >&2
  exit 1
fi
sudo setfacl -m "u:$(id -un):rw" /dev/kvm
python3 - <<'PY'
import os
import subprocess

assert os.access('/dev/kvm', os.R_OK | os.W_OK), 'runner cannot access KVM'
# Initialize a paused, empty machine and immediately quit. No disk, network,
# credentials or host filesystem is attached. Refuse unsupported virtualization
# before downloading/installing the full appliance.
subprocess.run(['qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-cpu', 'host',
                '-m', '128', '-nodefaults', '-display', 'none', '-S', '-monitor', 'stdio'],
               input=b'quit\n', check=True, timeout=30, stdout=subprocess.DEVNULL)
print('KVM access and empty-machine preflight passed')
PY
