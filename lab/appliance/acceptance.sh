#!/bin/sh
set -eu
trap 'echo REGALIA_FAIL:acceptance-command' EXIT
fail() {
  echo "REGALIA_FAIL:$1"
  # This guest has no commissioned credentials. Retain bounded startup/audit
  # diagnostics so a specific refusal can be distinguished from a broken daemon.
  systemctl --no-pager --full status regalia-kms.service || true
  journalctl --no-pager -b -u regalia-kms.service -n 30 || true
  journalctl --no-pager -b -k -g 'apparmor=.*DENIED' -n 20 || true
  /sbin/poweroff -f
  exit 1
}
check() { "$@" || fail "$1"; }
echo REGALIA_ACCEPTANCE_BEGIN
check test "$(cat /etc/debian_version | cut -d. -f1)" = 13
check test "$(cat /proc/1/comm)" = systemd
check test ! -e /etc/regalia-kms/config.json
check test ! -e /etc/regalia-kms/commissioned
check test -x /usr/local/sbin/regalia-kms
for directory in /go /.cache/go-build /root/go /tmp/regalia-build; do
  check test ! -e "$directory"
done
kernel_count=$(dpkg-query -W -f='${db:Status-Status}\n' 'linux-image-[0-9]*' | grep -c '^installed$')
check test "$kernel_count" = 1
/usr/local/sbin/regalia-kms -version
check systemctl start regalia-kms.service
check test "$(systemctl show regalia-kms.service -p ActiveState --value)" = inactive
check test "$(systemctl show regalia-kms.service -p ConditionResult --value)" = no
check test "$(systemctl show regalia-kms.service -p NoNewPrivileges --value)" = yes
check test "$(systemctl show regalia-kms.service -p ProtectSystem --value)" = strict
check test -z "$(systemctl show regalia-kms.service -p CapabilityBoundingSet --value)"
check test "$(systemctl show regalia-kms.service -p AppArmorProfile --value)" = regalia-kms
check systemctl is-active nftables.service
check sh -c 'nft list chain inet regalia input | grep -q "policy drop"'
check sh -c 'nft list chain inet regalia output | grep -q "policy drop"'
check sh -c 'grep -q "^root:[!*]" /etc/shadow'
check sh -c 'getent passwd regalia-kms | grep -q "/usr/sbin/nologin$"'
check sh -c 'test -z "$(ss -H -lnt)"'
check sh -c 'test "$(cat /sys/module/apparmor/parameters/enabled)" = Y'
check sh -c 'test "$(cat /proc/sys/kernel/dmesg_restrict)" = 1'
check sh -c 'test "$(cat /proc/sys/kernel/kptr_restrict)" = 2'
check sh -c 'test -z "$(swapon --noheadings --show)"'
for package in openssh-server docker.io avahi-daemon cups bluez golang-go gcc vim-tiny vim-common nano locales libc-l10n util-linux-locales eject fdisk task-english tasksel tasksel-data libfdisk1 installation-report laptop-detect os-prober binutils binutils-common binutils-x86-64-linux-gnu libbinutils libctf0 libctf-nobfd0 libgprofng0 libsframe1; do
  if dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | grep -q '^installed$'; then
    fail "unexpected-package-$package"
  fi
done
check grep -qx 'LANG=C.UTF-8' /etc/locale.conf
check sh -c 'systemctl show-environment | grep -qx "LANG=C.UTF-8"'
check test -r /var/log/regalia-minimization.json
# Root already mounts the export disk below. The same helpers must not grant
# mounting privileges to a plain appliance UID, outside daemon-specific NNP.
check python3 -I - <<'PY'
import os
import pathlib
import pwd
import stat
import subprocess
for name in ('mount', 'umount'):
    binary = pathlib.Path('/usr/bin') / name
    info = binary.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
    assert stat.S_IMODE(info.st_mode) == 0o755
    override = subprocess.check_output(['/usr/bin/dpkg-statoverride', '--list', str(binary)], text=True).split()
    assert len(override) == 4 and override[:2] == ['root', 'root']
    assert int(override[2], 8) == 0o755 and override[3] == str(binary)
target = pathlib.Path('/run/regalia-nonroot-mount')
target.mkdir(mode=0o755)
account = pwd.getpwnam('regalia-kms')
def ordinary_uid():
    os.setgroups([])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
attempt = subprocess.run(['/usr/bin/mount', '--bind', '/etc', str(target)],
                         preexec_fn=ordinary_uid, capture_output=True, text=True, timeout=10,
                         env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
assert attempt.returncode != 0
assert 'superuser' in attempt.stderr or 'permission denied' in attempt.stderr.lower()
assert not os.path.ismount(target)
target.rmdir()
print('REGALIA_NONROOT_MOUNT_DENIED')
PY
# Temporarily start the real daemon with a public fixture and no credentials.
# It must run under the installed policy while remaining cryptographically unready.
# These public fixtures are removed before exporting the reusable disk.
cp /usr/local/share/regalia-appliance/custody-fixture.json /etc/regalia-kms/acceptance-manifest.json
chown root:regalia-kms /etc/regalia-kms/acceptance-manifest.json
chmod 0640 /etc/regalia-kms/acceptance-manifest.json
printf '%s\n' '{"registry_path":"/etc/regalia-kms/acceptance-manifest.json","site":"sitea"}' >/etc/regalia-kms/config.json
chown root:regalia-kms /etc/regalia-kms/config.json
chmod 0640 /etc/regalia-kms/config.json
touch /etc/regalia-kms/commissioned
check systemctl start regalia-kms.service
check systemctl is-active regalia-kms.service
check python3 -I - <<'PY'
import time
import urllib.error
import urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def status(path):
    try:
        with opener.open('http://127.0.0.1:8443' + path, timeout=2) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
for attempt in range(30):
    try:
        if status('/v1/health/live') == 200:
            break
    except OSError:
        pass
    time.sleep(0.2)
else:
    raise SystemExit('daemon did not become live')
assert status('/v1/health/ready') == 503, 'credential-free daemon declared ready'
PY
# Type=simple returns after fork, before systemd has applied every restriction
# and exec'd the daemon. Inspect the process only after its HTTP liveness passes.
pid=$(systemctl show regalia-kms.service -p MainPID --value)
check test "$pid" -gt 1
echo REGALIA_PROCESS_ENFORCEMENT_BEGIN
cat "/proc/$pid/attr/current"
grep -E '^(CapEff|NoNewPrivs|Seccomp):' "/proc/$pid/status"
check sh -c "grep -qx 'regalia-kms (enforce)' /proc/$pid/attr/current"
check sh -c "grep -Eq '^CapEff:[[:space:]]+0000000000000000$' /proc/$pid/status"
check sh -c "grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/$pid/status"
check sh -c "grep -Eq '^Seccomp:[[:space:]]+2$' /proc/$pid/status"
check systemctl stop regalia-kms.service
# The same config check is valid at the allowed path, and permission denied at a
# DAC-readable path outside AppArmor policy. Check the specific error, not any
# failing exit. Neither fixture has private material.
check systemd-run --quiet --wait --pipe --unit=regalia-config-positive \
  -p User=regalia-kms -p NoNewPrivileges=yes -p AppArmorProfile=regalia-kms \
  /usr/local/sbin/regalia-kms -check-config -config /etc/regalia-kms/config.json
printf '{}\n' >/tmp/regalia-denied.json
chmod 0644 /tmp/regalia-denied.json
if systemd-run --quiet --wait --pipe --unit=regalia-config-negative \
  -p User=regalia-kms -p NoNewPrivileges=yes -p AppArmorProfile=regalia-kms \
  /usr/local/sbin/regalia-kms -check-config -config /tmp/regalia-denied.json \
  >/tmp/regalia-denial.log 2>&1; then
  fail apparmor-accepted-forbidden-config
fi
check grep -q 'permission denied' /tmp/regalia-denial.log
rm -f /etc/regalia-kms/config.json /etc/regalia-kms/commissioned \
  /etc/regalia-kms/acceptance-manifest.json /usr/local/share/regalia-appliance/custody-fixture.json \
  /tmp/regalia-denied.json /tmp/regalia-denial.log
check systemctl start regalia-kms.service
check test "$(systemctl show regalia-kms.service -p ActiveState --value)" = inactive
check test "$(systemctl show regalia-kms.service -p ConditionResult --value)" = no
check sh -c 'test -z "$(ss -H -lnt)"'
echo REGALIA_ENFORCED_DAEMON_PASS
echo REGALIA_PACKAGE_INVENTORY_BEGIN
cat /var/log/regalia-packages.tsv
echo REGALIA_PACKAGE_INVENTORY_END
mkdir -p /mnt/regalia-export
check mount -t 9p -o trans=virtio,version=9p2000.L regalia_export /mnt/regalia-export
cp /var/log/regalia-packages.tsv /mnt/regalia-export/packages.tsv
cp /var/log/regalia-go-version.txt /mnt/regalia-export/go-version.txt
cp /var/log/regalia-binary-build.txt /mnt/regalia-export/binary-build.txt
cp /usr/local/sbin/regalia-kms /mnt/regalia-export/regalia-kms
# Remove the automatic verification boot flag after the successful prototype
# test; normal boots retain the same commissioning and network restrictions.
sed -i 's/ regalia.image_verify=1//' /etc/default/grub
update-grub
truncate -s 0 /etc/machine-id
rm -f /var/lib/systemd/random-seed
tar --one-file-system --exclude='./proc' --exclude='./sys' --exclude='./dev' \
  --exclude='./run' --exclude='./tmp' --exclude='./mnt' --exclude='./var/log/journal' \
  -C / -I 'gzip -1' -cf /mnt/regalia-export/rootfs.tar.gz .
sync
echo REGALIA_ACCEPTANCE_PASS
trap - EXIT
/sbin/poweroff
