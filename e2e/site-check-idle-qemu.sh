#!/usr/bin/env bash
# Exercise the shipped units with Debian 13 systemd PID 1 and a real VFAT
# automount. The node command is a test double for document comparison and
# invocation counts; no WireGuard, credentials, TPM, or host mounts are used.
# Run: e2e/site-check-idle-qemu.sh FIXTURES CASE
# FIXTURES contains ARM64 Debian 13 vmlinuz/initrd.img, a Debian ext4 root.raw labeled bcw-root
# (systemd, Python 3, util-linux, VFAT/autofs support), and an 80 MiB esp.raw
# with loader/credentials/regalia.site.cred containing "measured".
# CASE is idle, missing, or failed. Each boot writes only to transient overlays.
set -euo pipefail
cd "$(dirname "$0")/.."
fixtures="$(cd "$1" && pwd -P)"
scenario="$2"
case "$scenario" in idle|missing|failed) ;; *) echo "unknown case: $scenario" >&2; exit 2;; esac
for file in vmlinuz initrd.img root.raw esp.raw; do
    test -r "$fixtures/$file" || { echo "missing guest fixture: $file" >&2; exit 2; }
done
deadline="$(command -v timeout || command -v gtimeout)"
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
overlay="$scratch/overlay"
mkdir -p "$overlay/bcw" "$overlay/scripts/local-bottom"
cp deploy/baremetal/units/regalia-site-check.service deploy/baremetal/units/regalia-wg-apply.service "$overlay/bcw/"
cp deploy/baremetal/units/regalia-site-check.service.d/per-host.conf "$overlay/bcw/enrolled.conf"
printf '%s\n' "$scenario" > "$overlay/bcw/case"

cat > "$overlay/scripts/local-bottom/bcw-fixture" <<'HOOK'
#!/bin/sh
set -eu
if [ "${1:-}" = prereqs ]; then exit 0; fi
root="$rootmnt"
printf 'BCW_INITRAMFS root mounted, installing guest fixture\n' > /dev/console
units="$root/etc/systemd/system"
mkdir -p "$units/regalia-site-check.service.d" "$units/regalia-wg-apply.service.d" \
    "$root/usr/local/lib/bcw" "$root/usr/lib/regalia-kms/deploy/baremetal" \
    "$root/etc/regalia" "$root/efi/loader/credentials" "$root/mnt/rewrite"
chroot "$root" /usr/bin/rm -f /.dockerenv
# The initramfs has klibc cat and mkdir, but no cp or rm.
for file in /bcw/*.service; do
    cat "$file" > "$units/${file##*/}"
done
cat /bcw/enrolled.conf > "$units/regalia-site-check.service.d/per-host.conf"
cat /bcw/enrolled.conf > "$units/regalia-wg-apply.service.d/per-host.conf"
cat /bcw/runner > "$root/usr/local/lib/bcw/runner"
cat /bcw/case > "$root/usr/local/lib/bcw/case"
cat /bcw/node.py > "$root/usr/lib/regalia-kms/deploy/baremetal/node.py"
printf '{}\n' > "$root/etc/regalia/node.json"
printf 'measured\n' > "$root/efi/loader/credentials/regalia.site.cred"
# The full WireGuard unit resolves this group before launching the fixture.
chroot "$root" /usr/bin/grep -q '^tss:' /etc/group || printf 'tss:x:995:\n' >> "$root/etc/group"
printf 'BCW_INITRAMFS switching to the fixture root\n' > /dev/console
HOOK
chmod +x "$overlay/scripts/local-bottom/bcw-fixture"
printf '%s\n' '/scripts/local-bottom/bcw-fixture "$@"' > "$overlay/scripts/local-bottom/ORDER"

cat > "$overlay/bcw/bcw-test.service" <<'UNIT'
[Unit]
Description=Regalia site-check automount regression
[Service]
Type=oneshot
ExecStart=/usr/bin/bash /usr/local/lib/bcw/runner
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=90
UNIT

cat > "$overlay/bcw/node.py" <<'PY'
from pathlib import Path
import sys

if sys.argv[1:] == ["--config", "/etc/regalia/node.json", "site-check", "--esp", "/efi"]:
    document = Path("/efi/loader/credentials/regalia.site.cred").read_text().strip()
    print(f"BCW site command read: {document}", flush=True)
    sys.exit(0 if document == "measured" else 2)
if sys.argv[1:] == ["--config", "/etc/regalia/node.json", "wg-apply"]:
    print("BCW wg command ran", flush=True)
    sys.exit(0)
raise SystemExit("BCW unexpected node invocation")
PY

cat > "$overlay/bcw/runner" <<'GUEST'
set -euo pipefail
scenario="$(cat /usr/local/lib/bcw/case)"
site=regalia-site-check.service
wg=regalia-wg-apply.service
finish() {
    status=$?
    trap - EXIT
    if ((status != 0)); then
        journalctl -b -u "$site" -u "$wg" -u efi.mount -u efi.automount --no-pager -o cat || true
    fi
    printf 'BCW_RESULT %s %s\n' "$scenario" "$status"
    systemctl --no-block poweroff
    exit "$status"
}
trap finish EXIT
fail() { echo "BCW_ASSERTION: $*" >&2; exit 1; }
count() { journalctl --sync; journalctl -b -u "$1" -o cat --no-pager | awk -v event="$2" 'index($0,event)==1{n++} END{print n+0}'; }
state() { systemctl show --property="$2" --value "$1"; }
has_mount() { awk -v type="$1" '$5=="/efi" && $0 ~ (" - " type " "){seen=1} END{exit !seen}' /proc/1/mountinfo; }

echo "BCW PID1 $(cat /proc/1/comm); $(systemctl --version | head -n 1)"
test "$(cat /proc/1/comm)" = systemd || fail "fixture PID 1 is not systemd"
modprobe vfat
modprobe autofs4 || modprobe autofs
if [[ "$scenario" != missing ]]; then
    options=rw,nosuid,nodev,noexec,fmask=0077,dmask=0077
    [[ "$scenario" != failed ]] || options+=,bcw_invalid_mount_option
    printf '[Mount]\nWhat=/dev/vdb\nWhere=/efi\nType=vfat\nOptions=%s\n' "$options" \
        > /run/systemd/system/efi.mount
fi
if [[ "$scenario" == idle ]]; then
    # Give the emulated sandbox enough time to start before the real idle timer expires.
    printf '[Automount]\nWhere=/efi\nDirectoryMode=0700\nTimeoutIdleSec=20s\n' > /run/systemd/system/efi.automount
fi
systemctl daemon-reload

if [[ "$scenario" != idle ]]; then
    test "$(cat /efi/loader/credentials/regalia.site.cred)" = measured
    if systemctl start "$wg"; then fail "wg-apply accepted absent or failed /efi"; fi
    if [[ "$scenario" == failed ]]; then
        [[ "$(state efi.mount Result)" == exit-code ]] || fail "fixture did not observe the actual mount fail"
    else
        [[ "$(state efi.mount LoadState)" == not-found ]] || fail "fixture did not withhold efi.mount"
    fi
    ! has_mount vfat || fail "fixture unexpectedly mounted /efi"
    [[ "$(state "$site" ActiveState)" == failed ]] || fail "regalia-site-check did not fail by name"
    [[ "$(count "$site" 'BCW site command read:')" == 0 ]] || fail "site-check consumed the unmounted decoy"
    [[ "$(count "$wg" 'BCW wg command ran')" == 0 ]] || fail "wg-apply ran after mount refusal"
    journalctl -b -u "$site" -u efi.mount --no-pager -o cat
    [[ "$(count "$site" 'regalia-site-check: /efi is not mounted as the boot ESP')" == 1 ]] ||
        fail "regalia-site-check did not report the missing ESP"
    exit 0
fi

systemctl start efi.automount
systemctl start "$wg" || fail "initial site-check and wg-apply did not succeed"
[[ "$(state "$site" ActiveState)/$(state "$site" SubState)" == active/exited ]] || fail "initial result did not latch"
has_mount vfat || fail "first site-check did not mount VFAT"
deadline=$((SECONDS+45))
while has_mount vfat && ((SECONDS < deadline)); do sleep 0.2; done
! has_mount vfat || fail "fixture did not observe the idle VFAT unmount"
has_mount autofs || fail "automount disappeared instead of expiring its backing mount"
[[ "$(state efi.mount ActiveState)" == inactive ]] || fail "idle /efi mount unit did not become inactive"
latched="$(state "$site" ActiveState)/$(state "$site" SubState)"
echo "BCW after idle: efi inactive, automount present, site $latched"
mount -t vfat /dev/vdb /mnt/rewrite
printf 'next-boot\n' >/mnt/rewrite/loader/credentials/regalia.site.cred
umount /mnt/rewrite
wg_status=0
systemctl start "$wg" || wg_status=$?
site_runs="$(count "$site" 'BCW site command read:')"
wg_runs="$(count "$wg" 'BCW wg command ran')"
echo "BCW later wg status=$wg_status site_runs=$site_runs wg_runs=$wg_runs"
journalctl -b -u "$site" -u "$wg" --no-pager -o cat
[[ "$latched" == active/exited ]] || fail "idle /efi unmount cleared the boot-scoped regalia-site-check result"
[[ "$wg_status/$site_runs/$wg_runs" == 0/1/2 ]] || fail "later wg-apply reran site-check or failed"
echo "BCW after later wg: efi $(state efi.mount ActiveState)"
[[ "$(cat /efi/loader/credentials/regalia.site.cred)" == next-boot ]] || fail "explicit access did not see the replacement document"
has_mount vfat || fail "the replacement document was not read from a mounted ESP"
[[ "$(count "$site" 'BCW site command read:')" == 1 ]] || fail "observing the remounted ESP reran site-check"
GUEST

(cd "$overlay" && find bcw scripts -print | cpio -o -H newc) | gzip > "$scratch/overlay.cpio.gz"
cat "$fixtures/initrd.img" "$scratch/overlay.cpio.gz" > "$scratch/initrd.img"
accel="${REGALIA_BCW_ACCEL:-tcg}"
case "$accel" in hvf) cpu=host;; tcg) cpu=max;; *) exit 2;; esac
# Include cold TCG boot and shutdown in the host deadline. The guest's
# service and actual idle-expiry limits are independent and remain shorter.
echo "BCW_HOST launching QEMU ($accel), case $scenario, 300s wall deadline"
qemu_status=0
"$deadline" --kill-after=10 300 qemu-system-aarch64 \
    -machine virt,gic-version=3 -accel "$accel" -cpu "$cpu" -smp 2 -m 1024 \
    -display none -serial stdio -monitor none -nic none -no-reboot -snapshot \
    -kernel "$fixtures/vmlinuz" -initrd "$scratch/initrd.img" \
    -drive "if=none,id=root,file=$fixtures/root.raw,format=raw" -device virtio-blk-pci,drive=root \
    -drive "if=none,id=esp,file=$fixtures/esp.raw,format=raw" -device virtio-blk-pci,drive=esp \
    -append 'root=LABEL=bcw-root rw console=ttyAMA0 earlycon loglevel=6 systemd.show_status=yes systemd.unit=bcw-test.service panic=1' \
    | tee "$scratch/console.log" || qemu_status=$?
if ((qemu_status != 0)); then
    echo "site-check-idle-qemu: $scenario exited at the QEMU boundary (status $qemu_status)" >&2
    exit "$qemu_status"
fi
if ! grep -Eq "(^|: )BCW_RESULT $scenario 0[[:space:]]*$" "$scratch/console.log"; then
    echo "site-check-idle-qemu: $scenario did not produce its guest success marker" >&2
    exit 1
fi
