#!/usr/bin/env bash
# unlock-boot-qemu.sh — a KMS host BOOTS through a peer: a real initrd, a real encrypted root, the TPM
# unsealing done by systemd, WireGuard before root (regalia-kms#66 PoC 6.1, 6.2, 6.5; #67 PoC 7.1, 7.4).
#
#   sudo REGALIA_UNLOCK_BIN=/path/to/regalia-unlock e2e/unlock-boot-qemu.sh
#
# A Debian 13 guest in QEMU (KVM when the machine has it), with a software TPM as its TPM and its whole
# disk a LUKS2 volume. Its initrd is built by the guest's own dracut with the module
# deploy/baremetal/initrd/dracut/90regalia-unlock. The peers run on this machine, in network
# namespaces, as in e2e/wg-boot-netns.sh; nothing is loaded outside a namespace.
#
#   boot 1  ENROLMENT. Nothing is enrolled: the console asks for the recovery key and the test types it
#           (PoC 6.5: the manual path works with no peer and no credential). The running guest seals
#           the local half and the WG-BOOT key to its own TPM, and reports the PCR values it booted with.
#   boot 2  UNATTENDED. Nobody types anything. systemd unseals both credentials in the initrd, the boot
#           mesh comes up, a peer verifies the guest's quote and gives its half, systemd-cryptsetup maps
#           the root volume with the key from the socket, the root filesystem comes up, and the boot
#           interface, its ruleset and its address are gone.
#   boot 3  NO PEER. The peers are unreachable: after its bounded rounds the client gives nothing, the
#           console asks for the recovery key, and the key opens the volume.
#
# The guest is built here from Debian's own packages (mmdebstrap). REGALIA_BOOT_ROOTFS names a directory
# to use instead: the one variable to change when the appliance image of #61 exists.
#
# NOT covered: measured boot (OVMF, a unified kernel image, PCR 11: the next stage), a modified initrd
# (PoC 6.3), any physical TPM or DL360, and the real datacenter networks.
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
[ "$(id -u)" = 0 ] || { echo "unlock-boot-qemu: run as root"; exit 2; }
BIN="${REGALIA_UNLOCK_BIN:?set REGALIA_UNLOCK_BIN to a built cmd/regalia-unlock (static: CGO_ENABLED=0)}"
for t in qemu-system-x86_64 swtpm tpm2_createek cryptsetup mkfs.ext4 wg nft ip cpio python3; do
  command -v "$t" >/dev/null || { echo "unlock-boot-qemu: $t is required"; exit 2; }
done
W="$(mktemp -d /var/tmp/regalia-boot.XXXXXX)"; chmod 700 "$W"
MOUNTED=()
cleanup(){
  for m in "${MOUNTED[@]:-}"; do [ -n "$m" ] && umount -R "$m" 2>/dev/null; done
  [ -e /dev/mapper/regalia-boot-build ] && cryptsetup close regalia-boot-build 2>/dev/null
  [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null
  # Never through a mount: the build binds this machine's /dev, /sys and /proc under $W.
  if grep -q " $W" /proc/mounts; then
    echo "unlock-boot-qemu: something is still mounted under $W: it is NOT removed" >&2
  elif [ "${REGALIA_BOOT_KEEP:-0}" != 1 ]; then
    rm -rf --one-file-system -- "$W"
  fi
}
trap cleanup EXIT
RECOVERY="cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb"

SUITE="${REGALIA_BOOT_SUITE:-trixie}"
echo "### the guest's root tree (Debian $SUITE)"
ROOT="$W/root"
if [ -n "${REGALIA_BOOT_ROOTFS:-}" ]; then
  cp -a "$REGALIA_BOOT_ROOTFS" "$ROOT"
else
  command -v mmdebstrap >/dev/null || { echo "unlock-boot-qemu: mmdebstrap is required (or REGALIA_BOOT_ROOTFS)"; exit 2; }
  mmdebstrap --variant=minbase \
    --include=systemd-sysv,udev,kmod,linux-image-amd64,dracut,systemd-cryptsetup,cryptsetup-bin,wireguard-tools,nftables,iproute2,e2fsprogs,tpm2-tools,ca-certificates \
    "$SUITE" "$ROOT" "${REGALIA_BOOT_MIRROR:-http://deb.debian.org/debian}" >"$W/mmdebstrap.log" 2>&1 \
    || { tail -40 "$W/mmdebstrap.log"; echo "unlock-boot-qemu: mmdebstrap failed"; exit 2; }
fi
for fs in proc sys dev; do mount --bind "/$fs" "$ROOT/$fs"; MOUNTED+=("$ROOT/$fs"); done
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
# what systemd needs to talk to a TPM, and is only suggested by its package
chroot "$ROOT" apt-get install -y -qq --no-install-recommends 'libtss2-tcti-device0*' >"$W/apt.log" 2>&1 \
  || { tail -20 "$W/apt.log"; echo "unlock-boot-qemu: the TPM library did not install"; exit 2; }

# What a KMS host has installed: the client, the units, the script, the dracut module.
install -D -m 0755 "$BIN" "$ROOT/usr/bin/regalia-unlock"
install -D -m 0755 deploy/baremetal/initrd/wg-boot "$ROOT/usr/lib/regalia/wg-boot"
install -m 0644 deploy/baremetal/initrd/regalia-unlock.socket deploy/baremetal/initrd/regalia-unlock.service \
  deploy/baremetal/initrd/regalia-wg-boot.service "$ROOT/usr/lib/systemd/system/"
install -D -m 0755 deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/module-setup.sh"
# And what only the test adds, in the real root: the enrolment step and the report.
install -m 0755 e2e/lib/boot-guest/e2e-enrol e2e/lib/boot-guest/e2e-report "$ROOT/usr/lib/regalia/"
install -m 0644 e2e/lib/boot-guest/regalia-e2e-enrol.service e2e/lib/boot-guest/regalia-e2e-report.service "$ROOT/etc/systemd/system/"
mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"
for u in regalia-e2e-enrol.service regalia-e2e-report.service; do ln -sf "/etc/systemd/system/$u" "$ROOT/etc/systemd/system/multi-user.target.wants/$u"; done
echo "/dev/mapper/root / ext4 defaults 0 1" > "$ROOT/etc/fstab"
echo "lisbon" > "$ROOT/etc/hostname"

echo "### the initrd, by the guest's own dracut, with the module"
KVER="$(ls "$ROOT/lib/modules" | sort -V | tail -1)"
chroot "$ROOT" dracut --force --no-hostonly --no-hostonly-cmdline --add regalia-unlock --kver "$KVER" /boot/initrd.e2e >"$W/dracut.log" 2>&1 \
  || { tail -40 "$W/dracut.log"; echo "unlock-boot-qemu: dracut failed"; exit 2; }
grep -i "regalia" "$W/dracut.log" | head -5 || true
chroot "$ROOT" lsinitrd /boot/initrd.e2e > "$W/lsinitrd.txt" 2>/dev/null || true
for f in 'usr/bin/regalia-unlock$' 'usr/lib/regalia/wg-boot$' 'regalia-unlock\.socket$' 'regalia-unlock\.service$' 'regalia-wg-boot\.service$' \
         'bin/wg$' 'bin/nft$' 'bin/ip$' 'wireguard\.ko' 'nf_tables\.ko' 'nft_ct\.ko' 'virtio_net\.ko'; do
  grep -q "$f" "$W/lsinitrd.txt" || { echo "unlock-boot-qemu: the initrd lacks $f"; grep -c . "$W/lsinitrd.txt"; exit 2; }
done
cp "$ROOT/boot/vmlinuz-$KVER" "$W/vmlinuz"; cp "$ROOT/boot/initrd.e2e" "$W/initrd"
for fs in dev sys proc; do umount -R "$ROOT/$fs"; done; MOUNTED=()

echo "### the disk: all of it one LUKS2 volume, opened only by the recovery key so far"
truncate -s 4G "$W/disk.img"
LOOP="$(losetup --find --show "$W/disk.img")"
printf '%s' "$RECOVERY" | cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file - "$LOOP"
printf '{"type":"systemd-recovery","keyslots":["0"]}' | cryptsetup token import --json-file - "$LOOP"
printf '%s' "$RECOVERY" | cryptsetup open --key-file - "$LOOP" regalia-boot-build
mkfs.ext4 -q -L root /dev/mapper/regalia-boot-build
mkdir "$W/mnt"; mount /dev/mapper/regalia-boot-build "$W/mnt"; MOUNTED+=("$W/mnt")
cp -a "$ROOT/." "$W/mnt/"
umount "$W/mnt"; MOUNTED=()
cryptsetup close regalia-boot-build
cryptsetup luksUUID "$LOOP" > "$W/uuid"
losetup -d "$LOOP"; LOOP=""
rm -rf "$ROOT"

echo "### three boots"
out="$(REGALIA_EXPECT_QEMU=1 REGALIA_BOOT_DIR="$W" REGALIA_UNLOCK_BIN="$BIN" python3 -Es -m unittest -v tests.test_baremetal_unlock_boot </dev/null 2>&1)" && rc=0 || rc=$?
printf '%s\n' "$out"
if [ "$rc" != 0 ]; then
  for log in "$W"/console-*.log; do [ -e "$log" ] && { echo "----- $(basename "$log") (last 80 lines)"; tail -80 "$log"; }; done
  echo "unlock-boot-qemu: FAILED"; exit 1
fi
# (the test prints each boot's console digest between its name and its "ok", so the two are not on one line)
if ! grep -q '^test_a_host_boots_through_a_peer' <<< "$out" || ! grep -q '^Ran 1 test' <<< "$out" || ! grep -qx 'OK' <<< "$out"; then
  echo "unlock-boot-qemu: the boot test did not run"; exit 1
fi
echo "unlock-boot-qemu: 3 boots passed (enrolment with the recovery key, unattended through a peer, no peer and the recovery key)"
