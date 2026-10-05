#!/usr/bin/env bash
# install-host.sh — put the KMS host image on THIS host's disk, with this host's own LUKS2 volume key (#61, second slice).
#
#   sudo deploy/baremetal/image/install-host.sh --disk /dev/sdX --rootfs rootfs.tar --rootfs-record rootfs-build.json \
#        --uki NAME.efi --uki-record NAME.signed.json --out DIR [--wipe] [--no-efi-entry]
#
# Run as root from a live medium ON the host (a Debian 13 live USB, the iLO's virtual media). The reproducible
# artifacts are rootfs.tar (build-rootfs.sh) and the signed UKI (uki.py sign); the disk is made here, per host,
# because the root volume's key must be: a pre-encrypted image would give every host one volume key (the design and
# its discussion are on #61). In order, refusing at the first failure, nothing written before step 3:
#   1. the inputs: rootfs.tar's sha256 is its record's rootfs_sha256; the UKI's is its record's signed.image_sha256
#   2. the disk: the operator types its serial (lsblk), which must be --disk's; a disk holding partitions needs
#      --wipe and the serial typed again
#   3. GPT: an ESP (FAT32, 1 GiB) and `regalia-root` (Linux root x86-64), the PARTLABEL the initrd's crypttab opens
#   4. LUKS2 (argon2id) on regalia-root, its volume key made HERE; the installer passphrase typed twice at the
#      console. It is the slot the README's steps replace: recovery-key.sh --enrol, the peer path, then
#      systemd-cryptenroll --wipe-slot=password
#   5. ext4 (label regalia-root-fs) inside it, rootfs.tar extracted with numeric owners; an empty /efi for the ESP
#   6. the ESP: the UKI at \EFI\Linux\<name>.efi and at the removable-media path \EFI\BOOT\BOOTX64.EFI, nothing else
#      (the per-host loader credentials and the membership chain come from enrolment, #66 B3)
#   7. a firmware entry for \EFI\Linux\<name>.efi, first in BootOrder (not with --no-efi-entry)
#   8. DIR/install-<serial>.json: the inputs' digests, the disk, the partition and LUKS UUIDs, the time. Nothing secret
#
# THE TEST MODE: with REGALIA_INSTALL_TEST=1, and only when --disk is a /dev/loopN, the serial is not asked (a loop
# device has none), the passphrase comes from standard input (one line), and no firmware entry is made. On any other
# disk the variable is refused.
#
# CURRENT LIMITATIONS (stated, not hidden; the cross-cutting list is LIMITATIONS.md):
#   * NO RELEASE CHECK YET: the inputs are checked against their own build records, which nothing signs. Which
#     root-committed document names both the rootfs and the UKI is #61's open question 1; until it lands, the
#     operator compares the printed digests with the ceremony's.
#   * THE ROOT FILESYSTEM HAS NO RUNTIME INTEGRITY: LUKS2 keeps it confidential, not unaltered (dm-verity on /usr is
#     #61's next design).
#   * ONE DISK: no mirror (#61's baseline asks for mirrored SSDs).
#   * /efi relies on systemd-gpt-auto-generator mounting the ESP the stub booted from; not yet seen on a booted
#     installed disk (the QEMU boot of an installed disk is this slice's next step).
#   * The TPM is not touched: no clear, no owner authorization; enrolment does that.
#   * Not run on a DL360 yet.
set -euo pipefail
umask 077
export LC_ALL=C TZ=UTC PATH="/usr/sbin:/usr/bin:/sbin:/bin"
die(){ echo "install-host: $*" >&2; exit 2; }
say(){ echo "install-host: $*"; }
ESP_TYPE=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
ROOT_TYPE=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709        # Linux root (x86-64), the discoverable-partitions type
DISK="" ROOTFS="" ROOTFS_RECORD="" UKI="" UKI_RECORD="" OUT="" WIPE=0 EFI_ENTRY=1
while [ $# -gt 0 ]; do
  case "$1" in
    --disk) DISK="${2:-}"; shift 2 ;;
    --rootfs) ROOTFS="${2:-}"; shift 2 ;;
    --rootfs-record) ROOTFS_RECORD="${2:-}"; shift 2 ;;
    --uki) UKI="${2:-}"; shift 2 ;;
    --uki-record) UKI_RECORD="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --wipe) WIPE=1; shift ;;
    --no-efi-entry) EFI_ENTRY=0; shift ;;
    *) die "unknown argument $1 (see the header)" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run as root"
for v in DISK ROOTFS ROOTFS_RECORD UKI UKI_RECORD OUT; do [ -n "${!v}" ] || die "--$(tr '[:upper:]_' '[:lower:]-' <<< "$v") is required"; done
for t in sfdisk cryptsetup mkfs.ext4 mkfs.vfat tar python3 lsblk blkid udevadm; do command -v "$t" >/dev/null || die "$t is required"; done
[ -b "$DISK" ] || die "$DISK is not a block device"
TEST=0
if [ "${REGALIA_INSTALL_TEST:-}" = 1 ]; then
  [[ "$DISK" =~ ^/dev/loop[0-9]+$ ]] || die "REGALIA_INSTALL_TEST is for a /dev/loopN only, never a host's disk"
  TEST=1; EFI_ENTRY=0
fi
mkdir -p "$OUT"
NAME="$(basename "$UKI" .efi)"
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "the UKI's name '$NAME' is not a plain file name"

# 1. the inputs, against their records, before anything is written
read_field(){ python3 -I -c 'import json,sys
v = json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."):
    v = v[k]
print(v)' "$1" "$2" 2>/dev/null; }
ROOTFS_SHA="$(sha256sum < "$ROOTFS" | cut -d' ' -f1)"
UKI_SHA="$(sha256sum < "$UKI" | cut -d' ' -f1)"
[ "$ROOTFS_SHA" = "$(read_field "$ROOTFS_RECORD" rootfs_sha256)" ] || die "rootfs.tar is not the file its record names (sha256 $ROOTFS_SHA)"
[ "$UKI_SHA" = "$(read_field "$UKI_RECORD" signed.image_sha256)" ] || die "the UKI is not the file its signed record names (sha256 $UKI_SHA)"
say "inputs: rootfs.tar $ROOTFS_SHA, commit $(read_field "$ROOTFS_RECORD" commit); UKI $NAME $UKI_SHA"
say "COMPARE both digests with the ceremony's before going on (no release check yet: the header's first limitation)"

# 2. the disk, by its serial typed at the console
SERIAL="$(lsblk -dno SERIAL "$DISK" 2>/dev/null | tr -d ' ')"
ask(){ local prompt="$1" answer; read -r -p "$prompt" answer < /dev/tty; printf '%s' "$answer"; }
if [ "$TEST" = 0 ]; then
  [ -n "$SERIAL" ] || die "$DISK reports no serial: refused (an installer writes only to a disk it can name)"
  # the serial names the install record's file: plain characters only (it is the firmware's text)
  [[ "$SERIAL" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "$DISK's serial is not plain text ([A-Za-z0-9._-]): refused"
  [ "$(ask "Type the serial of the disk to install on ($DISK, $(lsblk -dno SIZE,MODEL "$DISK" | tr -s ' ')): ")" = "$SERIAL" ] \
    || die "the serial typed is not $DISK's: nothing was written"
else
  SERIAL="test-$(basename "$DISK")"
fi
if [ -n "$(lsblk -no NAME "$DISK" | tail -n +2)" ]; then
  [ "$WIPE" = 1 ] || die "$DISK holds partitions: refused without --wipe"
  if [ "$TEST" = 0 ]; then
    [ "$(ask "$DISK holds partitions. Type its serial AGAIN to wipe it: ")" = "$SERIAL" ] || die "not confirmed: nothing was written"
  fi
fi

# the passphrase, before the disk is touched (typed twice, or one line on stdin in the test mode)
if [ "$TEST" = 1 ]; then
  IFS= read -r PASSPHRASE || die "the test mode reads the installer passphrase from standard input"
else
  IFS= read -r -s -p "Installer passphrase for the root volume (replaced by the recovery key, then wiped): " PASSPHRASE < /dev/tty; echo
  IFS= read -r -s -p "Again: " again < /dev/tty; echo
  [ "$PASSPHRASE" = "$again" ] || die "the two passphrases differ: nothing was written"
  unset again
fi
[ "${#PASSPHRASE}" -ge 12 ] || die "the installer passphrase is shorter than 12 characters"

W="$(mktemp -d /run/regalia-install.XXXXXX)"
MAPPED="regalia-install-$$"
cleanup(){
  for m in "$W/esp" "$W/root"; do mountpoint -q "$m" 2>/dev/null && umount "$m"; done
  [ -e "/dev/mapper/$MAPPED" ] && cryptsetup close "$MAPPED"
  rm -rf --one-file-system -- "$W"
  unset PASSPHRASE
}
trap cleanup EXIT

# 3. GPT
say "partitioning $DISK (GPT: ESP 1 GiB, regalia-root)"
wipefs -aq "$DISK"
sfdisk -q "$DISK" <<EOF
label: gpt
size=1GiB, type=$ESP_TYPE, name="esp"
type=$ROOT_TYPE, name="regalia-root"
EOF
udevadm settle
part(){ local p; p="$(lsblk -lnpo NAME "$DISK" | sed -n "$((1 + $1))p")"; [ -b "$p" ] || die "partition $1 of $DISK did not appear"; printf '%s' "$p"; }
ESP_DEV="$(part 1)" ROOT_DEV="$(part 2)"

# 4. LUKS2, the volume key made here
say "LUKS2 on $ROOT_DEV (argon2id), its volume key from this host"
printf '%s' "$PASSPHRASE" | cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --label regalia-root --key-file - "$ROOT_DEV"
printf '%s' "$PASSPHRASE" | cryptsetup open --key-file - "$ROOT_DEV" "$MAPPED"

# 5. the filesystem and the rootfs
mkfs.ext4 -q -L regalia-root-fs "/dev/mapper/$MAPPED"
mkdir -p "$W/root" "$W/esp"
mount "/dev/mapper/$MAPPED" "$W/root"
say "extracting rootfs.tar"
tar --numeric-owner -xpf "$ROOTFS" -C "$W/root"
mkdir -p "$W/root/efi"
chmod 0700 "$W/root/efi"

# 6. the ESP: the UKI at its own place and at the removable-media fallback, nothing else
mkfs.vfat -F 32 -n ESP "$ESP_DEV" >/dev/null
mount -o umask=0077 "$ESP_DEV" "$W/esp"
mkdir -p "$W/esp/EFI/Linux" "$W/esp/EFI/BOOT"
cp "$UKI" "$W/esp/EFI/Linux/$NAME.efi"
cp "$UKI" "$W/esp/EFI/BOOT/BOOTX64.EFI"
sync
for f in "EFI/Linux/$NAME.efi" EFI/BOOT/BOOTX64.EFI; do
  [ "$(sha256sum < "$W/esp/$f" | cut -d' ' -f1)" = "$UKI_SHA" ] || die "the ESP's $f is not the UKI after writing"
done

ESP_UUID="$(blkid -s PARTUUID -o value "$ESP_DEV")" ROOT_UUID="$(blkid -s PARTUUID -o value "$ROOT_DEV")"
LUKS_UUID="$(cryptsetup luksUUID "$ROOT_DEV")"
umount "$W/esp" "$W/root"
cryptsetup close "$MAPPED"

# 7. the firmware entry
if [ "$EFI_ENTRY" = 1 ]; then
  [ -d /sys/firmware/efi ] || die "this system was not booted by UEFI: no firmware entry can be made (--no-efi-entry to skip)"
  efibootmgr --create --disk "$DISK" --part 1 --label "regalia $NAME" --loader "\\EFI\\Linux\\$NAME.efi" >/dev/null \
    || die "efibootmgr could not create the entry (the disk is installed; make it by hand, KERNEL-UPDATE 3.1)"
fi

# 8. the install record
# (values as arguments, never pasted into the code: a disk's serial is the firmware's text)
python3 -I - "$OUT/install-$SERIAL.json" "$SERIAL" "$ROOTFS_SHA" "$NAME" "$UKI_SHA" "$ESP_UUID" "$ROOT_UUID" "$LUKS_UUID" "$EFI_ENTRY" <<'PY'
import json, sys, time
path, serial, rootfs, name, uki, esp, root, luks, entry = sys.argv[1:]
record = {"schema": "regalia.install/v1", "disk_serial": serial, "rootfs_sha256": rootfs, "uki": name, "uki_sha256": uki,
          "esp_partuuid": esp, "root_partuuid": root, "luks_uuid": luks, "efi_entry": entry == "1",
          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
with open(path, "x") as f:
    json.dump(record, f, indent=1, sort_keys=True)
    f.write("\n")
PY
say "installed on $DISK ($SERIAL): ESP $ESP_UUID, regalia-root $ROOT_UUID (LUKS $LUKS_UUID). Record: $OUT/install-$SERIAL.json"
say "next, on the booted host: recovery-key.sh --enrol, the enrolment, then wipe the installer passphrase (README)"
