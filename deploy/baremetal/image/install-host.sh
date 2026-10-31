#!/usr/bin/env bash
# install-host.sh — put the KMS host image on THIS host's disk, with this host's own LUKS2 volume key (#61, second slice).
#
#   sudo deploy/baremetal/image/install-host.sh --disk /dev/sdX [--disk /dev/sdY] --rootfs rootfs.tar --rootfs-record rootfs-build.json \
#        --uki NAME.efi --uki-record NAME.signed.json --out DIR [--wipe] [--no-efi-entry]
#
# --disk twice makes a MIRROR (regalia-kms#544): on each disk an ESP and a Linux RAID member, RAID1 (metadata 1.2) over
# the two members as /dev/md/regalia-root, and the one LUKS2 volume on it. One volume key and one keyslot set, as on one
# disk; each disk holds ciphertext only. The ESPs are two copies of the same files, not a RAID (the firmware reads an ESP
# before anything assembles an md). Each disk's serial is typed, and two disks reporting one serial are refused.
#
# Run as root from a live medium ON the host (a Debian 13 live USB, the iLO's virtual media). The reproducible
# artifacts are rootfs.tar (build-rootfs.sh) and the signed UKI (uki.py sign); the disk is made here, per host,
# because the root volume's key must be: a pre-encrypted image would give every host one volume key (the design and
# its discussion are on #61). In order, refusing at the first failure, nothing written before step 3:
#   1. the inputs: rootfs.tar's sha256 is its record's rootfs_sha256; the UKI's is its record's signed.image_sha256
#   2. the disk: the operator types its serial (lsblk), which must be --disk's; a disk holding data (partitions, or
#      any signature wipefs finds on the whole device) needs --wipe and the serial typed again; an install record
#      for this serial already in DIR is refused (move it away). DIR is made only after these checks
#   3. GPT: an ESP (FAT32, 1 GiB) and `regalia-root` (Linux root x86-64), the PARTLABEL the initrd's crypttab opens
#   4. LUKS2 (argon2id) on regalia-root, its volume key made HERE; the installer passphrase typed twice at the
#      console. It is the slot the README's steps replace: recovery-key.sh --enrol, the peer path, then
#      systemd-cryptenroll --wipe-slot=password
#   5. ext4 (label regalia-root-fs) inside it, rootfs.tar extracted with numeric owners; an empty /efi for the ESP
#   6. the ESP: the UKI at \EFI\Linux\<name>.efi and at the removable-media path \EFI\BOOT\BOOTX64.EFI, nothing else
#      (the per-host loader credentials and the membership chain come from enrolment, #66 B3)
#   7. a firmware entry for \EFI\Linux\<name>.efi, first in BootOrder, through bootnext.py (not with --no-efi-entry)
#   8. DIR/install-<serial>.json: the inputs' digests, the disk, the partition and LUKS UUIDs, the time. Nothing secret
#
# THE TEST MODE: with REGALIA_INSTALL_TEST=1, and only when --disk is a /dev/loopN backed by a regular file, the serial is not asked (a loop
# device has none), the passphrase comes from standard input (one line), and no firmware entry is made. On any other
# disk the variable is refused.
#
# CURRENT LIMITATIONS (stated, not hidden; the cross-cutting list is LIMITATIONS.md):
#   * NO RELEASE CHECK YET: the inputs are checked against their own build records, which nothing signs. Which
#     root-committed document names both the rootfs and the UKI is #61's open question 1; until it lands, the
#     operator compares the printed digests with the ceremony's.
#   * THE ROOT FILESYSTEM HAS NO RUNTIME INTEGRITY: LUKS2 keeps it confidential, not unaltered (dm-verity on /usr is
#     #61's next design).
#   * THE MIRROR IS NOT BOOTABLE YET (#544): the initrd has no mdadm and opens PARTLABEL=regalia-root, so --disk twice is
#     refused outside the test mode. Its firmware entries (one per ESP), keeping the ESPs in step on an update, and what a
#     degraded mirror means at boot and in the evidence are #544's next steps and its owner's questions 2-4.
#   * /efi relies on systemd-gpt-auto-generator mounting the ESP the stub booted from; not yet seen on a booted
#     installed disk (the QEMU boot of an installed disk is this slice's next step).
#   * The TPM is not touched: no clear, no owner authorization; enrolment does that.
#   * Not run on a DL360 yet.
set -euo pipefail
umask 077
export LC_ALL=C TZ=UTC PATH="/usr/sbin:/usr/bin:/sbin:/bin"
REPO="$(cd "$(dirname "$0")/../../.." && pwd -P)"     # the checkout this runs from: its bootnext.py makes the firmware entry
die(){ echo "install-host: $*" >&2; exit 2; }
say(){ echo "install-host: $*"; }
ESP_TYPE=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
ROOT_TYPE=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709        # Linux root (x86-64), the discoverable-partitions type
RAID_TYPE=A19D880F-05FC-4D3B-A006-743F0F84911E        # Linux RAID: a mirror's member
DISKS=() ROOTFS="" ROOTFS_RECORD="" UKI="" UKI_RECORD="" OUT="" WIPE=0 EFI_ENTRY=1
while [ $# -gt 0 ]; do
  case "$1" in
    --disk) DISKS+=("${2:-}"); shift 2 ;;
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
[ "${#DISKS[@]}" -ge 1 ] || die "--disk is required"
[ "${#DISKS[@]}" -le 2 ] || die "--disk is given once, or twice for a mirror; not ${#DISKS[@]} times"
for v in ROOTFS ROOTFS_RECORD UKI UKI_RECORD OUT; do [ -n "${!v}" ] || die "--$(tr '[:upper:]_' '[:lower:]-' <<< "$v") is required"; done
MIRROR=0; [ "${#DISKS[@]}" = 2 ] && MIRROR=1
for t in sfdisk wipefs losetup cryptsetup mkfs.ext4 mkfs.vfat tar python3 lsblk blkid udevadm; do command -v "$t" >/dev/null || die "$t is required"; done
[ "$MIRROR" = 0 ] || command -v mdadm >/dev/null || die "mdadm is required for a mirror"
for d in "${DISKS[@]}"; do [ -b "$d" ] || die "$d is not a block device"; done
# one disk named twice, by two paths, is one disk: compared as the kernel's device numbers
[ "$MIRROR" = 0 ] || [ "$(stat -Lc %t:%T "${DISKS[0]}")" != "$(stat -Lc %t:%T "${DISKS[1]}")" ] || die "the two --disk are the same disk"
DISK="${DISKS[0]}"
TEST=0
if [ "${REGALIA_INSTALL_TEST:-}" = 1 ]; then
  for d in "${DISKS[@]}"; do
    [[ "$d" =~ ^/dev/loop[0-9]+$ ]] || die "REGALIA_INSTALL_TEST is for a /dev/loopN only, never a host's disk"
    # ... and one backed by a FILE: a loop device over a real disk (losetup /dev/loopN /dev/sda) is that disk
    BACK="$(losetup -nO BACK-FILE "$d" 2>/dev/null | sed 's/[[:space:]]*$//')"
    [ -f "$BACK" ] && [ ! -L "$BACK" ] || die "REGALIA_INSTALL_TEST is for a loop device backed by a regular file; $d is backed by '${BACK:-nothing}'"
  done
  TEST=1; EFI_ENTRY=0
fi
# A MIRROR IS NOT BOOTABLE YET (#544): the image's initrd has no mdadm to assemble it, its crypttab opens
# PARTLABEL=regalia-root, and the unlock service answers that device's request only. Until those land, a mirrored
# install would leave a host that cannot boot, so only the test mode makes one.
[ "$MIRROR" = 0 ] || [ "$TEST" = 1 ] || die "a mirrored install is not bootable yet (regalia-kms#544: the initrd cannot assemble it): refused. Nothing was written"
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

# 2. each disk, by its serial typed at the console
ask(){ local prompt="$1" answer; read -r -p "$prompt" answer < /dev/tty; printf '%s' "$answer"; }
SERIALS=()
for d in "${DISKS[@]}"; do
  if [ "$TEST" = 0 ]; then
    s="$(lsblk -dno SERIAL "$d" 2>/dev/null | tr -d ' ')"
    [ -n "$s" ] || die "$d reports no serial: refused (an installer writes only to a disk it can name)"
    # the serial names the install record's file: plain characters only (it is the firmware's text)
    [[ "$s" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "$d's serial is not plain text ([A-Za-z0-9._-]): refused"
    [ "$(ask "Type the serial of the disk to install on ($d, $(lsblk -dno SIZE,MODEL "$d" | tr -s ' ')): ")" = "$s" ] \
      || die "the serial typed is not $d's: nothing was written"
  else
    s="test-$(basename "$d")"
  fi
  SERIALS+=("$s")
done
# two disks reporting one serial cannot be told apart, at the console or in the record
[ "$MIRROR" = 0 ] || [ "${SERIALS[0]}" != "${SERIALS[1]}" ] || die "the two disks report the same serial (${SERIALS[0]}): refused"
SERIAL="${SERIALS[0]}"
# data is a partition OR any signature on the whole device (a filesystem, a LUKS header, an LVM PV, an md member,
# a partition table with no partitions): either needs --wipe. A device whose signatures cannot be read is refused
for i in "${!DISKS[@]}"; do
  d="${DISKS[$i]}"
  SIGS="$(wipefs --noheadings "$d")" || die "cannot read $d's signatures (wipefs): refused"
  if [ -n "$(lsblk -no NAME "$d" | tail -n +2)" ] || [ -n "$SIGS" ]; then
    [ "$WIPE" = 1 ] || die "$d holds data (partitions or signatures): refused without --wipe"
    if [ "$TEST" = 0 ]; then
      [ "$(ask "$d holds data. Type its serial AGAIN to wipe it: ")" = "${SERIALS[$i]}" ] || die "not confirmed: nothing was written"
    fi
  fi
done
# the record is made last: one that exists would fail the install at its very end, the disk written and unrecorded
RECORD="$OUT/install-${SERIALS[0]}${SERIALS[1]:++${SERIALS[1]}}.json"     # one serial, or the two joined by +
[ ! -e "$RECORD" ] && [ ! -L "$RECORD" ] || die "$RECORD exists: move it away first (it is the previous install's evidence)"
mkdir -p "$OUT"

# the firmware entry needs a UEFI-booted live medium: said before anything is written, not at step 7 (regalia-kms-ed)
[ "$EFI_ENTRY" = 0 ] || [ -d /sys/firmware/efi ] \
  || die "this live medium was not booted in UEFI mode: boot it in UEFI mode (or give --no-efi-entry and make the entry later). Nothing was written"

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

MD="/dev/md/regalia-root" MADE_MD=0
# an md of that name already on this system (an earlier install's, assembled again by udev) is someone else's: refused
# before anything is written, and never stopped by this run
[ "$MIRROR" = 0 ] || [ ! -e "$MD" ] || die "$MD already exists on this system (mdadm --detail $MD): refused. Nothing was written"
W="$(mktemp -d /run/regalia-install.XXXXXX)"
MAPPED="regalia-install-$$"
cleanup(){
  for m in "$W/esp" "$W/root"; do mountpoint -q "$m" 2>/dev/null && umount "$m"; done
  [ -e "/dev/mapper/$MAPPED" ] && cryptsetup close "$MAPPED"
  [ "$MADE_MD" = 1 ] && [ -e "$MD" ] && mdadm --stop "$MD" >/dev/null 2>&1
  rm -rf --one-file-system -- "$W"
  unset PASSPHRASE
}
trap cleanup EXIT

# 3. GPT. One disk: an ESP and regalia-root. A mirror: on each disk an ESP and a Linux RAID member
# (regalia-root-a, regalia-root-b); the md RAID1 over the two members is regalia-root, and LUKS2 goes on it
part(){ local p; p="$(lsblk -lnpo NAME "$1" | sed -n "$((1 + $2))p")"; [ -b "$p" ] || die "partition $2 of $1 did not appear"; printf '%s' "$p"; }
ESP_DEVS=() MEMBERS=()
for i in "${!DISKS[@]}"; do
  d="${DISKS[$i]}"
  wipefs -aq "$d"
  if [ "$MIRROR" = 0 ]; then
    say "partitioning $d (GPT: ESP 1 GiB, regalia-root)"
    sfdisk -q "$d" <<EOF
label: gpt
size=1GiB, type=$ESP_TYPE, name="esp"
type=$ROOT_TYPE, name="regalia-root"
EOF
  else
    side="$([ "$i" = 0 ] && echo a || echo b)"
    say "partitioning $d (GPT: ESP 1 GiB, regalia-root-$side, a mirror's member)"
    sfdisk -q "$d" <<EOF
label: gpt
size=1GiB, type=$ESP_TYPE, name="esp-$side"
type=$RAID_TYPE, name="regalia-root-$side"
EOF
  fi
done
udevadm settle
for d in "${DISKS[@]}"; do ESP_DEVS+=("$(part "$d" 1)"); MEMBERS+=("$(part "$d" 2)"); done
ESP_DEV="${ESP_DEVS[0]}"
if [ "$MIRROR" = 0 ]; then
  ROOT_DEV="${MEMBERS[0]}"
else
  # metadata 1.2 (at the start of each member): nothing outside the md reads a member as a filesystem
  say "RAID1 $MD over ${MEMBERS[*]} (metadata 1.2)"
  mdadm --create "$MD" --level=1 --raid-devices=2 --metadata=1.2 --name=regalia-root --homehost=any --run --quiet "${MEMBERS[@]}"
  MADE_MD=1
  udevadm settle
  ROOT_DEV="$MD"
fi

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

# 6. the ESP (each disk's, on a mirror): the UKI at its own place and at the removable-media fallback, nothing else.
# The firmware reads an ESP before anything can assemble an md, so a mirror's ESPs are two copies, not a RAID: the
# same files, each read back against the UKI's digest
umount "$W/root"
for e in "${ESP_DEVS[@]}"; do
  mkfs.vfat -F 32 -n ESP "$e" >/dev/null
  mount -o umask=0077 "$e" "$W/esp"
  mkdir -p "$W/esp/EFI/Linux" "$W/esp/EFI/BOOT"
  cp "$UKI" "$W/esp/EFI/Linux/$NAME.efi"
  cp "$UKI" "$W/esp/EFI/BOOT/BOOTX64.EFI"
  sync
  for f in "EFI/Linux/$NAME.efi" EFI/BOOT/BOOTX64.EFI; do
    [ "$(sha256sum < "$W/esp/$f" | cut -d' ' -f1)" = "$UKI_SHA" ] || die "the ESP $e's $f is not the UKI after writing"
  done
  umount "$W/esp"
done

ESP_UUID="$(blkid -s PARTUUID -o value "$ESP_DEV")"
LUKS_UUID="$(cryptsetup luksUUID "$ROOT_DEV")"
cryptsetup close "$MAPPED"
if [ "$MIRROR" = 0 ]; then
  ROOT_UUID="$(blkid -s PARTUUID -o value "$ROOT_DEV")"
else
  ESP_UUIDS=() MEMBER_UUIDS=()
  for e in "${ESP_DEVS[@]}"; do ESP_UUIDS+=("$(blkid -s PARTUUID -o value "$e")"); done
  for m in "${MEMBERS[@]}"; do MEMBER_UUIDS+=("$(blkid -s PARTUUID -o value "$m")"); done
  MD_UUID="$(mdadm --detail --export "$MD" | sed -n 's/^MD_UUID=//p')"
  [ -n "$MD_UUID" ] || die "cannot read $MD's UUID"
fi

# 7. the firmware entry (a mirror's two entries, one per ESP, are #544's next step; refused above outside the test mode)
[ "$MIRROR" = 0 ] || [ "$EFI_ENTRY" = 0 ] || die "a mirror's firmware entries are not made yet (regalia-kms#544)"
if [ "$EFI_ENTRY" = 1 ]; then
  [ -d /sys/firmware/efi ] || die "this system was not booted by UEFI: no firmware entry can be made (--no-efi-entry to skip)"
  # through bootnext.py, the one place that writes the firmware's boot variables (its guard test): created only if no
  # entry has the label, and read back active, loading the UKI, first in BootOrder
  ( cd "$REPO" && python3 -Es -m deploy.baremetal.bootnext install-entry --disk "$DISK" --part 1 --partuuid "$ESP_UUID" --label "regalia $NAME" \
      --loader "\\EFI\\Linux\\$NAME.efi" ) \
    || die "the firmware entry was not made (above; the disk IS installed): an old 'regalia $NAME' entry from a previous install is removed first, then rerun the entry by hand (KERNEL-UPDATE 3.1)"
fi

# 8. the install record
# (values as arguments, never pasted into the code: a disk's serial is the firmware's text)
if [ "$MIRROR" = 0 ]; then
python3 -I - "$RECORD" "$SERIAL" "$ROOTFS_SHA" "$NAME" "$UKI_SHA" "$ESP_UUID" "$ROOT_UUID" "$LUKS_UUID" "$EFI_ENTRY" <<'PY'
import json, sys, time
path, serial, rootfs, name, uki, esp, root, luks, entry = sys.argv[1:]
record = {"schema": "regalia.install/v1", "disk_serial": serial, "rootfs_sha256": rootfs, "uki": name, "uki_sha256": uki,
          "esp_partuuid": esp, "root_partuuid": root, "luks_uuid": luks, "efi_entry": entry == "1",
          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
with open(path, "x") as f:
    json.dump(record, f, indent=1, sort_keys=True)
    f.write("\n")
PY
say "installed on $DISK ($SERIAL): ESP $ESP_UUID, regalia-root $ROOT_UUID (LUKS $LUKS_UUID). Record: $RECORD"
else
python3 -I - "$RECORD" "$ROOTFS_SHA" "$NAME" "$UKI_SHA" "$MD_UUID" "$LUKS_UUID" "$EFI_ENTRY" \
  "${SERIALS[0]}" "${ESP_UUIDS[0]}" "${MEMBER_UUIDS[0]}" "${SERIALS[1]}" "${ESP_UUIDS[1]}" "${MEMBER_UUIDS[1]}" <<'PY'
import json, sys, time
path, rootfs, name, uki, md, luks, entry = sys.argv[1:8]
disks = [{"disk_serial": s, "esp_partuuid": e, "member_partuuid": m} for s, e, m in (sys.argv[8:11], sys.argv[11:14])]
record = {"schema": "regalia.install/v2", "layout": "raid1", "disks": disks, "md_uuid": md, "rootfs_sha256": rootfs, "uki": name,
          "uki_sha256": uki, "luks_uuid": luks, "efi_entry": entry == "1", "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
with open(path, "x") as f:
    json.dump(record, f, indent=1, sort_keys=True)
    f.write("\n")
PY
say "installed a mirror on ${DISKS[*]} (${SERIALS[*]}): md $MD_UUID (LUKS $LUKS_UUID), ESPs ${ESP_UUIDS[*]}. Record: $RECORD"
fi
say "next, on the booted host: recovery-key.sh --enrol, the enrolment, then wipe the installer passphrase (README)"
