#!/usr/bin/env bash
# install-host.sh — put the KMS host image on THIS host's disk: the verity /usr (A/B), and /var on this host's own LUKS2
# volume key (#61: the installer slice, then the dm-verity design of 2026-10-05, its second slice).
#
#   sudo deploy/baremetal/image/install-host.sh --disk /dev/sdX --usr usr.erofs --usr-verity usr.verity \
#        --rootfs-record rootfs-build.json --uki NAME.efi --uki-record NAME.signed.json --out DIR [--wipe] [--no-efi-entry]
#
# Run as root from a live medium ON the host (a Debian 13 live USB, the iLO's virtual media). The reproducible
# artifacts are usr.erofs and usr.verity (build-rootfs.sh: /usr as erofs and its dm-verity hash tree, the root hash
# and its PARTUUIDs in rootfs-build.json's "usr") and the signed UKI (uki.py sign). /var is made here, per host,
# because its volume key must be: a pre-encrypted image would give every host one volume key (#61).
#
# THE LAYOUT (#61 comment 18, "the disk layout"; the type GUIDs are the discoverable-partitions spec's, as
# `systemd-id128 show` lists them):
#   1 esp            EFI System (C12A7328-…)          FAT32, 1 GiB: the UKI, nothing else
#   2 usr-a          Linux /usr x86-64 (8484680C-…)    usr.erofs; PARTUUID = the root hash's first 128 bits
#   3 usr-a-verity   /usr verity x86-64 (77FF5F63-…)   usr.verity; PARTUUID = the root hash's last 128 bits
#   4 usr-b          Linux /usr x86-64                 reserved for the updater's next image: its superblock area zeroed
#   5 usr-b-verity   /usr verity x86-64                reserved, the same
#   6 regalia-root   Linux /var (4D21B016-…)           LUKS2 (argon2id), ext4 inside (label regalia-var): /var, EMPTY
# usr-a and usr-b are USR_SIZE each, the verity partitions USR_VERITY_SIZE each (below), so the updater writes B into
# the same space A has. The four usr partitions carry the spec's read-only flag (GPT attribute 60). The PARTUUIDs of
# usr-a and usr-a-verity are what systemd-veritysetup-generator derives from `usrhash=` (the UKI's command line), so
# the UKI finds its own /usr pair with no fstab; usr-b's are random until the updater writes B and sets B's.
# PARTLABEL regalia-root is kept: the initrd's crypttab opens it (deploy/baremetal/initrd/dracut/90regalia-unlock).
#
# In order, refusing at the first failure, nothing written before step 3:
#   1. the inputs: the UKI's sha256 is its record's signed.image_sha256; rootfs-build.json's "usr" is read whole (the
#      root hash, the two PARTUUIDs, which must BE its halves, the sizes, the sha256s, the verity parameters);
#      usr.erofs and usr.verity have those sizes and sha256s; then `veritysetup verify` reads every block of
#      usr.erofs against usr.verity and the root hash. Each image must fit its partition
#   2. the disk: the operator types its serial (lsblk), which must be --disk's; it must hold the layout and a /var of
#      VAR_MIN at least; a disk holding data (partitions, or any signature wipefs finds on the whole device) needs
#      --wipe and the serial typed again; an install record for this serial already in DIR is refused (move it away).
#      DIR is made only after these checks
#   3. GPT, as above; each new partition's signatures wiped, and the first MiB of usr-b and usr-b-verity zeroed, so
#      no earlier install's image is left looking like one
#   4. usr.erofs to usr-a and usr.verity to usr-a-verity, then read back FROM THE PARTITIONS: each one's PARTUUID is
#      the record's, its first <size> bytes have the image's sha256, and `veritysetup verify` passes on the two
#      partitions with the root hash (what was checked in step 1 is what was written)
#   5. LUKS2 (argon2id) on regalia-root, its volume key made HERE; the installer passphrase typed twice at the
#      console. It is the slot the README's steps replace: recovery-key.sh --enrol, the peer path, then
#      systemd-cryptenroll --wipe-slot=password. ext4 inside it, labelled regalia-var, left empty: rootfs.tar is not
#      extracted (the image's /var is made at boot by tmpfiles, the dm-verity design)
#   6. the ESP: the UKI at \EFI\Linux\<name>.efi and at the removable-media path \EFI\BOOT\BOOTX64.EFI, nothing else
#      (the per-host loader credentials and the membership chain come from enrolment, #66 B3)
#   7. a firmware entry for \EFI\Linux\<name>.efi, first in BootOrder, through bootnext.py, carrying NO options
#      (95 on #61: with Secure Boot off, systemd-stub takes a loader's command line over the UKI's, so an entry's
#      options could name another usrhash=; bootnext reads the entry back and refuses one with optional data).
#      Not with --no-efi-entry
#   8. DIR/install-<serial>.json (regalia.install/v3): the inputs' digests, the root hash, the disk, every
#      partition's PARTUUID, the LUKS UUID, the sizes, the time. Nothing secret
#
# THE TEST MODE: with REGALIA_INSTALL_TEST=1, and only when --disk is a /dev/loopN backed by a regular file, the serial is not asked (a loop
# device has none), the passphrase comes from standard input (one line), and no firmware entry is made. On any other
# disk the variable is refused.
#
# CURRENT LIMITATIONS (stated, not hidden; the cross-cutting list is LIMITATIONS.md):
#   * NOT BOOTABLE YET: the layout is the dm-verity design's, but the initrd does not yet open it (systemd-veritysetup,
#     /var from the LUKS2 volume, / on tmpfs) and the UKI carries no usrhash= (the dm-verity design's next slice); so
#     this installer cannot yet check that the UKI names THIS root hash, and the QEMU boot (the slice after) is what
#     shows the two agree. Until then a host installed by it does not boot to the KMS.
#   * NO RELEASE CHECK YET: the inputs are checked against their own build records, which nothing signs. Which
#     root-committed document names both the /usr image and the UKI is #61's open question 1; until it lands, the
#     operator compares the printed root hash and UKI digest with the ceremony's.
#   * /var IS CONFIDENTIAL, NOT INTEGRITY-PROTECTED: LUKS2 keeps it secret, not unaltered (the design's limitation).
#   * /var's PARTUUID is random: systemd-gpt-auto-generator mounts a var-type partition only if its UUID is derived
#     from the machine ID, so it is opened and mounted by the initrd's crypttab (PARTLABEL=regalia-root) and fstab,
#     never by its type alone.
#   * usr-b IS RESERVED, NOT CLEARED: only its first MiB (where erofs and verity keep their superblocks) is zeroed.
#   * A MIRROR (--disk twice, #544) IS REFUSED: the verity layout on two disks would put the same PARTUUIDs on both,
#     and usrhash= names ONE partition pair; how a mirror holds the A/B /usr is #544's to decide.
#   * The TPM is not touched: no clear, no owner authorization; enrolment does that.
#   * Not run on a DL360 yet.
set -euo pipefail
umask 077
export LC_ALL=C TZ=UTC PATH="/usr/sbin:/usr/bin:/sbin:/bin"
REPO="$(cd "$(dirname "$0")/../../.." && pwd -P)"     # the checkout this runs from: its bootnext.py makes the firmware entry
die(){ echo "install-host: $*" >&2; exit 2; }
say(){ echo "install-host: $*"; }
# the discoverable-partitions spec's type GUIDs (systemd 257's `systemd-id128 show esp usr-x86-64 usr-x86-64-verity var`)
ESP_TYPE=C12A7328-F81F-11D2-BA4B-00A0C93EC93B
USR_TYPE=8484680C-9521-48C6-9C11-B0720656F69E         # Linux /usr (x86-64)
USR_VERITY_TYPE=77FF5F63-E7B6-4633-ACF4-1565B864C0E6  # Linux /usr verity (x86-64)
VAR_TYPE=4D21B016-B534-45C2-A9FB-5C16E091FD2D         # Linux /var
READ_ONLY="GUID:60"                                   # the spec's read-only flag, on the four usr partitions
MIB=$((1024 * 1024))
ESP_SIZE=$((1024 * MIB))
# Each usr slot. 4 GiB holds a /usr several times today's, so the updater's next image fits where A's did; the verity
# partition holds the hash tree of a WHOLE 4 GiB data partition (sha256, 4096-byte blocks: 32.3 MiB) with room for a
# wider hash. Changing either changes the layout every installed host has: the updater reads them from the GPT.
USR_SIZE=$((4096 * MIB))
USR_VERITY_SIZE=$((128 * MIB))
VAR_MIN=$((4096 * MIB))
DISKS=() USR="" USR_VERITY="" ROOTFS_RECORD="" UKI="" UKI_RECORD="" OUT="" WIPE=0 EFI_ENTRY=1
while [ $# -gt 0 ]; do
  case "$1" in
    --disk) DISKS+=("${2:-}"); shift 2 ;;
    --usr) USR="${2:-}"; shift 2 ;;
    --usr-verity) USR_VERITY="${2:-}"; shift 2 ;;
    --rootfs-record) ROOTFS_RECORD="${2:-}"; shift 2 ;;
    --uki) UKI="${2:-}"; shift 2 ;;
    --uki-record) UKI_RECORD="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --wipe) WIPE=1; shift ;;
    --no-efi-entry) EFI_ENTRY=0; shift ;;
    --rootfs) die "--rootfs: rootfs.tar is no longer installed; /usr is the verity image (--usr usr.erofs --usr-verity usr.verity, #61)" ;;
    *) die "unknown argument $1 (see the header)" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run as root"
[ "${#DISKS[@]}" -ge 1 ] || die "--disk is required"
[ "${#DISKS[@]}" = 1 ] || die "--disk is given once: a mirror (#544) of the verity layout is refused (the same PARTUUIDs on two disks; the header's limitations). Nothing was written"
for v in USR USR_VERITY ROOTFS_RECORD UKI UKI_RECORD OUT; do [ -n "${!v}" ] || die "--$(tr '[:upper:]_' '[:lower:]-' <<< "$v") is required"; done
for t in sfdisk wipefs losetup blockdev cryptsetup veritysetup mkfs.ext4 mkfs.vfat dd python3 lsblk blkid udevadm; do command -v "$t" >/dev/null || die "$t is required"; done
DISK="${DISKS[0]}"
[ -b "$DISK" ] || die "$DISK is not a block device"
TEST=0
if [ "${REGALIA_INSTALL_TEST:-}" = 1 ]; then
  [[ "$DISK" =~ ^/dev/loop[0-9]+$ ]] || die "REGALIA_INSTALL_TEST is for a /dev/loopN only, never a host's disk"
  # ... and one backed by a FILE: a loop device over a real disk (losetup /dev/loopN /dev/sda) is that disk
  BACK="$(losetup -nO BACK-FILE "$DISK" 2>/dev/null | sed 's/[[:space:]]*$//')"
  [ -f "$BACK" ] && [ ! -L "$BACK" ] || die "REGALIA_INSTALL_TEST is for a loop device backed by a regular file; $DISK is backed by '${BACK:-nothing}'"
  TEST=1; EFI_ENTRY=0
fi
NAME="$(basename "$UKI" .efi)"
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || die "the UKI's name '$NAME' is not a plain file name"
for f in "$USR" "$USR_VERITY" "$ROOTFS_RECORD" "$UKI" "$UKI_RECORD"; do [ -f "$f" ] || die "$f is not a file"; done

# 1. the inputs, against their records, before anything is written
UKI_SHA="$(sha256sum < "$UKI" | cut -d' ' -f1)"
UKI_WANT="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["signed"]["image_sha256"])' "$UKI_RECORD" 2>/dev/null)" || UKI_WANT=""
[ "$UKI_SHA" = "$UKI_WANT" ] || die "the UKI is not the file its signed record names (sha256 $UKI_SHA)"
# the record's "usr", read whole and judged in one place; its values come out as KEY=value lines of checked text only
USR_FIELDS="$(python3 -I - "$ROOTFS_RECORD" <<'PY'
import json, re, sys
try:
    record = json.load(open(sys.argv[1]))
    usr = record["usr"]
except Exception as e:
    sys.exit("rootfs-build.json has no readable \"usr\" (%s): built before the /usr image (#61)?" % type(e).__name__)
HEX64, COMMIT = re.compile(r"[0-9a-f]{64}"), re.compile(r"[0-9a-f]{40}([0-9a-f]{24})?")
def need(ok, why):
    if not ok:
        sys.exit("rootfs-build.json's usr: " + why)
roothash = usr.get("roothash")
need(isinstance(roothash, str) and HEX64.fullmatch(roothash), "roothash is not 64 lowercase hex")
def uuid(h): return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:32])
# systemd's convention: the data partition is the root hash's first 128 bits, the hash partition its last 128
need(usr.get("usr_partuuid") == uuid(roothash[:32]), "usr_partuuid %r is not the root hash's first 128 bits" % (usr.get("usr_partuuid"),))
need(usr.get("usr_verity_partuuid") == uuid(roothash[32:]), "usr_verity_partuuid %r is not the root hash's last 128 bits" % (usr.get("usr_verity_partuuid"),))
for k in ("erofs_sha256", "verity_sha256"):
    need(isinstance(usr.get(k), str) and HEX64.fullmatch(usr[k]), "%s is not 64 lowercase hex" % k)
for k in ("erofs_size", "verity_size"):
    need(type(usr.get(k)) is int and usr[k] > 0 and usr[k] % 4096 == 0, "%s is not a positive multiple of 4096" % k)
need((usr.get("verity_format"), usr.get("verity_hash"), usr.get("verity_data_block_size"), usr.get("verity_hash_block_size"))
     == (1, "sha256", 4096, 4096), "the verity parameters are not format 1, sha256, 4096/4096")
need(isinstance(record.get("commit"), str) and COMMIT.fullmatch(record["commit"]), "the record names no commit")
for k, v in (("ROOTHASH", roothash), ("USR_PARTUUID", usr["usr_partuuid"]), ("USR_VERITY_PARTUUID", usr["usr_verity_partuuid"]),
             ("EROFS_SHA", usr["erofs_sha256"]), ("VERITY_SHA", usr["verity_sha256"]), ("EROFS_SIZE", usr["erofs_size"]),
             ("VERITY_SIZE", usr["verity_size"]), ("COMMIT", record["commit"])):
    print("%s=%s" % (k, v))
PY
)" || die "the /usr image's record is refused (above): nothing was written"
field(){ sed -n "s/^$1=//p" <<< "$USR_FIELDS"; }
ROOTHASH="$(field ROOTHASH)" USR_PARTUUID="$(field USR_PARTUUID)" USR_VERITY_PARTUUID="$(field USR_VERITY_PARTUUID)"
EROFS_SHA="$(field EROFS_SHA)" VERITY_SHA="$(field VERITY_SHA)" EROFS_SIZE="$(field EROFS_SIZE)" VERITY_SIZE="$(field VERITY_SIZE)"
COMMIT="$(field COMMIT)"
[ "$(stat -Lc %s "$USR")" = "$EROFS_SIZE" ] && [ "$(sha256sum < "$USR" | cut -d' ' -f1)" = "$EROFS_SHA" ] \
  || die "usr.erofs is not the image its record names (size $(stat -Lc %s "$USR"), sha256 $(sha256sum < "$USR" | cut -d' ' -f1))"
[ "$(stat -Lc %s "$USR_VERITY")" = "$VERITY_SIZE" ] && [ "$(sha256sum < "$USR_VERITY" | cut -d' ' -f1)" = "$VERITY_SHA" ] \
  || die "usr.verity is not the hash tree its record names (size $(stat -Lc %s "$USR_VERITY"), sha256 $(sha256sum < "$USR_VERITY" | cut -d' ' -f1))"
# every block of the image against the hash tree and the root hash (userspace: no device-mapper, nothing opened)
veritysetup verify "$USR" "$USR_VERITY" "$ROOTHASH" >/dev/null 2>&1 \
  || die "veritysetup verify refuses usr.erofs and usr.verity under the root hash $ROOTHASH: nothing was written"
[ "$EROFS_SIZE" -le "$USR_SIZE" ] || die "usr.erofs ($EROFS_SIZE bytes) is larger than a usr partition ($USR_SIZE)"
[ "$VERITY_SIZE" -le "$USR_VERITY_SIZE" ] || die "usr.verity ($VERITY_SIZE bytes) is larger than a usr verity partition ($USR_VERITY_SIZE)"
say "inputs: /usr usrhash=$ROOTHASH (usr.erofs $EROFS_SHA), commit $COMMIT; UKI $NAME $UKI_SHA"
say "COMPARE the root hash and the UKI digest with the ceremony's before going on (no release check yet: the header's limitations)"

# 2. the disk, by its serial typed at the console
ask(){ local prompt="$1" answer; read -r -p "$prompt" answer < /dev/tty; printf '%s' "$answer"; }
if [ "$TEST" = 0 ]; then
  SERIAL="$(lsblk -dno SERIAL "$DISK" 2>/dev/null | tr -d ' ')"
  [ -n "$SERIAL" ] || die "$DISK reports no serial: refused (an installer writes only to a disk it can name)"
  # the serial names the install record's file: plain characters only (it is the firmware's text)
  [[ "$SERIAL" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "$DISK's serial is not plain text ([A-Za-z0-9._-]): refused"
  [ "$(ask "Type the serial of the disk to install on ($DISK, $(lsblk -dno SIZE,MODEL "$DISK" | tr -s ' ')): ")" = "$SERIAL" ] \
    || die "the serial typed is not $DISK's: nothing was written"
else
  SERIAL="test-$(basename "$DISK")"
fi
# the layout and a /var of VAR_MIN, plus 1 MiB at each end for the GPT and its backup
NEED=$((ESP_SIZE + 2 * (USR_SIZE + USR_VERITY_SIZE) + VAR_MIN + 2 * MIB))
HAVE="$(blockdev --getsize64 "$DISK")"
[ "$HAVE" -ge "$NEED" ] || die "$DISK is $HAVE bytes; the layout needs $NEED (ESP, two usr slots, a /var of $VAR_MIN): nothing was written"
# data is a partition OR any signature on the whole device (a filesystem, a LUKS header, an LVM PV, an md member,
# a partition table with no partitions): either needs --wipe. A device whose signatures cannot be read is refused
SIGS="$(wipefs --noheadings "$DISK")" || die "cannot read $DISK's signatures (wipefs): refused"
if [ -n "$(lsblk -no NAME "$DISK" | tail -n +2)" ] || [ -n "$SIGS" ]; then
  [ "$WIPE" = 1 ] || die "$DISK holds data (partitions or signatures): refused without --wipe"
  if [ "$TEST" = 0 ]; then
    [ "$(ask "$DISK holds data. Type its serial AGAIN to wipe it: ")" = "$SERIAL" ] || die "not confirmed: nothing was written"
  fi
fi
# the record is made last: one that exists would fail the install at its very end, the disk written and unrecorded
RECORD="$OUT/install-$SERIAL.json"
[ ! -e "$RECORD" ] && [ ! -L "$RECORD" ] || die "$RECORD exists: move it away first (it is the previous install's evidence)"
mkdir -p "$OUT"

# the firmware entry needs a UEFI-booted live medium: said before anything is written, not at step 7 (regalia-kms-ed)
[ "$EFI_ENTRY" = 0 ] || [ -d /sys/firmware/efi ] \
  || die "this live medium was not booted in UEFI mode: boot it in UEFI mode (or give --no-efi-entry and make the entry later). Nothing was written"

# the passphrase, before the disk is touched (typed twice, or one line on stdin in the test mode)
if [ "$TEST" = 1 ]; then
  IFS= read -r PASSPHRASE || die "the test mode reads the installer passphrase from standard input"
else
  IFS= read -r -s -p "Installer passphrase for the /var volume (replaced by the recovery key, then wiped): " PASSPHRASE < /dev/tty; echo
  IFS= read -r -s -p "Again: " again < /dev/tty; echo
  [ "$PASSPHRASE" = "$again" ] || die "the two passphrases differ: nothing was written"
  unset again
fi
[ "${#PASSPHRASE}" -ge 12 ] || die "the installer passphrase is shorter than 12 characters"

W="$(mktemp -d /run/regalia-install.XXXXXX)"
MAPPED="regalia-install-$$"
cleanup(){
  for m in "$W/esp" "$W/var"; do mountpoint -q "$m" 2>/dev/null && umount "$m"; done
  [ -e "/dev/mapper/$MAPPED" ] && cryptsetup close "$MAPPED"
  rm -rf --one-file-system -- "$W"
  unset PASSPHRASE
}
trap cleanup EXIT

# 3. GPT
say "partitioning $DISK (GPT: esp, usr-a, usr-a-verity, usr-b, usr-b-verity, regalia-root)"
wipefs -aq "$DISK"
sfdisk -q "$DISK" <<EOF
label: gpt
size=$((ESP_SIZE / MIB))MiB, type=$ESP_TYPE, name="esp"
size=$((USR_SIZE / MIB))MiB, type=$USR_TYPE, uuid=$USR_PARTUUID, name="usr-a", attrs="$READ_ONLY"
size=$((USR_VERITY_SIZE / MIB))MiB, type=$USR_VERITY_TYPE, uuid=$USR_VERITY_PARTUUID, name="usr-a-verity", attrs="$READ_ONLY"
size=$((USR_SIZE / MIB))MiB, type=$USR_TYPE, name="usr-b", attrs="$READ_ONLY"
size=$((USR_VERITY_SIZE / MIB))MiB, type=$USR_VERITY_TYPE, name="usr-b-verity", attrs="$READ_ONLY"
type=$VAR_TYPE, name="regalia-root"
EOF
udevadm settle
part(){ local p; p="$(lsblk -lnpo NAME "$DISK" | sed -n "$((1 + $1))p")"; [ -b "$p" ] || die "partition $1 of $DISK did not appear"; printf '%s' "$p"; }
ESP_DEV="$(part 1)" USR_A="$(part 2)" USR_A_VERITY="$(part 3)" USR_B="$(part 4)" USR_B_VERITY="$(part 5)" VAR_DEV="$(part 6)"
# nothing an earlier layout left at the same offsets may read as a filesystem, a LUKS header or a verity superblock
for p in "$ESP_DEV" "$USR_A" "$USR_A_VERITY" "$USR_B" "$USR_B_VERITY" "$VAR_DEV"; do wipefs -aq "$p"; done
for p in "$USR_B" "$USR_B_VERITY"; do dd if=/dev/zero of="$p" bs=1M count=1 conv=fsync status=none; done

# 4. the /usr image into slot A, then read back from the partitions themselves
say "writing usr.erofs to $USR_A and usr.verity to $USR_A_VERITY"
dd if="$USR" of="$USR_A" bs=4M iflag=fullblock conv=fsync status=none
dd if="$USR_VERITY" of="$USR_A_VERITY" bs=4M iflag=fullblock conv=fsync status=none
udevadm settle
for pv in "$USR_A $USR_PARTUUID $EROFS_SIZE $EROFS_SHA" "$USR_A_VERITY $USR_VERITY_PARTUUID $VERITY_SIZE $VERITY_SHA"; do
  read -r p uuid size sha <<< "$pv"
  [ "$(blkid -p -s PART_ENTRY_UUID -o value "$p" | tr '[:upper:]' '[:lower:]')" = "$uuid" ] || die "$p's PARTUUID is not $uuid after partitioning"
  [ "$(head -c "$size" "$p" | sha256sum | cut -d' ' -f1)" = "$sha" ] || die "$p does not read back as the image written to it"
done
veritysetup verify "$USR_A" "$USR_A_VERITY" "$ROOTHASH" >/dev/null 2>&1 || die "veritysetup verify refuses $USR_A and $USR_A_VERITY after writing"

# 5. /var: LUKS2, the volume key made here, and an empty ext4 inside
say "LUKS2 on $VAR_DEV (argon2id), its volume key from this host; ext4 regalia-var inside, empty"
printf '%s' "$PASSPHRASE" | cryptsetup luksFormat --type luks2 --pbkdf argon2id --batch-mode --label regalia-root --key-file - "$VAR_DEV"
printf '%s' "$PASSPHRASE" | cryptsetup open --key-file - "$VAR_DEV" "$MAPPED"
mkfs.ext4 -q -L regalia-var "/dev/mapper/$MAPPED"
LUKS_UUID="$(cryptsetup luksUUID "$VAR_DEV")"
cryptsetup close "$MAPPED"

# 6. the ESP: the UKI at its own place and at the removable-media fallback, nothing else, read back against its digest
mkfs.vfat -F 32 -n ESP "$ESP_DEV" >/dev/null
mkdir -p "$W/esp"
mount -o umask=0077 "$ESP_DEV" "$W/esp"
mkdir -p "$W/esp/EFI/Linux" "$W/esp/EFI/BOOT"
cp "$UKI" "$W/esp/EFI/Linux/$NAME.efi"
cp "$UKI" "$W/esp/EFI/BOOT/BOOTX64.EFI"
sync
for f in "EFI/Linux/$NAME.efi" EFI/BOOT/BOOTX64.EFI; do
  [ "$(sha256sum < "$W/esp/$f" | cut -d' ' -f1)" = "$UKI_SHA" ] || die "the ESP's $f is not the UKI after writing"
done
umount "$W/esp"

uuid_of(){ blkid -p -s PART_ENTRY_UUID -o value "$1" | tr '[:upper:]' '[:lower:]'; }
ESP_UUID="$(uuid_of "$ESP_DEV")" USR_B_UUID="$(uuid_of "$USR_B")" USR_B_VERITY_UUID="$(uuid_of "$USR_B_VERITY")" VAR_UUID="$(uuid_of "$VAR_DEV")"

# 7. the firmware entry, with no options (bootnext refuses an entry that reads back carrying any)
if [ "$EFI_ENTRY" = 1 ]; then
  [ -d /sys/firmware/efi ] || die "this system was not booted by UEFI: no firmware entry can be made (--no-efi-entry to skip)"
  # through bootnext.py, the one place that writes the firmware's boot variables (its guard test): created only if no
  # entry has the label, and read back active, loading the UKI, with no optional data, first in BootOrder
  ( cd "$REPO" && python3 -Es -m deploy.baremetal.bootnext install-entry --disk "$DISK" --part 1 --partuuid "$ESP_UUID" --label "regalia $NAME" \
      --loader "\\EFI\\Linux\\$NAME.efi" ) \
    || die "the firmware entry was not made (above; the disk IS installed): an old 'regalia $NAME' entry from a previous install is removed first, then rerun the entry by hand (KERNEL-UPDATE 3.1)"
fi

# 8. the install record
# (values as arguments, never pasted into the code: a disk's serial is the firmware's text)
python3 -I - "$RECORD" "$SERIAL" "$NAME" "$UKI_SHA" "$EFI_ENTRY" "$COMMIT" "$ROOTHASH" "$EROFS_SHA" "$VERITY_SHA" \
  "$ESP_UUID" "$USR_PARTUUID" "$USR_VERITY_PARTUUID" "$USR_B_UUID" "$USR_B_VERITY_UUID" "$VAR_UUID" "$LUKS_UUID" \
  "$USR_SIZE" "$USR_VERITY_SIZE" <<'PY'
import json, sys, time
(path, serial, name, uki, entry, commit, roothash, erofs, verity,
 esp, usr_a, usr_a_verity, usr_b, usr_b_verity, var, luks, usr_size, verity_size) = sys.argv[1:]
record = {"schema": "regalia.install/v3", "layout": "verity-ab", "disk_serial": serial, "uki": name, "uki_sha256": uki,
          "efi_entry": entry == "1", "rootfs_commit": commit,
          "usr": {"slot": "a", "roothash": roothash, "erofs_sha256": erofs, "verity_sha256": verity},
          "partuuids": {"esp": esp, "usr_a": usr_a, "usr_a_verity": usr_a_verity, "usr_b": usr_b, "usr_b_verity": usr_b_verity,
                        "var": var},
          "usr_partition_size": int(usr_size), "usr_verity_partition_size": int(verity_size), "luks_uuid": luks,
          "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
with open(path, "x") as f:
    json.dump(record, f, indent=1, sort_keys=True)
    f.write("\n")
PY
say "installed on $DISK ($SERIAL): usr-a usrhash=$ROOTHASH, /var LUKS $LUKS_UUID on $VAR_UUID. Record: $RECORD"
say "next, on the booted host: recovery-key.sh --enrol, the enrolment, then wipe the installer passphrase (README)"
