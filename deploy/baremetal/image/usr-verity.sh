#!/usr/bin/env bash
# usr-verity.sh — the KMS host's /usr as a read-only erofs image under dm-verity, reproducibly (#61, the dm-verity
# design of 2026-10-05, first slice: the image; the owner requires dm-verity before the first ceremony, #297).
#
#   usr-verity.sh --usr DIR --seed HEX --epoch N --out DIR
#
# build-rootfs.sh runs it INSIDE its build tree, so mkfs.erofs and veritysetup are the snapshot's (erofs-utils and
# cryptsetup-bin, named in the build record), never the builder's. It can be run alone on any tree (e2e/usr-verity.sh).
#
# IN:  --usr DIR    the tree that becomes /usr (build-rootfs.sh: the host tree's /usr, bind-mounted read-only)
#      --seed HEX   what the salt and the UUIDs are derived from (build-rootfs.sh: the commit, 40 hex), so two builds
#                   of one commit make the same bytes and no per-build randomness enters the image
#      --epoch N    every inode's time (mkfs.erofs -T, --all-time) and the filesystem's build time; an inherited
#                   SOURCE_DATE_EPOCH is ignored
# OUT, written last and all together, in DIR (which must be empty, and lie outside --usr once both are resolved):
#      usr.erofs        erofs, 4096-byte blocks, uncompressed, no xattrs, UUID derived from the seed
#      usr.verity       its dm-verity hash tree (format 1, sha256, 4096/4096), salt and UUID derived from the seed
#      usr-verity.txt   key=value: the roothash, the two PARTUUIDs, the salt, the UUIDs, sizes, sha256s, tool versions
#
# THE PARTUUIDs follow systemd's convention (systemd-veritysetup-generator, usrhash=): the data partition's UUID is the
# first 128 bits of the root hash and the hash partition's the last 128, so `usrhash=<roothash>` on the signed UKI's
# command line finds its own /usr pair with no fstab, and an A/B pair is selected by which UKI booted. The installer
# and the updater must write exactly these (usr_partuuid, usr_verity_partuuid), never random ones.
#
# The derivations (a domain label, a NUL, the seed; sha256):
#   salt                 = sha256("regalia-kms usr-verity salt v1\0" + seed)              (64 hex)
#   verity superblock id = sha256("regalia-kms usr-verity uuid v1\0" + seed)[:16]         as an RFC 4122 v4 UUID
#   erofs UUID           = sha256("regalia-kms usr-erofs uuid v1\0" + seed)[:16]          as an RFC 4122 v4 UUID
#
# Before writing, the image is checked: fsck.erofs reads it, and veritysetup verify reads every block against the
# root hash (userspace, no device-mapper).
#
# CURRENT LIMITATIONS (stated, not hidden):
#   * NOT BOOTED YET: install-host.sh writes them to usr-a and usr-a-verity, but no initrd opens them and no UKI
#     carries usrhash= (the initrd/UKI and QEMU slices of #61's dm-verity design).
#   * NO XATTRS (-x-1): as rootfs.tar, which carries none either; so a file capability or a builder's security label
#     cannot enter the image. A program that would need a file capability does not get one.
#   * UNCOMPRESSED: the simplest layout to reproduce; compression is a later measurement if size matters.
#   * The seed is the commit: a commit that changes nothing in /usr still changes the salt and so the root hash.
set -euo pipefail
umask 022
export LC_ALL=C TZ=UTC PATH="/usr/sbin:/usr/bin:/sbin:/bin"
die(){ echo "usr-verity: $*" >&2; exit 2; }
USR="" SEED="" EPOCH="" OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --usr) USR="${2:-}"; shift 2 ;;
    --seed) SEED="${2:-}"; shift 2 ;;
    --epoch) EPOCH="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    *) die "unknown argument $1 (--usr DIR --seed HEX --epoch N --out DIR)" ;;
  esac
done
[ -n "$USR" ] && [ -d "$USR" ] && [ ! -L "$USR" ] || die "--usr must be a directory (not a link): '$USR'"
[[ "$SEED" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]] || die "--seed must be a commit: 40 or 64 lowercase hex, not '$SEED'"
[[ "$EPOCH" =~ ^[0-9]{1,11}$ ]] || die "--epoch must be seconds since 1970, not '$EPOCH'"
[ -n "$OUT" ] && [ -d "$OUT" ] || die "--out must be an existing directory: '$OUT'"
[ -z "$(ls -A "$OUT")" ] || die "--out $OUT must be empty"
# --out must lie outside --usr, after resolving both (a symlink, .., or a relative path cannot hide it): the staging
# directory is made inside --out, and inside --usr mkfs.erofs would put it, a random name and all, into the image
USR_REAL="$(realpath -e -- "$USR")" && OUT_REAL="$(realpath -e -- "$OUT")" || die "--usr and --out must resolve"
case "$OUT_REAL/" in "$USR_REAL"/*) die "--out $OUT ($OUT_REAL) lies inside --usr $USR ($USR_REAL)" ;; esac
for t in mkfs.erofs fsck.erofs veritysetup sha256sum; do command -v "$t" >/dev/null || die "$t is required"; done

derive(){ printf 'regalia-kms %s v1\0%s' "$1" "$SEED" | sha256sum | cut -d' ' -f1; }
as_uuid(){ printf '%s-%s-%s-%s-%s' "${1:0:8}" "${1:8:4}" "${1:12:4}" "${1:16:4}" "${1:20:12}"; }
v4_uuid(){   # the first 128 bits of $1, with the RFC 4122 version (4) and variant (10xx) bits set
  local h="$1" variant
  variant="$(printf '%x' $(( (0x${h:16:1} & 3) | 8 )))"
  as_uuid "${h:0:12}4${h:13:3}${variant}${h:17:15}"
}
SALT="$(derive usr-verity\ salt)"
VERITY_UUID="$(v4_uuid "$(derive usr-verity\ uuid)")"
EROFS_UUID="$(v4_uuid "$(derive usr-erofs\ uuid)")"

W="$(mktemp -d "$OUT/.usr-verity.XXXXXX")"
trap 'rm -rf --one-file-system -- "$W"' EXIT

# the filesystem: 4096-byte blocks named (the default is the BUILDER's page size), every time the epoch, no xattrs
# SOURCE_DATE_EPOCH is removed from its environment: mkfs.erofs reads it after its options, so an inherited one would
# override -T/--all-time and the image would disagree with the record's source_date_epoch
env -u SOURCE_DATE_EPOCH mkfs.erofs -d0 -b4096 -x-1 -T"$EPOCH" --all-time -U"$EROFS_UUID" "$W/usr.erofs" "$USR" >"$W/mkfs.log" 2>&1 \
  || { cat "$W/mkfs.log" >&2; die "mkfs.erofs failed"; }
DATA_SIZE="$(stat -c %s "$W/usr.erofs")"
[ "$DATA_SIZE" -gt 0 ] && [ $((DATA_SIZE % 4096)) = 0 ] || die "usr.erofs is $DATA_SIZE bytes, not a whole number of 4096-byte blocks"
fsck.erofs "$W/usr.erofs" >"$W/fsck.log" 2>&1 || { cat "$W/fsck.log" >&2; die "fsck.erofs refuses the image just made"; }

# the hash tree: every parameter named, none defaulted
veritysetup format --format=1 --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
  --salt="$SALT" --uuid="$VERITY_UUID" --root-hash-file="$W/roothash" "$W/usr.erofs" "$W/usr.verity" >"$W/format.log" 2>&1 \
  || { cat "$W/format.log" >&2; die "veritysetup format failed"; }
ROOTHASH="$(tr -d '\n' < "$W/roothash")"
[[ "$ROOTHASH" =~ ^[0-9a-f]{64}$ ]] || die "veritysetup gave no sha256 root hash ('$ROOTHASH')"
grep -qi "^Root hash:[[:space:]]*$ROOTHASH\$" "$W/format.log" || die "the root hash file and veritysetup's report disagree"
veritysetup verify "$W/usr.erofs" "$W/usr.verity" "$ROOTHASH" >"$W/verify.log" 2>&1 \
  || { cat "$W/verify.log" >&2; die "veritysetup verify refuses the image just made"; }
chmod 0644 "$W/usr.erofs" "$W/usr.verity"     # veritysetup makes its file 0600: both are public build outputs

{
  echo "schema=regalia.usr-verity/v1"
  echo "seed=$SEED"
  echo "source_date_epoch=$EPOCH"
  echo "roothash=$ROOTHASH"
  echo "usr_partuuid=$(as_uuid "${ROOTHASH:0:32}")"
  echo "usr_verity_partuuid=$(as_uuid "${ROOTHASH:32:32}")"
  echo "verity_salt=$SALT"
  echo "verity_uuid=$VERITY_UUID"
  echo "verity_hash=sha256"
  echo "verity_format=1"
  echo "verity_data_block_size=4096"
  echo "verity_hash_block_size=4096"
  echo "erofs_uuid=$EROFS_UUID"
  echo "erofs_size=$DATA_SIZE"
  echo "erofs_sha256=$(sha256sum < "$W/usr.erofs" | cut -d' ' -f1)"
  echo "verity_size=$(stat -c %s "$W/usr.verity")"
  echo "verity_sha256=$(sha256sum < "$W/usr.verity" | cut -d' ' -f1)"
  echo "mkfs_erofs=$(mkfs.erofs -V 2>&1 | head -1)"
  echo "veritysetup=$(veritysetup --version 2>&1 | head -1)"
} > "$W/usr-verity.txt"
for f in usr.erofs usr.verity usr-verity.txt; do mv "$W/$f" "$OUT/$f"; done
echo "usr-verity: roothash $ROOTHASH, usr.erofs $DATA_SIZE bytes"
