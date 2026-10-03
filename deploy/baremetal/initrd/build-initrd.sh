#!/usr/bin/env bash
# build-initrd.sh — build the KMS host initrd REPRODUCIBLY, from pinned inputs (regalia-kms#248).
#
#   sudo deploy/baremetal/initrd/build-initrd.sh --snapshot 20261003T121500Z --client REGALIA-UNLOCK --out DIR
#
# Every builder runs this itself, on its own machine, and never copies another builder's initrd: the
# image's build record carries the initrd's sha256, and `uki.py sign` requires the two builders' records
# to be identical (#224), so two independent builds that agree are what make the initrd checked by
# more than one machine (KERNEL-UPDATE.md, step 1.0).
#
# THE INPUTS, all pinned, all named in the build record it writes:
#   --snapshot TIME   one snapshot.debian.org timestamp: Debian 13's main suite, its updates and its
#                     security suite, as they were at that time (so every builder gets the same versions)
#   --epoch N         SOURCE_DATE_EPOCH, every timestamp in the image (default: the snapshot's time)
#   --client FILE     the unlock client, built with: CGO_ENABLED=0 go build -trimpath -buildvcs=false
#   this repository   the client's units, the boot mesh script, the dracut module (by sha256)
#   PACKAGES below    the root tree dracut runs in: nothing else, so nothing else can reach the initrd
#
# THE ENVIRONMENT is not an input: the caller's locale, time zone, umask and variables never reach the
# build (it runs with umask 022 and, in the root tree, `env -i` with a fixed PATH, LC_ALL=C and TZ=UTC).
#
# OUT: DIR/initrd.img, DIR/initrd-build.json (regalia.initrd-build/v1: the inputs and the result), and
# DIR/initrd-listing.txt (one line per entry: path, type, mode, uid, gid, size, sha256, link).
# Measured on two runners, in two directories and with another locale, time zone and umask
# (e2e/initrd-reproducible.sh): byte-identical.
set -euo pipefail
umask 022
export LC_ALL=C TZ=UTC PATH="/usr/sbin:/usr/bin:/sbin:/bin"
cd "$(dirname "$0")/../../.."
SCHEMA="regalia.initrd-build/v1"
SUITE=trixie
PACKAGES="systemd-sysv,udev,kmod,linux-image-amd64,dracut,systemd-cryptsetup,cryptsetup-bin,wireguard-tools,nftables,iproute2,e2fsprogs,tpm2-tools,libtss2-tcti-device0t64"
REPO_FILES=(deploy/baremetal/initrd/wg-boot deploy/baremetal/initrd/regalia-unlock.service deploy/baremetal/initrd/regalia-unlock-relay.service
            deploy/baremetal/initrd/regalia-unlock-core.socket deploy/baremetal/initrd/regalia-wg-boot.service
            deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab)
die(){ echo "build-initrd: $*" >&2; exit 2; }
SNAPSHOT="" EPOCH="" CLIENT="" OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --snapshot) SNAPSHOT="${2:-}"; shift 2 ;;
    --epoch) EPOCH="${2:-}"; shift 2 ;;
    --client) CLIENT="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    *) die "unknown argument $1 (--snapshot TIME --client FILE --out DIR [--epoch N])" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run as root (the root tree is built and chrooted into)"
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "--snapshot must be a snapshot.debian.org time, e.g. 20261003T121500Z"
SNAPSHOT_EPOCH="$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2}T${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}Z" +%s)" \
  || die "--snapshot $SNAPSHOT is not a time"
EPOCH="${EPOCH:-$SNAPSHOT_EPOCH}"
[[ "$EPOCH" =~ ^[0-9]{1,11}$ ]] || die "--epoch must be seconds since 1970"
[ -f "$CLIENT" ] && [ -r "$CLIENT" ] || die "--client must name the built unlock client"
[ -n "$OUT" ] || die "--out DIR is required"
command -v mmdebstrap >/dev/null || die "mmdebstrap is required"
KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
[ -r "$KEYRING" ] || die "$KEYRING is required (debian-archive-keyring)"
mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || die "--out $OUT must be empty"

W="$(mktemp -d /var/tmp/regalia-initrd.XXXXXX)"
MOUNTED=()
cleanup(){
  for m in "${MOUNTED[@]:-}"; do [ -n "$m" ] && umount -R "$m" 2>/dev/null; done
  if grep -q " $W" /proc/mounts; then echo "build-initrd: something is still mounted under $W: it is NOT removed" >&2
  else rm -rf --one-file-system -- "$W"; fi
}
trap cleanup EXIT
ROOT="$W/root"
MAIN="https://snapshot.debian.org/archive/debian/$SNAPSHOT"
SECURITY="https://snapshot.debian.org/archive/debian-security/$SNAPSHOT"
SOURCES=("deb [signed-by=$KEYRING] $MAIN $SUITE main" "deb [signed-by=$KEYRING] $MAIN $SUITE-updates main"
         "deb [signed-by=$KEYRING] $SECURITY $SUITE-security main")
echo "### the root tree: Debian $SUITE (main, updates, security) as of $SNAPSHOT"
# a snapshot's Release file is past its Valid-Until, which only a snapshot may be
env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$EPOCH" mmdebstrap --variant=minbase \
  --aptopt='Acquire::Check-Valid-Until "false"' --aptopt='Acquire::Retries "5"' --include="$PACKAGES" \
  "$SUITE" "$ROOT" "${SOURCES[@]}" >"$W/mmdebstrap.log" 2>&1 || { tail -40 "$W/mmdebstrap.log"; die "mmdebstrap failed"; }

install -D -m 0755 "$CLIENT" "$ROOT/usr/bin/regalia-unlock"
install -D -m 0755 deploy/baremetal/initrd/wg-boot "$ROOT/usr/lib/regalia/wg-boot"
install -m 0644 deploy/baremetal/initrd/regalia-unlock.service deploy/baremetal/initrd/regalia-unlock-relay.service \
  deploy/baremetal/initrd/regalia-unlock-core.socket deploy/baremetal/initrd/regalia-wg-boot.service "$ROOT/usr/lib/systemd/system/"
install -D -m 0755 deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/module-setup.sh"
install -m 0644 deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/crypttab"
# what this repository adds gets the fixed time too, as a package's files have theirs
find "$ROOT/usr/bin/regalia-unlock" "$ROOT/usr/lib/regalia" "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock" \
  "$ROOT"/usr/lib/systemd/system/regalia-* -exec touch -h -d "@$EPOCH" {} +

for fs in proc sys dev; do mount --bind "/$fs" "$ROOT/$fs"; MOUNTED+=("$ROOT/$fs"); done
KVER="$(find "$ROOT/lib/modules" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort -V | tail -1)"
[ -n "$KVER" ] || die "the root tree holds no kernel modules"
# DRACUT_NO_MKNOD=1 on every builder: dracut sets it by itself inside a container (systemd-detect-virt -c) and
# then leaves out /dev/null, kmsg, console, random and urandom, so the archive depended on the build host
# (measured, #248). Without them the image boots the same: the kernel's built-in initramfs holds /dev/console,
# and systemd mounts devtmpfs on /dev before anything else.
inroot(){ chroot "$ROOT" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC HOME=/root SOURCE_DATE_EPOCH="$EPOCH" DRACUT_NO_MKNOD=1 "$@"; }
echo "### dracut --reproducible, kernel $KVER, SOURCE_DATE_EPOCH=$EPOCH"
inroot dracut --force --reproducible --no-hostonly --no-hostonly-cmdline --add regalia-unlock --kver "$KVER" /tmp/initrd.img \
  >"$W/dracut.log" 2>&1 || { tail -40 "$W/dracut.log"; die "dracut failed"; }
cp "$ROOT/tmp/initrd.img" "$OUT/initrd.img"

mkdir "$ROOT/tmp/unpacked"
inroot sh -c 'cd /tmp/unpacked && lsinitrd --unpack /tmp/initrd.img' >/dev/null 2>&1 || die "cannot unpack the initrd"
# (no mtime: the unpacked copy carries the time it was unpacked; the archive's own times are covered by its sha256)
(cd "$ROOT/tmp/unpacked" && find . -mindepth 1 -printf '%P\t%y\t%m\t%U\t%G\t%s\t%l\n' | sort | while IFS=$'\t' read -r p y m u g s l; do
   h=""; [ "$y" = f ] && h="$(sha256sum < "$p" | cut -d' ' -f1)"
   printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$y" "$m" "$u" "$g" "$s" "$h" "$l"
 done) > "$OUT/initrd-listing.txt"
inroot dpkg-query -W -f '${Package}=${Version}\n' | sort > "$W/packages.txt"
DRACUT_VERSION="$(inroot dpkg-query -W -f '${Version}' dracut)"
for fs in dev sys proc; do umount -R "$ROOT/$fs"; done; MOUNTED=()

# the build record: what went in and what came out
{
  echo "schema=$SCHEMA"; echo "snapshot=$SNAPSHOT"; echo "source_date_epoch=$EPOCH"; echo "suite=$SUITE"
  echo "kernel=$KVER"; echo "dracut=$DRACUT_VERSION"; echo "packages_requested=$PACKAGES"
  echo "client_sha256=$(sha256sum < "$CLIENT" | cut -d' ' -f1)"
  for f in "${REPO_FILES[@]}"; do echo "file=$f $(sha256sum < "$f" | cut -d' ' -f1)"; done
  echo "packages_sha256=$(sha256sum < "$W/packages.txt" | cut -d' ' -f1)"
  echo "initrd_sha256=$(sha256sum < "$OUT/initrd.img" | cut -d' ' -f1)"
  echo "initrd_size=$(stat -c %s "$OUT/initrd.img")"
  echo "initrd_entries=$(wc -l < "$OUT/initrd-listing.txt")"
} > "$W/record.txt"
python3 -Es - "$W/record.txt" "$W/packages.txt" "$OUT/initrd-build.json" <<'PY'
import json, sys
record, files = {}, {}
for line in open(sys.argv[1]):
    key, _, value = line.rstrip("\n").partition("=")
    if key == "file":
        path, digest = value.split(" ")
        files[path] = digest
    else:
        record[key] = int(value) if key in ("source_date_epoch", "initrd_size", "initrd_entries") else value
record["packages_requested"] = record["packages_requested"].split(",")
record["repository_files"] = files
record["packages"] = [l.strip() for l in open(sys.argv[2]) if l.strip()]
with open(sys.argv[3], "w") as f:
    json.dump(record, f, indent=1, sort_keys=True)
    f.write("\n")
PY
echo "build-initrd: $(python3 -Es -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["initrd_sha256"], r["initrd_size"], "bytes,", r["initrd_entries"], "entries, dracut", r["dracut"], "kernel", r["kernel"])' "$OUT/initrd-build.json")"
