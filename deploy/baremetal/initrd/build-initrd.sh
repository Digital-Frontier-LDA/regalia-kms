#!/usr/bin/env bash
# build-initrd.sh — build the KMS host initrd REPRODUCIBLY, from pinned inputs (regalia-kms#248).
#
#   sudo deploy/baremetal/initrd/build-initrd.sh --snapshot 20261003T121500Z --out DIR [--go GO] [--epoch N] [--keyring FILE]
#
# Every builder runs this itself, on its own machine, from its own clone of the repository at the agreed
# commit, and never copies another builder's initrd, client or script: the image's build record carries the
# initrd's sha256, and `uki.py sign` requires the two builders' records to be identical (#224), so two
# independent builds that agree are what make the initrd checked by more than one machine
# (KERNEL-UPDATE.md, step 1.0).
#
# THE INPUTS, all pinned, all named in the build record it writes:
#   the commit        this repository's HEAD, which must be clean (no change, no untracked file): the client's
#                     source, its units, the boot mesh script, the dracut module, and this script itself
#   the Go toolchain  the exact release go.mod names (its toolchain line, else its go line), fetched and
#                     checksum-verified by Go itself (GOTOOLCHAIN): `--go` (default: the `go` on PATH) only
#                     launches it. The client is built HERE, CGO_ENABLED=0 -trimpath -buildvcs=false
#   --snapshot TIME   one snapshot.debian.org timestamp: Debian 13's main suite, its updates and its
#                     security suite, as they were at that time (so every builder gets the same versions)
#   --epoch N         SOURCE_DATE_EPOCH, every timestamp in the image (default: the snapshot's time)
#   PACKAGES below    the root tree dracut runs in: nothing else, so nothing else can reach the initrd
#
# THE ENVIRONMENT is not an input: the caller's locale, time zone, umask and variables never reach the
# build (umask 022; mmdebstrap, go and everything in the root tree run under `env -i` with a fixed PATH,
# LC_ALL=C and TZ=UTC). Only a proxy setting (GOPROXY, HTTPS_PROXY) passes to `go`: it decides where a module
# is fetched from, never what it holds (go.sum and the checksum database do).
#
# --keyring FILE: the Debian archive keyring the archive is verified with (default: the system's); it decides
# whether the archive is trusted, never what it holds.
#
# OUT, written last and all together: DIR/initrd.img, DIR/regalia-unlock (the client it compiled, which
# `uki.py build --unlock-client` takes), DIR/initrd-listing.txt (one line per entry: path,
# type, mode, uid, gid, size, links, sha256, link target) and DIR/initrd-build.json (regalia.initrd-build/v1: the inputs
# and the result), the record moved in last; a refusal leaves DIR empty.
# Measured on two runners and a Debian 13 container, in two directories and in a hostile environment
# (e2e/initrd-reproducible.sh): byte-identical.
set -euo pipefail
umask 022
CALLER_GO="$(command -v go || true)"
CALLER_GOPROXY="${GOPROXY:-}" CALLER_HTTPS_PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
export LC_ALL=C TZ=UTC PATH="/usr/sbin:/usr/bin:/sbin:/bin"
REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO"
SCRIPT="deploy/baremetal/initrd/build-initrd.sh"
SCHEMA="regalia.initrd-build/v1"
SUITE=trixie
PACKAGES="systemd-sysv,udev,kmod,linux-image-amd64,dracut,systemd-cryptsetup,cryptsetup-bin,wireguard-tools,nftables,iproute2,e2fsprogs,tpm2-tools,libtss2-tcti-device0t64"
REPO_FILES=("$SCRIPT" go.mod go.sum deploy/baremetal/initrd/wg-boot deploy/baremetal/initrd/regalia-unlock.service
            deploy/baremetal/initrd/regalia-unlock-relay.service deploy/baremetal/initrd/regalia-unlock-core.socket
            deploy/baremetal/initrd/regalia-wg-boot.service deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh
            deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab)
die(){ echo "build-initrd: $*" >&2; exit 2; }
SNAPSHOT="" EPOCH="" OUT="" GO="$CALLER_GO" KEYRING=/usr/share/keyrings/debian-archive-keyring.gpg
while [ $# -gt 0 ]; do
  case "$1" in
    --snapshot) SNAPSHOT="${2:-}"; shift 2 ;;
    --epoch) EPOCH="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    --go) GO="${2:-}"; shift 2 ;;
    --keyring) KEYRING="${2:-}"; shift 2 ;;
    *) die "unknown argument $1 (--snapshot TIME --out DIR [--go GO] [--epoch N] [--keyring FILE])" ;;
  esac
done
[ "$(id -u)" = 0 ] || die "run as root (the root tree is built and chrooted into)"
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "--snapshot must be a snapshot.debian.org time, e.g. 20261003T121500Z"
SNAPSHOT_EPOCH="$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2}T${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}Z" +%s)" \
  || die "--snapshot $SNAPSHOT is not a time"
EPOCH="${EPOCH:-$SNAPSHOT_EPOCH}"
[[ "$EPOCH" =~ ^[0-9]{1,11}$ ]] || die "--epoch must be seconds since 1970"
[ -n "$OUT" ] || die "--out DIR is required"
[ -n "$GO" ] && [ -x "$GO" ] || die "no go to launch the pinned toolchain with (put go on PATH, or --go FILE)"
for t in mmdebstrap git python3; do command -v "$t" >/dev/null || die "$t is required"; done
[ -r "$KEYRING" ] || die "$KEYRING is required (debian-archive-keyring, or --keyring FILE)"
KEYRING="$(readlink -f "$KEYRING")"

# the commit, clean: what this builder compiles and installs is exactly what the commit holds
# (run as root on a checkout another user owns: git is told to trust exactly this path, and reads without
# taking the index lock, so nothing under .git becomes root's)
repo_git(){ git -c safe.directory="$REPO" --no-optional-locks -C "$REPO" "$@"; }
COMMIT="$(repo_git rev-parse --verify HEAD)" || die "$REPO is not a git checkout"
[ -z "$(repo_git status --porcelain --untracked-files=all)" ] \
  || die "the checkout has changes or untracked files: build from a clean clone at the agreed commit"
GO_VERSION="$(sed -n 's/^toolchain \(go[0-9][0-9.]*\)$/\1/p' go.mod)"
[ -n "$GO_VERSION" ] || GO_VERSION="$(sed -n 's/^go \([0-9][0-9.]*\)$/go\1/p' go.mod)"
[[ "$GO_VERSION" =~ ^go1\.[0-9]+\.[0-9]+$ ]] || die "go.mod must name an exact Go release (go 1.X.Y or toolchain go1.X.Y), not '$GO_VERSION'"
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

echo "### the unlock client, by $GO_VERSION, from commit $COMMIT"
mkdir -p "$W/go/home" "$W/go/path" "$W/go/cache" "$W/go/mod" "$W/stage"
env -i PATH="$(dirname "$GO"):$PATH" LC_ALL=C TZ=UTC HOME="$W/go/home" GOPATH="$W/go/path" GOCACHE="$W/go/cache" GOMODCACHE="$W/go/mod" \
  GOTOOLCHAIN="$GO_VERSION" CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly \
  ${CALLER_GOPROXY:+GOPROXY="$CALLER_GOPROXY"} ${CALLER_HTTPS_PROXY:+HTTPS_PROXY="$CALLER_HTTPS_PROXY"} \
  "$GO" build -trimpath -buildvcs=false -o "$W/regalia-unlock" ./cmd/regalia-unlock >"$W/go.log" 2>&1 \
  || { tail -20 "$W/go.log"; die "the client did not build"; }
BUILT_BY="$("$GO" version "$W/regalia-unlock" | sed 's/^.*: //')"
[ "$BUILT_BY" = "$GO_VERSION" ] || die "the client was built by $BUILT_BY, not $GO_VERSION (go.mod's)"

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

install -D -m 0755 "$W/regalia-unlock" "$ROOT/usr/bin/regalia-unlock"
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
# --nohardlink: dracut otherwise runs util-linux `hardlink` over its tree BEFORE it clamps the mtimes, and hardlink
# links two identical files only when their mtimes are equal (measured, util-linux 2.41). Two identical files
# written during the build then become one hard-linked entry or two, as their writes fall in one second or two:
# the same files, another archive (#248, run 37145757537: 58682888 vs 58683049 bytes).
inroot dracut --force --reproducible --nohardlink --no-hostonly --no-hostonly-cmdline --add regalia-unlock --kver "$KVER" /tmp/initrd.img \
  >"$W/dracut.log" 2>&1 || { tail -40 "$W/dracut.log"; die "dracut failed"; }
cp "$ROOT/tmp/initrd.img" "$W/stage/initrd.img"

mkdir "$ROOT/tmp/unpacked"
inroot sh -c 'cd /tmp/unpacked && lsinitrd --unpack /tmp/initrd.img' >/dev/null 2>&1 || die "cannot unpack the initrd"
# (no mtime: the unpacked copy carries the time it was unpacked; the archive's own times are covered by its sha256.
# The link count IS listed: cpio restores hard links, and a file stored once or twice is another archive, #248)
(cd "$ROOT/tmp/unpacked" && find . -mindepth 1 -printf '%P\t%y\t%m\t%U\t%G\t%s\t%n\t%l\n' | sort | while IFS=$'\t' read -r p y m u g s n l; do
   h=""; [ "$y" = f ] && h="$(sha256sum < "$p" | cut -d' ' -f1)"
   printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$y" "$m" "$u" "$g" "$s" "$n" "$h" "$l"
 done) > "$W/stage/initrd-listing.txt"
# No hard-linked file: whether dracut links two identical files depended on the clock (#248), so a file with
# more than one link means --nohardlink was dropped or a dracut update links some other way. Refused.
linked="$(awk -F'\t' '$2 == "f" && $7 > 1 {print $1 " (" $7 " links)"}' "$W/stage/initrd-listing.txt" | head -5)"
[ -z "$linked" ] || die "the initrd holds hard-linked files, which make the archive depend on the build's timing (#248): $(tr '\n' ' ' <<< "$linked")"
inroot dpkg-query -W -f '${Package}=${Version}\n' | sort > "$W/packages.txt"
DRACUT_VERSION="$(inroot dpkg-query -W -f '${Version}' dracut)"
for fs in dev sys proc; do umount -R "$ROOT/$fs"; done; MOUNTED=()

# the build record: what went in and what came out
{
  echo "schema=$SCHEMA"; echo "commit=$COMMIT"; echo "go=$GO_VERSION"; echo "snapshot=$SNAPSHOT"; echo "source_date_epoch=$EPOCH"
  echo "suite=$SUITE"; echo "kernel=$KVER"; echo "dracut=$DRACUT_VERSION"; echo "packages_requested=$PACKAGES"
  echo "client_sha256=$(sha256sum < "$W/regalia-unlock" | cut -d' ' -f1)"
  for f in "${REPO_FILES[@]}"; do echo "file=$f $(sha256sum < "$f" | cut -d' ' -f1)"; done
  echo "packages_sha256=$(sha256sum < "$W/packages.txt" | cut -d' ' -f1)"
  echo "initrd_sha256=$(sha256sum < "$W/stage/initrd.img" | cut -d' ' -f1)"
  echo "initrd_size=$(stat -c %s "$W/stage/initrd.img")"
  echo "initrd_entries=$(wc -l < "$W/stage/initrd-listing.txt")"
} > "$W/record.txt"
python3 -I - "$W/record.txt" "$W/packages.txt" "$W/stage/initrd-build.json" <<'PY'
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
# into --out last, the record after the files it describes: a refusal before this leaves --out empty
cp "$W/regalia-unlock" "$W/stage/regalia-unlock"
for f in initrd.img regalia-unlock initrd-listing.txt initrd-build.json; do mv "$W/stage/$f" "$OUT/$f"; done
echo "build-initrd: $(python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["initrd_sha256"], r["initrd_size"], "bytes,", r["initrd_entries"], "entries, commit", r["commit"][:12], r["go"], "dracut", r["dracut"], "kernel", r["kernel"])' "$OUT/initrd-build.json")"
