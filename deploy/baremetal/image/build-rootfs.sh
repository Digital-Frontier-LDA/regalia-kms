#!/usr/bin/env bash
# build-rootfs.sh — build the KMS host's ROOT FILESYSTEM reproducibly, from pinned inputs (#61, first slice).
#
#   sudo deploy/baremetal/image/build-rootfs.sh --snapshot 20261003T121500Z --out DIR [--go GO] [--epoch N] [--keyring FILE]
#
# As build-initrd.sh does for the initrd: every builder runs this itself, from its own clean clone at the agreed
# commit, and two builders' archives must be identical. The design is on #61.
#
# THE INPUTS, all pinned, all named in the build record:
#   the commit        this repository's HEAD, exactly (repo-git.sh: no change, no untracked file, no bytecode;
#                     its git configuration held to what a clone writes; read as its owner)
#   --snapshot TIME   one snapshot.debian.org time: Debian 13's main, updates and security suites as they were
#   the keyring       the pinned Debian archive keyring (debverify.py KEYRING_SHA256), fetched by hash if not given
#   the Go toolchain  the exact release go.mod names, fetched and checksum-verified by Go (GOTOOLCHAIN)
#   etcd              etcd.pin: upstream's tag, the commit it must be, and upstream's Go release for it (ADR-0002 D32;
#                     why not Debian's etcd-server: deploy/baremetal/ETCD.md). Built from source in the BUILD tree as
#                     upstream's build_lib.sh does, its modules verified by its go.sum and the checksum database
#   PACKAGES          deploy/baremetal/image/packages.txt's [packages], each with its reason, derived from what the
#                     host runs and checked in CI (tests/test_baremetal_rootfs_packages.py)
#
# TWO TREES from the same snapshot:
#   BUILD  gcc, libc6-dev, libpcsclite-dev, pkg-config (and erofs-utils, cryptsetup-bin for the /usr image, below):
#          packages.txt's [built] programs are compiled IN it, so the
#          cgo link (the -tags piv daemon's PC/SC) is against the snapshot's libraries, never the builder's. The
#          toolchain and the modules are fetched outside it first (go.sum and the checksum database verify them);
#          inside it nothing reaches the network (GOPROXY=off, GOTOOLCHAIN=local, the module cache read-only).
#   HOST   mmdebstrap --variant=minbase with exactly [packages], then from the commit: the deploy package at
#          /usr/lib/regalia-kms (every unit's WorkingDirectory), the units, sysusers.d and tmpfiles.d, the daemon's
#          AppArmor profile, and the [built] programs at their paths. systemd-sysusers runs in it, so the system
#          users exist in the image. What it STARTS is units-enabled.txt, enabled under /usr (#61 K61V-4: /etc is a tmpfs,
#          empty when PID 1 loads units), with a "disable *" preset so the first-boot preset pass every boot runs enables
#          nothing more; dpkg's database is moved to /usr/lib/sysimage/dpkg (owner decision q-18 = A).
#
# THE HERMETIC /usr (#61's dm-verity design of 2026-10-05; the owner requires it before the first ceremony, #297): the
#   host tree's /etc is also copied to /usr/share/factory/etc, so /usr alone holds everything a booted host runs and
#   the /etc it starts from; then usr-verity.sh, run INSIDE the build tree (its erofs-utils and cryptsetup-bin are the
#   snapshot's), makes /usr an erofs image and its dm-verity hash tree, salt and UUIDs derived from the commit.
#
# OUT, written last and all together: DIR/rootfs.tar (sorted, numeric owners, every mtime clamped to the epoch, pax
# with no atime or ctime), DIR/rootfs-listing.txt (path, type, mode, uid, gid, size, sha256, link),
# DIR/usr.erofs and DIR/usr.verity (the /usr image and its hash tree), and DIR/rootfs-build.json
# (regalia.rootfs-build/v1: the inputs, the package set with versions, each built program's sha256 and Go release,
# the repository files' sha256, and "usr": the root hash, the two PARTUUIDs derived from it, the salt, the UUIDs, the
# images' sizes and sha256s and the tools' versions). A refusal leaves DIR empty.
#
# CURRENT LIMITATIONS (stated, not hidden; the cross-cutting list is LIMITATIONS.md):
#   * NOT A BOOTABLE DISK YET. No partitions, LUKS2, crypttab, ESP, kernel/UKI pairing, network configuration,
#     node.json or first-boot step: later slices of #61. The node units (regalia-sync, admission, etcd, the audit
#     shippers) are not enabled by the image, and an operator's `systemctl enable` writes the tmpfs /etc, gone at the next
#     boot: their enablement after enrolment is open (README.md's steps predate the verity /usr).
#   * THE /usr IMAGE IS INSTALLED, NOT YET BOOTED: install-host.sh writes usr.erofs and usr.verity to the A/B usr
#     partitions (rootfs.tar is no longer extracted); the initrd's systemd-veritysetup, usrhash= on the UKI and the
#     boot from them are the next slices of the dm-verity design. /usr/share/factory/etc is copied, but no tmpfiles rule populates a tmpfs /etc from it yet,
#     and what else lives outside /usr is the /etc and /var inventory's (etc-inventory.txt).
#   * NO HARDENING beyond the units' own sandboxes: AppArmor profiles other than the daemon's, sysctl, sshd policy,
#     removing unwanted binaries (#61's baseline) are later slices.
#   * PACKAGES ARE AUTHENTICATED BY APT ONLY: every .deb is checked by apt against the snapshot's signed index with
#     the pinned keyring. The independent per-file check build-initrd.sh makes (debverify, #246) is not run on the
#     host tree.
#   * MEASURED ONLY WHERE STATED: e2e/rootfs-reproducible.sh, in CI on GitHub's runner. The cgo link's
#     reproducibility is measured there, not argued; another builder, another snapshot, another measurement.
#   * NETWORK: snapshot.debian.org and the Go module proxy and checksum database; no offline build.
#   * THE BUILD RECORD IS UNSIGNED, as build-initrd.sh's.
#   * THE TREE BUILDER IS THE BUILDER'S: mmdebstrap (and the apt it drives to fetch) come from the build host, not the
#     snapshot. Its version is recorded (rootfs-build.json "mmdebstrap"), not pinned; two builds on one host cannot
#     show a drift there, a rebuild elsewhere would.
#   * DATA FILES are checked to exist only where packages.txt lists them; one nobody lists is missed until a node
#     trips on it (#457).
#   * CHECKED ONCE, USED LATER: the checkout is checked before the build (build-initrd.sh's limitation applies).
set -euo pipefail
umask 022
CALLER_GO="$(command -v go || true)"
CALLER_GOPROXY="${GOPROXY:-}" CALLER_HTTPS_PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
export LC_ALL=C TZ=UTC PATH="/usr/sbin:/usr/bin:/sbin:/bin"
REPO="$(cd "$(dirname "$0")/../../.." && pwd -P)"     # the real path: what is checked is what is read (#390)
cd "$REPO"
SCRIPT="deploy/baremetal/image/build-rootfs.sh"
LIST="deploy/baremetal/image/packages.txt"
SCHEMA="regalia.rootfs-build/v1"
SUITE=trixie
BUILD_PACKAGES="gcc,libc6-dev,libpcsclite-dev,pkg-config,erofs-utils,cryptsetup-bin"   # the last two: the /usr image
PIN="deploy/baremetal/image/etcd.pin"
ENABLED="deploy/baremetal/image/units-enabled.txt"
PRESET="deploy/baremetal/image/regalia-kms.preset"
REPO_FILES=("$SCRIPT" "$LIST" "$PIN" "$ENABLED" "$PRESET" deploy/baremetal/image/usr-verity.sh deploy/baremetal/initrd/repo-git.sh deploy/baremetal/initrd/tree-retry.sh deploy/baremetal/debverify.py e2e/lib/debian-keyring.sh go.mod go.sum)
die(){ echo "build-rootfs: $*" >&2; exit 2; }
SNAPSHOT="" EPOCH="" OUT="" GO="$CALLER_GO" KEYRING=""
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
[ "$(id -u)" = 0 ] || die "run as root (the trees are built and chrooted into)"
[[ "$SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "--snapshot must be a snapshot.debian.org time, e.g. 20261003T121500Z"
SNAPSHOT_EPOCH="$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2}T${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}Z" +%s)" \
  || die "--snapshot $SNAPSHOT is not a time"
EPOCH="${EPOCH:-$SNAPSHOT_EPOCH}"
[[ "$EPOCH" =~ ^[0-9]{1,11}$ ]] || die "--epoch must be seconds since 1970"
[ -n "$OUT" ] || die "--out DIR is required"
[ -n "$GO" ] && [ -x "$GO" ] || die "no go to launch the pinned toolchain with (put go on PATH, or --go FILE)"
for t in mmdebstrap git python3 gpgv curl tar; do command -v "$t" >/dev/null || die "$t is required"; done
[ -z "$KEYRING" ] || [ -r "$KEYRING" ] || die "--keyring $KEYRING cannot be read"

# the commit, clean, read as its owner (build-initrd.sh's rules, the same file)
# shellcheck source=deploy/baremetal/initrd/repo-git.sh
. "$REPO/deploy/baremetal/initrd/repo-git.sh"
# shellcheck source=deploy/baremetal/initrd/tree-retry.sh
. "$REPO/deploy/baremetal/initrd/tree-retry.sh"
repo_git_check || die "the checkout is refused (above)"
echo "build-rootfs: the checkout is read as uid $(repo_git_uid) (top $(stat -c %u "$REPO"), .git $(stat -c %u "$REPO/.git"))"
COMMIT="$(repo_git rev-parse --verify HEAD)" || die "$REPO is not a git checkout"
repo_git_clean || die "the checkout is not exactly commit $COMMIT (above)"
GO_VERSION="$(sed -n 's/^toolchain \(go[0-9][0-9.]*\)$/\1/p' go.mod)"
[ -n "$GO_VERSION" ] || GO_VERSION="$(sed -n 's/^go \([0-9][0-9.]*\)$/go\1/p' go.mod)"
[[ "$GO_VERSION" =~ ^go1\.[0-9]+\.[0-9]+$ ]] || die "go.mod must name an exact Go release, not '$GO_VERSION'"

# packages.txt, read by the same rules the CI test holds it to: [packages] (Debian's) and [built] (ours)
SPEC="$(python3 -I - "$LIST" <<'PY'
import re, sys
sections, section = {"packages": [], "built": [], "upstream": []}, None
for number, raw in enumerate(open(sys.argv[1]), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    m = re.fullmatch(r"\[([a-z-]+)\]", line)
    if m:
        section = m.group(1)
        continue
    if section in sections:
        fields = [f.strip() for f in line.split("|")]
        if len(fields) != 3 or not fields[0] or not fields[2]:
            raise SystemExit("packages.txt line %d: not 'name | what | why'" % number)
        sections[section].append(fields)
names = [f[0] for f in sections["packages"]]
if not all(re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", n) for n in names):
    raise SystemExit("packages.txt: a [packages] name is not a Debian package name")
print("PACKAGES " + ",".join(names))
for f in sections["packages"]:
    for w in f[1].split():
        if w != "-":
            print("PROVIDES " + w)
for f in sections["upstream"]:
    if f[0] != "etcd" or not all(re.fullmatch(r"/usr/bin/[a-z0-9-]+", w) for w in f[1].split()):
        raise SystemExit("packages.txt: [upstream] %r is not 'etcd | /usr/bin/<name> ... | why' (etcd.pin is the one upstream)" % f[0])
    for w in f[1].split():
        print("PROVIDES " + w)
for f in sections["built"]:
    if not re.fullmatch(r"cmd/[a-z0-9-]+", f[0]) or not re.fullmatch(r"/usr/s?bin/[a-z0-9-]+", f[1]):
        raise SystemExit("packages.txt: [built] %r is not 'cmd/<name> | /usr/(s)bin/<name> | why'" % f[0])
    print("BUILT %s %s" % (f[0], f[1]))
PY
)" || die "$LIST cannot be read (above)"
PACKAGES="$(sed -n 's/^PACKAGES //p' <<< "$SPEC")"
mapfile -t PROVIDES < <(sed -n 's/^PROVIDES //p' <<< "$SPEC")
mapfile -t BUILT < <(sed -n 's/^BUILT //p' <<< "$SPEC")
[ -n "$PACKAGES" ] && [ "${#BUILT[@]}" -gt 0 ] || die "$LIST names no packages or no built programs"
mkdir -p "$OUT"
[ -z "$(ls -A "$OUT")" ] || die "--out $OUT must be empty"

W="$(mktemp -d /var/tmp/regalia-rootfs.XXXXXX)"
TREE_RETRY_BASE="$W"                     # every tree retry_tree removes lies inside it (tree-retry.sh)
MOUNTED=()
cleanup(){
  for m in "${MOUNTED[@]:-}"; do [ -n "$m" ] && umount -R "$m" 2>/dev/null; done
  if grep -q " $W" /proc/mounts; then echo "build-rootfs: something is still mounted under $W: it is NOT removed" >&2
  else rm -rf --one-file-system -- "$W"; fi
}
trap cleanup EXIT
mkdir -p "$W/stage" "$W/go/home" "$W/go/path" "$W/go/cache" "$W/go/mod"

# the keyring, by hash, before anything is fetched with it (#246)
[ -n "$KEYRING" ] || KEYRING="$(e2e/lib/debian-keyring.sh "$W/keyring")" || die "the pinned Debian archive keyring could not be fetched"
KEYRING="$(readlink -f "$KEYRING")"
PINNED_KEYRING="$(sed -n 's/^KEYRING_SHA256 = "\([0-9a-f]\{64\}\)"$/\1/p' deploy/baremetal/debverify.py)"
[ -n "$PINNED_KEYRING" ] || die "deploy/baremetal/debverify.py names no KEYRING_SHA256"
[ "$(sha256sum < "$KEYRING" | cut -d' ' -f1)" = "$PINNED_KEYRING" ] \
  || die "$KEYRING is not the pinned Debian archive keyring (sha256 $PINNED_KEYRING, deploy/baremetal/debverify.py)"

MAIN="https://snapshot.debian.org/archive/debian/$SNAPSHOT"
SECURITY="https://snapshot.debian.org/archive/debian-security/$SNAPSHOT"
SOURCES=("deb [signed-by=$KEYRING] $MAIN $SUITE main" "deb [signed-by=$KEYRING] $MAIN $SUITE-updates main"
         "deb [signed-by=$KEYRING] $SECURITY $SUITE-security main")
tree(){   # tree DIR PACKAGES: a minbase tree of Debian $SUITE at the snapshot, with PACKAGES (a fetch that fails is
          # tried again into a new tree, tree-retry.sh, #503)
  retry_tree "$W/mmdebstrap-$(basename "$1").log" "$1" env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$EPOCH" \
    mmdebstrap --variant=minbase --aptopt='Acquire::Check-Valid-Until "false"' --aptopt='Acquire::Retries "5"' \
    --aptopt='Acquire::Retries::Delay "true"' --aptopt='APT::Install-Recommends "false"' \
    --include="$2" "$SUITE" "$1" "${SOURCES[@]}" \
    || { tail -40 "$W/mmdebstrap-$(basename "$1").log"; die "mmdebstrap failed for $(basename "$1")"; }
}

# ---- the toolchain and the modules, fetched OUTSIDE the build tree (verified by go.sum and the checksum database)
echo "### the Go toolchain ($GO_VERSION) and the modules, verified by Go"
goenv=(env -i PATH="$(dirname "$GO"):$PATH" LC_ALL=C TZ=UTC HOME="$W/go/home" GOPATH="$W/go/path" GOCACHE="$W/go/cache"
       GOMODCACHE="$W/go/mod" GOTOOLCHAIN="$GO_VERSION" GOFLAGS=-mod=readonly GOTELEMETRY=off
       ${CALLER_GOPROXY:+GOPROXY="$CALLER_GOPROXY"} ${CALLER_HTTPS_PROXY:+HTTPS_PROXY="$CALLER_HTTPS_PROXY"})
"${goenv[@]}" "$GO" mod download >"$W/go-download.log" 2>&1 || { tail -20 "$W/go-download.log"; die "the modules could not be fetched"; }
# the toolchain GOTOOLCHAIN selected: the one it downloaded into the module cache, or the launching go itself when
# that already is go.mod's release (it is then not downloaded). Either way, the release is checked
TOOLCHAIN="$("${goenv[@]}" "$GO" env GOROOT)" || die "the toolchain's GOROOT cannot be read"
[ -x "$TOOLCHAIN/bin/go" ] || die "the toolchain $GO_VERSION has no bin/go ($TOOLCHAIN)"
[ "$("${goenv[@]}" "$TOOLCHAIN/bin/go" env GOVERSION)" = "$GO_VERSION" ] || die "the toolchain at $TOOLCHAIN is not $GO_VERSION"

# ---- etcd (ADR-0002 D32): upstream's source at the pinned commit, its modules and its own Go release, all fetched
# and verified OUTSIDE the build tree, as the daemon's are (why upstream and not Debian's package: ETCD.md)
pin(){ sed -n "s/^$1=\(.*\)$/\1/p" "$PIN"; }
ETCD_REPO="$(pin ETCD_REPO)" ETCD_TAG="$(pin ETCD_TAG)" ETCD_COMMIT="$(pin ETCD_COMMIT)" ETCD_GO="$(pin ETCD_GO)"
[ "$ETCD_REPO" = https://github.com/etcd-io/etcd ] && [[ "$ETCD_TAG" =~ ^v3\.[0-9]+\.[0-9]+$ ]] && [[ "$ETCD_COMMIT" =~ ^[0-9a-f]{40}$ ]] \
  && [[ "$ETCD_GO" =~ ^go1\.[0-9]+\.[0-9]+$ ]] || die "$PIN must name upstream's repository, a v3 tag, its 40-hex commit and a Go release"
echo "### etcd $ETCD_TAG ($ETCD_COMMIT), its modules and $ETCD_GO, verified by git and Go"
mkdir -p "$W/etcd/home" "$W/etcd/path" "$W/etcd/cache" "$W/etcd/mod" "$W/etcd/src"
env -i PATH="$PATH" HOME="$W/etcd/home" GIT_TERMINAL_PROMPT=0 ${CALLER_HTTPS_PROXY:+HTTPS_PROXY="$CALLER_HTTPS_PROXY"} \
  git -c advice.detachedHead=false clone -q --depth 1 --branch "$ETCD_TAG" "$ETCD_REPO" "$W/etcd/git" >"$W/etcd-git.log" 2>&1 \
  || { tail -5 "$W/etcd-git.log"; die "etcd $ETCD_TAG could not be fetched"; }
# the tag is a name; the commit is what was reviewed. A tag moved upstream is refused, never followed
got="$(git -C "$W/etcd/git" rev-parse --verify 'HEAD^{commit}')"
[ "$got" = "$ETCD_COMMIT" ] || die "etcd's $ETCD_TAG is commit $got, not the pinned $ETCD_COMMIT: refused"
git -C "$W/etcd/git" archive --format=tar HEAD | tar -x -C "$W/etcd/src" || die "etcd's source could not be exported"
[ "go$(cat "$W/etcd/src/.go-version")" = "$ETCD_GO" ] && grep -qx "toolchain $ETCD_GO" "$W/etcd/src/server/go.mod" \
  || die "etcd $ETCD_TAG is not built with $ETCD_GO upstream (.go-version, server/go.mod): update $PIN"
etcdenv=(env -i PATH="$(dirname "$GO"):$PATH" LC_ALL=C TZ=UTC HOME="$W/etcd/home" GOPATH="$W/etcd/path" GOCACHE="$W/etcd/cache"
         GOMODCACHE="$W/etcd/mod" GOTOOLCHAIN="$ETCD_GO" GOFLAGS=-mod=readonly GOTELEMETRY=off
         ${CALLER_GOPROXY:+GOPROXY="$CALLER_GOPROXY"} ${CALLER_HTTPS_PROXY:+HTTPS_PROXY="$CALLER_HTTPS_PROXY"})
ETCD_PROGRAMS=(server:etcd etcdctl:etcdctl etcdutl:etcdutl)       # module directory : program, as upstream's build_lib.sh
for p in "${ETCD_PROGRAMS[@]}"; do
  (cd "$W/etcd/src/${p%%:*}" && "${etcdenv[@]}" "$GO" mod download) >>"$W/etcd-download.log" 2>&1 \
    || { tail -20 "$W/etcd-download.log"; die "etcd's ${p%%:*} modules could not be fetched"; }
done
ETCD_TOOLCHAIN="$(cd "$W/etcd/src/server" && "${etcdenv[@]}" "$GO" env GOROOT)" || die "etcd's toolchain's GOROOT cannot be read"
[ "$("${etcdenv[@]}" "$ETCD_TOOLCHAIN/bin/go" env GOVERSION)" = "$ETCD_GO" ] || die "the toolchain at $ETCD_TOOLCHAIN is not $ETCD_GO"

# ---- the BUILD tree: [built] compiled in it, against the snapshot's libraries
BUILD="$W/build"
echo "### the build tree: Debian $SUITE as of $SNAPSHOT, with $BUILD_PACKAGES"
tree "$BUILD" "$BUILD_PACKAGES"
mkdir -p "$BUILD/build/src" "$BUILD/build/gomod" "$BUILD/build/goroot" "$BUILD/build/cache" "$BUILD/build/home" "$BUILD/build/out" \
         "$BUILD/build/etcd-mod" "$BUILD/build/etcd-goroot" "$BUILD/build/etcd-cache"
cp -a "$W/etcd/src" "$BUILD/build/etcd"
repo_git archive --format=tar "$COMMIT" | tar -x -C "$BUILD/build/src" || die "the commit could not be exported"
# the module cache and the toolchain, read-only: nothing inside the tree can change what was verified outside it
for pair in "$W/go/mod:$BUILD/build/gomod" "$TOOLCHAIN:$BUILD/build/goroot" "$W/etcd/mod:$BUILD/build/etcd-mod" \
            "$ETCD_TOOLCHAIN:$BUILD/build/etcd-goroot"; do
  mount --bind "${pair%%:*}" "${pair#*:}"; MOUNTED+=("${pair#*:}")
  mount -o remount,bind,ro "${pair#*:}"
done
for fs in proc dev; do mount --bind "/$fs" "$BUILD/$fs"; MOUNTED+=("$BUILD/$fs"); done
inbuild(){ chroot "$BUILD" env -i PATH="/build/goroot/bin:/usr/bin:/bin" GOROOT=/build/goroot LC_ALL=C TZ=UTC \
             HOME=/build/home GOCACHE=/build/cache GOMODCACHE=/build/gomod GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly GOTELEMETRY=off \
             SOURCE_DATE_EPOCH="$EPOCH" "$@"; }
for entry in "${BUILT[@]}"; do
  read -r source path <<< "$entry"
  name="$(basename "$source")"
  tags="" cgo=0
  [ "$name" = regalia-kms ] && { tags="-tags piv"; cgo=1; }        # the production daemon is the piv build (#72 G2)
  echo "### $name (${tags:-no tags}, CGO_ENABLED=$cgo), by $GO_VERSION"
  # shellcheck disable=SC2086  # tags is one flag and its value, or nothing
  inbuild sh -c "cd /build/src && CGO_ENABLED=$cgo go build $tags -trimpath -buildvcs=false -o /build/out/$name ./$source" \
    >"$W/go-$name.log" 2>&1 || { tail -20 "$W/go-$name.log"; die "$name did not build"; }
  built_by="$(inbuild go version "/build/out/$name" | sed 's/^.*: //')"
  [ "$built_by" = "$GO_VERSION" ] || die "$name was built by $built_by, not $GO_VERSION (go.mod's)"
done
# GOAMD64 named, not defaulted: the instruction-set level is part of what was built (v1: any x86-64, the DL360s' too)
ETCD_GOAMD64=v1
# etcd, as upstream's scripts/build_lib.sh builds it (static, -trimpath, GitSHA stamped), by its own Go release
inetcd(){ chroot "$BUILD" env -i PATH="/build/etcd-goroot/bin:/usr/bin:/bin" GOROOT=/build/etcd-goroot LC_ALL=C TZ=UTC \
            HOME=/build/home GOCACHE=/build/etcd-cache GOMODCACHE=/build/etcd-mod GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=readonly \
            GOTELEMETRY=off GOAMD64="$ETCD_GOAMD64" SOURCE_DATE_EPOCH="$EPOCH" "$@"; }
for p in "${ETCD_PROGRAMS[@]}"; do
  echo "### ${p#*:} (etcd $ETCD_TAG, CGO_ENABLED=0), by $ETCD_GO"
  inetcd sh -c "cd /build/etcd/${p%%:*} && CGO_ENABLED=0 go build -trimpath -buildvcs=false \
                -ldflags=-X=go.etcd.io/etcd/api/v3/version.GitSHA=${ETCD_COMMIT:0:7} -o /build/out/${p#*:} ." \
    >"$W/go-${p#*:}.log" 2>&1 || { tail -20 "$W/go-${p#*:}.log"; die "${p#*:} did not build"; }
  built_by="$(inetcd go version "/build/out/${p#*:}" | sed 's/^.*: //')"
  [ "$built_by" = "$ETCD_GO" ] || die "${p#*:} was built by $built_by, not $ETCD_GO ($PIN)"
done
# (GOTELEMETRY=off: go's telemetry can leave a child running from the toolchain, which keeps its mount busy; CI's
# first run. A mount still busy after a few seconds is a refusal, said by name, never a lazy unmount)
for m in "${MOUNTED[@]}"; do
  for _ in 1 2 3 4 5; do umount -R "$m" 2>/dev/null && continue 2; sleep 1; done
  die "$m is still in use after the build: $(fuser -vm "$m" 2>&1 | tail -n +2 | tr -s ' ' | head -3 | tr '\n' ';')"
done; MOUNTED=()

# ---- the HOST tree: exactly [packages], then this commit's files
ROOT="$W/root"
echo "### the host tree: Debian $SUITE as of $SNAPSHOT, with packages.txt's $(tr ',' '\n' <<< "$PACKAGES" | wc -l) packages"
tree "$ROOT" "$PACKAGES"
SRC="$BUILD/build/src"
mkdir -p "$ROOT/usr/lib/regalia-kms" "$ROOT/usr/lib/sysusers.d" "$ROOT/usr/lib/tmpfiles.d" "$ROOT/etc/apparmor.d"
cp -a "$SRC/deploy" "$ROOT/usr/lib/regalia-kms/deploy"                                 # every unit's WorkingDirectory
(cd "$SRC/deploy/baremetal/units" && find . -mindepth 1 \( -type d -o -name '*.service' -o -name '*.timer' -o -name '*.path' -o -name '*.conf' \) \
   ! -name '*.sysusers.conf' ! -name '*.tmpfiles.conf' -print0 | sort -z | while IFS= read -r -d '' f; do
     if [ -d "$f" ]; then mkdir -p "$ROOT/usr/lib/systemd/system/$f"; else install -m 0644 "$f" "$ROOT/usr/lib/systemd/system/$f"; fi
   done)
install -m 0644 "$SRC/deploy/systemd/regalia-kms.service" "$ROOT/usr/lib/systemd/system/regalia-kms.service"
for f in "$SRC"/deploy/baremetal/units/*.sysusers.conf "$SRC"/deploy/systemd/*.sysusers.conf; do
  [ -e "$f" ] && install -m 0644 "$f" "$ROOT/usr/lib/sysusers.d/$(basename "$f" .sysusers.conf).conf"
done
for f in "$SRC"/deploy/baremetal/units/*.tmpfiles.conf; do
  [ -e "$f" ] && install -m 0644 "$f" "$ROOT/usr/lib/tmpfiles.d/$(basename "$f" .tmpfiles.conf).conf"
done
install -m 0644 "$SRC/deploy/baremetal/apparmor/usr.sbin.regalia-kms" "$ROOT/etc/apparmor.d/usr.sbin.regalia-kms"
for entry in "${BUILT[@]}"; do
  read -r source path <<< "$entry"
  install -D -m 0755 "$BUILD/build/out/$(basename "$source")" "$ROOT$path"
done
for p in "${ETCD_PROGRAMS[@]}"; do install -D -m 0755 "$BUILD/build/out/${p#*:}" "$ROOT/usr/bin/${p#*:}"; done
# the system users the units run as, in the image (systemd-sysusers allocates in a fixed order: reproducible)
# (SOURCE_DATE_EPOCH: /etc/shadow's last-change day is the epoch's, not the build's)
chroot "$ROOT" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C SOURCE_DATE_EPOCH="$EPOCH" systemd-sysusers >"$W/sysusers.log" 2>&1 \
  || { cat "$W/sysusers.log"; die "systemd-sysusers failed in the host tree"; }
# what a machine makes of itself at first boot, or a build leaves behind, is not the image's
: > "$ROOT/etc/machine-id"
rm -rf -- "$ROOT/var/lib/apt/lists" "$ROOT/var/cache/apt" "$ROOT/var/log/apt" "$ROOT/var/log/dpkg.log" "$ROOT/var/log/alternatives.log"
mkdir -p "$ROOT/var/lib/apt/lists/partial" "$ROOT/var/cache/apt/archives/partial"
rm -f -- "$ROOT"/etc/ssh/ssh_host_*_key "$ROOT"/etc/ssh/ssh_host_*_key.pub
# no apt sources in the image: a host is updated by a new image, never by apt (#61's design). mmdebstrap left the
# builder's own sources, which name the keyring at this build's temporary path (CI's third run: the one difference)
rm -f -- "$ROOT"/etc/apt/sources.list.d/*
printf '# The KMS host image is updated by a new image, never by apt (regalia-kms#61): no sources.\n' > "$ROOT/etc/apt/sources.list"

# the in-tree check: every command packages.txt says a package provides is there and executable (#457's
# limitation, closed from this side: a scan can miss a command, the image cannot)
echo "### every command packages.txt lists, in the host tree"
missing=()
for w in "${PROVIDES[@]}"; do
  case "$w" in
    py:*) chroot "$ROOT" env -i PATH=/usr/bin:/bin python3 -I -c "import ${w#py:}" 2>/dev/null || missing+=("$w") ;;
    *'*') ls "$ROOT"/usr/bin/"${w%\*}"* >/dev/null 2>&1 || missing+=("$w") ;;
    # a program (under a bin or sbin) must be executable, through its link if it is one; a data file (zone data, a
    # CA bundle: packages.txt's DATA FILES) must exist (regalia-kms-1e on #458)
    */bin/*|*/sbin/*) [ -x "$ROOT$w" ] || missing+=("$w") ;;
    /*) [ -e "$ROOT$w" ] || missing+=("$w") ;;
    *) chroot "$ROOT" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin sh -c "command -v '$w'" >/dev/null || missing+=("$w") ;;
  esac
done
[ "${#missing[@]}" = 0 ] || die "packages.txt says these are provided, and the host tree lacks them: ${missing[*]}"
chroot "$ROOT" dpkg-query -W -f '${Package}=${Version}\n' | sort > "$W/packages.txt"

# ---- what the image STARTS (#61 K61V-4): enablement under /usr, from units-enabled.txt. / is a tmpfs, so /etc is empty
# when PID 1 loads units: a link under /etc/systemd/system is never seen. Every link a package made there must be named
# in units-enabled.txt ([enabled], [alias] or [dropped]: a new one is a decision, not an accident); the [enabled] and
# [alias] lines become links under /usr/lib/systemd/system; then the image's /etc holds no enablement at all
echo "### the units the image starts, enabled under /usr ($ENABLED)"
ENABLE_SPEC="$(python3 -I - "$ENABLED" <<'PY'
import re, sys
UNIT, TARGET = re.compile(r"[a-zA-Z0-9:_.\\-]+(@[a-zA-Z0-9:_.\\-]*)?\.(service|socket|timer|path|target)"), re.compile(r"[a-z0-9-]+\.target")
sections, section = {"enabled": "ENABLE", "alias": "ALIAS", "dropped": "DROP"}, None
for number, raw in enumerate(open(sys.argv[1]), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    m = re.fullmatch(r"\[([a-z]+)\]", line)
    if m:
        section = m.group(1)
        if section not in sections:
            raise SystemExit("units-enabled.txt line %d: no section [%s]" % (number, section))
        continue
    fields = [f.strip() for f in line.split("|")]
    first = UNIT if section == "alias" else TARGET
    if section is None or len(fields) != 3 or not fields[2] or not first.fullmatch(fields[0]) or not UNIT.fullmatch(fields[1]):
        raise SystemExit("units-enabled.txt line %d: not '%s | unit | why'" % (number, "alias" if section == "alias" else "target"))
    print(sections[section], fields[0], fields[1])
PY
)" || die "$ENABLED cannot be read (above)"
UNITDIR="$ROOT/usr/lib/systemd/system"
unknown=()
while IFS= read -r l; do
  case "$l" in
    *.wants/*) grep -qxF -e "ENABLE ${l%%.wants/*} ${l#*.wants/}" -e "DROP ${l%%.wants/*} ${l#*.wants/}" <<< "$ENABLE_SPEC" || unknown+=("$l") ;;
    */*) unknown+=("$l") ;;
    *) grep -qxF "ALIAS $l $(basename "$(readlink "$ROOT/etc/systemd/system/$l")")" <<< "$ENABLE_SPEC" || unknown+=("$l") ;;
  esac
done < <(cd "$ROOT/etc/systemd/system" && find . -type l -printf '%P\n' | sort)
[ "${#unknown[@]}" = 0 ] || die "the packages enabled units under /etc/systemd/system that $ENABLED does not name (enable or drop each, with why): ${unknown[*]}"
while read -r kind a b; do
  case "$kind" in
    ENABLE)
      file="$b"; [[ "$b" =~ ^([^@]+@)[^.]+(\..+)$ ]] && file="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"      # an instance: its template
      [ -f "$UNITDIR/$file" ] || die "$ENABLED enables $b, and the image has no /usr/lib/systemd/system/$file"
      mkdir -p "$UNITDIR/$a.wants"
      if [ -L "$UNITDIR/$a.wants/$b" ]; then [ "$(readlink "$UNITDIR/$a.wants/$b")" = "../$file" ] || die "the image's $a.wants/$b names another unit"
      else ln -s "../$file" "$UNITDIR/$a.wants/$b"; fi ;;
    ALIAS)
      [ -f "$UNITDIR/$b" ] || die "$ENABLED aliases $a to $b, and the image has no /usr/lib/systemd/system/$b"
      [ ! -e "$UNITDIR/$a" ] && [ ! -L "$UNITDIR/$a" ] || die "the image already has /usr/lib/systemd/system/$a"
      ln -s "$b" "$UNITDIR/$a" ;;
  esac
done <<< "$ENABLE_SPEC"
find "$ROOT/etc/systemd/system" -type l -delete
find "$ROOT/etc/systemd/system" -mindepth 1 -type d -empty -delete
rm -rf -- "$ROOT/var/lib/systemd/deb-systemd-helper-enabled" "$ROOT/var/lib/systemd/deb-systemd-helper-masked"
# every boot is a first boot (/etc/machine-id is missing when PID 1 starts), and PID 1 then applies the preset policy:
# the image's is "disable *" (regalia-kms.preset), shown here doing nothing to the tree, as PID 1 will do it to /etc
install -D -m 0644 "$PRESET" "$ROOT/usr/lib/systemd/system-preset/00-regalia-kms.preset"
chroot "$ROOT" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C systemctl --root=/ preset-all --preset-mode=enable-only >"$W/preset.log" 2>&1 \
  || { cat "$W/preset.log"; die "systemctl preset-all failed in the host tree"; }
made="$(cd "$ROOT/etc/systemd/system" && find . -mindepth 1 -printf '%P ' 2>/dev/null)"
[ -z "$made" ] || die "the preset pass a first boot runs enabled units under /etc/systemd/system: $made"

# ---- dpkg's database is the image's (owner decision q-18 = A): moved into /usr, where it is read-only and in the verity
# hash with the files it lists, so a host's /var never disagrees with its /usr after an A/B update. dpkg reads admindir
# from dpkg.cfg.d; dpkg-query does not (measured, dpkg 1.22): give it --admindir or DPKG_ADMINDIR. Nothing on the host
# runs either. /var/lib/dpkg is not used on the host, and what only a package installation uses (apt's and debconf's
# state, ucf's hashes) is dropped
mkdir -p "$ROOT/usr/lib/sysimage"
mv "$ROOT/var/lib/dpkg" "$ROOT/usr/lib/sysimage/dpkg" || die "/var/lib/dpkg could not be moved into /usr"
printf '# The KMS host image keeps its package database in /usr, read-only (regalia-kms#61, q-18)\nadmindir /usr/lib/sysimage/dpkg\n' \
  > "$ROOT/etc/dpkg/dpkg.cfg.d/regalia-kms-admindir"
rm -rf -- "$ROOT/var/lib/apt" "$ROOT/var/cache/apt" "$ROOT/var/cache/debconf" "$ROOT/var/lib/ucf"
[ "$(DPKG_ADMINDIR=/usr/lib/sysimage/dpkg chroot "$ROOT" dpkg-query -W -f '${Package}=${Version}\n' | sort)" = "$(cat "$W/packages.txt")" ] \
  || die "the moved dpkg database does not list the packages the tree has"

# ---- what the build host left in /etc (etc-inventory.txt [open]: mmdebstrap copies the BUILD's hostname, hosts,
# resolv.conf; the fstab is its placeholder): fixed files, the same on every builder, and no backup or lock left
printf 'localhost\n' > "$ROOT/etc/hostname"
printf '127.0.0.1\tlocalhost\n::1\t\tlocalhost ip6-localhost ip6-loopback\n' > "$ROOT/etc/hosts"
printf '# The KMS host image names no resolver (regalia-kms#61): audit_sink_url and the NTS servers are addresses or /etc/hosts.\n' > "$ROOT/etc/resolv.conf"
printf '# The KMS host mounts nothing from /etc/fstab (regalia-kms#61): / is a tmpfs, /usr the verity image and /var the\n# LUKS2 volume, all from the signed kernel command line.\n' > "$ROOT/etc/fstab"
rm -f -- "$ROOT/etc/.pwd.lock" "$ROOT/etc/passwd-" "$ROOT/etc/group-" "$ROOT/etc/shadow-" "$ROOT/etc/gshadow-"

# the hermetic /usr: the image's /etc, as built, is also /usr's factory copy (the dm-verity design: / is a tmpfs and
# /etc is made from it at boot). The image's own files win over a package's factory default of the same name
mkdir -p "$ROOT/usr/share/factory/etc"
cp -a "$ROOT/etc/." "$ROOT/usr/share/factory/etc/" || die "/etc could not be copied to /usr/share/factory/etc"

# the archive: sorted, numeric owners, mtimes clamped to the epoch, no atime/ctime; the API filesystems' contents
# are not the image's
echo "### rootfs.tar, SOURCE_DATE_EPOCH=$EPOCH"
tar --create --file="$W/stage/rootfs.tar" --sort=name --format=pax \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime --mtime="@$EPOCH" --clamp-mtime --numeric-owner \
    --exclude=./proc/* --exclude=./sys/* --exclude=./dev/* --exclude=./run/* --exclude=./tmp/* -C "$ROOT" . \
  || die "the archive could not be written"
python3 -I - "$W/stage/rootfs.tar" > "$W/stage/rootfs-listing.txt" <<'PY' || die "the listing could not be written"
import hashlib, sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    for m in t:
        kind = "f" if m.isfile() else "d" if m.isdir() else "l" if m.issym() else "h" if m.islnk() else "c" if m.ischr() else "b" if m.isblk() else "p" if m.isfifo() else "?"
        digest = hashlib.sha256(t.extractfile(m).read()).hexdigest() if m.isfile() else ""
        print("\t".join([m.name, kind, "%o" % m.mode, str(m.uid), str(m.gid), str(m.size), digest, m.linkname or ""]))
PY

# ---- the /usr image: erofs and its dm-verity hash tree, made IN the build tree by the snapshot's tools, from the host
# tree's /usr read-only (usr-verity.sh, the commit's own copy; the seed is the commit)
echo "### usr.erofs and usr.verity, from the host tree's /usr"
mkdir -p "$BUILD/build/usr-src" "$BUILD/build/usr-out"
mount --bind "$ROOT/usr" "$BUILD/build/usr-src"; MOUNTED+=("$BUILD/build/usr-src")
mount -o remount,bind,ro "$BUILD/build/usr-src"
for fs in proc dev; do mount --bind "/$fs" "$BUILD/$fs"; MOUNTED+=("$BUILD/$fs"); done
chroot "$BUILD" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC \
  bash /build/src/deploy/baremetal/image/usr-verity.sh --usr /build/usr-src --seed "$COMMIT" --epoch "$EPOCH" --out /build/usr-out \
  >"$W/usr-verity.log" 2>&1 || { tail -20 "$W/usr-verity.log"; die "the /usr image could not be made"; }
for m in "${MOUNTED[@]}"; do umount -R "$m" || die "$m could not be unmounted after the /usr image"; done; MOUNTED=()
for f in usr.erofs usr.verity usr-verity.txt; do mv "$BUILD/build/usr-out/$f" "$W/stage/$f"; done
grep -qx "seed=$COMMIT" "$W/stage/usr-verity.txt" && grep -qx "source_date_epoch=$EPOCH" "$W/stage/usr-verity.txt" \
  && [ "$(sed -n 's/^erofs_sha256=//p' "$W/stage/usr-verity.txt")" = "$(sha256sum < "$W/stage/usr.erofs" | cut -d' ' -f1)" ] \
  && [ "$(sed -n 's/^verity_sha256=//p' "$W/stage/usr-verity.txt")" = "$(sha256sum < "$W/stage/usr.verity" | cut -d' ' -f1)" ] \
  || die "the /usr image's record does not name this commit, this epoch and these files"

# the build record
{
  echo "schema=$SCHEMA"; echo "commit=$COMMIT"; echo "go=$GO_VERSION"; echo "snapshot=$SNAPSHOT"; echo "source_date_epoch=$EPOCH"
  echo "suite=$SUITE"; echo "packages_requested=$PACKAGES"; echo "build_packages=$BUILD_PACKAGES"
  # the tree builder is the BUILDER's, not pinned: its version is named, so a later rebuild elsewhere can be compared
  echo "mmdebstrap=$(mmdebstrap --version 2>/dev/null | head -1)"
  for entry in "${BUILT[@]}"; do read -r source path <<< "$entry"; echo "built=$path $(sha256sum < "$ROOT$path" | cut -d' ' -f1) $source"; done
  echo "etcd=$ETCD_TAG $ETCD_COMMIT $ETCD_GO $ETCD_GOAMD64"
  for p in "${ETCD_PROGRAMS[@]}"; do echo "etcd_program=/usr/bin/${p#*:} $(sha256sum < "$ROOT/usr/bin/${p#*:}" | cut -d' ' -f1)"; done
  for f in "${REPO_FILES[@]}"; do echo "file=$f $(sha256sum < "$f" | cut -d' ' -f1)"; done
  echo "packages_sha256=$(sha256sum < "$W/packages.txt" | cut -d' ' -f1)"
  echo "rootfs_sha256=$(sha256sum < "$W/stage/rootfs.tar" | cut -d' ' -f1)"
  echo "rootfs_size=$(stat -c %s "$W/stage/rootfs.tar")"
  echo "rootfs_entries=$(wc -l < "$W/stage/rootfs-listing.txt")"
} > "$W/record.txt"
python3 -I - "$W/record.txt" "$W/packages.txt" "$W/stage/rootfs-build.json" "$W/stage/usr-verity.txt" <<'PY'
import json, sys
record, files, built, etcd = {}, {}, {}, {"programs": {}}
for line in open(sys.argv[1]):
    key, _, value = line.rstrip("\n").partition("=")
    if key == "file":
        path, digest = value.split(" ")
        files[path] = digest
    elif key == "etcd":
        etcd["tag"], etcd["commit"], etcd["go"], etcd["goamd64"] = value.split(" ")
    elif key == "etcd_program":
        path, digest = value.split(" ")
        etcd["programs"][path] = digest
    elif key == "built":
        path, digest, source = value.split(" ")
        built[path] = {"sha256": digest, "source": source}
    else:
        record[key] = int(value) if key in ("source_date_epoch", "rootfs_size", "rootfs_entries") else value
record["packages_requested"] = record["packages_requested"].split(",")
record["build_packages"] = record["build_packages"].split(",")
record["built"] = built
record["etcd"] = etcd
record["repository_files"] = files
record["packages"] = [l.strip() for l in open(sys.argv[2]) if l.strip()]
usr = dict(l.rstrip("\n").partition("=")[::2] for l in open(sys.argv[4]) if l.strip())
for key in ("source_date_epoch", "erofs_size", "verity_size", "verity_format", "verity_data_block_size", "verity_hash_block_size"):
    usr[key] = int(usr[key])
record["usr"] = usr
with open(sys.argv[3], "w") as f:
    json.dump(record, f, indent=1, sort_keys=True)
    f.write("\n")
PY
for f in rootfs.tar rootfs-listing.txt usr.erofs usr.verity rootfs-build.json; do mv "$W/stage/$f" "$OUT/$f"; done
echo "build-rootfs: $(python3 -I -c 'import json,sys; r=json.load(open(sys.argv[1])); print(r["rootfs_sha256"], r["rootfs_size"], "bytes,", r["rootfs_entries"], "entries, commit", r["commit"][:12], r["go"])' "$OUT/rootfs-build.json")"
echo "build-rootfs: /usr $(python3 -I -c 'import json,sys; u=json.load(open(sys.argv[1]))["usr"]; print("usrhash=" + u["roothash"], "usr.erofs", u["erofs_size"], "bytes, PARTUUIDs", u["usr_partuuid"], u["usr_verity_partuuid"])' "$OUT/rootfs-build.json")"
