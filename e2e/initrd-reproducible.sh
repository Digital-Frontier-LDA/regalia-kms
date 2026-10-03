#!/usr/bin/env bash
# initrd-reproducible.sh — is the KMS host initrd reproducible? (regalia-kms#248)
#
#   sudo REGALIA_GO=/path/to/go e2e/initrd-reproducible.sh OUT [BUILDS]
#
# Runs deploy/baremetal/initrd/build-initrd.sh BUILDS times (default 2), each from nothing, in its own
# directory, at one pinned snapshot. Build 2 runs in a HOSTILE environment that the builder must not let
# through: another locale, time zone, umask, TMPDIR and working directory; stray SOURCE_DATE_EPOCH, GZIP and
# ZSTD_CLEVEL; Go variables that would change the client (GOFLAGS, CGO_ENABLED=1, GOTOOLCHAIN=local) or
# weaken its verification (GOSUMDB=off, GONOSUMDB, GOINSECURE); and,
# with REGALIA_HOSTILE_APT=1 (CI only: it writes under the host's /etc/apt), a host apt configuration with
# a dead proxy and recommends switched on, which would break the download or change the package set if
# mmdebstrap read it. Every build's initrd and build record must be identical. It writes OUT/build-N/
# (initrd.img, initrd-build.json, initrd-listing.txt) and prints the listing lines that differ, if any. CI
# runs it on two runners and in a Debian 13 container, and compares those too (.github/workflows/ci.yml).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "initrd-reproducible: run as root"; exit 2; }
OUT="${1:?usage: initrd-reproducible.sh OUT [BUILDS]}"
BUILDS="${2:-2}"
GO="${REGALIA_GO:?set REGALIA_GO to a go (any release from 1.21: it launches the toolchain go.mod pins)}"
SNAPSHOT="${REGALIA_SNAPSHOT:-20261003T121500Z}"
HOSTILE_APT=/etc/apt/apt.conf.d/99regalia-initrd-reproducible-hostile
HOSTILE_TMP=""
cleanup(){
  [ "${REGALIA_HOSTILE_APT:-0}" = 1 ] && rm -f -- "$HOSTILE_APT"
  [ -n "$HOSTILE_TMP" ] && rm -rf --one-file-system -- "$HOSTILE_TMP"
  return 0
}
trap cleanup EXIT
mkdir -p "$OUT"
for n in $(seq 1 "$BUILDS"); do
  echo "### build $n"
  if [ "$n" = 2 ]; then
    if [ "${REGALIA_HOSTILE_APT:-0}" = 1 ]; then
      [ ! -e "$HOSTILE_APT" ] || { echo "initrd-reproducible: $HOSTILE_APT already exists: not touching it"; exit 2; }
      printf 'Acquire::http::Proxy "http://127.0.0.1:9";\nAcquire::https::Proxy "http://127.0.0.1:9";\nAPT::Install-Recommends "true";\n' > "$HOSTILE_APT"
    fi
    HOSTILE_TMP="$(mktemp -d /var/tmp/regalia-hostile-tmp.XXXXXX)"
    ( umask 077; cd /
      env LANG=de_DE.UTF-8 LC_ALL=de_DE.UTF-8 TZ=Pacific/Kiritimati TMPDIR="$HOSTILE_TMP" SOURCE_DATE_EPOCH=0 GZIP=-1 ZSTD_CLEVEL=1 \
        GOFLAGS=-ldflags=-X=main.hostile=1 CGO_ENABLED=1 GOTOOLCHAIN=local GOSUMDB=off GONOSUMDB='*' GOINSECURE='*' \
        "$REPO/deploy/baremetal/initrd/build-initrd.sh" --snapshot "$SNAPSHOT" --go "$GO" --out "$OUT/build-$n" )
  else
    deploy/baremetal/initrd/build-initrd.sh --snapshot "$SNAPSHOT" --go "$GO" --out "$OUT/build-$n"
  fi
done
same=yes
for n in $(seq 2 "$BUILDS"); do
  if ! cmp -s "$OUT/build-1/initrd.img" "$OUT/build-$n/initrd.img"; then
    same=no
    echo "initrd-reproducible: build $n DIFFERS from build 1"
    echo "--- listing lines that differ (path, type, mode, uid, gid, size, sha256, link):"
    diff "$OUT/build-1/initrd-listing.txt" "$OUT/build-$n/initrd-listing.txt" | head -200 || true
    echo "--- where the two archives differ (segments decompressed, cpio headers compared):"
    python3 -Es e2e/lib/initrd-cpio-diff.py "$OUT/build-1/initrd.img" "$OUT/build-$n/initrd.img" || true
  fi
  if ! cmp -s "$OUT/build-1/initrd-build.json" "$OUT/build-$n/initrd-build.json"; then
    same=no
    echo "initrd-reproducible: build $n's record DIFFERS from build 1's"
    diff "$OUT/build-1/initrd-build.json" "$OUT/build-$n/initrd-build.json" | grep -v '^[<>] *"[a-z0-9.+~-]*=' | head -40 || true
  fi
done
sha="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["initrd_sha256"])' "$OUT/build-1/initrd-build.json")"
if [ "$same" = yes ]; then
  echo "initrd-reproducible: IDENTICAL, $BUILDS builds on this machine: $sha"
else
  echo "initrd-reproducible: NOT reproducible on this machine"; exit 1
fi
