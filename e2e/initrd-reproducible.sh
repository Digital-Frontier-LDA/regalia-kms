#!/usr/bin/env bash
# initrd-reproducible.sh — is the KMS host initrd reproducible? (regalia-kms#248)
#
#   sudo REGALIA_UNLOCK_BIN=/path/to/regalia-unlock e2e/initrd-reproducible.sh OUT [BUILDS]
#
# Runs deploy/baremetal/initrd/build-initrd.sh BUILDS times (default 2), each from nothing, in its own
# directory, at one pinned snapshot. Build 2 runs in a HOSTILE environment: another locale, time zone and
# umask, and stray SOURCE_DATE_EPOCH, GZIP and ZSTD_CLEVEL variables, which the builder must not let
# through. Every build's initrd and build record must be identical. It writes OUT/build-N/ (initrd.img,
# initrd-build.json, initrd-listing.txt) and prints the listing lines that differ, if any. CI runs it on
# two runners and in a Debian 13 container, and compares those too (.github/workflows/ci.yml).
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "initrd-reproducible: run as root"; exit 2; }
OUT="${1:?usage: initrd-reproducible.sh OUT [BUILDS]}"
BUILDS="${2:-2}"
BIN="${REGALIA_UNLOCK_BIN:?set REGALIA_UNLOCK_BIN to a built cmd/regalia-unlock (CGO_ENABLED=0, -trimpath -buildvcs=false)}"
SNAPSHOT="${REGALIA_SNAPSHOT:-20261003T121500Z}"
mkdir -p "$OUT"
for n in $(seq 1 "$BUILDS"); do
  echo "### build $n"
  if [ "$n" = 2 ]; then
    ( umask 077; env LANG=de_DE.UTF-8 LC_ALL=de_DE.UTF-8 TZ=Pacific/Kiritimati SOURCE_DATE_EPOCH=0 GZIP=-1 ZSTD_CLEVEL=1 \
        deploy/baremetal/initrd/build-initrd.sh --snapshot "$SNAPSHOT" --client "$BIN" --out "$OUT/build-$n" )
  else
    deploy/baremetal/initrd/build-initrd.sh --snapshot "$SNAPSHOT" --client "$BIN" --out "$OUT/build-$n"
  fi
done
same=yes
for n in $(seq 2 "$BUILDS"); do
  if ! cmp -s "$OUT/build-1/initrd.img" "$OUT/build-$n/initrd.img"; then
    same=no
    echo "initrd-reproducible: build $n DIFFERS from build 1"
    echo "--- listing lines that differ (path, type, mode, uid, gid, size, sha256, link, mtime):"
    diff "$OUT/build-1/initrd-listing.txt" "$OUT/build-$n/initrd-listing.txt" | head -200 || true
  fi
  if ! cmp -s "$OUT/build-1/initrd-build.json" "$OUT/build-$n/initrd-build.json"; then
    same=no
    echo "initrd-reproducible: build $n's record DIFFERS from build 1's"
    diff "$OUT/build-1/initrd-build.json" "$OUT/build-$n/initrd-build.json" | grep -v '^[<>] *"[a-z0-9.+~-]*=' | head -40 || true
  fi
done
sha="$(python3 -Es -c 'import json,sys; print(json.load(open(sys.argv[1]))["initrd_sha256"])' "$OUT/build-1/initrd-build.json")"
if [ "$same" = yes ]; then
  echo "initrd-reproducible: IDENTICAL, $BUILDS builds on this machine: $sha"
else
  echo "initrd-reproducible: NOT reproducible on this machine"; exit 1
fi
