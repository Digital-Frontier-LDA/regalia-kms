#!/usr/bin/env bash
# rootfs-reproducible.sh — is the KMS host's root filesystem reproducible? (regalia-kms#61)
#
#   sudo REGALIA_GO=/path/to/go e2e/rootfs-reproducible.sh OUT [BUILDS]
#
# Runs deploy/baremetal/image/build-rootfs.sh BUILDS times (default 2), each from nothing, in its own directory, at
# one pinned snapshot. Build 2 runs in a HOSTILE environment the builder must not let through: another locale, time
# zone, umask, TMPDIR and working directory; a stray SOURCE_DATE_EPOCH; and Go variables that would change the
# programs (GOFLAGS, CGO_ENABLED, GOTOOLCHAIN=local) or weaken their verification (GOSUMDB=off, GONOSUMDB, GOINSECURE).
# Every build's rootfs.tar and build record must be identical. It writes OUT/build-N/ and, on a difference, prints
# the listing lines that differ. CI runs it on a GitHub runner (.github/workflows/ci.yml, rootfs-reproducible).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "rootfs-reproducible: run as root"; exit 2; }
OUT="${1:?usage: rootfs-reproducible.sh OUT [BUILDS]}"
BUILDS="${2:-2}"
GO="${REGALIA_GO:?set REGALIA_GO to a go (any release from 1.21: it launches the toolchain go.mod pins)}"
SNAPSHOT="${REGALIA_SNAPSHOT:-20261003T121500Z}"
HOSTILE_TMP=""
cleanup(){ [ -n "$HOSTILE_TMP" ] && rm -rf --one-file-system -- "$HOSTILE_TMP"; return 0; }
trap cleanup EXIT
mkdir -p "$OUT"
for n in $(seq 1 "$BUILDS"); do
  echo "### build $n"
  if [ "$n" = 2 ]; then
    HOSTILE_TMP="$(mktemp -d /var/tmp/regalia-hostile-tmp.XXXXXX)"
    ( umask 077; cd /
      env LANG=de_DE.UTF-8 LC_ALL=de_DE.UTF-8 TZ=Pacific/Kiritimati TMPDIR="$HOSTILE_TMP" SOURCE_DATE_EPOCH=0 \
        GOFLAGS=-ldflags=-X=main.hostile=1 CGO_ENABLED=0 GOTOOLCHAIN=local GOSUMDB=off GONOSUMDB='*' GOINSECURE='*' \
        "$REPO/deploy/baremetal/image/build-rootfs.sh" --snapshot "$SNAPSHOT" --go "$GO" --out "$OUT/build-$n" )
  else
    deploy/baremetal/image/build-rootfs.sh --snapshot "$SNAPSHOT" --go "$GO" --out "$OUT/build-$n" | tee "$OUT/build-$n.log"
  fi
done
first="$(sha256sum < "$OUT/build-1/rootfs.tar" | cut -d' ' -f1)"
same=1
for n in $(seq 2 "$BUILDS"); do
  this="$(sha256sum < "$OUT/build-$n/rootfs.tar" | cut -d' ' -f1)"
  if [ "$this" != "$first" ] || ! cmp -s "$OUT/build-1/rootfs-build.json" "$OUT/build-$n/rootfs-build.json"; then
    same=0
    echo "rootfs-reproducible: build $n differs from build 1 ($this vs $first); the listing lines that differ:"
    diff "$OUT/build-1/rootfs-listing.txt" "$OUT/build-$n/rootfs-listing.txt" | head -60 || true
    diff "$OUT/build-1/rootfs-build.json" "$OUT/build-$n/rootfs-build.json" | head -20 || true
  fi
done
[ "$same" = 1 ] || exit 1
echo "rootfs-reproducible: IDENTICAL over $BUILDS builds: rootfs.tar $first ($(wc -l < "$OUT/build-1/rootfs-listing.txt") entries)"
