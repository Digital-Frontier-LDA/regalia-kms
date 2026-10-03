#!/usr/bin/env bash
# debian-keyring.sh DIR — Debian's own archive keyring, pinned, into DIR; prints its path (#198).
#
# The runner's debian-archive-keyring (Ubuntu's copy) predates trixie's signing keys, so apt cannot verify a trixie
# archive with it. This fetches Debian's debian-archive-keyring 2025.1 and checks it against the SHA-256 that
# trixie's Packages index states. That index was checked by its own SHA-256 in trixie's InRelease, whose signature
# was verified with gpgv by an existing Debian 13 keyring when this pin was written (2026-10-03, snapshot
# 20261003T121500Z). Moving the pin is a reviewed change like the snapshot date.
set -euo pipefail
DIR="${1:?usage: debian-keyring.sh DIR}"
URL=https://snapshot.debian.org/archive/debian/20261003T121500Z/pool/main/d/debian-archive-keyring/debian-archive-keyring_2025.1_all.deb
SHA256=9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac
mkdir -p "$DIR"
curl -sSfL --retry 3 -m 120 -o "$DIR/keyring.deb" "$URL" >&2
echo "$SHA256  $DIR/keyring.deb" | sha256sum -c --quiet >&2 || { echo "debian-keyring: the keyring package is not the pinned one" >&2; exit 2; }
dpkg-deb -x "$DIR/keyring.deb" "$DIR/x"
install -m 0644 "$DIR/x/usr/share/keyrings/debian-archive-keyring.gpg" "$DIR/debian-archive-keyring.gpg"
rm -rf "$DIR/x" "$DIR/keyring.deb"
echo "$DIR/debian-archive-keyring.gpg"
