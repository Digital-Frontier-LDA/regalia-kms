#!/usr/bin/env bash
# initrd-reproducible.sh — is the KMS host initrd reproducible? (regalia-kms#248)
#
#   sudo REGALIA_UNLOCK_BIN=/path/to/regalia-unlock e2e/initrd-reproducible.sh OUT
#
# Builds the initrd TWICE, each time from nothing: a fresh Debian root tree from one pinned
# snapshot.debian.org timestamp (so both get the same package versions), this repository's client,
# units and dracut module installed as e2e/unlock-boot-qemu.sh installs them, and
# `dracut --reproducible --no-hostonly` with a fixed SOURCE_DATE_EPOCH. The two builds use different
# directories. It writes to OUT, for each build N (1, 2):
#   initrd-N.img       the initrd
#   listing-N.txt      every entry, unpacked: path, type, mode, uid, gid, size, sha256 (files), target (links), mtime
#   sha256-N.txt       the initrd's sha256
# and prints whether the two are byte-identical, and if not, the listing lines that differ. CI runs it on
# two runners and compares across them too (.github/workflows/ci.yml, initrd-reproducible).
# It measures; it decides nothing. The guest's own dracut builds the initrd inside the root tree.
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
[ "$(id -u)" = 0 ] || { echo "initrd-reproducible: run as root"; exit 2; }
OUT="${1:?usage: initrd-reproducible.sh OUT}"
BIN="${REGALIA_UNLOCK_BIN:?set REGALIA_UNLOCK_BIN to a built cmd/regalia-unlock (static, -trimpath)}"
SNAPSHOT="${REGALIA_SNAPSHOT:-20261002T000000Z}"
EPOCH="${REGALIA_SOURCE_DATE_EPOCH:-1790899200}"     # 2026-10-02T00:00:00Z: fixed, not the build's time
MIRROR="https://snapshot.debian.org/archive/debian/$SNAPSHOT"
command -v mmdebstrap >/dev/null || { echo "initrd-reproducible: mmdebstrap is required"; exit 2; }
mkdir -p "$OUT"
W="$(mktemp -d /var/tmp/regalia-repro.XXXXXX)"; chmod 700 "$W"
MOUNTED=()
cleanup(){
  for m in "${MOUNTED[@]:-}"; do [ -n "$m" ] && umount -R "$m" 2>/dev/null; done
  if grep -q " $W" /proc/mounts; then echo "initrd-reproducible: something is still mounted under $W: it is NOT removed" >&2
  else rm -rf --one-file-system -- "$W"; fi
}
trap cleanup EXIT

build(){  # build N DIR
  local n="$1" root="$W/$2/root"
  mkdir -p "$W/$2"
  echo "### build $n: the root tree from $MIRROR, in $W/$2"
  SOURCE_DATE_EPOCH="$EPOCH" mmdebstrap --variant=minbase \
    --aptopt='Acquire::Check-Valid-Until "false"' --aptopt='Acquire::Retries "5"' \
    --include=systemd-sysv,udev,kmod,linux-image-amd64,dracut,systemd-cryptsetup,cryptsetup-bin,wireguard-tools,nftables,iproute2,e2fsprogs,tpm2-tools \
    trixie "$root" "$MIRROR" >"$W/mmdebstrap-$n.log" 2>&1 \
    || { tail -40 "$W/mmdebstrap-$n.log"; echo "initrd-reproducible: mmdebstrap failed (build $n)"; exit 2; }
  # what systemd needs to talk to a TPM, as e2e/unlock-boot-qemu.sh adds it (only suggested by its package)
  cp /etc/resolv.conf "$root/etc/resolv.conf"
  for fs in proc sys dev; do mount --bind "/$fs" "$root/$fs"; MOUNTED+=("$root/$fs"); done
  chroot "$root" env SOURCE_DATE_EPOCH="$EPOCH" apt-get -o Acquire::Check-Valid-Until=false install -y -qq --no-install-recommends \
    'libtss2-tcti-device0*' >"$W/apt-$n.log" 2>&1 || { tail -20 "$W/apt-$n.log"; echo "initrd-reproducible: the TPM library did not install"; exit 2; }
  install -D -m 0755 "$BIN" "$root/usr/bin/regalia-unlock"
  install -D -m 0755 deploy/baremetal/initrd/wg-boot "$root/usr/lib/regalia/wg-boot"
  install -m 0644 deploy/baremetal/initrd/regalia-unlock.service deploy/baremetal/initrd/regalia-unlock-relay.service \
    deploy/baremetal/initrd/regalia-unlock-core.socket deploy/baremetal/initrd/regalia-wg-boot.service "$root/usr/lib/systemd/system/"
  install -D -m 0755 deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh "$root/usr/lib/dracut/modules.d/90regalia-unlock/module-setup.sh"
  install -m 0644 deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab "$root/usr/lib/dracut/modules.d/90regalia-unlock/crypttab"
  # what we installed gets the fixed time too, as a package's files have theirs
  find "$root/usr/bin/regalia-unlock" "$root/usr/lib/regalia" "$root/usr/lib/dracut/modules.d/90regalia-unlock" \
    "$root"/usr/lib/systemd/system/regalia-* -exec touch -h -d "@$EPOCH" {} +
  local kver; kver="$(find "$root/lib/modules" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort -V | tail -1)"
  chroot "$root" env SOURCE_DATE_EPOCH="$EPOCH" dracut --force --reproducible --no-hostonly --no-hostonly-cmdline \
    --add regalia-unlock --kver "$kver" /tmp/initrd.img >"$W/dracut-$n.log" 2>&1 \
    || { tail -40 "$W/dracut-$n.log"; echo "initrd-reproducible: dracut failed (build $n)"; exit 2; }
  cp "$root/tmp/initrd.img" "$OUT/initrd-$n.img"
  mkdir "$root/tmp/unpacked"
  chroot "$root" sh -c 'cd /tmp/unpacked && lsinitrd --unpack /tmp/initrd.img' >/dev/null 2>&1 \
    || { echo "initrd-reproducible: cannot unpack build $n"; exit 2; }
  # one line per entry; a file's content by its sha256, a link by its target
  (cd "$root/tmp/unpacked" && find . -mindepth 1 -printf '%P\t%y\t%m\t%U\t%G\t%s\t%T@\t%l\n' | sort | while IFS=$'\t' read -r p y m u g s t l; do
     h=""; [ "$y" = f ] && h="$(sha256sum < "$p" | cut -d' ' -f1)"
     printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$p" "$y" "$m" "$u" "$g" "$s" "$h" "$l" "${t%%.*}"
   done) > "$OUT/listing-$n.txt"
  sha256sum < "$OUT/initrd-$n.img" | cut -d' ' -f1 > "$OUT/sha256-$n.txt"
  for fs in dev sys proc; do umount -R "$root/$fs"; done; MOUNTED=()
  grep -m1 -i "dracut version\|Executing: " "$W/dracut-$n.log" || true
  echo "build $n: $(cat "$OUT/sha256-$n.txt") ($(stat -c %s "$OUT/initrd-$n.img") bytes, $(wc -l < "$OUT/listing-$n.txt") entries)"
  rm -rf --one-file-system -- "${root:?}"
}

build 1 one
build 2 two-other-dir
entries="$(grep -c . "$OUT/listing-1.txt")"
if cmp -s "$OUT/initrd-1.img" "$OUT/initrd-2.img"; then
  echo "initrd-reproducible: IDENTICAL on this runner: $(cat "$OUT/sha256-1.txt") ($entries entries)"
else
  echo "initrd-reproducible: the two builds DIFFER on this runner"
  echo "--- listing lines that differ (path, type, mode, uid, gid, size, sha256, link, mtime):"
  diff "$OUT/listing-1.txt" "$OUT/listing-2.txt" | head -200 || true
  echo "--- differing entries: $(diff "$OUT/listing-1.txt" "$OUT/listing-2.txt" | grep -c '^[<>]' || true)"
fi
