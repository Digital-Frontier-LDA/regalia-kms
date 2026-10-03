#!/usr/bin/env bash
# initrd-drift.sh — has the KMS host's initrd moved since its inventory was reviewed? (#198)
#
#   sudo REGALIA_UNLOCK_BIN=path/to/regalia-unlock bash e2e/initrd-drift.sh REPORT.md
#
# Builds the initrd as e2e/unlock-boot-qemu.sh does (the same packages, the same dracut module, the same
# client), but from TODAY's Debian archive: the main suite, its updates and its security suite. It then
# writes its inventory (`uki initrd-inventory --root`) and compares it with deploy/baremetal/initrd/initrd-inventory.txt.
# Exit 0: nothing moved. Exit 1: REPORT.md says which packages moved (and which carry a security fix) and which
# lines dracut generated differently. The scheduled workflow initrd-drift.yml files that report as an issue.
# Exit 2: the build itself failed. Changes this machine: nothing outside its temporary directory.
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
[ "$(id -u)" = 0 ] || { echo "initrd-drift: run as root"; exit 2; }
OUT="${1:?usage: initrd-drift.sh REPORT.md}"
BIN="${REGALIA_UNLOCK_BIN:?set REGALIA_UNLOCK_BIN to a built cmd/regalia-unlock (static: CGO_ENABLED=0)}"
SUITE="${REGALIA_BOOT_SUITE:-trixie}"
MIRROR="${REGALIA_DRIFT_MIRROR:-http://deb.debian.org/debian}"
SECURITY="${REGALIA_DRIFT_SECURITY:-http://deb.debian.org/debian-security}"
command -v mmdebstrap >/dev/null || { echo "initrd-drift: mmdebstrap is required"; exit 2; }
W="$(mktemp -d /var/tmp/regalia-drift.XXXXXX)"; chmod 700 "$W"
ROOT="$W/root"
MOUNTED=()
cleanup(){
  for m in "${MOUNTED[@]:-}"; do [ -n "$m" ] && umount -R "$m" 2>/dev/null; done
  if grep -q " $W" /proc/mounts; then echo "initrd-drift: something is still mounted under $W: it is NOT removed" >&2
  else rm -rf --one-file-system -- "$W"; fi
}
trap cleanup EXIT

# THE SAME PACKAGES as e2e/unlock-boot-qemu.sh (tests/test_initrd_drift.py holds the two lists together)
INCLUDE=systemd-sysv,udev,kmod,linux-image-amd64,dracut,systemd-cryptsetup,cryptsetup-bin,wireguard-tools,nftables,iproute2,e2fsprogs,tpm2-tools,ca-certificates,systemd-ukify,systemd-boot-efi,sbsigntool,openssl,python3-cryptography
echo "### today's archive: $SUITE, $SUITE-updates, $SUITE-security"
mmdebstrap --variant=minbase --include="$INCLUDE" "$SUITE" "$ROOT" \
  "deb $MIRROR $SUITE main" "deb $MIRROR $SUITE-updates main" "deb $SECURITY $SUITE-security main" >"$W/mmdebstrap.log" 2>&1 \
  || { tail -40 "$W/mmdebstrap.log"; echo "initrd-drift: mmdebstrap failed"; exit 2; }
for fs in proc sys dev; do mount --bind "/$fs" "$ROOT/$fs"; MOUNTED+=("$ROOT/$fs"); done
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
chroot "$ROOT" apt-get install -y -qq --no-install-recommends 'libtss2-tcti-device0*' >"$W/apt.log" 2>&1 \
  || { tail -20 "$W/apt.log"; echo "initrd-drift: the TPM library did not install"; exit 2; }
# what a KMS host has installed, as e2e/unlock-boot-qemu.sh installs it
install -D -m 0755 "$BIN" "$ROOT/usr/bin/regalia-unlock"
install -D -m 0755 deploy/baremetal/initrd/wg-boot "$ROOT/usr/lib/regalia/wg-boot"
install -m 0644 deploy/baremetal/initrd/regalia-unlock.service deploy/baremetal/initrd/regalia-unlock-relay.service \
  deploy/baremetal/initrd/regalia-unlock-core.socket deploy/baremetal/initrd/regalia-wg-boot.service "$ROOT/usr/lib/systemd/system/"
install -D -m 0755 deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/module-setup.sh"
install -m 0644 deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/crypttab"
echo "### the initrd, by its own dracut"
KVER="$(ls "$ROOT/lib/modules" | sort -V | tail -1)"
chroot "$ROOT" dracut --force --no-hostonly --no-hostonly-cmdline --add regalia-unlock --kver "$KVER" /boot/initrd.drift >"$W/dracut.log" 2>&1 \
  || { tail -40 "$W/dracut.log"; echo "initrd-drift: dracut failed"; exit 2; }
mkdir -p "$ROOT/tmp/src"; cp -r deploy "$ROOT/tmp/src/"
chroot "$ROOT" sh -c "cd /tmp/src && python3 -Es -m deploy.baremetal.uki initrd-inventory --initrd /boot/initrd.drift --root /" > "$W/current.txt" \
  || { echo "initrd-drift: the inventory could not be written"; exit 2; }
# the security suite's package list, to say which moved packages carry a security fix
python3 -I -c 'import lzma,sys,urllib.request; sys.stdout.write(lzma.decompress(urllib.request.urlopen(sys.argv[1], timeout=120).read()).decode("utf-8","replace"))' \
  "$SECURITY/dists/$SUITE-security/main/binary-amd64/Packages.xz" > "$W/security.txt" || { echo "initrd-drift: the security archive's package list could not be read"; exit 2; }
echo "kernel $KVER; $(grep -c . "$W/current.txt") entries"
rc=0
python3 -Es -m deploy.baremetal.initrd_drift --pinned deploy/baremetal/initrd/initrd-inventory.txt --current "$W/current.txt" \
  --security "$W/security.txt" --out "$OUT" || rc=$?
exit "$rc"
