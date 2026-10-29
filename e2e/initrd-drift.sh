#!/usr/bin/env bash
# initrd-drift.sh — has the KMS host's initrd moved since its inventory was reviewed? (#198)
#
#   sudo REGALIA_UNLOCK_BIN=path/to/regalia-unlock bash e2e/initrd-drift.sh REPORT.md
#
# Builds the initrd as e2e/unlock-boot-qemu.sh does (the same packages, the same dracut module, the same
# client), but from TODAY's Debian archive: the main suite, its updates and its security suite (each signed by
# the archive key, checked by apt against debian-archive-keyring). It then
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
# BUILT AS THE BUILDER BUILDS (#330): only the archive may differ from the reviewed build. The reviewed inventory was
# built with SOURCE_DATE_EPOCH at its snapshot's time (build-initrd.sh's default), named in its own header, so that
# time is read from there: it moves with the inventory, in one pull request. Run on dracut's defaults instead, every
# day's report carried 7 generated lines no real build has: dev/console, kmsg, null, random and urandom (no
# DRACUT_NO_MKNOD), etc/shadow (its last-changed day follows SOURCE_DATE_EPOCH) and build-parameter.txt (the flags).
PINNED=deploy/baremetal/initrd/initrd-inventory.txt
# every snapshot time on every "Reviewed image" line, each one separately: two on one line are two, not the last one
SNAPSHOT="$(grep -E '^# Reviewed image: ' "$PINNED" | grep -oE 'snapshot\.debian\.org [0-9]{8}T[0-9]{6}Z' | grep -oE '[0-9]{8}T[0-9]{6}Z$' || true)"
[ "$(grep -c . <<< "$SNAPSHOT")" = 1 ] \
  || { echo "initrd-drift: $PINNED's header names no one reviewed snapshot ('$SNAPSHOT'), so the reviewed build's epoch is unknown"; exit 2; }
EPOCH="$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2}T${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}Z" +%s)" \
  || { echo "initrd-drift: the reviewed snapshot $SNAPSHOT is not a time"; exit 2; }
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
# (git: the boot test's guest signs from a clone of its checkout, #266; no dracut module takes it into the initrd)
INCLUDE=systemd-sysv,udev,kmod,linux-image-amd64,dracut,systemd-cryptsetup,cryptsetup-bin,wireguard-tools,nftables,iproute2,e2fsprogs,tpm2-tools,ca-certificates,systemd-ukify,systemd-boot-efi,sbsigntool,openssl,python3-cryptography,git
echo "### today's archive: $SUITE, $SUITE-updates, $SUITE-security"
KEYRING="$(e2e/lib/debian-keyring.sh "$W/keyring")"      # Debian's own, pinned: the runner's predates trixie's keys
# (apt's lists are kept: the security suite's verified package list is read from them below)
env -i PATH="$PATH" LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH="$EPOCH" mmdebstrap --variant=minbase --skip=cleanup/apt/lists --include="$INCLUDE" "$SUITE" "$ROOT" \
  "deb [signed-by=$KEYRING] $MIRROR $SUITE main" "deb [signed-by=$KEYRING] $MIRROR $SUITE-updates main" \
  "deb [signed-by=$KEYRING] $SECURITY $SUITE-security main" >"$W/mmdebstrap.log" 2>&1 \
  || { tail -40 "$W/mmdebstrap.log"; echo "initrd-drift: mmdebstrap failed"; exit 2; }
install -D -m 0644 "$KEYRING" "$ROOT$KEYRING"      # the guest's own apt reads the same lines
for fs in proc sys dev; do mount --bind "/$fs" "$ROOT/$fs"; MOUNTED+=("$ROOT/$fs"); done
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
chroot "$ROOT" apt-get install -y -qq --no-install-recommends 'libtss2-tcti-device0*' >"$W/apt.log" 2>&1 \
  || { tail -20 "$W/apt.log"; echo "initrd-drift: the TPM library did not install"; exit 2; }
# what a KMS host has installed, as e2e/unlock-boot-qemu.sh installs it
install -D -m 0755 "$BIN" "$ROOT/usr/bin/regalia-unlock"
# the membership root the initrd trusts (#156), which 90regalia-unlock's check() requires (#330: without it dracut
# stops at the module and nothing is compared). The boot test's fixed TEST root, made as it makes it: the inventory
# binds this entry to the build's input (=root-key on both sides, uki.py), so any root compares equal
python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))["root_public"]; open(sys.argv[2],"wb").write(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode())' \
  tests/vectors/highwater-v1.json "$W/root-key.json"
install -D -m 0644 "$W/root-key.json" "$ROOT/usr/lib/regalia/root-key.json"
install -D -m 0755 deploy/baremetal/initrd/wg-boot "$ROOT/usr/lib/regalia/wg-boot"
install -m 0644 deploy/baremetal/initrd/regalia-boot-render.service deploy/baremetal/initrd/regalia-unlock.service \
  deploy/baremetal/initrd/regalia-wg-boot.service "$ROOT/usr/lib/systemd/system/"
install -D -m 0755 deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/module-setup.sh"
install -m 0644 deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/crypttab"
# the module's own check() first, against this tree (#330): a requirement the build does not meet stops it here in
# check()'s own words, not at "dracut failed" with the reason forty lines up dracut's log
echo "### the dracut module's check()"
bash e2e/lib/dracut-module-check.sh "$ROOT" "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock" \
  || { echo "initrd-drift: the regalia-unlock module's check() fails on this tree: dracut would stop at it"; exit 2; }
echo "### the initrd, by its own dracut, as build-initrd.sh runs it (SOURCE_DATE_EPOCH=$EPOCH, snapshot $SNAPSHOT)"
KVER="$(ls "$ROOT/lib/modules" | sort -V | tail -1)"
# build-initrd.sh's own chroot environment and dracut flags (tests/test_initrd_drift.py holds them equal)
inroot(){ chroot "$ROOT" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC HOME=/root SOURCE_DATE_EPOCH="$EPOCH" DRACUT_NO_MKNOD=1 "$@"; }
inroot dracut --force --reproducible --nohardlink --no-hostonly --no-hostonly-cmdline --add regalia-unlock --kver "$KVER" /boot/initrd.drift >"$W/dracut.log" 2>&1 \
  || { tail -40 "$W/dracut.log"; echo "initrd-drift: dracut failed"; exit 2; }
mkdir -p "$ROOT/tmp/src"; cp -r deploy "$ROOT/tmp/src/"
chroot "$ROOT" sh -c "cd /tmp/src && python3 -Es -m deploy.baremetal.uki initrd-inventory --initrd /boot/initrd.drift --root /" > "$W/current.txt" \
  || { echo "initrd-drift: the inventory could not be written"; exit 2; }
# the security suite's package list, to say which moved packages carry a security fix: the one apt fetched and
# VERIFIED for the build (InRelease signed by the archive key, then Packages by its hash), from the chroot's lists
LIST="$(ls "$ROOT"/var/lib/apt/lists/*_dists_"$SUITE"-security_main_binary-amd64_Packages* 2>/dev/null | head -1)"
[ -n "$LIST" ] || { echo "initrd-drift: apt holds no verified package list of $SUITE-security"; exit 2; }
case "$LIST" in
  *.lz4) lz4 -dc "$LIST" ;; *.gz) gzip -dc "$LIST" ;; *.xz) xz -dc "$LIST" ;; *.zst) zstd -dc "$LIST" ;; *) cat "$LIST" ;;
esac > "$W/security.txt" || { echo "initrd-drift: the security suite's package list could not be read"; exit 2; }
echo "kernel $KVER; $(grep -c . "$W/current.txt") entries"
rc=0
python3 -Es -m deploy.baremetal.initrd_drift --pinned "$PINNED" --current "$W/current.txt" \
  --security "$W/security.txt" --out "$OUT" || rc=$?
exit "$rc"
