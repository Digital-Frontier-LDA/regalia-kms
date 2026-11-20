#!/usr/bin/env bash
# unlock-boot-qemu.sh — a KMS host BOOTS through a peer: a real initrd, a real encrypted root, the TPM
# unsealing done by systemd, WireGuard before root (regalia-kms#66 PoC 6.1, 6.2, 6.5; #67 PoC 7.1, 7.4).
#
#   sudo REGALIA_GO=/path/to/go REGALIA_BOOT_MIRROR=https://snapshot.debian.org/archive/debian/<TIME>/ \
#        REGALIA_BOOT_SECURITY_MIRROR=https://snapshot.debian.org/archive/debian-security/<TIME>/ e2e/unlock-boot-qemu.sh
#
# A Debian 13 guest in QEMU (KVM when the machine has it) under UEFI (OVMF), with a software TPM as its
# TPM. MEASURED BOOT: the guest boots a unified kernel image built and signed by deploy/baremetal/uki.py
# (TEST keys made here), whose initrd is built REPRODUCIBLY by deploy/baremetal/initrd/build-initrd.sh (#248:
# the archive snapshot of the guest, dracut with the module deploy/baremetal/initrd/dracut/90regalia-unlock,
# the client compiled by the builder) and is the same for every host. Its disk is laid out by
# deploy/baremetal/image/install-host.sh in its test mode (#61 K61V-4), as a host's: an ESP (the image as
# EFI/Linux/e2e.efi and EFI/BOOT/BOOTX64.EFI, and the host's credentials in loader/credentials, which
# systemd-stub measures into PCR 12), the guest's /usr as an erofs image under dm-verity in usr-a (the UKI
# names it: usrhash=), usr-b reserved, and regalia-root, the LUKS2 volume, which is /var: / is a tmpfs and
# /etc is copied from /usr/share/factory/etc at every boot. The peers run on this machine, in network
# namespaces, as in e2e/wg-boot-netns.sh; nothing is loaded outside a namespace.
#
# REGALIA_BOOT_CASES=verity REGALIA_BOOT_IMAGE=DIR (a build-rootfs.sh output) runs the VERITY /usr's boots instead,
# on the REAL image (tests/test_baremetal_unlock_boot.py's OnQemuVerity): enrolment, which also makes the installer's
# firmware entry through bootnext (and refuses one carrying load options); a control boot from that entry, every
# boot proving /usr is /dev/mapper/usr (verified, the root hash its UKI names), / a tmpfs, /var the LUKS2 mapping
# mounted in the initrd, BootCurrent the installer's entry, nothing enabled under /etc, one machine ID kept on /var,
# and the image's units (the factory /etc, sysusers, AppArmor with the KMS's profile, chrony, node_exporter, the
# KMS) started; THE PER-HOST UNITS (regalia-kms-r1s.8): enrolment writes this host's firewall ruleset, its audit
# collector configuration and a sealed PIN at their /var names, and after the reboot nftables (the table loaded), every
# audit shipper and prune timer, and the KMS behind the firewall with its PIN named by the image's generator are
# started, nothing enabled under /etc; then those files moved aside: nftables and the shippers SKIPPED by their gates
# and the KMS REFUSING (its assert on the ruleset), until a control boot with them back; a WRONG USRHASH (one digit: no /usr, no key given, the guest ends by itself); a TAMPERED block (one
# byte of usr-a: dm-verity panics the kernel); A/B (image B in usr-b and its UKI, then A's again, the fallback); a
# BROKEN FACTORY /etc (an image without /usr/share/factory/etc: sysusers, apparmor and the KMS never start). Each
# failing case has a control boot that passes after it.
#
#   boot 1  ENROLMENT. Nothing is enrolled: the console asks for the recovery key and the test types it
#           (PoC 6.5: the manual path works with no peer and no credential). The running guest seals
#           the local half and the WG-BOOT key to its own TPM (PCR 7, and PCR 11 through the image's
#           initrd-phase signature), and reports its PCRs: PCR 11 must be the build record's.
#   boot 1b AN UNDECRYPTABLE SEALED CREDENTIAL: the client cannot start; the console, which asks from the
#           start whatever the client does, takes the recovery key, promptly.
#   boot 2  UNATTENDED. Nobody types anything. systemd unseals both credentials in the initrd, the boot
#           mesh comes up, a peer verifies the guest's quote and gives its half, systemd-cryptsetup maps
#           the root volume with the key the client answered its request with, the root filesystem comes up, and the boot
#           interface, its ruleset and its address are gone.
#   boot 2e A FORKED CHAIN (#66 B3): another epoch 1, validly signed by the root the image trusts, on the ESP in
#           place of the one the guest's TPM anchored: the initrd's render refuses it (CONFLICT), nothing is asked of
#           a peer, and the console takes the recovery key.
#   boot 2c AN OLDER SIGNED IMAGE, APPROVED (#135): a second image of the same build (one word more on its
#           command line, so another PCR 11, signed by the same keys). The peers' document lists both: it boots
#           unattended, as boot 2.
#   boot 2k #75 TIER Q, Q1: AN IMAGE WHOSE KERNEL DIFFERS (the same kernel with bytes appended). Before booting: its
#           measured .linux is the first image's plus the bytes, and they alone change its predicted PCR 11. Not
#           approved, both peers refuse it naming PCR 11; approved, it boots unattended. Each time the client's console
#           line gives the initrd-phase PCR 11 its own build record predicts. No journald forwarding on its command
#           line (#413): the client's lines reach the console through its unit.
#   boot 2d THE SAME IMAGE, RETIRED: the document lists the current image only. The TPM releases the local
#           half all the same (its signed PCR 11 policy has no counter), both peers refuse the quote naming
#           PCR 11, nothing is given; the client keeps asking, and the recovery key typed at the console opens.
#           Boot 2b then boots the current image again: retiring one image strands nothing.
#   boot 2b A CREDENTIAL FROM SMBIOS (a unit drop-in, as the firmware could pass one): not acted on, since
#           the image's command line stops systemd importing credentials; the unlock goes on.
#   boots 3-6  A PLANTED CREDENTIAL on the ESP (a unit drop-in, an extra unit, a tmpfiles line, an empty
#           file): PCR 12 is not the one the peers expect, and they refuse the quote.
#   boot 7  A COMMAND LINE FROM SMBIOS (io.systemd.stub.kernel-cmdline-extra, switching credential import
#           back on, and an extra unit): either the stub ignores it, or PCR 12 moves and the peers refuse;
#           nothing planted runs.
#   boot 8  NO PEER, FOR LONGER THAN ANY DEFAULT TIMEOUT (#70). The peers are unreachable; the client keeps
#           asking, at the backoff's schedule and past its cap; after 150 s a wrong key only brings the
#           prompt back (tries=0), and the recovery key still opens: neither systemd-cryptsetup nor the
#           root's device wait gave up, and nothing ended in a shell. Boots 8 and 9 need KVM.
#   boot 9  THE PEERS COME BACK (#70, a blackout). Unreachable for 150 s and past the backoff's cap, then
#           back: nobody types anything, and the host unlocks by itself.
#   boots 10-12  A NEW MANIFEST (#66 B3, the ESP advance). The ESP at epoch 2 with the TPM anchor still at 1
#           (a crash between regalia-esp-advance's two steps): rendered under epoch 2. Both at 2: rendered.
#           The order reversed, the ESP at 1 under an anchor at 2: a ROLLBACK, the recovery key. The ESP is
#           written here by the test, not by node.esp_advance (tests/test_baremetal_esp_advance.py), and the
#           peers stay at epoch 1, so these boots show the render, not an unlock under epoch 2.
#
# The guest is built here from Debian's own packages (mmdebstrap). REGALIA_BOOT_ROOTFS names a directory
# to use instead; REGALIA_BOOT_IMAGE (with REGALIA_BOOT_CASES=verity) boots #61's image itself.
#
# NOT covered: Secure Boot (OVMF runs without enrolled keys; the image is signed but nothing checks it),
# a modified initrd (PoC 6.3), any physical TPM or DL360, and the real datacenter networks.
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
[ "$(id -u)" = 0 ] || { echo "unlock-boot-qemu: run as root"; exit 2; }
GO="${REGALIA_GO:?set REGALIA_GO to a go (from 1.21: it launches the release go.mod pins, which builds the client)}"
OVMF="${REGALIA_OVMF:-/usr/share/OVMF}"
[ -r "$OVMF/OVMF_CODE_4M.fd" ] && [ -r "$OVMF/OVMF_VARS_4M.fd" ] || { echo "unlock-boot-qemu: OVMF is required ($OVMF/OVMF_CODE_4M.fd)"; exit 2; }
for t in qemu-system-x86_64 swtpm tpm2_createek cryptsetup veritysetup mkfs.ext4 mkfs.vfat sfdisk losetup wipefs blockdev openssl wg nft ip python3 tar; do
  command -v "$t" >/dev/null || { echo "unlock-boot-qemu: $t is required"; exit 2; }
done
W="$(mktemp -d /var/tmp/regalia-boot.XXXXXX)"; chmod 700 "$W"
MOUNTED=()
cleanup(){
  for m in "${MOUNTED[@]:-}"; do [ -n "$m" ] && umount -R "$m" 2>/dev/null; done
  [ -e /dev/mapper/regalia-boot-build ] && cryptsetup close regalia-boot-build 2>/dev/null
  [ -n "${LOOP:-}" ] && losetup -d "$LOOP" 2>/dev/null
  # Never through a mount: the build binds this machine's /dev, /sys and /proc under $W.
  if grep -q " $W" /proc/mounts; then
    echo "unlock-boot-qemu: something is still mounted under $W: it is NOT removed" >&2
  elif [ "${REGALIA_BOOT_KEEP:-0}" != 1 ]; then
    rm -rf --one-file-system -- "$W"
  fi
}
trap cleanup EXIT
RECOVERY="cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb"
# which boots (#61 K61V-4): "unlock", the boots through a peer (the default), or "verity", the verity /usr's own boots,
# run on the REAL image (REGALIA_BOOT_IMAGE: a build-rootfs.sh output directory, its rootfs.tar the guest's tree)
CASES="${REGALIA_BOOT_CASES:-unlock}"
case "$CASES" in
  unlock) ;;
  verity) [ -n "${REGALIA_BOOT_IMAGE:-}" ] && [ -f "$REGALIA_BOOT_IMAGE/rootfs.tar" ] \
            || { echo "unlock-boot-qemu: REGALIA_BOOT_CASES=verity boots the real image: set REGALIA_BOOT_IMAGE to a build-rootfs.sh output directory"; exit 2; } ;;
  *) echo "unlock-boot-qemu: REGALIA_BOOT_CASES is unlock or verity, not '$CASES'"; exit 2 ;;
esac
HEAD="$(git -c safe.directory="$PWD" rev-parse --verify HEAD)"

SUITE="${REGALIA_BOOT_SUITE:-trixie}"
echo "### the guest's root tree (Debian $SUITE)"
ROOT="$W/root"
if [ -n "${REGALIA_BOOT_ROOTFS:-}" ]; then
  cp -a "$REGALIA_BOOT_ROOTFS" "$ROOT"
else
  command -v mmdebstrap >/dev/null || { echo "unlock-boot-qemu: mmdebstrap is required (or REGALIA_BOOT_ROOTFS)"; exit 2; }
  # a snapshot of the archive (REGALIA_BOOT_MIRROR=https://snapshot.debian.org/archive/debian/<time>/ in CI) gives
  # the same packages on every run, so the initrd matches its reviewed inventory (#198); its Release file is
  # past its Valid-Until, which only a snapshot may be
  APTOPT=()
  case "${REGALIA_BOOT_MIRROR:-}" in *snapshot.debian.org*) APTOPT=(--aptopt='Acquire::Check-Valid-Until "false"') ;; esac
  # the main suite, its updates and its SECURITY suite (REGALIA_BOOT_SECURITY_MIRROR, the security archive's
  # snapshot at the same time in CI): a reviewed baseline without security updates is not one to ship (#198)
  MIRROR="${REGALIA_BOOT_MIRROR:-http://deb.debian.org/debian}"
  # (explicit lines name their keyring: mmdebstrap only picks one by itself for a bare mirror URL)
  KEYRING="$(e2e/lib/debian-keyring.sh "$W/keyring")"      # Debian's own, pinned: the runner's predates trixie's keys
  SOURCES=("deb [signed-by=$KEYRING] $MIRROR $SUITE main" "deb [signed-by=$KEYRING] $MIRROR $SUITE-updates main"
           "deb [signed-by=$KEYRING] ${REGALIA_BOOT_SECURITY_MIRROR:-http://deb.debian.org/debian-security} $SUITE-security main")
  mmdebstrap --variant=minbase "${APTOPT[@]}" \
    --include=systemd-sysv,udev,kmod,linux-image-amd64,dracut,systemd-cryptsetup,cryptsetup-bin,wireguard-tools,nftables,iproute2,e2fsprogs,tpm2-tools,ca-certificates,systemd-ukify,systemd-boot-efi,sbsigntool,openssl,python3-cryptography,git \
    "$SUITE" "$ROOT" "${SOURCES[@]}" >"$W/mmdebstrap.log" 2>&1 \
    || { tail -40 "$W/mmdebstrap.log"; echo "unlock-boot-qemu: mmdebstrap failed"; exit 2; }
  # the guest's own apt reads the same lines: the keyring at the same path inside it
  install -D -m 0644 "$KEYRING" "$ROOT$KEYRING"
fi
echo "### the initrd, built reproducibly by deploy/baremetal/initrd/build-initrd.sh (#248), at the guest's snapshot"
# the same archive snapshot as the guest's tree: the builder takes its time from the mirror's URL
SNAPSHOT="${REGALIA_BOOT_SNAPSHOT:-}"
if [ -z "$SNAPSHOT" ] && [[ "${REGALIA_BOOT_MIRROR:-}" =~ snapshot\.debian\.org/archive/debian/([0-9]{8}T[0-9]{6}Z) ]]; then SNAPSHOT="${BASH_REMATCH[1]}"; fi
[ -n "$SNAPSHOT" ] || { echo "unlock-boot-qemu: the initrd is built from a pinned archive snapshot: set REGALIA_BOOT_MIRROR to a snapshot.debian.org URL, or REGALIA_BOOT_SNAPSHOT"; exit 2; }
[ -n "${KEYRING:-}" ] || KEYRING="$(e2e/lib/debian-keyring.sh "$W/keyring")"
# the membership root the initrd trusts (#156): the fixed TEST root whose chains tests/vectors/highwater-v1.json
# holds, as its canonical file (the JSON string, no newline), as a ceremony record would give the real one
python3 -I -c 'import json,sys; v=json.load(open(sys.argv[1]))["root_public"]; open(sys.argv[2],"wb").write(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode())' \
  tests/vectors/highwater-v1.json "$W/root-key.json"
deploy/baremetal/initrd/build-initrd.sh --snapshot "$SNAPSHOT" --go "$GO" --keyring "$KEYRING" --root-key "$W/root-key.json" --out "$W/initrd-build" \
  || { echo "unlock-boot-qemu: the initrd builder failed"
       # a mismatched inventory leaves its three files in --out: keep them with the diagnostics CI uploads (#620's run)
       if [ -n "${REGALIA_DIAG_DIR:-}" ]; then
         mkdir -p "$REGALIA_DIAG_DIR"; cp -- "$W"/initrd-build/initrd-inventory.* "$W"/initrd-build/initrd-dracut.log "$REGALIA_DIAG_DIR"/ 2>/dev/null || true
       fi
       exit 2; }
BIN="$W/initrd-build/regalia-unlock"          # the client the builder compiled: the initrd's, and the host's
for fs in proc sys dev; do mount --bind "/$fs" "$ROOT/$fs"; MOUNTED+=("$ROOT/$fs"); done
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
# what systemd needs to talk to a TPM, and is only suggested by its package
chroot "$ROOT" apt-get install -y -qq --no-install-recommends 'libtss2-tcti-device0*' >"$W/apt.log" 2>&1 \
  || { tail -20 "$W/apt.log"; echo "unlock-boot-qemu: the TPM library did not install"; exit 2; }
# and mkfs.erofs, which makes the guest's /usr image (deploy/baremetal/image/usr-verity.sh, run in this tree, #61 K61V-4);
# installed after the tree is made, so its package list stays e2e/initrd-drift.sh's
{ chroot "$ROOT" apt-get update -qq && chroot "$ROOT" apt-get install -y -qq --no-install-recommends erofs-utils; } >>"$W/apt.log" 2>&1 \
  || { tail -20 "$W/apt.log"; echo "unlock-boot-qemu: erofs-utils did not install"; exit 2; }

# What a KMS host has installed: the client, the units, the script, the dracut module.
install -D -m 0755 "$BIN" "$ROOT/usr/bin/regalia-unlock"
install -D -m 0755 deploy/baremetal/initrd/wg-boot "$ROOT/usr/lib/regalia/wg-boot"
install -m 0644 deploy/baremetal/initrd/regalia-boot-render.service deploy/baremetal/initrd/regalia-unlock.service \
  deploy/baremetal/initrd/regalia-wg-boot.service "$ROOT/usr/lib/systemd/system/"
install -D -m 0755 deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/module-setup.sh"
install -m 0644 deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/crypttab"

echo "### the initrd the builder made, beside the guest's kernel of the same snapshot"
KVER="$(ls "$ROOT/lib/modules" | sort -V | tail -1)"
BUILT_KVER="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["kernel"])' "$W/initrd-build/initrd-build.json")"
[ "$BUILT_KVER" = "$KVER" ] || { echo "unlock-boot-qemu: the initrd was built for kernel $BUILT_KVER, the guest has $KVER"; exit 2; }
echo "### Debian kernel $KVER config at snapshot $SNAPSHOT (the UKI kernel)"
grep -E '^CONFIG_(FAT_FS|VFAT_FS|NLS_CODEPAGE_437|NLS_ASCII|NLS_ISO8859_1|NLS_UTF8|BINFMT_MISC)=' "$ROOT/boot/config-$KVER"
cp "$W/initrd-build/initrd.img" "$ROOT/boot/initrd.e2e"
chroot "$ROOT" lsinitrd /boot/initrd.e2e > "$W/lsinitrd.txt" 2>/dev/null || true
for f in 'etc/crypttab$' 'usr/bin/regalia-unlock$' 'usr/lib/regalia/wg-boot$' 'regalia-unlock\.service$' 'cryptsetup\.target\.wants/regalia-unlock\.service' 'regalia-wg-boot\.service$' \
         'systemd-pcrphase-initrd\.service$' 'initrd\.target\.wants/systemd-pcrphase-initrd\.service' 'systemd-pcrextend$' \
         'bin/wg$' 'bin/nft$' 'bin/ip$' 'wireguard\.ko' 'nf_tables\.ko' 'nft_ct\.ko' 'virtio_net\.ko'; do
  grep -q "$f" "$W/lsinitrd.txt" || { echo "unlock-boot-qemu: the initrd lacks $f"; grep -c . "$W/lsinitrd.txt"; exit 2; }
done
# nothing per host: no /etc/regalia, and the one crypttab line of the module
if grep -q 'etc/regalia' "$W/lsinitrd.txt"; then echo "unlock-boot-qemu: the initrd holds files under /etc/regalia"; exit 2; fi
# nothing in it acts on a credential by name: no generator of units from credentials, the imports reset
if grep -q 'systemd-debug-generator' "$W/lsinitrd.txt"; then echo "unlock-boot-qemu: the initrd holds systemd-debug-generator"; exit 2; fi
# every unit in the finished image that takes credentials by name has its reset, and systemd-cryptsetup's too
mkdir "$ROOT/tmp/ird"
chroot "$ROOT" sh -c 'cd /tmp/ird && lsinitrd --unpack /boot/initrd.e2e' >/dev/null 2>&1 || { echo "unlock-boot-qemu: cannot unpack the initrd"; exit 2; }
uncovered=""; taking=""
[ -f "$ROOT/tmp/ird/usr/lib/systemd/system/systemd-journald.service" ] || { echo "unlock-boot-qemu: the unpacked initrd has no systemd units"; exit 2; }
for unit in "$ROOT"/tmp/ird/usr/lib/systemd/system/*.service; do
  name="${unit##*/}"; case "$name" in regalia-*) continue ;; esac
  # the unit with all its drop-ins, as systemd reads it; the reset must be there and must sort last
  grep -qsE '^(ImportCredential|LoadCredential|LoadCredentialEncrypted)=[^[:space:]]' "$unit" "$unit.d/"*.conf || continue
  taking="$taking $name"
  last="$(ls "$unit.d/"*.conf 2>/dev/null | sort | tail -1)"
  [ "${last##*/}" = 99-regalia-no-credentials.conf ] || uncovered="$uncovered $name"
done
[ -f "$ROOT/tmp/ird/usr/lib/systemd/system/systemd-cryptsetup@.service.d/99-regalia-no-credentials.conf" ] || uncovered="$uncovered systemd-cryptsetup@.service"
# a drop-in under etc/ would come after every one under usr/: none may set a credential
if grep -rqsE '^(ImportCredential|LoadCredential|LoadCredentialEncrypted)=[^[:space:]]' "$ROOT"/tmp/ird/etc/systemd/system/; then
  uncovered="$uncovered (a credential setting under etc/systemd/system)"
fi
[ -z "$uncovered" ] || { echo "unlock-boot-qemu: units in the image that take credentials by name, with no reset:$uncovered"; exit 2; }
# not vacuous: journald takes credentials in every systemd 257 initrd, and it was found and reset
case " $taking " in *" systemd-journald.service "*) ;; *) echo "unlock-boot-qemu: the check found no credential-taking unit (journald):$taking"; exit 2 ;; esac
echo "units that take credentials, each reset last:$taking systemd-cryptsetup@.service"
rm -rf "$ROOT/tmp/ird"
chroot "$ROOT" lsinitrd -f etc/crypttab /boot/initrd.e2e | grep -v '^#' > "$W/crypttab.txt"
cmp -s "$W/crypttab.txt" <(grep -v '^#' deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab) \
  || { cat "$W/crypttab.txt"; echo "unlock-boot-qemu: the initrd's crypttab is not the module's"; exit 2; }

echo "### the guest's /usr, as the host image's (#61 K61V-4): / a tmpfs, /usr a verity image, /etc from /usr's factory copy"
# The guest boots what a KMS host boots: everything it runs is in /usr (an erofs image under dm-verity, made by
# deploy/baremetal/image/usr-verity.sh), enabled under /usr, and its /etc is /usr/share/factory/etc, copied at every
# boot by regalia-etc-factory.service (#723). The test adds only its two units (the enrolment step and the report), into
# /usr: so the guest's /usr is a TEST image, its root hash not the production one.
#   unlock: the guest is this tree (as before #61), given the image's /etc machinery from this commit: the factory copy's
#           unit, drop-ins and tmpfiles, and the "disable *" preset, with no enablement left under /etc
#   verity: the guest is the REAL image, REGALIA_BOOT_IMAGE's rootfs.tar (build-rootfs.sh), with the test's units
if [ "$CASES" = verity ]; then
  GUEST="$W/guest"; mkdir "$GUEST"
  tar -x --numeric-owner -f "$REGALIA_BOOT_IMAGE/rootfs.tar" -C "$GUEST" || { echo "unlock-boot-qemu: $REGALIA_BOOT_IMAGE/rootfs.tar cannot be read"; exit 2; }
  [ -d "$GUEST/usr/share/factory/etc" ] && [ -f "$GUEST/usr/lib/systemd/system/regalia-etc-factory.service" ] \
    || { echo "unlock-boot-qemu: $REGALIA_BOOT_IMAGE is not a verity image (no factory /etc, no regalia-etc-factory.service)"; exit 2; }
  # Fidelity: the verity /usr is exactly the shipped module-free tree. Drivers needed after
  # switch-root must already have been loaded by the UKI's initrd; never inject the builder's modules.
  [ ! -d "$GUEST/usr/lib/modules" ] || { echo "unlock-boot-qemu: shipped /usr unexpectedly carries modules"; exit 2; }
else
  GUEST="$ROOT"
  # This synthetic guest models the same module-free /usr as the real image. The UKI initrd is
  # already built; keep its kernel in /boot for ukify, but no builder modules may help after switch-root.
  rm -rf -- "$GUEST/usr/lib/modules"
  U=deploy/baremetal/units
  for f in "$U/regalia-etc-factory.service" "$U/00-regalia-etc.tmpfiles.conf"; do
    [ -f "$f" ] || { echo "unlock-boot-qemu: $f is missing: the guest's /etc could not be made at boot"; exit 2; }
  done
  install -m 0644 "$U/regalia-etc-factory.service" "$GUEST/usr/lib/systemd/system/"
  for d in "$U"/*.service.d; do
    [ -f "$d/regalia-etc.conf" ] && install -D -m 0644 "$d/regalia-etc.conf" "$GUEST/usr/lib/systemd/system/${d##*/}/regalia-etc.conf"
  done
  install -D -m 0644 "$U/00-regalia-etc.tmpfiles.conf" "$GUEST/usr/lib/tmpfiles.d/00-regalia-etc.conf"
  install -D -m 0644 deploy/baremetal/image/regalia-kms.preset "$GUEST/usr/lib/systemd/system-preset/00-regalia-kms.preset"
  find "$GUEST/etc/systemd/system" -type l -delete
  : > "$GUEST/etc/fstab"                      # / is a tmpfs, /usr and /var come from the command line
  : > "$GUEST/etc/machine-id"
  echo "alder" > "$GUEST/etc/hostname"
fi
# the test's own: the enrolment step and the report, enabled under /usr
mkdir -p "$GUEST/usr/lib/regalia" "$GUEST/usr/lib/systemd/system/multi-user.target.wants"
install -m 0755 e2e/lib/boot-guest/e2e-enrol e2e/lib/boot-guest/e2e-report "$GUEST/usr/lib/regalia/"
install -m 0644 e2e/lib/boot-guest/regalia-e2e-enrol.service e2e/lib/boot-guest/regalia-e2e-report.service "$GUEST/usr/lib/systemd/system/"
for u in regalia-e2e-enrol.service regalia-e2e-report.service; do ln -sfn "../$u" "$GUEST/usr/lib/systemd/system/multi-user.target.wants/$u"; done
if [ "$CASES" = unlock ]; then
  rm -rf "$GUEST/usr/share/factory/etc"; mkdir -p "$GUEST/usr/share/factory/etc"
  cp -a "$GUEST/etc/." "$GUEST/usr/share/factory/etc/"
fi
# usr_image NAME SEED: the guest's /usr as erofs and its hash tree (usr-verity.sh, run in this tree: its erofs-utils and
# cryptsetup-bin are the snapshot's), and the record uki.py and install-host.sh read (build-rootfs.sh's rootfs-build.json,
# its "usr" and commit), in $W/usr-NAME. Another SEED is another salt, so another root hash for the same files
EPOCH="$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2}T${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}Z" +%s)"
install -D -m 0755 deploy/baremetal/image/usr-verity.sh "$ROOT/build/usr-verity.sh"
usr_image(){
  local name="$1" seed="$2"
  mkdir -p "$ROOT/build/usr-src" "$ROOT/build/usr-out-$name" "$W/usr-$name"
  mount --bind "$GUEST/usr" "$ROOT/build/usr-src"; MOUNTED+=("$ROOT/build/usr-src")
  mount -o remount,bind,ro "$ROOT/build/usr-src"
  chroot "$ROOT" env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC bash /build/usr-verity.sh --usr /build/usr-src --seed "$seed" \
    --epoch "$EPOCH" --out "/build/usr-out-$name" > "$W/usr-verity-$name.log" 2>&1 \
    || { tail -20 "$W/usr-verity-$name.log"; echo "unlock-boot-qemu: the /usr image $name could not be made"; exit 2; }
  umount "$ROOT/build/usr-src"; unset 'MOUNTED[${#MOUNTED[@]}-1]'
  mv "$ROOT/build/usr-out-$name"/* "$W/usr-$name/"; rmdir "$ROOT/build/usr-out-$name"
  python3 -I - "$W/usr-$name/usr-verity.txt" "$seed" > "$W/usr-$name/rootfs-build.json" <<'PY'
import json, sys
usr = dict(l.rstrip("\n").partition("=")[::2] for l in open(sys.argv[1]) if l.strip())
for key in ("source_date_epoch", "erofs_size", "verity_size", "verity_format", "verity_data_block_size", "verity_hash_block_size"):
    usr[key] = int(usr[key])
json.dump({"schema": "regalia.rootfs-build/v1", "commit": sys.argv[2], "usr": usr}, sys.stdout, indent=1, sort_keys=True)
PY
  echo "/usr $name: usrhash=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["usr"]["roothash"])' "$W/usr-$name/rootfs-build.json")"
}
usr_image a "$HEAD"
if [ "$CASES" = verity ]; then
  # B: the same files under another seed, so another root hash: the next image an update writes to usr-b (A/B)
  usr_image b "$(printf 'regalia-kms e2e usr-b\0%s' "$HEAD" | sha256sum | cut -c1-40)"
  # C: the factory /etc taken out of /usr (#723's runtime case): regalia-etc-factory.service's assert fails, and with it
  # systemd-sysusers, apparmor.service and regalia-kms.service, each of which requires it (directly or through apparmor)
  mv "$GUEST/usr/share/factory/etc" "$W/factory-etc.aside"
  usr_image c "$(printf 'regalia-kms e2e usr-c\0%s' "$HEAD" | sha256sum | cut -c1-40)"
  mv "$W/factory-etc.aside" "$GUEST/usr/share/factory/etc"
  # WRONG USRHASH: A's record with ONE hex digit of its root hash changed (its PARTUUIDs then derived from it, as
  # build-rootfs.sh would write them): the UKI built from it names a /usr no partition carries
  python3 -I - "$W/usr-a/rootfs-build.json" > "$W/usr-wrong.json" <<'PY'
import json, sys
record = json.load(open(sys.argv[1]))
h = record["usr"]["roothash"]
h = h[:-1] + ("0" if h[-1] != "0" else "1")
uuid = lambda x: "-".join((x[:8], x[8:12], x[12:16], x[16:20], x[20:32]))
record["usr"].update(roothash=h, usr_partuuid=uuid(h[:32]), usr_verity_partuuid=uuid(h[32:]))
json.dump(record, sys.stdout, indent=1, sort_keys=True)
PY
fi

echo "### the unified kernel image, built and signed by deploy/baremetal/uki.py with TEST keys"
mkdir "$W/keys"
for k in initrd system secure-boot; do
  openssl genrsa -out "$W/keys/TEST-$k.key" 2048 2>/dev/null
  openssl rsa -in "$W/keys/TEST-$k.key" -pubout -out "$W/keys/TEST-$k.pub" 2>/dev/null
  openssl req -new -x509 -key "$W/keys/TEST-$k.key" -out "$W/keys/TEST-$k.crt" -subj "/CN=TEST $k key, not for production/" -days 30 2>/dev/null
done
mkdir -p "$ROOT/tmp/uki/src" "$ROOT/tmp/uki/out"
# #266: uki.py builds and signs only from a clean checkout at the commit the initrd was built from, and holds the
# build record's files to it: the guest gets a clone of this checkout's HEAD (git in the guest root), never a copy
git -C "$ROOT/tmp/uki/src" init --quiet
git -c safe.directory="$PWD" -C "$ROOT/tmp/uki/src" fetch --quiet --depth=1 "$PWD" HEAD     # CI's checkout is shallow
git -C "$ROOT/tmp/uki/src" checkout --quiet --detach FETCH_HEAD
[ "$(git -C "$ROOT/tmp/uki/src" rev-parse HEAD)" = "$(git -c safe.directory="$PWD" rev-parse HEAD)" ] || { echo "the guest's clone is not at HEAD"; exit 1; }
cp -r "$W/keys" "$ROOT/tmp/uki/"
cp "$W/initrd-build/initrd-build.json" "$ROOT/tmp/uki/initrd-build.json"      # the initrd's build record, an input (#248)
cp "$W/root-key.json" "$ROOT/tmp/uki/root-key.json"                           # the membership root it trusts, an input (#156)
printf '%s\n' "${REGALIA_BOOT_CMDLINE:-console=ttyS0,115200 net.ifnames=0 panic=30 loglevel=4 systemd.import_credentials=no init_on_free=1 init_on_alloc=1 rd.shell=0 rd.emergency=reboot}" > "$ROOT/tmp/uki/cmdline"
# root=tmpfs, usrhash= (from the /usr record), panic-on-corruption and /var's mount are uki.py's own words (#61 K61V-3/4):
# the command line here gives none of them (uki.py refuses one that does)
for r in "$W"/usr-*/rootfs-build.json; do d="${r%/rootfs-build.json}"; cp "$r" "$ROOT/tmp/uki/${d##*/}.json"; done
[ -f "$W/usr-wrong.json" ] && cp "$W/usr-wrong.json" "$ROOT/tmp/uki/usr-wrong.json"
KEYS="--initrd-key /tmp/uki/keys/TEST-initrd.key --initrd-cert /tmp/uki/keys/TEST-initrd.crt --system-key /tmp/uki/keys/TEST-system.key"
KEYS="$KEYS --system-cert /tmp/uki/keys/TEST-system.crt --secure-boot-key /tmp/uki/keys/TEST-secure-boot.key --secure-boot-cert /tmp/uki/keys/TEST-secure-boot.crt"
# #198: the review build records, run alone first, so that a refusal says what. The image is checked
# against deploy/baremetal/initrd/initrd-inventory.txt, every entry pinned; on a difference the lines that
# differ are printed (from `uki initrd-inventory --root /`, classed by the chroot's dpkg database), to read
# before a pull request changes the inventory.
cp "$BIN" "$ROOT/tmp/uki/regalia-unlock.compiled"
if ! chroot "$ROOT" sh -c "cd /tmp/uki/src && python3 -Es -m deploy.baremetal.uki initrd-review --initrd /boot/initrd.e2e --unlock-client /tmp/uki/regalia-unlock.compiled --root-key /tmp/uki/root-key.json" >"$W/review.json" 2>&1; then
  python3 -I -c 'import json,sys; [print(f) for f in json.load(open(sys.argv[1]))["findings"] if not f.startswith("inventory: ")]' "$W/review.json" 2>/dev/null \
    || cat "$W/review.json"
  chroot "$ROOT" sh -c "cd /tmp/uki/src && python3 -Es -m deploy.baremetal.uki initrd-inventory --initrd /boot/initrd.e2e --root /" > "$W/inventory.txt" 2>&1 || true
  { grep -v '^#' deploy/baremetal/initrd/initrd-inventory.txt || true; } | sed '/^$/d' | sort > "$W/pinned.txt"
  sort "$W/inventory.txt" > "$W/found.txt"
  echo "### the image's inventory lines the reviewed inventory does not hold (+) and the reverse (-):"
  comm -23 "$W/found.txt" "$W/pinned.txt" | sed 's/^/INVENTORY+ /' || true
  comm -13 "$W/found.txt" "$W/pinned.txt" | sed 's/^/INVENTORY- /' || true
  echo "unlock-boot-qemu: the image's initrd does not pass uki.py's review"; exit 2
fi
echo "the initrd passes uki.py's review (#198): inventory $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["inventory_sha256"][:16])' "$W/review.json")"
# shellcheck disable=SC2086  # the two lists are words on purpose
# uki_image NAME CMDLINE LINUX USR-RECORD (paths in the chroot): built twice (the signer requires a second builder's
# identical record), then signed; to $W/NAME.efi and its signed record $W/NAME.record.json
uki_image(){
  local name="$1" ukargs
  ukargs="--linux $3 --initrd /boot/initrd.e2e --cmdline $2 --os-release /usr/lib/os-release --uname $KVER --usr-record $4"
  ukargs="$ukargs --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub --pcrpkey /tmp/uki/keys/TEST-system.pub --initrd-build /tmp/uki/initrd-build.json --root-key /tmp/uki/root-key.json"
  # shellcheck disable=SC2086  # the lists are words on purpose
  chroot "$ROOT" sh -c "cd /tmp/uki/src && python3 -Es -m deploy.baremetal.uki build $ukargs --name $name --out /tmp/uki/out --unlock-client /tmp/uki/regalia-unlock.compiled \
    && python3 -Es -m deploy.baremetal.uki build $ukargs --name $name --out /tmp/uki/second --unlock-client /tmp/uki/regalia-unlock.compiled \
    && python3 -Es -m deploy.baremetal.uki sign $ukargs --record /tmp/uki/out/$name.record.json --second-record /tmp/uki/second/$name.record.json --out /tmp/uki/out $KEYS" \
    > "$W/uki-$name.log" 2>&1 || { cat "$W/uki-$name.log"; echo "unlock-boot-qemu: the image $name did not build or sign"; exit 2; }
  cp "$ROOT/tmp/uki/out/$name.efi" "$W/$name.efi"; cp "$ROOT/tmp/uki/out/$name.signed.json" "$W/$name.record.json"
}
uki_image e2e /tmp/uki/cmdline "/boot/vmlinuz-$KVER" /tmp/uki/usr-a.json
grep 'PCR 11' "$W/uki-e2e.log" || true
if [ "$CASES" = unlock ]; then
  # A SECOND SIGNED IMAGE of the same build (#135): the same initrd and kernel, one inert word more on its command
  # line, so another PCR 11, signed by the same keys. The TPM's signed PCR 11 policy accepts both; only the peers'
  # measurement document tells them apart. Boots 2c and 2d approve it and then retire it.
  printf '%s regalia.e2e-image=old\n' "$(cat "$ROOT/tmp/uki/cmdline")" > "$ROOT/tmp/uki/cmdline-old"
  uki_image e2e-old /tmp/uki/cmdline-old "/boot/vmlinuz-$KVER" /tmp/uki/usr-a.json
  # #75 TIER Q, Q1: AN IMAGE WHOSE KERNEL DIFFERS. The same kernel with bytes appended after its PE image, which the
  # loader ignores (it boots identically) and systemd-stub measures with the whole .linux section into PCR 11: only the
  # measurement differs, the property under test (regalia-kms-d9). A real second kernel would not do: the initrd's
  # modules are built for this one. Its command line has no systemd.journald.forward_to_console=1, as the default
  # REGALIA_BOOT_CMDLINE has none since #413 (nor a production image's); the sed below strips it from this image's
  # command line even when an override of REGALIA_BOOT_CMDLINE adds it back. The other boots take an override as given.
  { cat "$ROOT/boot/vmlinuz-$KVER"; head -c 4096 /dev/zero | tr '\0' 'R'; } > "$ROOT/tmp/uki/vmlinuz-k2"
  sed 's/ systemd\.journald\.forward_to_console=1//' "$ROOT/tmp/uki/cmdline" > "$ROOT/tmp/uki/cmdline-k2"
  uki_image e2e-k2 /tmp/uki/cmdline-k2 /tmp/uki/vmlinuz-k2 /tmp/uki/usr-a.json
  cmp -s "$W/e2e.efi" "$W/e2e-old.efi" && { echo "unlock-boot-qemu: the two images are the same file"; exit 2; }
  cmp -s "$W/e2e.efi" "$W/e2e-k2.efi" && { echo "unlock-boot-qemu: the Q1 image is the first image's file"; exit 2; }
else
  # the verity boots' images (#61 K61V-4), each the same build with another /usr record: B (the A/B update's next
  # image), C (the broken factory /etc), and A's record with one digit of its root hash changed (WRONG USRHASH)
  uki_image e2e-b /tmp/uki/cmdline "/boot/vmlinuz-$KVER" /tmp/uki/usr-b.json
  uki_image e2e-c /tmp/uki/cmdline "/boot/vmlinuz-$KVER" /tmp/uki/usr-c.json
  # WRONG USRHASH's console also carries the journal (systemd.journald.forward_to_console=1, this test image only): its
  # initrd fails behind the passphrase prompt, which holds systemd's status lines back, so its console said only "Boot has
  # failed", not why (measured on the #722 review's local run). The test asserts the cause, the /usr device's own failure
  printf '%s systemd.journald.forward_to_console=1\n' "$(cat "$ROOT/tmp/uki/cmdline")" > "$ROOT/tmp/uki/cmdline-badhash"
  uki_image e2e-badhash /tmp/uki/cmdline-badhash "/boot/vmlinuz-$KVER" /tmp/uki/usr-wrong.json
  for x in a b c; do cp "$W/usr-$x/rootfs-build.json" "$W/usr-$x.json"; done
fi
cp "$W/keys/TEST-initrd.pub" "$W/initrd.pub"
rm -rf "$ROOT/tmp/uki" "$W/keys"
for fs in dev sys proc; do umount -R "$ROOT/$fs"; done; MOUNTED=()

echo "### the disk, as install-host.sh lays out a host's (#61 K61V-4, its test mode): the ESP, usr-a and usr-b with their hash trees, and regalia-root, the LUKS2 /var"
# install-host.sh's sizes: a 1 GiB ESP, two 4 GiB usr slots and their 128 MiB hash trees, a /var of 4 GiB at least (sparse)
truncate -s 14G "$W/disk.img"
LOOP="$(losetup --find --show --partscan "$W/disk.img")"
mkdir "$W/install"
printf '%s\n' "$RECOVERY" | REGALIA_INSTALL_TEST=1 deploy/baremetal/image/install-host.sh --disk "$LOOP" --usr "$W/usr-a/usr.erofs" \
  --usr-verity "$W/usr-a/usr.verity" --rootfs-record "$W/usr-a/rootfs-build.json" --uki "$W/e2e.efi" --uki-record "$W/e2e.record.json" \
  --out "$W/install" > "$W/install.log" 2>&1 || { cat "$W/install.log"; echo "unlock-boot-qemu: install-host.sh refused the guest's disk"; exit 2; }
cat "$W/install.log"
PART="${LOOP}p6"
for _ in $(seq 1 50); do [ -b "$PART" ] && break; sleep 0.1; done
[ -b "$PART" ] || { echo "unlock-boot-qemu: no partition device $PART"; exit 2; }
# the recovery key is install-host.sh's installer passphrase (keyslot 0), its argon2id slot converted to pbkdf2 at
# 1000 iterations: an emulated guest's console would spend minutes on argon2id at every typed key. The token marks it
# as systemd's recovery key, as recovery-key.sh --enrol leaves a host's
printf '%s' "$RECOVERY" | cryptsetup luksConvertKey --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file - "$PART"
printf '{"type":"systemd-recovery","keyslots":["0"]}' | cryptsetup token import --json-file - "$PART"
mkdir "$W/esp"; mount "${LOOP}p1" "$W/esp"; MOUNTED+=("$W/esp")
mkdir -p "$W/esp/loader/credentials"; echo "the image: $(stat -c %s "$W/e2e.efi") bytes"
umount "$W/esp"; MOUNTED=()
losetup -d "$LOOP"; LOOP=""
[ "$GUEST" = "$ROOT" ] || rm -rf --one-file-system "$GUEST"
rm -rf "$ROOT"

python3 -BI -c 'import sys; sys.path.insert(0, "e2e/lib"); import tpmdiag; print(tpmdiag.versions())' || true
if [ "$CASES" = verity ]; then CLASS=OnQemuVerity TEST=test_the_verity_usr_boots; else CLASS=OnQemu TEST=test_a_host_boots_through_a_peer; fi
echo "### the boots ($CASES): tests.test_baremetal_unlock_boot.$CLASS"
out="$(REGALIA_EXPECT_QEMU=1 REGALIA_EXPECT_KVM="${REGALIA_EXPECT_KVM:-0}" REGALIA_BOOT_DIR="$W" REGALIA_OVMF="$OVMF" REGALIA_UNLOCK_BIN="$BIN" python3 -BEs -m unittest -v "tests.test_baremetal_unlock_boot.$CLASS" </dev/null 2>&1)" && rc=0 || rc=$?
printf '%s\n' "$out"
if [ "$rc" != 0 ]; then
  for log in "$W"/console-*.log; do [ -e "$log" ] && { echo "----- $(basename "$log") (last 80 lines)"; tail -80 "$log"; }; done
  # regalia-zga/a0y: $W is removed on exit, so a failing run's consoles and swtpm logs (level 20) are copied out first,
  # for the job to upload (.github/actions/tpm-diagnostics)
  if [ -n "${REGALIA_DIAG_DIR:-}" ]; then
    mkdir -p "$REGALIA_DIAG_DIR"; cp -- "$W"/console-*.log "$W"/swtpm-*.log "$REGALIA_DIAG_DIR"/ 2>/dev/null || true
  fi
  # regalia-a0y: a boot whose firmware could not measure is the host's QEMU/swtpm, named apart from a product failure
  faulted="$(grep -l 'Failed to measure data for event [0-9]*: 0x8000000000000007' "$W"/console-*.log 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$faulted" != 0 ]; then
    echo "unlock-boot-qemu: FAILED: HOST TPM EMULATION FAULT (regalia-a0y) in $faulted boot(s): the host's QEMU/swtpm dropped a measurement, not the product"
    exit 1
  fi
  echo "unlock-boot-qemu: FAILED"; exit 1
fi
# (the test prints each boot's console digest between its name and its "ok", so the two are not on one line)
if ! grep -q "^$TEST" <<< "$out" || ! grep -q '^Ran 1 test' <<< "$out" || ! grep -qx 'OK' <<< "$out"; then
  echo "unlock-boot-qemu: the boot test did not run"; exit 1
fi
# The initrd's actual module payload and preload entry must belong to the UKI kernel just booted.
python3 -BEs e2e/tests/image-esp-content.py "$W/initrd-build" --kernel "$KVER"
[ "$CASES" = verity ] && { echo "unlock-boot-qemu: the verity /usr's boots passed (enrolment and the installer's firmware entry, an entry with options refused, the proof on every boot, the per-host units started after the reboot and gated without their files (the KMS refusing with no firewall), a wrong usrhash, a tampered block, A/B and the fallback, a broken factory /etc)"; exit 0; }
echo "unlock-boot-qemu: 17 boots passed (enrolment with the recovery key, an undecryptable credential and the recovery key, unattended through a peer, a forked chain refused by the TPM anchor, an older signed image approved and then retired (refused: the recovery key), an SMBIOS drop-in not acted on, four planted ESP credentials refused (one empty), an SMBIOS command line, no peer for 150 s and the recovery key, the peers back after 150 s and an unattended unlock, a new epoch on the ESP ahead of the anchor and with it, the ESP behind the anchor refused)"

