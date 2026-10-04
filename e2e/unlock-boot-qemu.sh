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
# the client compiled by the builder) and is the same for every host. Its disk: an ESP (the
# image as EFI/BOOT/BOOTX64.EFI, and the host's credentials in loader/credentials, which systemd-stub
# measures into PCR 12) and a GPT partition labelled regalia-root, a LUKS2 volume. The peers run on this
# machine, in network namespaces, as in e2e/wg-boot-netns.sh; nothing is loaded outside a namespace.
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
#   boot 2k #75 TIER Q, Q1: AN IMAGE WHOSE KERNEL DIFFERS (the same kernel with bytes appended): its predicted PCR 11
#           differs in both phases, it boots unattended once approved, and the client's console line gives the
#           initrd-phase PCR 11 its own build record predicts. Its command line has no journald forwarding (#413).
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
#
# The guest is built here from Debian's own packages (mmdebstrap). REGALIA_BOOT_ROOTFS names a directory
# to use instead: the one variable to change when the appliance image of #61 exists.
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
for t in qemu-system-x86_64 swtpm tpm2_createek cryptsetup mkfs.ext4 mkfs.vfat sfdisk openssl wg nft ip python3; do
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
  || { echo "unlock-boot-qemu: the initrd builder failed"; exit 2; }
BIN="$W/initrd-build/regalia-unlock"          # the client the builder compiled: the initrd's, and the host's
for fs in proc sys dev; do mount --bind "/$fs" "$ROOT/$fs"; MOUNTED+=("$ROOT/$fs"); done
cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
# what systemd needs to talk to a TPM, and is only suggested by its package
chroot "$ROOT" apt-get install -y -qq --no-install-recommends 'libtss2-tcti-device0*' >"$W/apt.log" 2>&1 \
  || { tail -20 "$W/apt.log"; echo "unlock-boot-qemu: the TPM library did not install"; exit 2; }

# What a KMS host has installed: the client, the units, the script, the dracut module.
install -D -m 0755 "$BIN" "$ROOT/usr/bin/regalia-unlock"
install -D -m 0755 deploy/baremetal/initrd/wg-boot "$ROOT/usr/lib/regalia/wg-boot"
install -m 0644 deploy/baremetal/initrd/regalia-boot-render.service deploy/baremetal/initrd/regalia-unlock.service \
  deploy/baremetal/initrd/regalia-wg-boot.service "$ROOT/usr/lib/systemd/system/"
install -D -m 0755 deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/module-setup.sh"
install -m 0644 deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab "$ROOT/usr/lib/dracut/modules.d/90regalia-unlock/crypttab"
# And what only the test adds, in the real root: the enrolment step and the report.
install -m 0755 e2e/lib/boot-guest/e2e-enrol e2e/lib/boot-guest/e2e-report "$ROOT/usr/lib/regalia/"
install -m 0644 e2e/lib/boot-guest/regalia-e2e-enrol.service e2e/lib/boot-guest/regalia-e2e-report.service "$ROOT/etc/systemd/system/"
mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"
for u in regalia-e2e-enrol.service regalia-e2e-report.service; do ln -sf "/etc/systemd/system/$u" "$ROOT/etc/systemd/system/multi-user.target.wants/$u"; done
echo "/dev/mapper/root / ext4 defaults 0 1" > "$ROOT/etc/fstab"
echo "lisbon" > "$ROOT/etc/hostname"

echo "### the initrd the builder made, beside the guest's kernel of the same snapshot"
KVER="$(ls "$ROOT/lib/modules" | sort -V | tail -1)"
BUILT_KVER="$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["kernel"])' "$W/initrd-build/initrd-build.json")"
[ "$BUILT_KVER" = "$KVER" ] || { echo "unlock-boot-qemu: the initrd was built for kernel $BUILT_KVER, the guest has $KVER"; exit 2; }
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
printf '%s\n' "${REGALIA_BOOT_CMDLINE:-root=/dev/mapper/root rw console=ttyS0,115200 net.ifnames=0 systemd.journald.forward_to_console=1 panic=30 loglevel=4 systemd.import_credentials=no init_on_free=1 init_on_alloc=1 rd.shell=0 rd.emergency=reboot rootflags=x-systemd.device-timeout=0}" > "$ROOT/tmp/uki/cmdline"
IN="--linux /boot/vmlinuz-$KVER --initrd /boot/initrd.e2e --cmdline /tmp/uki/cmdline --os-release /usr/lib/os-release --uname $KVER"
IN="$IN --stub /usr/lib/systemd/boot/efi/linuxx64.efi.stub --pcrpkey /tmp/uki/keys/TEST-system.pub --initrd-build /tmp/uki/initrd-build.json --root-key /tmp/uki/root-key.json"
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
# two builds (the signer requires a second builder's identical record), then the signature
chroot "$ROOT" sh -c "cd /tmp/uki/src && python3 -Es -m deploy.baremetal.uki build $IN --name e2e --out /tmp/uki/out --unlock-client /tmp/uki/regalia-unlock.compiled \
  && python3 -Es -m deploy.baremetal.uki build $IN --name e2e --out /tmp/uki/second --unlock-client /tmp/uki/regalia-unlock.compiled \
  && python3 -Es -m deploy.baremetal.uki sign $IN --record /tmp/uki/out/e2e.record.json --second-record /tmp/uki/second/e2e.record.json --out /tmp/uki/out $KEYS" >"$W/uki.log" 2>&1 \
  || { cat "$W/uki.log"; echo "unlock-boot-qemu: the image did not build or sign"; exit 2; }
grep 'PCR 11' "$W/uki.log" || true
# A SECOND SIGNED IMAGE of the same build (#135): the same initrd and kernel, one inert word more on its command
# line, so another PCR 11, signed by the same keys. The TPM's signed PCR 11 policy accepts both; only the peers'
# measurement document tells them apart. Boots 2c and 2d approve it and then retire it.
printf '%s regalia.e2e-image=old\n' "$(cat "$ROOT/tmp/uki/cmdline")" > "$ROOT/tmp/uki/cmdline-old"
IN_OLD="${IN/--cmdline \/tmp\/uki\/cmdline /--cmdline /tmp/uki/cmdline-old }"
# shellcheck disable=SC2086  # the two lists are words on purpose
chroot "$ROOT" sh -c "cd /tmp/uki/src && python3 -Es -m deploy.baremetal.uki build $IN_OLD --name e2e-old --out /tmp/uki/out --unlock-client /tmp/uki/regalia-unlock.compiled \
  && python3 -Es -m deploy.baremetal.uki build $IN_OLD --name e2e-old --out /tmp/uki/second --unlock-client /tmp/uki/regalia-unlock.compiled \
  && python3 -Es -m deploy.baremetal.uki sign $IN_OLD --record /tmp/uki/out/e2e-old.record.json --second-record /tmp/uki/second/e2e-old.record.json --out /tmp/uki/out $KEYS" >"$W/uki-old.log" 2>&1 \
  || { cat "$W/uki-old.log"; echo "unlock-boot-qemu: the second image did not build or sign"; exit 2; }
# #75 TIER Q, Q1: AN IMAGE WHOSE KERNEL DIFFERS. The same kernel with bytes appended after its PE image, which the
# loader ignores (it boots identically) and systemd-stub measures with the whole .linux section into PCR 11: only the
# measurement differs, the property under test (regalia-kms-d9). A real second kernel would not do: the initrd's
# modules are built for this one. Its command line has NO systemd.journald.forward_to_console=1 (a production
# image's has none either, #413): what its console shows is what the units themselves put there.
{ cat "$ROOT/boot/vmlinuz-$KVER"; head -c 4096 /dev/zero | tr '\0' 'R'; } > "$ROOT/tmp/uki/vmlinuz-k2"
sed 's/ systemd\.journald\.forward_to_console=1//' "$ROOT/tmp/uki/cmdline" > "$ROOT/tmp/uki/cmdline-k2"
IN_K2="${IN/--linux \/boot\/vmlinuz-$KVER /--linux /tmp/uki/vmlinuz-k2 }"
IN_K2="${IN_K2/--cmdline \/tmp\/uki\/cmdline /--cmdline /tmp/uki/cmdline-k2 }"
[ "$IN_K2" != "$IN" ] || { echo "unlock-boot-qemu: the Q1 image's inputs are the first image's"; exit 2; }
# shellcheck disable=SC2086  # the two lists are words on purpose
chroot "$ROOT" sh -c "cd /tmp/uki/src && python3 -Es -m deploy.baremetal.uki build $IN_K2 --name e2e-k2 --out /tmp/uki/out --unlock-client /tmp/uki/regalia-unlock.compiled \
  && python3 -Es -m deploy.baremetal.uki build $IN_K2 --name e2e-k2 --out /tmp/uki/second --unlock-client /tmp/uki/regalia-unlock.compiled \
  && python3 -Es -m deploy.baremetal.uki sign $IN_K2 --record /tmp/uki/out/e2e-k2.record.json --second-record /tmp/uki/second/e2e-k2.record.json --out /tmp/uki/out $KEYS" >"$W/uki-k2.log" 2>&1 \
  || { cat "$W/uki-k2.log"; echo "unlock-boot-qemu: the Q1 image (another kernel) did not build or sign"; exit 2; }
cp "$ROOT/tmp/uki/out/e2e-k2.efi" "$W/e2e-k2.efi"; cp "$ROOT/tmp/uki/out/e2e-k2.signed.json" "$W/e2e-k2.record.json"
cp "$ROOT/tmp/uki/out/e2e.efi" "$W/e2e.efi"; cp "$ROOT/tmp/uki/out/e2e.signed.json" "$W/e2e.record.json"; cp "$W/keys/TEST-initrd.pub" "$W/initrd.pub"
cp "$ROOT/tmp/uki/out/e2e-old.efi" "$W/e2e-old.efi"; cp "$ROOT/tmp/uki/out/e2e-old.signed.json" "$W/e2e-old.record.json"
cmp -s "$W/e2e.efi" "$W/e2e-old.efi" && { echo "unlock-boot-qemu: the two images are the same file"; exit 2; }
cmp -s "$W/e2e.efi" "$W/e2e-k2.efi" && { echo "unlock-boot-qemu: the Q1 image is the first image's file"; exit 2; }
rm -rf "$ROOT/tmp/uki" "$W/keys"
for fs in dev sys proc; do umount -R "$ROOT/$fs"; done; MOUNTED=()

echo "### the disk: the ESP with the image, and a GPT partition labelled regalia-root, a LUKS2 volume opened only by the recovery key so far"
truncate -s 4G "$W/disk.img"
printf 'label: gpt\nsize=512MiB, type=uefi, name=ESP\nname=regalia-root\n' | sfdisk -q "$W/disk.img"
LOOP="$(losetup --find --show --partscan "$W/disk.img")"
PART="${LOOP}p2"
for _ in $(seq 1 50); do [ -b "${LOOP}p1" ] && break; sleep 0.1; done
mkfs.vfat -n ESP "${LOOP}p1" >/dev/null
mkdir "$W/esp"; mount "${LOOP}p1" "$W/esp"; MOUNTED+=("$W/esp")
mkdir -p "$W/esp/EFI/BOOT" "$W/esp/loader/credentials"; cp "$W/e2e.efi" "$W/esp/EFI/BOOT/BOOTX64.EFI"; echo "the image: $(stat -c %s "$W/e2e.efi") bytes"
umount "$W/esp"; MOUNTED=()
for _ in $(seq 1 50); do [ -b "$PART" ] && break; sleep 0.1; done
[ -b "$PART" ] || { echo "unlock-boot-qemu: no partition device $PART"; exit 2; }
printf '%s' "$RECOVERY" | cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file - "$PART"
printf '{"type":"systemd-recovery","keyslots":["0"]}' | cryptsetup token import --json-file - "$PART"
printf '%s' "$RECOVERY" | cryptsetup open --key-file - "$PART" regalia-boot-build
mkfs.ext4 -q -L root /dev/mapper/regalia-boot-build
mkdir "$W/mnt"; mount /dev/mapper/regalia-boot-build "$W/mnt"; MOUNTED+=("$W/mnt")
cp -a "$ROOT/." "$W/mnt/"
umount "$W/mnt"; MOUNTED=()
cryptsetup close regalia-boot-build
losetup -d "$LOOP"; LOOP=""
rm -rf "$ROOT"

echo "### twelve boots"
out="$(REGALIA_EXPECT_QEMU=1 REGALIA_EXPECT_KVM="${REGALIA_EXPECT_KVM:-0}" REGALIA_BOOT_DIR="$W" REGALIA_OVMF="$OVMF" REGALIA_UNLOCK_BIN="$BIN" python3 -BEs -m unittest -v tests.test_baremetal_unlock_boot </dev/null 2>&1)" && rc=0 || rc=$?
printf '%s\n' "$out"
if [ "$rc" != 0 ]; then
  for log in "$W"/console-*.log; do [ -e "$log" ] && { echo "----- $(basename "$log") (last 80 lines)"; tail -80 "$log"; }; done
  echo "unlock-boot-qemu: FAILED"; exit 1
fi
# (the test prints each boot's console digest between its name and its "ok", so the two are not on one line)
if ! grep -q '^test_a_host_boots_through_a_peer' <<< "$out" || ! grep -q '^Ran 1 test' <<< "$out" || ! grep -qx 'OK' <<< "$out"; then
  echo "unlock-boot-qemu: the boot test did not run"; exit 1
fi
echo "unlock-boot-qemu: 14 boots passed (enrolment with the recovery key, an undecryptable credential and the recovery key, unattended through a peer, a forked chain refused by the TPM anchor, an older signed image approved and then retired (refused: the recovery key), an SMBIOS drop-in not acted on, four planted ESP credentials refused (one empty), an SMBIOS command line, no peer for 150 s and the recovery key, the peers back after 150 s and an unattended unlock)"
