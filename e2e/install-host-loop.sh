#!/usr/bin/env bash
# install-host-loop.sh — deploy/baremetal/image/install-host.sh on a loop device (#61, second slice).
#
#   sudo e2e/install-host-loop.sh
#
# A small stand-in rootfs.tar and a stand-in UKI file, each with the record the installer checks, installed onto a 2 GiB
# sparse loop device in the installer's test mode. Then, read back from the disk itself:
#   the GPT (two partitions: the ESP type, and Linux root x86-64 labelled regalia-root, the initrd crypttab's PARTLABEL);
#   the LUKS2 header (argon2id, exactly one keyslot, the label), opened with the installer passphrase;
#   every file of the stand-in tree inside it, with its owner and mode (numeric), and an empty /efi of mode 0700;
#   the ESP holding the UKI at \EFI\Linux\<name>.efi and \EFI\BOOT\BOOTX64.EFI, byte for byte, and nothing else;
#   the install record, naming the digests and UUIDs it found.
# And refused, each before anything is written: an input that is not its record's, the test mode on a disk that is not
# a loop device, and a disk holding partitions without --wipe.
# It INSTALLS nothing on this machine; it uses /run for its work and removes what it made by its exact paths.
# shellcheck disable=SC2319  # file-wide: `ok $?` reads the check made just before it, on purpose
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "install-host-loop: run as root"; exit 2; }
INSTALLER="$PWD/deploy/baremetal/image/install-host.sh"
W="$(mktemp -d /run/install-host-loop.XXXXXX)"
LOOP=""
passed=0 failed=0
ok(){ if [ "$1" = 0 ]; then passed=$((passed + 1)); echo "  PASS $2"; else failed=$((failed + 1)); echo "  FAIL $2"; fi; }
cleanup(){
  mountpoint -q "$W/check" 2>/dev/null && umount "$W/check"
  [ -e /dev/mapper/install-host-loop ] && cryptsetup close install-host-loop
  [ -n "$LOOP" ] && losetup -d "$LOOP"
  rm -rf --one-file-system -- "$W"
}
trap cleanup EXIT
PASS="installer-test-passphrase"

# the stand-ins, with the records the installer reads
mkdir -p "$W/tree/etc" "$W/tree/usr/bin" "$W/tree/var/lib/thing"
echo "hello" > "$W/tree/etc/greeting"; chmod 0644 "$W/tree/etc/greeting"
printf '#!/bin/sh\necho hi\n' > "$W/tree/usr/bin/tool"; chmod 0755 "$W/tree/usr/bin/tool"
chown 123:456 "$W/tree/var/lib/thing"; chmod 0700 "$W/tree/var/lib/thing"
ln -s ../usr/bin/tool "$W/tree/etc/tool-link"
tar --numeric-owner --sort=name -cf "$W/rootfs.tar" -C "$W/tree" .
printf '{"rootfs_sha256": "%s", "commit": "test"}\n' "$(sha256sum < "$W/rootfs.tar" | cut -d' ' -f1)" > "$W/rootfs-build.json"
head -c 300000 /dev/urandom > "$W/e2e-test.efi"
printf '{"signed": {"image_sha256": "%s"}}\n' "$(sha256sum < "$W/e2e-test.efi" | cut -d' ' -f1)" > "$W/e2e-test.signed.json"
truncate -s 2G "$W/disk.img"
LOOP="$(losetup --find --show --partscan "$W/disk.img")"
install(){ REGALIA_INSTALL_TEST=1 "$INSTALLER" --disk "$1" --rootfs "$W/rootfs.tar" --rootfs-record "$2" --uki "$W/e2e-test.efi" \
             --uki-record "$W/e2e-test.signed.json" --out "$W/out" "${@:3}" <<< "$PASS"; }

# from here every check reports PASS or FAIL and the script goes on: errexit would end it at the first failing
# check instead of saying which (and `ok $?` is meant to read the check just made)
set +e
echo "### refusals before anything is written"
printf '{"rootfs_sha256": "%s", "commit": "test"}\n' "$(printf 0%.0s {1..64})" > "$W/wrong-record.json"
out="$(install "$LOOP" "$W/wrong-record.json" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "rootfs.tar is not the file its record names" <<< "$out" && [ -z "$(lsblk -no NAME "$LOOP" | tail -n +2)" ]; ok $? "an input that is not its record's is refused, and the disk is untouched"
out="$(REGALIA_INSTALL_TEST=1 "$INSTALLER" --disk /dev/null --rootfs "$W/rootfs.tar" --rootfs-record "$W/rootfs-build.json" --uki "$W/e2e-test.efi" \
         --uki-record "$W/e2e-test.signed.json" --out "$W/out" <<< "$PASS" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -qE "not a block device|is for a /dev/loopN only" <<< "$out"; ok $? "the test mode is refused for anything but a loop device"

echo "### install"
install "$LOOP" "$W/rootfs-build.json"; ok $? "the installer finished"
udevadm settle
out="$(install "$LOOP" "$W/rootfs-build.json" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "holds partitions: refused without --wipe" <<< "$out"; ok $? "a disk holding partitions is refused without --wipe"

echo "### the disk, read back"
layout="$(sfdisk -J "$LOOP")"
python3 -I - "$layout" <<'PY'; ok $? "GPT: an ESP and a Linux-root partition labelled regalia-root"
import json, sys
parts = json.loads(sys.argv[1])["partitiontable"]["partitions"]
assert len(parts) == 2, parts
assert parts[0]["type"].upper() == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" and parts[0].get("name") == "esp", parts[0]
assert parts[1]["type"].upper() == "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" and parts[1].get("name") == "regalia-root", parts[1]
PY
ESP_DEV="${LOOP}p1" ROOT_DEV="${LOOP}p2"
meta="$(cryptsetup luksDump --dump-json-metadata "$ROOT_DEV")"
python3 -I - "$meta" <<'PY'; ok $? "LUKS2: exactly one keyslot, argon2id"
import json, sys
m = json.loads(sys.argv[1])
assert len(m["keyslots"]) == 1, m["keyslots"].keys()
assert next(iter(m["keyslots"].values()))["kdf"]["type"] == "argon2id"
PY
[ "$(cryptsetup luksDump "$ROOT_DEV" | sed -n 's/^Label:[[:space:]]*//p')" = regalia-root ]; ok $? "the LUKS2 label is regalia-root"
printf '%s' "$PASS" | cryptsetup open --key-file - "$ROOT_DEV" install-host-loop; ok $? "the installer passphrase opens the volume"
mkdir -p "$W/check"
mount -o ro /dev/mapper/install-host-loop "$W/check"
diff <(cd "$W/tree" && find . -mindepth 1 -printf '%P %y %m %U %G %l\n' | sort) \
     <(cd "$W/check" && find . -mindepth 1 \! -path './lost+found*' \! -path ./efi -printf '%P %y %m %U %G %l\n' | sort); ok $? "every file of the tree is inside, owner and mode kept"
[ "$(stat -c '%a %F' "$W/check/efi")" = "700 directory" ] && [ -z "$(ls -A "$W/check/efi")" ]; ok $? "an empty /efi of mode 0700"
umount "$W/check"; cryptsetup close install-host-loop
mount -o ro "$ESP_DEV" "$W/check"
uki="$(sha256sum < "$W/e2e-test.efi" | cut -d' ' -f1)"
[ "$(sha256sum < "$W/check/EFI/Linux/e2e-test.efi" | cut -d' ' -f1)" = "$uki" ] && [ "$(sha256sum < "$W/check/EFI/BOOT/BOOTX64.EFI" | cut -d' ' -f1)" = "$uki" ]
ok $? "the ESP holds the UKI at \\EFI\\Linux and at the removable-media path, byte for byte"
[ "$(cd "$W/check" && find . -type f | sort | tr '\n' ' ')" = "./EFI/BOOT/BOOTX64.EFI ./EFI/Linux/e2e-test.efi " ]; ok $? "and nothing else"
umount "$W/check"
record="$W/out/install-test-$(basename "$LOOP").json"
python3 -I - "$record" "$(sha256sum < "$W/rootfs.tar" | cut -d' ' -f1)" "$uki" "$(cryptsetup luksUUID "$ROOT_DEV")" <<'PY'; ok $? "the install record names the digests and the LUKS UUID"
import json, sys
r = json.load(open(sys.argv[1]))
assert r["rootfs_sha256"] == sys.argv[2] and r["uki_sha256"] == sys.argv[3] and r["luks_uuid"] == sys.argv[4], r
assert r["efi_entry"] is False
PY

echo
echo "install-host-loop: $passed passed, $failed failed"
[ "$failed" = 0 ]
