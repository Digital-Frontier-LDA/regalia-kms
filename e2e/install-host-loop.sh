#!/usr/bin/env bash
# install-host-loop.sh — deploy/baremetal/image/install-host.sh on loop devices (#61, second slice; the mirror, #544).
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
# a loop device or on a loop device over a block device, a disk holding partitions or a whole-device filesystem
# without --wipe, and a reinstall while the previous install's record is in --out.
# A MIRROR (--disk twice, #544), on two more loop devices: refused for one disk named twice, for three disks, and
# outside the test mode (it is not bootable yet); then made, and read back: on each disk an ESP and a Linux RAID member
# (esp-a/regalia-root-a, esp-b/regalia-root-b), RAID1 with metadata 1.2, one LUKS2 keyslot (argon2id) on the md, both
# ESPs holding the UKI and nothing else, and EITHER DISK ALONE assembling degraded and opening with the whole tree;
# the v2 install record names both disks, the md and the LUKS UUID.
# It INSTALLS nothing on this machine; it uses /run for its work and removes what it made by its exact paths.
# shellcheck disable=SC2319  # file-wide: `ok $?` reads the check made just before it, on purpose
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "install-host-loop: run as root"; exit 2; }
INSTALLER="$PWD/deploy/baremetal/image/install-host.sh"
W="$(mktemp -d /run/install-host-loop.XXXXXX)"
LOOP="" OVER="" BARE="" MA="" MB=""
passed=0 failed=0
ok(){ if [ "$1" = 0 ]; then passed=$((passed + 1)); echo "  PASS $2"; else failed=$((failed + 1)); echo "  FAIL $2"; fi; }
cleanup(){
  mountpoint -q "$W/check" 2>/dev/null && umount "$W/check"
  [ -e /dev/mapper/install-host-loop ] && cryptsetup close install-host-loop
  for md in /dev/md/regalia-root /dev/md/*regalia-root*; do [ -e "$md" ] && mdadm --stop "$md" >/dev/null 2>&1; done
  for l in "$OVER" "$BARE" "$MA" "$MB"; do [ -n "$l" ] && losetup "$l" >/dev/null 2>&1 && losetup -d "$l"; done
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
# a loop device over a block device is that device: the test mode asks no serial, so it is refused there too
OVER="$(losetup --find --show "$LOOP")"
out="$(install "$OVER" "$W/rootfs-build.json" 2>&1)" && rc=0 || rc=$?
losetup -d "$OVER"
[ "$rc" != 0 ] && grep -q "is for a loop device backed by a regular file" <<< "$out"; ok $? "the test mode is refused for a loop device over a block device"
# a filesystem on the WHOLE device holds no partition, and is data all the same
truncate -s 64M "$W/bare.img"; mkfs.ext4 -q -F "$W/bare.img"
BARE="$(losetup --find --show "$W/bare.img")"
out="$(install "$BARE" "$W/rootfs-build.json" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "holds data (partitions or signatures): refused without --wipe" <<< "$out" && [ "$(blkid -o value -s TYPE "$BARE")" = ext4 ]
ok $? "a filesystem on the whole device is refused without --wipe, and left as it was"
losetup -d "$BARE"

echo "### install"
install "$LOOP" "$W/rootfs-build.json"; ok $? "the installer finished"
udevadm settle
out="$(install "$LOOP" "$W/rootfs-build.json" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "holds data (partitions or signatures): refused without --wipe" <<< "$out"; ok $? "a disk holding partitions is refused without --wipe"
# with --wipe, the previous install's record still in --out: refused before the disk is touched
before="$(cryptsetup luksUUID "${LOOP}p2")"
out="$(install "$LOOP" "$W/rootfs-build.json" --wipe 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "install-test-$(basename "$LOOP").json exists: move it away first" <<< "$out" && [ "$(cryptsetup luksUUID "${LOOP}p2")" = "$before" ]
ok $? "a reinstall onto the previous install's record is refused, and the disk is untouched"

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

echo "### a mirror (#544): --disk twice"
truncate -s 2G "$W/mirror-a.img" "$W/mirror-b.img"
MA="$(losetup --find --show --partscan "$W/mirror-a.img")"; MB="$(losetup --find --show --partscan "$W/mirror-b.img")"
mirror(){ REGALIA_INSTALL_TEST=1 "$INSTALLER" --disk "$1" --disk "$2" --rootfs "$W/rootfs.tar" --rootfs-record "$W/rootfs-build.json" \
            --uki "$W/e2e-test.efi" --uki-record "$W/e2e-test.signed.json" --out "$W/out" "${@:3}" <<< "$PASS"; }
untouched(){ for d in "$@"; do [ -z "$(lsblk -no NAME "$d" | tail -n +2)" ] && [ -z "$(wipefs --noheadings "$d")" ] || return 1; done; }
out="$(mirror "$MA" "$MA" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "the two --disk are the same disk" <<< "$out" && untouched "$MA"; ok $? "one disk named twice is refused, and left as it was"
out="$(REGALIA_INSTALL_TEST=1 "$INSTALLER" --disk "$MA" --disk "$MB" --disk "$LOOP" --rootfs "$W/rootfs.tar" --rootfs-record "$W/rootfs-build.json" \
         --uki "$W/e2e-test.efi" --uki-record "$W/e2e-test.signed.json" --out "$W/out" <<< "$PASS" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "given once, or twice for a mirror" <<< "$out" && untouched "$MA" "$MB"; ok $? "three disks are refused"
# outside the test mode a mirror is refused before any serial is asked: the image cannot boot one yet
out="$("$INSTALLER" --disk "$MA" --disk "$MB" --rootfs "$W/rootfs.tar" --rootfs-record "$W/rootfs-build.json" \
         --uki "$W/e2e-test.efi" --uki-record "$W/e2e-test.signed.json" --out "$W/out" < /dev/null 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "a mirrored install is not bootable yet" <<< "$out" && untouched "$MA" "$MB"; ok $? "a mirror outside the test mode is refused, both disks untouched"
mirror "$MA" "$MB"; ok $? "the installer made the mirror"
udevadm settle
stop_md(){ for md in /dev/md/regalia-root /dev/md/*regalia-root*; do [ -e "$md" ] && mdadm --stop "$md" >/dev/null 2>&1; done; true; }
stop_md                                            # udev may have assembled it again once the members were seen
python3 -I - "$(sfdisk -J "$MA")" "$(sfdisk -J "$MB")" <<'PY'; ok $? "GPT on each: an ESP and a Linux RAID member, regalia-root-a and regalia-root-b"
import json, sys
for side, layout in zip("ab", sys.argv[1:]):
    parts = json.loads(layout)["partitiontable"]["partitions"]
    assert len(parts) == 2, parts
    assert parts[0]["type"].upper() == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" and parts[0].get("name") == "esp-" + side, parts[0]
    assert parts[1]["type"].upper() == "A19D880F-05FC-4D3B-A006-743F0F84911E" and parts[1].get("name") == "regalia-root-" + side, parts[1]
PY
mdadm --assemble /dev/md/regalia-root "${MA}p2" "${MB}p2" >/dev/null 2>&1; ok $? "the two members assemble"
# an md of that name already running is someone else's: refused before any write, and left running
before="$(cryptsetup luksUUID /dev/md/regalia-root)"
out="$(mirror "$MA" "$MB" --wipe --out "$W/out-again" 2>&1)" && rc=0 || rc=$?
# (--out elsewhere: the first install's record would refuse it earlier, and this is about the md)
[ "$rc" != 0 ] && grep -q "/dev/md/regalia-root already exists on this system" <<< "$out" && [ -e /dev/md/regalia-root ] \
  && [ "$(cryptsetup luksUUID /dev/md/regalia-root)" = "$before" ]
ok $? "an md of that name already assembled is refused before anything is written, and left running"
detail="$(mdadm --detail --export /dev/md/regalia-root)"
grep -qx 'MD_LEVEL=raid1' <<< "$detail" && grep -qx 'MD_DEVICES=2' <<< "$detail" && grep -qx 'MD_METADATA=1.2' <<< "$detail"; ok $? "RAID1, two devices, metadata 1.2"
mmeta="$(cryptsetup luksDump --dump-json-metadata /dev/md/regalia-root)"
python3 -I - "$mmeta" <<'PY'; ok $? "LUKS2 on the md: exactly one keyslot, argon2id"
import json, sys
m = json.loads(sys.argv[1])
assert len(m["keyslots"]) == 1 and next(iter(m["keyslots"].values()))["kdf"]["type"] == "argon2id", m["keyslots"]
PY
for side in a b; do
  e="$([ "$side" = a ] && echo "${MA}p1" || echo "${MB}p1")"
  mount -o ro "$e" "$W/check"
  [ "$(sha256sum < "$W/check/EFI/Linux/e2e-test.efi" | cut -d' ' -f1)" = "$uki" ] && [ "$(sha256sum < "$W/check/EFI/BOOT/BOOTX64.EFI" | cut -d' ' -f1)" = "$uki" ] \
    && [ "$(cd "$W/check" && find . -type f | sort | tr '\n' ' ')" = "./EFI/BOOT/BOOTX64.EFI ./EFI/Linux/e2e-test.efi " ]
  ok $? "ESP $side holds the UKI at both paths, byte for byte, and nothing else"
  umount "$W/check"
done
mluks="$(cryptsetup luksUUID /dev/md/regalia-root)"; mdu="$(sed -n 's/^MD_UUID=//p' <<< "$detail")"
stop_md
# EITHER DISK ALONE: the other gone, its one member assembles degraded and the volume opens with the whole tree
for side in a b; do
  member="$([ "$side" = a ] && echo "${MA}p2" || echo "${MB}p2")"
  mdadm --assemble --run /dev/md/regalia-root "$member" >/dev/null 2>&1 \
    && printf '%s' "$PASS" | cryptsetup open --key-file - /dev/md/regalia-root install-host-loop \
    && mount -o ro /dev/mapper/install-host-loop "$W/check" \
    && diff <(cd "$W/tree" && find . -mindepth 1 -printf '%P %y %m %U %G %l\n' | sort) \
            <(cd "$W/check" && find . -mindepth 1 \! -path './lost+found*' \! -path ./efi -printf '%P %y %m %U %G %l\n' | sort) >/dev/null
  ok $? "disk $side alone: its member assembles degraded and the volume opens with the whole tree"
  mountpoint -q "$W/check" && umount "$W/check"; [ -e /dev/mapper/install-host-loop ] && cryptsetup close install-host-loop; stop_md
done
mrecord="$W/out/install-test-$(basename "$MA")+test-$(basename "$MB").json"
python3 -I - "$mrecord" "$mdu" "$mluks" "$uki" "$(blkid -s PARTUUID -o value "${MA}p1")" "$(blkid -s PARTUUID -o value "${MB}p2")" <<'PY'; ok $? "the install record (v2) names both disks, the md and the LUKS UUID"
import json, sys
r = json.load(open(sys.argv[1]))
assert r["schema"] == "regalia.install/v2" and r["layout"] == "raid1", r
assert r["md_uuid"] == sys.argv[2] and r["luks_uuid"] == sys.argv[3] and r["uki_sha256"] == sys.argv[4], r
assert [d["disk_serial"].startswith("test-loop") for d in r["disks"]] == [True, True], r["disks"]
assert r["disks"][0]["esp_partuuid"] == sys.argv[5] and r["disks"][1]["member_partuuid"] == sys.argv[6], r["disks"]
assert r["efi_entry"] is False
PY

echo
echo "install-host-loop: $passed passed, $failed failed"
[ "$failed" = 0 ]
