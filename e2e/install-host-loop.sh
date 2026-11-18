#!/usr/bin/env bash
# install-host-loop.sh — deploy/baremetal/image/install-host.sh on loop devices (#61: the installer, then the dm-verity
# design's second slice: the A/B verity /usr partitions, and the LUKS2 regalia-root as /var).
#
#   sudo e2e/install-host-loop.sh
#
# A stand-in /usr tree made into usr.erofs and usr.verity by the build's own usr-verity.sh, with the rootfs-build.json
# "usr" the build writes from it, and a stand-in UKI file with its signed record, installed onto a 16 GiB sparse loop
# device in the installer's test mode. Then, read back from the disk itself:
#   the GPT: esp, usr-a, usr-a-verity, usr-b, usr-b-verity, regalia-root, each with the discoverable-partitions type
#   GUID, the sizes the updater relies on (A and B alike), the read-only flag on the four usr partitions, and usr-a's
#   and usr-a-verity's PARTUUIDs exactly the root hash's halves (the record's usr_partuuid, usr_verity_partuuid);
#   usr-a and usr-a-verity byte-equal to usr.erofs and usr.verity, `veritysetup verify` passing FROM THE PARTITIONS
#   with the root hash (and refusing another root hash: its control); a full usr partition's hash tree fits a verity one;
#   usr-b and usr-b-verity reserved and empty (no signature, the first MiB zero);
#   the LUKS2 header on regalia-root (argon2id, exactly one keyslot, the label), opened with the installer passphrase:
#   ext4 labelled regalia-var holding nothing (rootfs.tar is not extracted);
#   the ESP holding the UKI at \EFI\Linux\<name>.efi and \EFI\BOOT\BOOTX64.EFI, byte for byte, and nothing else;
#   the install record (v3), naming the root hash, every PARTUUID and the LUKS UUID.
# And refused, each before anything is written: an image that is not its record's, AN IMAGE WHOSE RECORD NAMES ITS
# sha256 BUT WHOSE BLOCKS veritysetup REFUSES, a record whose PARTUUIDs are not the root hash's halves, a record with no
# "usr", a UKI that is not its record's, --rootfs (no longer installed), a mirror (--disk twice), a disk too small for
# the layout, the test mode on a disk that is not a loop device or on a loop device over a block device, a whole-device
# filesystem without --wipe, a disk holding partitions without --wipe, and a reinstall while the previous record is in
# --out. Then a reinstall with --wipe over an image left in usr-b: usr-b is empty again.
# It INSTALLS nothing on this machine; it uses /run for its work and removes what it made by its exact paths.
# shellcheck disable=SC2319  # file-wide: `ok $?` reads the check made just before it, on purpose
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "install-host-loop: run as root"; exit 2; }
INSTALLER="$PWD/deploy/baremetal/image/install-host.sh"
USR_VERITY_SH="$PWD/deploy/baremetal/image/usr-verity.sh"
W="$(mktemp -d /run/install-host-loop.XXXXXX)"
LOOP="" OVER="" BARE="" SMALL="" OTHER=""
passed=0 failed=0
ok(){ if [ "$1" = 0 ]; then passed=$((passed + 1)); echo "  PASS $2"; else failed=$((failed + 1)); echo "  FAIL $2"; fi; }
cleanup(){
  mountpoint -q "$W/check" 2>/dev/null && umount "$W/check"
  [ -e /dev/mapper/install-host-loop ] && cryptsetup close install-host-loop
  for l in "$OVER" "$BARE" "$SMALL" "$OTHER"; do [ -n "$l" ] && losetup "$l" >/dev/null 2>&1 && losetup -d "$l"; done
  [ -n "$LOOP" ] && losetup -d "$LOOP"
  rm -rf --one-file-system -- "$W"
}
trap cleanup EXIT
PASS="installer-test-passphrase"
SEED="0123456789abcdef0123456789abcdef01234567"
GIB=$((1024 * 1024 * 1024)) MIB=$((1024 * 1024))

# the stand-ins: a /usr tree, made into the image by the build's own script, and the record the build writes from it
mkdir -p "$W/usr/bin" "$W/usr/share/factory/etc" "$W/usr/lib/thing" "$W/img"
echo "hello" > "$W/usr/share/factory/etc/greeting"; chmod 0644 "$W/usr/share/factory/etc/greeting"
printf '#!/bin/sh\necho hi\n' > "$W/usr/bin/tool"; chmod 0755 "$W/usr/bin/tool"
chown 123:456 "$W/usr/lib/thing"; chmod 0700 "$W/usr/lib/thing"
head -c 3000000 /dev/urandom > "$W/usr/lib/thing/blob"     # several hundred blocks: a hash tree of more than one level
ln -s ../bin/tool "$W/usr/lib/tool-link"
bash "$USR_VERITY_SH" --usr "$W/usr" --seed "$SEED" --epoch 1700000000 --out "$W/img" >/dev/null
USR="$W/img/usr.erofs" VER="$W/img/usr.verity"
# rootfs-build.json as build-rootfs.sh writes it: usr-verity.txt's lines, the counts as numbers ($1 the file, $2 python
# that may change the record "r" before it is written)
record(){ python3 -I - "$W/img/usr-verity.txt" "$SEED" "$1" "${2:-}" <<'PY'
import json, sys
usr = dict(l.rstrip("\n").partition("=")[::2] for l in open(sys.argv[1]) if l.strip())
for key in ("source_date_epoch", "erofs_size", "verity_size", "verity_format", "verity_data_block_size", "verity_hash_block_size"):
    usr[key] = int(usr[key])
r = {"schema": "regalia.rootfs-build/v1", "commit": sys.argv[2], "usr": usr}
exec(sys.argv[4])
with open(sys.argv[3], "w") as f:
    json.dump(r, f, indent=1, sort_keys=True)
PY
}
record "$W/rootfs-build.json"
ROOTHASH="$(sed -n 's/^roothash=//p' "$W/img/usr-verity.txt")"
USR_PARTUUID="$(sed -n 's/^usr_partuuid=//p' "$W/img/usr-verity.txt")" USR_VERITY_PARTUUID="$(sed -n 's/^usr_verity_partuuid=//p' "$W/img/usr-verity.txt")"
head -c 300000 /dev/urandom > "$W/e2e-test.efi"
# the UKI's signed record: its digest, and the /usr it names (#61 K61V-3: usr_roothash and its command line's usrhash=)
uki_record(){   # uki_record OUT IMAGE_SHA USR_ROOTHASH CMDLINE_USRHASH
  printf '{"signed": {"image_sha256": "%s"}, "usr_roothash": "%s", "cmdline": "rd.shell=0 root=tmpfs usrhash=%s systemd.verity_usr_options=panic-on-corruption"}\n' \
    "$2" "$3" "$4" > "$1"; }
UKI_SHA="$(sha256sum < "$W/e2e-test.efi" | cut -d' ' -f1)"
uki_record "$W/e2e-test.signed.json" "$UKI_SHA" "$ROOTHASH" "$ROOTHASH"
truncate -s 16G "$W/disk.img"
LOOP="$(losetup --find --show --partscan "$W/disk.img")"
# install DISK RECORD [USR] [VERITY] [more arguments]
install(){ REGALIA_INSTALL_TEST=1 "$INSTALLER" --disk "$1" --usr "${3:-$USR}" --usr-verity "${4:-$VER}" --rootfs-record "$2" \
             --uki "$W/e2e-test.efi" --uki-record "$W/e2e-test.signed.json" --out "$W/out" "${@:5}" <<< "$PASS"; }
untouched(){ for d in "$@"; do [ -z "$(lsblk -no NAME "$d" | tail -n +2)" ] && [ -z "$(wipefs --noheadings "$d")" ] || return 1; done; }
refused(){   # refused WHY DISK RECORD [USR] [VERITY] [more]: the installer fails, saying WHY, and DISK is untouched
  local why="$1" out rc; shift
  out="$(install "$@" 2>&1)" && rc=0 || rc=$?
  [ "$rc" != 0 ] && grep -qF -- "$why" <<< "$out" && untouched "$1" || { echo "$out" | tail -3 | sed 's/^/    | /'; return 1; }
}

# from here every check reports PASS or FAIL and the script goes on: errexit would end it at the first failing
# check instead of saying which (and `ok $?` is meant to read the check just made)
set +e
echo "### refusals before anything is written"
record "$W/r-sha.json" 'r["usr"]["erofs_sha256"] = "0" * 64'
refused "usr.erofs is not the image its record names" "$LOOP" "$W/r-sha.json"; ok $? "an image that is not its record's sha256 is refused, the disk untouched"
record "$W/r-vsha.json" 'r["usr"]["verity_sha256"] = "0" * 64'
refused "usr.verity is not the hash tree its record names" "$LOOP" "$W/r-vsha.json"; ok $? "a hash tree that is not its record's sha256 is refused, the disk untouched"
# THE CHECK BEFORE WRITING: one byte of the image changed, and its record naming the changed file's sha256 (a record
# made to match): only veritysetup verify, against the root hash, sees it, and it must see it before the disk is touched
cp "$USR" "$W/bad.erofs"
python3 -I -c 'import os, sys
with open(sys.argv[1], "r+b") as f:
    f.seek(os.path.getsize(sys.argv[1]) // 2); b = f.read(1); f.seek(-1, 1); f.write(bytes([b[0] ^ 0xFF]))' "$W/bad.erofs"
cmp -s "$USR" "$W/bad.erofs"; [ $? = 1 ]; ok $? "(control) the changed image differs from the image"
veritysetup verify "$W/bad.erofs" "$VER" "$ROOTHASH" >/dev/null 2>&1; [ $? != 0 ]; ok $? "(control) veritysetup verify refuses the changed image"
record "$W/r-bad.json" "r['usr']['erofs_sha256'] = '$(sha256sum < "$W/bad.erofs" | cut -d' ' -f1)'"
refused "veritysetup verify refuses usr.erofs and usr.verity under the root hash $ROOTHASH: nothing was written" "$LOOP" "$W/r-bad.json" "$W/bad.erofs"
ok $? "an image whose sha256 its record names, but whose blocks are not the root hash's, is refused by veritysetup verify BEFORE the disk is touched"
record "$W/r-uuid.json" 'r["usr"]["usr_partuuid"] = "00000000-0000-0000-0000-000000000000"'
refused "usr_partuuid '00000000-0000-0000-0000-000000000000' is not the root hash's first 128 bits" "$LOOP" "$W/r-uuid.json"
ok $? "a record whose usr_partuuid is not the root hash's first half is refused"
record "$W/r-vuuid.json" 'r["usr"]["usr_verity_partuuid"] = r["usr"]["usr_partuuid"]'
refused "usr_verity_partuuid" "$LOOP" "$W/r-vuuid.json"; ok $? "a record whose usr_verity_partuuid is not the root hash's last half is refused"
record "$W/r-nousr.json" 'del r["usr"]'
refused 'has no readable "usr"' "$LOOP" "$W/r-nousr.json"; ok $? "a record with no \"usr\" (built before the /usr image) is refused"
cp "$W/e2e-test.signed.json" "$W/uki-good.json"; uki_record "$W/e2e-test.signed.json" "$(printf 0%.0s {1..64})" "$ROOTHASH" "$ROOTHASH"
refused "the UKI is not the file its signed record names" "$LOOP" "$W/rootfs-build.json"; ok $? "a UKI that is not its record's is refused"
# #61 K61V-3: the UKI must open THIS /usr. One hex digit of the root hash changed, in the record and its command line
OTHERHASH="$(python3 -I -c 'import sys; h = sys.argv[1]; print(h[:-1] + ("0" if h[-1] != "0" else "1"))' "$ROOTHASH")"
uki_record "$W/e2e-test.signed.json" "$UKI_SHA" "$OTHERHASH" "$OTHERHASH"
refused "the UKI opens the /usr with root hash $OTHERHASH (its usrhash=), not this one ($ROOTHASH)" "$LOOP" "$W/rootfs-build.json"
ok $? "a UKI whose usrhash= is another /usr's (one digit) is refused, the disk untouched"
uki_record "$W/e2e-test.signed.json" "$UKI_SHA" "$ROOTHASH" "$OTHERHASH"
refused "the UKI's command line does not carry exactly usrhash=$ROOTHASH" "$LOOP" "$W/rootfs-build.json"
ok $? "a UKI record whose usr_roothash is not its command line's usrhash= is refused"
printf '{"signed": {"image_sha256": "%s"}}\n' "$UKI_SHA" > "$W/e2e-test.signed.json"
refused "the UKI's record names no /usr" "$LOOP" "$W/rootfs-build.json"; ok $? "a UKI record built before usrhash= (no usr_roothash) is refused"
cp "$W/uki-good.json" "$W/e2e-test.signed.json"
refused "rootfs.tar is no longer installed" "$LOOP" "$W/rootfs-build.json" "" "" --rootfs "$W/rootfs.tar"; ok $? "--rootfs is refused: rootfs.tar is not extracted any more"
truncate -s 16G "$W/other.img"; OTHER="$(losetup --find --show "$W/other.img")"
refused "a mirror (#544) of the verity layout is refused" "$LOOP" "$W/rootfs-build.json" "" "" --disk "$OTHER" && untouched "$OTHER"
ok $? "a mirror (--disk twice) is refused, both disks untouched"
losetup -d "$OTHER"; OTHER=""
truncate -s 8G "$W/small.img"; SMALL="$(losetup --find --show "$W/small.img")"
refused "the layout needs" "$SMALL" "$W/rootfs-build.json"; ok $? "a disk too small for the layout and a /var is refused, untouched"
losetup -d "$SMALL"; SMALL=""
out="$(REGALIA_INSTALL_TEST=1 "$INSTALLER" --disk /dev/null --usr "$USR" --usr-verity "$VER" --rootfs-record "$W/rootfs-build.json" --uki "$W/e2e-test.efi" \
         --uki-record "$W/e2e-test.signed.json" --out "$W/out" <<< "$PASS" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -qE "not a block device|is for a /dev/loopN only" <<< "$out"; ok $? "the test mode is refused for anything but a loop device"
# a loop device over a block device is that device: the test mode asks no serial, so it is refused there too
OVER="$(losetup --find --show "$LOOP")"
out="$(install "$OVER" "$W/rootfs-build.json" 2>&1)" && rc=0 || rc=$?
losetup -d "$OVER"; OVER=""
[ "$rc" != 0 ] && grep -q "is for a loop device backed by a regular file" <<< "$out"; ok $? "the test mode is refused for a loop device over a block device"
# a filesystem on the WHOLE device holds no partition, and is data all the same (made small, then the file grown)
truncate -s 64M "$W/bare.img"; mkfs.ext4 -q -F "$W/bare.img"; truncate -s 16G "$W/bare.img"
BARE="$(losetup --find --show "$W/bare.img")"
out="$(install "$BARE" "$W/rootfs-build.json" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "holds data (partitions or signatures): refused without --wipe" <<< "$out" && [ "$(blkid -o value -s TYPE "$BARE")" = ext4 ]
ok $? "a filesystem on the whole device is refused without --wipe, and left as it was"
losetup -d "$BARE"; BARE=""
untouched "$LOOP"; ok $? "after every refusal the disk is still blank"

echo "### install"
install "$LOOP" "$W/rootfs-build.json"; ok $? "the installer finished"
udevadm settle
out="$(install "$LOOP" "$W/rootfs-build.json" 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "holds data (partitions or signatures): refused without --wipe" <<< "$out"; ok $? "a disk holding partitions is refused without --wipe"
# with --wipe, the previous install's record still in --out: refused before the disk is touched
before="$(cryptsetup luksUUID "${LOOP}p6")"
out="$(install "$LOOP" "$W/rootfs-build.json" "" "" --wipe 2>&1)" && rc=0 || rc=$?
[ "$rc" != 0 ] && grep -q "install-test-$(basename "$LOOP").json exists: move it away first" <<< "$out" && [ "$(cryptsetup luksUUID "${LOOP}p6")" = "$before" ]
ok $? "a reinstall onto the previous install's record is refused, and the disk is untouched"

echo "### the disk, read back"
python3 -I - "$(sfdisk -J "$LOOP")" "$USR_PARTUUID" "$USR_VERITY_PARTUUID" "$GIB" "$MIB" <<'PY'; ok $? "GPT: esp, usr-a, usr-a-verity, usr-b, usr-b-verity, regalia-root; the spec's types; usr-a's PARTUUIDs the root hash's halves; A and B the same sizes; read-only usr"
import json, sys
table = json.loads(sys.argv[1])["partitiontable"]
parts, usr_uuid, verity_uuid, gib, mib = table["partitions"], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
sector = table.get("sectorsize", 512)
ESP, USR, USRV, VAR = ("C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "8484680C-9521-48C6-9C11-B0720656F69E",
                       "77FF5F63-E7B6-4633-ACF4-1565B864C0E6", "4D21B016-B534-45C2-A9FB-5C16E091FD2D")
want = [("esp", ESP, gib), ("usr-a", USR, 4 * gib), ("usr-a-verity", USRV, 128 * mib), ("usr-b", USR, 4 * gib),
        ("usr-b-verity", USRV, 128 * mib), ("regalia-root", VAR, None)]
assert [p.get("name") for p in parts] == [w[0] for w in want], [p.get("name") for p in parts]
for p, (name, kind, size) in zip(parts, want):
    assert p["type"].upper() == kind, (name, p["type"])
    assert size is None or p["size"] * sector == size, (name, p["size"])
    assert ("GUID:60" in p.get("attrs", "")) == name.startswith("usr-"), (name, p.get("attrs"))
assert parts[1]["uuid"].lower() == usr_uuid and parts[2]["uuid"].lower() == verity_uuid, (parts[1]["uuid"], parts[2]["uuid"])
assert parts[3]["uuid"].lower() != usr_uuid and parts[4]["uuid"].lower() != verity_uuid, "B must not carry A's PARTUUIDs"
assert parts[5]["size"] * sector >= 4 * gib, parts[5]
assert not any(p["type"].upper() == "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709" for p in parts), "a root partition: rootfs.tar's"
PY
ESP_DEV="${LOOP}p1" USR_A="${LOOP}p2" USR_A_VERITY="${LOOP}p3" USR_B="${LOOP}p4" USR_B_VERITY="${LOOP}p5" VAR_DEV="${LOOP}p6"
cmp -n "$(stat -c %s "$USR")" "$USR" "$USR_A" && cmp -n "$(stat -c %s "$VER")" "$VER" "$USR_A_VERITY"
ok $? "usr-a is usr.erofs and usr-a-verity is usr.verity, byte for byte"
veritysetup verify "$USR_A" "$USR_A_VERITY" "$ROOTHASH" >/dev/null 2>&1; ok $? "veritysetup verify passes from the partitions with the root hash"
veritysetup verify "$USR_A" "$USR_A_VERITY" "$(printf 0%.0s {1..64})" >/dev/null 2>&1; [ $? != 0 ]; ok $? "(control) and refuses another root hash"
[ "$(veritysetup dump "$USR_A_VERITY" | sed -n 's/^Data blocks:[[:space:]]*//p')" = "$(( $(stat -c %s "$USR") / 4096 ))" ]
ok $? "the hash tree covers exactly the image's blocks, not the whole partition"
python3 -I - <<'PY'; ok $? "the hash tree of a WHOLE usr partition (4 GiB, sha256, 4096-byte blocks) fits a usr verity partition"
blocks, size = 4 * 1024 ** 3 // 4096, 4096         # the superblock
while blocks > 1:
    blocks = -(-blocks // (4096 // 32))            # 128 sha256 digests a block
    size += blocks * 4096
assert size <= 128 * 1024 ** 2, size
print("    (%d bytes)" % size)
PY
for p in "$USR_B" "$USR_B_VERITY"; do
  [ -z "$(blkid -p -o value -s TYPE "$p" 2>/dev/null)" ] && [ -z "$(wipefs --noheadings "$p")" ] && cmp -s -n "$MIB" "$p" /dev/zero
  ok $? "$(basename "$p") is reserved and empty: no signature, the first MiB zero"
done
meta="$(cryptsetup luksDump --dump-json-metadata "$VAR_DEV")"
python3 -I - "$meta" <<'PY'; ok $? "regalia-root is LUKS2: exactly one keyslot, argon2id"
import json, sys
m = json.loads(sys.argv[1])
assert len(m["keyslots"]) == 1, m["keyslots"].keys()
assert next(iter(m["keyslots"].values()))["kdf"]["type"] == "argon2id"
PY
[ "$(cryptsetup luksDump "$VAR_DEV" | sed -n 's/^Label:[[:space:]]*//p')" = regalia-root ]; ok $? "the LUKS2 label is regalia-root"
printf '%s' "$PASS" | cryptsetup open --key-file - "$VAR_DEV" install-host-loop; ok $? "the installer passphrase opens the volume"
[ "$(blkid -o value -s TYPE /dev/mapper/install-host-loop)" = ext4 ] && [ "$(blkid -o value -s LABEL /dev/mapper/install-host-loop)" = regalia-var ]
ok $? "inside it, ext4 labelled regalia-var"
mkdir -p "$W/check"
# each mount is part of the check that reads it: a mount that fails must not leave an empty mountpoint to read as an
# empty /var (CodeRabbit on #721), and each unmount and close is checked, so a cleanup that fails turns the run red
mount -o ro /dev/mapper/install-host-loop "$W/check" \
  && [ "$(cd "$W/check" && find . -mindepth 1 \! -path './lost+found*' | wc -l)" = 0 ]; ok $? "/var holds nothing: rootfs.tar was not extracted"
umount "$W/check" && cryptsetup close install-host-loop; ok $? "/var unmounted and its volume closed"
uki="$(sha256sum < "$W/e2e-test.efi" | cut -d' ' -f1)"
mount -o ro "$ESP_DEV" "$W/check" && [ "$(sha256sum < "$W/check/EFI/Linux/e2e-test.efi" | cut -d' ' -f1)" = "$uki" ] && [ "$(sha256sum < "$W/check/EFI/BOOT/BOOTX64.EFI" | cut -d' ' -f1)" = "$uki" ]
ok $? "the ESP holds the UKI at \\EFI\\Linux and at the removable-media path, byte for byte"
[ "$(cd "$W/check" && find . -type f | sort | tr '\n' ' ')" = "./EFI/BOOT/BOOTX64.EFI ./EFI/Linux/e2e-test.efi " ]; ok $? "and nothing else"
umount "$W/check"; ok $? "the ESP unmounted"
uuid(){ blkid -p -s PART_ENTRY_UUID -o value "$1" | tr '[:upper:]' '[:lower:]'; }
python3 -I - "$W/out/install-test-$(basename "$LOOP").json" "$ROOTHASH" "$uki" "$(cryptsetup luksUUID "$VAR_DEV")" \
  "$(uuid "$ESP_DEV")" "$(uuid "$USR_A")" "$(uuid "$USR_A_VERITY")" "$(uuid "$USR_B")" "$(uuid "$USR_B_VERITY")" "$(uuid "$VAR_DEV")" \
  "$(sha256sum < "$USR" | cut -d' ' -f1)" "$SEED" <<'PY'; ok $? "the install record (v3) names the root hash, every PARTUUID, the digests and the LUKS UUID"
import json, sys
r = json.load(open(sys.argv[1]))
roothash, uki, luks, esp, ua, uav, ub, ubv, var, erofs, commit = sys.argv[2:]
assert r["schema"] == "regalia.install/v3" and r["layout"] == "verity-ab", r
assert r["usr"]["roothash"] == roothash and r["usr"]["slot"] == "a" and r["usr"]["erofs_sha256"] == erofs, r["usr"]
assert r["uki_sha256"] == uki and r["luks_uuid"] == luks and r["rootfs_commit"] == commit, r
assert r["partuuids"] == {"esp": esp, "usr_a": ua, "usr_a_verity": uav, "usr_b": ub, "usr_b_verity": ubv, "var": var}, r["partuuids"]
assert r["usr_partition_size"] == 4 * 1024 ** 3 and r["usr_verity_partition_size"] == 128 * 1024 ** 2, r
assert r["efi_entry"] is False and "rootfs_sha256" not in r
PY

echo "### a reinstall with --wipe over an image left in usr-b"
# what an updater's earlier B would leave: a whole /usr pair in slot B
dd if="$USR" of="$USR_B" bs=4M conv=fsync status=none && dd if="$VER" of="$USR_B_VERITY" bs=4M conv=fsync status=none
veritysetup verify "$USR_B" "$USR_B_VERITY" "$ROOTHASH" >/dev/null 2>&1; ok $? "(control) slot B holds a whole verifiable /usr pair"
install "$LOOP" "$W/rootfs-build.json" "" "" --wipe --out "$W/out-again"; ok $? "the installer reinstalled with --wipe"
udevadm settle
for p in "$USR_B" "$USR_B_VERITY"; do
  [ -z "$(blkid -p -o value -s TYPE "$p" 2>/dev/null)" ] && cmp -s -n "$MIB" "$p" /dev/zero
  ok $? "$(basename "$p") is empty again: no signature, the first MiB zero"
done
veritysetup verify "$USR_B" "$USR_B_VERITY" "$ROOTHASH" >/dev/null 2>&1; [ $? != 0 ]; ok $? "and slot B no longer verifies as a /usr"
veritysetup verify "$USR_A" "$USR_A_VERITY" "$ROOTHASH" >/dev/null 2>&1; ok $? "slot A verifies from the partitions after the reinstall"

echo
echo "install-host-loop: $passed passed, $failed failed"
[ "$failed" = 0 ]
