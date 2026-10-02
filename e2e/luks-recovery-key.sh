#!/usr/bin/env bash
# luks-recovery-key.sh — the KMS host's disk recovery key on a REAL dm-crypt volume (regalia-kms#77,
# Phase 17, the software half of PoC 17.1). A loop device, LUKS2, a filesystem; root; it runs in CI.
#
#   sudo e2e/luks-recovery-key.sh
#
#   1  a LUKS2 volume as an installed host has it: the installer's passphrase, and a stand-in for the
#      TPM (or peer) keyslot. A filesystem inside holds a marker file.
#   2  deploy/baremetal/recovery-key.sh --enrol adds the recovery key as a keyslot of its own, and
#      --check proves the key opens it. The installer's passphrase is wiped as commissioning does.
#      host_probe's root_disk_recovery_keyslot judges the real header: true.
#   3  TOTAL OUTAGE: the stand-in keyslot is destroyed. Nothing but the recovery key is left. The key,
#      alone, opens the volume, the filesystem mounts, and the marker reads back.
#   4  what must NOT open it, each tried against the device as a boot prompt would: another key, one
#      letter wrong, the same letters without dashes, grouped in fours, in capitals.
#   5  the key has been used, so it is replaced: --replace; the used key opens nothing, the new one
#      opens and mounts the volume.
#
# No TPM is involved: this proves the recovery path is independent of one, not that the TPM path
# works (that is the swtpm scripts'). The file-backed half, which needs no root, is
# tests/test_baremetal_recovery_key.py; it is run here too, where a skip is a failure.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
[ "$(id -u)" = 0 ] || { echo "luks-recovery-key: run as root (it makes a loop device and a dm-crypt mapping)"; exit 2; }
for t in cryptsetup losetup mkfs.ext4 mount umount python3; do
  command -v "$t" >/dev/null || { echo "luks-recovery-key: $t is required (cryptsetup-bin, util-linux, e2fsprogs, python3)"; exit 2; }
done
S=deploy/baremetal/recovery-key.sh
pass=0; failed=0
P(){ pass=$((pass+1)); printf 'PASS  %s\n' "$*"; }
F(){ failed=$((failed+1)); printf 'FAIL  %s\n' "$*"; }

W="$(mktemp -d)"; NAME="regalia-recovery-e2e-$$"; LOOP=""
cleanup(){ mountpoint -q "$W/mnt" && umount "$W/mnt"; [ -e "/dev/mapper/$NAME" ] && cryptsetup close "$NAME"
           [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null; rm -rf -- "$W"; }
trap cleanup EXIT
INSTALLER="the installer's passphrase"
KEY="cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb"
NEW_KEY="vvuuttrr-nnllkkjj-iihhggff-eeddccbb-cbdefghi-jklnrtuv-bcdefghi-jklnrtuc"
FAST=(--pbkdf pbkdf2 --pbkdf-force-iterations 1000)
# unlock <secret>: open the volume for real, as the boot prompt does with what was typed there.
unlock(){ cryptsetup open --key-file <(printf '%s' "$1") "$LOOP" "$NAME" </dev/null >/dev/null 2>&1; }
judge(){ cryptsetup luksDump --dump-json-metadata "$LOOP" | python3 -I -c '
import json, sys
sys.path.insert(0, "deploy/baremetal")
import host_probe
ok, why = host_probe.recovery_keyslots(json.load(sys.stdin))
print(why); sys.exit(0 if ok else 1)'; }

# 1 ------------------------------------------------------------------------------------------------
truncate -s 64M "$W/disk.img"; mkdir "$W/mnt"
LOOP="$(losetup --find --show "$W/disk.img")" || { echo "luks-recovery-key: no loop device"; exit 2; }
cryptsetup luksFormat --type luks2 --batch-mode "${FAST[@]}" --key-file <(printf '%s' "$INSTALLER") "$LOOP" </dev/null || { echo "luks-recovery-key: luksFormat failed"; exit 2; }
head -c 32 /dev/urandom > "$W/standin.key"
cryptsetup luksAddKey --batch-mode "${FAST[@]}" --key-file <(printf '%s' "$INSTALLER") --new-key-slot 1 "$LOOP" "$W/standin.key" </dev/null
printf '{"type":"regalia-test-unlock","keyslots":["1"]}' | cryptsetup token import --json-file - "$LOOP"
cryptsetup open --key-file "$W/standin.key" "$LOOP" "$NAME" </dev/null && mkfs.ext4 -q "/dev/mapper/$NAME" && mount "/dev/mapper/$NAME" "$W/mnt" \
  && echo "regalia-kms root volume marker $$" > "$W/mnt/marker" && umount "$W/mnt" && cryptsetup close "$NAME" \
  && P "1: a LUKS2 volume with the installer's passphrase and a TPM stand-in keyslot, holding a filesystem" \
  || { F "1: could not build the volume"; exit 1; }

# 2 ------------------------------------------------------------------------------------------------
out="$(printf '%s\n%s\n' "$INSTALLER" "$KEY" | bash "$S" --enrol "$LOOP" 2>&1)" && P "2: --enrol added the recovery key as its own keyslot" || F "2: --enrol: $out"
out="$(printf '%s\n' "$KEY" | bash "$S" --check "$LOOP" 2>&1)" && P "2: --check: the key opens that keyslot" || F "2: --check: $out"
[ ! -e "/dev/mapper/$NAME" ] && P "2: --check unlocked nothing (no mapping exists)" || F "2: --check left a mapping"
why="$(judge)" && F "2: the probe passed while the installer's passphrase is still enrolled: $why" || P "2: the probe refuses while the installer's passphrase remains ($why)"
cryptsetup luksKillSlot --batch-mode "$LOOP" 0 </dev/null 2>/dev/null
why="$(judge)" && P "2: root_disk_recovery_keyslot on the real header: $why" || F "2: the probe refuses a commissioned header: $why"
bash "$S" --status "$LOOP" >/dev/null 2>&1 && P "2: --status: one recovery keyslot, no unlabelled passphrase" || F "2: --status failed on a commissioned header"

# 3 ------------------------------------------------------------------------------------------------
cryptsetup luksKillSlot --batch-mode "$LOOP" 1 </dev/null 2>/dev/null
unlock "$INSTALLER" && { F "3: the installer's passphrase still opens the volume"; cryptsetup close "$NAME"; }
cryptsetup open --key-file "$W/standin.key" "$LOOP" "$NAME" </dev/null >/dev/null 2>&1 && { F "3: the TPM stand-in still opens the volume"; cryptsetup close "$NAME"; }
[ "$(cryptsetup luksDump --dump-json-metadata "$LOOP" | python3 -I -c 'import json,sys; print(len(json.load(sys.stdin)["keyslots"]))')" = 1 ] \
  && P "3: total outage: one keyslot is left, the recovery key's" || F "3: more than the recovery keyslot is left"
if unlock "$KEY" && mount -o ro "/dev/mapper/$NAME" "$W/mnt" && [ "$(cat "$W/mnt/marker")" = "regalia-kms root volume marker $$" ]; then
  P "3: the recovery key ALONE opened the volume; the filesystem mounted and the marker read back"
else F "3: the recovery key alone did not bring the volume back"; fi
mountpoint -q "$W/mnt" && umount "$W/mnt"; [ -e "/dev/mapper/$NAME" ] && cryptsetup close "$NAME"

# 4 ------------------------------------------------------------------------------------------------
squeezed="${KEY//-/}"
declare -A wrong=(
  ["another host's key"]="$NEW_KEY"
  ["one letter wrong"]="${KEY:0:20}$([ "${KEY:20:1}" = c ] && echo b || echo c)${KEY:21}"
  ["the letters without the dashes"]="$squeezed"
  ["grouped in fours"]="$(sed -E 's/.{4}/&-/g; s/-$//' <<< "$squeezed")"
  ["in capitals"]="${KEY^^}"
)
for name in "${!wrong[@]}"; do
  if unlock "${wrong[$name]}"; then F "4: $name OPENED the volume"; cryptsetup close "$NAME"
  else P "4: $name does not open the volume"; fi
done

# 5 ------------------------------------------------------------------------------------------------
out="$(printf '%s\n%s\n' "$KEY" "$NEW_KEY" | bash "$S" --replace "$LOOP" 2>&1)" && P "5: --replace: a new key in, the used one out" || F "5: --replace: $out"
unlock "$KEY" && { F "5: the USED key still opens the volume"; cryptsetup close "$NAME"; } || P "5: the used key opens nothing"
if unlock "$NEW_KEY" && mount -o ro "/dev/mapper/$NAME" "$W/mnt" && [ -s "$W/mnt/marker" ]; then P "5: the new key opens and mounts the volume"
else F "5: the new key did not open the volume"; fi
mountpoint -q "$W/mnt" && umount "$W/mnt"; [ -e "/dev/mapper/$NAME" ] && cryptsetup close "$NAME"
why="$(judge)" && P "5: the probe still measures one recovery keyslot: $why" || F "5: after --replace the probe refuses: $why"

# the file-backed half, where a skip is a failure
out="$(REGALIA_EXPECT_CRYPTSETUP=1 python3 -Es -m unittest -v tests.test_baremetal_recovery_key 2>&1)"; rc=$?
[ "$rc" = 0 ] && grep -q '^Ran 36 tests' <<< "$out" && ! grep -qi skipped <<< "$out" \
  && P "the 36 file-backed tests of recovery-key.sh ran and passed (the failure paths are there: a rollback that fails, a replace that stops half way, a signal)" || { F "the file-backed tests did not all run and pass"; printf '%s\n' "$out" | tail -30; }

echo "luks-recovery-key: $pass passed, $failed failed"
[ "$failed" = 0 ]
