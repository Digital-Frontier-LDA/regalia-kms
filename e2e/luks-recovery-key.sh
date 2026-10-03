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
for t in cryptsetup losetup mkfs.ext4 mount umount python3 flock; do
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
judge(){ cryptsetup luksDump --dump-json-metadata "$LOOP" | python3 -IB -c '
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
out="$(bash "$S" --status "$LOOP" 2>&1)" && grep -q "^STATE: clean" <<< "$out" && P "2: --status: STATE: clean (one recovery keyslot, every keyslot named by a token)" || F "2: --status failed on a commissioned header"

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

# 6 ------------------------------------------------------------------------------------------------
# #278: every run above that took a key is on the real audit trail, hash-chained, and no key is in it.
TRAIL=/var/log/regalia/recovery-key.jsonl
if [ -f "$TRAIL" ] && python3 -Es deploy/baremetal/trails.py verify "$TRAIL" >"$W/verify.json" 2>&1; then
  P "6: the recovery-key trail's chain verifies ($(cat "$W/verify.json"))"
else F "6: the recovery-key trail does not verify: $(cat "$W/verify.json" 2>/dev/null)"; fi
ok=1; for k in "$KEY" "$NEW_KEY" "$INSTALLER"; do grep -qF -- "$k" "$TRAIL" 2>/dev/null && ok=0; done
[ "$ok" = 1 ] && P "6: no key and no passphrase is in the trail" || F "6: a secret is in $TRAIL"
outcomes="$(python3 -I -c 'import json, sys
print(" ".join("%s:%s" % (e["mode"], e["outcome"]) for e in map(json.loads, open(sys.argv[1])) if e.get("device") == sys.argv[2]))' "$TRAIL" "$LOOP")"
[ "$outcomes" = "enrol:REQUESTED enrol:ALLOW check:REQUESTED check:ALLOW replace:REQUESTED replace:ALLOW" ] \
  && P "6: each run is on the trail, requested before and its outcome after: $outcomes" || F "6: the trail for $LOOP reads: $outcomes"
# every request answered exactly once, by an outcome naming its seq
pairs() { python3 -I -c 'import json, sys
events = [e for e in map(json.loads, open(sys.argv[1])) if e.get("device") == sys.argv[2]]
asked = [e["seq"] for e in events if e["outcome"] == "REQUESTED"]
answered = [e.get("request") for e in events if e["outcome"] != "REQUESTED"]
sys.exit(0 if asked and sorted(answered) == sorted(asked) else 1)' "$1" "$2"; }
pairs "$TRAIL" "$LOOP" && P "6: every request on the trail is answered exactly once" || F "6: a request on $TRAIL is unanswered or answered twice"

# 7 ------------------------------------------------------------------------------------------------
# #278: recovery-reconcile.py on the real trail. After step 3 only the recovery keyslot is left: keeping it
# (proven with the new key's card) changes nothing, and the run is recorded, requested then ALLOW.
RTRAIL=/var/log/regalia/recovery-reconcile.jsonl
slot="$(cryptsetup luksDump --dump-json-metadata "$LOOP" | python3 -I -c 'import json, sys
print(next(t["keyslots"][0] for t in json.load(sys.stdin)["tokens"].values() if t["type"] == "systemd-recovery"))')"
out="$(printf '%s\n' "$NEW_KEY" | python3 -I deploy/baremetal/recovery-reconcile.py "$LOOP" --keep-slot "$slot" 2>&1)" \
  && P "7: recovery-reconcile.py kept keyslot $slot with the new key's card" || F "7: recovery-reconcile.py: $out"
if [ -f "$RTRAIL" ] && python3 -Es deploy/baremetal/trails.py verify "$RTRAIL" >"$W/rverify.json" 2>&1; then
  P "7: the reconcile trail's chain verifies ($(cat "$W/rverify.json"))"
else F "7: the reconcile trail does not verify: $(cat "$W/rverify.json" 2>/dev/null)"; fi
pairs "$RTRAIL" "$LOOP" && P "7: its request is answered exactly once" || F "7: a reconcile request is unanswered or answered twice"
grep -qF -- "$NEW_KEY" "$RTRAIL" && F "7: the card's key is in $RTRAIL" || P "7: no key is in the reconcile trail"


# the file-backed half, where a skip is a failure
out="$(REGALIA_EXPECT_CRYPTSETUP=1 python3 -BEs -m unittest -v tests.test_baremetal_recovery_key 2>&1)"; rc=$?
[ "$rc" = 0 ] && grep -q '^Ran 38 tests' <<< "$out" && ! grep -qi skipped <<< "$out" \
  && P "the 38 file-backed tests of recovery-key.sh ran and passed (the failure paths are there: a step that fails, a replace that stops half way, a signal during the writes; every header sync is lab/recovery/matrix.py)" || { F "the file-backed tests did not all run and pass"; printf '%s\n' "$out" | tail -30; }

echo "luks-recovery-key: $pass passed, $failed failed"
[ "$failed" = 0 ]
