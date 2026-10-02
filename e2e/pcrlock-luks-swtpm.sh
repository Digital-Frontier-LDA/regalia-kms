#!/usr/bin/env bash
# pcrlock-luks-swtpm.sh — a MEASUREMENT for regalia-kms#75: can an NV-backed TPM policy
# (systemd-pcrlock) retire a boot image for a LUKS2 volume, locally, with no peer?
#
# Why it is asked. The PIN and the disk are sealed today to a signed PCR 11 policy, which has no
# counter: every image the PCR-signing key ever signed keeps unsealing, for ever. The PIN now also
# needs the host key on the root disk (PIN-CUSTODY.md), so what retires an image is the root disk's
# unlock. systemd has one local mechanism for that: systemd-pcrlock keeps the policy in a TPM NV
# index, and an update REPLACES it. This script measures whether that holds, on a software TPM and a
# LUKS2 volume in a file, with systemd's own tools throughout.
#
#   0  the instrument: after a "boot", PCR 11 is what systemd-pcrlock predicts for that image
#   1  a policy for image-1; a LUKS2 volume enrolled to it (--tpm2-pcrlock); it unlocks on image-1,
#      and its passphrase still opens it (the recovery path)
#   2  the update: image-2 is approved beside image-1; image-1 still unlocks; after a reboot into
#      image-2 the SAME volume unlocks with no re-enrolment
#   3  retirement: image-1's variant is removed and the policy remade; image-2 unlocks; image-1 does
#      not, nor does an image that was never approved
#   4  the retired image tries to come back: with the OLD policy file restored (a disk rollback) it
#      still does not unlock; and it cannot remake the policy to include itself
#   5  control: image-2 unlocks again, and the TPM counted no failed authorization
#
# A "boot" restarts the swtpm (PCRs zeroed) and measures one word into PCR 11 with systemd-pcrextend,
# which also writes the measurement log systemd-pcrlock checks the PCR against. That is a stand-in
# for a UKI: `systemd-pcrlock lock-uki` on the real hosts.
#
# IT WRITES SYSTEM STATE, so it isolates itself: everything runs in a private mount namespace with
# a tmpfs over /efi, /boot and /var/lib/systemd (make-policy writes the policy to /var/lib/systemd
# and, from systemd 256, a credential into the ESP, whatever --policy says). The unlock itself needs
# device-mapper, which a mount namespace does not isolate: a mapping named regalia-pcrlock-test is
# created and removed. So the script runs only in CI (GITHUB_ACTIONS), or with
# REGALIA_PCRLOCK_HOST_OK=1 on a machine you are willing to do that on. REGALIA_PCRLOCK_NO_DM=1
# skips every unlock (for trying the rest somewhere without device-mapper): the run then FAILS at the
# end, because nothing was proven.
#
# NOT A DECISION. pcrlock is marked experimental by systemd, cannot be combined with a signed PCR
# policy, and here it is fed one PCR's log. What it would take on a DL360 (the firmware log, every
# measured PCR predicted) is not covered.
set -uo pipefail
NAME=regalia-pcrlock-test
if [ "${GITHUB_ACTIONS:-}" != true ] && [ "${REGALIA_PCRLOCK_HOST_OK:-}" != 1 ]; then
  echo "pcrlock-luks-swtpm: refusing to run here: it creates a device-mapper volume ($NAME) on this machine."
  echo "  It runs in CI. Elsewhere set REGALIA_PCRLOCK_HOST_OK=1 (add REGALIA_PCRLOCK_NO_DM=1 to skip the unlocks)."
  exit 2
fi
if [ "${REGALIA_PCRLOCK_IN_NS:-}" != 1 ]; then
  SUDO=(); [ "$(id -u)" = 0 ] || SUDO=(sudo -n)
  exec "${SUDO[@]}" env REGALIA_PCRLOCK_IN_NS=1 GITHUB_ACTIONS="${GITHUB_ACTIONS:-}" REGALIA_PCRLOCK_HOST_OK="${REGALIA_PCRLOCK_HOST_OK:-}" \
    REGALIA_PCRLOCK_NO_DM="${REGALIA_PCRLOCK_NO_DM:-}" PATH="/usr/sbin:/sbin:$PATH" unshare -m bash "$0" "$@"
fi
[ "$(id -u)" = 0 ] || { echo "pcrlock-luks-swtpm: needs root"; exit 2; }
for d in /efi /boot /var/lib/systemd; do
  [ -d "$d" ] || continue
  mount -t tmpfs tmpfs "$d" || { echo "pcrlock-luks-swtpm: cannot put a tmpfs over $d: not running unisolated"; exit 2; }
done
mkdir -p /var/lib/systemd
pass=0; fail=0; skipped=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
S(){ printf '  SKIP %s\n' "$1"; skipped=$((skipped+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
find_tool(){ local t; for t in "$@"; do [ -x "$t" ] && { echo "$t"; return 0; }; command -v "$t" 2>/dev/null && return 0; done; return 1; }
PCRLOCK="$(find_tool /usr/lib/systemd/systemd-pcrlock systemd-pcrlock)" || { echo "pcrlock-luks-swtpm: systemd-pcrlock is required (systemd 255 or later)"; exit 2; }
PCREXTEND="$(find_tool /usr/lib/systemd/systemd-pcrextend)" || { echo "pcrlock-luks-swtpm: systemd-pcrextend is required"; exit 2; }
ENROLL="$(find_tool systemd-cryptenroll "${REGALIA_CRYPTENROLL:-/nonexistent}")" || { echo "pcrlock-luks-swtpm: systemd-cryptenroll is required (Debian: systemd-cryptsetup)"; exit 2; }
ATTACH="$(find_tool systemd-cryptsetup /usr/lib/systemd/systemd-cryptsetup "${REGALIA_SYSTEMD_CRYPTSETUP:-/nonexistent}")" || { echo "pcrlock-luks-swtpm: systemd-cryptsetup is required"; exit 2; }
for t in swtpm tpm2_pcrread tpm2_getcap tpm2_shutdown cryptsetup sha256sum python3; do
  command -v "$t" >/dev/null || { echo "pcrlock-luks-swtpm: $t is required (swtpm, tpm2-tools, cryptsetup-bin)"; exit 2; }
done
echo "pcrlock-luks-swtpm: $("$PCRLOCK" --version | head -1), $(cryptsetup --version | cut -d' ' -f1-2), swtpm $(swtpm --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
W="$(mktemp -d)"; cd "$W" || exit 2
detach(){ [ -e "/dev/mapper/$NAME" ] && "$ATTACH" detach "$NAME" >/dev/null 2>&1; return 0; }
stop(){ [ -f "$W/tpm.pid" ] || return 0; tpm2_shutdown -c >/dev/null 2>&1; kill "$(cat "$W/tpm.pid")" 2>/dev/null; rm -f "$W/tpm.pid"; }
trap 'detach; stop; rm -rf "$W"' EXIT
D="swtpm:path=$W/tpm.sock"; export TPM2TOOLS_TCTI="$D"
# systemd's own switches: measure though this is no UKI boot; this TPM; these logs (the firmware log is
# an empty file: there is no firmware here, and PCR 11 is the only PCR this run extends).
export SYSTEMD_FORCE_MEASURE=1 SYSTEMD_TPM2_DEVICE="$D" SYSTEMD_MEASURE_LOG_USERSPACE="$W/userspace.log" SYSTEMD_MEASURE_LOG_FIRMWARE="$W/firmware.log"
: > "$W/firmware.log"
POLICY=/var/lib/systemd/pcrlock.json; COMP="$W/comp"; VARIANTS="$COMP/650-image.pcrlock.d"
mkdir -p "$VARIANTS"

boot(){ stop; mkdir -p "$W/state"; rm -f "$W/userspace.log"
  swtpm socket --tpm2 --tpmstate "dir=$W/state" --server "type=unixio,path=$W/tpm.sock" \
    --ctrl "type=unixio,path=$W/tpm.sock.ctrl" --flags not-need-init,startup-clear --daemon --pid "file=$W/tpm.pid"
  for _ in 1 2 3 4 5 6 7 8 9 10; do tpm2_pcrread sha256:11 >/dev/null 2>&1 && break; sleep 0.3; done
  "$PCREXTEND" --tpm2-device="$D" --pcr=11 "$1" >"$W/extend.log" 2>&1 || { F "systemd-pcrextend could not measure $1: $(tail -1 "$W/extend.log")"; return 1; }; }
pcr11(){ tpm2_pcrread sha256:11 | awk '/11 *:/{print tolower(substr($NF,3))}'; }
approve(){ printf '%s' "$1" > "$W/word"; "$PCRLOCK" lock-raw --pcr=11 --pcrlock="$VARIANTS/$1.pcrlock" "$W/word" >/dev/null 2>&1; }
# policy: remake the NV policy from the component files. Prints make-policy's last lines; its status is the function's.
policy(){ "$PCRLOCK" --components="$COMP" make-policy >"$W/policy.log" 2>&1; local rc=$?; tail -4 "$W/policy.log" | cut -c1-200; return "$rc"; }
nv(){ python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("nvIndex"))' "$POLICY" 2>/dev/null; }
# unlock: 0 when the volume opens through its TPM token alone (no passphrase asked: headless).
unlock(){ detach
  "$ATTACH" attach "$NAME" "$W/luks.img" - "tpm2-device=$D,tpm2-pcrlock=$POLICY,headless=true" >"$W/attach.log" 2>&1
  local rc=$?; [ "$rc" = 0 ] && [ -e "/dev/mapper/$NAME" ]; rc=$?; detach; return "$rc"; }
opens(){ if [ "${REGALIA_PCRLOCK_NO_DM:-}" = 1 ]; then S "$1 (no device-mapper here)"; return; fi
  unlock && P "$1" || F "$1: it did not unlock: $(tail -2 "$W/attach.log" | tr '\n' ' ' | cut -c1-220)"; }
closed(){ if [ "${REGALIA_PCRLOCK_NO_DM:-}" = 1 ]; then S "$1 (no device-mapper here)"; return; fi
  unlock && F "$1: IT UNLOCKED" || P "$1 ($(tail -1 "$W/attach.log" | cut -c1-110))"; }

hdr "0  the instrument: a boot measures what systemd-pcrlock predicts"
approve image-1
boot image-1
want="$("$PCRLOCK" --components="$COMP" predict 2>/dev/null | awk '/PCR 11 /{f=1} f && /sha256:/{print $2; exit}')"
[ -n "$want" ] && [ "$(pcr11)" = "$want" ] && P "PCR 11 after booting image-1 is the predicted value ($want)" || F "PCR 11 is $(pcr11), predicted ${want:-nothing}"

hdr "1  a policy for image-1, and a LUKS2 volume enrolled to it"
out="$(policy)" && [ -s "$POLICY" ] && P "the policy is made and its digest written to an NV index ($(nv))" || F "make-policy failed: $out"
NV="$(nv)"
grep -qi "$(printf '0x%x' "${NV:-0}" 2>/dev/null)" <<< "$(tpm2_getcap handles-nv-index 2>/dev/null)" && P "that NV index exists in the TPM" || F "no NV index $NV in the TPM: $(tpm2_getcap handles-nv-index 2>&1 | tr '\n' ' ')"
truncate -s 32M "$W/luks.img"; (umask 077; head -c 32 /dev/urandom | base64 > "$W/key")
cryptsetup luksFormat -q --type luks2 --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --key-file "$W/key" "$W/luks.img" >/dev/null 2>&1 || F "luksFormat failed"
out="$("$ENROLL" --unlock-key-file="$W/key" --tpm2-device="$D" --tpm2-pcrlock="$POLICY" --tpm2-pcrs= "$W/luks.img" 2>&1)" \
  && P "enrolled: $(tail -1 <<< "$out")" || F "systemd-cryptenroll failed: $out"
token="$(cryptsetup luksDump --dump-json-metadata "$W/luks.img" 2>/dev/null | python3 -c 'import json,sys
t = [v for v in json.load(sys.stdin)["tokens"].values() if v.get("type") == "systemd-tpm2"]
print(len(t), t[0].get("tpm2_pcrlock"), t[0].get("tpm2-pcrs"), "tpm2_pubkey" in t[0]) if t else print(0)' 2>/dev/null)"
[ "$token" = "1 True [] False" ] && P "the header: one systemd-tpm2 token, NV-backed (tpm2_pcrlock), no PCR list of its own, no signed policy" || F "the token is not as expected: $token"
header(){ cryptsetup luksHeaderBackup "$W/luks.img" --header-backup-file "$W/hdr.$$" >/dev/null 2>&1; sha256sum < "$W/hdr.$$" | cut -d' ' -f1; rm -f "$W/hdr.$$"; }
H1="$(header)"
opens "it unlocks on image-1, through the TPM token alone"
cryptsetup open --test-passphrase --key-file "$W/key" "$W/luks.img" >/dev/null 2>&1 && P "its passphrase still opens it (the recovery path)" || F "the passphrase no longer opens the volume"

hdr "2  the update: image-2 is approved beside image-1"
approve image-2
cp "$POLICY" "$W/policy-1-only.json"
out="$(policy)" && [ "$(nv)" = "$NV" ] && P "the policy is remade in the SAME NV index, on the running image-1" || F "make-policy failed or moved the index: $out"
cp "$POLICY" "$W/policy-1-and-2.json"
opens "image-1, still running, still unlocks"
boot image-2
opens "after a reboot into image-2 the same volume unlocks"
[ "$(header)" = "$H1" ] && P "with no re-enrolment: the LUKS header is byte for byte the one from step 1" || F "the LUKS header changed"

hdr "3  retirement: image-1 is removed from the policy"
rm -f "$VARIANTS/image-1.pcrlock"
out="$(policy)" && P "the policy is remade on image-2, without image-1" || F "make-policy failed: $out"
cp "$POLICY" "$W/policy-2-only.json"
opens "image-2 unlocks"
boot image-1
closed "image-1, retired, does NOT unlock"
boot image-3
closed "an image that was never approved does not unlock"

hdr "4  the retired image tries to come back"
boot image-1
cp "$W/policy-1-and-2.json" "$POLICY"
closed "with the OLD policy file restored (a disk rollback), image-1 still does not unlock: the NV index holds the new policy"
cp "$W/policy-1-only.json" "$POLICY"
closed "nor with the policy file from before the update"
# It re-approves itself and asks for a new policy. Writing the NV index needs the PIN kept in the policy
# file, sealed so that only a boot the CURRENT policy accepts can open it.
cp "$W/policy-2-only.json" "$POLICY"; approve image-1
if out="$(policy)"; then F "the retired image REMADE the policy with itself in it: $(tr '\n' ' ' <<< "$out" | cut -c1-200)"
else P "the retired image cannot remake the policy to include itself ($(tail -1 <<< "$out" | cut -c1-120))"; fi
closed "and it still does not unlock"
rm -f "$VARIANTS/image-1.pcrlock"; cp "$W/policy-2-only.json" "$POLICY"

hdr "5  control"
boot image-2
opens "image-2 unlocks again"
[ "$(header)" = "$H1" ] && P "the LUKS header never changed" || F "the LUKS header changed"
grep -q 'TPM2_PT_LOCKOUT_COUNTER: 0x0$' <<< "$(tpm2_getcap properties-variable 2>/dev/null)" \
  && P "the TPM's lockout counter is 0: no refusal above was a lockout" || F "the TPM counted failed tries: $(tpm2_getcap properties-variable 2>/dev/null | grep LOCKOUT_COUNTER)"

echo; echo "pcrlock-luks-swtpm: $pass passed, $fail failed$([ "$skipped" -gt 0 ] && echo ", $skipped SKIPPED (the unlocks: nothing about retirement was proven)")"
[ "$fail" -eq 0 ] && [ "$skipped" -eq 0 ]
