#!/usr/bin/env bash
# nitrokey-envelope-restore-drill.sh — regalia#6 acceptance criterion 4 on a real Nitrokey HSM 2:
# an envelope sealed to a hardware KEK opens after the card is WIPED and the KEK is restored from its
# DKEK-wrapped backup. DESTRUCTIVE: it initialises the card twice. Staging cards only — it refuses
# unless the staging registry lists the card as disposable and its C.DevAut matches the pin.
#
#   REGALIA_CEREMONY_DIR=<regalia-ceremony checkout> HSM_SO_PIN=… HSM_USER_PIN=… \
#     HSM_STAGING_REGISTRY_FILE=<regalia>/tools/hsm-staging-registry.json \
#     e2e/nitrokey-envelope-restore-drill.sh DENK0404144
#
# Sequence (the daemon half is TestEnvelopeSurvivesTokenWipeAndDKEKRestore, one phase per step):
#   1 initialise with one DKEK share; create and import a drill-only share (random password)
#   2 generate an RSA-2048 KEK ON the card; wrap-export it under the DKEK (sc-hsm-tool --wrap-key)
#   3 SEAL an envelope through the production seal path; it must open on this card first
#   4 WIPE (initialise again); the KEK must be gone
#   5 the envelope must NOT open                                  (negative control: the wipe was real)
#   6 import the DKEK share; unwrap the KEK backup (sc-hsm-tool --unwrap-key)
#   7 the envelope must open, byte-identical, and the restored key must match the commissioned
#     public-key pin (ADR-0002 D1)
#
# THE DKEK HERE IS A THROWAWAY: one share, one random password, generated per run. What this drill
# proves is the key-and-envelope half; DKEK custody (4-of-6 password shares, a corrupted-share
# negative control) was drilled on this card on 2026-09-21 (doc/drills in regalia).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERIAL="${1:?serial of the staging Nitrokey}"
CEREMONY="${REGALIA_CEREMONY_DIR:?REGALIA_CEREMONY_DIR must point at a regalia-ceremony checkout}"
: "${HSM_SO_PIN:?}" "${HSM_USER_PIN:?}" "${HSM_STAGING_REGISTRY_FILE:?}"
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
export HSM_PKCS11_MODULE="$MODULE"
KEY_ID=10
STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-envdrill.XXXXXX")"
chmod 700 "$STATE"
LOG="$STATE/transcript.log"
say(){ printf '%s %s\n' "$(date -u +%T)" "$*" | tee -a "$LOG"; }
die(){ say "FAIL: $*"; say "state kept for inspection: $STATE"; exit 1; }
for t in sc-hsm-tool pkcs11-tool pkcs15-tool openssl go; do command -v "$t" >/dev/null || die "$t is required"; done
# shellcheck source=/dev/null
. "$CEREMONY/tools/hsm-reader-select.sh"

# ---- the gate: a registered, disposable staging card, proven by its device certificate -----------
hsm_assert_staging_card "$SERIAL" || die "$SERIAL is not a registered staging card (or its DevAut does not match): refusing to wipe it"
reader(){ hsm_reader_for "$SERIAL" 2>/dev/null; }
slot(){ hsm_slot_id_for "$SERIAL" 2>/dev/null; }
READER="$(reader)"; [ -n "$READER" ] || die "cannot resolve $SERIAL to a reader"
say "card $SERIAL at reader $READER; state $STATE"

p11(){ local s; s="$(slot)"; [ -n "$s" ] || die "cannot resolve $SERIAL to a PKCS#11 slot"
       REGALIA_DRILL_PIN="$HSM_USER_PIN" pkcs11-tool --module "$MODULE" --slot "$s" --login --pin env:REGALIA_DRILL_PIN "$@"; }
has_kek(){ p11 --list-objects --type privkey 2>/dev/null | grep -qiE "ID: *$KEY_ID\b"; }
phase(){ REGALIA_ENVDRILL_PHASE="$1" REGALIA_ENVDRILL_MODULE="$MODULE" REGALIA_ENVDRILL_SERIAL="$SERIAL" \
         REGALIA_ENVDRILL_OBJECT_ID="$KEY_ID" REGALIA_ENVDRILL_PIN="$HSM_USER_PIN" REGALIA_ENVDRILL_STATE="$STATE" \
         go -C "$ROOT" test -count=1 -v -run '^TestEnvelopeSurvivesTokenWipeAndDKEKRestore$' ./internal/integration 2>&1 \
         | tee -a "$LOG" | grep -E -- '--- (PASS|FAIL|SKIP)|_test.go:' ; }
passed(){ grep -q -- "--- PASS: TestEnvelopeSurvivesTokenWipeAndDKEKRestore" <(tail -40 "$LOG"); }
# PINs and the DKEK password are typed into sc-hsm-tool's prompts over a pty, never put on argv
# (sc-hsm-tool has no env: form). See e2e/lib/sc-hsm-pty.py.
schsm(){ SCHSM_SO_PIN="$HSM_SO_PIN" SCHSM_USER_PIN="$HSM_USER_PIN" SCHSM_DKEK_PW="$DKEK_PW" "$ROOT/e2e/lib/sc-hsm-pty.py" sc-hsm-tool "$@"; }
initialise(){
  schsm --reader "$READER" --initialize \
    --dkek-shares 1 --label regalia-drill >>"$LOG" 2>&1 || die "initialise failed"
  READER="$(reader)"; [ -n "$READER" ] || die "card not found after initialise"
}
import_share(){
  schsm --reader "$READER" --import-dkek-share "$STATE/dkek.pbe" >>"$LOG" 2>&1 \
    || die "DKEK share import failed"
}

DKEK_PW="$(openssl rand -hex 16)"

say "STEP 1 — initialise, create and import a drill-only DKEK share"
initialise
schsm --create-dkek-share "$STATE/dkek.pbe" >>"$LOG" 2>&1 || die "create DKEK share failed"
import_share

say "STEP 2 — generate an RSA-2048 KEK on the card and wrap-export it under the DKEK"
p11 --keypairgen --key-type rsa:2048 --id "$KEY_ID" --label drill-kek --usage-decrypt >>"$LOG" 2>&1 || die "KEK keygen failed"
has_kek || die "the generated KEK is not visible"
KEY_REF="$(pkcs15-tool --reader "$READER" --list-keys 2>/dev/null \
  | awk -v want="$KEY_ID" '
      # pkcs15-tool prints "Key ref" BEFORE "ID" in each block, and "Auth ID" also contains "ID".
      /^Private/                 { ref = "" }
      /^[ \t]*Key ref[ \t]*:/    { ref = $4 }
      /^[ \t]*ID[ \t]*:/         { if ($NF == want && ref != "") { print ref; exit } }')"
[ -n "$KEY_REF" ] || die "cannot find the key reference of ID $KEY_ID"
schsm --reader "$READER" --wrap-key "$STATE/kek.wrapped" --key-reference "$KEY_REF" >>"$LOG" 2>&1 \
  || die "wrap-export failed"
[ -s "$STATE/kek.wrapped" ] || die "empty wrapped backup"
say "  KEK at key reference $KEY_REF, backup $(wc -c < "$STATE/kek.wrapped") bytes"

say "STEP 3 — seal an envelope to the KEK (it must open on this card first)"
phase seal; passed || die "seal phase"

say "STEP 4 — WIPE the card"
initialise
has_kek && die "the KEK is still on the card after the wipe"
say "  KEK gone"

say "STEP 5 — the envelope must NOT open on the wiped card"
phase open-refused; passed || die "open-refused phase"

say "STEP 6 — import the DKEK share and unwrap the KEK backup"
import_share
# sc-hsm-tool --unwrap-key exits 1 even on success (measured 2026-08-06; see the ceremony's
# hsm-recovery-drill.sh), so success is decided by the key being back, not by the exit status.
schsm --reader "$READER" --unwrap-key "$STATE/kek.wrapped" --key-reference "$KEY_REF" >>"$LOG" 2>&1 || true
has_kek || die "the KEK is not back after --unwrap-key"
say "  KEK restored at key reference $KEY_REF"

say "STEP 7 — the envelope sealed before the wipe must open now"
phase open; passed || die "open phase"

say "DRILL PASSED: sealed → wiped → refused → restored from the DKEK backup → opened, byte-identical"
# The wrapped backup and the share are drill-only, but they ARE key material: removed, not kept.
rm -f "$STATE/kek.wrapped" "$STATE/dkek.pbe" "$STATE/envelope-drill.json"   # the seal record holds the drill secret
say "transcript: $LOG"
