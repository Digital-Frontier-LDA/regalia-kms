#!/usr/bin/env bash
# nitrokey-cross-card-restore-drill.sh — regalia#26 criterion 2 (the Nitrokey half) and the
# different-hardware version of regalia#6 criterion 4: an envelope sealed to a KEK generated on ONE
# genuine Nitrokey HSM 2 opens on a DIFFERENT genuine unit after the KEK is restored there from its
# DKEK-wrapped backup, and the restored key is the key the first card's pin commits to (ADR-0002 D1).
#
#   REGALIA_CEREMONY_DIR=<regalia-ceremony> HSM_STAGING_REGISTRY_FILE=<regalia>/tools/hsm-staging-registry.json \
#   SRC_SO_PIN=… SRC_USER_PIN=… DST_SO_PIN=… DST_USER_PIN=… \
#     e2e/nitrokey-cross-card-restore-drill.sh <source serial> <target serial>
#
# DESTRUCTIVE: both cards are initialised. Staging cards only: each must be listed in the staging
# registry with a C.DevAut pin that the card's own C.DevAut matches. Each card keeps its OWN SO PIN
# and user PIN; only the DKEK is shared, because that is what a restore domain is.
#
# Sequence (the daemon half is TestEnvelopeSurvivesTokenWipeAndDKEKRestore, one phase per step):
#   1 initialise BOTH cards with one DKEK share each; create one drill-only share (random password)
#     and import it into both; their DKEK key check values must match (same restore domain)
#   2 generate an RSA-2048 KEK ON the source; wrap-export it under the DKEK
#   3 SEAL an envelope through the production seal path, pinned to the source key; it must open there
#   4 the envelope must NOT open on the target yet    (negative control: the target has no such key)
#   5 unwrap the KEK backup onto the TARGET
#   6 the envelope must open ON THE TARGET, byte-identical, and the target's key must match the pin
#     committed on the source
#
# THE DKEK HERE IS A THROWAWAY: one share, a random password, generated per run and deleted after.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${1:?source serial}"; DST="${2:?target serial}"
[ "$SRC" != "$DST" ] || { echo "source and target must be two different cards" >&2; exit 2; }
CEREMONY="${REGALIA_CEREMONY_DIR:?REGALIA_CEREMONY_DIR must point at a regalia-ceremony checkout}"
: "${SRC_SO_PIN:?}" "${SRC_USER_PIN:?}" "${DST_SO_PIN:?}" "${DST_USER_PIN:?}" "${HSM_STAGING_REGISTRY_FILE:?}"
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
export HSM_PKCS11_MODULE="$MODULE"
KEY_ID=10
STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-xcard.XXXXXX")"; chmod 700 "$STATE"
LOG="$STATE/transcript.log"
# OPENSC HIDES CARDS PAST 16 VIRTUAL SLOTS. Each reader takes 4 (slots_per_card), and
# max_virtual_slots defaults to 16, so on a bench with two vpcd readers and three HSMs the FIFTH
# reader gets no PKCS#11 slot at all (measured 2026-09-24: DENK0404547 vanished from `pkcs11-tool -L`
# while `opensc-tool -l` still listed it). A drill that cannot see a card must not read that as "the
# card has no key", so the drill raises the limit in its own config, and checks both cards resolve.
cat > "$STATE/opensc.conf" <<'CONF'
app default {
}
app opensc-pkcs11 {
	pkcs11 {
		max_virtual_slots = 32;
		slots_per_card = 4;
	}
}
CONF
export OPENSC_CONF="${OPENSC_CONF:-$STATE/opensc.conf}"
say(){ printf '%s %s\n' "$(date -u +%T)" "$*" | tee -a "$LOG"; }
die(){ say "FAIL: $*"; say "state kept for inspection: $STATE"; exit 1; }
for t in sc-hsm-tool pkcs11-tool pkcs15-tool opensc-tool openssl go; do command -v "$t" >/dev/null || die "$t is required"; done
# shellcheck source=/dev/null
. "$CEREMONY/tools/hsm-reader-select.sh"
# shellcheck source=/dev/null
. "$CEREMONY/qubes/scripts/ceremony-kcv.sh"

pin_of(){ case "$1:$2" in "$SRC:so") echo "$SRC_SO_PIN";; "$SRC:user") echo "$SRC_USER_PIN";; "$DST:so") echo "$DST_SO_PIN";; "$DST:user") echo "$DST_USER_PIN";; esac; }
for s in "$SRC" "$DST"; do
  hsm_assert_staging_card "$s" || die "$s is not a registered staging card (or its DevAut does not match): refusing to initialise it"
done
# Resolved in the MAIN shell, into $READER. An inline `--reader "$(hsm_reader_for …)"` that fails
# passes `--reader ""`, which OpenSC reads as reader 0, i.e. ANOTHER card (review of #37).
reader_of(){ READER="$(hsm_reader_for "$1" 2>/dev/null || true)"; [ -n "$READER" ] || die "cannot resolve $1 to a PC/SC reader"; }
reader(){ reader_of "$1"; echo "$READER"; }
# sc-hsm-tool has no env: form, so its PINs and DKEK password are typed into its own prompts over a
# pty (e2e/lib/sc-hsm-pty.py) and never appear in the process list.
schsm(){ local card="$1"; shift
  SCHSM_SO_PIN="$(pin_of "$card" so)" SCHSM_USER_PIN="$(pin_of "$card" user)" SCHSM_DKEK_PW="$DKEK_PW" \
    "$ROOT/e2e/lib/sc-hsm-pty.py" sc-hsm-tool "$@"; }
# Resolved in the MAIN shell, so a card PKCS#11 cannot see stops the drill instead of reading as empty.
slot_of(){ local s; s="$(hsm_slot_id_for "$1" 2>/dev/null || true)"; [ -n "$s" ] || die "PKCS#11 cannot see $1 (OPENSC_CONF=$OPENSC_CONF)"; SLOT="$s"; }
for s in "$SRC" "$DST"; do slot_of "$s"; done
say "source $SRC (reader $(reader "$SRC")), target $DST (reader $(reader "$DST")); state $STATE; OPENSC_CONF=$OPENSC_CONF"

p11(){ local card="$1"; shift; slot_of "$card"
       REGALIA_DRILL_PIN="$(pin_of "$card" user)" pkcs11-tool --module "$MODULE" --slot "$SLOT" --login --pin env:REGALIA_DRILL_PIN "$@"; }
# Lists the card's private keys; a failed listing stops the drill, it is never "no key".
has_kek(){ local out; slot_of "$1"
  out="$(REGALIA_DRILL_PIN="$(pin_of "$1" user)" pkcs11-tool --module "$MODULE" --slot "$SLOT" --login --pin env:REGALIA_DRILL_PIN --list-objects --type privkey 2>&1)" \
    || die "cannot list the private keys on $1"
  grep -qiE "ID: *$KEY_ID\b" <<< "$out"; }
phase(){ # phase <name> <card>
  REGALIA_ENVDRILL_PHASE="$1" REGALIA_ENVDRILL_MODULE="$MODULE" REGALIA_ENVDRILL_SERIAL="$2" \
  REGALIA_ENVDRILL_OBJECT_ID="$KEY_ID" REGALIA_ENVDRILL_PIN="$(pin_of "$2" user)" REGALIA_ENVDRILL_STATE="$STATE" \
    go -C "$ROOT" test -count=1 -v -run '^TestEnvelopeSurvivesTokenWipeAndDKEKRestore$' ./internal/integration > "$STATE/phase.out" 2>&1 || true
  cat "$STATE/phase.out" >> "$LOG"
  local out; out="$(cat "$STATE/phase.out")"   # THIS phase's output only, not the log's tail
  grep -E -- '--- (PASS|FAIL|SKIP)|_test.go:' <<< "$out" | sed 's/^/    /'
  grep -q -- "--- PASS: TestEnvelopeSurvivesTokenWipeAndDKEKRestore" <<< "$out"; }
initialise(){ local card="$1"; reader_of "$card"
  schsm "$card" --reader "$READER" --initialize --dkek-shares 1 --label regalia-xcard-drill >>"$LOG" 2>&1 \
    || die "initialise $card failed"; }
import_share(){ local card="$1"; reader_of "$card"
  schsm "$card" --reader "$READER" --import-dkek-share "$STATE/dkek.pbe" > "$STATE/import-$card.log" 2>&1 \
    || die "DKEK share import into $card failed"; cat "$STATE/import-$card.log" >> "$LOG"; }

DKEK_PW="$(openssl rand -hex 16)"

say "STEP 1 — initialise both cards; one drill-only DKEK share imported into each; the KCVs must match"
initialise "$SRC"; initialise "$DST"
schsm "$SRC" --create-dkek-share "$STATE/dkek.pbe" >>"$LOG" 2>&1 || die "create DKEK share failed"
import_share "$SRC"; import_share "$DST"
kcv_src="$(kcv_of "$STATE/import-$SRC.log" || true)"; kcv_dst="$(kcv_of "$STATE/import-$DST.log" || true)"
[ -n "$kcv_src" ] && [ "$kcv_src" = "$kcv_dst" ] || die "the two cards do not report the same DKEK key check value ('$kcv_src' vs '$kcv_dst')"
say "  both cards hold DKEK KCV $kcv_src — one restore domain"

say "STEP 2 — generate an RSA-2048 KEK on the SOURCE and wrap-export it under the DKEK"
p11 "$SRC" --keypairgen --key-type rsa:2048 --id "$KEY_ID" --label xcard-kek --usage-decrypt >>"$LOG" 2>&1 || die "KEK keygen failed"
has_kek "$SRC" || die "the generated KEK is not visible on the source"
has_kek "$DST" && die "the target already holds a key with ID $KEY_ID before the restore"
reader_of "$SRC"
keys="$(pkcs15-tool --reader "$READER" --list-keys 2>/dev/null || true)"
KEY_REF="$(awk -v want="$KEY_ID" '
    /^Private/                 { ref = "" }
    /^[ \t]*Key ref[ \t]*:/    { ref = $4 }
    /^[ \t]*ID[ \t]*:/         { if ($NF == want && ref != "") { print ref; exit } }' <<< "$keys")"
[ -n "$KEY_REF" ] || die "cannot find the key reference of ID $KEY_ID"
reader_of "$SRC"
schsm "$SRC" --reader "$READER" --wrap-key "$STATE/kek.wrapped" --key-reference "$KEY_REF" >>"$LOG" 2>&1 \
  || die "wrap-export failed"
[ -s "$STATE/kek.wrapped" ] || die "empty wrapped backup"
say "  KEK at key reference $KEY_REF, backup $(wc -c < "$STATE/kek.wrapped") bytes"

say "STEP 3 — seal an envelope to the SOURCE's KEK (it must open there first)"
phase seal "$SRC" || die "seal phase"

say "STEP 4 — the envelope must NOT open on the TARGET before the restore"
# The refusal must be BECAUSE the key is absent: the target is reachable and logged into, and holds
# no key with this ID. Without this, an unreachable target refuses too, and proves nothing.
has_kek "$DST" && die "the target already holds a key with ID $KEY_ID"
say "  target reachable (PKCS#11 slot $SLOT), logged in, no key with ID $KEY_ID"
phase open-refused "$DST" || die "open-refused phase on the target"

say "STEP 5 — unwrap the KEK backup onto the TARGET"
# sc-hsm-tool --unwrap-key exits 1 even on success (measured 2026-08-06), so the key being there decides.
reader_of "$DST"
schsm "$DST" --reader "$READER" --unwrap-key "$STATE/kek.wrapped" --key-reference "$KEY_REF" >>"$LOG" 2>&1 || true
has_kek "$DST" || die "the KEK is not on the target after --unwrap-key"
say "  KEK restored on $DST at key reference $KEY_REF"

say "STEP 6 — the envelope sealed on the source must open ON THE TARGET"
phase open "$DST" || die "open phase on the target"

say "DRILL PASSED: sealed on $SRC → refused on $DST → KEK restored onto $DST from the DKEK backup → opened there, byte-identical, under the pin committed on $SRC"
# The seal record holds the drill secret in plaintext (and the envelope): it goes with the key material.
rm -f "$STATE/kek.wrapped" "$STATE/dkek.pbe" "$STATE"/import-*.log "$STATE/envelope-drill.json"
say "transcript: $LOG"
