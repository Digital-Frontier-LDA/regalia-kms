#!/usr/bin/env bash
# nitrokey-token-swap-drill.sh — regalia#48 rows F3 (USB detach and return) and F5 (a different genuine
# card in place of the commissioned one) on REAL cards, with one long-lived provider across the whole
# sequence (TestPhysicalTokenSwapIsRefusedBeforeAnyPIN). What this script adds is the measurement the
# test cannot make about itself: EVERY attached card's PIN retry counter, read before and after from
# outside the process (an empty VERIFY answers 63Cx without spending a try). Every counter must end
# where it started.
#
#   REGALIA_CEREMONY_DIR=<regalia-ceremony> HSM_STAGING_REGISTRY_FILE=<regalia>/tools/hsm-staging-registry.json \
#   COMMISSIONED_PIN=… OTHER_PIN=… sudo -v && \
#     e2e/nitrokey-token-swap-drill.sh <commissioned serial> <other serial> [object id, default 10]
#
# The commissioned card must hold an RSA-2048 KEK at the object ID. The other card must be a genuine
# card holding a DIFFERENT key under the same ID, so that only the public-key pin can refuse it.
# Nothing is initialised or written; the commissioned card is USB de-authorised and re-authorised.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARD="${1:?commissioned serial}"; OTHER="${2:?other serial}"; OBJECT="${3:-10}"
[ "$CARD" != "$OTHER" ] || { echo "two different cards are required" >&2; exit 2; }
CEREMONY="${REGALIA_CEREMONY_DIR:?}"
: "${COMMISSIONED_PIN:?}" "${OTHER_PIN:?}" "${HSM_STAGING_REGISTRY_FILE:?}"
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
export HSM_PKCS11_MODULE="$MODULE"
STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-swap.XXXXXX")"; chmod 700 "$STATE"
LOG="$STATE/transcript.log"
# Three or more readers: OpenSC's default 16 virtual slots hide the fifth (see the cross-card drill).
printf 'app default {\n}\napp opensc-pkcs11 {\n\tpkcs11 {\n\t\tmax_virtual_slots = 32;\n\t}\n}\n' > "$STATE/opensc.conf"
export OPENSC_CONF="${OPENSC_CONF:-$STATE/opensc.conf}"
say(){ printf '%s %s\n' "$(date -u +%T)" "$*" | tee -a "$LOG"; }
die(){ say "FAIL: $*"; say "state kept for inspection: $STATE"; exit 1; }
sudo -n true 2>/dev/null || die "needs sudo for the USB toggle; run 'sudo -v' first"
# shellcheck source=/dev/null
. "$CEREMONY/tools/hsm-reader-select.sh"

for s in "$CARD" "$OTHER"; do hsm_assert_staging_card "$s" || die "$s is not a registered staging card: refusing"; done
USB=""
for d in /sys/bus/usb/devices/*; do
  [ -f "$d/serial" ] && [ "$(tr -d ' ' < "$d/serial")" = "${CARD}0000" ] && USB="$(basename "$d")"
done
[ -n "$USB" ] || die "cannot find $CARD on USB"

# Every attached SmartCard-HSM, by serial, and its user-PIN retry counter.
counters(){ local list line r s sw
  list="$(opensc-tool -l 2>/dev/null || true)"
  while read -r line; do
    r="$(awk '{print $1}' <<< "$line")"; s="$(sed -n 's/.*(\(DENK[0-9]\{7\}\)0000.*/\1/p' <<< "$line")"
    [ -n "$s" ] || continue
    sw="$(opensc-tool --reader "$r" -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00" -s "00 20 00 81" 2>&1 \
          | grep -oE 'SW1=0x[0-9A-F]+, SW2=0x[0-9A-F]+' | tail -1 || true)"
    printf '%s=%s ' "$s" "$(sed -n 's/SW1=0x63, SW2=0xC\([0-9A-F]\)/\1/p' <<< "$sw")"
  done <<< "$list"; echo; }
BEFORE="$(counters)"
say "commissioned $CARD at USB $USB, other $OTHER, object $OBJECT; OPENSC_CONF=$OPENSC_CONF"
say "PIN tries before: $BEFORE"

REGALIA_SWAPDRILL_MODULE="$MODULE" REGALIA_SWAPDRILL_SERIAL="$CARD" REGALIA_SWAPDRILL_PIN="$COMMISSIONED_PIN" \
REGALIA_SWAPDRILL_USB="$USB" REGALIA_SWAPDRILL_OTHER_SERIAL="$OTHER" REGALIA_SWAPDRILL_OTHER_PIN="$OTHER_PIN" \
REGALIA_SWAPDRILL_OBJECT_ID="$OBJECT" \
  go -C "$ROOT" test -count=1 -v -run '^TestPhysicalTokenSwapIsRefusedBeforeAnyPIN$' ./internal/integration > "$STATE/test.out" 2>&1 || true
cat "$STATE/test.out" >> "$LOG"
grep -E -- '--- (PASS|FAIL|SKIP)|_test.go:' "$STATE/test.out" | sed 's/^/    /' | tee -a /dev/null
# The card must be back whatever the test did.
[ "$(cat "/sys/bus/usb/devices/$USB/authorized")" = 1 ] || { echo 1 | sudo tee "/sys/bus/usb/devices/$USB/authorized" >/dev/null; sleep 3; }
sleep 2
AFTER="$(counters)"
say "PIN tries after:  $AFTER"
grep -q -- "--- PASS: TestPhysicalTokenSwapIsRefusedBeforeAnyPIN" "$STATE/test.out" || die "the provider half failed"
[ "$BEFORE" = "$AFTER" ] || die "a PIN retry counter moved: before '$BEFORE', after '$AFTER'"
say "DRILL PASSED: detach refused, a different genuine card quarantined before any PIN, the same provider served again on return; no counter moved"
say "transcript: $LOG"
