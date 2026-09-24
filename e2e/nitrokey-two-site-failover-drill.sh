#!/usr/bin/env bash
# nitrokey-two-site-failover-drill.sh — active/passive failover across TWO genuine Nitrokey HSM 2 cards
# (regalia#15/#435 on real hardware; the one-card version is TestCosmosSigningAcrossAnActivePassivePromotion).
#
#   REGALIA_CEREMONY_DIR=<regalia-ceremony> HSM_STAGING_REGISTRY_FILE=<regalia>/tools/hsm-staging-registry.json \
#   A_SO_PIN=… A_USER_PIN=… B_SO_PIN=… B_USER_PIN=… \
#     e2e/nitrokey-two-site-failover-drill.sh <site A serial> <site B serial>
#
# DESTRUCTIVE: both cards are initialised. Staging cards only (registry + C.DevAut gate).
#
# The fleet design (REQUIREMENTS A3/A5): each site holds the SAME wallet key, imported under that
# site's OWN DKEK. So, per card: initialise with its own PINs, create and import its own drill-only
# DKEK share, and import one throwaway secp256k1 wallet key with the JVM-free importer
# (hsm-import-key-nojvm.sh). Then:
#   - the two DKEK key check values must DIFFER (two restore domains, not one);
#   - both cards must expose the wallet's public key;
#   - TestCosmosSigningFailsOverBetweenTwoCards runs the promotion across them;
#   - every card's PIN counter is read from outside before and after, and must not move.
# The wallet key, its PKCS#12, both DKEK shares and every password file are deleted at the end.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
A="${1:?site A serial}"; B="${2:?site B serial}"
[ "$A" != "$B" ] || { echo "two different cards are required" >&2; exit 2; }
CEREMONY="${REGALIA_CEREMONY_DIR:?}"
: "${A_SO_PIN:?}" "${A_USER_PIN:?}" "${B_SO_PIN:?}" "${B_USER_PIN:?}" "${HSM_STAGING_REGISTRY_FILE:?}"
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
export HSM_PKCS11_MODULE="$MODULE"
KEY_REF=49          # the SmartCard-HSM key reference, DECIMAL, for PKCS#11 ID 0x31 (the registry's "31")
OBJECT_ID=31
STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-2site.XXXXXX")"; chmod 700 "$STATE"
LOG="$STATE/transcript.log"
printf 'app default {\n}\napp opensc-pkcs11 {\n\tpkcs11 {\n\t\tmax_virtual_slots = 32;\n\t}\n}\n' > "$STATE/opensc.conf"
export OPENSC_CONF="${OPENSC_CONF:-$STATE/opensc.conf}"
say(){ printf '%s %s\n' "$(date -u +%T)" "$*" | tee -a "$LOG"; }
die(){ say "FAIL: $*"; say "state kept for inspection: $STATE"; exit 1; }
cleanup(){ rm -f "$STATE"/wallet.* "$STATE"/*.pw "$STATE"/*.pbe "$STATE"/*.pin; }
trap cleanup EXIT
for t in sc-hsm-tool pkcs11-tool opensc-tool openssl python3 go; do command -v "$t" >/dev/null || die "$t is required"; done
# shellcheck source=/dev/null
. "$CEREMONY/tools/hsm-reader-select.sh"
# shellcheck source=/dev/null
. "$CEREMONY/qubes/scripts/ceremony-kcv.sh"
IMPORT="$CEREMONY/qubes/scripts/hsm-import-key-nojvm.sh"
[ -x "$IMPORT" ] || die "no importer at $IMPORT"

pin_of(){ case "$1:$2" in "$A:so") echo "$A_SO_PIN";; "$A:user") echo "$A_USER_PIN";; "$B:so") echo "$B_SO_PIN";; "$B:user") echo "$B_USER_PIN";; esac; }
for s in "$A" "$B"; do hsm_assert_staging_card "$s" || die "$s is not a registered staging card: refusing"; done
reader(){ hsm_reader_for "$1" 2>/dev/null; }
slot(){ local s; s="$(hsm_slot_id_for "$1" 2>/dev/null || true)"; [ -n "$s" ] || die "PKCS#11 cannot see $1"; echo "$s"; }
counters(){ local list line r s sw
  list="$(opensc-tool -l 2>/dev/null || true)"
  while read -r line; do
    r="$(awk '{print $1}' <<< "$line")"; s="$(sed -n 's/.*(\(DENK[0-9]\{7\}\)0000.*/\1/p' <<< "$line")"
    [ -n "$s" ] || continue
    sw="$(opensc-tool --reader "$r" -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00" -s "00 20 00 81" 2>&1 \
          | grep -oE 'SW1=0x[0-9A-F]+, SW2=0x[0-9A-F]+' | tail -1 || true)"
    printf '%s=%s ' "$s" "$(sed -n 's/SW1=0x63, SW2=0xC\([0-9A-F]\)/\1/p' <<< "$sw")"
  done <<< "$list"; echo; }

# The throwaway wallet: one secp256k1 key, the stand-in for the seed-derived funding key.
openssl ecparam -name secp256k1 -genkey -noout -out "$STATE/wallet.key"
openssl req -new -x509 -key "$STATE/wallet.key" -subj "/CN=regalia two-site drill wallet" -days 30 -out "$STATE/wallet.crt" 2>/dev/null
openssl rand -hex 16 > "$STATE/wallet.p12.pw"
openssl pkcs12 -export -inkey "$STATE/wallet.key" -in "$STATE/wallet.crt" -out "$STATE/wallet.p12" -passout "file:$STATE/wallet.p12.pw"
WALLET_SPKI="$(openssl ec -in "$STATE/wallet.key" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
say "sites: A=$A (reader $(reader "$A"), slot $(slot "$A")), B=$B (reader $(reader "$B"), slot $(slot "$B")); wallet SPKI sha256:$WALLET_SPKI"
BEFORE="$(counters)"; say "PIN tries before: $BEFORE"

provision(){ local card="$1" r kcv
  r="$(reader "$card")"
  say "provision $card — initialise, its OWN DKEK share, import the wallet under it"
  sc-hsm-tool --reader "$r" --initialize --so-pin "$(pin_of "$card" so)" --pin "$(pin_of "$card" user)" \
    --dkek-shares 1 --label "regalia-2site-$card" >>"$LOG" 2>&1 || die "initialise $card failed"
  openssl rand -hex 16 > "$STATE/$card.dkek.pw"
  sc-hsm-tool --create-dkek-share "$STATE/$card.pbe" --password "$(cat "$STATE/$card.dkek.pw")" >>"$LOG" 2>&1 || die "DKEK share for $card"
  sc-hsm-tool --reader "$r" --import-dkek-share "$STATE/$card.pbe" --password "$(cat "$STATE/$card.dkek.pw")" > "$STATE/$card.import.log" 2>&1 \
    || die "DKEK import into $card"
  cat "$STATE/$card.import.log" >> "$LOG"
  kcv="$(kcv_of "$STATE/$card.import.log" || true)"; [ -n "$kcv" ] || die "no DKEK KCV from $card"
  printf '%s' "$kcv" > "$STATE/$card.kcv"
  ( umask 077; pin_of "$card" user > "$STATE/$card.pin" )
  "$IMPORT" --p12 "$STATE/wallet.p12" --pw-file "$STATE/wallet.p12.pw" --id "$KEY_REF" --label two-site-wallet \
    --dkek "$STATE/$card.pbe" --dkek-pw "$STATE/$card.dkek.pw" --pin-file "$STATE/$card.pin" \
    --reader "$r" --slot "$(slot "$card")" --cert "$STATE/wallet.crt" >>"$LOG" 2>&1 || die "wallet import into $card failed"
  local pub; pub="$(REGALIA_DRILL_PIN="$(pin_of "$card" user)" pkcs11-tool --module "$MODULE" --slot "$(slot "$card")" \
     --login --pin env:REGALIA_DRILL_PIN --read-object --type pubkey --id "$OBJECT_ID" 2>/dev/null | sha256sum | cut -d' ' -f1)"
  [ "$pub" = "$WALLET_SPKI" ] || die "$card does not expose the wallet key after the import"
  say "  $card: DKEK KCV $kcv, wallet key present at ID $OBJECT_ID"
}
provision "$A"; provision "$B"
[ "$(cat "$STATE/$A.kcv")" != "$(cat "$STATE/$B.kcv")" ] || die "both cards share one DKEK: the sites are not independent restore domains"
say "the two sites hold DIFFERENT DKEKs and the SAME wallet key"

say "FAILOVER — TestCosmosSigningFailsOverBetweenTwoCards"
REGALIA_TWOSITE_MODULE="$MODULE" REGALIA_TWOSITE_OBJECT_ID="$OBJECT_ID" \
REGALIA_TWOSITE_SLOT_A="$(slot "$A")" REGALIA_TWOSITE_PIN_A="$A_USER_PIN" \
REGALIA_TWOSITE_SLOT_B="$(slot "$B")" REGALIA_TWOSITE_PIN_B="$B_USER_PIN" \
  go -C "$ROOT" test -count=1 -v -run '^TestCosmosSigningFailsOverBetweenTwoCards$' ./internal/integration > "$STATE/test.out" 2>&1 || true
cat "$STATE/test.out" >> "$LOG"
grep -E -- '--- (PASS|FAIL|SKIP)|_test.go:' "$STATE/test.out" | sed 's/^/    /'
AFTER="$(counters)"; say "PIN tries after:  $AFTER"
grep -q -- "--- PASS: TestCosmosSigningFailsOverBetweenTwoCards" "$STATE/test.out" || die "the failover test failed"
[ "$BEFORE" = "$AFTER" ] || die "a PIN retry counter moved: before '$BEFORE', after '$AFTER'"
say "DRILL PASSED: one wallet on two genuine cards under two DKEKs; signing failed over from $A to $B; the demoted site was refused at its stale epoch; no counter moved"
say "transcript: $LOG"
