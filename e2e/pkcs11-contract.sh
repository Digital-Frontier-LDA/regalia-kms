#!/usr/bin/env bash
# pkcs11-contract.sh — the common PKCS#11 application contract, run unchanged on any HSM (#62, PoC 2.1
# and 2.2): only the module and the token serial differ between a Nitrokey HSM 2 and a PicoHSM.
#
#   HSM_PIN_FILE=~/.config/regalia-qual/DENK0404144.pins \
#     e2e/pkcs11-contract.sh --serial DENK0404144 [--module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so]
#
# Staging tokens only (the serial must be in STAGING_SERIALS). The user PIN comes from HSM_PIN_FILE
# (HSM_USER_PIN=...) or HSM_USER_PIN, and reaches pkcs11-tool through its environment (--pin env:…),
# never argv or the transcript. It spends no wrong PIN.
#
#   1  identity and versions recorded (OpenSC, token model, firmware, serial)
#   2  an EC P-256 and an RSA-2048 key generated ON the token, with a fresh id
#   3  their private halves are sensitive, never extractable, and local; asked directly (C_GetAttributeValue),
#      the token refuses every secret attribute (e2e/lib/p11_extract_probe.py)
#   4  ECDSA sign on the token, verified by openssl with the exported public key; a tampered message fails
#   5  RSA encrypt by openssl, decrypt on the token, round trip exact
#   6  a new session (new process, re-login) and a pcscd restart: the keys are still usable
#   7  cleanup: the test keys are deleted and gone
# Evidence: a sanitized transcript in $EVIDENCE_DIR (default ./evidence-pkcs11-<serial>-<utc>.log).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
SERIAL=""
STAGING_SERIALS="${STAGING_SERIALS:-DENK0404144 DENK0404380 DENK0404547 ESP2202E14A ESP41D722E2}"
while [ $# -gt 0 ]; do case "$1" in
  --serial) SERIAL="${2:?}"; shift 2;; --module) MODULE="${2:?}"; shift 2;;
  -h|--help) sed -n '2,23p' "$0"; exit 0;; *) echo "pkcs11-contract: unknown argument $1" >&2; exit 2;; esac; done
die(){ echo "pkcs11-contract: $*" >&2; exit 2; }
[ -n "$SERIAL" ] || die "--serial is required (the token is chosen by serial, never by slot index)"
case " $STAGING_SERIALS " in *" $SERIAL "*) ;; *) die "$SERIAL is not a staging token: refusing";; esac
for t in pkcs11-tool openssl python3; do command -v "$t" >/dev/null || die "$t is required"; done
[ -r "$MODULE" ] || die "no PKCS#11 module at $MODULE"
if [ -n "${HSM_PIN_FILE:-}" ]; then
  HSM_USER_PIN="$(sed -n 's/^HSM_USER_PIN=//p' "$HSM_PIN_FILE" | head -1)"
fi
[ -n "${HSM_USER_PIN:-}" ] || die "no user PIN (HSM_PIN_FILE or HSM_USER_PIN)"
export REGALIA_Q_PIN="$HSM_USER_PIN"; unset HSM_USER_PIN

UTC="$(date -u +%Y%m%dT%H%M%SZ)"
EVID="${EVIDENCE_DIR:-.}/evidence-pkcs11-$SERIAL-$UTC.log"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
log(){ printf '%s\n' "$*" | sed "s/$REGALIA_Q_PIN/<pin>/g" >> "$EVID"; }
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; log "PASS $1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; log "FAIL $1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; log "### $1"; }

# The slot holding the token with this serial; exactly one, or refuse.
slot_of(){ pkcs11-tool --module "$MODULE" -L 2>/dev/null | python3 -c '
import re, sys
serial = sys.argv[1]; slot = None; hits = []
for line in sys.stdin:
    m = re.match(r"Slot (\d+) \((0x[0-9a-f]+)\)", line)
    if m: slot = m.group(2)
    if "serial num" in line and line.split(":", 1)[1].strip() == serial: hits.append(slot)
print(hits[0] if len(hits) == 1 else "")' "$SERIAL"; }
SLOT="$(slot_of)"; [ -n "$SLOT" ] || die "no single token with serial $SERIAL (pkcs11-tool -L)"
p11(){ pkcs11-tool --module "$MODULE" --slot "$SLOT" "$@"; }
p11l(){ p11 --login --pin env:REGALIA_Q_PIN "$@"; }
ID_EC="$(printf '7e%06x' $((RANDOM*RANDOM % 16777215)))"; ID_RSA="$(printf '7f%06x' $((RANDOM*RANDOM % 16777215)))"

hdr "1  identity and versions"
log "date: $UTC"; log "module: $MODULE"; log "opensc: $(opensc-tool --info 2>&1 | head -1)"; log "openssl: $(openssl version)"
info="$(p11 -T 2>&1)"; log "$info"
grep -q "$SERIAL" <<< "$info" && P "token $SERIAL in slot $SLOT ($(sed -n 's/.*token model *: *//p' <<< "$info" | head -1), firmware $(sed -n 's/.*firmware version *: *//p' <<< "$info" | head -1))" || F "token info does not name $SERIAL"

hdr "2  keys generated on the token"
out="$(p11l --keypairgen --key-type EC:prime256v1 --id "$ID_EC" --label "q62-ec-$UTC" --usage-sign 2>&1)"; rc=$?; log "$out"
[ "$rc" = 0 ] && P "EC P-256 generated (id $ID_EC)" || F "EC generation failed: $(tail -1 <<< "$out")"
out="$(p11l --keypairgen --key-type rsa:2048 --id "$ID_RSA" --label "q62-rsa-$UTC" --usage-decrypt --usage-sign 2>&1)"; rc=$?; log "$out"
[ "$rc" = 0 ] && P "RSA-2048 generated (id $ID_RSA)" || F "RSA generation failed: $(tail -1 <<< "$out")"

hdr "3  private halves: sensitive, never extractable, local; reading one fails"
objs="$(p11l --list-objects --type privkey 2>&1)"; log "$objs"
for id in "$ID_EC" "$ID_RSA"; do
  acc="$(python3 -c '
import re, sys
id_, text = sys.argv[1], sys.stdin.read()
for b in text.split("Private Key Object")[1:]:
    if re.search(r"^\s*ID:\s*%s\s*$" % re.escape(id_), b, re.M):
        m = re.search(r"^\s*Access:\s*(.+)$", b, re.M); print(m.group(1).strip() if m else ""); break' "$id" <<< "$objs")"
  if grep -q "sensitive" <<< "$acc" && grep -q "never extractable" <<< "$acc" && grep -q "local" <<< "$acc"; then
    P "$id: pkcs11-tool reports Access = $acc"
  else F "$id: Access = ${acc:-not reported}"; fi
  # pkcs11-tool will not read a private key at all, so ask the TOKEN directly (C_GetAttributeValue).
  out="$(python3 "$HERE/lib/p11_extract_probe.py" "$MODULE" "$SERIAL" "$id" 2>&1)"; rc=$?; log "extract probe $id: $out"
  [ "$rc" = 0 ] && P "$id: the token refuses its secret attributes ($(python3 -c 'import json,sys; d=json.loads(sys.stdin.read()); print("CKA_VALUE "+d["CKA_VALUE"]["rv"]+", PRIVATE_EXPONENT "+d["CKA_PRIVATE_EXPONENT"]["rv"])' <<< "$out" 2>/dev/null))" \
    || F "$id: extraction probe: $out"
done

hdr "4  ECDSA on the token, verified by openssl"
p11 --read-object --type pubkey --id "$ID_EC" -o "$W/ec.der" >/dev/null 2>&1
openssl pkey -pubin -inform DER -in "$W/ec.der" -out "$W/ec.pem" 2>/dev/null
printf 'regalia #62 contract %s' "$UTC" > "$W/msg"; openssl dgst -sha256 -binary "$W/msg" > "$W/msg.h"
out="$(p11l --sign --mechanism ECDSA --id "$ID_EC" --signature-format openssl -i "$W/msg.h" -o "$W/msg.sig" 2>&1)"; rc=$?; log "$out"
[ "$rc" = 0 ] && openssl dgst -sha256 -verify "$W/ec.pem" -signature "$W/msg.sig" "$W/msg" >/dev/null 2>&1 \
  && P "signature made on the token verifies with openssl" || F "ECDSA sign/verify failed: $(tail -1 <<< "$out")"
printf 'X' >> "$W/msg"
openssl dgst -sha256 -verify "$W/ec.pem" -signature "$W/msg.sig" "$W/msg" >/dev/null 2>&1 && F "a tampered message verified" || P "a tampered message does not verify"

hdr "5  RSA: encrypt with openssl, decrypt on the token"
p11 --read-object --type pubkey --id "$ID_RSA" -o "$W/rsa.der" >/dev/null 2>&1
openssl pkey -pubin -inform DER -in "$W/rsa.der" -out "$W/rsa.pem" 2>/dev/null
head -c 32 /dev/urandom > "$W/secret"
done_rsa=0
for mech in RSA-PKCS-OAEP RSA-PKCS; do
  if [ "$mech" = RSA-PKCS-OAEP ]; then
    openssl pkeyutl -encrypt -pubin -inkey "$W/rsa.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$W/secret" -out "$W/ct" 2>/dev/null
    extra=(--hash-algorithm SHA256 --mgf MGF1-SHA256)
  else
    openssl pkeyutl -encrypt -pubin -inkey "$W/rsa.pem" -pkeyopt rsa_padding_mode:pkcs1 -in "$W/secret" -out "$W/ct" 2>/dev/null; extra=()
  fi
  out="$(p11l --decrypt --mechanism "$mech" "${extra[@]}" --id "$ID_RSA" -i "$W/ct" -o "$W/pt" 2>&1)"; rc=$?; log "$mech: $out"
  if [ "$rc" = 0 ] && cmp -s "$W/secret" "$W/pt"; then P "$mech: decrypted on the token, exact round trip"; done_rsa=1
  else log "$mech not usable: $(tail -1 <<< "$out")"; printf '  (%s: %s)\n' "$mech" "$(tail -1 <<< "$out")"; fi
done
[ "$done_rsa" = 1 ] || F "no RSA decryption mechanism worked"

hdr "6  new session and pcscd restart: the keys survive, re-login works"
again(){ printf 'again %s' "$1" > "$W/m2"; openssl dgst -sha256 -binary "$W/m2" > "$W/m2.h"
  p11l --sign --mechanism ECDSA --id "$ID_EC" --signature-format openssl -i "$W/m2.h" -o "$W/m2.sig" >/dev/null 2>&1 \
  && openssl dgst -sha256 -verify "$W/ec.pem" -signature "$W/m2.sig" "$W/m2" >/dev/null 2>&1; }
again session && P "a new process re-logs in and signs" || F "new session failed"
if sudo -n systemctl restart pcscd 2>/dev/null; then
  sleep 3; SLOT="$(slot_of)"
  [ -n "$SLOT" ] && again restart && P "after a pcscd restart the token is found again by serial and signs" || F "after pcscd restart: slot '${SLOT}'"
else echo "  (pcscd restart skipped: no passwordless sudo)"; log "pcscd restart skipped"; fi

hdr "7  cleanup"
for id in "$ID_EC" "$ID_RSA"; do
  p11l --delete-object --type privkey --id "$id" >/dev/null 2>&1; p11l --delete-object --type pubkey --id "$id" >/dev/null 2>&1
done
left="$(p11l --list-objects 2>&1 | grep -cE "ID: *($ID_EC|$ID_RSA)")"
[ "$left" = 0 ] && P "the test keys are deleted" || F "$left test object(s) remain"

echo; echo "pkcs11-contract $SERIAL: $pass passed, $fail failed (evidence: $EVID)"; log "RESULT $pass passed, $fail failed"
[ "$fail" -eq 0 ]
