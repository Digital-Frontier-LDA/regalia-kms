#!/usr/bin/env bash
# pkcs11-removal.sh — what an HSM does when it disappears mid-use (#62, PoC 2.3), by unbinding its USB
# device inside this machine (USB deauthorize/authorize: a guest-level removal; a physical pull by the hardware operator is the
# witness step). Staging tokens only.
#
#   sudo -v && HSM_PIN_FILE=~/.config/regalia-qual/DENK0404144.pins e2e/pkcs11-removal.sh --serial DENK0404144
#
#   1  idle: removed and restored while nothing runs; the token comes back, found by serial
#   2  during signing: a stream of ECDSA signatures; the token is removed mid-stream. Every signature
#      that was reported done must verify; nothing fails "successfully"; signing resumes after restore
#   3  during decryption: the same with RSA decryptions, each checked against the plaintext
#   4  startup without the token: operations fail outright (no fallback), then work once it is back
#   5  shared state: the same key (same public key) is there after every removal; then it is deleted
set -uo pipefail
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
SERIAL=""; VIDPID="${HSM_USB_ID:-}"
STAGING_SERIALS="${STAGING_SERIALS:-DENK0404144 DENK0404380 DENK0404547 ESP2202E14A ESP41D722E2}"
while [ $# -gt 0 ]; do case "$1" in
  --serial) SERIAL="${2:?}"; shift 2;; --module) MODULE="${2:?}"; shift 2;; --usb-id) VIDPID="${2:?}"; shift 2;;
  -h|--help) sed -n '2,16p' "$0"; exit 0;; *) echo "pkcs11-removal: unknown argument $1" >&2; exit 2;; esac; done
die(){ echo "pkcs11-removal: $*" >&2; exit 2; }
[ -n "$SERIAL" ] || die "--serial is required"
case " $STAGING_SERIALS " in *" $SERIAL "*) ;; *) die "$SERIAL is not a staging token: refusing";; esac
sudo -n true 2>/dev/null || die "needs passwordless sudo (USB unbind/bind)"
[ -z "${HSM_PIN_FILE:-}" ] || HSM_USER_PIN="$(sed -n 's/^HSM_USER_PIN=//p' "$HSM_PIN_FILE" | head -1)"
[ -n "${HSM_USER_PIN:-}" ] || die "no user PIN (HSM_PIN_FILE or HSM_USER_PIN)"
export REGALIA_Q_PIN="$HSM_USER_PIN"; unset HSM_USER_PIN

USBDEV=""   # resolved from the token itself below, once its slot is known
UTC="$(date -u +%Y%m%dT%H%M%SZ)"; EVID="${EVIDENCE_DIR:-.}/evidence-removal-$SERIAL-$UTC.log"
W="$(mktemp -d)"
pass=0; fail=0
# Literal redaction, the PIN read from the environment by Python: never on any command line (a sed
# program would carry it in argv) and never interpreted as regex syntax.
log(){ printf '%s\n' "$*" | python3 -c 'import os, sys; p = os.environ.get("REGALIA_Q_PIN", ""); t = sys.stdin.read(); sys.stdout.write(t.replace(p, "<pin>") if p else t)' >> "$EVID"; }
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; log "PASS $1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; log "FAIL $1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; log "### $1"; }
# The kernel's own disconnect/reconnect (USB "authorized" 0/1): a real remove then add, which pcscd's
# hotplug sees. A driver unbind/bind does not emit an add event, so pcscd never re-detects the reader:
# that tests pcscd, not the token.
remove(){ echo 0 | sudo tee "/sys/bus/usb/devices/$USBDEV/authorized" >/dev/null; log "removed $USBDEV at $(date -u +%T.%N)"; }
restore(){ [ -n "$USBDEV" ] || return 0; echo 1 | sudo tee "/sys/bus/usb/devices/$USBDEV/authorized" >/dev/null 2>&1; log "restored $USBDEV at $(date -u +%T.%N)"; }
ID_EC=""; ID_RSA=""; CREATED=()
# On any exit: the token back on the bus, then its test keys deleted (best effort), then the temp dir.
cleanup_keys(){ local id; wait_back 2>/dev/null; for id in "${CREATED[@]}"; do
  p11l --delete-object --type privkey --id "$id" >/dev/null 2>&1; p11l --delete-object --type pubkey --id "$id" >/dev/null 2>&1; done; }
trap 'restore; cleanup_keys; rm -rf "$W"' EXIT

slot_of(){ pkcs11-tool --module "$MODULE" -L 2>/dev/null | python3 -c '
import re, sys
serial = sys.argv[1]; slot = None; hits = []
for line in sys.stdin:
    m = re.match(r"Slot (\d+) \((0x[0-9a-f]+)\)", line)
    if m: slot = m.group(2)
    if "serial num" in line and line.split(":", 1)[1].strip() == serial: hits.append(slot)
print(hits[0] if len(hits) == 1 else "")' "$SERIAL"; }
wait_back(){ local i; for i in $(seq 1 30); do SLOT="$(slot_of)"; [ -n "$SLOT" ] && return 0; sleep 1; done; return 1; }
p11(){ pkcs11-tool --module "$MODULE" --slot "$SLOT" "$@"; }
p11l(){ p11 --login --pin env:REGALIA_Q_PIN "$@"; }
SLOT="$(slot_of)"; [ -n "$SLOT" ] || die "no single token with serial $SERIAL"
# The USB device to remove is the one BEHIND THIS TOKEN: the serial pcscd puts in the slot's reader
# name (the last parenthesised group, from the device's iSerialNumber), matched to exactly one device
# in sysfs. A default vendor:product once removed the Nitrokey while the Pico was under test.
USB_SERIAL="$(pkcs11-tool --module "$MODULE" -L 2>/dev/null | python3 -c '
import re, sys
slot = sys.argv[1]
for line in sys.stdin:
    m = re.match(r"Slot \d+ \((0x[0-9a-f]+)\): (.*)$", line)
    if m and m.group(1) == slot:
        groups = re.findall(r"\(([^()]*)\)", m.group(2))
        print(groups[-1].strip() if groups else "")
        break' "$SLOT")"
[ -n "$USB_SERIAL" ] || die "the reader of slot $SLOT names no USB serial: cannot tell which device to remove"
mapfile -t devs < <(for d in /sys/bus/usb/devices/*; do
  [ "$(tr -d '[:space:]' 2>/dev/null < "$d/serial")" = "$(tr -d '[:space:]' <<< "$USB_SERIAL")" ] && basename "$d"; done)
[ "${#devs[@]}" = 1 ] || die "need exactly one USB device with serial $USB_SERIAL, found ${#devs[@]}"
USBDEV="${devs[0]}"
if [ -n "$VIDPID" ]; then   # optional cross-check (--usb-id / HSM_USB_ID)
  [ "$(cat "/sys/bus/usb/devices/$USBDEV/idVendor"):$(cat "/sys/bus/usb/devices/$USBDEV/idProduct")" = "$VIDPID" ] \
    || die "the device behind $SERIAL ($USBDEV) is not $VIDPID"
fi
# Fresh ids: refuse any id already on the token (PKCS#11 does not make CKA_ID unique), and remember
# only the objects THIS run created, so cleanup can never delete a key that was there before.
# An id counts as free only against a listing that SUCCEEDED (an absent token lists nothing).
free_id(){ local prefix="$1" id listing; listing="$(p11l --list-objects 2>/dev/null)" || return 1
  for _ in 1 2 3 4 5; do
    id="$(printf '%s%06x' "$prefix" $((RANDOM*RANDOM % 16777215)))"
    grep -qiE "ID: *$id\b" <<< "$listing" || { echo "$id"; return 0; }
  done; return 1; }
ID_EC="$(free_id 7d)" && ID_RSA="$(free_id 7c)" || die "no free object id on the token"
p11l --keypairgen --key-type EC:prime256v1 --id "$ID_EC" --label "q62r-ec-$UTC" --usage-sign >/dev/null 2>&1 && CREATED+=("$ID_EC") || die "EC keygen failed"
p11l --keypairgen --key-type rsa:2048 --id "$ID_RSA" --label "q62r-rsa-$UTC" --usage-decrypt >/dev/null 2>&1 && CREATED+=("$ID_RSA") || die "RSA keygen failed"
p11 --read-object --type pubkey --id "$ID_EC" -o "$W/ec.der" >/dev/null 2>&1; openssl pkey -pubin -inform DER -in "$W/ec.der" -out "$W/ec.pem"
p11 --read-object --type pubkey --id "$ID_RSA" -o "$W/rsa.der" >/dev/null 2>&1; openssl pkey -pubin -inform DER -in "$W/rsa.der" -out "$W/rsa.pem"
EC_FP="$(sha256sum < "$W/ec.der")"; RSA_FP="$(sha256sum < "$W/rsa.der")"
same_keys(){ p11 --read-object --type pubkey --id "$ID_EC" -o "$W/ec2.der" >/dev/null 2>&1 && p11 --read-object --type pubkey --id "$ID_RSA" -o "$W/rsa2.der" >/dev/null 2>&1 \
  && [ "$(sha256sum < "$W/ec2.der")" = "$EC_FP" ] && [ "$(sha256sum < "$W/rsa2.der")" = "$RSA_FP" ]; }
sign_once(){ printf 'm %s' "$1" > "$W/m$1"; openssl dgst -sha256 -binary "$W/m$1" > "$W/h$1"
  p11l --sign --mechanism ECDSA --id "$ID_EC" --signature-format openssl -i "$W/h$1" -o "$W/s$1" >/dev/null 2>&1; }
log "device $SERIAL usb $USBDEV module $MODULE $(opensc-tool --info 2>&1 | head -1)"

hdr "1  idle removal"
remove; sleep 2
[ -z "$(slot_of)" ] && P "the token is gone while removed" || F "the token is still listed while removed"
restore; wait_back && P "restored and found again by serial (slot $SLOT)" || F "not back after restore"
same_keys && P "the same keys are there" || F "keys changed or missing after idle removal"

hdr "2  removal during a stream of signatures"
( for i in $(seq 1 40); do if sign_once "$i"; then echo "ok $i"; else echo "err $i"; fi; done ) > "$W/stream" 2>&1 &
sp=$!; sleep 3; remove; sleep 3; restore; wait "$sp"
ok=$(grep -c '^ok' "$W/stream"); er=$(grep -c '^err' "$W/stream"); log "stream: $ok ok, $er err"
bad=0; for i in $(sed -n 's/^ok //p' "$W/stream"); do openssl dgst -sha256 -verify "$W/ec.pem" -signature "$W/s$i" "$W/m$i" >/dev/null 2>&1 || bad=$((bad+1)); done
[ "$ok" -gt 0 ] && [ "$er" -gt 0 ] && P "the removal interrupted the stream ($ok done, $er failed)" || F "the stream needs both outcomes: $ok done, $er failed"
[ "$bad" = 0 ] && P "every signature reported as done verifies ($ok of $ok)" || F "$bad signature(s) reported done do not verify"
wait_back && sign_once after && openssl dgst -sha256 -verify "$W/ec.pem" -signature "$W/safter" "$W/mafter" >/dev/null 2>&1 \
  && P "signing resumes after restore" || F "signing does not resume"
same_keys && P "the same keys are there" || F "keys changed after removal during signing"

hdr "3  removal during a stream of decryptions"
head -c 32 /dev/urandom > "$W/pt"
# A mechanism PROVEN to work before the removal (OAEP first, PKCS#1 v1.5 otherwise), so a stream in
# which nothing ever decrypts cannot pass this section vacuously.
MECH=(); for m in OAEP PKCS; do
  if [ "$m" = OAEP ]; then
    openssl pkeyutl -encrypt -pubin -inkey "$W/rsa.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$W/pt" -out "$W/ct" 2>/dev/null
    try=(--mechanism RSA-PKCS-OAEP --hash-algorithm SHA256 --mgf MGF1-SHA256)
  else
    openssl pkeyutl -encrypt -pubin -inkey "$W/rsa.pem" -pkeyopt rsa_padding_mode:pkcs1 -in "$W/pt" -out "$W/ct" 2>/dev/null
    try=(--mechanism RSA-PKCS)
  fi
  if p11l --decrypt "${try[@]}" --id "$ID_RSA" -i "$W/ct" -o "$W/d0" >/dev/null 2>&1 && cmp -s "$W/pt" "$W/d0"; then MECH=("${try[@]}"); break; fi
done
[ "${#MECH[@]}" -gt 0 ] && P "before the removal, ${MECH[1]} decrypts exactly" || F "no RSA mechanism decrypts before the removal: section 3 cannot test anything"
if [ "${#MECH[@]}" -gt 0 ]; then
  ( for i in $(seq 1 30); do
      if p11l --decrypt "${MECH[@]}" --id "$ID_RSA" -i "$W/ct" -o "$W/d$i" >/dev/null 2>&1; then echo "ok $i"; else echo "err $i"; fi
    done ) > "$W/dstream" 2>&1 &
  dp=$!; sleep 3; remove; sleep 3; restore; wait "$dp"
  ok=$(grep -c '^ok' "$W/dstream"); er=$(grep -c '^err' "$W/dstream"); log "decrypt stream (${MECH[1]}): $ok ok, $er err"
  bad=0; for i in $(sed -n 's/^ok //p' "$W/dstream"); do cmp -s "$W/pt" "$W/d$i" || bad=$((bad+1)); done
  [ "$ok" -gt 0 ] && [ "$er" -gt 0 ] && P "the removal interrupted the decryptions ($ok done, $er failed)" || F "the stream needs both outcomes: $ok done, $er failed"
  [ "$bad" = 0 ] && P "every decryption reported as done is exact ($ok of $ok)" || F "$bad decryption(s) reported done are wrong"
  wait_back && p11l --decrypt "${MECH[@]}" --id "$ID_RSA" -i "$W/ct" -o "$W/dafter" >/dev/null 2>&1 && cmp -s "$W/pt" "$W/dafter" \
    && P "after reinsertion, decryption is exact again" || F "no exact decryption after reinsertion"
  same_keys && P "the same keys are there" || F "keys changed after removal during decryption"
else
  log "section 3 skipped its stream: no RSA mechanism decrypts (already counted as a failure)"
fi

hdr "4  startup without the token"
remove; sleep 2
out="$(pkcs11-tool --module "$MODULE" --login --pin env:REGALIA_Q_PIN --token-label regalia-staging --sign --mechanism ECDSA --id "$ID_EC" -i "$W/h1" -o "$W/sx" 2>&1)"; rc=$?; log "startup without token: rc=$rc $out"
[ "$rc" != 0 ] && [ ! -s "$W/sx" ] && P "an operation with the token absent fails outright (no fallback, no output)" || F "an operation succeeded without the token"
restore; wait_back && sign_once start && P "it works once the token is back" || F "no recovery after restore"

hdr "5  cleanup"
for id in "${CREATED[@]}"; do p11l --delete-object --type privkey --id "$id" >/dev/null 2>&1; p11l --delete-object --type pubkey --id "$id" >/dev/null 2>&1; done
# Only a listing that SUCCEEDED can show the keys are gone: an absent token lists nothing and would
# otherwise read as "deleted" (seen on the bench: a run whose token had vanished reported its keys gone).
if listing="$(p11l --list-objects 2>&1)"; then
  left="$(grep -cE "ID: *($ID_EC|$ID_RSA)" <<< "$listing")"
  [ "$left" = 0 ] && P "the test keys are deleted" || F "$left test object(s) remain"
else
  F "cannot list the token to confirm the test keys are gone: $(tail -1 <<< "$listing")"
fi

echo; echo "pkcs11-removal $SERIAL: $pass passed, $fail failed (evidence: $EVID)"; log "RESULT $pass passed, $fail failed"
[ "$fail" -eq 0 ]
