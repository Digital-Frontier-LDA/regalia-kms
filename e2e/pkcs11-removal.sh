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
#
#   exit 0 all passed; 1 a check failed; 2 the drill could not run; 3 a call hung (its bound ended it): what that
#   call was to measure is NOT measured, whatever passed or failed around it (#684)
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
# Not exported (#225): the PIN reaches only the gated login that uses it (p11l), and the log's redaction on fd 3.
Q_PIN="$HSM_USER_PIN"; unset HSM_USER_PIN

USBDEV=""   # resolved from the token itself below, once its slot is known
UTC="$(date -u +%Y%m%dT%H%M%SZ)"; EVID="${EVIDENCE_DIR:-.}/evidence-removal-$SERIAL-$UTC.log"
W="$(mktemp -d)"
# A BENCH-SAFE OpenSC. These suites never test the YubiKey, but OpenSC's enumeration leaves its PIV applet
# selected, so a concurrent OpenPGP login by another process lands on PIV and spends PIV PIN tries (three
# were spent that way on 2026-10-02). Unless the caller set OPENSC_CONF, the YubiKey's reader is ignored.
if [ -z "${OPENSC_CONF:-}" ]; then
  IGN="$(python3 -I -c 'import sys; print(", ".join("\"%s\"" % n.strip().replace("\"", "") for n in sys.argv[1].split(",") if n.strip()) or "\"__none__\"")' "${HSM_IGNORE_READERS:-Yubico}")"
  printf 'app default {\n  ignored_readers = %s;\n}\n' "$IGN" > "$W/opensc.conf"
  export OPENSC_CONF="$W/opensc.conf"; OWN_OPENSC_CONF=1
fi
pass=0; fail=0; hungs=0
# Literal redaction, the PIN read from the environment by Python: never on any command line (a sed
# program would carry it in argv) and never interpreted as regex syntax.
log(){ printf '%s\n' "$*" | python3 -I -c 'import os, sys; p = os.fdopen(3).read().rstrip("\n"); t = sys.stdin.read(); sys.stdout.write(t.replace(p, "<pin>") if p else t)' 3<<< "$Q_PIN" >> "$EVID"; }
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; log "PASS $1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; log "FAIL $1"; fail=$((fail+1)); }
# A third outcome, never a FAIL (#684): an operator must not read "it hung" as "the removal did not interrupt it"
H(){ printf '  \033[33mHUNG/ERROR\033[0m %s\n' "$1"; log "HUNG/ERROR $1"; hungs=$((hungs+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; log "### $1"; }
# The kernel's own disconnect/reconnect (USB "authorized" 0/1): a real remove then add, which pcscd's
# hotplug sees. A driver unbind/bind does not emit an add event, so pcscd never re-detects the reader:
# that tests pcscd, not the token.
remove(){ echo 0 | sudo tee "/sys/bus/usb/devices/$USBDEV/authorized" >/dev/null; log "removed $USBDEV at $(date -u +%T.%N)"; }
restore(){ [ -n "$USBDEV" ] || return 0; echo 1 | sudo tee "/sys/bus/usb/devices/$USBDEV/authorized" >/dev/null 2>&1; log "restored $USBDEV at $(date -u +%T.%N)"; }
ID_EC=""; ID_RSA=""; CREATED=()
# On any exit: the token back on the bus, then its test keys deleted (best effort), then the temp dir.
cleanup_keys(){ local id; wait_back 2>/dev/null || return 0; for id in "${CREATED[@]}"; do
  p11l --delete-object --type privkey --id "$id" >/dev/null 2>&1; p11l --delete-object --type pubkey --id "$id" >/dev/null 2>&1; done; }
trap 'restore; cleanup_keys; rm -rf "$W"' EXIT

# Every token call is bounded by lib/bounded.py (#684), not timeout(1): its -k reaches the whole process group only
# with GNU coreutils (uutils' timeout signals the tool alone, and a forked child outlives the bound). bounded.py sends
# SIGTERM to the tool's process group, and KILL_GRACE s later SIGKILL if anything is left (status 124, or 137).
KILL_GRACE=5
bounded(){ python3 -I "$(dirname "$0")/lib/bounded.py" "$1" "$KILL_GRACE" "${@:2}"; }
# A call its bound ended is an ERROR, never a negative answer (#684): a hung listing prints no slot, which reads
# as "the token is gone" and would make a hang a silent PASS. Listings return HUNG for it, and checks fail on it.
HUNG=3
hung(){ [ "$1" = 124 ] || [ "$1" = 137 ]; }
# listed takes the PIPESTATUS of "bounded … | python3 …": HUNG if the bound ended the listing, else the parser's status
listed(){ hung "$1" && return "$HUNG"; return "$2"; }
slot_of(){ bounded 30 pkcs11-tool --module "$MODULE" -L 2>/dev/null | python3 -I -c '
import re, sys
serial = sys.argv[1]; slot = None; hits = []
for line in sys.stdin:
    m = re.match(r"Slot (\d+) \((0x[0-9a-f]+)\)", line)
    if m: slot = m.group(2)
    if "serial num" in line and line.split(":", 1)[1].strip() == serial: hits.append(slot)
print(hits[0] if len(hits) == 1 else "")' "$SERIAL"; listed "${PIPESTATUS[@]}"; }
wait_back(){ local i; for i in $(seq 1 30); do SLOT="$(slot_of)"; [ -n "$SLOT" ] && return 0; sleep 1; done; return 1; }
# EVERY LOGIN IS GATED ON WHAT IS IN THE SLOT NOW (review of #152): slot $SLOT must hold the token with
# serial $SERIAL, no other slot may hold that serial, and under the suite's own isolated config it must
# be the ONLY slot. During a removal the check fails and no PIN is sent; a reader that arrived later and
# took this slot ID fails it too. Residual: the token removed AND another arriving in the milliseconds
# between this check and pkcs11-tool's own login. Every call is bounded (bounded.py: 30 s, then SIGKILL).
target_ok(){ bounded 30 pkcs11-tool --module "$MODULE" -L 2>/dev/null | python3 -I -c '
import re, sys
slot, serial, isolated = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
cur, slots, hits = None, 0, []
for line in sys.stdin:
    m = re.match(r"Slot \d+ \((0x[0-9a-f]+)\)", line)
    if m:
        cur = m.group(1); slots += 1
    elif "serial num" in line and line.split(":", 1)[1].strip() == serial:
        hits.append(cur)
ok = hits == [slot] and (slots == 1 or not isolated)
sys.exit(0 if ok else 1)' "$SLOT" "$SERIAL" "${OWN_OPENSC_CONF:-0}"; listed "${PIPESTATUS[@]}"; }
p11(){ bounded 60 pkcs11-tool --module "$MODULE" --slot "$SLOT" "$@"; }
p11l(){ target_ok || { [ $? = "$HUNG" ] && { echo "p11l: the slot listing hung: no login, no PIN" >&2; return 124; }
    echo "p11l: slot $SLOT does not hold $SERIAL alone right now: no login, no PIN" >&2; return 97
  }
  REGALIA_Q_PIN="$Q_PIN" p11 --login --pin env:REGALIA_Q_PIN "$@"; }
SLOT="$(slot_of)"; [ -n "$SLOT" ] || die "no single token with serial $SERIAL"
# ONE READER ONLY from here on (e2e/lib/opensc_isolate.py): another token can no longer take this
# token's slot ID when its reader disappears, and OpenSC stops probing the other cards.
if [ "${OWN_OPENSC_CONF:-0}" = 1 ]; then
  HSM_IGNORE_READERS="${HSM_IGNORE_READERS:-Yubico}" python3 -Es "$(dirname "$0")/lib/opensc_isolate.py" "$SLOT" "$W/opensc.conf" "$MODULE" >/dev/null \
    || die "cannot isolate this token's reader in OpenSC"
  SLOT="$(slot_of)"; [ -n "$SLOT" ] || die "the token is not visible after isolating its reader"
  [ "$(bounded 30 pkcs11-tool --module "$MODULE" -L 2>/dev/null | grep -c '^Slot')" = 1 ] || die "more than one slot is visible after isolation"
fi
# The USB device to remove is the one BEHIND THIS TOKEN: the serial pcscd puts in the slot's reader
# name (the last parenthesised group, from the device's iSerialNumber), matched to exactly one device
# in sysfs. A default vendor:product once removed the Nitrokey while the Pico was under test.
USB_SERIAL="$(bounded 30 pkcs11-tool --module "$MODULE" -L 2>/dev/null | python3 -I -c '
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
  p11l --sign --mechanism ECDSA --id "$ID_EC" --signature-format openssl -i "$W/h$1" -o "$W/s$1" 2>>"$W/sign.err" >/dev/null; }
# A stream's calls: done (0), not attempted (97, the gate found no token), hung (124/137: the bound ended the call),
# failed in flight (anything else). A hung call is no outcome at all (#684): it feeds neither verdict. Any hung call
# makes the section HUNG/ERROR (H), not a FAIL, and the run exits 3.
stream_line(){ if hung "$1"; then echo "hung $2"; else case $1 in 0) echo "ok $2";; 97) echo "skip $2";; *) echo "err $2";; esac; fi; }
stream_verdict(){ local ok er sk hu; ok=$(grep -c '^ok' "$1"); er=$(grep -c '^err' "$1"); sk=$(grep -c '^skip' "$1"); hu=$(grep -c '^hung' "$1")
  if [ "$hu" -gt 0 ]; then H "$hu call(s) in the $2 hung (their bound ended them): interruption not measured"
  elif [ "$ok" -gt 0 ] && [ $((er + sk)) -gt 0 ]; then P "the removal interrupted the $2 ($ok done, $er failed in flight, $sk not attempted)"
  else F "both outcomes are needed in the $2: $ok done, $er failed in flight, $sk not attempted"; fi; }
log "device $SERIAL usb $USBDEV module $MODULE $(opensc-tool --info 2>&1 | head -1)"

# The NEGATIVE checks: each passes only on an answer the tool gave, never on a call its bound ended (#684). A hung
# call is HUNG/ERROR (H): neither a pass nor a failure.
gone_while_removed(){ local s; s="$(slot_of)"; case $? in
    "$HUNG") H "the slot listing hung while the token was removed: 'gone' not measured";;
    *) [ -z "$s" ] && P "the token is gone while removed" || F "the token is still listed while removed";; esac; }
absent_read_fails(){ local out rc; out="$(p11 --read-object --type pubkey --id "$ID_EC" -o "$W/px" 2>&1)"; rc=$?
  log "no-login read without token (slot $STALE): rc=$rc $out"
  if hung "$rc"; then H "the read on the absent token's slot hung (rc=$rc): its failure not measured"
  elif [ "$rc" != 0 ] && [ ! -s "$W/px" ]; then P "the PKCS#11 layer finds nothing on the absent token's slot (no fallback; no PIN involved)"
  else F "a read on the absent token's slot returned data"; fi; }
absent_sign_fails(){ local out rc; out="$(p11l --sign --mechanism ECDSA --id "$ID_EC" -i "$W/h1" -o "$W/sx" 2>&1)"; rc=$?
  log "startup without token (slot $STALE, empty): rc=$rc $out"
  if hung "$rc"; then H "the sign on the absent token's slot hung (rc=$rc): its failure not measured"
  elif [ "$rc" != 0 ] && [ ! -s "$W/sx" ] && ! grep -q 'CKR_PIN' <<< "$out"; then
    P "an operation with the token absent fails outright (no fallback, no output, no PIN presented)"
  else F "an operation with the token absent did not fail cleanly: $(tail -1 <<< "$out")"; fi; }

hdr "1  idle removal"
remove; sleep 2
gone_while_removed
restore; wait_back && P "restored and found again by serial (slot $SLOT)" || F "not back after restore"
same_keys && P "the same keys are there" || F "keys changed or missing after idle removal"

hdr "2  removal during a stream of signatures"
# TIME-BOUNDED STREAMS: operations are paced over 15 s so the stream straddles the 3 s removal whatever one
# operation costs (~2.6 s with one reader visible, ~20 s when OpenSC probed every card; a failure can return
# at once). The last error line of each failure is kept for the evidence.
( end=$((SECONDS+15)); i=0; while [ "$SECONDS" -lt "$end" ]; do i=$((i+1))
    sign_once "$i"; stream_line "$?" "$i"; sleep 0.5; done ) > "$W/stream" 2>&1 &
sp=$!; sleep 3; remove; sleep 3; restore; wait "$sp"
ok=$(grep -c '^ok' "$W/stream"); log "stream: $(tr '\n' ' ' < "$W/stream")"
[ -s "$W/sign.err" ] && log "first signing error: $(head -1 "$W/sign.err")"
bad=0; for i in $(sed -n 's/^ok //p' "$W/stream"); do openssl dgst -sha256 -verify "$W/ec.pem" -signature "$W/s$i" "$W/m$i" >/dev/null 2>&1 || bad=$((bad+1)); done
# What was SEEN: done, failed in flight (the token went away during the call), not attempted (the gate
# found no token and sent nothing). A removal needs some done and some that did not complete.
stream_verdict "$W/stream" "stream"
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
  ( end=$((SECONDS+15)); i=0; while [ "$SECONDS" -lt "$end" ]; do i=$((i+1))
      p11l --decrypt "${MECH[@]}" --id "$ID_RSA" -i "$W/ct" -o "$W/d$i" 2>>"$W/decrypt.err" >/dev/null
      stream_line "$?" "$i"
      sleep 0.5; done ) > "$W/dstream" 2>&1 &
  dp=$!; sleep 3; remove; sleep 3; restore; wait "$dp"
  ok=$(grep -c '^ok' "$W/dstream"); log "decrypt stream (${MECH[1]}): $(tr '\n' ' ' < "$W/dstream")"
  [ -s "$W/decrypt.err" ] && log "first decryption error: $(head -1 "$W/decrypt.err")"
  bad=0; for i in $(sed -n 's/^ok //p' "$W/dstream"); do cmp -s "$W/pt" "$W/d$i" || bad=$((bad+1)); done
  stream_verdict "$W/dstream" "decryptions"
  [ "$bad" = 0 ] && P "every decryption reported as done is exact ($ok of $ok)" || F "$bad decryption(s) reported done are wrong"
  wait_back && p11l --decrypt "${MECH[@]}" --id "$ID_RSA" -i "$W/ct" -o "$W/dafter" >/dev/null 2>&1 && cmp -s "$W/pt" "$W/dafter" \
    && P "after reinsertion, decryption is exact again" || F "no exact decryption after reinsertion"
  same_keys && P "the same keys are there" || F "keys changed after removal during decryption"
else
  log "section 3 skipped its stream: no RSA mechanism decrypts (already counted as a failure)"
fi

hdr "4  startup without the token"
# THE PIN GOES TO THIS TOKEN OR TO NOTHING. This step once logged in by a hard-coded token LABEL;
# with the token under test removed, that label matched ANOTHER token on the bench, which was handed
# this token's PIN and spent a try (2026-10-02). It now does what the daemon does: the token is
# looked for by serial (absent), and the operation is attempted on the removed token's own slot ID,
# which must hold no token at all, so no card can receive the PIN. If any token sits in that slot,
# the attempt is not made.
STALE="$SLOT"
remove; sleep 2
slot_has_token(){ bounded 30 pkcs11-tool --module "$MODULE" -L 2>/dev/null | python3 -I -c '
import re, sys
want, cur, hit = sys.argv[1], None, False
for line in sys.stdin:
    m = re.match(r"Slot \d+ \((0x[0-9a-f]+)\)", line)
    if m:
        cur = m.group(1)
    elif cur == want and "token label" in line:
        hit = True
sys.exit(0 if hit else 1)' "$1"; listed "${PIPESTATUS[@]}"; }
# Only a slot both listings ANSWERED for (the token not listed, the slot holding nothing) is tried: a hung
# listing says nothing about what is in the slot, so it gates the attempt off like a token found there.
startup_without_token(){ local listed listed_rc held
  listed="$(slot_of)"; listed_rc=$?
  slot_has_token "$STALE"; held=$?
  if [ "$listed_rc" = "$HUNG" ] || [ "$held" = "$HUNG" ]; then
    H "a slot listing hung after the removal: startup without the token not measured"
  elif [ -n "$listed" ]; then
    F "the token is still listed while removed: no startup test"
  elif [ "$held" = 0 ]; then
    F "slot $STALE holds another token after the removal: not presenting this token's PIN to it"
  else
    # The PKCS#11 layer itself, with NO login and therefore no PIN: reading the key's public object on the
    # removed token's slot must fail and produce nothing (no fallback to another token).
    absent_read_fails
    absent_sign_fails
  fi; }
startup_without_token
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

result(){ echo; echo "pkcs11-removal $SERIAL: $pass passed, $fail failed, $hungs hung (evidence: $EVID)"; log "RESULT $pass passed, $fail failed, $hungs hung"; [ "$hungs" -eq 0 ] || return 3; [ "$fail" -eq 0 ]; }
result
