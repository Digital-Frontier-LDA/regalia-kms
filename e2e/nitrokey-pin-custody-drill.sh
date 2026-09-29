#!/usr/bin/env bash
# nitrokey-pin-custody-drill.sh — regalia#20 criterion 4 for the NITROKEY: rotation, host rebuild,
# token outage, replacement and total recovery of the UNATTENDED user PIN. ADR-0002 D2 keeps it as a
# systemd encrypted service credential, and D4 (no PKA at runtime) makes that the production design
# for the Nitrokey, not an interim. The twin of yubikey-pin-custody-drill.sh.
#
#   REGALIA_CEREMONY_DIR=<regalia-ceremony> HSM_STAGING_REGISTRY_FILE=<regalia>/tools/hsm-staging-registry.json \
#   NK_PIN_PRIMARY=… [NK_PIN_REPLACEMENT=…] \
#     sudo -v && e2e/nitrokey-pin-custody-drill.sh <primary serial> [replacement serial]
#
# The daemon half is TestNitrokeyPINCustodyDrill through the PRODUCTION driver
# (NewPKCS11DriverWithProbes), run as a TRANSIENT SYSTEMD SERVICE with LoadCredentialEncrypted=, so
# the PIN reaches pin.LockedFileSource exactly as in production. PINs travel only on stdin and in the
# environment of pkcs11-tool (--pin env:…); never on argv or in the transcript.
#
# NOT DESTRUCTIVE to the card's contents: each card gets one throwaway P-256 key at PKCS#11 ID 0x51
# (refused if that ID is taken) and loses it at the end; its PIN is rotated and put back. On a card
# initialised with RESET RETRY COUNTER OFF (hsm-init-hardened.sh --rrc off) a lost PIN cannot be
# unblocked, so the drill refuses to start unless every card is at 3 tries, spends exactly ONE retry
# on purpose (the stale row), and a correct PIN restores the counter at once.
#
#   R  ROTATION        seal v1 → serve; rotate the card PIN, seal v2; the STALE v1 must spend exactly
#                      one retry and latch; v2 serves and restores the counter
#   H  HOST REBUILD    the host credential key is gone: v2 must not start the service (no PIN
#                      presented); reseal from the RECOVERY KIT (PINs encrypted to a break-glass key)
#   O  OUTAGE          the card is de-authorised on USB: absent, no PIN presented; back → serve
#   Y  REPLACEMENT     (with a replacement serial) another card takes the role, own key and credential
#   T  TOTAL RECOVERY  no host key, recovery kit + break-glass only → reseal on a new host → serve
#
# BENCH SUBSTITUTE, recorded as such: this bench qube has no TPM2, so credentials are sealed with
# systemd's HOST key (--with-key=host). Everything above the sealing primitive is the production path;
# the TPM2 binding (--with-key=tpm2 --tpm2-pcrs=…) is #46's, and deploy/seal-hsm-pin.sh uses it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIMARY="${1:?primary Nitrokey serial}"; REPLACEMENT="${2:-}"
: "${NK_PIN_PRIMARY:?}" "${HSM_STAGING_REGISTRY_FILE:?}" "${REGALIA_CEREMONY_DIR:?}"
[ -z "$REPLACEMENT" ] || : "${NK_PIN_REPLACEMENT:?NK_PIN_REPLACEMENT is required with a replacement serial}"
[ "$PRIMARY" != "$REPLACEMENT" ] || { echo "primary and replacement must be two cards" >&2; exit 2; }
MODULE="${HSM_PKCS11_MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
OBJECT_ID=51
STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-nkpindrill.XXXXXX")"; chmod 700 "$STATE"
LOG="$STATE/transcript.log"
HOSTKEY=/var/lib/systemd/credential.secret
say(){ printf '%s %s\n' "$(date -u +%T)" "$*" | tee -a "$LOG"; }
die(){ say "FAIL: $*"; say "state kept for inspection: $STATE"; exit 1; }
for t in pkcs11-tool opensc-tool systemd-creds systemd-run age age-keygen go python3; do command -v "$t" >/dev/null || die "$t is required"; done
sudo -n true 2>/dev/null || die "needs sudo (systemd-creds and the service run as root); run 'sudo -v' first"
# shellcheck source=/dev/null
. "$REGALIA_CEREMONY_DIR/tools/hsm-reader-select.sh"

pin_of(){ case "$1" in "$PRIMARY") printf '%s' "$NK_PIN_PRIMARY";; "$REPLACEMENT") printf '%s' "${NK_PIN_REPLACEMENT:-}";; esac; }
CARDS="$PRIMARY${REPLACEMENT:+ $REPLACEMENT}"

# ---- the gate: registered staging cards, pinned by C.DevAut ---------------------------------------
for s in $CARDS; do hsm_assert_staging_card "$s" || die "$s is not a registered staging Nitrokey: refusing"; done
# Readers and slots resolve in the MAIN shell: a failed inline lookup would pass "" (= reader 0).
declare -A READER SLOT
for s in $CARDS; do
  READER[$s]="$(hsm_reader_for "$s" 2>/dev/null || true)"; [ -n "${READER[$s]}" ] || die "cannot resolve $s to a PC/SC reader"
  SLOT[$s]="$(hsm_slot_id_for "$s" 2>/dev/null || true)"; [ -n "${SLOT[$s]}" ] || die "PKCS#11 cannot see $s"
done
# The user-PIN counter, read with an empty VERIFY: no attempt is spent.
tries(){ local sw; sw="$(opensc-tool --reader "${READER[$1]}" -s "00 A4 04 00 0B E8 2B 06 01 04 01 81 C3 1F 02 01 00" -s "00 20 00 81" 2>&1 \
          | grep -oE 'SW1=0x[0-9A-F]+, SW2=0x[0-9A-F]+' | tail -1 || true)"
        sed -n 's/SW1=0x63, SW2=0xC\([0-9A-F]\)/\1/p' <<< "$sw"; }
counters(){ local s line="  counters:"; for s in $CARDS; do line="$line $s=$(tries "$s" || true)"; done; say "$line"; }
for s in $CARDS; do [ "$(tries "$s")" = 3 ] || die "$s does not start at 3 user-PIN tries: a drill that starts low cannot measure what it spends"; done
say "cards: $CARDS; state $STATE"

# ---- helpers ------------------------------------------------------------------------------------
p11(){ local card="$1"; shift; PKCS11_PIN="$(pin_of "$card")" pkcs11-tool --module "$MODULE" --slot "${SLOT[$card]}" "$@"; }
change_pin(){ # change_pin <card> <old> <new>
  PKCS11_PIN="$2" NEW_PIN="$3" pkcs11-tool --module "$MODULE" --slot "${SLOT[$1]}" --login --pin env:PKCS11_PIN \
    --change-pin --new-pin env:NEW_PIN >>"$LOG" 2>&1; }
seal(){ sudo systemd-creds encrypt --with-key=host --name="$1" - "$2" 2>>"$LOG" >/dev/null; }
say "building the drill test binary"
go -C "$ROOT" test -c -o "$STATE/drill.test" ./internal/integration >>"$LOG" 2>&1 || die "build"
declare -A PINNED
commission(){ local out; out="$(REGALIA_NKDRILL_PHASE=commission REGALIA_NKDRILL_MODULE="$MODULE" REGALIA_NKDRILL_SERIAL="$1" \
    REGALIA_NKDRILL_OBJECT_ID="$OBJECT_ID" "$STATE/drill.test" -test.count=1 -test.v -test.run '^TestNitrokeyPINCustodyDrill$' 2>&1)"
  PINNED[$1]="$(sed -n 's/.*PUBKEY_SHA256=\(sha256:[0-9a-f]*\).*/\1/p' <<< "$out" | head -1)"
  [ -n "${PINNED[$1]}" ] || { printf '%s\n' "$out" >> "$LOG"; die "could not commission the drill key on $1"; }; }
phase(){ # phase <name> <serial> <credential blob> ; returns the test's status
  local out rc; out="$(sudo systemd-run --quiet --pipe --wait --collect -p LimitMEMLOCK=1M \
      -p "LoadCredentialEncrypted=nk-drill.pin:$3" \
      --setenv=REGALIA_NKDRILL_PHASE="$1" --setenv=REGALIA_NKDRILL_MODULE="$MODULE" --setenv=REGALIA_NKDRILL_SERIAL="$2" \
      --setenv=REGALIA_NKDRILL_OBJECT_ID="$OBJECT_ID" --setenv=REGALIA_NKDRILL_CREDENTIAL=nk-drill.pin \
      --setenv=REGALIA_NKDRILL_PUBKEY_SHA256="${PINNED[$2]}" \
      "$STATE/drill.test" -test.count=1 -test.v -test.run '^TestNitrokeyPINCustodyDrill$' 2>&1)" && rc=0 || rc=$?
  PHASE_RC=$rc
  printf '%s\n' "$out" | grep -E -- '--- (PASS|FAIL|SKIP)|_test.go:|Failed to|credential' | sed 's/^/    /' | tee -a "$LOG"
  grep -q -- "--- PASS: TestNitrokeyPINCustodyDrill" <<< "$out" && [ "$rc" = 0 ]; }
refused_by_systemd(){ [ "$PHASE_RC" = 243 ] && say "  refused by systemd: exit 243 (EXIT_CREDENTIALS), the service never ran"; }
usb_of(){ local d; for d in /sys/bus/usb/devices/*; do grep -q "^$1" "$d/serial" 2>/dev/null && { echo "$d"; return 0; }; done; return 1; }
authorize(){ echo "$2" | sudo tee "$1/authorized" >/dev/null; sleep 3; }

# The recovery kit: every enrolled card's PIN, encrypted to the break-glass recipient. In production
# the break-glass identity is Shamir-split (4-of-6); here it is per run and deleted at the end.
age-keygen -o "$STATE/breakglass.id" 2>/dev/null; chmod 600 "$STATE/breakglass.id"
BG="$(age-keygen -y "$STATE/breakglass.id")"
printf '%s\n%s\n' "$NK_PIN_PRIMARY" "${NK_PIN_REPLACEMENT:-}" | age -r "$BG" -o "$STATE/recovery-kit.age"
kit_pin(){ age -d -i "$STATE/breakglass.id" "$STATE/recovery-kit.age" | sed -n "${1}p" | tr -d '\n'; }
say "recovery kit: the card PINs encrypted to break-glass recipient $BG"

HOSTKEY_EXISTED=0; sudo test -e "$HOSTKEY" && HOSTKEY_EXISTED=1
ROTATED=""; KEYS_MADE=""
restore(){ # always: the card PIN, the drill keys, the host key, USB authorisation
  set +e
  for d in /sys/bus/usb/devices/*; do [ "$(cat "$d/authorized" 2>/dev/null)" = 0 ] && authorize "$d" 1; done
  local keep=0 s
  if [ -n "$ROTATED" ]; then
    if change_pin "$PRIMARY" "$ROTATED" "$NK_PIN_PRIMARY"; then say "restore: $PRIMARY PIN put back"
    else keep=1; say "RESTORE FAILED: $PRIMARY still has the rotated PIN; it is in $STATE/rotated.age, openable with $STATE/breakglass.id"; fi
  fi
  for s in $KEYS_MADE; do
    p11 "$s" --login --pin env:PKCS11_PIN --delete-object --type privkey --id "$OBJECT_ID" >>"$LOG" 2>&1 \
      && say "restore: drill key removed from $s" || { keep=1; say "RESTORE: could not remove the drill key from $s (ID $OBJECT_ID)"; }
  done
  if sudo test -e "$STATE/host-key.orig"; then sudo mv -f "$STATE/host-key.orig" "$HOSTKEY" && say "restore: original host credential key put back"
  elif [ "$HOSTKEY_EXISTED" = 0 ]; then sudo rm -f "$HOSTKEY"; fi
  counters
  rm -f "$STATE/drill.test" "$STATE"/*.cred
  [ "$keep" = 1 ] || rm -f "$STATE/breakglass.id" "$STATE/recovery-kit.age" "$STATE/rotated.age"
}
trap restore EXIT

# ---- the drill key on each card -------------------------------------------------------------------
for s in $CARDS; do
  if p11 "$s" --login --pin env:PKCS11_PIN --list-objects 2>/dev/null | grep -qiE "^\s*ID:\s*$OBJECT_ID\s*$"; then
    die "$s already holds an object with ID $OBJECT_ID: refusing to overwrite it"
  fi
  p11 "$s" --login --pin env:PKCS11_PIN --keypairgen --key-type EC:prime256v1 --id "$OBJECT_ID" --label pin-custody-drill >>"$LOG" 2>&1 \
    || die "could not generate the drill key on $s (is its DKEK import complete?)"
  KEYS_MADE="$KEYS_MADE $s"
  commission "$s"; say "drill key on $s, commissioned ${PINNED[$s]}"
done
counters

# ---- R: ROTATION -----------------------------------------------------------------------------------
say "R1 — seal the primary's PIN (v1) and serve through it"
printf '%s' "$NK_PIN_PRIMARY" | seal nk-drill.pin "$STATE/v1.cred"
phase serve "$PRIMARY" "$STATE/v1.cred" || die "v1 did not serve"; counters
say "R2 — rotate: new PIN on the card, sealed as v2 BEFORE anything restarts"
NEWPIN="$(python3 -c 'import secrets; print("".join(secrets.choice("0123456789") for _ in range(8)))')"
printf '%s' "$NEWPIN" | age -r "$BG" -o "$STATE/rotated.age"   # so a failed run can still restore it
change_pin "$PRIMARY" "$NK_PIN_PRIMARY" "$NEWPIN" || die "PIN change on $PRIMARY"
ROTATED="$NEWPIN"   # only now does the card hold it: set earlier, a failed change would make restore spend a retry
printf '%s' "$ROTATED" | seal nk-drill.pin "$STATE/v2.cred"
[ "$(tries "$PRIMARY")" = 3 ] || die "retry counter not at 3 after the rotation"; counters
say "R3 — the STALE v1 against the rotated card: exactly one retry, then latched"
phase stale "$PRIMARY" "$STATE/v1.cred" || die "stale phase"
[ "$(tries "$PRIMARY")" = 2 ] || die "the stale credential spent $((3 - $(tries "$PRIMARY"))) retries, not exactly one"; counters
say "R4 — v2 installed: serves, and the correct PIN restores the counter"
phase serve "$PRIMARY" "$STATE/v2.cred" || die "v2 did not serve"
[ "$(tries "$PRIMARY")" = 3 ] || die "counter not restored by the correct PIN"; counters

# ---- H: HOST REBUILD -------------------------------------------------------------------------------
say "H1 — the host credential key is gone (a rebuilt host): v2 must not even start the service"
sudo mv "$HOSTKEY" "$STATE/host-key.orig"
if phase serve "$PRIMARY" "$STATE/v2.cred"; then die "DEFECT: a credential sealed to the old host opened on the new one"; fi
refused_by_systemd || die "v2 failed, but not as an undecryptable credential (exit $PHASE_RC): the row proves nothing"
[ "$(tries "$PRIMARY")" = 3 ] || die "a service that could not decrypt its credential spent a retry"; counters
say "H2 — reseal from the recovery kit on the new host → serve"
age -d -i "$STATE/breakglass.id" "$STATE/rotated.age" | seal nk-drill.pin "$STATE/v3.cred"
phase serve "$PRIMARY" "$STATE/v3.cred" || die "the resealed credential did not serve"; counters

# ---- O: OUTAGE -------------------------------------------------------------------------------------
say "O1 — the card is out (de-authorised on USB): absent, no PIN presented; back: serves"
NK="$(usb_of "$PRIMARY")" || die "cannot find $PRIMARY on USB"
authorize "$NK" 0
pkcs11-tool --module "$MODULE" --list-slots 2>/dev/null | grep -q "$PRIMARY" && die "$PRIMARY still visible"
phase absent "$PRIMARY" "$STATE/v3.cred" || die "absent phase"
authorize "$NK" 1; sleep 2
[ "$(tries "$PRIMARY")" = 3 ] || die "the outage spent a retry"
phase serve "$PRIMARY" "$STATE/v3.cred" || die "did not serve after the card came back"; counters

# ---- Y: REPLACEMENT --------------------------------------------------------------------------------
LAST="$PRIMARY"; LAST_PIN_LINE=""
if [ -n "$REPLACEMENT" ]; then
  say "Y1 — the replacement card takes the role with its own key and sealed credential"
  kit_pin 2 | seal nk-drill.pin "$STATE/replacement.cred"
  phase serve "$REPLACEMENT" "$STATE/replacement.cred" || die "the replacement did not serve"; counters
  LAST="$REPLACEMENT"; LAST_PIN_LINE=2
else
  say "Y1 — skipped: no replacement serial given"
fi

# ---- T: TOTAL RECOVERY -----------------------------------------------------------------------------
say "T1 — total loss: host key gone again, recovery kit + break-glass only → reseal on a new host → serve"
sudo rm -f "$HOSTKEY"
if [ -n "$LAST_PIN_LINE" ]; then kit_pin "$LAST_PIN_LINE"; else age -d -i "$STATE/breakglass.id" "$STATE/rotated.age"; fi \
  | seal nk-drill.pin "$STATE/recovered.cred"
phase serve "$LAST" "$STATE/recovered.cred" || die "total recovery did not serve"; counters

say "DRILL PASSED: rotation (stale credential spent exactly one retry, then latched), host rebuild, outage${REPLACEMENT:+, replacement} and total recovery"
say "transcript: $LOG"
