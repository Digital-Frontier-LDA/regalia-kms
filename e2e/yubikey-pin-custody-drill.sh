#!/usr/bin/env bash
# yubikey-pin-custody-drill.sh — regalia#20 acceptance criterion 4 on real YubiKeys: rotation, host
# rebuild, HSM outage, YubiKey replacement and total recovery of the UNATTENDED PIN, which ADR-0002 D2
# keeps as a systemd encrypted service credential. DESTRUCTIVE on the primary card: it rotates the
# card's PIN, spends exactly ONE retry on purpose (the stale-credential row), and puts both back.
#
#   YK_PIN_PRIMARY=… YK_PIN_REPLACEMENT=… HSM_STAGING_REGISTRY_FILE=<regalia>/tools/hsm-staging-registry.json \
#     sudo -v && e2e/yubikey-pin-custody-drill.sh <primary serial> <replacement serial> [nitrokey serial]
#
# The daemon half is TestYubiKeyPINCustodyDrill, run as a TRANSIENT SYSTEMD SERVICE with
# LoadCredentialEncrypted=, so the PIN reaches pin.LockedFileSource exactly as in production: sealed
# at rest, decrypted by systemd into the service's private credentials directory. PINs travel only on
# stdin and through a pty; never on argv, in the environment of a logged command, or in the transcript.
#
# Sequence (every phase is followed by a read of both cards' PIN counters):
#   R  ROTATION         seal v1 → serve; rotate the card PIN and seal v2; the STALE v1 must spend
#                       exactly one retry and latch; v2 must serve (and restores the counter)
#   H  HOST REBUILD     remove the host credential key: v2 must no longer start the service, with no
#                       PIN presented; a new host reseals from the RECOVERY KIT (PINs encrypted to a
#                       break-glass age key) → serve
#   O  OUTAGES          the HSM (Nitrokey) is de-authorised on USB: YubiKey custody must not care →
#                       serve; the YubiKey itself is de-authorised → absent (no PIN presented) → back → serve
#   Y  REPLACEMENT      the replacement token takes the role with its own sealed credential → serve
#   T  TOTAL RECOVERY   no host key, primary token unused, no HSM: recovery kit + break-glass only →
#                       reseal the replacement's PIN on a new host → serve
#
# BENCH SUBSTITUTE, recorded as such: this bench qube has no TPM2, so credentials are sealed with
# systemd's HOST key (--with-key=host) rather than tpm2. Everything above the sealing primitive is
# the production path; the TPM binding itself is #46's.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIMARY="${1:?primary YubiKey serial}"; REPLACEMENT="${2:?replacement YubiKey serial}"; NITROKEY="${3:-}"
: "${YK_PIN_PRIMARY:?}" "${YK_PIN_REPLACEMENT:?}" "${HSM_STAGING_REGISTRY_FILE:?}"
OBJECT="${REGALIA_PINDRILL_OBJECT:-9c}"
STATE="$(mktemp -d "${TMPDIR:-/tmp}/regalia-pindrill.XXXXXX")"; chmod 700 "$STATE"
LOG="$STATE/transcript.log"
HOSTKEY=/var/lib/systemd/credential.secret
say(){ printf '%s %s\n' "$(date -u +%T)" "$*" | tee -a "$LOG"; }
die(){ say "FAIL: $*"; say "state kept for inspection: $STATE"; exit 1; }
for t in ykman systemd-creds systemd-run age age-keygen go python3 openssl; do command -v "$t" >/dev/null || die "$t is required"; done
sudo -n true 2>/dev/null || die "needs sudo (systemd-creds and the service run as root); run 'sudo -v' first"

# ---- the gate: two registered staging YubiKeys, proven by the key in 9A ----------------------------
registered(){ python3 - "$HSM_STAGING_REGISTRY_FILE" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
m = [x for x in d["devices"] if x.get("kind") == "yubikey-piv" and x.get("token_serial") == sys.argv[2] and x.get("role") == "staging"]
print(m[0]["piv_9a_sha256"] if len(m) == 1 else "")
PY
}
for s in "$PRIMARY" "$REPLACEMENT"; do
  want="$(registered "$s")"; [ -n "$want" ] || die "$s is not a registered staging YubiKey: refusing"
  have="$(ykman --device "$s" piv keys export 9a - 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1)"
  [ "$have" = "$want" ] || die "$s: the key in 9A is not the registered one: refusing"
done
[ "$PRIMARY" != "$REPLACEMENT" ] || die "primary and replacement must be two cards"
tries(){ ykman --device "$1" piv info 2>/dev/null | sed -n 's/^PIN tries remaining: *\([0-9]*\)\/.*/\1/p'; }
counters(){ say "  counters: $PRIMARY=$(tries "$PRIMARY" || echo absent) $REPLACEMENT=$(tries "$REPLACEMENT" || echo absent)"; }
for s in "$PRIMARY" "$REPLACEMENT"; do [ "$(tries "$s")" = 3 ] || die "$s does not start at 3 PIN tries: a drill that starts low cannot measure what it spends"; done
say "cards $PRIMARY (primary) and $REPLACEMENT (replacement), registered and pinned; state $STATE"

# ---- helpers ------------------------------------------------------------------------------------
# USB device of a YubiKey, by serial: de-authorise each candidate until that serial vanishes.
usb_of_yubikey(){ local d; for d in /sys/bus/usb/devices/*; do
    [ "$(cat "$d/idVendor" 2>/dev/null)" = 1050 ] || continue
    echo 0 | sudo tee "$d/authorized" >/dev/null; sleep 2
    if ! ykman list --serials | grep -qx "$1"; then echo 1 | sudo tee "$d/authorized" >/dev/null; sleep 3; echo "$d"; return 0; fi
    echo 1 | sudo tee "$d/authorized" >/dev/null; sleep 3
  done; return 1; }
authorize(){ echo "$2" | sudo tee "$1/authorized" >/dev/null; sleep 3; }
# Change a card's PIN; both PINs on stdin to a pty-driven ykman, never argv.
change_pin(){ OLD="$2" NEW="$3" python3 - "$1" <<'PY'
import os, pty, re, select, sys, termios, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp("ykman", ["ykman", "--device", sys.argv[1], "piv", "access", "change-pin"])
buf, sent = "", 0
answers = [os.environ["OLD"], os.environ["NEW"], os.environ["NEW"]]
while True:
    r, _, _ = select.select([fd], [], [], 30)
    if not r: break
    try: chunk = os.read(fd, 1024)
    except OSError: break
    if not chunk: break
    buf += chunk.decode(errors="replace")
    while sent < len(answers) and len(re.findall(r"(PIN|confirmation)[^\n]*: ?", buf)) > sent:
        # Type only once the prompt has turned echo OFF: getpass flushes input typed before that,
        # and the PIN would be echoed into this buffer too. Measured: without it ykman hangs.
        until = time.time() + 5
        while termios.tcgetattr(fd)[3] & termios.ECHO and time.time() < until:
            time.sleep(0.02)
        os.write(fd, (answers[sent] + "\n").encode()); sent += 1
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
PY
}
seal(){ # seal <name> <out> ; the PIN arrives on stdin
  sudo systemd-creds encrypt --with-key=host --name="$1" - "$2" 2>>"$LOG" >/dev/null; }
say "building the drill test binary"
go -C "$ROOT" test -c -tags piv -o "$STATE/drill.test" ./internal/integration 2>&1 | tee -a "$LOG" || die "build"
phase(){ # phase <name> <serial> <credential blob> ; returns the test's status
  local out; out="$(sudo systemd-run --quiet --pipe --wait --collect -p LimitMEMLOCK=1M \
      -p "LoadCredentialEncrypted=yubi-drill.pin:$3" \
      --setenv=REGALIA_PINDRILL_PHASE="$1" --setenv=REGALIA_PINDRILL_SERIAL="$2" \
      --setenv=REGALIA_PINDRILL_CREDENTIAL=yubi-drill.pin --setenv=REGALIA_PINDRILL_OBJECT="$OBJECT" \
      "$STATE/drill.test" -test.count=1 -test.v -test.run '^TestYubiKeyPINCustodyDrill$' 2>&1)"; local rc=$?
  PHASE_RC=$rc
  printf '%s\n' "$out" | grep -E -- '--- (PASS|FAIL|SKIP)|_test.go:|Failed to|credential' | sed 's/^/    /' | tee -a "$LOG"
  grep -q -- "--- PASS: TestYubiKeyPINCustodyDrill" <<< "$out" && [ "$rc" = 0 ]; }

refused_by_systemd(){ # the service never started because its credential could not be decrypted
  [ "$PHASE_RC" = 243 ] && say "  refused by systemd: exit 243 (EXIT_CREDENTIALS), the service never ran"; }

# The recovery kit: every enrolled token's PIN, encrypted to the break-glass recipient. In production
# the break-glass identity is Shamir-split (4-of-6); here it is per run and deleted at the end.
age-keygen -o "$STATE/breakglass.id" 2>/dev/null; chmod 600 "$STATE/breakglass.id"
BG="$(age-keygen -y "$STATE/breakglass.id")"
printf '%s\n%s\n' "$YK_PIN_PRIMARY" "$YK_PIN_REPLACEMENT" | age -r "$BG" -o "$STATE/recovery-kit.age"
kit_pin(){ age -d -i "$STATE/breakglass.id" "$STATE/recovery-kit.age" | sed -n "${1}p" | tr -d '\n'; }
say "recovery kit: both PINs encrypted to break-glass recipient $BG"

HOSTKEY_EXISTED=0; sudo test -e "$HOSTKEY" && HOSTKEY_EXISTED=1
ROTATED=""
restore(){ # always: the card's PIN, the host key, USB authorisation
  set +e
  for d in /sys/bus/usb/devices/*; do [ "$(cat "$d/authorized" 2>/dev/null)" = 0 ] && authorize "$d" 1; done
  local keep=0
  if [ -n "$ROTATED" ]; then
    if change_pin "$PRIMARY" "$ROTATED" "$YK_PIN_PRIMARY" >/dev/null 2>&1; then say "restore: $PRIMARY PIN put back"
    else keep=1; say "RESTORE FAILED: $PRIMARY still has the rotated PIN; it is in $STATE/rotated.age, openable with $STATE/breakglass.id"; fi
  fi
  if sudo test -e "$STATE/host-key.orig"; then sudo mv -f "$STATE/host-key.orig" "$HOSTKEY" && say "restore: original host credential key put back"
  elif [ "$HOSTKEY_EXISTED" = 0 ]; then sudo rm -f "$HOSTKEY"; fi
  counters
  rm -f "$STATE/drill.test" "$STATE"/*.cred   # sealed PINs: useless off this host, still not kept
  [ "$keep" = 1 ] || rm -f "$STATE/breakglass.id" "$STATE/recovery-kit.age" "$STATE/rotated.age"
}
trap restore EXIT

# ---- R: ROTATION -----------------------------------------------------------------------------------
say "R1 — seal the primary's PIN (v1) and serve through it"
printf '%s' "$YK_PIN_PRIMARY" | seal yubi-drill.pin "$STATE/v1.cred"
phase serve "$PRIMARY" "$STATE/v1.cred" || die "v1 did not serve"; counters
say "R2 — rotate: new PIN on the card, sealed as v2 BEFORE anything restarts"
NEWPIN="$(python3 -c 'import secrets; print("".join(secrets.choice("0123456789") for _ in range(8)))')"
printf '%s' "$NEWPIN" | age -r "$BG" -o "$STATE/rotated.age"   # so a failed run can still restore it
change_pin "$PRIMARY" "$YK_PIN_PRIMARY" "$NEWPIN" >/dev/null 2>&1 || die "PIN change on $PRIMARY"
# Only now is the card's PIN the rotated one. Set earlier, a failed change would make the restore
# present a PIN the card never had and spend a retry.
ROTATED="$NEWPIN"
printf '%s' "$ROTATED" | seal yubi-drill.pin "$STATE/v2.cred"
[ "$(tries "$PRIMARY")" = 3 ] || die "retry metadata not at 3 after the rotation"; counters
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
kit_rotated(){ age -d -i "$STATE/breakglass.id" "$STATE/rotated.age"; }   # the kit is updated at rotation
kit_rotated | seal yubi-drill.pin "$STATE/v3.cred"
phase serve "$PRIMARY" "$STATE/v3.cred" || die "the resealed credential did not serve"; counters

# ---- O: OUTAGES ------------------------------------------------------------------------------------
if [ -n "$NITROKEY" ]; then
  say "O1 — the HSM is out (Nitrokey $NITROKEY de-authorised): YubiKey custody must not depend on it"
  NK=""; for d in /sys/bus/usb/devices/*; do grep -q "^${NITROKEY}" "$d/serial" 2>/dev/null && NK="$d"; done
  [ -n "$NK" ] || die "cannot find Nitrokey $NITROKEY on USB"
  authorize "$NK" 0
  pkcs11-tool --list-slots 2>/dev/null | grep -q "$NITROKEY" && die "the Nitrokey is still visible"
  phase serve "$PRIMARY" "$STATE/v3.cred" || die "YubiKey custody failed while the HSM was out"
  authorize "$NK" 1; sleep 2
  pkcs11-tool --list-slots 2>/dev/null | grep -q "$NITROKEY" && say "  Nitrokey back" || say "  WARNING: Nitrokey not visible again yet"
else
  say "O1 — skipped: no Nitrokey serial given"
fi
say "O2 — the YubiKey itself is out: absent, no PIN presented; back: serves"
YK="$(usb_of_yubikey "$PRIMARY")" || die "cannot find $PRIMARY on USB"
authorize "$YK" 0
ykman list --serials | grep -qx "$PRIMARY" && die "$PRIMARY still visible"
phase absent "$PRIMARY" "$STATE/v3.cred" || die "absent phase"
authorize "$YK" 1
[ "$(tries "$PRIMARY")" = 3 ] || die "the outage spent a retry"
phase serve "$PRIMARY" "$STATE/v3.cred" || die "did not serve after the token came back"; counters

# ---- Y: REPLACEMENT --------------------------------------------------------------------------------
say "Y1 — the replacement token takes the role with its own sealed credential"
kit_pin 2 | seal yubi-drill.pin "$STATE/replacement.cred"
phase serve "$REPLACEMENT" "$STATE/replacement.cred" || die "the replacement did not serve"; counters

# ---- T: TOTAL RECOVERY -----------------------------------------------------------------------------
say "T1 — total loss: host key gone again, primary unused, recovery kit + break-glass only"
sudo rm -f "$HOSTKEY"
if phase serve "$REPLACEMENT" "$STATE/replacement.cred"; then die "DEFECT: the old host's credential opened after total loss"; fi
refused_by_systemd || die "failed, but not as an undecryptable credential (exit $PHASE_RC)"
kit_pin 2 | seal yubi-drill.pin "$STATE/recovered.cred"
phase serve "$REPLACEMENT" "$STATE/recovered.cred" || die "total recovery did not serve"; counters

say "DRILL PASSED: rotation (stale credential spent exactly one retry, then latched), host rebuild, HSM and token outages, replacement and total recovery"
say "transcript: $LOG"
