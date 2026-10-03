#!/usr/bin/env bash
# recovery-key.sh — the KMS host's disk RECOVERY KEY: its own LUKS2 keyslot, independent of the TPM and
# of every peer (#77, Phase 17). Run as root, at the console, on the device that holds the root volume.
#
#   sudo deploy/baremetal/recovery-key.sh --status  DEVICE   the header's state; exit 0 only when "clean"
#   sudo deploy/baremetal/recovery-key.sh --enrol   DEVICE   add the recovery key as a keyslot of its own
#   sudo deploy/baremetal/recovery-key.sh --check   DEVICE   prove a typed key opens THAT keyslot; unlocks nothing
#   sudo deploy/baremetal/recovery-key.sh --replace DEVICE   after any use: a new key in, the used one out
#
# WHAT IT IS. One key per host, generated at the ceremony (step 0), written by hand on the KMS host
# recovery card and carried in every escrow. It opens that host's disk BY ITSELF: no TPM, no peer, no
# running KMS. That is the point (a total outage, or a node with no healthy peer) and the danger, so
# it is kept apart from every site and never stored on a host (THREE-SITE-THREAT-MODEL.md, A3).
#
# THE FORMAT is systemd's recovery key: 256 random bits as 8 groups of 8 letters from
# "cbdefghijklnrtuv", with a dash between groups (71 characters). Those letters are on the same keys
# of a QWERTY, QWERTZ and AZERTY keyboard, which matters at a boot prompt whose layout nobody chose.
# THE DASHES ARE PART OF THE KEY, and it is lower case: the same letters without dashes, in other
# groups or in capitals are a different passphrase and do not open the disk (measured, cryptsetup
# 2.7.5). The keyslot is marked with a systemd-recovery token, so systemd-cryptenroll lists it as
# "recovery" and host_probe.py measures it (root_disk_recovery_keyslot) from the header alone.
#
# THE HEADER'S STATE (#175). Every mode reads it first and every mode ends by printing it, read again:
#   clean           one recovery keyslot, every keyslot named by a token, no empty recovery token
#   no-recovery     no recovery keyslot (a host not yet commissioned): --enrol
#   orphan-keyslot  one recovery keyslot, and a keyslot no token names: the installer's passphrase
#                   before commissioning ends, or a key left by an --enrol or --replace that stopped
#                   (the same run, with the same keys, picks it up)
#   added-unproven  two recovery keyslots, and the header records that one replaces the other: a
#                   --replace that stopped before the used keyslot was destroyed (run it again)
#   orphan-token    a recovery token that names no keyslot: it opens nothing; --enrol and --replace
#                   remove it before anything else
#   unknown         anything this script does not decide: two recovery keyslots no --replace made, a
#                   token naming two keyslots, a recovery keyslot a boot prompt skips. Nothing is
#                   changed; the custodian decides with deploy/baremetal/recovery-reconcile.py
# What is printed is what the header holds, not what the run meant to do.
#
# --enrol asks for a passphrase that opens the volume now (the installer's, at commissioning), then for
# the recovery key twice. Commissioning order:
#   1. --enrol, then --check with the key read from the CARD (not from memory of step 1);
#   2. enrol the TPM (README, section 3) and reboot once to see it unlock unattended;
#   3. only then wipe the installer's passphrase: systemd-cryptenroll --wipe-slot=password DEVICE.
#
# --replace is what follows ANY use of the key, a rehearsal included: whoever typed it at a console
# has seen it. It asks for the used key once and the new one twice, in three steps: ADD the new key in
# a keyslot of its own, PROVE it opens that keyslot as a boot prompt tries it and MARK it (its token
# records which keyslot it replaces, by number and salt, and that one's generation plus one), and only
# then DESTROY the used keyslot by its number. THE NEW KEY is printed by the ceremony disc's
# `pin-escrow.sh --new-recovery-key` and written on a new card; it is never invented by hand (the
# keyslot is protected on the assumption of 256 random bits). It is ESCROWED ONLY AFTER --replace and
# --check have succeeded here: an escrow written first would hold a key that opens nothing.
#
# ONE RUN AT A TIME. This script and recovery-reconcile.py take the same lock for the device
# (/run/lock/regalia-recovery-<device>.lock) and read the header with the same classifier
# (recovery_state.py, beside this script, run by its path with python3 -Es).
#
# WHERE THE KEY COMES FROM (#175, decided 2026-10-03): the ceremony, only. It is generated on the
# offline ceremony machine and written to the card and the escrow there, as nShield writes a card set
# and Vault encrypts unseal shares to their custodians at generation. A key generated here would have
# to travel back to the ceremony to be escrowed, and would open the disk before its escrow existed.
#
# NO UNDO. Once the first header write starts, INT, TERM, HUP and PIPE are ignored: the run finishes.
# A kill, a power cut or a failing write leaves one of the states above, at every point with the used
# key or the new key opening the disk (lab/recovery/matrix.py proves it at every header sync), and the
# same command with the same keys finishes it.
#
# Python is run isolated (-I): a json.py in root's working directory is not what parses the header.
#
# Every secret is typed hidden, or read one per line from standard input when that is not a terminal
# (order: the current passphrase or used key, then the new key). None reaches a command line or the
# environment: cryptsetup reads them from file descriptors.
set -uo pipefail
# Byte-wise character classes: in a UTF-8 locale a range follows the locale's collation.
export LC_ALL=C
fail(){ printf 'recovery-key: FAIL: %s\n' "$*" >&2; outcome DENY "$*"; exit 1; }
# Until the request is recorded (TRAILED) there is no outcome to record: a usage error writes nothing.
TRAILED=""; outcome(){ :; }
say(){ printf 'recovery-key: %s\n' "$*" >&2; }
MODE=""; DEV=""
while [ $# -gt 0 ]; do case "$1" in
  --status|--enrol|--check|--replace) [ -z "$MODE" ] || fail "one of --status, --enrol, --check, --replace"; MODE="${1#--}"; shift;;
  -h|--help) sed -n '2,/^set -uo pipefail$/{/^set -uo pipefail$/!p}' "$0"; exit 0;;
  -*) fail "unknown argument '$1' (see --help)";;
  *) [ -z "$DEV" ] || fail "one device"; DEV="$1"; shift;; esac; done
[ -n "$MODE" ] || fail "one of --status, --enrol, --check, --replace is required (see --help)"
[ -n "$DEV" ] || fail "name the LUKS2 device (the partition under the root volume; see lsblk)"
for t in cryptsetup python3 flock; do command -v "$t" >/dev/null || fail "$t is required"; done
[ -r "$DEV" ] || fail "cannot read $DEV (run as root)"
cryptsetup isLuks --type luks2 "$DEV" 2>/dev/null || fail "$DEV is not a LUKS2 volume"

# Python runs by path with -Es (no environment, no user site): recovery_state.py beside this script,
# which resolves through symlinks. No module in the working directory is ever what reads the header.
HERE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)" || fail "cannot find this script's directory"
STATE_PY="$HERE/recovery_state.py"
[ -f "$STATE_PY" ] || fail "$STATE_PY is missing"
# ONE RUN AT A TIME per device, this script and recovery-reconcile.py alike: the same lock file.
LOCK="$(python3 -Es "$STATE_PY" lock "$DEV")" || fail "cannot take the recovery lock for $DEV"
exec 9<"$LOCK" || fail "cannot open $LOCK"
flock -n 9 || fail "another recovery-key.sh or recovery-reconcile.py is working on $DEV; wait for it"

KEY_FORMAT='^([cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}$'
# What systemd-cryptenroll uses for its own recovery and TPM keyslots: the key has 256 bits of
# entropy, so a slow key-derivation function adds nothing and only delays the boot prompt.
KDF=(--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --hash sha512)

dump(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null; }
# read_state: set STATE RECOVERY UNNAMED EMPTY PAIR ALL WHY from the header; fails when it cannot be read.
# THE ONE READER OF THE HEADER'S STATE is recovery_state.py, which recovery-reconcile.py imports too.
# It prints <state>|<recovery>|<unnamed>|<empty tokens>|<used new>|<all keyslots>|<why>.
read_state(){ local line; line="$(dump | python3 -Es "$STATE_PY" classify)" && [ -n "$line" ] || return 1
  IFS='|' read -r STATE RECOVERY UNNAMED EMPTY PAIR ALL WHY <<< "$line"; }

A=""; B=""; C=""; trap 'A=""; B=""; C=""' EXIT
NAME_A=""; NAME_B=""
# ask <prompt>: one secret, hidden at a terminal, or the next line of standard input.
ask(){ local v=""; if [ -t 0 ]; then IFS= read -r -s -p "$1" v; echo >&2; else IFS= read -r v || true; fi; printf '%s' "$v"; }
# well_formed <key> <what>: refuse, before the disk hears it, anything that cannot be a recovery key,
# and say which of the three usual copying errors it is.
well_formed(){
  [[ "$1" =~ $KEY_FORMAT ]] && return 0
  local low="${1,,}" squeezed
  squeezed="$(printf '%s' "$low" | tr -d ' -')"
  if [[ "$low" =~ $KEY_FORMAT ]]; then fail "$2 is in CAPITALS: a recovery key is lower case, and in capitals it is another passphrase"
  elif [[ "$squeezed" =~ ^[cbdefghijklnrtuv]{64}$ ]]; then fail "$2 has the right letters in the wrong grouping: it is 8 groups of 8 with a DASH between groups, no spaces; the dashes are part of the key"
  else fail "$2 is not a recovery key: 8 groups of 8 letters from cbdefghijklnrtuv with a dash between groups (71 characters)"; fi; }
# opens <secret> [slot]: does it open the volume (that keyslot)? Unlocks nothing.
opens(){ if [ -n "${2:-}" ]; then cryptsetup open --test-passphrase --key-slot "$2" --key-file <(printf '%s' "$1") "$DEV" >/dev/null 2>&1
         else cryptsetup open --test-passphrase --key-file <(printf '%s' "$1") "$DEV" >/dev/null 2>&1; fi; }
# opens_nothing <key>: succeed only if cryptsetup says, by its own exit code 2 ("no key available with
# this passphrase"), that the key opens no keyslot. Any other failure (the header or the device could
# not be read) is "cannot tell", never "opens nothing".
opens_nothing(){ cryptsetup open --test-passphrase --key-file <(printf '%s' "$1") "$DEV" >/dev/null 2>&1; [ $? = 2 ]; }
# proven <key> <slot>: the key opens that keyslot, AND opens the volume when no keyslot is named, which
# is how a boot prompt tries it.
proven(){ opens "$1" "$2" && opens "$1"; }
has_slot(){ case " $ALL " in *" $1 "*) return 0;; esac; return 1; }
token_of(){ dump | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
print(next(i for i, t in (meta.get("tokens") or {}).items() if t.get("type") == "systemd-recovery" and sys.argv[1] in [str(s) for s in t.get("keyslots") or []]))
' "$1"; }
# generation_of <slot>: the generation recorded in the recovery token that names it (0 if it has none:
# a token made before generations, or by systemd-cryptenroll). A generation outside 0..2^31-1 is not
# one this script wrote: it fails, and the caller refuses.
generation_of(){ dump | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
for t in (meta.get("tokens") or {}).values():
    if isinstance(t, dict) and t.get("type") == "systemd-recovery" and sys.argv[1] in [str(s) for s in t.get("keyslots") or []]:
        g = t.get("regalia_generation", 0)
        if not isinstance(g, int) or isinstance(g, bool) or not 0 <= g <= 2**31 - 1:
            sys.exit(1)
        print(g)
        break
else:
    sys.exit(1)
' "$1"; }
salt_of(){ dump | python3 -I -c '
import json, re, sys
salt = ((json.load(sys.stdin).get("keyslots") or {}).get(sys.argv[1]) or {}).get("kdf", {}).get("salt")
if not isinstance(salt, str) or not re.fullmatch(r"[A-Za-z0-9+/=]{8,256}", salt):
    sys.exit(1)
print(salt)
' "$1"; }
# replaced_by_it <slot>: the recovery token naming this keyslot records that it REPLACED another
# keyslot (by salt), and no keyslot with that salt is in the header any more: the header's own
# evidence that a --replace reached the end of its work on this keyslot.
replaced_by_it(){ dump | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
salts = {(k or {}).get("kdf", {}).get("salt") for k in (meta.get("keyslots") or {}).values() if isinstance(k, dict)}
for t in (meta.get("tokens") or {}).values():
    if isinstance(t, dict) and t.get("type") == "systemd-recovery" and [str(s) for s in t.get("keyslots") or []] == [sys.argv[1]]:
        salt = t.get("regalia_replaces_salt")
        sys.exit(0 if isinstance(salt, str) and salt and salt not in salts else 1)
sys.exit(1)
' "$1"; }
# mark <slot> <generation> [<the keyslot it replaces>]: the systemd-recovery token for a keyslot.
mark(){ local extra="" salt
  if [ -n "${3:-}" ]; then salt="$(salt_of "$3")" || return 1; extra=",\"regalia_replaces\":\"$3\",\"regalia_replaces_salt\":\"$salt\""; fi
  printf '{"type":"systemd-recovery","keyslots":["%s"],"regalia_generation":%d%s}' "$1" "$2" "$extra" \
    | cryptsetup token import --json-file - "$DEV" >/dev/null 2>&1; }

# report: the header as it is now, read again. On standard output: every keyslot by kind (and, when
# keys were typed, which of them opens it), then the state and its one way forward.
report(){
  local s kind
  if ! read_state; then echo "STATE: unreadable — the LUKS2 header of $DEV could not be read; run --status again"; return; fi
  echo "KEYSLOTS OF $DEV"
  dump | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
kind = {}
for t in (meta.get("tokens") or {}).values():
    for s in (t.get("keyslots") or []):
        kind.setdefault(str(s), []).append({"systemd-recovery": "recovery key", "systemd-tpm2": "TPM"}.get(t.get("type"), str(t.get("type"))))
for s in sorted(meta.get("keyslots") or {}, key=lambda s: (len(s), s)):
    print("%s\t%s" % (s, " + ".join(kind[s]) if s in kind else "passphrase (no token names it)"))
' | while IFS=$'\t' read -r s kind; do
    opened=""
    case " $RECOVERY $UNNAMED " in *" $s "*)
      [ -n "$A" ] && opens "$A" "$s" && opened="$opened, opens with $NAME_A"
      [ -n "$B" ] && opens "$B" "$s" && opened="$opened, opens with $NAME_B";; esac
    printf '  keyslot %-3s %s%s\n' "$s" "$kind" "$opened"
  done
  case "$STATE" in
    clean) echo "STATE: clean — one recovery keyslot ($RECOVERY), every keyslot named by a token";;
    no-recovery) echo "STATE: no-recovery — no recovery keyslot: --enrol";;
    orphan-keyslot) echo "STATE: orphan-keyslot — keyslot $UNNAMED is a passphrase no token names: the installer's (once the TPM is proven: systemd-cryptenroll --wipe-slot=password $DEV), or a key left by an --enrol or --replace that stopped (run it again with the same keys: it picks the keyslot up)";;
    added-unproven) echo "STATE: added-unproven — keyslot ${PAIR#* } replaces keyslot ${PAIR% *}, which is not destroyed yet: run --replace again with the used key and the new key, in that order";;
    orphan-token) echo "STATE: orphan-token — recovery token $EMPTY names no keyslot and opens nothing: --enrol or --replace removes it first, or cryptsetup token remove --token-id ${EMPTY%% *} $DEV";;
    unknown) echo "STATE: unknown — $WHY. This script changes nothing here: the custodian decides which keyslot to keep (sudo python3 -I $HERE/recovery-reconcile.py $DEV --keep-slot N --retire-slot M)";;
  esac; }
# The header before this run's first write: "nothing was changed" is said only when it is still so.
H0=""
changed(){ [ "$(dump)" != "$H0" ]; }
# end <status> <message>: the message, then the header as it is, then the outcome on the audit trail. A
# failure that left the header exactly as it was says so (DENY); one that did not, says that (INCOMPLETE).
end(){ local rc="$1" result; shift
  if [ "$rc" = 0 ]; then result=ALLOW; say "$*"
  elif [ -n "$H0" ] && changed; then result=INCOMPLETE; say "FAIL: $*"
  elif [ -n "$H0" ]; then result=DENY; say "FAIL: $*. The header is as it was before this run."
  else result=DENY; say "FAIL: $*"; fi
  report
  outcome "$result" "$*" || rc=1
  exit "$rc"; }

# THE AUDIT TRAIL (#278): /var/log/regalia/recovery-key.jsonl, hash-chained, written by trails.py beside this
# script (python3 -Es by its path; the event on standard input; it refuses, and writes nothing, if it cannot).
# For --enrol, --check and --replace: the request is recorded before a key is asked for (and the run refuses
# if it cannot be), and exactly one outcome after: ALLOW, DENY (the header as it was), INCOMPLETE (the header
# changed; run it again), or DENY "interrupted" at a prompt. Never a key: the mode, the device, the header's
# state, its keyslots. --status writes nothing.
TRAILS_PY="$HERE/trails.py"
# trail <outcome> <reason> [<request seq> [<mode>]]: one event, with the header's state as it is read now; it
# prints the line's seq. An outcome names the request it answers (its seq), so the two are paired on the trail.
trail(){ read_state 2>/dev/null || STATE=unreadable
  python3 -I -c 'import json, sys
keys = ("outcome", "reason", "request", "mode", "device", "state", "recovery", "unnamed", "keyslots")
event = dict(zip(keys, sys.argv[1:]))
event["reason"] = event["reason"][:240]
if event["request"]:
    event["request"] = int(event["request"])
else:
    del event["request"]
for k in ("recovery", "unnamed", "keyslots"):
    event[k] = event[k].split()
event["event"] = "recovery-key"
print(json.dumps(event, sort_keys=True))' "$1" "$2" "${3:-}" "${4:-$MODE}" "$DEV" "$STATE" "$RECOVERY" "$UNNAMED" "$ALL" \
    | python3 -Es "$TRAILS_PY" append recovery-key; }
# the outcome, once: an outcome that cannot be written is said, and the run's status is a failure
REQUEST=""
outcome(){ [ -n "$TRAILED" ] || return 0
  TRAILED=""
  trail "$1" "$2" "$REQUEST" >/dev/null && return 0
  printf 'recovery-key: FAIL: the outcome (%s) could not be written to the audit trail (%s)\n' "$1" "$TRAILS_PY" >&2
  return 1; }
requested(){ local open seq mode
  [ -f "$TRAILS_PY" ] || fail "$TRAILS_PY is missing: nothing is done unrecorded"
  # A run killed after its request (SIGKILL, the OOM killer, a power cut) left it unanswered: it is closed
  # first, under this run's lock, so every request on the trail has exactly one outcome.
  open="$(python3 -Es "$TRAILS_PY" unanswered recovery-key "device=$DEV")" || fail "the audit trail cannot be read: nothing was done"
  if [ -n "$open" ]; then
    read -r seq mode <<< "$(python3 -I -c 'import json, sys; e = json.loads(sys.argv[1]); print(e["seq"], e["mode"])' "$open")"
    trail INCOMPLETE "the previous run was killed: no outcome was recorded" "$seq" "$mode" >/dev/null \
      || fail "the audit trail cannot be written: nothing was done"
    say "the audit trail held an unanswered request (seq $seq, --$mode) for $DEV: it is closed as INCOMPLETE"
  fi
  REQUEST="$(trail REQUESTED "")" && [ -n "$REQUEST" ] || fail "the audit trail cannot be written: nothing was done"
  TRAILED=1
  # a Ctrl-C at a prompt (before any write) is recorded too; from the first write on, signals are ignored
  trap 'outcome DENY "interrupted before any change"; exit 130' INT TERM HUP; }
# writes: from here on the run is not stopped by INT, TERM, HUP or PIPE; it finishes and reports.
writes(){ trap '' INT TERM HUP PIPE; H0="$(dump)"; }
# sweep: remove recovery tokens that name no keyslot. They open nothing and mark nothing.
sweep(){ local t; for t in $EMPTY; do cryptsetup token remove --token-id "$t" "$DEV" </dev/null >/dev/null 2>&1; done
  read_state || end 1 "the LUKS2 header of $DEV could not be read"
  [ -z "$EMPTY" ] || end 1 "recovery token $EMPTY names no keyslot and could not be removed"; }
# add <a secret that opens the volume> <new key>: a new keyslot for the key, the lowest free number,
# chosen here and given to cryptsetup. It sets ADDED. NOT marked yet: the caller proves it first.
ADDED=""
add(){
  local slot="" n
  read_state || end 1 "the LUKS2 header of $DEV could not be read"
  for n in $(seq 0 31); do has_slot "$n" || { slot="$n"; break; }; done
  [ -n "$slot" ] || end 1 "every keyslot of $DEV is in use"
  if ! cryptsetup luksAddKey --batch-mode "${KDF[@]}" --new-key-slot "$slot" --key-file <(printf '%s' "$1") "$DEV" <(printf '%s' "$2") </dev/null >/dev/null 2>&1; then
    read_state || end 1 "cryptsetup failed to add keyslot $slot, and the header could not be read again"
    has_slot "$slot" || end 1 "cryptsetup refused to add the keyslot (does the first value open this volume with no keyslot named?)"
    say "cryptsetup reported a failure, but keyslot $slot was written: it is proven like any other"
  fi
  ADDED="$slot"; }
# retire <keyslot>: destroy the used recovery keyslot by its number, authorised by the new key, then
# remove the token it leaves empty. The new key is proven before this is ever called.
retire(){
  cryptsetup luksKillSlot --key-file <(printf '%s' "$B") "$DEV" "$1" </dev/null >/dev/null 2>&1
  read_state || end 1 "the header could not be read after the used keyslot $1 was to be destroyed: run --status, then --replace again with the same two keys"
  ! has_slot "$1" || end 1 "the USED keyslot $1 could not be destroyed: the used key still opens the disk. Run --replace again with the same two keys"
  sweep; }
# spent: the used key opens nothing, by cryptsetup's own answer.
spent(){
  opens "$A" && end 1 "the used key STILL opens $DEV through another keyslot; look at cryptsetup luksDump $DEV"
  opens_nothing "$A" || end 1 "cannot show that the used key opens nothing (the header or the device could not be read); run --status"; }
read_state || fail "cannot read the LUKS2 header of $DEV"
[ "$MODE" = status ] || requested
case "$MODE" in
status)
  report
  [ "$STATE" = clean ]; exit $?
  ;;
check)
  case "$STATE" in
    added-unproven) end 1 "$DEV has 2 recovery keyslots, a --replace that stopped: run it again";;
    clean|orphan-keyslot|orphan-token) [ "$(wc -w <<< "$RECOVERY")" -eq 1 ] || end 1 "$DEV has no recovery keyslot";;
    *) end 1 "$DEV is in state $STATE: no single recovery keyslot to check";;
  esac
  B="$(ask "The recovery key, read from the card (hidden): ")"
  well_formed "$B" "that value"
  NAME_B="the key typed"
  opens "$B" "$RECOVERY" || end 1 "that key does NOT open the recovery keyslot ($RECOVERY) of $DEV. The card, or the escrow it was copied from, does not hold this host's key"
  opens "$B" || end 1 "that key opens keyslot $RECOVERY when it is named, but NOT the volume as a boot prompt tries it"
  say "OK: that key opens the recovery keyslot ($RECOVERY) of $DEV. Nothing was unlocked."
  say "It has now been typed at a console: after a REAL use, or a rehearsal with witnesses, --replace it."
  report
  outcome ALLOW "the key typed opens recovery keyslot $RECOVERY" || exit 1
  ;;
enrol)
  case "$STATE" in unknown|added-unproven) end 1 "$DEV is in state $STATE; --enrol does not work beside it";; esac
  [ "$(wc -w <<< "$RECOVERY")" -le 1 ] || end 1 "$DEV already has more than one recovery keyslot"
  A="$(ask "A passphrase that opens $DEV now (the installer's; hidden): ")"
  [ -n "$A" ] || fail "no passphrase given; nothing was changed"
  opens "$A" || fail "that passphrase does not open $DEV; nothing was changed"
  NAME_A="the passphrase typed"
  B="$(ask "The recovery key, from the KMS host recovery card (hidden): ")"
  if [ -t 0 ]; then C="$(ask "The recovery key again: ")"; [ "$B" = "$C" ] || fail "the two entries differ; nothing was changed"; fi
  well_formed "$B" "that value"
  [ "$A" != "$B" ] || fail "the passphrase and the recovery key are the same value; nothing was changed"
  NAME_B="the recovery key typed"
  # EVERY KEYSLOT NO TOKEN NAMES MUST BE OPENED BY WHAT WAS JUST TYPED, checked for all of them BEFORE
  # anything is written. An --enrol that stopped between adding its keyslot and marking it leaves the
  # recovery key it was given in a keyslot no token names: that one keyslot (only one) may hold the key
  # typed now, and is picked up. Anything else is refused with the header untouched.
  HOLDS_B=""
  for s in $UNNAMED; do
    opens "$A" "$s" && continue
    if opens "$B" "$s"; then
      [ -z "$HOLDS_B" ] || fail "keyslots $HOLDS_B and $s both hold the recovery key typed, and no token names either: decide by hand which to keep (cryptsetup luksKillSlot $DEV <the other>). Nothing was changed"
      HOLDS_B="$s"; continue
    fi
    fail "keyslot $s is a passphrase no token names, and it is not the one you typed. If it is a second passphrase you know, enrol with that volume reduced to one passphrase. If you do not know it, an --enrol that stopped may have left it: see --status. Nothing was changed"
  done
  if [ -n "$RECOVERY" ]; then
    [ -z "$HOLDS_B" ] || fail "keyslot $HOLDS_B holds the recovery key as well as keyslot $RECOVERY, and no token names it: cryptsetup luksKillSlot $DEV $HOLDS_B. Nothing was changed"
    # The same key, typed again, is already the recovery key: an --enrol that finished, or that
    # stopped after marking it. Any other key: one host has one recovery key.
    proven "$B" "$RECOVERY" || fail "$DEV already has a recovery keyslot ($RECOVERY), and the key typed does not open it. To change the key use --replace; one host has one recovery key"
    if [ "$STATE" = orphan-token ]; then writes; sweep; end 0 "ENROLLED: the recovery key is keyslot $RECOVERY of $DEV; the empty recovery token an earlier run left was removed. Now run --check with the key read from the CARD."; fi
    end 0 "ENROLLED already: the key typed is the recovery key, keyslot $RECOVERY of $DEV, proven. Nothing was changed. Run --check with the key read from the CARD."
  fi
  writes; sweep
  if [ -n "$HOLDS_B" ]; then ADDED="$HOLDS_B"; say "keyslot $HOLDS_B already holds this recovery key (left by an --enrol that stopped): using it"
  else add "$A" "$B"; fi
  proven "$B" "$ADDED" || end 1 "keyslot $ADDED holds the key typed but does not open the volume as a boot prompt tries it; it is NOT marked as the recovery key. Remove it (cryptsetup luksKillSlot $DEV $ADDED) and enrol again"
  mark "$ADDED" 1 || end 1 "keyslot $ADDED holds the recovery key typed, proven, but could not be marked: run --enrol again with the same two values"
  end 0 "ENROLLED: the recovery key is keyslot $ADDED of $DEV. Now run --check with the key read from the CARD."
  ;;
replace)
  case "$STATE" in
    unknown) end 1 "$DEV is in state unknown: this script will not guess which key to destroy";;
    no-recovery) end 1 "$DEV has no recovery keyslot to replace: --enrol";;
  esac
  A="$(ask "The recovery key that was USED (hidden): ")"
  well_formed "$A" "the used key"
  NAME_A="the used key"
  B="$(ask "The NEW recovery key, from the new card (hidden): ")"
  if [ -t 0 ]; then C="$(ask "The new recovery key again: ")"; [ "$B" = "$C" ] || fail "the two entries differ; nothing was changed"; fi
  well_formed "$B" "the new key"
  [ "$A" != "$B" ] || fail "the new key is the used key; nothing was changed"
  NAME_B="the new key"
  if [ "$STATE" = added-unproven ]; then
    # FINISHING A --replace THAT STOPPED between marking the new keyslot and destroying the used one.
    # WHICH KEYSLOT IS THE NEW ONE is read from the header, never from the order the keys were typed
    # in: typed the wrong way round, the new key would be destroyed and the seen one kept.
    read -r old new <<< "$PAIR"
    if opens "$B" "$old" && opens "$A" "$new"; then
      end 1 "the key typed as USED opens the NEW keyslot ($new) and the key typed as new opens the used one ($old): they were typed in the wrong order. Nothing was changed"
    fi
    proven "$B" "$new" \
      || end 1 "$DEV has 2 recovery keyslots, and these are not the used key of keyslot $old and the new key of keyslot $new; nothing was changed"
    # luksKillSlot wipes a keyslot's key material BEFORE it updates the metadata: a destroy killed
    # between the two leaves keyslot $old listed (and marked as the replaced one) while the used key
    # opens nothing. The header's mark and the new key's proof say what to do; cryptsetup's own
    # "no key available" (never a read failure) says the used key is already spent.
    if ! opens "$A" "$old"; then
      opens_nothing "$A" \
        || end 1 "$DEV has 2 recovery keyslots, and these are not the used key of keyslot $old and the new key of keyslot $new; nothing was changed"
      say "the used key opens nothing: keyslot $old's key material was wiped by a destroy that stopped before it reached the header; it is removed now"
    fi
    writes; sweep
    retire "$old"; spent
    end 0 "REPLACED: an unfinished --replace was completed: the used keyslot $old is destroyed, the new recovery key is keyslot $new of $DEV; the used key opens nothing."
  fi
  # One recovery keyslot (clean, orphan-keyslot or orphan-token).
  if opens_nothing "$A" && proven "$B" "$RECOVERY" && replaced_by_it "$RECOVERY"; then
    # A --replace that stopped AFTER the used keyslot was destroyed: the new key is the one recovery
    # key, the used key opens nothing, and the header records that this keyslot replaced one that is
    # gone. Only the empty token the used keyslot left may remain.
    if [ "$STATE" = orphan-token ]; then writes; sweep; fi
    end 0 "REPLACED: the new recovery key is keyslot $RECOVERY of $DEV and the key typed as used opens nothing; the header records that this keyslot replaced one that is gone."
  fi
  opens "$A" "$RECOVERY" || end 1 "that key does not open the recovery keyslot ($RECOVERY); nothing was changed"
  generation="$(generation_of "$RECOVERY")" || end 1 "the used keyslot's token carries a generation this script did not write; nothing was changed. See cryptsetup luksDump $DEV"
  [ "$generation" -lt 2147483647 ] || end 1 "the used keyslot's token is at the last generation this script writes; nothing was changed. See cryptsetup luksDump $DEV"
  # A --replace that stopped between adding its keyslot and marking it left the new key in a keyslot
  # no token names. Given the same new key again, that keyslot is the one to mark: adding a second
  # would put the key in two keyslots and leave one unmarked.
  HOLDS_B=""
  for s in $UNNAMED; do
    if opens "$B" "$s"; then
      [ -z "$HOLDS_B" ] || end 1 "keyslots $HOLDS_B and $s both hold the new key, and no token names either: decide by hand which to keep (cryptsetup luksKillSlot $DEV <the other>). Nothing was changed"
      HOLDS_B="$s"
    fi
  done
  OLD="$RECOVERY"
  writes; sweep
  if [ -n "$HOLDS_B" ]; then ADDED="$HOLDS_B"; say "keyslot $HOLDS_B already holds the new key (left by a --replace that stopped): using it"
  else add "$A" "$B"; fi
  # 1 ADD (above). 2 PROVE and MARK: the new key opens its keyslot as a boot prompt tries it, BEFORE the
  # used one is destroyed: at no moment is the host without a recovery key that is known to open it.
  proven "$B" "$ADDED" || end 1 "the new keyslot $ADDED does not open the volume with the new key as a boot prompt tries it; it is NOT marked and the used key is still enrolled. Remove it (cryptsetup luksKillSlot $DEV $ADDED) and replace again"
  mark "$ADDED" "$((generation + 1))" "$OLD" || end 1 "the new keyslot $ADDED is proven but could not be marked; the used key is still enrolled. Run --replace again with the same two keys"
  # 3 DESTROY the used keyslot, by its number.
  retire "$OLD"; spent
  read_state
  for s in $UNNAMED; do [ "$s" = "$ADDED" ] || say "WARNING: keyslot $s is a passphrase no token names, and neither key typed here opens it as the recovery key (the installer's? a key from an abandoned --replace?). It still opens the disk: --status fails until it is removed"; done
  end 0 "REPLACED: the new recovery key is keyslot $ADDED of $DEV; the used key opens nothing."
  ;;
esac
