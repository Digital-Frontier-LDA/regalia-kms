#!/usr/bin/env bash
# recovery-key.sh — the KMS host's disk RECOVERY KEY: its own LUKS2 keyslot, independent of the TPM and
# of every peer (#77, Phase 17). Run as root, at the console, on the device that holds the root volume.
#
#   sudo deploy/baremetal/recovery-key.sh --status  DEVICE   the keyslots by kind; exit 1 unless exactly one
#                                                            recovery keyslot and no unlabelled passphrase
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
# --enrol asks for a passphrase that opens the volume now (the installer's, at commissioning), then for
# the recovery key twice. It refuses if a recovery keyslot already exists. Commissioning order:
#   1. --enrol, then --check with the key read from the CARD (not from memory of step 1);
#   2. enrol the TPM (README, section 3) and reboot once to see it unlock unattended;
#   3. only then wipe the installer's passphrase: systemd-cryptenroll --wipe-slot=password DEVICE.
#
# --replace is what follows ANY use of the key, a rehearsal included: whoever typed it at a console
# has seen it. It asks for the used key once and the new one twice (from a new ceremony escrow),
# adds the new keyslot, proves the new key opens it, and only then destroys the used keyslot.
# If it stops between those two steps (a failure, a kill), BOTH keys open the disk and --status says
# so: run --replace again with the same two keys, and it destroys the used keyslot.
#
# WHEN A RUN FAILS it says "nothing was changed" only after reading the header again. If a keyslot
# it added could not be taken back, it says that the key just typed opens the disk and prints the
# commands that remove it. A signal takes an unproven keyslot back; a kill cannot, and the next
# --enrol refuses to work beside a keyslot that no token names and the typed passphrase does not open.
#
# Every secret is typed hidden, or read one per line from standard input when that is not a terminal
# (order: the current passphrase or used key, then the new key). None reaches a command line or the
# environment: cryptsetup reads them from file descriptors.
set -uo pipefail
# Byte-wise character classes: in a UTF-8 locale a range follows the locale's collation.
export LC_ALL=C
fail(){ printf 'recovery-key: FAIL: %s\n' "$*" >&2; exit 1; }
say(){ printf 'recovery-key: %s\n' "$*" >&2; }
MODE=""; DEV=""
while [ $# -gt 0 ]; do case "$1" in
  --status|--enrol|--check|--replace) [ -z "$MODE" ] || fail "one of --status, --enrol, --check, --replace"; MODE="${1#--}"; shift;;
  -h|--help) sed -n '2,/^set -uo pipefail$/{/^set -uo pipefail$/!p}' "$0"; exit 0;;
  -*) fail "unknown argument '$1' (see --help)";;
  *) [ -z "$DEV" ] || fail "one device"; DEV="$1"; shift;; esac; done
[ -n "$MODE" ] || fail "one of --status, --enrol, --check, --replace is required (see --help)"
[ -n "$DEV" ] || fail "name the LUKS2 device (the partition under the root volume; see lsblk)"
for t in cryptsetup python3; do command -v "$t" >/dev/null || fail "$t is required"; done
[ -r "$DEV" ] || fail "cannot read $DEV (run as root)"
cryptsetup isLuks --type luks2 "$DEV" 2>/dev/null || fail "$DEV is not a LUKS2 volume"

KEY_FORMAT='^([cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}$'
# What systemd-cryptenroll uses for its own recovery and TPM keyslots: the key has 256 bits of
# entropy, so a slow key-derivation function adds nothing and only delays the boot prompt.
KDF=(--pbkdf pbkdf2 --pbkdf-force-iterations 1000 --hash sha512)

# slots: "<recovery keyslots, space-separated>|<keyslots no token names>|<all keyslots>" from the header.
slots(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -c '
import json, sys
try:
    meta = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
order = lambda s: (len(s), s)
all_slots = sorted(meta.get("keyslots") or {}, key=order)
tokens = [t for t in (meta.get("tokens") or {}).values() if isinstance(t, dict)]
named = {str(s) for t in tokens for s in (t.get("keyslots") or [])}
recovery = sorted({str(s) for t in tokens if t.get("type") == "systemd-recovery" for s in (t.get("keyslots") or [])}, key=order)
print("%s|%s|%s" % (" ".join(recovery), " ".join(s for s in all_slots if s not in named), " ".join(all_slots)))
' || fail "cannot read the LUKS2 header of $DEV"; }
# kinds: one line per keyslot, "<slot> <kind>", the kind being its token's type or "passphrase".
kinds(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -c '
import json, sys
meta = json.load(sys.stdin)
kind = {}
for t in (meta.get("tokens") or {}).values():
    for s in (t.get("keyslots") or []):
        kind.setdefault(str(s), []).append({"systemd-recovery": "recovery key", "systemd-tpm2": "TPM"}.get(t.get("type"), str(t.get("type"))))
for s in sorted(meta.get("keyslots") or {}, key=lambda s: (len(s), s)):
    print("  keyslot %-3s %s" % (s, " + ".join(kind[s]) if s in kind else "passphrase (no token names it)"))
'; }
# token_of <slot>: the id of the systemd-recovery token that names it.
token_of(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -c '
import json, sys
meta = json.load(sys.stdin)
print(next(i for i, t in (meta.get("tokens") or {}).items() if t.get("type") == "systemd-recovery" and sys.argv[1] in [str(s) for s in t.get("keyslots") or []]))
' "$1"; }

A=""; B=""; C=""; trap 'A=""; B=""; C=""' EXIT
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
# kill_slot <slot>: destroy a keyslot this run just made, without a passphrase. Standard input is
# closed for it: in batch mode cryptsetup still waits on an open pipe there (measured, 2.7.5), and
# this script's own input may be one, with a secret still unread in it.
kill_slot(){ cryptsetup luksKillSlot --batch-mode "$DEV" "$1" </dev/null >/dev/null 2>&1; }
# orphans: the ids of systemd-recovery tokens that name no keyslot. cryptsetup unassigns a token when
# its keyslot is destroyed but does not delete it; such a token opens nothing and marks nothing.
orphans(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -c '
import json, sys
meta = json.load(sys.stdin)
print(" ".join(i for i, t in sorted((meta.get("tokens") or {}).items()) if isinstance(t, dict) and t.get("type") == "systemd-recovery" and not t.get("keyslots")))
'; }
sweep(){ local t; for t in $(orphans); do cryptsetup token remove --token-id "$t" "$DEV" </dev/null >/dev/null 2>&1; done; }
# has_slot <slot>: is that keyslot in the header now? Fails (2) when the header cannot be read.
has_slot(){ local now; now="$(slots)" || return 2; case " ${now##*|} " in *" $1 "*) return 0;; esac; return 1; }
# undo <slot>: take back a keyslot this run added, and the token that names it. IT DOES NOT TRUST
# ITSELF: after the attempt the header is read again, and it succeeds only if that keyslot is gone.
# If it is not, the key just typed still opens the disk, and the caller must say so instead of
# "nothing was changed"; the commands that finish the job by hand are printed here.
undo(){
  local token; token="$(token_of "$1" 2>/dev/null)"
  kill_slot "$1"
  has_slot "$1"; case $? in
    1) ;;
    *) say "keyslot $1 of $DEV COULD NOT BE REMOVED and holds the key just typed: that key opens the disk."
       say "remove it by hand: cryptsetup luksKillSlot $DEV $1${token:+ ; cryptsetup token remove --token-id $token $DEV}"
       return 1;; esac
  if [ -n "$token" ] && ! cryptsetup token remove --token-id "$token" "$DEV" </dev/null >/dev/null 2>&1; then
    say "keyslot $1 is removed, but its token $token remains (it names no keyslot now): cryptsetup token remove --token-id $token $DEV"
  fi
  return 0; }
# PENDING is the keyslot this run has added and not yet proven. A signal that arrives in that state
# takes it back (bash runs the trap once the cryptsetup call in progress has returned). A kill that
# cannot be caught leaves it behind; --enrol finds such a keyslot on the next run (below).
PENDING=""
interrupted(){ trap - INT TERM HUP
  if [ -n "$PENDING" ]; then say "interrupted: taking back keyslot $PENDING"; undo "$PENDING" && say "keyslot $PENDING removed; nothing was changed"; fi
  exit 130; }
trap interrupted INT TERM HUP
# add <secret that opens the volume> <new key>: a new keyslot for the key with its systemd-recovery
# token; the keyslot is left in ADDED (and in PENDING until the caller has proven it). The keyslot
# NUMBER is chosen here, from a header that was read successfully, and given to cryptsetup: so every
# later failure knows exactly which keyslot to take back, and a key never stays behind as an
# unlabelled passphrase without the operator being told.
ADDED=""
add(){
  local snapshot used slot="" n
  snapshot="$(slots)" || exit 1
  used=" ${snapshot##*|} "
  for n in $(seq 0 31); do case "$used" in *" $n "*) ;; *) slot="$n"; break;; esac; done
  [ -n "$slot" ] || fail "every keyslot of $DEV is in use. Nothing was changed"
  PENDING="$slot"
  if ! cryptsetup luksAddKey --batch-mode "${KDF[@]}" --new-key-slot "$slot" --key-file <(printf '%s' "$1") "$DEV" <(printf '%s' "$2") >/dev/null 2>&1; then
    # Refused, normally before anything was written. "Normally" is checked, not assumed.
    has_slot "$slot"; [ $? = 1 ] || { undo "$slot" || exit 1; }
    PENDING=""
    fail "cryptsetup refused to add the keyslot (is the first value one that opens this volume?). Nothing was changed"
  fi
  if ! printf '{"type":"systemd-recovery","keyslots":["%s"]}' "$slot" | cryptsetup token import --json-file - "$DEV" >/dev/null 2>&1; then
    undo "$slot" || exit 1
    PENDING=""
    fail "the keyslot could not be marked as the recovery key, and was removed again. Nothing was changed"
  fi
  ADDED="$slot"; }
# proven <key> <slot>: the key opens that keyslot, AND opens the volume when no keyslot is named, which
# is how a boot prompt tries it (a keyslot whose priority is "ignore" passes the first test only).
proven(){ opens "$1" "$2" && opens "$1"; }
# retire <keyslot> <its token> <a key that opens another keyslot>: destroy a used recovery keyslot.
retire(){
  cryptsetup luksKillSlot --key-file <(printf '%s' "$3") "$DEV" "$1" </dev/null >/dev/null 2>&1
  has_slot "$1"; [ $? = 1 ] || fail "the USED keyslot $1 could not be destroyed: the used key still opens the disk. Run --replace again with the same two keys to finish, or by hand: cryptsetup luksKillSlot $DEV $1 ; cryptsetup token remove --token-id $2 $DEV"
  cryptsetup token remove --token-id "$2" "$DEV" </dev/null >/dev/null 2>&1 \
    || fail "the used keyslot is destroyed but its token $2 remains (it names no keyslot now): cryptsetup token remove --token-id $2 $DEV"; }

SNAPSHOT="$(slots)" || exit 1
IFS='|' read -r RECOVERY STRAY _ <<< "$SNAPSHOT"
COUNT="$(wc -w <<< "$RECOVERY")"
case "$MODE" in
status)
  echo "KEYSLOTS OF $DEV"; kinds
  [ "$COUNT" -ne 2 ] || { say "2 recovery keyslots: a --replace that did not finish? Run --replace again with the used key and the new key; it destroys the used one"; exit 1; }
  [ "$COUNT" -eq 1 ] || { say "$COUNT recovery keyslots: a commissioned host has exactly one"; exit 1; }
  [ -z "$STRAY" ] || { say "keyslot $STRAY is a passphrase no token names (the installer's?): once the TPM and the recovery key are proven, systemd-cryptenroll --wipe-slot=password $DEV"; exit 1; }
  left="$(orphans)"; [ -z "$left" ] || { say "token $left is a recovery token that names no keyslot (left by a keyslot removed by hand): cryptsetup token remove --token-id ${left%% *} $DEV"; exit 1; }
  ;;
enrol)
  [ -z "$RECOVERY" ] || fail "$DEV already has a recovery keyslot ($RECOVERY). To change the key use --replace; one host has one recovery key"
  A="$(ask "A passphrase that opens $DEV now (the installer's; hidden): ")"
  [ -n "$A" ] || fail "no passphrase given; nothing was changed"
  B="$(ask "The recovery key, from the KMS host recovery card (hidden): ")"
  if [ -t 0 ]; then C="$(ask "The recovery key again: ")"; [ "$B" = "$C" ] || fail "the two entries differ; nothing was changed"; fi
  well_formed "$B" "that value"
  [ "$A" != "$B" ] || fail "the passphrase and the recovery key are the same value; nothing was changed"
  # A KEYSLOT NO TOKEN NAMES MUST BE THE ONE JUST TYPED. An --enrol that was killed between adding
  # its keyslot and marking it leaves the recovery key it was given as an unlabelled passphrase,
  # which still opens the disk. Enrolling another key beside it would hide that.
  opens "$A" || fail "that passphrase does not open $DEV; nothing was changed"
  for s in $STRAY; do
    opens "$A" "$s" || fail "keyslot $s is a passphrase no token names and it is NOT the one you typed (an --enrol that was interrupted may have left a recovery key there). Remove it first: cryptsetup luksKillSlot $DEV $s. Nothing was changed"
  done
  sweep
  add "$A" "$B"
  if ! proven "$B" "$ADDED"; then
    undo "$ADDED" || exit 1
    PENDING=""
    fail "the new keyslot did not open with the key just typed, and was removed again. Nothing was changed"
  fi
  PENDING=""
  say "ENROLLED: the recovery key is keyslot $ADDED of $DEV. Now run --check with the key read from the CARD."
  kinds >&2
  ;;
check)
  [ "$COUNT" -ne 2 ] || fail "$DEV has 2 recovery keyslots: a --replace that did not finish. Run --replace again with the used key and the new key"
  [ "$COUNT" -eq 1 ] || fail "$DEV has $COUNT recovery keyslots, not one; see --status"
  B="$(ask "The recovery key, read from the card (hidden): ")"
  well_formed "$B" "that value"
  opens "$B" "$RECOVERY" || fail "that key does NOT open the recovery keyslot ($RECOVERY) of $DEV. The card, or the escrow it was copied from, does not hold this host's key"
  opens "$B" || fail "that key opens keyslot $RECOVERY when it is named, but NOT the volume as a boot prompt tries it (is the keyslot's priority 'ignore'? cryptsetup config --priority normal --key-slot $RECOVERY $DEV)"
  say "OK: that key opens the recovery keyslot ($RECOVERY) of $DEV. Nothing was unlocked."
  say "It has now been typed at a console: after a REAL use, or a rehearsal with witnesses, --replace it."
  ;;
replace)
  [ "$COUNT" -eq 1 ] || [ "$COUNT" -eq 2 ] || fail "$DEV has $COUNT recovery keyslots; see --status"
  A="$(ask "The recovery key that was USED (hidden): ")"
  well_formed "$A" "the used key"
  B="$(ask "The NEW recovery key, from the new card (hidden): ")"
  if [ -t 0 ]; then C="$(ask "The new recovery key again: ")"; [ "$B" = "$C" ] || fail "the two entries differ; nothing was changed"; fi
  well_formed "$B" "the new key"
  [ "$A" != "$B" ] || fail "the new key is the used key; nothing was changed"
  if [ "$COUNT" -eq 2 ]; then
    # FINISHING A --replace THAT STOPPED between adding the new keyslot and destroying the used one
    # (a failure there, or a kill). Both keys open the disk in that state, and nothing else in this
    # script will touch it. It is recognised by the two keys themselves: the used key opens one of
    # the two recovery keyslots and the new key opens the other.
    read -r s1 s2 <<< "$RECOVERY"
    if opens "$A" "$s1" && proven "$B" "$s2"; then old="$s1"; new="$s2"
    elif opens "$A" "$s2" && proven "$B" "$s1"; then old="$s2"; new="$s1"
    else fail "$DEV has 2 recovery keyslots, and these are not the used key of one and the new key of the other; nothing was changed. See --status"; fi
    old_token="$(token_of "$old")" || fail "cannot find the used keyslot's token; nothing was changed"
    retire "$old" "$old_token" "$B"
    slot="$new"; say "an unfinished --replace was completed"
  else
    opens "$A" "$RECOVERY" || fail "that key does not open the recovery keyslot ($RECOVERY); nothing was changed"
    old_token="$(token_of "$RECOVERY")" || fail "cannot find the used keyslot's token; nothing was changed"
    sweep
    add "$A" "$B"
    # The new key is proven BEFORE the used one is destroyed: at no moment is the host without a
    # recovery key that is known to open it.
    if ! proven "$B" "$ADDED"; then
      undo "$ADDED" || exit 1
      PENDING=""
      fail "the new keyslot did not open with the new key and was removed; the used key is still enrolled"
    fi
    PENDING=""
    slot="$ADDED"
    retire "$RECOVERY" "$old_token" "$B"
  fi
  opens "$A" && fail "the used key STILL opens $DEV through another keyslot; look at cryptsetup luksDump $DEV"
  say "REPLACED: the new recovery key is keyslot $slot of $DEV; the used key opens nothing."
  kinds >&2
  ;;
esac
