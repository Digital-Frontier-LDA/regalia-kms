#!/usr/bin/env bash
# recovery-key.sh — the KMS host's disk RECOVERY KEY: its own LUKS2 keyslot, independent of the TPM and
# of every peer (#77, Phase 17). Run as root, at the console, on the device that holds the root volume.
#
#   sudo deploy/baremetal/recovery-key.sh --status  DEVICE   the keyslots by kind; exit 1 unless exactly one
#                                                            recovery keyslot that a boot prompt will try,
#                                                            no unlabelled passphrase and no empty token
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
# has seen it. It asks for the used key once and the new one twice, adds the new keyslot, proves the
# new key opens it, and only then destroys the used keyslot. THE NEW KEY is printed by the ceremony
# disc's `pin-escrow.sh --new-recovery-key` and written on a new card; it is never invented by hand
# (the keyslot is protected on the assumption of 256 random bits). It is ESCROWED ONLY AFTER
# --replace and --check have succeeded here: an escrow written first would hold a key that opens nothing.
# If it stops between those two steps (a failure, a kill), BOTH keys open the disk and --status says
# so: run --replace again with the same two keys, in the same order, and it destroys the used keyslot.
# Which of the two is the new one is recorded in the header when it is added (its token says which
# keyslot it replaces, and carries that one's generation plus one), so keys typed in the wrong order
# are refused, and two recovery keyslots that no --replace made are never decided by this script.
#
# WHEN A RUN FAILS it says "nothing was changed" only after reading the header again. If a keyslot
# it added could not be taken back, it says that the key just typed opens the disk and prints the
# commands that remove it. A signal takes an unproven keyslot back; a kill cannot, and the next
# --enrol refuses to work beside a keyslot that no token names and the typed passphrase does not open.
#
# Python is run isolated (-I): a json.py in root's working directory is not what parses the header.
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
slots(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
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
kinds(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
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
token_of(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
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
orphans(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
print(" ".join(i for i, t in sorted((meta.get("tokens") or {}).items()) if isinstance(t, dict) and t.get("type") == "systemd-recovery" and not t.get("keyslots")))
'; }
sweep(){ local t; for t in $(orphans); do cryptsetup token remove --token-id "$t" "$DEV" </dev/null >/dev/null 2>&1; done; }
# generation_of <slot>: the generation recorded in the recovery token that names it (0 if it has none:
# a token made before generations, or by systemd-cryptenroll). --enrol writes 1; each --replace
# writes, in the NEW keyslot's token, the used key's generation plus one AND the keyslot it replaces.
# A generation outside 0..2^31-1 is not one this script wrote: it fails, and the caller refuses.
generation_of(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
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
# unfinished: with exactly two recovery keyslots in the header, print "<used keyslot> <new keyslot>"
# if, and only if, the header itself says they are a --replace that stopped half way: each keyslot is
# named by exactly one recovery token, each of those tokens names only that keyslot, and exactly one
# of them says it REPLACES the other keyslot, names THAT KEYSLOT'S SALT, and carries the other
# generation plus one. The salt is the keyslot's identity: keyslot NUMBERS are reused (the lowest free
# one), and the mark outlives a completed replace, so a recovery key that somebody adds later in the
# recycled number must not be taken for the used half of a replace that never stopped. Anything else
# (a second recovery key made by systemd-cryptenroll or by hand, a token naming both keyslots, a
# generation that is not a small whole number) is not decided here: it prints the reason and fails.
unfinished(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
import json, sys
meta = json.load(sys.stdin)
tokens = [t for t in (meta.get("tokens") or {}).values() if isinstance(t, dict) and t.get("type") == "systemd-recovery" and t.get("keyslots")]
slots = sorted({str(s) for t in tokens for s in t["keyslots"]})
def refuse(why):
    print(why); sys.exit(1)
if len(slots) != 2:
    refuse("there are not exactly two recovery keyslots")
owner = {}
for t in tokens:
    if len(t["keyslots"]) != 1:
        refuse("one recovery token names more than one keyslot")
    slot = str(t["keyslots"][0])
    if slot in owner:
        refuse("keyslot %s is named by more than one recovery token" % slot)
    owner[slot] = t
def generation(t):
    g = t.get("regalia_generation", 0)
    return g if isinstance(g, int) and not isinstance(g, bool) and 0 <= g <= 2**31 - 1 else None
def salt(slot):
    value = ((meta.get("keyslots") or {}).get(slot) or {}).get("kdf", {}).get("salt")
    return value if isinstance(value, str) and value else None
a, b = slots
newer = [(new, old) for new, old in ((a, b), (b, a))
         if str(owner[new].get("regalia_replaces")) == old and salt(old) is not None
         and owner[new].get("regalia_replaces_salt") == salt(old) and generation(owner[new]) is not None
         and generation(owner[old]) is not None and generation(owner[new]) == generation(owner[old]) + 1]
if len(newer) != 1:
    refuse("the two recovery keyslots do not say that one replaces the other")
print("%s %s" % (newer[0][1], newer[0][0]))
'; }
# ignored <slot>: is that keyslot marked "ignore" (priority 0)? Such a keyslot is skipped whenever no
# keyslot is named, which is how a boot prompt tries a passphrase.
ignored(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
import json, sys
sys.exit(0 if (json.load(sys.stdin).get("keyslots") or {}).get(sys.argv[1], {}).get("priority") == 0 else 1)
' "$1"; }
# has_slot <slot>: is that keyslot in the header now? Fails (2) when the header cannot be read.
has_slot(){ local now; now="$(slots)" || return 2; case " ${now##*|} " in *" $1 "*) return 0;; esac; return 1; }
# salt_of <slot>: the salt of a keyslot's key derivation, which no other keyslot shares.
salt_of(){ cryptsetup luksDump --dump-json-metadata "$DEV" 2>/dev/null | python3 -I -c '
import json, re, sys
salt = ((json.load(sys.stdin).get("keyslots") or {}).get(sys.argv[1]) or {}).get("kdf", {}).get("salt")
if not isinstance(salt, str) or not re.fullmatch(r"[A-Za-z0-9+/=]{8,256}", salt):
    sys.exit(1)
print(salt)
' "$1"; }
# label <slot> <generation> [<the keyslot it replaces>]: mark a keyslot as the recovery key. The
# replaced keyslot is recorded by number AND by salt (see unfinished).
label(){ local mark="" salt
  if [ -n "${3:-}" ]; then salt="$(salt_of "$3")" || return 1; mark=",\"regalia_replaces\":\"$3\",\"regalia_replaces_salt\":\"$salt\""; fi
  printf '{"type":"systemd-recovery","keyslots":["%s"],"regalia_generation":%d%s}' "$1" "$2" "$mark" \
    | cryptsetup token import --json-file - "$DEV" >/dev/null 2>&1; }
# unlabel <slot>: remove the recovery token that names a keyslot, and leave the keyslot.
unlabel(){ local token; token="$(token_of "$1" 2>/dev/null)" || return 0
  cryptsetup token remove --token-id "$token" "$DEV" </dev/null >/dev/null 2>&1; }
# undo <slot>: take back a keyslot this run added, and the token that named it. IT DOES NOT TRUST
# ITSELF: after the attempt the header is read again.
#   0  the keyslot is gone and no empty recovery token is left: nothing was changed
#   2  the keyslot is gone, but an empty token could not be removed (it opens nothing; reported)
#   1  the keyslot is STILL THERE: the key just typed opens the disk. Said here, with the commands.
undo(){
  local token left; token="$(token_of "$1" 2>/dev/null)"
  kill_slot "$1"
  has_slot "$1"; case $? in
    1) ;;
    *) say "keyslot $1 of $DEV COULD NOT BE REMOVED and holds the key just typed: that key opens the disk."
       say "remove it by hand: cryptsetup luksKillSlot $DEV $1${token:+ ; cryptsetup token remove --token-id $token $DEV}"
       return 1;; esac
  # Whatever token named it is empty now. Found by looking, not by the id read before the kill: that
  # read can fail, and a second undo (after a signal) would not find it by keyslot any more.
  sweep; left="$(orphans)"
  [ -z "$left" ] || { say "keyslot $1 is removed, but an empty recovery token remains (it names no keyslot): cryptsetup token remove --token-id ${left%% *} $DEV"; return 2; }
  return 0; }
# take_back <slot> <what went wrong>: undo, then fail with a sentence that is true. A keyslot that
# was in the header BEFORE this run (ADOPTED: left unlabelled by a run that was killed, and picked up
# by this one) is not destroyed: only the label this run gave it is removed.
ADOPTED=""
take_back(){
  if [ "$ADOPTED" = "$1" ]; then
    unlabel "$1"; sweep; PENDING=""
    if token_of "$1" >/dev/null 2>&1; then
      fail "$2. Keyslot $1 was there before this run and is left in place, but the label this run gave it could NOT be removed: cryptsetup token remove --token-id $(token_of "$1") $DEV. See --status"
    fi
    fail "$2. Keyslot $1 was there before this run and is left as it was, unlabelled: it still holds the new key. See --status"
  fi
  undo "$1"; case $? in
    0) PENDING=""; fail "$2, and the keyslot was removed again. Nothing was changed";;
    2) PENDING=""; fail "$2, and the keyslot was removed again; the empty token named above is all that is left";;
    *) PENDING=""; exit 1;; esac; }
# PENDING is the keyslot this run has added (or adopted) and not yet proven. A signal in that state
# takes it back (bash runs the trap once the cryptsetup call in progress has returned). While it does
# so, further signals are IGNORED, a closed standard error included: an undo must not be cut short by
# a second Ctrl-C, or by the reader of `… 2>&1 | tee` having gone away. STAGE names the other moments
# at which the header has changed and a message is owed. A kill cannot be caught; --enrol and
# --replace find what it leaves behind on the next run (below).
PENDING=""; STAGE=""
interrupted(){
  trap '' INT TERM HUP PIPE
  local msg="" left
  if [ -n "$PENDING" ] && [ "$ADOPTED" = "$PENDING" ]; then
    unlabel "$PENDING"; sweep
    if left="$(token_of "$PENDING" 2>/dev/null)"; then
      msg="interrupted: keyslot $PENDING was there before this run and is left in place, but the label this run gave it could NOT be removed: cryptsetup token remove --token-id $left $DEV. See --status"
    else
      msg="interrupted: keyslot $PENDING was there before this run and is left as it was, unlabelled. See --status"
    fi
  elif [ -n "$PENDING" ]; then
    has_slot "$PENDING"; case $? in
      1) # not there: never added, or already removed by a rollback that this signal interrupted,
         # whose token may still be in the header, empty
         sweep; left="$(orphans)"
         if [ -z "$left" ]; then msg="interrupted: no keyslot of this run is in the header; nothing was changed"
         else msg="interrupted: no keyslot of this run is in the header, but an empty recovery token remains: cryptsetup token remove --token-id ${left%% *} $DEV"; fi;;
      *) undo "$PENDING"; case $? in
           0) msg="interrupted: keyslot $PENDING, added by this run, was taken back; nothing was changed";;
           2) msg="interrupted: keyslot $PENDING, added by this run, was taken back";;
           *) msg="interrupted, and keyslot $PENDING could not be taken back (see above)";; esac;; esac
  elif [ "$STAGE" = retiring ]; then
    msg="interrupted while the USED keyslot was being destroyed: the new key is enrolled. Run --status; if it shows two recovery keyslots, run --replace again with the same two keys"
  elif [ "$STAGE" = replaced ]; then
    msg="interrupted after the used keyslot was destroyed: the new key is the recovery key. Run --status, and --check with the new key"
  elif [ "$STAGE" = enrolled ]; then
    msg="interrupted after the recovery key was enrolled and proven: it is in the header. Run --status"
  fi
  [ -z "$msg" ] || say "$msg"
  exit 130; }
trap interrupted INT TERM HUP
# add <secret that opens the volume> <new key> <generation> [<the keyslot it replaces>]: a new keyslot for the key with its
# systemd-recovery token; the keyslot is left in ADDED (and in PENDING until the caller has proven
# it). The keyslot NUMBER is chosen here, from a header that was read successfully, and given to
# cryptsetup: so every later failure knows exactly which keyslot to take back.
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
    has_slot "$slot"; [ $? = 1 ] || take_back "$slot" "cryptsetup reported a failure after writing the keyslot"
    PENDING=""
    fail "cryptsetup refused to add the keyslot (does the first value open this volume with no keyslot named?). Nothing was changed"
  fi
  label "$slot" "$3" "${4:-}" || take_back "$slot" "the keyslot could not be marked as the recovery key"
  ADDED="$slot"; }
# proven <key> <slot>: the key opens that keyslot, AND opens the volume when no keyslot is named, which
# is how a boot prompt tries it (a keyslot whose priority is "ignore" passes the first test only).
proven(){ opens "$1" "$2" && ! ignored "$2" && opens "$1"; }
# retire <keyslot> <its token> <a key that opens another keyslot>: destroy a used recovery keyslot.
retire(){
  STAGE=retiring
  cryptsetup luksKillSlot --key-file <(printf '%s' "$3") "$DEV" "$1" </dev/null >/dev/null 2>&1
  has_slot "$1"; [ $? = 1 ] || fail "the USED keyslot $1 could not be destroyed: the used key still opens the disk. Run --replace again with the same two keys to finish, or by hand: cryptsetup luksKillSlot $DEV $1 ; cryptsetup token remove --token-id $2 $DEV"
  sweep; local left; left="$(orphans)"
  STAGE=replaced
  [ -z "$left" ] || fail "the used keyslot is destroyed but an empty recovery token remains (it names no keyslot): cryptsetup token remove --token-id ${left%% *} $DEV"; }

SNAPSHOT="$(slots)" || exit 1
IFS='|' read -r RECOVERY STRAY _ <<< "$SNAPSHOT"
COUNT="$(wc -w <<< "$RECOVERY")"
case "$MODE" in
status)
  echo "KEYSLOTS OF $DEV"; kinds
  if [ "$COUNT" -eq 2 ]; then
    if pair="$(unfinished)"; then say "2 recovery keyslots: a --replace that did not finish (keyslot ${pair#* } replaces ${pair% *}). Run --replace again with the used key and the new key, in that order; it destroys the used one"
    else say "2 recovery keyslots ($RECOVERY), and the header does not say that one replaces the other ($pair): a second recovery key was added by something else. Decide which to keep, then cryptsetup luksKillSlot $DEV <the other> and cryptsetup token remove"; fi
    exit 1
  fi
  [ "$COUNT" -eq 1 ] || { say "$COUNT recovery keyslots: a commissioned host has exactly one"; exit 1; }
  ! ignored "$RECOVERY" || { say "recovery keyslot $RECOVERY has priority 'ignore': a boot prompt would not try it. cryptsetup config --priority normal --key-slot $RECOVERY $DEV"; exit 1; }
  [ -z "$STRAY" ] || { say "keyslot $STRAY is a passphrase no token names (the installer's? a key left by an interrupted run?): once the TPM and the recovery key are proven, systemd-cryptenroll --wipe-slot=password $DEV"; exit 1; }
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
  opens "$A" || fail "that passphrase does not open $DEV; nothing was changed"
  # EVERY KEYSLOT NO TOKEN NAMES MUST BE OPENED BY WHAT WAS JUST TYPED. An --enrol that was killed
  # between adding its keyslot and marking it leaves the recovery key it was given as an unlabelled
  # passphrase, which still opens the disk; enrolling another key beside it would hide that. A second
  # passphrase somebody set on purpose looks the same from here, and is refused the same way.
  for s in $STRAY; do
    opens "$A" "$s" || fail "keyslot $s is a passphrase no token names, and it is not the one you typed. If it is a second passphrase you know, enrol with that volume reduced to one passphrase. If you do not know it, an --enrol that was interrupted may have left a recovery key there: cryptsetup luksKillSlot $DEV $s. Nothing was changed"
  done
  add "$A" "$B" 1
  proven "$B" "$ADDED" || take_back "$ADDED" "the new keyslot did not open with the key just typed"
  PENDING=""; STAGE=enrolled
  sweep
  STAGE=""
  say "ENROLLED: the recovery key is keyslot $ADDED of $DEV. Now run --check with the key read from the CARD."
  kinds >&2
  ;;
check)
  [ "$COUNT" -ne 2 ] || fail "$DEV has 2 recovery keyslots; see --status"
  [ "$COUNT" -eq 1 ] || fail "$DEV has $COUNT recovery keyslots, not one; see --status"
  ! ignored "$RECOVERY" || fail "recovery keyslot $RECOVERY has priority 'ignore': a boot prompt would not try it, whatever key it holds. cryptsetup config --priority normal --key-slot $RECOVERY $DEV"
  B="$(ask "The recovery key, read from the card (hidden): ")"
  well_formed "$B" "that value"
  opens "$B" "$RECOVERY" || fail "that key does NOT open the recovery keyslot ($RECOVERY) of $DEV. The card, or the escrow it was copied from, does not hold this host's key"
  opens "$B" || fail "that key opens keyslot $RECOVERY when it is named, but NOT the volume as a boot prompt tries it"
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
  LEFT=""
  if [ "$COUNT" -eq 2 ]; then
    # FINISHING A --replace THAT STOPPED between adding the new keyslot and destroying the used one
    # (a failure there, or a kill). Both keys open the disk in that state. WHICH KEYSLOT IS THE NEW ONE
    # is read from the header (the token that names the keyslot it replaces), never from the order the keys were
    # typed in: typed the wrong way round, the new key would be destroyed and the seen one kept.
    pair="$(unfinished)" || fail "$DEV has 2 recovery keyslots ($RECOVERY), and the header does not say they are a --replace that stopped ($pair): this script will not guess which key to destroy. Decide by hand: cryptsetup luksKillSlot $DEV <the keyslot to remove>, then cryptsetup token remove. Nothing was changed"
    read -r old new <<< "$pair"
    if opens "$B" "$old" && opens "$A" "$new"; then
      fail "the key typed as USED opens the NEW keyslot ($new) and the key typed as new opens the used one ($old): they were typed in the wrong order. Nothing was changed"
    fi
    opens "$A" "$old" && proven "$B" "$new" \
      || fail "$DEV has 2 recovery keyslots, and these are not the used key of keyslot $old and the new key of keyslot $new; nothing was changed. See --status"
    old_token="$(token_of "$old")" || fail "cannot find the used keyslot's token; nothing was changed"
    retire "$old" "$old_token" "$B"
    slot="$new"; say "an unfinished --replace was completed: the used keyslot $old is destroyed"
  else
    ! ignored "$RECOVERY" || fail "recovery keyslot $RECOVERY has priority 'ignore', so the used key cannot authorise a new keyslot: cryptsetup config --priority normal --key-slot $RECOVERY $DEV. Nothing was changed"
    opens "$A" "$RECOVERY" || fail "that key does not open the recovery keyslot ($RECOVERY); nothing was changed"
    old_token="$(token_of "$RECOVERY")" || fail "cannot find the used keyslot's token; nothing was changed"
    generation="$(generation_of "$RECOVERY")" || fail "the used keyslot's token carries a generation this script did not write; nothing was changed. See cryptsetup luksDump $DEV"
    [ "$generation" -lt 2147483647 ] || fail "the used keyslot's token is at the last generation this script writes; nothing was changed. See cryptsetup luksDump $DEV"
    # A --replace that was KILLED between adding its keyslot and marking it left the new key in a
    # keyslot no token names. Given the same new key again, that keyslot is the one to mark: adding a
    # second would put the key in two keyslots and leave one unlabelled.
    for s in $STRAY; do
      if [ -z "$ADDED" ] && opens "$B" "$s"; then
        ADOPTED="$s"; PENDING="$s"
        label "$s" "$((generation + 1))" "$RECOVERY" || take_back "$s" "keyslot $s holds the new key (left by a --replace that was interrupted) but could not be marked as the recovery key"
        ADDED="$s"; say "keyslot $s already holds the new key (left by a --replace that was interrupted): using it"
      else LEFT="$LEFT $s"; fi
    done
    [ -n "$ADDED" ] || add "$A" "$B" "$((generation + 1))" "$RECOVERY"
    # The new key is proven BEFORE the used one is destroyed: at no moment is the host without a
    # recovery key that is known to open it.
    proven "$B" "$ADDED" || take_back "$ADDED" "the new keyslot did not open with the new key (the used key is still enrolled)"
    PENDING=""
    slot="$ADDED"
    retire "$RECOVERY" "$old_token" "$B"
  fi
  opens "$A" && fail "the used key STILL opens $DEV through another keyslot; look at cryptsetup luksDump $DEV"
  STAGE=""
  say "REPLACED: the new recovery key is keyslot $slot of $DEV; the used key opens nothing."
  [ -z "$LEFT" ] || say "WARNING: keyslot$LEFT is a passphrase no token names, and neither key typed here opens it (the installer's? a key from an abandoned --replace?). It still opens the disk: --status fails until it is removed"
  kinds >&2
  ;;
esac
