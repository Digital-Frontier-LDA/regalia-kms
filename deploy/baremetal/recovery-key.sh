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
# undo <slot>: take back a keyslot this run added, and the token that names it.
undo(){ local token; token="$(token_of "$1" 2>/dev/null)"; kill_slot "$1"
        [ -z "$token" ] || cryptsetup token remove --token-id "$token" "$DEV" </dev/null >/dev/null 2>&1; }
# add <secret that opens the volume> <new key>: a new keyslot for the key with its systemd-recovery
# token; prints the keyslot. The keyslot NUMBER is chosen here, from a header that was read
# successfully, and given to cryptsetup: so every later failure knows exactly which keyslot to take
# back, and a key never stays behind as an unlabelled passphrase.
add(){
  local snapshot used slot="" n
  snapshot="$(slots)" || exit 1
  used=" ${snapshot##*|} "
  for n in $(seq 0 31); do case "$used" in *" $n "*) ;; *) slot="$n"; break;; esac; done
  [ -n "$slot" ] || fail "every keyslot of $DEV is in use. Nothing was changed"
  cryptsetup luksAddKey --batch-mode "${KDF[@]}" --new-key-slot "$slot" --key-file <(printf '%s' "$1") "$DEV" <(printf '%s' "$2") >/dev/null 2>&1 \
    || fail "cryptsetup refused to add the keyslot (is the first value one that opens this volume?). Nothing was changed"
  if ! printf '{"type":"systemd-recovery","keyslots":["%s"]}' "$slot" | cryptsetup token import --json-file - "$DEV" >/dev/null 2>&1; then
    undo "$slot"
    fail "the keyslot could not be marked as the recovery key, and was removed again. Nothing was changed"
  fi
  printf '%s' "$slot"; }

SNAPSHOT="$(slots)" || exit 1
IFS='|' read -r RECOVERY STRAY _ <<< "$SNAPSHOT"
case "$MODE" in
status)
  echo "KEYSLOTS OF $DEV"; kinds
  n="$(wc -w <<< "$RECOVERY")"
  [ "$n" -eq 1 ] || { say "$n recovery keyslots: a commissioned host has exactly one"; exit 1; }
  [ -z "$STRAY" ] || { say "keyslot $STRAY is a passphrase no token names (the installer's?): once the TPM and the recovery key are proven, systemd-cryptenroll --wipe-slot=password $DEV"; exit 1; }
  ;;
enrol)
  [ -z "$RECOVERY" ] || fail "$DEV already has a recovery keyslot ($RECOVERY). To change the key use --replace; one host has one recovery key"
  A="$(ask "A passphrase that opens $DEV now (the installer's; hidden): ")"
  [ -n "$A" ] || fail "no passphrase given; nothing was changed"
  B="$(ask "The recovery key, from the KMS host recovery card (hidden): ")"
  if [ -t 0 ]; then C="$(ask "The recovery key again: ")"; [ "$B" = "$C" ] || fail "the two entries differ; nothing was changed"; fi
  well_formed "$B" "that value"
  [ "$A" != "$B" ] || fail "the passphrase and the recovery key are the same value; nothing was changed"
  slot="$(add "$A" "$B")" || exit 1
  opens "$B" "$slot" || { undo "$slot"; fail "the new keyslot did not open with the key just typed, and was removed again. Nothing was changed"; }
  say "ENROLLED: the recovery key is keyslot $slot of $DEV. Now run --check with the key read from the CARD."
  kinds >&2
  ;;
check)
  [ "$(wc -w <<< "$RECOVERY")" -eq 1 ] || fail "$DEV has $(wc -w <<< "$RECOVERY") recovery keyslots, not one; see --status"
  B="$(ask "The recovery key, read from the card (hidden): ")"
  well_formed "$B" "that value"
  opens "$B" "$RECOVERY" || fail "that key does NOT open the recovery keyslot ($RECOVERY) of $DEV. The card, or the escrow it was copied from, does not hold this host's key"
  say "OK: that key opens the recovery keyslot ($RECOVERY) of $DEV. Nothing was unlocked."
  say "It has now been typed at a console: after a REAL use, or a rehearsal with witnesses, --replace it."
  ;;
replace)
  [ "$(wc -w <<< "$RECOVERY")" -eq 1 ] || fail "$DEV has $(wc -w <<< "$RECOVERY") recovery keyslots, not one; see --status"
  A="$(ask "The recovery key that was USED (hidden): ")"
  well_formed "$A" "the used key"
  opens "$A" "$RECOVERY" || fail "that key does not open the recovery keyslot ($RECOVERY); nothing was changed"
  B="$(ask "The NEW recovery key, from the new card (hidden): ")"
  if [ -t 0 ]; then C="$(ask "The new recovery key again: ")"; [ "$B" = "$C" ] || fail "the two entries differ; nothing was changed"; fi
  well_formed "$B" "the new key"
  [ "$A" != "$B" ] || fail "the new key is the used key; nothing was changed"
  old_token="$(token_of "$RECOVERY")" || fail "cannot find the used keyslot's token; nothing was changed"
  slot="$(add "$A" "$B")" || exit 1
  # The new key is proven BEFORE the used one is destroyed: at no moment is the host without a
  # recovery key that is known to open it.
  opens "$B" "$slot" || { undo "$slot"; fail "the new keyslot did not open with the new key and was removed; the used key is still enrolled"; }
  cryptsetup luksKillSlot --key-file <(printf '%s' "$B") "$DEV" "$RECOVERY" >/dev/null 2>&1 \
    || fail "the new key is enrolled (keyslot $slot) but the USED keyslot $RECOVERY could not be destroyed: it still opens the disk. Destroy it: cryptsetup luksKillSlot $DEV $RECOVERY"
  cryptsetup token remove --token-id "$old_token" "$DEV" >/dev/null 2>&1 \
    || fail "the used keyslot is destroyed but its token $old_token remains: cryptsetup token remove --token-id $old_token $DEV"
  opens "$A" && fail "the used key STILL opens $DEV through another keyslot; look at cryptsetup luksDump $DEV"
  say "REPLACED: the new recovery key is keyslot $slot of $DEV; the used key opens nothing."
  kinds >&2
  ;;
esac
