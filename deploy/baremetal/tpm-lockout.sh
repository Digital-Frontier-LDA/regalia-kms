#!/usr/bin/env bash
# tpm-lockout.sh — set, show and clear the KMS host TPM's dictionary-attack (lockout) settings (#57).
# Run ONCE per host at commissioning, as root, at the console.
#
#   sudo deploy/baremetal/tpm-lockout.sh --status     what the TPM has now; exit 1 unless it is the policy
#   sudo deploy/baremetal/tpm-lockout.sh --set        the policy below, and the lockout authorization
#   sudo deploy/baremetal/tpm-lockout.sh --clear      forgive every counted try (needs the authorization)
#
# WHY. The TPM counts failed authorizations and, at a limit, refuses every protected key until tries
# heal. A power cut counts as one: when a protected key was used since the last start and the TPM gets
# no TPM2_Shutdown, it adds a failed try at the next start. A KMS host uses such a key at every boot
# (systemd unseals the PIN credential through a primary key it creates each time), so a run of power
# cuts walks the counter up, and at the limit the PIN is not released and the KMS does not come back
# unattended (measured on swtpm, 2026-10-02: 3 cuts at swtpm's default limit of 3).
#
# THE POLICY (a recorded decision, #57; deploy/baremetal/host_probe.py measures it, tpm_lockout_policy):
#   32 failed tries before lockout
#   600 s for one try to heal        so power cuts are forgiven on their own, one every 10 minutes
#   86400 s lockout-hierarchy recovery   after a WRONG lockout authorization, the lockout hierarchy
#                                    refuses even the right one for a day. That is its own protection.
#
# THE LOCKOUT AUTHORIZATION is what lets someone change these settings or clear the counter. It must
# not stay empty: with an empty one, anyone on the host can. --set asks for a new one (16-32 printable
# characters, typed twice, hidden; or one line on stdin) when the TPM has none. It is a ceremony
# secret: generated and escrowed with the others, typed here from the escrow, never stored on the host.
# It never reaches argv or the environment of a command.
#
# --set changes nothing, and asks for nothing, when the TPM already has the policy and an
# authorization. If the settings drifted and an authorization is set, it asks for it ONCE: a wrong one
# costs a day (above), so read it from the escrow, do not guess.
#
# The TPM is the kernel resource manager's (/dev/tpmrm0, the tpm2-tools default). TPM2TOOLS_TCTI may
# name a private simulator, for tests; the raw /dev/tpm0 is refused.
set -uo pipefail
# Byte-wise character classes: in a UTF-8 locale a range such as [!-~] follows the locale's collation
# and refuses plain ASCII letters (measured, en_US.UTF-8).
export LC_ALL=C
MAX_TRIES=32; HEAL_SECONDS=600; LOCKOUT_RECOVERY=86400
fail(){ printf 'tpm-lockout: FAIL: %s\n' "$*" >&2; exit 1; }
say(){ printf 'tpm-lockout: %s\n' "$*" >&2; }
MODE=""
while [ $# -gt 0 ]; do case "$1" in
  --status|--set|--clear) [ -z "$MODE" ] || fail "one of --status, --set, --clear"; MODE="${1#--}"; shift;;
  -h|--help) sed -n '2,/^set -uo pipefail$/{/^set -uo pipefail$/!p}' "$0"; exit 0;;
  *) fail "unknown argument '$1' (see --help)";; esac; done
[ -n "$MODE" ] || fail "one of --status, --set, --clear is required (see --help)"
[ "$(id -u)" = 0 ] || fail "run as root (sudo)"
for t in tpm2_getcap tpm2_dictionarylockout tpm2_changeauth; do command -v "$t" >/dev/null || fail "$t is required (tpm2-tools)"; done
case "${TPM2TOOLS_TCTI:-}" in *tpm0|*"/dev/tpm0"*) fail "TPM2TOOLS_TCTI points at /dev/tpm0 (no resource manager); use /dev/tpmrm0";; esac

# prop <name>: one value of tpm2_getcap properties-variable, in decimal.
props=""
read_props(){ props="$(tpm2_getcap properties-variable 2>/dev/null)" || fail "cannot read the TPM (tpm2_getcap properties-variable)"; }
prop(){ local v; v="$(awk -v n="$1:" '$1==n{print $2; exit}' <<< "$props")"; [ -n "$v" ] || fail "the TPM did not report $1"; printf '%d' "$v"; }
is_policy(){ [ "$(prop TPM2_PT_MAX_AUTH_FAIL)" = "$MAX_TRIES" ] && [ "$(prop TPM2_PT_LOCKOUT_INTERVAL)" = "$HEAL_SECONDS" ] \
  && [ "$(prop TPM2_PT_LOCKOUT_RECOVERY)" = "$LOCKOUT_RECOVERY" ]; }
record(){ read_props; cat <<REC
TPM LOCKOUT SETTINGS
  failed tries before lockout : $(prop TPM2_PT_MAX_AUTH_FAIL)   (policy $MAX_TRIES)
  seconds for a try to heal   : $(prop TPM2_PT_LOCKOUT_INTERVAL)   (policy $HEAL_SECONDS)
  lockout-hierarchy recovery  : $(prop TPM2_PT_LOCKOUT_RECOVERY) s   (policy $LOCKOUT_RECOVERY)
  lockout authorization set   : $([ "$(prop lockoutAuthSet)" = 1 ] && echo yes || echo "NO (anyone on this host can change the above)")
  failed tries counted now    : $(prop TPM2_PT_LOCKOUT_COUNTER)
  in lockout                  : $([ "$(prop inLockout)" = 1 ] && echo "YES (no protected key is released)" || echo no)
REC
}
AUTH=""; AUTH2=""; trap 'AUTH=""; AUTH2=""' EXIT
# The authorization goes to the tools on their standard input (file:-), never as an argument.
ask_current(){
  if [ -t 0 ]; then
    say "the lockout authorization is asked for ONCE. A wrong one blocks the lockout hierarchy for $(prop TPM2_PT_LOCKOUT_RECOVERY) s."
    IFS= read -r -s -p "Lockout authorization, from the escrow (hidden): " AUTH; echo >&2
  else IFS= read -r AUTH || true; fi
  [ -n "$AUTH" ] || fail "no authorization given; nothing was tried on the TPM"; }

read_props
case "$MODE" in
status)
  record
  is_policy && [ "$(prop lockoutAuthSet)" = 1 ] && [ "$(prop inLockout)" = 0 ] || exit 1
  ;;
set)
  if [ "$(prop lockoutAuthSet)" = 1 ]; then
    if is_policy; then say "the TPM already has the policy and a lockout authorization; nothing to do"; record; exit 0; fi
    ask_current
    printf '%s' "$AUTH" | tpm2_dictionarylockout -Q -s -n "$MAX_TRIES" -t "$HEAL_SECONDS" -l "$LOCKOUT_RECOVERY" -p file:- >/dev/null 2>&1 \
      || fail "the TPM refused: a wrong lockout authorization (the lockout hierarchy is now blocked for its recovery time), or it was already blocked. Nothing was changed"
  else
    # No authorization yet: the settings first, with the empty one, so that nothing typed below can
    # be the reason they are refused; then the authorization.
    if [ -t 0 ]; then
      IFS= read -r -s -p "NEW lockout authorization, from the escrow (16-32 characters, hidden): " AUTH; echo >&2
      IFS= read -r -s -p "Again: " AUTH2; echo >&2
      [ "$AUTH" = "$AUTH2" ] || fail "the two entries differ; nothing was changed"
    else IFS= read -r AUTH || true; fi
    printable='^[[:graph:]]{16,32}$'
    [[ "$AUTH" =~ $printable ]] || fail "the lockout authorization must be 16-32 printable characters with no space; nothing was changed"
    tpm2_dictionarylockout -Q -s -n "$MAX_TRIES" -t "$HEAL_SECONDS" -l "$LOCKOUT_RECOVERY" >/dev/null 2>&1 \
      || fail "the TPM refused the settings with an empty lockout authorization; nothing was changed"
    printf '%s' "$AUTH" | tpm2_changeauth -Q -c lockout file:- >/dev/null 2>&1 \
      || fail "the settings are in place but the TPM refused the new lockout authorization: it is still EMPTY. Run --set again"
  fi
  AUTH=""; AUTH2=""
  read_props
  is_policy && [ "$(prop lockoutAuthSet)" = 1 ] || fail "the TPM does not report the policy after setting it"
  record
  ;;
clear)
  [ "$(prop lockoutAuthSet)" = 1 ] || fail "the lockout authorization is empty: run --set first (it sets one), then --clear"
  [ "$(prop TPM2_PT_LOCKOUT_COUNTER)" != 0 ] || { say "no failed try is counted; nothing to clear"; record; exit 0; }
  ask_current
  printf '%s' "$AUTH" | tpm2_dictionarylockout -Q -c -p file:- >/dev/null 2>&1 \
    || fail "the TPM refused: a wrong lockout authorization (the lockout hierarchy is now blocked for its recovery time), or it was already blocked. Nothing was cleared"
  AUTH=""
  record
  ;;
esac
