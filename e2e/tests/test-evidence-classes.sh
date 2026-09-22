#!/usr/bin/env bash
# test-evidence-classes.sh — a run must say what CLASS of evidence it produced (regalia#439 item 7).
#
# WHY. A run used to end in a list of "ok" lines that say nothing about whether a real token was
# involved. That difference is the whole subject of regalia#435 and #439: a SoftHSM pass and a
# Nitrokey pass look identical in a log and mean entirely different things, and the qualification
# record is assembled by people reading these logs. Every divergence that has cost this project
# time — CKA_LOCAL on the Pico, the all-zero DKEK KCV, the absent device certificate — was a place
# where the model and the device disagree.
#
# The two rows that matter most are the negative ones: --plan must not claim evidence, and a run
# that FAILED must not claim it either. A trap that prints "EVIDENCE PRODUCED" after `set -e`
# aborted is a record of things that did not happen.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN="$HERE/../run.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
[ -r "$RUN" ] || { echo "no run.sh at $RUN" >&2; exit 1; }

hdr "every mode declares a class, and no mode is silent"
missing=""
for mode in docker native-vm pico-gate pico-nightly cosmos-hardware cosmos-devnet; do
  # The declaration must be inside that mode's arm, not merely somewhere in the file.
  arm="$(awk -v m="  $mode)" 'index($0,m)==1{f=1} f{print} f && /^    ;;$/{exit}' "$RUN")"
  grep -q 'evidence ' <<<"$arm" || missing="$missing $mode"
done
[ -z "$missing" ] && P "all six modes declare an evidence class" \
  || F "these modes declare none:$missing"

hdr "the classes are the three that mean different things"
for class in software emulated physical; do
  grep -q "evidence $class " "$RUN" && P "'$class' is used" || F "'$class' is never used"
done

hdr "--plan does not claim evidence, because nothing ran"
out="$(bash "$RUN" --plan --mode cosmos-hardware 2>&1)"
grep -q 'WOULD PRODUCE (nothing ran)' <<<"$out" \
  && P "a plan says it is a plan" || F "a plan claimed produced evidence: $(grep -i '=====' <<<"$out" | tail -1)"
grep -q 'NOTHING HERE TOUCHED A REAL TOKEN' <<<"$out" \
  && F "a plan lectured about hardware evidence it never attempted" \
  || P "…and does not moralise about a run that did not happen"

hdr "a FAILED run produces no evidence, and says so"
# docker mode without REGALIA_CEREMONY_DIR refuses — a real failure, mid-run, after the software
# arms have already been declared.
out="$(env -u REGALIA_CEREMONY_DIR bash "$RUN" --mode docker 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && P "the failing run exits non-zero (exit $rc)" || F "the failing mode exited 0"
grep -q 'RUN FAILED' <<<"$out" \
  && P "the summary heading says the run failed" \
  || F "a failed run printed a normal evidence heading: $(grep -i '=====' <<<"$out" | tail -1)"
grep -q 'A FAILED RUN PRODUCES NO EVIDENCE' <<<"$out" \
  && P "…and says plainly that none of it may be recorded" \
  || F "the failed run does not say its list is not evidence"
grep -q 'EVIDENCE PRODUCED' <<<"$out" \
  && F "the failed run also printed the success heading" || P "…and does not also claim success"

hdr "a software-and-emulator-only run warns it is not hardware evidence"
out="$(bash "$RUN" --plan --mode docker 2>&1)"
grep -q 'PHYSICAL' <<<"$out" && F "docker mode claimed PHYSICAL evidence" || P "docker mode claims none"

printf '\n\033[1m### RESULT\033[0m\n  %d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
