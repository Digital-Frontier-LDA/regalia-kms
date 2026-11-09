#!/usr/bin/env bash
# import-key-certify-mutants.sh — each refusal of e2e/import-key-certify-swtpm.sh is real (#702): with the check that
# refuses it disabled in a COPY of this tree, that case fails, and every other case still passes.
#
#   sudo -v && e2e/import-key-certify-mutants.sh
#
#   control   the unmodified copy: every case passes
#   binding   the AK-EK binding check off            -> case a (a software key, a software AK) is accepted
#   ek        the intake EK check off                -> case b (another TPM's certification) is accepted
#   name      the certified-Name check off           -> case c (a certification of another object) is accepted
#   missing   a missing certification accepted       -> case d (no certification) is accepted
# The tree under test is never modified: each mutant is an exact edit, made once, to deploy/baremetal/importkey.py in
# a private copy, refused if the text to edit is not there exactly once.
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

# run <label> [<old> <new>]: copy the tree, apply the edit, run the e2e; its output in $W/<label>.out
run(){
  local label="$1" t="$W/$1"; mkdir -p "$t"
  cp -a "$HERE/." "$t/" && rm -rf "$t/.git" || { F "$label: cannot copy the tree"; return 1; }
  if [ $# -eq 3 ]; then
    python3 -I -c '
import sys
p, old, new = sys.argv[1:]
s = open(p).read()
if s.count(old) != 1:
    sys.exit("the text to edit appears %d times, not once" % s.count(old))
open(p, "w").write(s.replace(old, new))' "$t/deploy/baremetal/importkey.py" "$2" "$3" || { F "$label: the mutation does not apply"; return 1; }
  fi
  (cd "$W" && "$t/e2e/import-key-certify-swtpm.sh" > "$W/$label.out" 2>&1)
}
# killed <label> <case header letter>: that case's line FAILs, and no other case's does
line_of(){ awk -v h="### $2 " 'index($0,h){on=1; next} /^.*### /{on=0} on && /(PASS|FAIL)/' "$W/$1.out"; }
killed(){ local label="$1" c="$2" others x
  line_of "$label" "$c" | grep -q FAIL || { F "$label: case $c still passes: the mutant survives"; sed 's/^/      /' "$W/$label.out" | tail -30; return; }
  others=""; for x in 0 a b c d; do [ "$x" = "$c" ] && continue; line_of "$label" "$x" | grep -q FAIL && others="$others $x"; done
  [ -z "$others" ] && P "$label: killed (case $c fails: $(line_of "$label" "$c" | grep FAIL | sed 's/.*FAIL //' | cut -c1-110)...)" \
    || F "$label: case $c fails, but so do cases$others: the mutant is not isolated"
}

echo "import-key-certify-mutants: $HERE"
run control
grep -q 'import-key-certify-swtpm: [0-9]* passed, 0 failed' "$W/control.out" \
  && P "control: $(tail -1 "$W/control.out")" || { F "control: the unmodified copy does not pass"; cat "$W/control.out"; }

run binding 'require(hmac.compare_digest(keep["ek_name"], ek_doc.hex())' 'require(True or hmac.compare_digest(keep["ek_name"], ek_doc.hex())'
killed binding a
run ek 'require(hmac.compare_digest(ek_doc.hex(), ek_name),' 'require(True or hmac.compare_digest(ek_doc.hex(), ek_name),'
killed ek b
run name 'require(c["name"] == name,' 'require(True or c["name"] == name,'
killed name c
run missing '    if document is None:
        raise Refused(' '    if document is None:
        return {"fingerprint": expected_fingerprint, "mutant": "accepted with no certification"}
    if False:
        raise Refused('
killed missing d

echo; echo "import-key-certify-mutants: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
