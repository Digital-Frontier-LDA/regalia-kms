"""regalia-kms-dx7.8 review, round 9 (CodeRabbit MAJOR PRRT_kwDOUcLtQM67aM7A, comment 4687175119): the mutant control
that reopens the gap the fix closes. It rewrites deploy/baremetal/ownerunlock.py back to the round-8 shape -- the stamp
runs AFTER reattest returns, under a re-taken lock (the gap), and the post-check and the stamp bind only the
measurement's nonce (not the boot record's) -- then restores the fixed file.

Usage (run from the repo root, the worktree's):
  python3 tests/dx78_round9_mutant.py apply
  python3 -Es -m unittest -v tests.test_baremetal_owner_unlock.AttestBooted.test_an_unlock_after_verification_before_attest_booted_returns_is_not_the_boot   # must FAIL
  python3 tests/dx78_round9_mutant.py revert
  python3 -Es -m unittest -v tests.test_baremetal_owner_unlock.AttestBooted.test_an_unlock_after_verification_before_attest_booted_returns_is_not_the_boot   # OK

The committed ownerunlock.py is the FIX; this helper is the mutant that proves the new test catches the regression
(a mutant that reopens the gap or drops the boot-record binding). It edits the worktree's ownerunlock.py in place and
restores it; nothing of it is production."""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TARGET = os.path.join(ROOT, "deploy", "baremetal", "ownerunlock.py")

# (a) the reattest call: drop on_verified, stamp after under a re-taken lock (the gap). CALL_OLD is the
# current fixed call (the round-9 fix, with the manifest's AK name passed to the stamp); CALL_NEW is the
# round-8 shape (no on_verified, stamp after reattest under a re-taken lock).
CALL_OLD = (
    '        lease.reattest(attester, evidence, node_id, session_id, manifest, node, phase="system",\n'
    '                       on_verified=lambda state, record, old: attest_booted_stamp(state, record, old, evidence["nonce"],\n'
    '                                                                                  node["ak_name"]))'
)
CALL_NEW = (
    '        lease.reattest(attester, evidence, node_id, session_id, manifest, node, phase="system")\n'
    '        with attest.locked_state(state_path) as (state, save):\n'
    '            attest_booted_stamp(state, state["nodes"].get(node_id, {}), None, evidence["nonce"])\n'
    '            save()'
)
# (b) the post-check: measurement-only (drop the boot require)
POST_OLD = (
    '    with attest.locked_state(state_path) as (state, _):\n'
    '        measurement = state["nodes"].get(node_id, {}).get("measurement")\n'
    '        boot = state["nodes"].get(node_id, {}).get("boot")\n'
    '    require(isinstance(measurement, dict) and measurement.get("nonce") == evidence["nonce"],\n'
    '            "attest-booted could not bind the record: the state holds %s for %s, not the record this verification "\n'
    '            "wrote: run attest-booted again" % (measurement, node_id))\n'
    '    require(isinstance(boot, dict) and boot.get("nonce") == evidence["nonce"],\n'
    '            "attest-booted could not bind the record: the state\'s boot record names a different verification "\n'
    '            "than the one that wrote the stamped measurement: run attest-booted again")'
)
POST_NEW = (
    '    with attest.locked_state(state_path) as (state, _):\n'
    '        measurement = state["nodes"].get(node_id, {}).get("measurement")\n'
    '    require(isinstance(measurement, dict) and measurement.get("nonce") == evidence["nonce"],\n'
    '            "attest-booted could not bind the record: the state holds %s for %s, not the record this verification "\n'
    '            "wrote: run attest-booted again" % (measurement, node_id))'
)
# (c) the stamp: measurement-only (drop the boot-record binding)
STAMP_OLD = (
    '    require(record.get("measurement", {}).get("nonce") == nonce_hex,\n'
    '            "attest-booted could not bind the record: the state holds %s for the node, not the record this "\n'
    '            "verification wrote" % (record.get("measurement"),))\n'
    '    # The record\'s boot record is this verification\'s too: check_counters writes the consumed nonce on the boot\n'
    '    # record it writes, so a record that carries a measurement stamped by this call but a boot record written by\n'
    '    # another -- a concurrent verify that committed after this one\'s save, in the lock-free gap between the state\'s\n'
    '    # last write and attest_booted\'s read of it -- cannot hold a stamped measurement and an unlock\'s boot record\n'
    '    # together. (An unlock that commits BEFORE this call is overwritten by it: same boot, same session, same key;\n'
    '    # its record is old_measurement.)\n'
    '    require(record.get("boot", {}).get("nonce") == nonce_hex,\n'
    '            "attest-booted could not bind the record: the state\'s boot record names a different verification "\n'
    '            "than the one that wrote the stamped measurement: run attest-booted again")'
)
STAMP_NEW = (
    '    require(record.get("measurement", {}).get("nonce") == nonce_hex,\n'
    '            "attest-booted could not bind the record: the state holds %s for the node, not the record this "\n'
    '            "verification wrote" % (record.get("measurement"),))'
)


def main(argv):
    if len(argv) < 2 or argv[1] not in ("apply", "revert"):
        print(__doc__)
        return 2
    mode = argv[1]
    src = open(TARGET).read()
    if mode == "apply":
        # Apply each region when its ORIGINAL form is present (the fix). Replace the original, never the
        # mutated form: a region whose mutated form is a prefix of its original form (the stamp binding) would
        # otherwise match the fixed file and be skipped, leaving the mutant not what its docstring says.
        for old, new, tag in ((CALL_OLD, CALL_NEW, "call"), (POST_OLD, POST_NEW, "post-check"),
                              (STAMP_OLD, STAMP_NEW, "stamp binding")):
            if old in src:
                src = src.replace(old, new)
                print("applied %s" % tag)
            elif new in src:
                print("already applied (%s)" % tag)
            else:
                print("MUTANT FAILED: %s region not found (is the file the fix?)" % tag)
                return 1
        open(TARGET, "w").write(src)
        print("MUTANT APPLIED (reverted: run with 'revert')")
        return 0
    # revert: undo ONLY the known replacements (apply's inverse), leaving any unrelated edit in the worktree
    # alone (git checkout -- would discard an unstaged edit outside the three regions).
    for new, old, tag in ((CALL_NEW, CALL_OLD, "call"), (POST_NEW, POST_OLD, "post-check"),
                          (STAMP_NEW, STAMP_OLD, "stamp binding")):
        if new in src:
            if old in src:
                print("revert FAILED: %s region is ambiguous (both forms present)" % tag)
                return 1
            src = src.replace(new, old)
            print("reverted %s" % tag)
        elif old in src:
            print("already reverted (%s)" % tag)
        else:
            print("revert FAILED: %s region not found (is the file the fix or the mutant?)" % tag)
            return 1
    open(TARGET, "w").write(src)
    print("reverted (the three regions restored; unrelated edits preserved)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
