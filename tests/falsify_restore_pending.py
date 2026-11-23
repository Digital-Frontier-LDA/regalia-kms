"""regalia-kms-dx7.26 named controls: each guard of the restore-pending marker is broken on purpose and a named test must
FAIL for it (an assertion; an error or a skip does not count). Each named test is first run on the tree as it is and must
pass. Run from the checkout's root: python3 -Es tests/falsify_restore_pending.py

The files are mutated in place and restored in a finally; run it on a clean checkout. The e2e half (e2e/etcd-unit-sandbox.sh,
real systemd) is CI's: rootfs-reproducible.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
UNITS = ROOT / "deploy/baremetal/units"
ETCD_GUARD = UNITS / "regalia-etcd.service.d/10-restore-pending.conf"
KMS_GUARD = UNITS / "regalia-kms.service.d/10-restore-pending.conf"
RESTORE = ROOT / "deploy/baremetal/restore.py"
ENROL = ROOT / "deploy/baremetal/enrol.py"
# the tests as a namespace package, whatever else on this Python is called "tests"
BOOT = ("import os, sys, types, unittest; sys.path.insert(0, os.getcwd()); m = types.ModuleType('tests'); "
        "m.__path__ = [os.path.join(os.getcwd(), 'tests')]; sys.modules['tests'] = m; "
        "unittest.main(module=None, argv=['falsify'] + sys.argv[1:])")
GATE = "tests.test_baremetal_units.RestorePendingGate."
RUN = "tests.test_baremetal_restore.RestorePending."
ENROLLING = "tests.test_baremetal_single_node_enrol.RestorePendingAtEnrolment."
REFUSAL = "tests.test_baremetal_single_node_enrol.BootstrapRefusal."


def run(test):
    done = subprocess.run([sys.executable, "-Es", "-c", BOOT, "-v", test], cwd=ROOT, capture_output=True, text=True)
    return done.returncode, re.sub(r"\x1b\[[0-9;]*m", "", done.stdout + done.stderr)       # no colour: the lines are read


def skipped(output):
    return re.search(r"skipped=|\.\.\. skipped", output) is not None


def replaced(path, before, after):
    def apply():
        text = path.read_text()
        assert text.count(before) == 1, "%s: the mutation's anchor drifted: %r" % (path, before)
        path.write_text(text.replace(before, after))
    return apply


def removed(path):
    return lambda: path.unlink()


def renamed(path, name):
    return lambda: path.rename(path.with_name(name))


def control(name, mutate, tests, saved):
    try:
        mutate()
        for test in tests:
            code, output = run(test)
            short = test.rsplit(".", 1)[1]
            killed = (code != 0 and ("FAIL: %s " % short) in output and ("ERROR: %s " % short) not in output
                      and not skipped(output))
            print("%s: %s %s" % (name, "KILLED by" if killed else "INVALID OR SURVIVED", test), flush=True)
            if not killed:
                print(output, flush=True)
                raise SystemExit(1)
    finally:
        for path, text in saved.items():
            for stray in path.parent.glob("*restore-pending*"):
                if stray != path:
                    stray.unlink()
            path.write_text(text)


CONTROLS = [
    ("1 the etcd drop-in removed", removed(ETCD_GUARD), [GATE + "test_the_marker_holds_etcd_and_the_daemon_skipped"]),
    ("2 the daemon's drop-in removed", removed(KMS_GUARD), [GATE + "test_the_marker_holds_etcd_and_the_daemon_skipped"]),
    ("3 restore's drop-in without the reset", replaced(RESTORE, 'return ("[Unit]\\nConditionPathExists=\\nConditionPathExists=%s',
                                                      'return ("[Unit]\\nConditionPathExists=%s'),
     [GATE + "test_restore_s_drop_in_lifts_the_marker_for_etcd_alone"]),
    ("4 the reset without etcd.conf.yml listed again", replaced(RESTORE, '\\nConditionPathExists=%s\\nConditionPathExists=/etc/regalia/node.json',
                                                                 '\\nConditionPathExists=/etc/regalia/node.json%s'),
     [GATE + "test_restore_s_drop_in_lifts_the_marker_for_etcd_alone"]),
    ("5 restore run writes no marker", replaced(RESTORE, '        mark_pending(host, "restore run: no live store', '        0 and mark_pending(host, "restore run: no live store'),
     [RUN + "test_the_marker_is_durable_before_anything_stops_and_removed_only_once_exchanged", RUN + "test_a_refusal_before_staging_keeps_it_and_starts_nothing"]),
    ("6 the marker cleared before the exchange", replaced(RESTORE, "    try:\n        how = host.exchange(", "    clear_pending(host)\n    try:\n        how = host.exchange("),
     [RUN + "test_the_marker_is_durable_before_anything_stops_and_removed_only_once_exchanged", RUN + "test_a_failed_exchange_keeps_it"]),
    ("7 enrol writes it under --bootstrap", replaced(ENROL, '"restore etcd (restore.py run)" % marker, file=out)\n        return False', '"restore etcd (restore.py run)" % marker, file=out)'),
     [ENROLLING + "test_genesis_writes_nothing"]),
    ("8 enrol does not write it without --bootstrap", replaced(ENROL, "    if os.path.lexists(node_json):\n        return False", "    if True:\n        return False"),
     [ENROLLING + "test_a_replacement_writes_it_whole"]),
    ("9 the etcd drop-in sorts after 50-restore.conf", renamed(ETCD_GUARD, "restore-pending.conf"),
     [GATE + "test_the_marker_s_drop_in_sorts_before_restore_s_reset", GATE + "test_restore_s_drop_in_lifts_the_marker_for_etcd_alone"]),
    # COUNCIL on #775: --bootstrap is refused before any write when the verified chain proves non-genesis. One control per
    # arm; the guard-removed control kills the whole set at once.
    ("10 the --bootstrap refusal guard removed",
     replaced(ENROL, '    if bootstrap and (manifest["epoch"] != 1 or replace or sole\n'
                     '                      or first_epoch(chain if isinstance(chain, list) else [chain], root_key,\n'
                     '                                     journal.doc["node_id"]) is not None):\n',
               '    if False:\n'),
     [REFUSAL + "test_a_later_epoch_refuses_before_any_write", REFUSAL + "test_a_replacement_refuses_before_any_write",
      REFUSAL + "test_the_owners_revoked_sole_node_refuses_before_any_write",
      REFUSAL + "test_a_recorded_prior_heartbeat_refuses_before_any_write"]),
    ("11 the guard's epoch arm removed",
     replaced(ENROL, '(manifest["epoch"] != 1 or replace or sole', '(False or replace or sole'),
     [REFUSAL + "test_a_later_epoch_refuses_before_any_write"]),
    ("12 the guard's replacement arm removed",
     replaced(ENROL, 'or replace or sole\n', 'or (replace or sole) is True\n'),
     [REFUSAL + "test_a_replacement_refuses_before_any_write"]),
    ("13 the guard's recorded-heartbeat arm removed",
     replaced(ENROL, 'or first_epoch(chain if isinstance(chain, list) else [chain], root_key,\n'
                     '                                     journal.doc["node_id"]) is not None):',
               'or False):'),
     [REFUSAL + "test_a_recorded_prior_heartbeat_refuses_before_any_write"]),
]

if __name__ == "__main__":
    os.chdir(ROOT)
    saved = {p: p.read_text() for p in (ETCD_GUARD, KMS_GUARD, RESTORE, ENROL)}
    named = sorted({t for _, _, tests in CONTROLS for t in tests})
    for test in named:                               # the controls' own control: each passes on the tree as it is
        code, output = run(test)
        if code != 0 or skipped(output):
            print("NOT GREEN BEFORE ANY MUTATION: %s\n%s" % (test, output), flush=True)
            raise SystemExit(1)
    print("%d named tests green on the tree as it is" % len(named), flush=True)
    for name, mutate, tests in CONTROLS:
        control(name, mutate, tests, saved)
    print("all %d named mutants killed; no skips" % len(CONTROLS), flush=True)
    assert all(path.is_file() and path.read_text() == text for path, text in saved.items()), "a mutation was left in the tree"
