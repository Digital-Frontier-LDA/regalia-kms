#!/usr/bin/env python3
"""#495: the production drill runner (deploy/baremetal/drill.py), dry-run end to end on the three-node fixture
(e2e/lib/threenode.py): the same scenarios as on the real servers (drill.scenarios), their faults made by the fixture
(e2e/lib/drillfixture.py), judged at the LEASE level from the nodes' admission trails.

    REGALIA_UNLOCK_BIN=<built cmd/regalia-unlock> sudo --preserve-env=RUNNER_ENVIRONMENT,REGALIA_UNLOCK_BIN python3 -Es e2e/drill-dryrun.py

IT CHANGES THE MACHINE (namespaces, interfaces, loop devices, dm-crypt mappings, transient units), so it runs only on a
GitHub-hosted runner, or on a throwaway host whose /etc/machine-id is in REGALIA_THREE_NODE_HOST_OK.

  1  three nodes, every node leased; drill.preflight on what the fixture can show (three serving; an operator and a
     different witness): the hardware-only checks (iLO, collector, baseline, PIN retries) are not this tier's
  2  drill.run over S1 (c powered off, then on), S2 (b restarted), S3 (a cut off from the mesh, then healed), S4 (b and c
     powered off, quarantined by an owner-signed epoch; a alone under the owner's survivor authorization, signed on the
     fixture's SoftHSM token and installed with the shipped `survivor install`; then a root epoch lifts the quarantine
     and b and c return) and S5 (a rolling restart of a, b, c), each fault journaled before it is injected; each
     scenario PASSES on its lease-level predicates (drillfixture.LeaseJudge)
  3  nothing left pending in the fault journal, restore ran, and the report's canonical bytes and digest are made, the
     request-level predicates listed as NOT JUDGED in it (the fixture runs no KMS daemon: #495)
"""
import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "lib"))
import threenode                                     # noqa: E402
from threenode import sh, until                      # noqa: E402
import drillfixture                                  # noqa: E402
from deploy.baremetal import authtime, drill         # noqa: E402

passed, failed = 0, 0
SERVICES = ("sync", "wg-apply", "admission")


def ok(condition, text, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  \033[32mPASS\033[0m %s" % text)
    else:
        failed += 1
        print("  \033[31mFAIL\033[0m %s%s" % (text, (": %s" % (detail,)) if detail != "" else ""))
    sys.stdout.flush()


def header(text):
    print("\n\033[1m### %s\033[0m" % text)
    sys.stdout.flush()


def scenario(cluster, work):
    names = ["a", "b", "c"]
    header("1  three nodes, every node leased; preflight on what the fixture can show")
    cluster.build()
    for name in names:
        cluster.disk(name)
    for name in names:
        cluster.enrol(name)
    for name in names:
        cluster.start(name, SERVICES)
    for name in names:
        until(lambda: cluster.lease(name), 150, 3)
    checks = [("three-serving", lambda: (all(cluster.lease(n) for n in names), {n: bool(cluster.lease(n)) for n in names})),
              ("operator-and-witness", lambda: (True, "the CI job (operator) and this script's judge (witness): a dry run"))]
    try:
        results = drill.preflight(checks, required=("three-serving", "operator-and-witness"))
        ok(all(r["ok"] for r in results), "preflight: three serving, an operator and a witness (the hardware-only checks are not "
           "this tier's)", results)
    except drill.Refused as refusal:
        ok(False, "preflight", str(refusal))
        return

    header("2  drill.run: S1, S2, S3, S4 and S5 on the fixture, each fault journaled first")
    journal = drill.Journal(str(work / "faults.jsonl"))
    backend = drillfixture.Fixture(cluster, journal, SERVICES)
    plan = {"S1": "c", "S2": "b", "S3": "a", "S4": {"survivor": "a", "others": ["b", "c"]}, "S5": ["a", "b", "c"]}
    outcome = drill.run(drill.scenarios(backend, plan, drillfixture.LeaseJudge(cluster)), abort=lambda: None,
                        restore=lambda: journal.restore(backend.undoers()))
    for entry in outcome["scenarios"]:
        ok(entry.get("passed"), "%s: every lease-level predicate holds (%s)" % (entry["scenario"], ", ".join(sorted(entry.get("predicates", {})))),
           {name: p for name, p in entry.get("predicates", {}).items() if not p["ok"]})
    ok(outcome["stopped"] is None and len(outcome["scenarios"]) == 5, "the run ended by itself, all five scenarios run", outcome["stopped"])

    header("3  the journal empty, restore ran, the report made")
    restored = outcome["restored"]
    ok(journal.pending() == [] and isinstance(restored, tuple) and restored[1] == [],
       "nothing pending in the fault journal after the run, and restore had nothing left to fail", {"pending": journal.pending(), "restore": restored})
    data, digest = drill.report("dryrun-tier-n", "ci-operator", "ci-witness", {"passed": outcome["passed"], "scenarios": outcome["scenarios"]},
                                {"tier": "N (the three-node fixture)", "not_judged": list(drillfixture.NOT_JUDGED),
                                 "why": "the fixture runs no KMS daemon: the request-level predicates are not claimed (#495)"})
    ok(len(digest) == 64 and b'"not_judged"' in data, "the report's canonical bytes and SHA-256 %s, the request-level predicates listed as "
       "not judged" % digest[:16])


def main():
    try:
        machine = pathlib.Path("/etc/machine-id").read_text().strip()
    except OSError:
        machine = None
    if os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" and (not machine or os.environ.get("REGALIA_THREE_NODE_HOST_OK") != machine):
        print("drill-dryrun: refused: this changes the machine (namespaces, interfaces, loop devices, dm-crypt, transient units). "
              "It runs on a GitHub-hosted runner; on another throwaway host set REGALIA_THREE_NODE_HOST_OK to its /etc/machine-id.")
        return 2
    present = [p for p in ("/run/netns/" + threenode.SWITCH,) + tuple("/run/netns/e2e3-" + n for n in threenode.NAMES) if os.path.exists(p)]
    present += sh("systemctl", "list-units", "--all", "--plain", "--no-legend", threenode.UNIT_PREFIX + "*", check=False).stdout.split()[:1]
    present += [p for p in (os.path.join(authtime.RUN_DIR, "authtime.json"),) if os.path.lexists(p)]
    present += [authtime.RUN_DIR + " (not empty)"] if os.path.isdir(authtime.RUN_DIR) and os.listdir(authtime.RUN_DIR) else []
    if present:
        print("drill-dryrun: refused: %s exists: another run's leftovers, or this host's own, are here" % ", ".join(present))
        return 2
    if os.geteuid() != 0 or not os.access(os.environ.get("REGALIA_UNLOCK_BIN", "/nonexistent"), os.X_OK):
        print("drill-dryrun: run as root, with REGALIA_UNLOCK_BIN naming a built cmd/regalia-unlock")
        return 2
    work = pathlib.Path(tempfile.mkdtemp(prefix="three-node-", dir="/tmp"))   # where swtpm's AppArmor profile lets it write
    cluster = threenode.Cluster(work)
    try:
        scenario(cluster, work)
    except Exception:                     # noqa: BLE001 - a step that could not run is a failure, said once
        import traceback
        ok(False, "the scenario ran to its end", traceback.format_exc()[-1500:])
        for name in list(cluster.nodes):
            print("----- %s sync\n%s\n----- %s admission\n%s" % (name, cluster.journal(name, "sync"), name, cluster.journal(name, "admission")))
    finally:
        cluster.close()
        sh("rm", "-rf", "--", str(work), check=False)
        print("\ndrill-dryrun: %d passed, %d failed" % (passed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
