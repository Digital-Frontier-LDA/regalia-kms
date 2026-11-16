"""ci-gate (#715) is the one check that says "every CI job passed". It can only say that about the jobs in its
`needs`: a job left out of it can fail, or never run, while ci-gate is green. The gate's own step counts the jobs it
sees, but that count only catches an edit to `needs`; a NEW job that nobody adds to `needs` keeps the count right and
sits outside the gate (regalia-kms-5st L1, review of #715). This test reads ci.yml and holds the gate to every other
job, to a count that matches, and to running whatever its needs' results are."""
import copy
import os
import re
import unittest

import yaml

CI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "workflows", "ci.yml")
GATE = "ci-gate"


def gate_findings(doc):
    """Why ci-gate does not cover every job, as a list of reasons; empty when it does."""
    jobs = doc.get("jobs") or {}
    gate = jobs.get(GATE)
    if not isinstance(gate, dict):
        return ["ci.yml has no job %s" % GATE]
    needs = gate.get("needs") or []
    if isinstance(needs, str):
        needs = [needs]
    found = []
    for name in sorted(set(jobs) - {GATE} - set(needs)):
        found.append("the job %s is not in %s.needs, so it can fail while %s passes" % (name, GATE, GATE))
    for name in sorted(set(needs) - set(jobs)):
        found.append("%s.needs names %s, which is not a job" % (GATE, name))
    if len(needs) != len(set(needs)):
        found.append("%s.needs lists a job twice" % GATE)
    # Without always(), a failed need skips the gate, and a skipped required check is not a failing one.
    if "always()" not in str(gate.get("if", "")):
        found.append("%s runs only if %r, not always()" % (GATE, gate.get("if")))
    runs = " ".join(str(step.get("run", "")) for step in gate.get("steps", []))
    counts = re.findall(r'\[ "\$n" -eq (\d+) \]', runs)
    if len(counts) != 1:
        found.append("%s's step does not check its job count exactly once (found %r)" % (GATE, counts))
    elif int(counts[0]) != len(set(needs)):
        found.append("%s checks for %s jobs but needs %d" % (GATE, counts[0], len(set(needs))))
    if gate.get("continue-on-error") or any(step.get("continue-on-error") for step in gate.get("steps", [])):
        found.append("%s may fail without failing" % GATE)
    return found


class CIGateNeedsEveryJob(unittest.TestCase):
    def load(self):
        with open(CI) as f:
            return yaml.safe_load(f)

    def test_the_gate_needs_every_other_job(self):
        self.assertEqual(gate_findings(self.load()), [])

    def test_each_way_out_is_found(self):
        # Each edit below is one way the gate stops covering CI, applied to the real ci.yml. A finder that missed
        # one would let that edit through, so each must produce a finding (the control is the test above: the
        # unedited file produces none).
        def new_job(doc):
            doc["jobs"]["a-new-job"] = {"runs-on": "ubuntu-26.04", "steps": [{"run": "true"}]}

        def drop_need(doc):
            doc["jobs"][GATE]["needs"] = doc["jobs"][GATE]["needs"][1:]

        def drop_need_and_count(doc):
            needs = doc["jobs"][GATE]["needs"][1:]
            doc["jobs"][GATE]["needs"] = needs
            for step in doc["jobs"][GATE]["steps"]:
                step["run"] = re.sub(r'-eq \d+ \]', '-eq %d ]' % len(needs), str(step.get("run", "")))

        def phantom_need(doc):
            doc["jobs"][GATE]["needs"] = doc["jobs"][GATE]["needs"] + ["no-such-job"]

        def no_always(doc):
            del doc["jobs"][GATE]["if"]

        def wrong_count(doc):
            for step in doc["jobs"][GATE]["steps"]:
                step["run"] = re.sub(r'-eq \d+ \]', '-eq 99 ]', str(step.get("run", "")))

        def soft_fail(doc):
            doc["jobs"][GATE]["continue-on-error"] = True

        for edit in (new_job, drop_need, drop_need_and_count, phantom_need, no_always, wrong_count, soft_fail):
            with self.subTest(edit=edit.__name__):
                doc = copy.deepcopy(self.load())
                edit(doc)
                self.assertNotEqual(gate_findings(doc), [], "the edit %s was not found" % edit.__name__)


if __name__ == "__main__":
    unittest.main()
