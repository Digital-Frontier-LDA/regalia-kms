"""e2e-repro.yml (regalia-kms-9xw): the by-hand re-run of node-units.yml's three-node-leases job at one commit, on hosted
runners, under the GA's conditions (2026-11-25): read-only token, no secrets or environments, a full 40-hex SHA only,
at most 5 runs, one dispatch at a time. Its steps are node-units.yml's, held equal here, so a repro runs what CI runs."""
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPRO = ROOT / ".github" / "workflows" / "e2e-repro.yml"
NODE_UNITS = ROOT / ".github" / "workflows" / "node-units.yml"


def load(path):
    with open(path) as f:
        return yaml.safe_load(f)


class Repro(unittest.TestCase):
    def setUp(self):
        self.text = REPRO.read_text()
        self.doc = load(REPRO)
        self.job = self.doc["jobs"]["three-node-leases"]
        self.ci = load(NODE_UNITS)["jobs"]["three-node-leases"]

    def test_it_is_dispatched_by_hand_only(self):
        triggers = self.doc.get(True, self.doc.get("on"))     # YAML 1.1 reads the key `on` as True
        self.assertEqual(list(triggers), ["workflow_dispatch"])

    def test_its_token_is_read_only_and_it_reaches_no_secret_or_environment(self):
        self.assertEqual(self.doc["permissions"], {"contents": "read"})
        for name, job in self.doc["jobs"].items():
            with self.subTest(job=name):
                self.assertNotIn("permissions", job)
                self.assertNotIn("environment", job)
        self.assertNotRegex(self.text, r"secrets\.")
        self.assertNotRegex(self.text, r"\benvironment:")

    def test_one_dispatch_at_a_time_never_cancelled(self):
        self.assertEqual(self.doc["concurrency"], {"group": "e2e-repro", "cancel-in-progress": False})

    def test_the_commit_must_be_a_full_sha_and_the_runs_at_most_5(self):
        inputs = self.doc.get(True, self.doc.get("on"))["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["runs"]["options"], ["1", "2", "3", "4", "5"])
        [plan] = self.doc["jobs"]["plan"]["steps"]
        self.assertEqual(plan["env"], {"REF": "${{ inputs.ref }}", "RUNS": "${{ inputs.runs }}"})
        self.assertIn('[[ "$REF" =~ ^[0-9a-f]{40}$ ]] || {', plan["run"])
        self.assertIn('[[ "$RUNS" =~ ^[1-5]$ ]] || {', plan["run"])
        self.assertEqual(self.job["needs"], "plan")
        self.assertEqual(self.job["strategy"]["matrix"]["run"], "${{ fromJSON(needs.plan.outputs.runs) }}")

    def test_no_input_is_expanded_inside_a_shell_script(self):
        """An input reaches a script through env only: `${{ inputs.* }}` inside `run:` would be script injection."""
        for name, job in self.doc["jobs"].items():
            for step in job["steps"]:
                with self.subTest(job=name, step=step.get("name") or step.get("uses")):
                    self.assertNotIn("${{ inputs", step.get("run", ""))

    def test_the_checkout_is_the_dispatched_commit_only(self):
        checkout, ci_checkout = self.job["steps"][0], self.ci["steps"][0]
        self.assertEqual(checkout["uses"], ci_checkout["uses"])
        self.assertEqual(checkout["with"], dict(ci_checkout["with"], ref="${{ inputs.ref }}"))

    def test_its_steps_are_node_units_three_node_leases_steps(self):
        """Everything between the checkout and the diagnostics is node-units.yml's, value for value (each script's text
        exactly), and so are the runner and the timeout: a repro runs what CI runs."""
        self.assertEqual((self.job["runs-on"], self.job["timeout-minutes"]), (self.ci["runs-on"], self.ci["timeout-minutes"]))
        self.assertEqual(len(self.job["steps"]), len(self.ci["steps"]))
        self.assertEqual(self.job["steps"][1:-1], self.ci["steps"][1:-1])
        diag, ci_diag = self.job["steps"][-1], self.ci["steps"][-1]
        self.assertEqual({k: v for k, v in diag.items() if k != "with"}, {k: v for k, v in ci_diag.items() if k != "with"})
        self.assertEqual(diag["with"], {"name": ci_diag["with"]["name"] + "-run-${{ matrix.run }}"})

    def test_the_job_it_mirrors_still_runs_the_three_node_lease_test(self):
        """If node-units.yml's job is renamed or emptied, the equality above would hold vacuously: it is not."""
        scripts = "\n".join(step.get("run", "") for step in self.ci["steps"])
        self.assertRegex(scripts, re.escape("python3 -Es e2e/three-node-leases.py"))


if __name__ == "__main__":
    unittest.main()
