"""e2e-repro.yml (regalia-kms-9xw): the by-hand re-run of node-units.yml's three-node-leases job at one commit, on hosted
runners, under the GA's conditions (2026-11-25): read-only token, no secrets or environments, a full 40-hex SHA only,
at most 5 runs, one dispatch at a time. Its steps are node-units.yml's, held equal here, so a repro runs what CI runs."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
REPRO = ROOT / ".github" / "workflows" / "e2e-repro.yml"
NODE_UNITS = ROOT / ".github" / "workflows" / "node-units.yml"
TRUSTED = ".e2e-repro-trusted"


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

    def test_one_dispatch_runs_at_a_time_and_a_running_one_is_not_cancelled(self):
        """cancel-in-progress: false keeps a RUNNING dispatch; GitHub still keeps one pending run per group, so a third
        dispatch replaces the waiting one (the header says so)."""
        self.assertEqual(self.doc["concurrency"], {"group": "e2e-repro", "cancel-in-progress": False})
        self.assertIn("GitHub keeps ONE pending run per group", self.text)

    def test_the_commit_must_be_a_full_sha_and_the_runs_at_most_5(self):
        inputs = self.doc.get(True, self.doc.get("on"))["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["runs"]["options"], ["1", "2", "3", "4", "5"])
        self.assertEqual(inputs["runs"]["default"], "1", "a mis-click should cost one run, not five")
        [plan] = self.doc["jobs"]["plan"]["steps"]
        self.assertEqual(plan["env"], {"REF": "${{ inputs.ref }}", "RUNS": "${{ inputs.runs }}",
                                       "REPO": "${{ github.repository }}", "GH_TOKEN": "${{ github.token }}"})
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

    def test_setup_go_caches_nothing(self):
        """A dispatch runs in main's cache scope, so the dispatched commit must write no cache entry main could later
        read (CodeQL cache poisoning, #788): node-units' setup-go step, with caching off and nothing else changed."""
        setup, ci_setup = self.job["steps"][1], self.ci["steps"][1]
        self.assertEqual(setup["uses"], ci_setup["uses"])
        self.assertIs(setup["with"].get("cache"), False)
        self.assertEqual(setup["with"], dict(ci_setup["with"], cache=False))

    def test_its_steps_are_node_units_three_node_leases_steps(self):
        """Everything between setup-go and the diagnostics is node-units.yml's, value for value (each script's text
        exactly), and so are the runner and the timeout: a repro runs what CI runs."""
        self.assertEqual((self.job["runs-on"], self.job["timeout-minutes"]), (self.ci["runs-on"], self.ci["timeout-minutes"]))
        self.assertEqual(len(self.job["steps"]), len(self.ci["steps"]) + 1, "one step added: main's diagnostics checkout")
        self.assertEqual(self.job["steps"][2:-2], self.ci["steps"][2:-1])
        diag, ci_diag = self.job["steps"][-1], self.ci["steps"][-1]
        self.assertEqual({k: v for k, v in diag.items() if k not in ("with", "uses")},
                         {k: v for k, v in ci_diag.items() if k not in ("with", "uses")})
        self.assertEqual(diag["uses"], "./" + TRUSTED + "/" + ci_diag["uses"][2:])
        self.assertEqual(diag["with"], {"name": ci_diag["with"]["name"] + "-run-${{ matrix.run }}"})

    def test_no_action_code_comes_from_the_dispatched_commit(self):
        """CodeQL actions/cache-poisoning/poisonable-step (#788): every local action is MAIN's, from a sparse checkout of
        refs/heads/main into its own path, made just before it under the same condition, with no credentials kept."""
        local = [(i, s) for i, s in enumerate(self.job["steps"]) if s.get("uses", "").startswith("./")]
        self.assertEqual([s["uses"] for _, s in local], ["./" + TRUSTED + "/.github/actions/tpm-diagnostics"])
        for i, step in local:
            trusted = self.job["steps"][i - 1]
            self.assertEqual(trusted["uses"], self.job["steps"][0]["uses"])
            self.assertEqual(trusted["with"], {"ref": "refs/heads/main", "path": TRUSTED,
                                               "sparse-checkout": ".github/actions", "persist-credentials": False})
            self.assertEqual(trusted.get("if"), step.get("if"))

    def test_the_job_it_mirrors_still_runs_the_three_node_lease_test(self):
        """If node-units.yml's job is renamed or emptied, the equality above would hold vacuously: it is not."""
        scripts = "\n".join(step.get("run", "") for step in self.ci["steps"])
        self.assertRegex(scripts, re.escape("python3 -Es e2e/three-node-leases.py"))


SHA = "a" * 40
REPO_NAME = "owner/regalia-kms"
FAKE_GH = """#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$*" in
  *compare*) [ -n "$FAKE_COMPARE_RC" ] && exit "$FAKE_COMPARE_RC"; printf '%s\\n' "$FAKE_COMPARE";;
  *pulls*) [ -n "$FAKE_PULLS_RC" ] && exit "$FAKE_PULLS_RC"; printf '%s' "$FAKE_PULLS";;
  *) exit 99;;
esac
"""


class PlanRefusesAnyCommitNotFromThisRepository(unittest.TestCase):
    """The plan job's script itself, run under bash -e (as Actions runs it) with a stand-in `gh` that answers the two
    questions it asks: is the commit in main's history, and which open pull requests have which head from which repo.
    A fork's commit would run as root on the runner, in main's cache scope (council, #788): it is refused, and so is
    every commit GitHub cannot vouch for."""

    def run_plan(self, ref=SHA, runs="5", compare="behind", compare_rc="", pulls="", pulls_rc=""):
        [plan] = load(REPRO)["jobs"]["plan"]["steps"]
        with tempfile.TemporaryDirectory() as tmp:
            gh = Path(tmp) / "gh"
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            out, log = Path(tmp) / "output", Path(tmp) / "log"
            out.write_text("")
            log.write_text("")
            env = {"PATH": "%s:/usr/bin:/bin" % tmp, "REF": ref, "RUNS": runs, "REPO": REPO_NAME, "GH_TOKEN": "x",
                   "GITHUB_OUTPUT": str(out), "FAKE_LOG": str(log), "FAKE_COMPARE": compare,
                   "FAKE_COMPARE_RC": compare_rc, "FAKE_PULLS": pulls, "FAKE_PULLS_RC": pulls_rc}
            done = subprocess.run(["bash", "-e", "-c", plan["run"]], env=env, capture_output=True, text=True)
            return done.returncode, out.read_text(), log.read_text(), done.stderr

    def assert_refused(self, result, why):
        rc, output, _, stderr = result
        self.assertNotEqual(rc, 0)
        self.assertEqual(output, "", "a refused plan must give the matrix nothing to run")
        self.assertIn(why, stderr)

    def test_a_commit_in_mains_history_runs(self):
        """compare main...REF is `behind` (REF is an ancestor of main) or `identical`; the pulls are never asked."""
        for status in ("behind", "identical"):
            with self.subTest(status=status):
                rc, output, log, _ = self.run_plan(compare=status)
                self.assertEqual((rc, output), (0, "runs=[1,2,3,4,5]\n"))
                self.assertEqual(log, "api repos/%s/compare/heads/main...%s --jq .status\n" % (REPO_NAME, SHA))

    def test_the_head_of_an_open_pull_request_from_this_repository_runs(self):
        for status in ("ahead", "diverged"):
            with self.subTest(status=status):
                pulls = "%s other/fork open\n%s %s open\n" % ("b" * 40, SHA, REPO_NAME)
                rc, output, _, _ = self.run_plan(runs="2", compare=status, pulls=pulls)
                self.assertEqual((rc, output), (0, "runs=[1,2]\n"))

    def test_a_forks_pull_request_head_is_refused(self):
        """GitHub resolves a fork's commit in the repo network, so compare can say `ahead` for it: that alone is
        never enough, and a pull request from a fork does not vouch for it either."""
        for repo in ("other/regalia-kms", "-", REPO_NAME + "x"):
            for status in ("ahead", "diverged"):
                with self.subTest(head_repo=repo, status=status):
                    self.assert_refused(self.run_plan(compare=status, pulls="%s %s open\n" % (SHA, repo)),
                                        "neither in main's history nor the head of an open pull request")

    def test_a_commit_nobody_vouches_for_is_refused(self):
        """`ahead` (a commit main lacks, possibly a fork's) and `diverged` are refused unless an open same-repo
        pull request has exactly this head."""
        for status in ("ahead", "diverged"):
            with self.subTest(status=status):
                self.assert_refused(self.run_plan(compare=status, pulls="%s %s open\n" % ("b" * 40, REPO_NAME)),
                                    "neither in main's history nor the head of an open pull request")

    def test_the_head_must_match_whole_and_be_open(self):
        for pulls in ("%s %s closed\n" % (SHA, REPO_NAME), "%s %s open\n" % (SHA[:39], REPO_NAME),
                      "%s0 %s open\n" % (SHA, REPO_NAME), "x%s %s open\n" % (SHA, REPO_NAME)):
            with self.subTest(pulls=pulls):
                self.assert_refused(self.run_plan(compare="ahead", pulls=pulls),
                                    "neither in main's history nor the head of an open pull request")

    def test_github_not_answering_is_a_refusal(self):
        self.assert_refused(self.run_plan(compare_rc="1"), "could not say whether")
        self.assert_refused(self.run_plan(compare="ahead", pulls_rc="1"), "could not list the open pull requests")

    def test_a_malformed_input_is_refused_before_github_is_asked(self):
        for ref, runs in ((SHA[:39], "5"), (SHA.upper(), "5"), (SHA + "\n", "5"), ("main", "5"), (SHA, "6"), (SHA, "0")):
            with self.subTest(ref=ref, runs=runs):
                result = self.run_plan(ref=ref, runs=runs)
                self.assert_refused(result, "must be")
                self.assertEqual(result[2], "", "GitHub was asked about a malformed input")


if __name__ == "__main__":
    unittest.main()
