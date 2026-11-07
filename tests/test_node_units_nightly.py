"""The nightly backstop for node-units' paths filter (#694). The filter skips these jobs when only a Go package outside
it changes, by GA ruling (a full run per PR costs too much), and tools/nodeunitsguard names those packages. That is
safe only while a schedule runs every job unfiltered: this test holds the schedule in place, and holds every job to
running on it."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "node-units.yml"
CRON_FIELD = r"[\d*/,-]+"


def on_block(text):
    """The workflow's `on:` block, without comments: its events at two spaces of indentation."""
    m = re.search(r"^on:\n((?:(?:  .*)?\n)*)", text, re.M)
    return "\n".join(line for line in (m.group(1) if m else "").splitlines() if not line.lstrip().startswith("#"))


def schedules(text):
    """The cron expressions of the `schedule:` event, each a five-field expression."""
    m = re.search(r"^  schedule:\n((?:    .*\n?)*)", on_block(text) + "\n", re.M)
    crons = re.findall(r"^    - cron:\s*['\"]([^'\"]+)['\"]\s*$", m.group(1), re.M) if m else []
    return [c for c in crons if re.fullmatch(r"\s+".join([CRON_FIELD] * 5), c.strip())]


def job_conditions(text):
    """{job: its job-level `if:`} for each job under `jobs:`; a job with none maps to None."""
    body = text.split("\njobs:\n", 1)[1] if "\njobs:\n" in text else ""
    found, job = {}, None
    for line in body.splitlines():
        m = re.match(r"^  ([\w-]+):\s*$", line)
        if m:
            job = m.group(1)
            found[job] = None
        elif job and re.match(r"^    if:\s*", line):
            found[job] = line.split(":", 1)[1].strip()
    return found


def cancels(text):
    """The workflow's concurrency cancel-in-progress expression."""
    m = re.search(r"^concurrency:\n(?:  .*\n)*?  cancel-in-progress:\s*(.+)$", text, re.M)
    return m.group(1).strip() if m else None


class TheNightlyRunsEveryNodeUnitsJob(unittest.TestCase):

    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_the_workflow_runs_on_a_schedule(self):
        self.assertEqual(len(schedules(self.text)), 1, "node-units.yml has no nightly schedule: the Go packages "
                         "tools/nodeunitsguard names as nightly-only are then never run (#694)")

    def test_no_job_is_kept_off_the_schedule(self):
        jobs = job_conditions(self.text)
        self.assertGreaterEqual(len(jobs), 12, sorted(jobs))
        for job, condition in jobs.items():
            with self.subTest(job=job):
                self.assertIsNone(condition, "%s runs only when %s: the nightly must run every job" % (job, condition))

    def test_a_scheduled_run_is_never_cancelled_by_another(self):
        self.assertEqual(cancels(self.text), "${{ github.event_name == 'pull_request' }}")

    def test_the_readers_see_a_planted_workflow(self):
        planted = ("on:\n  # c\n  schedule:\n    - cron: '23 2 * * *'\n  push:\n    paths:\n      - a/**\n"
                   "concurrency:\n  group: g\n  cancel-in-progress: true\n\njobs:\n  a:\n    runs-on: x\n"
                   "  b:\n    if: github.event_name == 'push'\n    runs-on: x\n")
        self.assertEqual(schedules(planted), ["23 2 * * *"])
        self.assertEqual(schedules(planted.replace("  schedule:\n    - cron: '23 2 * * *'\n", "")), [])
        self.assertEqual(schedules(planted.replace("'23 2 * * *'", "'nightly'")), [])
        self.assertEqual(job_conditions(planted), {"a": None, "b": "github.event_name == 'push'"})
        self.assertEqual(cancels(planted), "true")


if __name__ == "__main__":
    unittest.main()
