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


# What a step's `if:` may test: its job's outcome so far. Anything else (an event, a ref, an input) could keep the
# step off the nightly, and is refused until it is reviewed here (#696 review, B1).
STEP_CONDITIONS = {"failure()", "always()", "cancelled()", "success()"}
# Each scheduled run must be a group of its own: a push to main must not replace a pending nightly (#696 review, B2).
GROUP = "${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}"


def step_conditions(text):
    """[(line number, condition)] for every `if:` below job level, with any ${{ }} wrapper removed."""
    body_start = text.index("\njobs:\n") if "\njobs:\n" in text else len(text)
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^( {5,})(?:- )?if:\s*(.+?)\s*$", line)
        if m and sum(len(x) + 1 for x in text.splitlines()[:n - 1]) >= body_start:
            cond = m.group(2)
            inner = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", cond)
            found.append((n, inner.group(1) if inner else cond))
    return found


def concurrency_group(text):
    m = re.search(r"^concurrency:\n(?:  .*\n)*?  group:\s*(.+)$", text, re.M)
    return m.group(1).strip() if m else None


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

    def test_no_step_is_kept_off_the_schedule(self):
        conditions = step_conditions(self.text)
        self.assertGreaterEqual(len(conditions), 10, conditions)
        for n, condition in conditions:
            if condition not in STEP_CONDITIONS:
                with self.subTest(line=n):
                    self.fail("node-units.yml:%d: a step runs only when %s: a step may test only its job's outcome "
                              "(%s), or the nightly may skip it" % (n, condition, ", ".join(sorted(STEP_CONDITIONS))))

    def test_a_scheduled_run_is_a_group_of_its_own(self):
        self.assertEqual(concurrency_group(self.text), GROUP,
                         "a scheduled run must fall back to its own run_id, or a push can replace a pending nightly")

    def test_the_readers_see_a_planted_workflow(self):
        planted = ("on:\n  # c\n  schedule:\n    - cron: '23 2 * * *'\n  push:\n    paths:\n      - a/**\n"
                   "concurrency:\n  group: g\n  cancel-in-progress: true\n\njobs:\n  a:\n    runs-on: x\n"
                   "  b:\n    if: github.event_name == 'push'\n    runs-on: x\n")
        self.assertEqual(schedules(planted), ["23 2 * * *"])
        self.assertEqual(schedules(planted.replace("  schedule:\n    - cron: '23 2 * * *'\n", "")), [])
        self.assertEqual(schedules(planted.replace("'23 2 * * *'", "'nightly'")), [])
        self.assertEqual(job_conditions(planted), {"a": None, "b": "github.event_name == 'push'"})
        self.assertEqual(cancels(planted), "true")
        self.assertEqual(concurrency_group(planted), "g")
        steps = planted + "    steps:\n      - if: failure()\n        run: x\n      - name: y\n        if: ${{ github.event_name != 'schedule' }}\n"
        self.assertEqual(step_conditions(steps), [(19, "failure()"), (22, "github.event_name != 'schedule'")])
        self.assertEqual(step_conditions("on:\n  push:\n        if: x\njobs:\n"), [])


if __name__ == "__main__":
    unittest.main()
