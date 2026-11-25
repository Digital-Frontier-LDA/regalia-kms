"""Exercise the actual one-node TODO gate with synthetic scenario output: since dx7.10.2 every step runs, so a step said
as TODO (counted neither as a pass nor as a failure) fails the job."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/node-units.yml"


class OneNodeTodos(unittest.TestCase):
    def gate(self, *lines):
        text = WORKFLOW.read_text()
        start = text.index("\n", text.index("# dx7.10.2: no step is said as TODO any more"))
        end = text.index("      - name: Keep the software TPMs", start)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "one.log").write_text("".join(line + "\n" for line in lines))
            return subprocess.run(["bash", "-e", "-c", text[start:end]], capture_output=True,
                                  env=dict(os.environ, RUNNER_TEMP=directory)).returncode

    def test_a_run_with_no_todo_passes(self):
        self.assertEqual(self.gate("  \033[32mPASS\033[0m a step that ran", "one-node: 41 passed, 0 failed"), 0)

    def test_any_todo_line_fails(self):
        for suffix in ("regalia-kms-dx7.7: re-anchor (not run)", "regalia-kms-dx7.8: planned outage (not run)", "anything else"):
            with self.subTest(suffix=suffix):
                self.assertNotEqual(self.gate("  \033[32mPASS\033[0m a step that ran", "  \033[33mTODO\033[0m " + suffix), 0)

    def test_todo_mentioned_inside_another_line_does_not_count(self):
        self.assertEqual(self.gate("  \033[32mPASS\033[0m no \033[33mTODO\033[0m step is left"), 0)


if __name__ == "__main__":
    unittest.main()
