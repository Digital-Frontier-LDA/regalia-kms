"""Exercise the actual one-node TODO gate with synthetic scenario output."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/node-units.yml"


class OneNodeTodos(unittest.TestCase):
    def gate(self, *ids, suffix_text=""):
        text = WORKFLOW.read_text()
        start = text.index("\n", text.index("# dx7.7 and dx7.8's steps are said as TODO"))
        end = text.index("      - name: Keep the software TPMs", start)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "one.log").write_text("".join(
                f"  \033[33mTODO\033[0m regalia-kms-dx7.{suffix}: pending plan{suffix_text}\n" for suffix in ids))
            return subprocess.run(["bash", "-e", "-c", text[start:end]], capture_output=True,
                                  env=dict(os.environ, RUNNER_TEMP=directory)).returncode

    def test_each_id_once_passes(self):
        self.assertEqual(self.gate(7, 8), 0)

    def test_missing_id_cannot_be_replaced_by_a_duplicate(self):
        for suffix in (7, 8):
            with self.subTest(suffix=suffix):
                self.assertNotEqual(self.gate(suffix, suffix), 0)

    def test_extra_or_missing_line_fails(self):
        self.assertNotEqual(self.gate(7, 8, 8), 0)
        self.assertNotEqual(self.gate(7), 0)

    def test_id_mentioned_in_another_todo_body_does_not_count(self):
        self.assertNotEqual(self.gate(7, suffix_text=" regalia-kms-dx7.8: mentioned only"), 0)
