"""The workflows' concurrency (2026-10-05): a pull request keeps one run, a new push cancelling its superseded one, so
the sessions' pushes do not starve the hosted runners; main and scheduled runs are never cancelled, not even while
pending (GitHub drops an older pending run of a group without cancel-in-progress), because every main run must finish."""
import glob
import os
import unittest

import yaml

WORKFLOWS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github", "workflows")
GROUP = "${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}"
CANCEL = "${{ github.event_name == 'pull_request' }}"


class Concurrency(unittest.TestCase):
    def test_a_pull_request_keeps_one_run_and_main_keeps_every_run(self):
        checked = []
        for path in sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml"))):
            name = os.path.basename(path)
            with open(path) as f:
                doc = yaml.safe_load(f)
            triggers = doc.get(True, doc.get("on"))          # YAML 1.1 reads the key `on` as True
            if name == "initrd-drift.yml":
                # its own: one drift report at a time, never cancelled
                self.assertEqual(doc["concurrency"], {"group": "initrd-drift", "cancel-in-progress": False})
                continue
            if "pull_request" not in triggers:
                continue
            with self.subTest(workflow=name):
                self.assertEqual(doc.get("concurrency"), {"group": GROUP, "cancel-in-progress": CANCEL})
            checked.append(name)
        self.assertIn("ci.yml", checked)


if __name__ == "__main__":
    unittest.main()
