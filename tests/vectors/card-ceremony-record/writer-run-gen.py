"""regalia-86f: regenerate regalia-kms's tests/vectors/card-ceremony-record/writer-run/ with regalia-ceremony's REAL
writer (offline-keys card-record), driven exactly as test_card_record_writer.Writer drives it: a fresh 2-of-3 lab root
(ok.generate, real age; its shares are not kept), card_record(first=True), then card_record(). Kept: both records, the
state directory, the root. Usage: python3 gen.py CEREMONY_TESTS_DIR OUT_DIR"""
import json
import os
import shutil
import sys
import unittest

tests, out = sys.argv[1], sys.argv[2]
sys.path.insert(0, tests)
import test_card_record_writer as w  # noqa: E402

assert w.HAVE_AGE, "real age is required: the writer-run is the writer's real output"


class Gen(w.Writer):
    def runTest(self):
        first, first_path = self.sign(first=True)
        second, second_path = self.sign()
        lines = w.ok.read_signing_state(self.state, self.root)
        self.assertEqual(w.ok.card_record_current(json.load(open(second_path)), self.root, lines)["sequence"], 2)
        os.makedirs(os.path.join(out, "state"))
        for n, path in ((1, first_path), (2, second_path)):
            shutil.copyfile(path, os.path.join(out, "card-record-%d.record.json" % n))
        for name in sorted(os.listdir(self.state)):
            shutil.copyfile(os.path.join(self.state, name), os.path.join(out, "state", name))
        with open(os.path.join(out, "root.hex"), "w") as f:
            f.write(self.root + "\n")
        print("root", self.root, "state", sorted(os.listdir(self.state)))


result = unittest.TextTestRunner(verbosity=2).run(Gen())
sys.exit(0 if result.wasSuccessful() else 1)
