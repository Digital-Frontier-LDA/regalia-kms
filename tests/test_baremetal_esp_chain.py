"""enrol.EspChain, the ESP's one membership-chain writer (#468), shared by node.esp_advance and reanchor.write_esp."""
import os
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import bootcreds, enrol
from deploy.baremetal import reanchor


class EspChain(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.esp = os.path.join(self.d, "esp")
        os.mkdir(self.esp, 0o755)
        self.target = os.path.join(self.esp, enrol._rendered_path(bootcreds.CHAIN_ON_ESP))
        self.trusted = unittest.mock.patch.object(enrol, "_ensure_trusted_dir",
                                                  lambda path, mode=0o755: os.makedirs(path, mode=mode, exist_ok=True))
        self.trusted.start()
        self.addCleanup(self.trusted.stop)

    def test_two_steps_nothing_written_until_write(self):
        w = enrol.EspChain(self.esp, b"chain-1")
        self.assertTrue(w.rewritten)
        self.assertFalse(os.path.exists(self.target))          # deciding wrote nothing
        self.assertTrue(w.write())
        with open(self.target, "rb") as f:
            self.assertEqual(f.read(), b"chain-1")

    def test_the_same_chain_is_not_rewritten(self):
        enrol.EspChain(self.esp, b"chain-1").write()
        with unittest.mock.patch.object(enrol, "_replace_esp", side_effect=AssertionError("rewritten")):
            w = enrol.EspChain(self.esp, b"chain-1")
            self.assertFalse(w.rewritten)
            self.assertFalse(w.write())

    def test_a_longer_file_is_not_taken_for_the_chain(self):
        os.makedirs(os.path.dirname(self.target), exist_ok=True)
        with open(self.target, "wb") as f:
            f.write(b"chain-1 and more")
        self.assertTrue(enrol.EspChain(self.esp, b"chain-1").rewritten)

    def test_a_link_is_refused_not_followed(self):
        os.makedirs(os.path.dirname(self.target), exist_ok=True)
        elsewhere = os.path.join(self.d, "elsewhere")
        with open(elsewhere, "wb") as f:
            f.write(b"chain-1")
        os.symlink(elsewhere, self.target)
        with self.assertRaisesRegex(enrol.Refused, "it is not followed"):
            enrol.EspChain(self.esp, b"chain-1")

    def test_a_fifo_is_refused_without_blocking(self):
        os.makedirs(os.path.dirname(self.target), exist_ok=True)
        os.mkfifo(self.target)
        with self.assertRaisesRegex(enrol.Refused, "is not a regular file"):
            enrol.EspChain(self.esp, b"chain-1")

    def test_a_write_that_does_not_read_back_is_refused(self):
        real = enrol._replace_esp
        w = enrol.EspChain(self.esp, b"chain-1")
        with unittest.mock.patch.object(enrol, "_replace_esp", lambda d, f, data: real(d, f, b"chain-2")), \
                self.assertRaisesRegex(enrol.Refused, "is not the one written"):
            w.write()

    def test_reanchor_writes_through_it_and_turns_its_refusals_into_its_own(self):
        envelopes = [{"manifest": {"epoch": 1}}]
        with unittest.mock.patch.object(reanchor.membership, "canonical", lambda e: b"chain-r"):
            self.assertTrue(reanchor.write_esp(self.esp, envelopes))
            self.assertFalse(reanchor.write_esp(self.esp, envelopes))
            os.unlink(self.target)
            os.symlink(os.path.join(self.d, "x"), self.target)
            with self.assertRaises(reanchor.Refused):
                reanchor.write_esp(self.esp, envelopes)


if __name__ == "__main__":
    unittest.main()
