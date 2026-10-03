"""e2e/lib/bench_cards.sh's gates, run against stand-in token tools (regalia-kms#174).

bench_gate and bench_reader_gate decide whether a PIN may be presented. Their own decisions are
tested here, with pkcs11-tool and opensc-tool replaced by scripts that print a chosen listing: the bench
runs showed them working on real cards, this pins what they refuse.
"""
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

LIB = Path(__file__).resolve().parents[1] / "e2e" / "lib" / "bench_cards.sh"

TWO = """Available slots:
Slot 0 (0x0): Nitrokey Nitrokey HSM (DENK04041440000         ) 01 00
  token label        : regalia-staging
  serial num         : DENK0404144
Slot 1 (0x4): Nitrokey Nitrokey HSM (DENK04043800000         ) 03 00
  token label        : regalia-staging-b
  serial num         : DENK0404380
"""
READERS = """# Detected readers (pcsc)
Nr.  Card  Features  Name
0    Yes             Nitrokey Nitrokey HSM (DENK04041440000         ) 01 00
1    Yes             Nitrokey Nitrokey HSM (DENK04043800000         ) 03 00
"""


class BenchGates(unittest.TestCase):

    def run_lib(self, script, listing=TWO, readers=READERS, cards=("DENK0404144", "DENK0404380")):
        with tempfile.TemporaryDirectory() as d:
            bin_dir = Path(d)
            (bin_dir / "listing").write_text(listing)
            (bin_dir / "readers").write_text(readers)
            for tool, src in (("pkcs11-tool", "listing"), ("opensc-tool", "readers")):
                path = bin_dir / tool
                path.write_text("#!/bin/sh\ncat '%s'\n" % (bin_dir / src))
                path.chmod(0o755)
            body = textwrap.dedent("""
                . '%s'
                BENCH_MODULE=/nonexistent/opensc-pkcs11.so
                %s
                %s
            """) % (LIB, "BENCH_CARDS=(%s)" % " ".join(cards) if cards else "", script)
            env = dict(os.environ, PATH="%s:%s" % (bin_dir, os.environ["PATH"]))
            done = subprocess.run(["bash", "-c", body], capture_output=True, text=True, env=env)
            return done.returncode, done.stderr

    def test_the_right_card_in_the_right_slot_passes(self):
        for slot in ("", "0x0", "0"):
            with self.subTest(slot=slot):
                rc, err = self.run_lib('bench_gate DENK0404144 %s' % slot)
                self.assertEqual(rc, 0, err)

    def test_what_the_gate_refuses(self):
        cases = {
            "another slot": ('bench_gate DENK0404144 0x4', TWO, ("DENK0404144", "DENK0404380")),
            "a serial that is a prefix": ('bench_gate DENK040438', TWO, ("DENK0404144", "DENK0404380")),
            "a card that is absent": ('bench_gate DENK0404547', TWO, ("DENK0404144", "DENK0404380")),
            "an extra slot beyond the isolated set": ('bench_gate DENK0404144', TWO, ("DENK0404144",)),
            "the serial in two slots": ('bench_gate DENK0404144', TWO.replace("DENK0404380\n", "DENK0404144\n"), ("DENK0404144", "DENK0404380")),
            "an empty listing": ('bench_gate DENK0404144', "", ("DENK0404144", "DENK0404380")),
            "no isolation was set up": ('bench_gate DENK0404144', TWO, ()),
            "a slot written with a leading zero": ('bench_gate DENK0404144 04', TWO, ("DENK0404144", "DENK0404380")),
        }
        for name, (script, listing, cards) in cases.items():
            with self.subTest(name):
                rc, err = self.run_lib(script, listing=listing, cards=cards)
                self.assertNotEqual(rc, 0, "%s: the gate let a PIN through" % name)

    def test_the_reader_gate_checks_the_index_against_the_serial(self):
        rc, err = self.run_lib("bench_reader_gate DENK0404144 0")
        self.assertEqual(rc, 0, err)
        for script in ("bench_reader_gate DENK0404144 1", "bench_reader_gate DENK0404144 7", "bench_reader_gate DENK0404547 0"):
            with self.subTest(script):
                rc, _ = self.run_lib(script)
                self.assertNotEqual(rc, 0)
        rc, _ = self.run_lib("bench_reader_gate DENK0404144 0", cards=())
        self.assertNotEqual(rc, 0, "the reader gate passed with no isolation set up")


if __name__ == "__main__":
    unittest.main()
