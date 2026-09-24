import unittest
from pathlib import Path

from tools import qualified_stack as qs

ROOT = Path(__file__).resolve().parents[1]


class QualifiedStackTests(unittest.TestCase):
    def setUp(self):
        self.stack = qs.load()

    def test_this_repositorys_go_mod_uses_the_qualified_token_libraries(self):
        # THE GATE: bumping piv-go or miekg/pkcs11 fails here until the new version has been through
        # the hardware drills and config/qualified-stack.json says so.
        self.assertEqual(qs.check_go_mod(self.stack, (ROOT / "go.mod").read_text()), [])

    def test_a_bumped_token_library_is_unqualified(self):
        bumped = (ROOT / "go.mod").read_text().replace("github.com/go-piv/piv-go/v2 v2.6.0", "github.com/go-piv/piv-go/v2 v2.7.0")
        problems = qs.check_go_mod(self.stack, bumped)
        self.assertEqual(len(problems), 1)
        self.assertIn("piv-go/v2 is v2.7.0, the qualified version is v2.6.0", problems[0])

    def test_go_mod_parsing_reads_single_line_and_block_requires(self):
        text = ("module x\n\nrequire github.com/a/b v1.0.0\n\nrequire (\n\tgithub.com/c/d v2.1.0 // indirect\n"
                "\tgithub.com/e/f v0.3.0\n)\n")
        self.assertEqual(qs.go_module_versions(text),
                         {"github.com/a/b": "v1.0.0", "github.com/c/d": "v2.1.0", "github.com/e/f": "v0.3.0"})

    def test_debian_versions_reduce_to_upstream(self):
        for debian, upstream in (("2.3.3-1", "2.3.3"), ("5.6.1+repack1-1", "5.6.1"), ("1:0.26.1-2", "0.26.1"), ("1.6.2-1", "1.6.2")):
            self.assertEqual(qs.upstream_version(debian), upstream)

    def test_token_listings_parse_as_measured_on_the_bench(self):
        self.assertEqual(qs.yubikey_firmwares("YubiKey 5 NFC (5.7.4) [OTP+FIDO+CCID] Serial: 35718625\n"),
                         [("YubiKey 5 NFC", "5.7.4", "35718625")])
        listing = ("# Detected readers (pcsc)\nNr.  Card  Features  Name\n0    No              Virtual PCD 00 00\n"
                   "3    Yes             Nitrokey Nitrokey HSM (DENK04043800000         ) 01 00\n")
        self.assertEqual(qs.smartcard_hsm_readers(listing), [("3", "DENK0404380")])
        self.assertEqual(qs.applet_version("Using reader with a card: …\nVersion              : 4.1\nConfig options       :\n"), "4.1")
        self.assertIsNone(qs.applet_version("no card"))

    def test_every_pinned_token_names_its_drill_evidence(self):
        for token in self.stack["tokens"]:
            with self.subTest(backend=token["backend"]):
                self.assertTrue(token["evidence"], "a qualified token with no drill record behind it")
                for path in token["evidence"]:
                    self.assertRegex(path, r"^doc/drills/\d{4}-\d{2}-\d{2}-[a-z0-9-]+\.md$")


if __name__ == "__main__":
    unittest.main()
