"""regalia-kms-51: the tools offline-keys runs with a key on a descriptor take each flag exactly as written. Its allow-list
checks the exact tokens (--signer, --key-fd, --offline-session, ...); with argparse's default abbreviations, `--sig other`
or `--key-f 0` given after the allowed flag would be taken instead (the last one wins). allow_abbrev=False on the parser
and on every subcommand."""
import contextlib
import io
import unittest

from deploy.baremetal import manifest, uki


class ExactFlags(unittest.TestCase):
    def refused(self, main, argv, token):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
            main(argv)
        self.assertEqual(caught.exception.code, 2)
        self.assertIn("unrecognized arguments: %s" % token, err.getvalue())

    def test_manifest_sign_takes_no_abbreviation(self):
        base = ["sign", "--root-key", "ab" * 32, "--proposal", "/nonexistent", "--signer", "root", "--key-fd", "9",
                "--offline-session", "ab" * 16, "--state-dir", "/nonexistent", "--out", "/nonexistent/e.json", "--genesis"]
        for token, value in (("--sig", "revocation"), ("--key-f", "0"), ("--offline-sess", "cd" * 16)):
            with self.subTest(token=token):
                self.refused(manifest.main, base + [token, value], token)

    def test_uki_sign_takes_no_abbreviation(self):
        base = ["sign"] + [x for flag in ("--linux", "--initrd", "--cmdline", "--os-release", "--stub", "--pcrpkey", "--initrd-build",
                                          "--root-key", "--uname", "--record", "--second-record", "--out", "--initrd-cert",
                                          "--system-cert", "--secure-boot-cert") for x in (flag, "/nonexistent")]
        for token in ("--offline-sess", "--initrd-key-f", "--system-key-f"):
            with self.subTest(token=token):
                self.refused(uki.main, base + [token, "0"], token)


if __name__ == "__main__":
    unittest.main()
