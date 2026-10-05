"""regalia-kms-51: the tools offline-keys runs with a key on a descriptor take each flag exactly as written. Its allow-list
checks the exact tokens (--signer, --key-fd, --offline-session, ...); with argparse's default abbreviations, `--sig other`
or `--key-f 0` given after the allowed flag would be taken instead, and so would an exact repeat (the last one wins).
keyfd.exact: no abbreviation, and every single-value option taken once, on the parser and every subcommand."""
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

    def test_a_flag_given_twice_is_refused(self):
        """regalia-kms-95: an EXACT repeat after the allowed flag (argparse would keep the last) is refused too."""
        base = ["sign", "--root-key", "ab" * 32, "--proposal", "/nonexistent", "--signer", "root", "--key-fd", "9",
                "--offline-session", "ab" * 16, "--state-dir", "/nonexistent", "--out", "/nonexistent/e.json", "--genesis"]
        for flag, value in (("--key-fd", "0"), ("--signer", "revocation"), ("--offline-session", "cd" * 16), ("--state-dir", "/tmp")):
            with self.subTest(flag=flag):
                err = io.StringIO()
                with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
                    manifest.main(base + [flag, value])
                self.assertEqual(caught.exception.code, 2)
                self.assertIn("%s given twice: each option is taken once" % flag, err.getvalue())
        uki_base = ["sign"] + [x for flag in ("--linux", "--initrd", "--cmdline", "--os-release", "--stub", "--pcrpkey", "--initrd-build",
                                              "--root-key", "--uname", "--record", "--second-record", "--out", "--initrd-cert",
                                              "--system-cert", "--secure-boot-cert") for x in (flag, "/nonexistent")]
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            uki.main(uki_base + ["--initrd-key-fd", "9", "--initrd-key-fd", "0"])
        self.assertIn("--initrd-key-fd given twice", err.getvalue())

    def test_uki_sign_takes_no_abbreviation(self):
        base = ["sign"] + [x for flag in ("--linux", "--initrd", "--cmdline", "--os-release", "--stub", "--pcrpkey", "--initrd-build",
                                          "--root-key", "--uname", "--record", "--second-record", "--out", "--initrd-cert",
                                          "--system-cert", "--secure-boot-cert") for x in (flag, "/nonexistent")]
        for token in ("--offline-sess", "--initrd-key-f", "--system-key-f"):
            with self.subTest(token=token):
                self.refused(uki.main, base + [token, "0"], token)


if __name__ == "__main__":
    unittest.main()
