"""deploy/baremetal/ekchain.py: a server's EK certificates against the pinned Infineon roots (regalia-kms-x6x).

The synthetic chains are tests/fixtures/ekchain/*.pem (make-synthetic.sh); the Infineon certificates are the
public ones ekroots/SOURCES.md names. Every negative test asserts the reason, not only the refusal."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from deploy.baremetal import ekchain

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "tests", "fixtures", "ekchain")
IFX = os.path.join(FIX, "infineon")
SERVERS = os.path.join(ekchain.PINS_DIR, "servers")
SWTPM_EK_NAME = "000b402c9638e48692ca206f6197b2fd81c1aec21afbe712d15888b6c8269fadcf7d"  # tpm2_readpublic on swtpm
AT_2017_10_08 = 1507420800


def cert(name):
    with open(os.path.join(FIX, name) if name.endswith(".pem") else os.path.join(IFX, name), "rb") as f:
        return ekchain.der_of(f.read(), name)


def synthetic_pins(directory, root="root.pem", ca_keys=("ica-2023.pem",)):
    """A PINS directory over the synthetic chain: `root` as both families' root, `ca_keys` their CA keys."""
    der = cert(root)
    with open(os.path.join(directory, "root.der"), "wb") as f:
        f.write(der)
    lines = ["root %s %s root.der" % (fam, hashlib.sha256(der).hexdigest()) for fam in ekchain.FAMILIES]
    for name in ca_keys:
        for fam in ekchain.FAMILIES:
            lines.append("ca-spki %s %s %s" % (fam, ekchain.spki_sha256(cert(name), name), name))
    with open(os.path.join(directory, "PINS"), "w") as f:
        f.write("\n".join(lines) + "\n")
    return directory


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="ekchain-test-")
        self.addCleanup(shutil.rmtree, self.d)

    def intake(self, ek="ek.pem", ca="ica-2023.pem", **kw):
        # synthetic_pins pins one root and CA key for both families, so the one chain serves both
        chain = (cert(ek), cert(ca))
        return ekchain.intake("server-9", {"rsa": chain, "ecc": chain}, pins_dir=kw.pop("pins", self.d), **kw)


class ThePins(unittest.TestCase):
    def test_the_committed_roots_are_the_pinned_infineon_roots(self):
        pins = ekchain.load_pins()
        for fam, cn in (("rsa", "Infineon OPTIGA(TM) RSA Root CA"), ("ecc", "Infineon OPTIGA(TM) ECC Root CA")):
            der = ekchain.pinned_root(pins, fam)
            out = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-issuer"], input=der,
                                 capture_output=True, check=True).stdout.decode()
            self.assertEqual(out.count("CN=" + cn), 2, out)  # self-signed
        self.assertEqual(pins["root"]["rsa"][0], "899e35474c9807eb4c7f2f7a12da0028fb250cd02154d0009fca7d9c66574f3b")
        self.assertEqual(pins["root"]["ecc"][0], "cfeb02fecd55ad7a73c6e1d11985d4c47dee248ab63dcb66091a2489660443c3")

    def test_both_issues_of_ca_029_have_the_pinned_key_and_verify_strictly_under_the_root(self):
        pins = ekchain.load_pins()
        for fam in ekchain.FAMILIES:
            for year in ("2017", "2023"):
                name = "%s-ca029-%s.der" % (fam, year)
                self.assertIn(ekchain.spki_sha256(cert(name), name), pins["ca_spki"][fam], name)
                with tempfile.TemporaryDirectory() as d:
                    for n, der in (("root.pem", ekchain.pinned_root(pins, fam)), ("ca.pem", cert(name))):
                        with open(os.path.join(d, n), "w") as f:
                            f.write(ekchain.pem_of(der))
                    p = subprocess.run(["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile",
                                        "root.pem", "ca.pem"], cwd=d, capture_output=True, text=True)
                self.assertEqual((p.returncode, p.stdout), (0, "ca.pem: OK\n"), name + p.stderr)

    def test_a_root_file_that_is_not_the_pinned_one_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            synthetic_pins(d)
            with open(os.path.join(d, "root.der"), "wb") as f:
                f.write(cert("root-other.pem"))
            with self.assertRaisesRegex(ekchain.Refused, "is not the pinned rsa root"):
                ekchain.pinned_root(ekchain.load_pins(d), "rsa")

    def test_a_malformed_pins_line_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            synthetic_pins(d)
            with open(os.path.join(d, "PINS"), "a") as f:
                f.write("root dsa 00 x.der\n")
            with self.assertRaisesRegex(ekchain.Refused, "PINS line"):
                ekchain.load_pins(d)


class TheChain(Base):
    def test_a_good_chain_is_verified_strictly_and_records_the_ek_name(self):
        synthetic_pins(self.d)
        record, findings = self.intake()
        self.assertEqual(findings, [])
        self.assertEqual(record["status"], "verified")
        self.assertEqual(record["ek_name"], SWTPM_EK_NAME)
        argv = record["families"]["rsa"]["openssl"]["argv"]
        self.assertIn("-x509_strict", argv)
        self.assertNotIn("-partial_chain", argv)
        self.assertTrue(record["families"]["rsa"]["openssl"]["stdout"].startswith("ek.pem: OK\n"))

    def test_openssl_sees_the_pinned_root_and_no_other_store(self):
        # A system store or an SSL_CERT_* variable would give openssl anchors PINS never named.
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw.get("env")))
            return subprocess.run(argv, **kw)
        os.environ["SSL_CERT_DIR"] = self.d
        self.addCleanup(os.environ.pop, "SSL_CERT_DIR", None)
        ekchain.openssl_verify(cert("root.pem"), cert("ica-2023.pem"), cert("ek.pem"), run=run)
        argv, env = calls[0]
        self.assertEqual(argv[:9], ["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-CAfile",
                                    "root.pem", "-untrusted", "ca.pem"])
        self.assertEqual(sorted(env), ["LC_ALL", "PATH"])

    # The pass conditions behind openssl's exit status (review of #709, M1): each one alone refuses, with its own
    # reason, and no ek_name. openssl verify itself is replaced; every other call runs for real.
    GOOD_CHAIN = ("ek.pem: OK\nChain:\ndepth=0:  (untrusted)\n"
                  "depth=1: C=XX, O=Synthetic, OU=TPM2.0, CN=Synthetic Manufacturing CA 029 (untrusted)\n"
                  "depth=2: C=XX, O=Synthetic, OU=Devices, CN=Synthetic Root CA\n")

    @staticmethod
    def faked_verify(rc, stdout, stderr=""):
        def run(argv, **kw):
            if argv[:2] == ["openssl", "verify"]:
                return subprocess.CompletedProcess(argv, rc, stdout, stderr)
            return subprocess.run(argv, **kw)
        return run

    def test_the_faked_good_chain_passes_so_each_fake_below_changes_one_thing(self):
        synthetic_pins(self.d)
        record, findings = self.intake(run=self.faked_verify(0, self.GOOD_CHAIN))
        self.assertEqual((findings, record["status"], record["ek_name"]), ([], "verified", SWTPM_EK_NAME))

    def test_ok_and_rc_0_but_depth_2_is_not_the_pinned_root_is_refused(self):
        synthetic_pins(self.d)
        other = self.GOOD_CHAIN.replace("depth=2: C=XX, O=Synthetic, OU=Devices, CN=Synthetic Root CA",
                                        "depth=2: C=XX, O=Elsewhere, CN=Another Root CA")
        record, findings = self.intake(run=self.faked_verify(0, other))
        self.assertEqual(record["status"], "refused")
        self.assertNotIn("ek_name", record)
        self.assertEqual(len(findings), 2)
        for fam, f in zip(ekchain.FAMILIES, findings):
            self.assertTrue(f.startswith("%s: openssl's chain is not EK -> CA -> the pinned root:\n" % fam), f)
            self.assertIn("CN=Another Root CA", f)
        self.assertFalse(record["families"]["rsa"]["openssl"]["chain_ends_at_root"])

    def test_rc_0_without_ok_is_refused(self):
        synthetic_pins(self.d)
        record, findings = self.intake(run=self.faked_verify(0, self.GOOD_CHAIN.replace("ek.pem: OK\n", "")))
        self.assertEqual(record["status"], "refused")
        self.assertNotIn("ek_name", record)
        self.assertEqual(len(findings), 2)
        for fam, f in zip(ekchain.FAMILIES, findings):
            self.assertTrue(f.startswith("%s: openssl verify -x509_strict refused the chain (rc 0): Chain:" % fam), f)

    def test_ok_on_stdout_with_rc_2_is_refused(self):
        synthetic_pins(self.d)
        record, findings = self.intake(run=self.faked_verify(2, self.GOOD_CHAIN, "error 2 at 1 depth lookup: x\n"))
        self.assertEqual(record["status"], "refused")
        self.assertNotIn("ek_name", record)
        self.assertEqual(findings, ["%s: openssl verify -x509_strict refused the chain (rc 2): error 2 at 1 depth "
                                    "lookup: x" % fam for fam in ekchain.FAMILIES])

    def test_both_families_are_required(self):
        # review of #709, L2: a run with one family left out must not record "verified"
        synthetic_pins(self.d)
        chain = (cert("ek.pem"), cert("ica-2023.pem"))
        for given, missing in (({"rsa": chain}, "ECC"), ({"ecc": chain}, "RSA")):
            with self.assertRaisesRegex(ekchain.Refused, r"^the %s EK certificate and its CA are required" % missing):
                ekchain.intake("server-9", given, pins_dir=self.d)
        with self.assertRaises(SystemExit) as e, contextlib.redirect_stderr(io.StringIO()) as usage:
            ekchain.main(["verify", "--server", "server-9", "--pins", self.d, "--rsa", os.path.join(FIX, "ek.pem"),
                          os.path.join(FIX, "ica-2023.pem")])
        self.assertEqual(e.exception.code, 2)
        self.assertIn("the following arguments are required: --ecc", usage.getvalue())

    def test_wrong_root_same_name_other_key_is_refused_by_openssl_and_no_ek_name(self):
        synthetic_pins(self.d, root="root-other.pem")
        record, findings = self.intake()
        self.assertEqual(record["status"], "refused")
        self.assertNotIn("ek_name", record)
        self.assertEqual(len(findings), 2)  # one per family
        # openssl looks the issuer up by name AND key id: a root with the name and another key is no issuer
        self.assertRegex(findings[0], r"rsa: openssl verify -x509_strict refused the chain \(rc 2\): .*"
                                      r"error 20 at 1 depth lookup: unable to get local issuer certificate")

    def test_partial_chain_a_ca_pinned_as_the_anchor_is_refused(self):
        # The anchor is the CA, not a root: what the 2026-11-03 drill ran with -partial_chain. Without it,
        # openssl must refuse; the same call WITH -partial_chain passes, so this test tells the two apart.
        synthetic_pins(self.d, root="ica-2023.pem")
        record, findings = self.intake()
        self.assertEqual(record["status"], "refused")
        self.assertNotIn("ek_name", record)
        self.assertRegex(findings[0], r"rc 2\): .*unable to get (local )?issuer certificate")
        with tempfile.TemporaryDirectory() as d:
            for n in ("ica-2023.pem", "ek.pem"):
                shutil.copy(os.path.join(FIX, n), d)
            p = subprocess.run(["openssl", "verify", "-x509_strict", "-no-CApath", "-no-CAstore", "-partial_chain",
                                "-CAfile", "ica-2023.pem", "ek.pem"], cwd=d, capture_output=True, text=True)
        self.assertEqual((p.returncode, p.stdout), (0, "ek.pem: OK\n"), p.stderr)

    def test_partial_chain_the_ca_missing_is_refused(self):
        synthetic_pins(self.d, ca_keys=("ica-2023.pem", "root.pem"))
        record, findings = self.intake(ca="root.pem")  # the root given in the CA's place: no CA 029 in the chain
        self.assertEqual(record["status"], "refused")
        self.assertRegex(findings[0], r"rc 2\): .*unable to get local issuer certificate")

    def test_swapped_ca_029_same_name_other_key_is_refused_before_openssl(self):
        synthetic_pins(self.d)
        record, findings = self.intake(ek="ek-other.pem", ca="ica-other.pem")
        self.assertEqual(record["status"], "refused")
        self.assertNotIn("openssl", record["families"]["rsa"])
        self.assertRegex(findings[0], r"rsa: the rsa issuing CA's key .* is not a pinned rsa CA key")

    def test_swapped_ca_029_the_other_familys_real_ca_is_refused(self):
        pins = ekchain.load_pins()
        ev, findings = ekchain.verify_family(pins, "ecc", cert("ek.pem"), cert("rsa-ca029-2023.der"))
        self.assertRegex(findings[0], r"ecc: the ecc issuing CA's key \(SPKI 31c0aa4f072f1d9e\.\.\.\) is not a pinned")
        ev, findings = ekchain.verify_family(pins, "rsa", cert("ek.pem"), cert("ecc-ca029-2023.der"))
        self.assertRegex(findings[0], r"rsa: the rsa issuing CA's key \(SPKI 942da2973e352388\.\.\.\) is not a pinned")

    def test_an_ek_the_pinned_ca_key_did_not_sign_is_refused(self):
        synthetic_pins(self.d)
        record, findings = self.intake(ek="ek-other.pem", ca="ica-2023.pem")
        self.assertRegex(findings[0], r"rc 2\): error 20 at 0 depth lookup: unable to get local issuer certificate")
        self.assertNotIn("ek_name", record)

    def test_one_family_failing_withholds_the_ek_name(self):
        synthetic_pins(self.d)
        record, findings = ekchain.intake("server-9", {"rsa": (cert("ek.pem"), cert("ica-2023.pem")),
                                                       "ecc": (cert("ek-other.pem"), cert("ica-2023.pem"))},
                                          pins_dir=self.d)
        self.assertEqual([f[:4] for f in findings], ["ecc:"])
        self.assertNotIn("ek_name", record)

    def test_a_hostname_is_not_a_server_name(self):
        synthetic_pins(self.d)
        with self.assertRaisesRegex(ekchain.Refused, "server-<n>"):
            ekchain.intake("kms-somewhere", {"rsa": (cert("ek.pem"), cert("ica-2023.pem"))}, pins_dir=self.d)


class TheEkName(Base):
    def test_template_l1_from_the_certificate_is_swtpms_createek_public_area(self):
        with open(os.path.join(FIX, "swtpm-ek-rsa.pub"), "rb") as f:
            blob = f.read()
        modulus, _ = ekchain.rsa_public(cert("ek.pem"), "ek")
        self.assertEqual(ekchain.ek_public_area_l1(modulus), ekchain.attest.public_area(blob, "swtpm EK"))
        self.assertEqual(ekchain.ek_name(cert("ek.pem"), blob), (SWTPM_EK_NAME, "tpm2_createek-public-area"))

    def test_an_ek_public_area_that_is_not_the_certificates_is_refused(self):
        synthetic_pins(self.d)
        with open(os.path.join(FIX, "swtpm-ek-rsa.pub"), "rb") as f:
            blob = bytearray(f.read())
        blob[-1] ^= 1
        record, findings = self.intake(ek_public=bytes(blob))
        self.assertEqual(record["status"], "refused")
        self.assertNotIn("ek_name", record)
        self.assertRegex(findings[0], "--ek-public is not the default-template RSA EK")


class AC3(unittest.TestCase):
    """A 2017 EK under a CA 029 certificate re-issued in 2023 under the same key. openssl's output is asserted
    verbatim: what it says is the answer."""

    def run_at(self, ca, attime):
        return ekchain.openssl_verify(cert("root.pem"), cert(ca), cert("ek.pem"), attime=attime)

    def test_today_the_2023_reissue_verifies_the_2017_ek(self):
        r = self.run_at("ica-2023.pem", None)
        self.assertEqual(r["rc"], 0, r)
        self.assertEqual(r["stdout"].splitlines()[0], "ek.pem: OK")
        self.assertTrue(r["chain_ends_at_root"], r["stdout"])

    def test_at_the_eks_issuance_only_the_2017_issue_verifies(self):
        r = self.run_at("ica-2023.pem", AT_2017_10_08)
        self.assertEqual(r["rc"], 2, r)
        self.assertIn("error 9 at 1 depth lookup: certificate is not yet valid", r["stderr"] + r["stdout"])
        r = self.run_at("ica-2017.pem", AT_2017_10_08)
        self.assertEqual((r["rc"], r["stdout"].splitlines()[0]), (0, "ek.pem: OK"), r)

    def test_the_two_issues_share_one_key_in_the_fixture_and_in_infineons(self):
        for a, b in (("ica-2017.pem", "ica-2023.pem"), ("rsa-ca029-2017.der", "rsa-ca029-2023.der"),
                     ("ecc-ca029-2017.der", "ecc-ca029-2023.der")):
            self.assertEqual(ekchain.spki_sha256(cert(a), a), ekchain.spki_sha256(cert(b), b))
            self.assertNotEqual(cert(a), cert(b))

    def test_server_1s_recorded_runs_on_the_real_certificates_say_the_same(self):
        with open(os.path.join(SERVERS, "server-1.json")) as f:
            runs = json.load(f)["ac3"]["runs"]
        for fam in ekchain.FAMILIES:
            for year, at, rc in (("2023", "now", 0), ("2017", "now", 0), ("2017", "2017-10-08", 0),
                                 ("2023", "2017-10-08", 2)):
                r = runs["%s ca029-%s at=%s" % (fam, year, at)]
                self.assertEqual(r["rc"], rc, (fam, year, at))
                self.assertNotIn("-partial_chain", r["argv"])
            self.assertIn("error 9 at 1 depth lookup: certificate is not yet valid",
                          runs["%s ca029-2023 at=2017-10-08" % fam]["stderr"])


class TheServerRecords(unittest.TestCase):
    def load(self, n):
        with open(os.path.join(SERVERS, "server-%d.json" % n)) as f:
            return json.load(f)

    def test_there_are_three_and_only_server_1_is_verified(self):
        self.assertEqual(sorted(os.listdir(SERVERS)), ["server-1.json", "server-2.json", "server-3.json"])
        for n in (2, 3):
            r = self.load(n)
            self.assertEqual((r["server"], r["status"]), ("server-%d" % n, "open"))
            self.assertNotIn("ek_name", r)
            self.assertNotIn("intake", r)

    def test_server_1_was_verified_against_the_current_pins_strictly(self):
        r = self.load(1)
        intake = r["intake"]
        pins = ekchain.load_pins()
        self.assertEqual((r["status"], intake["status"], intake["server"]), ("verified", "verified", "server-1"))
        self.assertEqual(intake["pins_sha256"], pins["sha256"], "PINS changed since server-1 was verified: re-run it")
        self.assertRegex(intake["ek_name"], r"^000b[0-9a-f]{64}$")
        self.assertEqual(sorted(intake["families"]), ["ecc", "rsa"])
        for fam, ev in intake["families"].items():
            self.assertEqual(ev["root_sha256"], pins["root"][fam][0])
            self.assertIn(ev["ca_spki_sha256"], pins["ca_spki"][fam])
            self.assertEqual(ev["openssl"]["rc"], 0)
            self.assertTrue(ev["openssl"]["stdout"].startswith("ek.pem: OK\n"))
            self.assertTrue(ev["openssl"]["chain_ends_at_root"])
            self.assertIn("-x509_strict", ev["openssl"]["argv"])
            self.assertNotIn("-partial_chain", ev["openssl"]["argv"])
        caps = r["captures"]["sha256"]
        self.assertEqual(intake["families"]["rsa"]["ek_cert_sha256"], caps["ek-0x1c00002.der"])
        self.assertEqual(intake["families"]["ecc"]["ek_cert_sha256"], caps["ek-0x1c0000a.der"])
        self.assertEqual(intake["families"]["rsa"]["ca_cert_sha256"], caps["ica-0x1c00002.der"])
        self.assertEqual(intake["families"]["ecc"]["ca_cert_sha256"], caps["ica-0x1c0000a.der"])


class TheCommand(Base):
    def test_exit_0_writes_a_verified_record_and_exit_1_a_refused_one(self):
        synthetic_pins(self.d)
        out_path = os.path.join(self.d, "record.json")
        ek = os.path.join(FIX, "ek.pem")
        args = ["verify", "--server", "server-9", "--pins", self.d, "--out", out_path, "--ecc", ek,
                os.path.join(FIX, "ica-2023.pem"), "--rsa", ek]
        err = io.StringIO()
        self.assertEqual(ekchain.main(args + [os.path.join(FIX, "ica-2023.pem")], err=err), 0, err.getvalue())
        with open(out_path) as f:
            self.assertEqual(json.load(f)["ek_name"], SWTPM_EK_NAME)
        err = io.StringIO()
        self.assertEqual(ekchain.main(args + [os.path.join(FIX, "ica-other.pem")], err=err), 1)
        self.assertIn("is not a pinned rsa CA key", err.getvalue())
        with open(out_path) as f:
            r = json.load(f)
        self.assertEqual(r["status"], "refused")
        self.assertNotIn("ek_name", r)

    def test_pins_checks_the_committed_roots(self):
        out = io.StringIO()
        self.assertEqual(ekchain.main(["pins"], out=out), 0)
        self.assertEqual(out.getvalue().count(": pinned"), 2)


if __name__ == "__main__":
    unittest.main()
