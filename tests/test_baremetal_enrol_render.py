"""regalia-node enrol commit's rendered ESP credentials (#190, #271): bootcreds.esp_files' files published under the
sealed files' rules (never replacing, journalled, resumable; the same bytes already there are accepted), then the
espcreds record of everything the stub will measure: the PCR 12 the peers must expect. esp_files is stood in for."""
import hashlib
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import bootcreds, enrol, espcreds


class Render(unittest.TestCase):
    def setUp(self):
        self.addCleanup(os.umask, os.umask(0o022))
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)
        self.dir, self.esp = self.d + "/enrol", self.d + "/esp"
        enrol._safe_directory(self.dir)
        enrol._ensure_trusted_dir(self.esp + "/loader/credentials")
        self.journal = enrol.Journal(self.dir, "a")
        self.files = {"loader/credentials/regalia.unlock-config.cred": b'{"config":1}',
                      "loader/credentials/regalia.boot-env.cred": b"BOOT_NIC_MAC=52:54:00:12:34:56\n"}
        with open(self.esp + "/loader/credentials/regalia.unlock-local.cred", "wb") as f:
            f.write(b"sealed\n")                                  # what the seal step left
        self.calls = []

    def esp_files(self, site, envelopes, root_key, device, anchor):
        self.calls.append((site, envelopes, root_key, device, anchor))
        return dict(self.files)

    def render(self):
        with unittest.mock.patch.object(bootcreds, "esp_files", self.esp_files):
            return enrol.render_credentials(self.journal, self.esp, {"site": 1}, {"envelope": 1}, "ab" * 32, "ANCHOR")

    def test_the_rendered_files_are_published_and_pcr12_covers_every_credential(self):
        record = self.render()
        self.assertEqual(self.calls, [({"site": 1}, [{"envelope": 1}], "ab" * 32, "/dev/disk/by-partlabel/regalia-root", "ANCHOR")])
        on_esp = {}
        for name in sorted(os.listdir(self.esp + "/loader/credentials")):
            with open(self.esp + "/loader/credentials/" + name, "rb") as f:
                on_esp[name] = f.read()
        self.assertEqual(on_esp["regalia.boot-env.cred"], self.files["loader/credentials/regalia.boot-env.cred"])
        self.assertEqual(record, espcreds.record(on_esp))
        self.assertEqual([c["file"] for c in record["credentials"]],
                         ["regalia.boot-env.cred", "regalia.unlock-config.cred", "regalia.unlock-local.cred"])
        journal = enrol.Journal(self.dir, "a")
        self.assertEqual(journal.get("espcreds")["pcr12"], record["pcr12"])
        self.assertEqual(journal.get("render")["files"]["loader/credentials/regalia.boot-env.cred"]["sha256"],
                         hashlib.sha256(self.files["loader/credentials/regalia.boot-env.cred"]).hexdigest())
        self.assertEqual(self.render(), record, "a rerun renders the same bytes and changes nothing")

    def test_a_rendered_file_is_replaced_and_a_none_is_removed(self):
        """regalia-kms-ed on #276: rendered files are public and re-derivable, so a resumed enrolment whose manifest
        moved on is not stranded by an earlier render; at B3, esp_files names the files that must be gone."""
        with open(self.esp + "/loader/credentials/regalia.unlock-config.cred", "wb") as f:
            f.write(b"an earlier manifest's config")
        with open(self.esp + "/loader/credentials/regalia.boot-nft.cred", "wb") as f:
            f.write(b"retired at B3")
        self.files["loader/credentials/regalia.boot-nft.cred"] = None
        self.files["loader/credentials/regalia.wg-boot-conf.cred"] = None          # absent already: nothing to do
        record = self.render()
        with open(self.esp + "/loader/credentials/regalia.unlock-config.cred", "rb") as f:
            self.assertEqual(f.read(), b'{"config":1}')
        self.assertFalse(os.path.exists(self.esp + "/loader/credentials/regalia.boot-nft.cred"))
        self.assertNotIn("regalia.boot-nft.cred", [c["file"] for c in record["credentials"]])
        self.assertIsNone(enrol.Journal(self.dir, "a").get("render")["files"]["loader/credentials/regalia.boot-nft.cred"])
        self.assertEqual([n for n in os.listdir(self.esp + "/loader/credentials") if n.endswith(".enrol-new")], [])

    def test_only_under_loader_credentials_or_efi_regalia(self):
        for path in ("../../etc/passwd", "/../x", "EFI/BOOT/BOOTX64.EFI", "loader/loader.conf", "loader/credentials",
                     "loader/credentials/../../x.cred", "..foo/x"):
            with self.subTest(path):
                self.files = {path: b"x"}
                with self.assertRaisesRegex(enrol.Refused, "outside loader/credentials/ and EFI/regalia/"):
                    self.render()
        self.files = {"/EFI/regalia/membership.json": b"[]", "loader/credentials/regalia.site.cred": b"site"}
        self.render()                                                     # B3's shapes (a leading slash is taken)
        self.assertEqual(enrol._rendered_path("Loader/Credentials/x.cred"), "Loader/Credentials/x.cred")   # FAT: no case
        self.assertTrue(os.path.exists(self.esp + "/EFI/regalia/membership.json"))


class WithTheRealRenderer(unittest.TestCase):
    """bootcreds.esp_files itself, against a HighWater on a fake TPM (as tests/test_baremetal_bootcreds.py does):
    the call's signature, and a stale chain refused with nothing written and no espcreds journalled."""

    def setUp(self):
        import tests.test_baremetal_bootcreds as bct
        import tests.test_baremetal_bootnet as bn
        import tests.test_baremetal_heartbeat as hbt
        from deploy.baremetal import membership as m, sitecfg
        self.addCleanup(os.umask, os.umask(0o022))
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.chmod(self.d, 0o755)
        self.dir, self.esp = self.d + "/enrol", self.d + "/esp"
        enrol._safe_directory(self.dir)
        self.journal = enrol.Journal(self.dir, "a")
        self.site, self.root = sitecfg.validate(bn.site()), hbt.pub(hbt.ROOT)
        self.anchor = m.HighWater("0x1500016", run=hbt.FakeTpm(), lock_path=self.d + "/hw.lock")
        self.anchor.define()
        self.envelopes = bct.chain(hbt.manifest(), hbt.manifest(c="QUARANTINED"))
        digests = m.Store._digests([m.accept_chain(None, self.envelopes[:i], self.root) for i in range(1, 3)])
        for epoch in (1, 2):
            self.anchor.anchor(epoch, digests)

    def test_the_anchored_chain_is_rendered_onto_the_esp(self):
        record = enrol.render_credentials(self.journal, self.esp, self.site, self.envelopes, self.root, self.anchor)
        self.assertEqual(sorted(c["file"] for c in record["credentials"]),
                         sorted("%s.cred" % n for n in __import__("deploy.baremetal.bootcreds", fromlist=["x"]).RENDERED))

    def test_a_stale_chain_writes_nothing(self):
        with self.assertRaisesRegex(Exception, "ROLLBACK|below"):
            enrol.render_credentials(self.journal, self.esp, self.site, self.envelopes[:1], self.root, self.anchor)
        self.assertFalse(os.path.exists(self.esp))
        self.assertIsNone(enrol.Journal(self.dir, "a").state("espcreds"))
        self.assertIsNone(enrol.Journal(self.dir, "a").state("render"))


if __name__ == "__main__":
    unittest.main()
