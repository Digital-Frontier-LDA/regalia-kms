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

    def test_the_same_bytes_already_there_are_accepted_anything_else_is_refused(self):
        with open(self.esp + "/loader/credentials/regalia.boot-env.cred", "wb") as f:
            f.write(self.files["loader/credentials/regalia.boot-env.cred"])
        self.render()
        with open(self.esp + "/loader/credentials/regalia.unlock-config.cred", "wb") as f:
            f.write(b"another manifest's config")
        fresh = enrol.Journal(self.dir, "a")
        fresh.doc["steps"].pop("render")
        self.journal = fresh
        with self.assertRaisesRegex(enrol.Refused, "this enrolment did not write it"):
            self.render()
        with open(self.esp + "/loader/credentials/regalia.unlock-config.cred", "rb") as f:
            self.assertEqual(f.read(), b"another manifest's config")

    def test_a_path_outside_the_esp_is_refused(self):
        self.files = {"../../etc/passwd": b"x"}
        with self.assertRaisesRegex(enrol.Refused, "outside the ESP"):
            self.render()


if __name__ == "__main__":
    unittest.main()
