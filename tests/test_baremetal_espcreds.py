"""deploy/baremetal/espcreds.py: the PCR 12 that systemd-stub leaves from a host's ESP credentials. The value
itself is checked against a real boot by tests/test_baremetal_unlock_boot.py (UKI under OVMF); here, the
archive's form and the rules that decide what goes into it."""
import hashlib
import os
import subprocess
import tempfile
import unittest

from deploy.baremetal import espcreds

FILES = {"regalia.unlock-config.cred": b'{"node_id": "a"}', "regalia.boot-env.cred": b"BOOT_NIC=eth0\n",
         "regalia.unlock-local.cred": b"k" * 301}


class EspCredentials(unittest.TestCase):
    def test_the_archive_is_the_stubs_form(self):
        packed = espcreds.archive(FILES)
        self.assertEqual(len(packed) % 4, 0)
        self.assertTrue(packed.startswith(b"070701") and packed.endswith(b"TRAILER!!!\0\0\0\0"))
        # the leading directories (0555 then 0500), then the files in sorted order, 0400, mtime zero
        names = [packed[i + 110:packed.index(b"\0", i + 110)] for i in range(len(packed)) if packed[i:i + 6] == b"070701"]
        self.assertEqual(names, [b".extra", b".extra/global_credentials"] + [b".extra/global_credentials/" + n.encode() for n in sorted(FILES)]
                         + [b"TRAILER!!!"])
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["cpio", "-idm", "--quiet"], input=packed, cwd=d, check=True)
            for name, content in FILES.items():
                path = os.path.join(d, ".extra/global_credentials", name)
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), content)
                self.assertEqual(os.stat(path).st_mode & 0o7777, 0o400)
                self.assertEqual(os.stat(path).st_mtime, 0)

    def test_pcr12_is_one_extend_with_the_archives_digest(self):
        want = hashlib.sha256(bytes(32) + hashlib.sha256(espcreds.archive(FILES)).digest()).hexdigest()
        self.assertEqual(espcreds.pcr12(FILES), want)
        self.assertEqual(espcreds.pcr12({}), espcreds.ZERO)                    # no file: the stub extends nothing
        # the order the files were given in does not matter; their names and contents do
        self.assertEqual(espcreds.pcr12(dict(reversed(list(FILES.items())))), want)
        for changed in (dict(FILES, **{"regalia.boot-env.cred": b"BOOT_NIC=eth1\n"}), dict(FILES, **{"tmpfiles.extra.cred": b"x"}),
                        {k.replace("boot-env", "boot-env2"): v for k, v in FILES.items()}):
            self.assertNotEqual(espcreds.pcr12(changed), want)

    def test_what_the_stub_skips_is_not_measured(self):
        want = espcreds.pcr12(FILES)
        for skipped in (".hidden.cred", "README", "regalia.boot-env", "a" * 251 + ".cred.x", "café.cred", "b" * 252 + ".cred"):
            self.assertEqual(espcreds.pcr12(dict(FILES, **{skipped: b"x"})), want, skipped)
        self.assertNotEqual(espcreds.pcr12(dict(FILES, **{"UPPER.CRED": b"x"})), want)       # the suffix, in any case
        self.assertNotEqual(espcreds.pcr12(dict(FILES, **{"a" * 250 + ".cred": b"x"})), want)  # 255 characters: taken

    def test_the_record_names_what_pcr12_was_computed_from(self):
        record = espcreds.record(FILES)
        self.assertEqual(record["pcr12"], espcreds.pcr12(FILES))
        self.assertEqual([c["name"] for c in record["credentials"]], ["regalia.boot-env", "regalia.unlock-config", "regalia.unlock-local"])
        self.assertEqual(record["credentials"][2], {"file": "regalia.unlock-local.cred", "name": "regalia.unlock-local",
                                                    "sha256": hashlib.sha256(b"k" * 301).hexdigest(), "size": 301})


if __name__ == "__main__":
    unittest.main()
