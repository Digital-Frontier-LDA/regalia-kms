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

    def test_the_archive_bytes_are_pinned(self):
        """The bytes, pinned for one small input (a name in upper case first, 255 characters, the suffix in
        upper case): the computation was shown equal to systemd-stub 257 on a real boot (#215), and any change
        to it must change this vector knowingly. Each header field is also checked by itself."""
        files = {"regalia.boot-env.cred": b"BOOT_NIC=eth0\n", "B.cred": b"upper first", "a" * 250 + ".cred": b"long", "c.CRED": b"any case"}
        packed = espcreds.archive(files)
        self.assertEqual(hashlib.sha256(packed).hexdigest(), "fbb972fd14ec4b95efcc152b0d5e9da68c2dfe78c7857a33de256dd40ecf5356")
        self.assertEqual(espcreds.pcr12(files), "fe8000584a49374abc0f39d85a32870faa9d19175fc97ce59ec4413f1a36a1ee")
        headers, at = [], 0
        while True:
            h = packed[at:at + 110]
            fields = [int(h[6 + 8 * i:14 + 8 * i], 16) for i in range(13)]
            if packed[at + 110:at + 120] != b"TRAILER!!!":                          # (the trailer is the stub's literal, "B" in it)
                self.assertRegex(h[6:].decode(), r"\A[0-9a-f]{104}\Z")            # lower-case hex words
            name = packed[at + 110:at + 110 + fields[11] - 1]
            headers.append((name, fields))
            at = at + 110 + fields[11]
            at += -at % 4 + fields[6] + (-fields[6] % 4)
            if name == b"TRAILER!!!":
                break
        self.assertEqual(at, len(packed))
        names = [n for n, _ in headers]
        self.assertEqual(names[:2], [b".extra", b".extra/global_credentials"])
        self.assertEqual([n.rsplit(b"/", 1)[-1] for n in names[2:-1]], [b"B.cred", b"a" * 250 + b".cred", b"c.CRED", b"regalia.boot-env.cred"])
        for index, (name, f) in enumerate(headers[:-1]):
            inode, mode, uid, gid, nlink, mtime = f[:6]
            self.assertEqual((inode, uid, gid, nlink, mtime, f[7:11], f[12]), (index + 1, 0, 0, 1, 0, [0, 0, 0, 0], 0), name)
            self.assertEqual(mode, {0: 0o40555, 1: 0o40500}.get(index, 0o100400), name)
        self.assertEqual(headers[-1][1], [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0])
        self.assertTrue(packed.endswith(b"0000000B00000000TRAILER!!!\0\0\0\0"))

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
        for skipped in (".hidden.cred", "README", "regalia.boot-env", "a" * 251 + ".cred.x", "café.cred", "b" * 252 + ".cred", "c" * 251 + ".cred"):         # 256 characters: skipped
            self.assertEqual(espcreds.pcr12(dict(FILES, **{skipped: b"x"})), want, skipped)
        self.assertNotEqual(espcreds.pcr12(dict(FILES, **{"UPPER.CRED": b"x"})), want)       # the suffix, in any case
        self.assertNotEqual(espcreds.pcr12(dict(FILES, **{"a" * 250 + ".cred": b"x"})), want)  # 255 characters: taken

    def test_the_record_names_what_pcr12_was_computed_from(self):
        record = espcreds.record(FILES)
        self.assertEqual(record["pcr12"], espcreds.pcr12(FILES))
        self.assertEqual([c["name"] for c in record["credentials"]], ["regalia.boot-env", "regalia.unlock-config", "regalia.unlock-local"])
        self.assertEqual(record["credentials"][2], {"file": "regalia.unlock-local.cred", "name": "regalia.unlock-local",
                                                    "sha256": hashlib.sha256(b"k" * 301).hexdigest(), "size": 301})
        # measured by the stub, never imported by systemd (".cred" exactly): it has no name
        self.assertIsNone(espcreds.record({"X.CRED": b"x"})["credentials"][0]["name"])


if __name__ == "__main__":
    unittest.main()
