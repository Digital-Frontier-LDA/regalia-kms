"""The laboratory profile must reject changed inputs before editing anything."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lab.appliance import tpm_profile


class TPMProfileInputBoundary(unittest.TestCase):
    def test_changed_input_and_symlink_refuse_without_partial_edit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            inputs = {name: (old + "\n").encode() for name, [(old, new)] in
                      {"bootstrap": tpm_profile.REPLACEMENTS["bootstrap"],
                       "configure.ac": tpm_profile.REPLACEMENTS["configure.ac"]}.items()}
            inputs["Makefile.am"] = "\n".join(old for old, new in tpm_profile.REPLACEMENTS["Makefile.am"]).encode()
            digests = {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()}
            for name, data in inputs.items():
                (root / name).write_bytes(data)
            with patch.object(tpm_profile, "INPUTS", digests):
                (root / "Makefile.am").write_bytes(b"different source")
                with self.assertRaises(ValueError):
                    tpm_profile.apply(root)
                self.assertEqual((root / "bootstrap").read_bytes(), inputs["bootstrap"])
                (root / "Makefile.am").unlink()
                (root / "Makefile.am").symlink_to(root / "bootstrap")
                with self.assertRaises(ValueError):
                    tpm_profile.apply(root)
                self.assertEqual((root / "bootstrap").read_bytes(), inputs["bootstrap"])
