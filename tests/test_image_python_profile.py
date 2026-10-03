"""A changed upstream file must refuse before any downstream edit is made."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deploy.images.verify import VerificationError
from lab.appliance import python_profile


class PythonProfileBoundaries(unittest.TestCase):
    def test_changed_upstream_table_refuses_without_partial_edits(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            files = {'debian/control': b'control fixture\n',
                     'debian/patches/issue127330.diff': b'patch fixture\n',
                     'Modules/_ssl_data_31.h': b'upstream table fixture\n'}
            for name, data in files.items():
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(data)
            policy = {'schema': 'regalia.python-source-profile/v1', 'upstream': '3.13.16',
                      'packaging': '3.13.15-1',
                      'input_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
            path = root / 'policy.json'
            path.write_text(json.dumps(policy))
            (root / 'Modules/_ssl_data_31.h').write_bytes(b'changed table\n')
            with patch.object(python_profile, 'POLICY', path), self.assertRaises(VerificationError):
                python_profile.prepare(root)
            for name in ('debian/control', 'debian/patches/issue127330.diff'):
                self.assertEqual((root / name).read_bytes(), files[name])


if __name__ == '__main__':
    unittest.main()
