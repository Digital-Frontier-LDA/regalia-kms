"""A review must not silently reverse patches or bypass source authentication."""
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from deploy.images.verify import VerificationError
from lab.appliance import python_patch_review


class PythonPatchReviewBoundaries(unittest.TestCase):
    def test_series_rejects_redirects_options_duplicates_and_empty_input(self):
        self.assertEqual(python_patch_review.series_names(b'# disabled\nfix.patch\n'), ['fix.patch'])
        for value in (b'../escape.patch', b'/absolute.patch', b'fix.patch -p0',
                      b'fix.patch\nfix.patch', b'..', b'--reverse', b'# empty', b'dir\\fix.patch'):
            with self.subTest(value=value), self.assertRaises(VerificationError):
                python_patch_review.series_names(value)

    def test_authentication_failure_precedes_tools_and_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'not-created' / 'review'
            with patch.object(python_patch_review.python_source, 'validate', side_effect=VerificationError('refused')), \
                 patch.object(python_patch_review.subprocess, 'check_output') as command:
                with self.assertRaises(VerificationError):
                    python_patch_review.review(Path(temp), output)
                command.assert_not_called()
                self.assertFalse(output.parent.exists())

    def test_isolated_dispatcher_ignores_hostile_directory_and_python_environment(self):
        dispatcher = Path(__file__).resolve().parents[1] / 'tools/lab_cli.py'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ('json.py', 'argparse.py', 'tarfile.py'):
                (root / name).write_text('raise RuntimeError("hostile module imported")\n')
            environment = dict(os.environ, PYTHONPATH=temp, PYTHONHOME=temp,
                               PYTHONUSERBASE=temp, PYTHONSTARTUP=str(root / 'json.py'))
            command = [sys.executable, '-I', str(dispatcher), 'appliance-python-patch-review', '--help']
            result = subprocess.run(command, cwd=root, env=environment, text=True,
                                    capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('GNU patch executable', result.stdout)
            command[1] = '-Es'
            result = subprocess.run(command, cwd=root, env=environment, text=True,
                                    capture_output=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('REFUSED: use python3 -I', result.stderr)

    def test_real_patch_does_not_correct_reverse_direction(self):
        executable = shutil.which('gpatch') or shutil.which('patch')
        if executable is None or not subprocess.check_output([executable, '--version'], text=True).startswith('GNU patch '):
            self.skipTest('GNU patch required for the real command boundary')
        def archive(members):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:xz') as output:
                for name, content in members.items():
                    item = tarfile.TarInfo(name)
                    item.size = len(content)
                    output.addfile(item, io.BytesIO(content))
            return stream.getvalue()
        source_name = 'Python-3.13.16.tar.xz'
        debian_name = 'python3.13_3.13.5-2+deb13u5.debian.tar.xz'
        frozen = {source_name: archive({'Python-3.13.16/example.txt': b'old\n'}),
                  debian_name: archive({'debian/patches/series': b'fix.patch\n',
                                        'debian/patches/fix.patch': b'--- a/example.txt\n+++ b/example.txt\n@@ -1 +1 @@\n-old\n+new\n'})}
        fixture = {'debian_packaging_version': '3.13.5-2+deb13u5', 'files': {name: {'sha256': 'fixture', 'bytes': len(data)} for name, data in frozen.items()}}
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(python_patch_review.python_source, 'validate', return_value=fixture), \
             patch.object(python_patch_review.python_source, 'inputs', return_value=frozen):
            output = Path(temp) / 'review'
            report = python_patch_review.review(Path(temp), output, executable)
            self.assertEqual(report['patches'][0]['forward_exit'], 0)
            self.assertEqual(report['patches'][0]['reverse_exit'], 1)
            self.assertFalse(report['package_admitted'])
            self.assertFalse(report['production_approved'])
            self.assertTrue((output / 'patch-review.json').is_file())
            with self.assertRaises(VerificationError):
                python_patch_review.review(Path(temp), output, executable)


if __name__ == '__main__':
    unittest.main()
