"""Lab entry commands must locate trusted code without ambient Python paths."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ENTRY = Path(__file__).resolve().parents[1] / 'tools/lab_cli.py'


class IsolatedLabEntry(unittest.TestCase):
    def test_isolation_is_required_and_command_is_bounded(self):
        for flags, command in (([], 'appliance-probe'), (['-I'], 'arbitrary.module')):
            result = subprocess.run([sys.executable, *flags, str(ENTRY), command, '--help'],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('Traceback', result.stderr)

    def test_cwd_and_pythonpath_modules_cannot_replace_standard_library(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); marker = root / 'injected'
            for name in ('json', 'socket', 'tempfile'):
                (root / (name+'.py')).write_text('open('+repr(str(marker))+',"w").write("injected")\nraise RuntimeError("injected")\n')
            env = {**os.environ, 'PYTHONPATH': directory, 'PYTHONUSERBASE': directory}
            result = subprocess.run([sys.executable, '-I', str(ENTRY), 'appliance-probe', '--help'],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('usage:', result.stdout)
            self.assertFalse(marker.exists())
