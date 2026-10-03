"""An authenticated test fixture is insufficient if tests skipped or hit the wrong runtime."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deploy.images.verify import VerificationError
from lab.appliance import python_regressions


class PythonRegressionBoundaries(unittest.TestCase):
    def test_missing_preload_legacy_api_and_extra_calls_cannot_pass_expat_gate(self):
        self.assertEqual(python_regressions.checked_expat_trace('REGALIA_EXPAT_SALT16_ACCEPTED\n'),
                         {'accepted_16_byte_calls': 1, 'legacy_calls': 0})
        for text in ('', 'XML parsing passed\n', 'REGALIA_EXPAT_LEGACY_SALT_ACCEPTED\n',
                     'REGALIA_EXPAT_SALT16_ACCEPTED\nREGALIA_EXPAT_LEGACY_SALT_ACCEPTED\n',
                     'REGALIA_EXPAT_SALT16_ACCEPTED\nREGALIA_EXPAT_SALT16_ACCEPTED\n',
                     'ERROR: ld.so: object cannot be preloaded\nREGALIA_EXPAT_SALT16_ACCEPTED\n'):
            with self.subTest(text=text), self.assertRaises(VerificationError):
                python_regressions.checked_expat_trace(text)

    def test_missing_ambiguous_skipped_failed_and_empty_execution_refuse(self):
        valid = {'tests_run': 2, 'errors': 0, 'failures': 0, 'skipped': 0,
                 'expected_failures': 0, 'unexpected_successes': 0}
        record = python_regressions.MARKER + json.dumps(valid)
        self.assertEqual(python_regressions.checked_result('upstream diagnostic\n' + record, 2), valid)
        for text in ('', record + '\n' + record):
            with self.subTest(text=text), self.assertRaises(VerificationError):
                python_regressions.checked_result(text, 2)
        for field in valid:
            changed = dict(valid, **{field: 0 if field == 'tests_run' else 1})
            with self.subTest(field=field), self.assertRaises(VerificationError):
                python_regressions.checked_result(python_regressions.MARKER + json.dumps(changed), 2)

    def test_failed_authentication_precedes_execution_and_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'not-created'
            with patch.object(python_regressions.python_source, 'validate', side_effect=VerificationError('refused')), \
                 patch.object(python_regressions.subprocess, 'run') as command:
                with self.assertRaises(VerificationError):
                    python_regressions.run(Path(temp), output)
                command.assert_not_called()
                self.assertFalse(output.exists())

    def test_uninstalled_runtime_refuses_before_package_lookup_or_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'not-created'
            with patch.object(python_regressions.python_source, 'validate', return_value={'status': 'verified'}), \
                 patch.object(python_regressions.sys, 'version_info', (3, 13, 5)), \
                 patch.object(python_regressions.subprocess, 'check_output') as command:
                with self.assertRaises(VerificationError):
                    python_regressions.run(Path(temp), output)
                command.assert_not_called()
                self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
