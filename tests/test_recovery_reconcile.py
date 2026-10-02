"""Explicit operator choices must never delete unproved or unselected slots."""
import copy
import tempfile
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('recovery_reconcile', Path(__file__).resolve().parents[1] / 'deploy/baremetal/recovery-reconcile.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


def metadata():
    return {'keyslots': {'0': {'kdf': {'salt': 'installer'}}, '1': {'kdf': {'salt': 'old'}},
                         '2': {'kdf': {'salt': 'new'}}},
            'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['1']},
                       '1': {'type': 'systemd-recovery', 'keyslots': ['2']}}}


class CustodianSelection(unittest.TestCase):
    def test_wrong_retirement_card_causes_no_writes(self):
        with patch.object(module, 'header', return_value=metadata()), patch.object(module, 'proves', side_effect=[True, False]), patch.object(module, 'command') as call:
            with self.assertRaisesRegex(module.Refused, 'retired card'):
                module.reconcile('/fixture', '2', ['1'], 'new', ['wrong'])
            call.assert_not_called()

    def test_never_accepts_another_token_type_or_shared_token(self):
        for token in [{'type': 'systemd-tpm2', 'keyslots': ['2']}, {'type': 'systemd-recovery', 'keyslots': ['1', '2']}]:
            data = metadata(); data['tokens'] = {'0': token}
            with patch.object(module, 'header', return_value=data), patch.object(module, 'command') as call:
                with self.assertRaises(module.Refused): module.reconcile('/fixture', '2', ['1'], 'new', ['old'])
                call.assert_not_called()

    def test_ignored_or_unlabelled_keys_and_duplicate_owners_are_not_clean(self):
        data = metadata(); del data['keyslots']['0']; del data['keyslots']['1']; del data['tokens']['0']
        self.assertEqual(module.describe(data)['state'], 'clean')
        for change in ['ignored', 'unlabelled', 'duplicate', 'orphan']:
            trial = copy.deepcopy(data)
            if change == 'ignored': trial['keyslots']['2']['priority'] = 0
            if change == 'unlabelled': trial['keyslots']['3'] = {'kdf': {'salt': 'unknown'}}
            if change == 'duplicate': trial['tokens']['4'] = trial['tokens']['1']
            if change == 'orphan': trial['tokens']['4'] = {'type': 'systemd-recovery', 'keyslots': []}
            self.assertEqual(module.describe(trial)['state'], 'needs-review')


class ReconciliationLock(unittest.TestCase):
    def test_other_instance_cannot_lock_the_same_device_alias(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(module, 'LOCKDIR', Path(temp)):
            device = Path(temp) / 'device'; device.touch()
            alias = Path(temp) / 'alias'; alias.symlink_to(device)
            with module.instance_lock(device):
                with self.assertRaises(BlockingIOError):
                    with module.instance_lock(alias): pass
            with module.instance_lock(device): pass
