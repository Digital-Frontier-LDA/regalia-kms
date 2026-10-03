import unittest
from pathlib import Path
import importlib.util
spec = importlib.util.spec_from_file_location('recovery_matrix_fixture',Path(__file__).resolve().parents[1]/'lab/recovery/matrix.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
clean_recovery = module.clean_recovery


class RecoveryHeaderObserver(unittest.TestCase):
    def test_only_one_live_recovery_slot_with_no_orphan_or_extra_key_is_clean(self):
        good={'keyslots':['0','1'],'tokens':{'0':{'type':'systemd-recovery','keyslots':['1']}}}
        self.assertTrue(clean_recovery(good))
        for bad in (
            dict(good,priorities={'0':1,'1':0}),
            {'keyslots':['0','1'],'tokens':{}},
            {'keyslots':['0','1','2'],'tokens':good['tokens']},
            {'keyslots':['0','1'],'tokens':dict(good['tokens'],orphan={'type':'systemd-recovery','keyslots':[]})},
            {'keyslots':['0','1','2'],'tokens':dict(good['tokens'],second={'type':'systemd-recovery','keyslots':['2']})},
        ):
            with self.subTest(state=bad): self.assertFalse(clean_recovery(bad))

    def test_the_state_is_read_from_the_header_independently_of_the_script(self):
        header_state = module.header_state
        salt = {'kdf': {'salt': 'c2FsdC1vZi10aGUtdXNlZC1rZXlzbG90'}}
        recovery = lambda slot, **extra: dict({'type': 'systemd-recovery', 'keyslots': [slot]}, **extra)
        cases = {
            'no-recovery': {'keyslots': {'0': {}}, 'tokens': {}},
            'clean': {'keyslots': {'1': {}}, 'tokens': {'0': recovery('1')}},
            'orphan-keyslot': {'keyslots': {'0': {}, '1': {}}, 'tokens': {'0': recovery('1')}},
            'orphan-token': {'keyslots': {'1': {}}, 'tokens': {'0': recovery('1'), '1': {'type': 'systemd-recovery', 'keyslots': []}}},
            'added-unproven': {'keyslots': {'1': salt, '2': {}}, 'tokens': {
                '0': recovery('1', regalia_generation=1),
                '1': recovery('2', regalia_generation=2, regalia_replaces='1', regalia_replaces_salt=salt['kdf']['salt'])}},
            'unknown': {'keyslots': {'1': {}, '2': {}}, 'tokens': {'0': recovery('1'), '1': recovery('2')}},
        }
        for expected, meta in cases.items():
            with self.subTest(state=expected): self.assertEqual(header_state(meta), expected)
        for name, meta in {
            'ignored priority': {'keyslots': {'1': {'priority': 0}}, 'tokens': {'0': recovery('1')}},
            'a token naming two keyslots': {'keyslots': {'1': {}, '2': {}}, 'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['1', '2']}}},
            'a mark naming the wrong salt': dict(cases['added-unproven'], keyslots={'1': {'kdf': {'salt': 'b3RoZXI='}}, '2': {}}),
        }.items():
            with self.subTest(case=name): self.assertEqual(header_state(meta), 'unknown')
        self.assertEqual(module.reported_state('x\nSTATE: clean — one\nSTATE: orphan-token — t\n'), 'orphan-token')
        self.assertIsNone(module.reported_state('killed before it printed anything'))
