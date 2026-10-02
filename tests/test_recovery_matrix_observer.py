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
