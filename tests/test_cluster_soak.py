import copy
import sys
from pathlib import Path
import unittest
original_path = sys.path.copy()
try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lab/bootstrap'))
    from chaos_cases import schedule, KINDS
    from soak import summarize
finally:
    sys.path[:] = original_path


class SoakEvidence(unittest.TestCase):
    def report(self):
        return {'status': 'passed', 'cleanup': 'passed', 'checks': [{'status': 'passed'}],
                'chaos': {'seed': 19, 'steps': 26, 'actions': [dict(x, status='passed', step=i, elapsed_seconds=.1)
                          for i, x in enumerate(schedule(19, 26), 1)]}}

    def test_complete_schedule_has_every_fault(self):
        summary = summarize(self.report(), 19, 26)
        self.assertEqual(sum(summary['coverage'].values()), 26)
        self.assertEqual(set(summary['coverage']), set(KINDS))

    def test_missing_fault_cleanup_and_failed_check_cannot_pass(self):
        for defect in ('action', 'cleanup', 'check', 'seed', 'schedule'):
            report = copy.deepcopy(self.report())
            if defect == 'action': report['chaos']['actions'].pop()
            if defect == 'cleanup': report['cleanup'] = 'failed'
            if defect == 'check': report['checks'][0]['status'] = 'failed'
            if defect == 'seed': report['chaos']['seed'] = 20
            if defect == 'schedule': report['chaos']['actions'][0]['variant'] = 99
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                summarize(report, 19, 26)
