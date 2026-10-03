import unittest
from unittest.mock import patch
from lab.appliance.minimize import removal_plan, minimize


class ReviewedImageRemoval(unittest.TestCase):
    def test_apt_cannot_remove_required_or_unreviewed_packages(self):
        for plan in ['Remv locales [2]\nRemv systemd [3]', 'Purg linux-image-amd64', 'Inst locales [2]', '']:
            with self.assertRaises(ValueError): removal_plan(plan, ['locales'])
        self.assertEqual(removal_plan('Remv locales [2]\nPurg locales [2]', ['locales']), ['locales'])

    def test_essential_candidate_is_refused_before_apt(self):
        with patch('lab.appliance.minimize.installed', return_value=(True, True)), patch('lab.appliance.minimize.subprocess.run') as call:
            with self.assertRaisesRegex(ValueError, 'Essential'): minimize(True)
            call.assert_not_called()

    def test_absent_required_role_is_refused_before_apt(self):
        with patch('lab.appliance.minimize.installed', return_value=(False, False)), patch('lab.appliance.minimize.subprocess.run') as call:
            with self.assertRaisesRegex(ValueError, 'required appliance'): minimize(True)
            call.assert_not_called()
