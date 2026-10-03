"""A kernel update may only select the reviewed, authenticated package closure."""
import unittest
from lab.appliance.kernel import PACKAGES, VERSION, upgrade_plan


class BoundedKernelUpgrade(unittest.TestCase):
    def fixture(self):
        return '\n'.join('Inst ' + name + ' (' + version + ' Debian Backports:stable-backports [amd64])'
                         for name, version in PACKAGES.items())

    def test_exact_reviewed_closure_is_accepted(self):
        self.assertEqual(upgrade_plan(self.fixture()), PACKAGES)

    def test_removal_extra_package_downgrade_and_incomplete_plan_are_refused(self):
        plan = self.fixture()
        for text in (plan+'\nRemv systemd [1]', plan+'\nInst libc6 (9 stable [amd64])',
                     plan.replace(VERSION, '6.12.111-1'), '\n'.join(plan.splitlines()[1:]),
                     plan+'\nConf systemd (1 stable [amd64])', plan+'\n'+plan.splitlines()[0]):
            with self.subTest(plan=text), self.assertRaises(ValueError): upgrade_plan(text)


if __name__ == '__main__': unittest.main()
