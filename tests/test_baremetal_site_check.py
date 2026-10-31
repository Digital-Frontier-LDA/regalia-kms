"""deploy/baremetal/node.py site_check (#615): the rootfs site configuration against the site document on the ESP,
which regalia-site-check.service runs and regalia-wg-apply.service Requires=. Accepted when they agree on every key
both hold; refused on any difference, and when the document is missing, unreadable or not one the initrd reads."""
import copy
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import bootcreds, node, sitecfg
import tests.test_baremetal_bootnet as bn

DEVICE = "/dev/disk/by-partlabel/regalia-root"


class FakeNode:
    def __init__(self, site):
        self.site, self.cfg = site, {"site": "/etc/regalia/site.json"}


class SiteCheckTests(unittest.TestCase):
    def setUp(self):
        self.esp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.esp)
        self.site = sitecfg.validate(bn.site())
        self.path = os.path.join(self.esp, node.SITE_ON_ESP)
        os.makedirs(os.path.dirname(self.path))

    def write(self, raw):
        with open(self.path, "wb") as f:
            f.write(raw)

    def test_the_document_rendered_from_this_site_is_accepted(self):
        self.write(bootcreds.site_document(self.site, DEVICE))
        self.assertEqual(node.site_check(FakeNode(self.site), self.esp), ("host_ipv4", "boot_mesh"))

    def test_the_compared_keys_are_every_key_both_hold_but_the_schema(self):
        # a key added to either list later is compared without an edit to node.py
        self.assertEqual(node.site_compared(), tuple(k for k in bootcreds.SITE_KEYS if k in sitecfg.KEYS and k != "schema"))
        self.assertEqual(node.site_compared(), ("host_ipv4", "boot_mesh"))

    def test_a_rootfs_file_left_from_the_old_site_is_refused(self):
        # the move: the ESP holds the new site's document, the rootfs still the old site's
        moved = copy.deepcopy(self.site)
        moved["host_ipv4"] = "192.0.2.77"
        self.write(bootcreds.site_document(moved, DEVICE))
        with self.assertRaisesRegex(node.Refused, r"differ in host_ipv4: the rootfs file is not this boot's site"):
            node.site_check(FakeNode(self.site), self.esp)

    def test_each_compared_key_is_compared(self):
        # one case per key, so no one of them can drop out of the comparison
        other_mesh = copy.deepcopy(self.site)
        other_mesh["boot_mesh"]["peers"][0]["underlay"] = "198.51.100.99"
        other_host = copy.deepcopy(self.site)
        other_host["host_ipv4"] = "192.0.2.77"
        for key, rootfs in (("boot_mesh", other_mesh), ("host_ipv4", other_host)):
            with self.subTest(key=key):
                self.write(bootcreds.site_document(self.site, DEVICE))
                with self.assertRaisesRegex(node.Refused, r"differ in %s\b" % key):
                    node.site_check(FakeNode(rootfs), self.esp)

    def test_a_difference_outside_the_compared_keys_is_not_a_refusal(self):
        # the service mesh is the rootfs's alone: the measured document does not hold it
        self.write(bootcreds.site_document(self.site, DEVICE))
        rootfs = copy.deepcopy(self.site)
        rootfs["kms_port"] = rootfs["kms_port"] + 1
        self.assertEqual(node.site_check(FakeNode(rootfs), self.esp), ("host_ipv4", "boot_mesh"))

    def test_a_missing_document_is_refused_not_passed(self):
        with self.assertRaisesRegex(node.Refused, "is not there: the site configuration cannot be checked"):
            node.site_check(FakeNode(self.site), self.esp)

    def test_a_document_the_initrd_would_not_read_is_refused(self):
        raw = bootcreds.site_document(self.site, DEVICE)
        for name, bad in (("not canonical", raw.replace(b",", b", ", 1)), ("not JSON", b"{"), ("empty", b""),
                          ("too large", b" " * (bootcreds.SITE_MAX_BYTES + 1))):
            with self.subTest(name):
                self.write(bad)
                with self.assertRaises(node.Refused):
                    node.site_check(FakeNode(self.site), self.esp)

    def test_a_link_is_not_followed(self):
        real = os.path.join(self.esp, "elsewhere.cred")
        with open(real, "wb") as f:
            f.write(bootcreds.site_document(self.site, DEVICE))
        os.symlink(real, self.path)
        with self.assertRaises((node.Refused, OSError)):
            node.site_check(FakeNode(self.site), self.esp)


UNITS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy", "baremetal", "units")


def directives(unit, key):
    with open(os.path.join(UNITS, unit)) as f:
        return [line.split("=", 1)[1].strip() for line in f if line.startswith(key + "=")]


class UnitTests(unittest.TestCase):
    def test_the_measured_document_is_bound_and_not_optional(self):
        # no "-": a missing document fails the unit at setup, never starts it without the file
        self.assertEqual(directives("regalia-site-check.service", "BindReadOnlyPaths"), ["/efi/" + node.SITE_ON_ESP])
        self.assertEqual(directives("regalia-site-check.service", "RequiresMountsFor"), ["/efi"])

    def test_it_checks_the_esp_it_binds(self):
        (start,) = directives("regalia-site-check.service", "ExecStart")
        self.assertTrue(start.endswith(" site-check --esp /efi"), start)

    def test_wg_apply_requires_it_and_starts_after_it(self):
        # Requires= alone would start both at once; After= alone would start wg-apply on a failed check
        self.assertIn("regalia-site-check.service", directives("regalia-wg-apply.service", "Requires"))
        self.assertIn("regalia-site-check.service", directives("regalia-wg-apply.service", "After"))


class MetricsTests(unittest.TestCase):
    def test_ok_and_refused_runs_both_write(self):
        for ok, value in ((True, 1), (False, 0)):
            got = []
            node.site_check_metrics(ok, publish=got.append)
            self.assertEqual(got[0][0], ("regalia_site_check_ok", {}, value))

    def test_a_metric_that_cannot_be_written_does_not_raise(self):
        def broken(samples):
            raise OSError("no textfile directory")
        node.site_check_metrics(True, publish=broken)


class MainTests(unittest.TestCase):
    """node.main site-check: the exit and the metric, from the subcommand the unit runs."""

    def setUp(self):
        self.esp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.esp)
        self.site = sitecfg.validate(bn.site())
        os.makedirs(os.path.join(self.esp, os.path.dirname(node.SITE_ON_ESP)))
        self.published = []
        for name, value in (("load", lambda path: {}), ("Node", lambda cfg: FakeNode(self.site)),
                            ("site_check_metrics", lambda ok: self.published.append(ok))):
            patch = unittest.mock.patch.object(node, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def test_agreement_exits_0_and_says_ok(self):
        with open(os.path.join(self.esp, node.SITE_ON_ESP), "wb") as f:
            f.write(bootcreds.site_document(self.site, DEVICE))
        self.assertEqual(node.main(["--config", "x", "--esp", self.esp, "site-check"]), 0)
        self.assertEqual(self.published, [True])

    def test_a_refusal_exits_2_and_says_not_ok(self):
        self.assertEqual(node.main(["--config", "x", "--esp", self.esp, "site-check"]), 2)
        self.assertEqual(self.published, [False])


if __name__ == "__main__":
    unittest.main()
