"""node.site_advance (#615, the writer): the new site document written to the ESP only when the anchored manifest's
measurement document already lists, for this node, the booted set with only PCR 12 replaced by what the ESP will then
measure. The judgement is siteadvance.target's (tests/test_baremetal_siteadvance.py); here, what the writer feeds it
and what it writes. The chain, the anchor and the document store are stand-ins; the ESP is a real directory and PCR 12
is espcreds.pcr12 over its real files."""
import copy
import fcntl
import hashlib
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import bootcreds, enrol, espcreds, measurements, node, sitecfg
from deploy.baremetal import membership as m
import tests.test_baremetal_bootnet as bn

SEALED = {"regalia.local.cred": b"sealed-local", "regalia.wg-boot.cred": b"sealed-wg"}       # never rewritten
FW, PHASES = "2019102300163636", {"initrd": {"11": "c3" * 32}, "system": {"11": "d4" * 32}}


def a_set(label, pcr12, phases=PHASES):
    return {"label": label, "tpm_firmware_version": FW, "pcrs": {"7": "77" * 32, "12": pcr12}, "phases": phases}


class FakeNode:
    node_id = "a"

    def __init__(self, state):
        self.state, self.cfg = state, {"root_key": "R"}

    def path(self, name):
        return os.path.join(self.state, name)

    def anchor(self, lock_path=None, schema=None):
        return "ANCHOR"

    def documents(self):
        return "DOCUMENTS"


class SiteAdvanceCase(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.esp = os.path.join(self.d, "esp")
        self.creds = os.path.join(self.esp, bootcreds.CREDENTIALS_DIR)
        os.makedirs(self.creds)
        self.old = sitecfg.validate(bn.site())
        self.new = copy.deepcopy(self.old)
        self.new["host_ipv4"] = "192.0.2.77"
        self.old_doc = bootcreds.site_document(self.old, node.ESP_RENDER_DEVICE)
        self.new_doc = bootcreds.site_document(self.new, node.ESP_RENDER_DEVICE)
        for name, data in dict(SEALED, **{"regalia.site.cred": self.old_doc}).items():
            with open(os.path.join(self.creds, name), "wb") as f:
                f.write(data)
        self.old_pcr = espcreds.pcr12(dict(SEALED, **{"regalia.site.cred": self.old_doc}))
        self.new_pcr = espcreds.pcr12(dict(SEALED, **{"regalia.site.cred": self.new_doc}))
        self.site_path = self.write_site(self.new)
        self.sets = [a_set("current", self.old_pcr), a_set("moved", self.new_pcr)]
        self.lock = os.path.join(self.d, "run", "esp-advance.lock")
        self.n = FakeNode(os.path.join(self.d, "state"))
        manifest = {"epoch": 7, "policy_version": "p7"}
        for target, name, value in ((node, "read_published", lambda path: ["E1"]),
                                    (m, "accept_chain", lambda prev, envelopes, root: {"schema": "s"}),
                                    (bootcreds, "anchored", lambda envelopes, root, anchor: manifest),
                                    (m, "digest", lambda doc: "d" * 64),
                                    (measurements, "held", lambda store, man: {"nodes": {"a": {"accepted": self.sets}}})):
            patch = unittest.mock.patch.object(target, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def write_site(self, site, name="new-site.json"):
        path = os.path.join(self.d, name)
        with open(path, "w") as f:
            json.dump(site, f)
        return path

    def on_esp(self, name="regalia.site.cred"):
        with open(os.path.join(self.creds, name), "rb") as f:
            return f.read()

    def advance(self, record=None, site_path=None):
        return node.site_advance(self.n, self.esp, site_path or self.site_path, lock_path=self.lock, record=record)


class Writes(SiteAdvanceCase):
    def test_an_approved_site_document_is_written_and_names_the_next_set(self):
        label, sha, rewritten = self.advance()
        self.assertEqual((label, sha, rewritten), ("moved", hashlib.sha256(self.new_doc).hexdigest(), True))
        self.assertEqual(self.on_esp(), self.new_doc)
        self.assertEqual(espcreds.pcr12(dict(SEALED, **{"regalia.site.cred": self.on_esp()})), self.new_pcr)

    def test_the_sealed_files_are_never_touched(self):
        before = {n: os.stat(os.path.join(self.creds, n)).st_ino for n in SEALED}
        self.advance()
        self.assertEqual({n: self.on_esp(n) for n in SEALED}, SEALED)
        self.assertEqual({n: os.stat(os.path.join(self.creds, n)).st_ino for n in SEALED}, before)

    def test_a_rerun_after_the_write_changes_nothing(self):
        self.advance()
        self.assertEqual(self.advance(), ("moved", hashlib.sha256(self.new_doc).hexdigest(), False))

    def test_the_request_is_recorded_before_the_write_and_allow_after(self):
        order, lines = [], []
        write = enrol._replace_esp
        record = lambda line: (order.append(line["event"]), lines.append(line))
        with unittest.mock.patch.object(enrol, "_replace_esp", lambda *a: (order.append("esp"), write(*a))[1]):
            self.advance(record=record)
        self.assertEqual(order, ["site-advance-requested", "esp", "site-advance"])
        self.assertEqual((lines[0]["booted_set"], lines[0]["next_set"], lines[0]["pcr12"], lines[-1]["outcome"]),
                         ("current", "moved", self.new_pcr, "ALLOW"))

    def test_a_request_that_cannot_be_recorded_writes_nothing(self):
        def broken(line):
            raise OSError("trail full")
        with self.assertRaises(OSError):
            self.advance(record=broken)
        self.assertEqual(self.on_esp(), self.old_doc)

    def test_a_failed_allow_after_the_write_is_incomplete_not_a_refusal(self):
        def allow_fails(line):
            if line.get("outcome") == "ALLOW":
                raise OSError("trail full")
        with self.assertRaises(node.TrailIncomplete):
            self.advance(record=allow_fails)
        self.assertEqual(self.on_esp(), self.new_doc)

    def test_it_writes_where_systemd_stub_reads_and_site_check_checks(self):
        # one path: the literal site-check binds in its unit, and the credentials directory systemd-stub measures
        self.assertEqual(node.SITE_ON_ESP, bootcreds.CREDENTIALS_DIR + "/regalia.site.cred")
        self.advance()
        self.assertEqual(open(os.path.join(self.esp, node.SITE_ON_ESP), "rb").read(), self.new_doc)

    def test_it_runs_under_the_esp_advance_lock(self):
        os.makedirs(os.path.dirname(self.lock))
        fd = os.open(self.lock, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with self.assertRaisesRegex(node.Refused, "holds %s: one at a time" % self.lock):
            self.advance()
        self.assertEqual(self.on_esp(), self.old_doc)


class Refuses(SiteAdvanceCase):
    def test_a_site_the_root_has_not_approved_is_refused_and_nothing_is_written(self):
        self.sets[:] = [a_set("current", self.old_pcr)]                     # no epoch N yet
        with self.assertRaisesRegex(node.Refused, "has not approved this site document"):
            self.advance()
        self.assertEqual(self.on_esp(), self.old_doc)

    def test_a_document_one_byte_off_the_approved_one_is_refused(self):
        off = copy.deepcopy(self.new)
        off["host_ipv4"] = "192.0.2.78"
        with self.assertRaisesRegex(node.Refused, "has not approved this site document"):
            self.advance(site_path=self.write_site(off, "off.json"))
        self.assertEqual(self.on_esp(), self.old_doc)

    def test_an_image_update_in_flight_is_refused(self):
        self.sets[1] = a_set("next-image", self.new_pcr, phases={"initrd": {"11": "e6" * 32}, "system": {"11": "f7" * 32}})
        with self.assertRaisesRegex(node.Refused, "image update is rolling through"):
            self.advance()
        self.assertEqual(self.on_esp(), self.old_doc)

    def test_a_boot_no_accepted_set_measures_is_refused(self):
        with open(os.path.join(self.creds, "regalia.local.cred"), "wb") as f:
            f.write(b"another")                                               # the ESP no longer measures the booted set
        with self.assertRaisesRegex(node.Refused, "no accepted set has the PCR 12 the ESP measures now"):
            self.advance()

    def test_another_nodes_site_is_refused(self):
        with self.assertRaisesRegex(node.Refused, "is not this node's"):
            self.advance(site_path=self.write_site(sitecfg.validate(bn.site("b")), "b.json"))
        self.assertEqual(self.on_esp(), self.old_doc)

    def test_a_site_sitecfg_rejects_is_refused(self):
        bad = copy.deepcopy(self.new)
        bad["host_ipv4"] = "not an address"
        with self.assertRaises((node.Refused, sitecfg.InvalidSite)):
            self.advance(site_path=self.write_site(bad, "bad.json"))
        self.assertEqual(self.on_esp(), self.old_doc)

    def test_no_accepted_set_for_this_node_is_refused(self):
        self.sets[:] = []
        with self.assertRaisesRegex(node.Refused, "lists no accepted set for a"):
            self.advance()

    def test_a_link_on_the_esp_is_refused(self):
        target = os.path.join(self.creds, "regalia.site.cred")
        os.replace(target, os.path.join(self.d, "elsewhere"))
        os.symlink(os.path.join(self.d, "elsewhere"), target)
        with self.assertRaises(node.Refused):
            self.advance()


if __name__ == "__main__":
    unittest.main()
