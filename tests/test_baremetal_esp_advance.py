"""node.esp_advance (#66 B3): the root oneshot that writes the published chain to the ESP, THEN moves the TPM anchor,
so that no reboot finds an ESP chain below its anchor (the initrd refuses that as a ROLLBACK). Sync never anchors
(tests/test_baremetal_store_anchors.py). The TPM is hbt.FakeTpm; the boots themselves are in
tests/test_baremetal_unlock_boot.py (QEMU)."""
import hashlib
import os
import unittest
import unittest.mock

from deploy.baremetal import bootcreds, enrol
from deploy.baremetal import membership as m
from deploy.baremetal import node
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_replacement as rt
from tests.test_baremetal_node import ROOT, Case


class EspAdvance(Case):
    def setUp(self):
        super().setUp()
        self.esp = os.path.join(self.d, "esp")
        os.mkdir(self.esp, 0o755)
        self.lock = os.path.join(self.d, "run", "esp-advance.lock")
        self.n = self.node()
        anchoring = self.n.anchor()
        anchoring.define()
        m.Store(self.n.path("membership.json"), ROOT, anchoring).commit(self.e1)      # as enrolment leaves it: anchored at 1
        self.sync = m.Store(self.n.path("membership.json"), ROOT, self.n.anchor(), anchors=False)
        self.m2 = dict(hbt.manifest(2, m.digest(self.m1)), policy_version="p2")
        self.e2 = rt.sign(self.m2)

    def on_esp(self):
        with open(os.path.join(self.esp, bootcreds.CHAIN_ON_ESP), "rb") as f:
            return m.load(f.read())

    def advance(self):
        return node.esp_advance(self.n, self.esp, lock_path=self.lock)

    def test_the_esp_is_written_before_the_anchor_moves(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        self.assertEqual(self.n.anchor().value(), 1, "sync moved the anchor")
        self.assertEqual(self.n.manifest()["epoch"], 2)                       # the root services read the chain ahead of the anchor
        order = []
        write, anchor = enrol._replace_esp, m.HighWater.anchor
        with unittest.mock.patch.object(enrol, "_replace_esp", lambda *a: (order.append("esp"), write(*a))[1]), \
                unittest.mock.patch.object(m.HighWater, "anchor", lambda hw, *a: (order.append("anchor"), anchor(hw, *a))[1]):
            epoch, sha, rewritten = self.advance()
        self.assertEqual(order, ["esp", "anchor"])
        self.assertEqual((epoch, rewritten), (2, True))
        self.assertEqual(self.on_esp(), [self.e1, self.e2])
        self.assertEqual(sha, hashlib.sha256(m.canonical([self.e1, self.e2])).hexdigest())
        self.assertEqual(self.n.anchor().value(), 2)
        self.assertEqual(self.advance()[1:], (sha, False))                    # again: nothing to write, the anchor already there

    def test_a_crash_between_the_write_and_the_anchor_is_completed_by_the_next_run(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        with unittest.mock.patch.object(m.HighWater, "anchor", side_effect=OSError("power cut")), self.assertRaises(OSError):
            self.advance()
        self.assertEqual(self.on_esp(), [self.e1, self.e2])                   # the ESP ahead: what the initrd accepts
        self.assertEqual(self.n.anchor().value(), 1)
        self.assertEqual(bootcreds.anchored(self.on_esp(), ROOT, self.n.anchor())["epoch"], 2)
        self.assertEqual(self.advance()[0], 2)
        self.assertEqual(self.n.anchor().value(), 2)

    def test_a_refused_chain_writes_nothing_and_leaves_the_anchor(self):
        self.sync.commit(self.e2)
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        self.advance()
        published = self.n.path(node.PUBLISHED)
        for label, chain, reason in (
                ("a rollback", [self.e1], "ROLLBACK"),
                ("a fork at the anchored epoch", [self.e1, rt.sign(dict(self.m2, policy_version="forked"))], "CONFLICT"),
                ("a chain the root did not sign", [self.e1, rt.sign(self.m2, key=hbt.REVOKE)], "")):
            with self.subTest(label):
                with open(published, "wb") as f:
                    f.write(m.canonical(chain))
                with self.assertRaises(m.Refused) as caught:
                    self.advance()
                self.assertIn(reason, str(caught.exception))
                self.assertEqual(self.on_esp(), [self.e1, self.e2])
                self.assertEqual(self.n.anchor().value(), 2)

    def test_only_the_chain_is_written(self):
        """The measured site credential is enrolment's; the ESP advance never touches loader/credentials."""
        credentials = os.path.join(self.esp, "loader", "credentials")
        os.makedirs(credentials)
        for path in (os.path.join(self.esp, "loader"), credentials):
            os.chmod(path, 0o755)                                             # whatever the umask: a trusted path
        with open(os.path.join(credentials, "regalia.site.cred"), "wb") as f:
            f.write(b"as enrolment wrote it")
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        self.advance()
        self.assertEqual(sorted(os.listdir(credentials)), ["regalia.site.cred"])
        with open(os.path.join(credentials, "regalia.site.cred"), "rb") as f:
            self.assertEqual(f.read(), b"as enrolment wrote it")
        self.assertEqual(sorted(os.listdir(os.path.join(self.esp, "EFI", "regalia"))), ["membership.json"])

    def test_a_link_on_the_esp_is_not_followed(self):
        node.publish(self.sync, self.n.path(node.PUBLISHED))
        os.makedirs(os.path.join(self.esp, "EFI", "regalia"))
        for path in (os.path.join(self.esp, "EFI"), os.path.join(self.esp, "EFI", "regalia")):
            os.chmod(path, 0o755)
        os.symlink(os.path.join(self.d, "elsewhere"), os.path.join(self.esp, bootcreds.CHAIN_ON_ESP))
        self.refused("", self.advance)
        self.assertFalse(os.path.exists(os.path.join(self.d, "elsewhere")))
        self.assertEqual(self.n.anchor().value(), 1)


if __name__ == "__main__":
    unittest.main()
