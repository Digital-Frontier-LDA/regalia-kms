"""deploy/baremetal/deliver.py (#199): signed manifests given to one running node, now that no authority host takes the
root's epochs. A delivery is a sync (convergence.catch_up through the node's own Store, with its measurements check,
#332): in order, every epoch held verified again (a different one is a CONFLICT), the epoch the batch leaves the node
at judged by its document, a refusal part-way leaving the last good epoch published and recorded; never as root."""
import json
import os
import unittest
import unittest.mock

from deploy.baremetal import deliver, node
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_measurements_store as mst
import tests.test_baremetal_replacement as rt

DOC1, DOC2, DOC3 = mst.DOC1, mst.DOC2, mst.DOC3


class GuardedNode:
    """What deliver() uses of a node.Node: its Store with the documents check, its documents, its state directory."""

    def __init__(self, case, name):
        self.case, self.name = case, name
        self.docs = case.documents(name)
        self._store = case.guarded(name, self.docs)

    def store(self):
        return self._store

    def documents(self):
        return self.docs

    def path(self, leaf):
        return os.path.join(self.case.d, "%s-%s" % (self.name, leaf))


class Deliver(mst.Case):
    def setUp(self):
        super().setUp()
        self.events = []
        self.e1 = self.under(DOC1)
        self.e2 = self.under(DOC2, self.e1["manifest"])
        self.e3 = self.under(DOC3, self.e2["manifest"])
        self.n = GuardedNode(self, "x")
        self.n.docs.put(DOC1)
        self.n.store().commit(self.e1)

    def published(self):
        with open(self.n.path(node.PUBLISHED)) as f:
            return [e["manifest"]["epoch"] for e in json.load(f)]

    def test_the_newer_epochs_are_committed_in_order_judged_by_their_document_and_published(self):
        self.assertEqual(deliver.deliver(self.n, [self.e1, self.e2, self.e3], [DOC3], self.events.append), 3)
        self.assertEqual((self.n.store().load()["epoch"], self.n.store().hw.value(), self.published()), (3, 3, [1, 2, 3]))
        self.assertEqual((self.events[-1]["outcome"], self.events[-1]["epoch"]), ("ALLOW", 3))

    def test_a_resent_epoch_after_the_highest_does_not_let_the_highest_skip_its_document(self):
        """regalia-kms-51's [e2, e3, e2]: the batch leaves the node at epoch 3, which is judged by ITS document (not held
        here): refused at 3, the node at 2, published and recorded at 2."""
        self.n.docs.put(DOC2)
        with self.assertRaises(m.Refused) as caught:
            deliver.deliver(self.n, [self.e2, self.e3, self.e2], [], self.events.append)
        self.assertIn("epoch 3 commits to measurements", str(caught.exception))
        self.assertEqual((self.n.store().load()["epoch"], self.n.store().hw.value(), self.published()), (2, 2, [1, 2]))
        self.assertEqual((self.events[-1]["outcome"], self.events[-1]["epoch"]), ("DENY", 2))

    def test_a_skipped_epoch_needs_no_document_but_the_one_it_ends_at_does(self):
        self.refused("epoch 3 commits to measurements", deliver.deliver, self.n, [self.e2, self.e3], [DOC2], self.events.append)
        self.assertEqual(self.n.store().load()["epoch"], 2)                  # the last good epoch: its document was given
        n2 = GuardedNode(self, "y")
        n2.docs.put(DOC1)
        n2.store().commit(self.e1)
        self.assertEqual(deliver.deliver(n2, [self.e2, self.e3], [DOC3], self.events.append), 3)    # 2 passed through without DOC2

    def test_a_held_epoch_resent_differently_is_a_conflict(self):
        other = rt.sign(dict(self.e1["manifest"], issued_at="2026-10-04T00:00:00Z"))
        self.refused("CONFLICT", deliver.deliver, self.n, [other, self.e2], [DOC2], self.events.append)
        self.assertEqual(self.n.store().load()["epoch"], 1)

    def test_a_gap_or_another_chain_is_refused(self):
        self.n.docs.put(DOC3)
        self.refused("does not follow", deliver.deliver, self.n, [self.e3], [], self.events.append)
        stray = rt.sign(dict(self.e2["manifest"], prev_digest="00" * 32))
        self.refused("prev_digest", deliver.deliver, self.n, [stray], [DOC2], self.events.append)
        self.assertEqual(self.n.store().load()["epoch"], 1)

    def test_what_only_the_root_may_sign_is_refused_signed_by_a_revocation_key(self):
        widening = rt.sign(self.e2["manifest"], key=hbt.REVOKE, signer="revocation")
        self.refused("cannot change the policy version", deliver.deliver, self.n, [widening], [DOC2], self.events.append)
        self.assertEqual(self.n.store().load()["epoch"], 1)

    def test_nothing_newer_and_nothing_at_all(self):
        self.refused("holds epoch 1 already", deliver.deliver, self.n, [self.e1], [], self.events.append)
        self.refused("non-empty list", deliver.deliver, self.n, [], [], self.events.append)

    def test_root_hands_over_with_an_argv_the_sync_half_parses(self):
        """as_sync's own command line, given to main as the regalia-sync process gets it: it reaches the run-as check
        (here refused, as root), never argparse's usage error (CI found `_deliver --config`, which only the order
        `--config … _deliver` parses)."""
        import pwd
        seen = []

        def run(argv, **kw):
            seen.append(argv)
            return unittest.mock.Mock(returncode=0, stdout='{"epoch": 2}\n', stderr="")
        self.assertEqual(deliver.as_sync("/etc/regalia/node.json", [self.e2["manifest"]], [], run=run), 2)
        argv = seen[0][seen[0].index("deploy.baremetal.deliver") + 1:]
        with unittest.mock.patch.object(deliver.os, "geteuid", return_value=0), \
                unittest.mock.patch.object(pwd, "getpwnam", return_value=unittest.mock.Mock(pw_uid=990)), \
                unittest.mock.patch("sys.stderr") as err:
            self.assertEqual(deliver.main(argv), 1)
        self.assertIn("runs as regalia-sync only", "".join(str(c) for c in err.write.call_args_list))

    def test_the_sync_half_never_runs_as_root(self):
        """Run as root, Store would leave membership.json root's and 0600, which regalia-sync could no longer read."""
        import pwd
        with unittest.mock.patch.object(deliver.os, "geteuid", return_value=0), \
                unittest.mock.patch.object(pwd, "getpwnam", return_value=unittest.mock.Mock(pw_uid=990)), \
                unittest.mock.patch("sys.stderr") as err:
            self.assertEqual(deliver.main(["--config", "/nonexistent/node.json", "_deliver"]), 1)
        self.assertIn("runs as regalia-sync only", "".join(str(c) for c in err.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
