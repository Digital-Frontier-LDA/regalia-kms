"""#332: measurement documents by digest, delivered with the epoch that names them. A node holds documents side
by side in a store named by digest; it judges an epoch by the document THAT epoch commits to and by no other;
it does not commit an epoch (nor move its TPM anchor) without that document; and sync brings the document with
the epoch. Fixtures are the sync tests': b, c and the authority hold the chain, a asks."""
import json
import os

from deploy.baremetal import convergence, measurements, sync
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_replacement as rt
import tests.test_baremetal_rollout as rlt
import tests.test_baremetal_sync as st

DOC1, DOC2, DOC3 = rlt.CURRENT, rlt.BOTH, rlt.NEXT


class Case(st.Case):
    def documents(self, name):
        return measurements.Documents(os.path.join(self.d, name + "-measurements"))

    def guarded(self, name, documents):
        """A store whose commits need the document, like a node's (node.Node.store)."""
        anchor = m.HighWater("0x1500016", lock_path=os.path.join(self.d, name + "-hw.lock"), run=hbt.FakeTpm())
        anchor.define()
        return m.Store(os.path.join(self.d, name + "-membership.json"), st.ct.ROOT, anchor, documents=documents.require_for)

    def under(self, document, previous=None):
        """The root-signed envelope of the next epoch (epoch 1 without `previous`), committing to `document`."""
        manifest = self.m1 if previous is None else self.chain(previous, previous["nodes"])
        return rt.sign(dict(manifest, policy_version=measurements.version(document)))

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))
        return str(caught.exception)


class Store(Case):
    def test_the_file_is_named_by_the_digest_and_its_name_gives_the_version(self):
        docs = self.documents("x")
        got = docs.put(DOC1)
        self.assertEqual(got, measurements.version(DOC1))
        name = m.canonical(DOC1)
        import hashlib
        self.assertEqual(os.listdir(docs.directory), [hashlib.sha256(name).hexdigest() + ".json"])
        self.assertEqual(docs.versions(), {got: hashlib.sha256(name).hexdigest()})
        self.assertEqual(docs.get(got), DOC1)
        self.assertIsNone(docs.get(measurements.version(DOC2)))
        self.assertEqual(docs.put(DOC1), got)                       # again: the same bytes, nothing changes

    def test_a_different_file_at_a_digest_name_is_refused_and_never_replaced(self):
        docs = self.documents("x")
        version = docs.put(DOC1)
        path = os.path.join(docs.directory, docs.versions()[version] + ".json")
        with open(path, "wb") as f:
            f.write(m.canonical(DOC2))                              # another document under DOC1's name
        self.refused("does not hold the document its name is the digest of", docs.get, version)
        self.refused("already exists with other bytes", docs.put, DOC1)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), m.canonical(DOC2))           # left as found, for the operator to look at

    def test_an_invalid_document_is_not_stored(self):
        docs = self.documents("x")
        self.refused("schema must be", docs.put, dict(DOC1, schema="regalia.measurements/v0"))
        self.assertEqual(docs.versions(), {})


class Held(Case):
    def test_the_verifier_takes_the_document_of_the_current_epoch_and_no_other(self):
        docs = self.documents("x")
        docs.put(DOC1)
        docs.put(DOC2)
        e1 = self.under(DOC1)
        e2 = self.under(DOC2, e1["manifest"])
        self.assertEqual(measurements.held(docs.directory, e1["manifest"]), DOC1)
        self.assertEqual(measurements.held(docs, e2["manifest"]), DOC2)
        e3 = self.under(DOC3, e2["manifest"])
        self.refused("epoch 3 commits to measurements %s, which this node does not hold" % measurements.version(DOC3),
                     measurements.held, docs, e3["manifest"])

    def test_after_a_commit_the_new_epochs_document_is_used_without_a_file_replaced(self):
        docs = self.documents("x")
        store = self.guarded("x", docs)
        docs.put(DOC1)
        e1 = self.under(DOC1)
        store.commit(e1)
        self.assertEqual(measurements.held(docs, store.load()), DOC1)
        before = {n: os.stat(os.path.join(docs.directory, n)).st_ino for n in os.listdir(docs.directory)}
        docs.put(DOC2)
        store.commit(self.under(DOC2, e1["manifest"]))
        self.assertEqual(measurements.held(docs, store.load()), DOC2)
        after = {n: os.stat(os.path.join(docs.directory, n)).st_ino for n in os.listdir(docs.directory)}
        self.assertEqual({n: after[n] for n in before}, before)       # DOC1's file is still the same file
        self.assertEqual(len(after), 2)


class Commit(Case):
    def test_an_epoch_whose_document_is_missing_is_not_committed_and_the_anchor_does_not_move(self):
        docs = self.documents("x")
        store = self.guarded("x", docs)
        e1 = self.under(DOC1)
        reason = self.refused("epoch 1 commits to measurements %s, which this node does not hold" % measurements.version(DOC1), store.commit, e1)
        self.assertIn("measurements install", reason)
        self.assertEqual(store.hw.value(), 0)
        self.assertFalse(os.path.exists(store.path))

    def test_an_epoch_whose_store_holds_another_document_is_not_committed(self):
        docs = self.documents("x")
        store = self.guarded("x", docs)
        docs.put(DOC2)                                                # the WRONG one
        self.refused("which this node does not hold", store.commit, self.under(DOC1))
        self.assertEqual(store.hw.value(), 0)
        docs.put(DOC1)
        self.assertEqual(store.commit(self.under(DOC1))["epoch"], 1)
        self.assertEqual(store.hw.value(), 1)

    def test_a_batch_needs_the_document_of_the_epoch_it_leaves_the_node_at(self):
        e1 = self.under(DOC1)
        e2 = self.under(DOC2, e1["manifest"])
        docs = self.documents("x")
        store = self.guarded("x", docs)
        docs.put(DOC2)                                                # epoch 1 is passed through: its document is not needed
        self.assertEqual(convergence.catch_up(store, [e1, e2])["epoch"], 2)
        docs = self.documents("y")
        store = self.guarded("y", docs)
        docs.put(DOC1)                                                # the end of the batch has none: refused THERE
        self.refused("epoch 2 commits to measurements", convergence.catch_up, store, [e1, e2])
        self.assertEqual((store.load()["epoch"], store.hw.value()), (1, 1))

    def test_a_restored_chain_needs_its_last_document(self):
        e1 = self.under(DOC1)
        e2 = self.under(DOC2, e1["manifest"])
        docs = self.documents("x")
        store = self.guarded("x", docs)
        docs.put(DOC1)
        self.refused("epoch 2 commits to measurements", store.restore, [e1, e2])
        self.assertEqual(store.hw.value(), 0)
        docs.put(DOC2)
        self.assertEqual(store.restore([e1, e2])["epoch"], 2)

    def test_a_store_without_the_check_is_unchanged(self):
        store = self.store("plain")
        self.assertEqual(store.commit(self.under(DOC1))["epoch"], 1)


class Migration(Case):
    def test_the_legacy_file_is_imported_exactly_once(self):
        docs, legacy, lines = self.documents("x"), os.path.join(self.d, "measurements.json"), []
        self.assertIsNone(measurements.migrate(docs, legacy, lines.append))           # none there: nothing
        with open(legacy, "w") as f:
            json.dump(DOC1, f, indent=2)                                               # as enrol wrote it, pretty
        self.assertEqual(measurements.migrate(docs, legacy, lines.append), measurements.version(DOC1))
        self.assertIsNone(measurements.migrate(docs, legacy, lines.append))
        self.assertEqual(len(lines), 1)
        self.assertIn("imported the measurements document", lines[0])
        self.assertEqual(docs.get(measurements.version(DOC1)), DOC1)

    def test_a_legacy_file_that_is_not_a_document_is_refused(self):
        legacy = os.path.join(self.d, "measurements.json")
        with open(legacy, "w") as f:
            f.write("{}")
        self.refused("measurements fields mismatch", measurements.migrate, self.documents("x"), legacy)


class Sync(Case):
    """The document travels with the epoch: a node that lacks it fetches it from the source that sent the epoch."""

    def setUp(self):
        super().setUp()
        self.auth_docs = self.documents("authority")
        self.auth_docs.put(DOC2)
        self.servers["authority"].documents = self.auth_docs
        self.m2 = self.advance(1, policy_version=measurements.version(DOC2))
        self.mine = self.documents("a-own")
        self.stores["a"] = self.guarded("a-own", self.mine)
        self.client = sync.Client("a", self.stores["a"], self.own, {convergence.AUTHORITY: self.wire("authority", "a")}, self.events.append,
                                  documents=self.mine)

    def test_a_node_lacking_the_document_fetches_it_then_commits(self):
        now_at, _ = self.client.pull(convergence.AUTHORITY)
        self.assertEqual(now_at["epoch"], 2)
        self.assertEqual(self.mine.get(measurements.version(DOC2)), DOC2)
        self.assertEqual(measurements.held(self.mine, self.stores["a"].load()), DOC2)

    def test_a_source_without_the_document_moves_nothing(self):
        os.unlink(os.path.join(self.auth_docs.directory, os.listdir(self.auth_docs.directory)[0]))
        self.refused("does not hold measurements", self.client.pull, convergence.AUTHORITY)
        self.assertIsNone(self.client._held())
        self.assertEqual(self.mine.versions(), {})

    def test_another_document_than_the_epoch_names_is_refused(self):
        real = self.wire("authority", "a")

        def lying(raw):
            if json.loads(raw)["op"] == "measurements":
                return m.canonical({"v": 1, "ok": True, "document": DOC1})
            return real(raw)
        self.client.transports[convergence.AUTHORITY] = lying
        self.refused("not the document epoch 2 commits to", self.client.pull, convergence.AUTHORITY)
        self.assertEqual(self.mine.versions(), {})
        self.assertIsNone(self.client._held())

    def test_the_server_answers_only_a_held_document_by_a_version(self):
        self.assertEqual(self.ask("authority", v=1, op="measurements", version=measurements.version(DOC2))["document"], DOC2)
        self.refusal("does not hold measurements", self.ask("authority", v=1, op="measurements", version=measurements.version(DOC3)))
        self.refusal("version must be a policy_version", self.ask("authority", v=1, op="measurements", version="../../etc/passwd"))
        self.refusal("holds no measurement documents", self.ask("b", v=1, op="measurements", version=measurements.version(DOC2)))

    def test_a_lost_document_of_the_epoch_held_heals_itself(self):
        self.client.pull(convergence.AUTHORITY)
        for name in os.listdir(self.mine.directory):
            os.unlink(os.path.join(self.mine.directory, name))
        self.refused("which this node does not hold", measurements.held, self.mine, self.stores["a"].load())
        self.client.pull(convergence.AUTHORITY)                       # nothing new to apply: the held epoch's document comes back
        self.assertEqual(measurements.held(self.mine, self.stores["a"].load()), DOC2)


class Verifier(Case):
    def test_a_server_given_attester_for_judges_each_request_under_the_manifest_held_then(self):
        calls, attester = [], self.peers["b"]["attester"]

        def attester_for(manifest):
            calls.append(manifest["epoch"])
            return attester
        self.servers["b"].attester = attester_for
        self.assertIn("nonce", self.ask("b", v=1, op="lease-nonce", node_id="a"))
        self.assertEqual(calls, [1])


if __name__ == "__main__":
    import unittest
    unittest.main()
