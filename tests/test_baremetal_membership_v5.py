"""Membership schema v5 (regalia-kms-dx7.1, docs/design/single-node.md 4.1): v4 plus a root-only `topology` field, the
designed size of the cluster ({"profile": "single-node" | "multi-node", "nodes", "single_node_limits_sha256" for one node}),
from which the signer floors are derived: a majority of the DESIGNED nodes, never of the nodes a manifest happens to list
as live. tests/vectors/make-membership-v5.py records the accept() calls made here for the Go port."""
import copy
import json
import pathlib
import unittest

from deploy.baremetal import beat
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
from deploy.baremetal import replacement
from deploy.baremetal import revoke
from tests.test_baremetal_heartbeat import T0, stamp
from tests.test_baremetal_membership import ROOT, ROOT_PUB, node, sign
from tests.test_baremetal_membership_v4 import (CARD_RECORD, K_A, NODE_KEYS, OWNER_KEYS, STRANGER, manifest4, nodes4, p256_sig, pub,
                                                quorum, restored, ssh, typed)

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "membership-v5.json"
LIMITS = "5e" * 32                     # the digest of the single-node limits text (dx7.11): a placeholder here
MULTI = {"profile": "multi-node", "nodes": 3}
SINGLE = {"profile": "single-node", "nodes": 1, "single_node_limits_sha256": LIMITS}
A, B, C = ("a", NODE_KEYS["a"]), ("b", NODE_KEYS["b"]), ("c", NODE_KEYS["c"])
D = ("d", NODE_KEYS["d"])
O1 = ("owner", OWNER_KEYS[0])


def manifest5(epoch, prev, nodes, topology=MULTI, **fields):
    man = manifest4(epoch, prev, nodes, **fields)
    man.update(schema=m.SCHEMA_V5, topology=copy.deepcopy(topology))
    return man


def one(nid="a", state="ACTIVE", i=0):
    return dict(node(nid, state, i), ssh_host_pub=ssh(i), signing_key=typed(NODE_KEYS[nid]))


def alone(nid):
    """A single-node manifest's three rules, for node `nid`: the node signs its own heartbeats and activation, the owner
    alone revokes."""
    return {"heartbeat_signers": {"threshold": 1, "parties": [nid]}, "activation_signers": {"threshold": 1, "parties": [nid]},
            "revocation_signers": [{"threshold": 1, "parties": ["owner"]}]}


def single5(epoch, prev, nodes=None, nid="a", **fields):
    return manifest5(epoch, prev, nodes or [one(nid)], SINGLE, **dict(alone(nid), **fields))


class Case(unittest.TestCase):
    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def genesis(self, man):
        return m.accept(None, sign(man, ROOT), ROOT_PUB)

    def invalid(self, reason, man):
        """A first manifest, signed by the root, refused by the format alone (through accept(), so the vectors carry it)."""
        self.refused(reason, self.genesis, man)


class Topology(Case):
    def test_a_multi_node_v5_is_v4_with_its_designed_size(self):
        first = self.genesis(manifest5(1, "", nodes4()))
        self.assertEqual((first["schema"], first["topology"], m.designed_nodes(first)), (m.SCHEMA_V5, MULTI, 3))
        self.assertTrue(m.may(first, "a", "authorize"))

    def test_a_single_node_v5_signs_alone(self):
        first = self.genesis(single5(1, ""))
        self.assertEqual((m.designed_nodes(first), m.node_floor(first)), (1, 1))
        self.assertTrue(m.may(first, "a", "serve"))

    def test_a_v4_manifest_is_a_three_node_cluster(self):
        """v4 predates the field: its designed size is three, the floors of 2 it has always had."""
        v4 = manifest4(1, "", nodes4())
        self.assertEqual((m.designed_nodes(v4), m.node_floor(v4)), (3, 2))

    def test_the_field_is_validated(self):
        def changed(base, change):
            man = copy.deepcopy(base)
            change(man)
            return man
        multi, single = manifest5(1, "", nodes4()), single5(1, "")
        for name, man, reason in (
                ("no topology", changed(multi, lambda x: x.pop("topology")), "manifest fields mismatch"),
                ("a topology under v4", dict(manifest4(1, "", nodes4()), topology=MULTI), "manifest fields mismatch"),
                ("a topology not an object", changed(multi, lambda x: x.update(topology="multi-node")), "topology must be an object"),
                ("an unknown profile", changed(multi, lambda x: x["topology"].update(profile="cluster")),
                 "topology.profile must be single-node or multi-node"),
                ("a profile not text", changed(multi, lambda x: x["topology"].update(profile=3)),
                 "topology.profile must be single-node or multi-node"),
                ("an extra field", changed(multi, lambda x: x["topology"].update(zone="alder")), "topology fields mismatch"),
                ("a multi-node limits digest", changed(multi, lambda x: x["topology"].update(single_node_limits_sha256=LIMITS)),
                 "topology fields mismatch"),
                ("a single node without its limits digest", changed(single, lambda x: x["topology"].pop("single_node_limits_sha256")),
                 "topology fields mismatch"),
                ("a limits digest in capitals", changed(single, lambda x: x["topology"].update(single_node_limits_sha256="5E" * 32)),
                 "topology.single_node_limits_sha256 must be 64 lowercase hex"),
                ("a limits digest short", changed(single, lambda x: x["topology"].update(single_node_limits_sha256="5e" * 31)),
                 "topology.single_node_limits_sha256 must be 64 lowercase hex"),
                ("nodes true", changed(multi, lambda x: x["topology"].update(nodes=True)), "topology.nodes must be an integer"),
                ("nodes as text", changed(multi, lambda x: x["topology"].update(nodes="3")), "topology.nodes must be an integer"),
                ("a single node of 3", changed(single, lambda x: x["topology"].update(nodes=3)), "a single-node topology has nodes 1, not 3"),
                ("a multi-node of 1", changed(multi, lambda x: x["topology"].update(nodes=1)),
                 "a multi-node topology has an odd number of nodes from 3, not 1"),
                ("a multi-node of 2", changed(multi, lambda x: x["topology"].update(nodes=2)),
                 "a multi-node topology has an odd number of nodes from 3, not 2"),
                ("a multi-node of 4", changed(multi, lambda x: x["topology"].update(nodes=4)),
                 "a multi-node topology has an odd number of nodes from 3, not 4"),
                ("a multi-node of 0", changed(multi, lambda x: x["topology"].update(nodes=0)),
                 "a multi-node topology has an odd number of nodes from 3, not 0"),
                ("a multi-node of 5", changed(multi, lambda x: x["topology"].update(nodes=5)),
                 "a multi-node topology of 5 nodes is not supported yet (3 only"),
                ("a multi-node of 7", changed(multi, lambda x: x["topology"].update(nodes=7)),
                 "a multi-node topology of 7 nodes is not supported yet (3 only")):
            with self.subTest(name):
                self.invalid(reason, man)


class Floors(Case):
    """The floor is floor(nodes / 2) + 1 of the DESIGNED nodes: 1 for one node, 2 for three (v4's), whatever the
    manifest lists as live."""

    def test_three_designed_nodes_keep_v4_s_floors(self):
        for name, change, reason in (
                ("a heartbeat threshold of 1", lambda x: x["heartbeat_signers"].update(threshold=1), "heartbeat_signers.threshold must be from 2"),
                ("an activation threshold of 1", lambda x: x["activation_signers"].update(threshold=1), "activation_signers.threshold must be from 2"),
                ("a node revocation rule at 1", lambda x: x["revocation_signers"][0].update(threshold=1),
                 "revocation_signers[0].threshold must be from 2"),
                ("the owner and a node at 1", lambda x: x["revocation_signers"][1].update(parties=["owner", "a"]),
                 "revocation_signers[1].threshold must be from 2")):
            with self.subTest(name):
                man = manifest5(1, "", nodes4())
                change(man)
                self.invalid(reason, man)
        self.genesis(manifest5(1, "", nodes4()))                                 # the control: v4's rules as they are

    def test_two_retired_nodes_do_not_make_three_designed_nodes_one(self):
        """No code derives the size from the nodes that are live: a three-node manifest with two RETIRED nodes is a
        three-node cluster in an outage, never a one-node cluster."""
        nodes = nodes4(b="RETIRED", c="RETIRED")
        man = manifest5(1, "", nodes, **alone("a"))
        self.assertEqual((m.designed_nodes(man), m.node_floor(man)), (3, 2))
        self.invalid("heartbeat_signers.threshold must be from 2", man)
        lone = manifest5(1, "", nodes, heartbeat_signers={"threshold": 2, "parties": ["a", "owner"]},
                         activation_signers={"threshold": 2, "parties": ["a", "b", "c"]})
        self.assertEqual(self.genesis(lone)["topology"], MULTI)

    def test_more_live_nodes_than_designed_are_refused(self):
        d = one("d", i=3)
        self.invalid("a 3-node topology lists at most 3 nodes that are not RETIRED or REVOKED_STOLEN (4)",
                     manifest5(1, "", nodes4() + [d]))
        self.genesis(manifest5(1, "", nodes4(c="RETIRED") + [d]))                # the control: c retired, d in its place

    def test_one_designed_node_has_at_most_one_live_node(self):
        for name, nodes, reason in (
                ("two active nodes", [one("a"), one("b", i=1)], "a single-node topology lists at most one node that is not RETIRED or "
                 "REVOKED_STOLEN (2)"),
                ("the node quarantined and another active", [one("a", "QUARANTINED"), one("b", i=1)], "(2)")):
            with self.subTest(name):
                self.invalid(reason, single5(1, "", nodes))
        self.genesis(single5(1, "", [one("b", "RETIRED", 1), one("a")]))         # the control: a tombstone does not count
        # none: the owner revoked it (CodeRabbit on #725), and the rules still name it
        self.genesis(single5(1, "", [one("a", "REVOKED_STOLEN")]))

    def test_with_no_live_node_the_rules_name_one_node_of_the_manifest(self):
        stopped = [one("a", "REVOKED_STOLEN"), one("b", "RETIRED", 1)]
        for name, rules, reason in (
                ("the owner in the heartbeat rule", {"heartbeat_signers": {"threshold": 1, "parties": ["owner"]}},
                 "under single-node heartbeat_signers is {threshold 1, parties [the node]}"),
                ("two nodes named", {"activation_signers": {"threshold": 1, "parties": ["b"]}},
                 "under single-node activation_signers is {threshold 1, parties [a]}")):
            with self.subTest(name):
                self.invalid(reason, single5(1, "", stopped, **rules))
        self.genesis(single5(1, "", stopped, nid="b"))                              # the control: one node named in both

    def test_one_designed_node_has_one_shape_of_rules(self):
        for name, rules, reason in (
                ("the owner in the heartbeat rule", {"heartbeat_signers": {"threshold": 1, "parties": ["a", "owner"]}},
                 "under single-node heartbeat_signers is {threshold 1, parties [a]}"),
                ("the owner alone in the heartbeat rule", {"heartbeat_signers": {"threshold": 1, "parties": ["owner"]}},
                 "under single-node heartbeat_signers is {threshold 1, parties [a]}"),
                ("the owner in the activation rule", {"activation_signers": {"threshold": 1, "parties": ["owner"]}},
                 "under single-node activation_signers is {threshold 1, parties [a]}"),
                ("the node and the owner at 2", {"activation_signers": {"threshold": 2, "parties": ["a", "owner"]}},
                 "under single-node activation_signers is {threshold 1, parties [a]}"),
                ("the node revoking itself", {"revocation_signers": [{"threshold": 1, "parties": ["a"]}]},
                 "under single-node revocation_signers is [{threshold 1, parties [owner]}]"),
                ("a second revocation rule", {"revocation_signers": [{"threshold": 1, "parties": ["owner"]}, {"threshold": 1, "parties": ["a"]}]},
                 "under single-node revocation_signers is [{threshold 1, parties [owner]}]"),
                ("the node and the owner revoking", {"revocation_signers": [{"threshold": 2, "parties": ["a", "owner"]}]},
                 "under single-node revocation_signers is [{threshold 1, parties [owner]}]"),
                ("a rule naming the tombstone", {"heartbeat_signers": {"threshold": 1, "parties": ["b"]}},
                 "under single-node heartbeat_signers is {threshold 1, parties [a]}")):
            with self.subTest(name):
                nodes = [one("a"), one("b", "RETIRED", 1)]
                self.invalid(reason, single5(1, "", nodes, **rules))

    def test_three_designed_nodes_refuse_the_single_node_rules(self):
        """The control of the floor: the rules one designed node takes are refused for three, because of the floor."""
        self.genesis(single5(1, ""))
        self.invalid("heartbeat_signers.threshold must be from 2", manifest5(1, "", [one("a")], **alone("a")))


class Transitions(Case):
    def test_a_quorum_cannot_change_the_topology(self):
        first = self.genesis(single5(1, ""))
        man = single5(2, m.digest(first))
        man["topology"] = dict(SINGLE, single_node_limits_sha256="5f" * 32)
        self.refused("a revocation quorum cannot change topology", m.accept, first, quorum(man, O1), ROOT_PUB)
        quarantined = single5(2, m.digest(first), [one("a", "QUARANTINED")])
        self.assertEqual(m.accept(first, quorum(quarantined, O1), ROOT_PUB)["nodes"][0]["state"], "QUARANTINED")  # the control

    def test_not_even_the_root_changes_the_topology(self):
        first = self.genesis(manifest5(1, "", nodes4(b="RETIRED", c="RETIRED"), heartbeat_signers={"threshold": 2, "parties": ["a", "owner"]},
                                       activation_signers={"threshold": 2, "parties": ["a", "b", "c"]}))
        reason = "topology is set at genesis and never changes, for any signer: another size or profile is a new genesis"
        to_one = single5(2, m.digest(first), [one("a"), one("b", "RETIRED", 1), one("c", "RETIRED", 2)])
        self.refused(reason, m.accept, first, sign(to_one, ROOT), ROOT_PUB)
        single = self.genesis(single5(1, ""))
        other = single5(2, m.digest(single))
        other["topology"]["single_node_limits_sha256"] = "5f" * 32
        self.refused(reason, m.accept, single, sign(other, ROOT), ROOT_PUB)
        same = single5(2, m.digest(single), policy_version="p2")
        self.assertEqual(m.accept(single, sign(same, ROOT), ROOT_PUB)["policy_version"], "p2")   # the control

    def test_a_single_node_is_replaced_by_the_root(self):
        first = self.genesis(single5(1, ""))
        replaced = single5(2, m.digest(first), [one("a", "RETIRED"), one("d", i=3)], nid="d")
        replacement.check_replacement(first, replaced, "a", "d")
        self.assertEqual(m.accept(first, sign(replaced, ROOT), ROOT_PUB)["heartbeat_signers"], {"threshold": 1, "parties": ["d"]})
        both = single5(2, m.digest(first), [one("a"), one("d", i=3)], nid="d")
        self.refused("a single-node topology lists at most one node that is not RETIRED or REVOKED_STOLEN (2)",
                     m.accept, first, sign(both, ROOT), ROOT_PUB)

    def test_the_owner_alone_revokes_the_only_node(self):
        """CodeRabbit on #725: the owner's REVOKED_STOLEN of the only node is a valid manifest (the KMS stops), and the root
        then enrols a replacement."""
        first = self.genesis(single5(1, ""))
        stolen = m.accept(first, quorum(single5(2, m.digest(first), [one("a", "REVOKED_STOLEN")]), O1), ROOT_PUB)
        self.assertFalse(m.may(stolen, "a", "serve"))
        revived = single5(3, m.digest(stolen), [one("a")])
        self.refused("tombstone: a is REVOKED_STOLEN, which is terminal for every signer", m.accept, stolen, sign(revived, ROOT), ROOT_PUB)
        replaced = single5(3, m.digest(stolen), [one("a", "REVOKED_STOLEN"), one("d", i=3)], nid="d")
        self.assertEqual(m.accept(stolen, sign(replaced, ROOT), ROOT_PUB)["heartbeat_signers"]["parties"], ["d"])
        quarantined = single5(2, m.digest(first), [one("a", "QUARANTINED")])
        self.refused("meet no revocation_signers rule of the current manifest (counting: a)", m.accept, first, quorum(quarantined, A), ROOT_PUB)
        self.assertEqual(m.accept(first, quorum(quarantined, O1), ROOT_PUB)["epoch"], 2)

    def test_the_root_moves_a_v4_chain_to_a_three_node_v5(self):
        v4 = self.genesis(manifest4(1, "", nodes4()))
        v5 = m.accept(v4, sign(manifest5(2, m.digest(v4), nodes4()), ROOT), ROOT_PUB)
        self.assertEqual((v5["schema"], v5["topology"]), (m.SCHEMA_V5, MULTI))
        self.refused("only the root can change the schema (regalia.membership/v4 to regalia.membership/v5)",
                     m.accept, v4, quorum(manifest5(2, m.digest(v4), nodes4()), A, B), ROOT_PUB)

    def test_a_v4_chain_never_becomes_one_node_in_place(self):
        v4 = self.genesis(manifest4(1, "", nodes4(b="RETIRED", c="RETIRED"), heartbeat_signers={"threshold": 2, "parties": ["a", "owner"]}))
        to_one = single5(2, m.digest(v4), v4["nodes"])
        self.refused("a regalia.membership/v4 chain is a three-node cluster: its move to regalia.membership/v5 names the topology "
                     "{multi-node, 3 nodes} (one node is a new genesis)", m.accept, v4, sign(to_one, ROOT), ROOT_PUB)

    def test_nothing_moves_a_chain_back_from_v5(self):
        v5 = self.genesis(manifest5(1, "", nodes4()))
        self.refused("schema regalia.membership/v4 cannot follow regalia.membership/v5: the schema only moves forward",
                     m.accept, v5, sign(manifest4(2, m.digest(v5), nodes4()), ROOT), ROOT_PUB)

    def test_the_move_to_v5_keeps_k_a_and_the_card_rules(self):
        v4 = self.genesis(manifest4(1, "", nodes4()))
        self.refused("anchor_policy_key is set at genesis and never changes", m.accept, v4,
                     sign(manifest5(2, m.digest(v4), nodes4(), anchor_policy_key=typed(STRANGER)), ROOT), ROOT_PUB)
        fewer = manifest5(2, m.digest(v4), nodes4())
        fewer["owner_keys"].pop()
        self.refused("owner_keys change only with a new card_record", m.accept, v4, sign(fewer, ROOT), ROOT_PUB)
        v5 = self.genesis(manifest5(1, "", nodes4()))
        self.refused("anchor_policy_key is set at genesis and never changes", m.accept, v5,
                     sign(manifest5(2, m.digest(v5), nodes4(), anchor_policy_key=typed(STRANGER)), ROOT), ROOT_PUB)
        lower = manifest5(2, m.digest(v5), nodes4(), card_record={"sequence": 1, "digest": "cb" * 32})
        self.refused("card_record changes only to a later card ceremony's record", m.accept, v5, sign(lower, ROOT), ROOT_PUB)
        self.assertEqual(m.accept(v4, sign(manifest5(2, m.digest(v4), nodes4()), ROOT), ROOT_PUB)["card_record"], CARD_RECORD)

    def test_the_root_is_never_a_party(self):
        man = manifest5(1, "", nodes4())
        man["owner_keys"].append({"alg": "ed25519", "key": ROOT_PUB})
        self.invalid("owner_keys[3] is a pinned root key: the payload root is never a quorum party", man)


class Consumers(Case):
    """What reads a v4 manifest's signers reads a v5 one's the same way."""

    def test_a_heartbeat_under_one_node_is_the_node_s_alone(self):
        first = single5(1, "")
        body = {"schema": hb.SCHEMA, "epoch": 1, "sequence": 1, "issued_at": stamp(T0), "expires_at": stamp(T0 + 3600),
                "manifest_digest": m.digest(first)}
        signed = {"heartbeat": body, "signatures": [{"party": "a", "key": pub(NODE_KEYS["a"]),
                                                     "sig": p256_sig(NODE_KEYS["a"], hb.DOMAIN + m.canonical(body))}]}
        self.assertEqual(hb.signed_by(signed, first)[3], {"a"})
        self.assertEqual(beat.counting_nodes(first), ["a"])

    def test_the_owner_revokes_a_v5_node(self):
        first = single5(1, "")
        nxt = revoke.candidate(first, "a", "QUARANTINED", T0)
        self.assertEqual((nxt["schema"], nxt["nodes"][0]["state"]), (m.SCHEMA_V5, "QUARANTINED"))
        self.assertEqual(m.accept(self.genesis(first), quorum(nxt, O1), ROOT_PUB)["epoch"], 2)

    def test_counting_parties_reads_a_v5_manifest(self):
        man = manifest5(1, "", nodes4())
        sigs = [{"party": "a", "key": pub(NODE_KEYS["a"]), "sig": p256_sig(NODE_KEYS["a"], b"x")}]
        self.assertEqual(m.counting_parties(man, b"x", sigs, "test"), {"a"})


class Vectors(unittest.TestCase):
    def test_the_shared_vectors_are_what_this_python_decides(self):
        """tests/vectors/membership-v5.json, which the Go port reads, replayed here: a vector the Python no longer decides
        the same way fails, so the file cannot drift from the code."""
        cases = json.loads(VECTORS.read_text())["cases"]
        self.assertGreater(len(cases), 40)
        seen = {"accepted": 0, "refused": 0}
        for case in cases:
            with self.subTest(case["name"]):
                try:
                    outcome = {"accepted": m.digest(m.accept(restored(case["current"]), restored(case["envelope"]), restored(case["root_public"])))}
                except m.Refused as refusal:
                    outcome = {"refused": str(refusal)}
                want = {k: case[k] for k in ("accepted", "refused") if k in case}
                self.assertEqual(outcome, want)
                seen[next(iter(want))] += 1
        self.assertTrue(seen["accepted"] >= 10 and seen["refused"] >= 30, seen)


if __name__ == "__main__":
    unittest.main()
