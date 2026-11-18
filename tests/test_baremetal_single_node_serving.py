"""regalia-kms-dx7.3 (docs/design/single-node.md 4.3): under the single-node profile a lone survivor, a fence, a take-over
and a rejoin are refused by name rather than passed vacuously over no other node; activation is 1-of-1, the node alone;
and the node's verifier of its own quotes exists there only. Under multi-node, each is as before. The self-issued
runtime lease and admission mode "single" are tests/test_baremetal_lease.py's SelfIssued and
tests/test_baremetal_admission.py's Single; tests/vectors/self-lease-v1.json holds Python and Go to one decision."""
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import activation as act, measurements, membership as m, rejoin, survivor as sv, takeover as tk
from tests.test_baremetal_activation import Counter
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, manifest4, nodes4, p256_sig, pub
from tests.test_baremetal_membership_v5 import MULTI, manifest5, single5

T0 = 1791201600
NAMED = "under the single-node profile (epoch 1): one node has no other node to survive, fence, take over from or rejoin"


def owner_signed(tip, others=()):
    """An authorization the owner signed WITHOUT the tool's checks, for `tip`: what verify must judge on its own."""
    auth = {"schema": sv.AUTH_SCHEMA, "node_id": "a", "quarantine_epoch": tip["epoch"], "quarantine_digest": m.digest(tip),
            "not_before": "2026-10-05T12:00:00Z", "expires_at": "2026-10-06T12:00:00Z", "fenced": "nothing: one node", "scope": "full",
            "fence": {"method": "attested", "nodes": {o: {"power_state": "unreachable", "read_at": "2026-10-05T12:00:00Z"} for o in others}}}
    return {"authorization": auth, "signature": {"party": m.OWNER, "key": pub(OWNER_KEYS[0]),
                                                 "sig": OWNER_KEYS[0].sign(sv.AUTH_DOMAIN + m.canonical(auth)).hex()}}


class Case(unittest.TestCase):
    def setUp(self):
        self.s1 = single5(1, "")
        self.multi = manifest5(1, "", nodes4(), MULTI)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))
        return str(caught.exception)


class Profile(Case):
    def test_the_profile_is_the_signed_topology_s_and_multi_node_before_v5(self):
        self.assertEqual([m.profile(x) for x in (self.s1, self.multi, manifest4(1, "", nodes4()))],
                         [m.SINGLE_NODE, m.MULTI_NODE, m.MULTI_NODE])
        broken = dict(self.multi, topology={"profile": "two-node", "nodes": 2})
        self.refused("topology.profile must be single-node or multi-node", m.profile, broken)
        self.refused("topology.profile must be single-node or multi-node", m.profile, dict(self.multi, topology=None))
        self.refused("a manifest is an object", m.profile, None)

    def test_not_single_node_names_the_profile_and_lets_multi_node_through(self):
        self.refused("a fence is refused " + NAMED, m.not_single_node, self.s1, "a fence")
        m.not_single_node(self.multi, "a fence")
        m.not_single_node(manifest4(1, "", nodes4()), "a fence")


class Survivor(Case):
    def test_the_owner_tool_refuses_a_survivor_authorization_by_profile(self):
        self.refused("a survivor authorization is refused " + NAMED, sv.make_authorization, self.s1, "a", "nothing to fence", T0,
                     lambda text: self.fail("the owner was asked to confirm"), lambda: self.fail("the owner's key was opened"))

    def test_the_node_refuses_one_by_profile_before_anything_else(self):
        signed = owner_signed(self.s1)
        self.refused("a survivor authorization is refused " + NAMED, sv.verify_authorization, signed, self.s1)
        self.refused("a survivor authorization is refused " + NAMED, sv.in_force, signed, self.s1, "a", T0 + 60)

    def test_installed_on_a_single_node_it_does_not_admit(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, sv.AUTH_FILE)
        with open(path, "w") as f:
            json.dump(owner_signed(self.s1), f)
        self.refused("a survivor authorization is refused " + NAMED, sv.seconds_left, path, self.s1, "a", lambda: (T0 + 60, True),
                     owner_uid=os.getuid())


class TakeOverAndRejoin(Case):
    def test_a_take_over_is_refused_by_profile_and_recorded(self):
        trail = []
        host = unittest.mock.Mock(side_effect=AssertionError("the host was touched"))
        self.refused("a take-over is refused " + NAMED, tk.take_over, host, owner_signed(self.s1), [self.s1], "a", T0 + 10 ** 5,
                     lambda raw: self.fail("signed"), trail.append)
        self.assertEqual([e["outcome"] for e in trail], ["REQUEST", "DENY"])
        self.assertEqual(host.mock_calls, [])

    def test_every_rejoin_command_is_refused_by_profile_and_recorded(self):
        for command, kw in (("admit", {"node": "b"}), ("join", {"line": "a=x", "member_id": "1"}), ("promote", {"node": "b"}),
                            ("finish", {}), ("abandon", {"node": "b"})):
            with self.subTest(command):
                trail = []
                host = unittest.mock.Mock(side_effect=AssertionError("the host was touched"))
                self.refused("a rejoin is refused " + NAMED, rejoin.audited_command, host, [self.s1], "a", command, record=trail.append, **kw)
                self.assertEqual([e["outcome"] for e in trail], ["REQUEST", "DENY"])
                self.assertEqual(host.mock_calls, [])


class Fence(Case):
    def run_fence(self, tip, fence):
        from deploy.baremetal import fence as fe, manifest as manifest_tool, owner
        from tests.test_baremetal_fence import BOXES
        from tests.test_baremetal_membership import ROOT_PUB
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        paths = {name: os.path.join(d, name + ".json") for name in ("inv", "chain")}
        with open(paths["inv"], "w") as f:
            json.dump({"schema": fe.INVENTORY_SCHEMA, "nodes": {"b": BOXES["b"]}}, f)
        with open(paths["chain"], "w") as f:
            json.dump([{"the chain": "verify_chain's, stood in for"}], f)
        read, write = os.pipe()
        os.write(write, b'{"b": {"username": "u", "password": "p"}}')
        os.close(write)
        out = os.path.join(d, "fence.json")
        with unittest.mock.patch.object(fe, "fence", fence), unittest.mock.patch.object(owner, "off_the_nodes", lambda: None), \
                unittest.mock.patch.object(manifest_tool, "verify_chain", lambda chain, root: tip), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as complained:
            got = owner.main(["fence", "--chain", paths["chain"], "--root-key", ROOT_PUB, "--inventory", paths["inv"], "--node", "b",
                              "--credentials-fd", str(read), "--out", out])
        return got, complained.getvalue(), os.path.lexists(out)

    def test_the_owner_s_fence_is_refused_by_profile_before_any_server_is_touched(self):
        calls = []
        got, said, wrote = self.run_fence(self.s1, lambda *a, **k: calls.append(a))
        self.assertEqual((got, calls, wrote), (1, [], False), said)
        self.assertIn("a fence is refused " + NAMED, said)

    def test_under_multi_node_the_fence_runs(self):
        calls = []
        got, said, wrote = self.run_fence(self.multi, lambda *a, **k: calls.append(a) or {"method": "redfish", "nodes": {}})
        self.assertEqual((got, len(calls), wrote), (0, 1, True), said)


class Activation(Case):
    def setUp(self):
        super().setUp()
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def node(self, name, counter=None):
        rec = act.GrantRecord(counter or Counter(), os.path.join(self.d, "%s-grant.json" % name), T0 - 3600)
        return act.Signer(name, rec, lambda raw, k=NODE_KEYS[name]: p256_sig(k, raw), pub(NODE_KEYS[name]))

    def test_under_single_node_the_node_activates_itself_one_of_one_and_asks_no_one(self):
        a, events = self.node("a"), []
        env = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.s1, lambda: (T0, True), a,
                          lambda peer, body: self.fail("a peer was asked"), [], events.append)
        self.assertEqual([s["party"] for s in env["signatures"]], ["a"])
        self.assertEqual(act.verify(env, self.s1)["activation_epoch"], 1)
        self.assertEqual((a.record.counter.v, events[-1]["outcome"]), (1, "ALLOW"))
        # the grant record still applies: the next activation is the next epoch, never the same one again
        again = act.propose("a", "site-a", "sha256:" + "ab" * 32, self.s1, lambda: (T0 + 60, True), a, None, [], events.append)
        self.assertEqual((again["lease"]["activation_epoch"], a.record.counter.v), (2, 2))

    def act(self, a, t, manifest=None):
        return act.propose("a", "site-a", "sha256:" + "ab" * 32, manifest or self.s1, lambda: (t, True), a, None, [], lambda e: None)

    def inherited(self, counter_at, epoch):
        """A reused TPM's node: its counter counted `counter_at` grants, its record's last epoch `epoch` (an earlier
        cluster's, or co-signed under multi-node, where an epoch runs ahead of this node's count)."""
        counter = Counter(counter_at)
        a = self.node("a", counter)
        with open(a.record.path, "w") as f:
            json.dump({"grants": counter_at, "activation_epoch": epoch, "site": "site-a", "node_id": "a", "expires_at": T0 - 600}, f)
        return a, counter

    def test_a_lost_grant_record_never_lowers_the_epoch(self):
        """CodeRabbit on #736: a lost record leaves no last grant and no co-signer can name it; the counter, raised to each
        epoch granted, is the floor."""
        counter = Counter()
        a = self.node("a", counter)
        for t in (T0, T0 + 60):
            self.act(a, t)
        os.unlink(a.record.path)
        again = self.act(a, T0 + 60 + act.RECOVERY_WAIT_S)                 # past the busy wait of a record that does not stand
        self.assertEqual((again["lease"]["activation_epoch"], counter.v), (3, 3))

    def test_the_counter_is_raised_to_the_epoch_so_a_reused_tpm_never_falls_back_to_its_count(self):
        """CodeRabbit's case on #736: record epoch 100 at count 2; the next grant is 101; that record is lost. The next epoch
        must be 102, never 4 (count + 1). Also the TPM reused for a new single-node genesis: the record it brings rules."""
        for manifest in (self.s1, single5(1, "", issued_at="2026-11-01T00:00:00Z")):     # this genesis, and a new one
            with self.subTest(m.digest(manifest)[:8]):
                a, counter = self.inherited(2, 100)
                self.assertEqual(self.act(a, T0, manifest)["lease"]["activation_epoch"], 101)
                self.assertEqual(counter.v, 101)                           # raised to the epoch, before the record
                os.unlink(a.record.path)
                later = self.act(a, T0 + act.RECOVERY_WAIT_S, manifest)["lease"]["activation_epoch"]
                self.assertEqual((later, counter.v), (102, 102))

    def test_a_crash_between_the_counter_and_the_record_never_lowers_the_epoch(self):
        a, counter = self.inherited(2, 100)
        real = os.replace
        with unittest.mock.patch("os.replace", side_effect=OSError("crash before the record")):
            with self.assertRaises(OSError):
                self.act(a, T0)
        self.assertEqual(counter.v, 101)                                   # the counter moved, the record did not
        self.assertIs(os.replace, real)
        self.assertEqual(self.act(a, T0 + 60)["lease"]["activation_epoch"], 102)  # the record (count 2) does not stand: 101 + 1

    def test_a_raise_past_the_bound_signs_nothing_and_moves_nothing(self):
        a, counter = self.inherited(1, act.MAX_FLOOR_JUMP + 1)              # the next epoch is MAX_FLOOR_JUMP + 1 above the count
        self.refused("increments, above %d: nothing is signed" % act.MAX_FLOOR_JUMP, self.act, a, T0)
        self.assertEqual(counter.v, 1)

    def test_under_multi_node_the_counter_still_counts_grants(self):
        a, counter = self.inherited(2, 100)
        a.record.record({"activation_epoch": 101, "site": "site-a", "node_id": "a"}, T0 + 600)
        self.assertEqual(counter.v, 3)

    def test_under_multi_node_one_node_alone_never_activates(self):
        a, events = self.node("a"), []
        self.refused("no node co-signed this activation", act.propose, "a", "site-a", "sha256:" + "ab" * 32, self.multi,
                     lambda: (T0, True), a, None, [], events.append)
        body = act.proposal("a", "site-a", "sha256:" + "ab" * 32, self.multi, 1, T0)
        alone = {"lease": body, "signatures": [{"party": "a", "key": pub(NODE_KEYS["a"]), "sig": p256_sig(NODE_KEYS["a"], act.message(body))}]}
        self.refused("1 of the nodes signed (a); activation needs 2", act.verify, alone, self.multi)


class OwnAttestation(Case):
    def test_the_node_attests_its_own_quotes_under_single_node_only(self):
        with unittest.mock.patch.object(measurements, "bind", lambda manifest, document: {
                n["node_id"]: {"tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}} for n in manifest["nodes"]}):
            policy = measurements.self_attest_policy(self.s1, None, "a")
            self.assertEqual(sorted(policy["nodes"]), ["a"])
            self.assertEqual(policy["nodes"]["a"]["ek_name"], self.s1["nodes"][0]["ek_name"])
            self.refused("a node attests its own quotes only under the single-node profile; epoch 1 is multi-node",
                         measurements.self_attest_policy, self.multi, None, "a")
            self.refused("'b' is not a node of the manifest", measurements.self_attest_policy, self.s1, None, "b")
