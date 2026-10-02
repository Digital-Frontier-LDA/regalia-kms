"""Rolling a new boot image through three nodes (#75, Phase 15): deploy/baremetal/measurements.py (the
document the membership manifest commits to, CURRENT and NEXT) and deploy/baremetal/rollout.py (may this
node reboot now; may CURRENT be retired).

The TPM identities and the lease signatures are the OpenSSL fixtures of tests/test_baremetal_lease.py.
The same sequence on three software TPMs, with real quotes, is e2e/rolling-policy-swtpm.sh."""
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from deploy.baremetal import attest, lease, measurements, replacement, rollout
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt

FW = "0" * 16
IMAGE1, IMAGE2, IMAGE3 = ({"7": "00" * 32, "11": c * 32} for c in ("a1", "b2", "c3"))


def one(label, pcrs, fw=FW):
    return {"label": label, "tpm_firmware_version": fw, "pcrs": dict(pcrs)}


def document(name, **nodes):
    """document("v2", a=[one(...), one(...)], ...)"""
    return {"schema": measurements.SCHEMA, "name": name, "nodes": {n: {"accepted": sets} for n, sets in nodes.items()}}


CURRENT = document("v1", **{n: [one("image-1", IMAGE1)] for n in "abc"})
BOTH = document("v2", **{n: [one("image-1", IMAGE1), one("image-2", IMAGE2)] for n in "abc"})
NEXT = document("v3", **{n: [one("image-2", IMAGE2)] for n in "abc"})


class Case(lt.Case):
    def under(self, doc, epoch=1, prev="", **states):
        """A manifest that commits to `doc`."""
        return dict(self.manifest(epoch, prev, **states), policy_version=measurements.version(doc))

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))
        return str(caught.exception)


class Document(Case):
    def test_the_version_is_a_digest_of_the_whole_document_and_fits_the_manifest_field(self):
        v = measurements.version(BOTH)
        self.assertRegex(v, r"^m1-[0-9a-f]{29}$")
        m.validate(self.under(BOTH))                                   # 32 characters: a valid policy_version
        self.assertEqual(v, measurements.version(copy.deepcopy(BOTH)))
        changed = copy.deepcopy(BOTH)
        changed["nodes"]["c"]["accepted"][1]["pcrs"]["11"] = "b3" * 32   # one hex digit of one PCR of one node
        self.assertNotEqual(measurements.version(changed), v)
        renamed = dict(copy.deepcopy(BOTH), name="v2b")
        self.assertNotEqual(measurements.version(renamed), v)
        # key order is not content
        reordered = {"nodes": dict(reversed(list(BOTH["nodes"].items()))), "name": "v2", "schema": measurements.SCHEMA}
        self.assertEqual(measurements.version(reordered), v)

    def test_a_document_is_accepted_only_under_the_manifest_that_commits_to_it(self):
        bound = measurements.bind(self.under(BOTH), BOTH)
        self.assertEqual(sorted(bound), ["a", "b", "c"])
        self.assertEqual([s["label"] for s in bound["a"]["accepted"]], ["image-1", "image-2"])
        # the older document under the newer manifest: the rollback a restored policy file would be
        self.refused("it is not the one the root approved, or it is an older or newer one", measurements.bind, self.under(NEXT), BOTH)
        self.refused("is not the one the root approved", measurements.bind, self.under(BOTH), NEXT)
        # a manifest that names no document at all (the pre-#75 free text)
        self.refused("commits to measurements p1", measurements.bind, self.manifest(), CURRENT)
        # one changed value is another document
        changed = copy.deepcopy(BOTH)
        changed["nodes"]["a"]["accepted"][1]["pcrs"]["11"] = "ff" * 32
        self.refused("is not the one the root approved", measurements.bind, self.under(BOTH), changed)

    def test_every_node_that_may_attest_needs_an_entry_and_no_stranger_gets_one(self):
        two = document("two", a=[one("image-1", IMAGE1)], b=[one("image-1", IMAGE1)])
        self.refused("no entry for c, which the manifest lets attest", measurements.bind, self.under(two), two)
        measurements.bind(self.under(two, c="QUARANTINED"), two)      # a node that may do nothing needs none
        measurements.bind(self.under(two, c="RETIRED"), two)
        extra = document("extra", **{n: [one("image-1", IMAGE1)] for n in ("a", "b", "c", "z")})
        self.refused("nodes the manifest does not list: z", measurements.bind, self.under(extra), extra)

    def test_the_bound_document_is_what_the_attestation_policy_is_built_from(self):
        manifest = self.under(BOTH)
        policy = replacement.attest_policy(manifest, measurements.bind(manifest, BOTH), peer_id="b")
        self.assertEqual(sorted(policy["nodes"]), ["a", "c"])
        self.assertEqual(policy["nodes"]["a"], {"ek_name": self.keys["a"].ek_name, "accepted": BOTH["nodes"]["a"]["accepted"]})
        nodes = attest.validate_policy(policy)
        self.assertEqual([s["label"] for s in nodes["c"]["accepted"]], ["image-1", "image-2"])

    def test_schema_refusals(self):
        ok = lambda: copy.deepcopy(BOTH)   # noqa: E731
        cases = (
            ("another schema", "schema must be", lambda d: d.update(schema="regalia.measurements/v0")),
            ("an unknown field", "fields mismatch", lambda d: d.update(note="x")),
            ("no name", "fields mismatch", lambda d: d.pop("name")),
            ("a name with a space", "short plain name", lambda d: d.update(name="v 2")),
            ("no nodes", "at least one node", lambda d: d.update(nodes={})),
            ("a node ID in capitals", "is not a node ID", lambda d: d["nodes"].update(A=d["nodes"]["a"])),
            ("three sets", "one or two measurement sets", lambda d: d["nodes"]["a"]["accepted"].append(one("image-3", IMAGE3))),
            ("no set", "one or two measurement sets", lambda d: d["nodes"]["a"].update(accepted=[])),
            ("a set twice", "share the label", lambda d: d["nodes"]["a"]["accepted"].__setitem__(1, one("image-1", IMAGE2))),
            ("an entry with extra fields", "fields mismatch", lambda d: d["nodes"]["a"].update(ek_name="x")),
        )
        for label, reason, change in cases:
            with self.subTest(label):
                doc = ok()
                change(doc)
                self.refused(reason, measurements.validate, doc)
                self.refused(reason, measurements.version, doc)
        self.refused("floats are not allowed", measurements.load, b'{"schema": 1.5}')
        self.refused("duplicate field", measurements.load, b'{"schema": "a", "schema": "b"}')
        self.assertEqual(measurements.load(m.canonical(BOTH)), BOTH)

    def test_the_target_is_the_last_set(self):
        self.assertEqual(measurements.target(CURRENT, "a")["label"], "image-1")
        self.assertEqual(measurements.target(BOTH, "a")["label"], "image-2")
        self.refused("no entry for z", measurements.target, BOTH, "z")


class Transition(Case):
    def test_a_rollout_is_approve_then_retire(self):
        self.assertEqual(measurements.transition(CURRENT, BOTH), "approve")
        self.assertEqual(measurements.transition(BOTH, NEXT), "retire")
        self.assertEqual(measurements.transition(BOTH, dict(copy.deepcopy(BOTH), name="again")), "unchanged")
        # abandoning NEXT is also a retirement: every node keeps a set it had
        self.assertEqual(measurements.transition(BOTH, CURRENT), "retire")

    def test_dropping_current_with_no_overlap_is_refused_unless_it_is_an_emergency(self):
        why = self.refused("would be locked out", measurements.transition, CURRENT, NEXT)
        self.assertIn("a: image-1 is dropped in the same step that adds image-2", why)
        self.assertEqual(measurements.transition(CURRENT, NEXT, emergency=True), "replace-without-overlap")

    def test_one_node_at_a_time_may_be_approved_but_not_approved_and_retired_in_one_document(self):
        only_a = document("a-first", a=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                          b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1)])
        self.assertEqual(measurements.transition(CURRENT, only_a), "approve")
        mixed = document("mixed", a=[one("image-2", IMAGE2)], b=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                         c=[one("image-1", IMAGE1)])
        self.refused("two steps, two documents", measurements.transition, only_a, mixed)

    def test_a_label_keeps_its_measurements_and_the_newcomer_is_listed_last(self):
        relabelled = document("v2", **{n: [one("image-1", IMAGE3), one("image-2", IMAGE2)] for n in "abc"})
        self.refused("has other measurements than before", measurements.transition, CURRENT, relabelled)
        self.refused("has other measurements than before", measurements.transition, CURRENT, relabelled, emergency=True)
        backwards = document("v2", **{n: [one("image-2", IMAGE2), one("image-1", IMAGE1)] for n in "abc"})
        self.refused("must be listed last", measurements.transition, CURRENT, backwards)

    def test_a_replaced_node_does_not_block_a_transition(self):
        with_d = document("v2d", b=[one("image-1", IMAGE1), one("image-2", IMAGE2)], c=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                          d=[one("image-2", IMAGE2)])
        self.assertEqual(measurements.transition(CURRENT, with_d), "approve")


class Reboot(Case):
    """Node order is a, b, c. A verifier's state says which set it last saw each peer on."""

    def setUp(self):
        super().setUp()
        self.manifest2 = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)))

    def state(self, **seen):
        """state(a="image-2") or state(a=("image-2", 1)): what this node's verifier recorded."""
        nodes = {}
        for node, value in seen.items():
            label, epoch = value if isinstance(value, tuple) else (value, self.manifest2["epoch"])
            nodes[node] = {"measurement": {"label": label, "epoch": epoch}}
        return {"schema": attest.STATE_SCHEMA, "nodes": nodes, "nonces": {}}

    def lease_for(self, node, issuer, manifest=None, **override):
        manifest = manifest or self.manifest2
        body = dict(self.body(manifest), node_id=node, ak_name=self.keys[node].ak_name, issuer=issuer)
        body.update(override)
        return lt.sign(body, self.keys[issuer])

    def leases(self, node, manifest=None):
        return [self.lease_for(node, peer, manifest) for peer in lt.NAMES if peer != node]

    def ask(self, node, state=None, leases=None, **kw):
        return rollout.may_reboot(self.manifest2, BOTH, node, state if state is not None else self.state(),
                                  self.leases(node) if leases is None else leases, self.now, **kw)

    def test_the_first_node_reboots_when_both_peers_vouch_for_it(self):
        verdict = self.ask("a")
        self.assertEqual(verdict, {"authorizers": ["b", "c"], "seconds": 300})

    def test_the_second_node_waits_until_it_has_itself_seen_the_first_back_on_next(self):
        self.refused("WAIT: it is not b's turn. a updates first", self.ask, "b")
        self.refused("never verified", self.ask, "b")
        self.refused("last verified on 'image-1' at epoch 2, not on image-2", self.ask, "b", self.state(a="image-1"))
        # seen on NEXT, but under the previous manifest: that verdict is not about this rollout
        self.refused("last verified on 'image-2' at epoch 1", self.ask, "b", self.state(a=("image-2", 1)))
        self.assertEqual(self.ask("b", self.state(a="image-2"))["authorizers"], ["a", "c"])

    def test_the_third_node_waits_for_both(self):
        self.refused("a updates first", self.ask, "c", self.state(b="image-2"))
        self.refused("b updates first", self.ask, "c", self.state(a="image-2", b="image-1"))
        self.ask("c", self.state(a="image-2", b="image-2"))

    def test_three_nodes_asking_at_the_same_moment_cannot_all_reboot(self):
        """Before anyone has updated, each node's own verifier has seen its peers on CURRENT only."""
        allowed = []
        for node in lt.NAMES:
            try:
                self.ask(node, self.state(**{p: "image-1" for p in lt.NAMES if p != node}))
                allowed.append(node)
            except m.Refused:
                pass
        self.assertEqual(allowed, ["a"])

    def test_a_peer_that_cannot_vouch_stops_the_reboot(self):
        self.refused("WAIT: no valid lease from c (none presented)", self.ask, "a", leases=[self.lease_for("a", "b")])
        self.refused("no valid lease from b (none presented); c (none presented)", self.ask, "a", leases=[])
        expired = self.lease_for("a", "c", expires_at=hbt.stamp(self.now - 1), issued_at=hbt.stamp(self.now - 200))
        self.refused("no valid lease from c (EXPIRED", self.ask, "a", leases=[self.lease_for("a", "b"), expired])
        # a lease the peer gave ANOTHER node says nothing about this one
        self.refused("no valid lease from c (its lease is for b)", self.ask, "a", leases=[self.lease_for("a", "b"), self.lease_for("b", "c")])
        # a lease signed by somebody else in the peer's name
        forged = lt.sign(self.lease_for("a", "c")["lease"], self.keys["b"])
        self.refused("no valid lease from c (", self.ask, "a", leases=[self.lease_for("a", "b"), forged])

    def test_a_peer_still_on_the_previous_manifest_does_not_count(self):
        """It would judge the rebooted node by the OLD measurements, which do not list NEXT."""
        manifest1 = self.under(CURRENT)
        old = self.lease_for("a", "c", manifest1)
        why = self.refused("no valid lease from c", self.ask, "a", leases=[self.lease_for("a", "b"), old])
        self.assertIn("its lease is from epoch 1: that peer has not accepted epoch 2", why)

    def test_a_peer_that_may_not_authorize_is_not_counted_on_and_one_must_remain(self):
        manifest = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), c="MAINTENANCE")
        verdict = rollout.may_reboot(manifest, BOTH, "a", self.state(), [self.lease_for("a", "b", manifest)], self.now)
        self.assertEqual(verdict["authorizers"], ["b"])
        alone = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), b="MAINTENANCE", c="DRAINING")
        self.refused("no other node may authorize under epoch 2: nobody would unlock a", rollout.may_reboot, alone, BOTH, "a",
                     self.state(), [], self.now)

    def test_a_node_that_would_not_be_unlocked_again_does_not_reboot(self):
        for state in ("DRAINING", "QUARANTINED"):
            with self.subTest(state):
                manifest = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), a=state)
                self.refused("a may not be unlocked under epoch 2: it would not come back", rollout.may_reboot, manifest, BOTH, "a",
                             self.state(), self.leases("a", manifest), self.now)

    def test_the_document_must_be_the_one_the_manifest_commits_to(self):
        self.refused("is not the one the root approved", rollout.may_reboot, self.manifest2, NEXT, "a", self.state(), self.leases("a"), self.now)
        self.refused("is not the one the root approved", rollout.may_reboot, self.under(CURRENT), BOTH, "a", self.state(), [], self.now)

    def test_a_node_taken_out_of_the_rollout_is_neither_waited_for_nor_counted_on(self):
        """a is down for repair: b may go, on c's word alone, if the operator says so."""
        self.refused("a updates first", self.ask, "b", self.state(), leases=[self.lease_for("b", "c")])
        verdict = self.ask("b", self.state(), leases=[self.lease_for("b", "c")], skip=("a",))
        self.assertEqual(verdict["authorizers"], ["c"])
        self.refused("b cannot be skipped and rebooted", self.ask, "b", skip=("b",))
        self.refused("not in the rollout: z", self.ask, "b", skip=("z",))
        self.refused("nobody would unlock b", self.ask, "b", self.state(), leases=[], skip=("a", "c"))


class Retire(Case):
    def setUp(self):
        super().setUp()
        self.manifest2 = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)))

    def states(self, **by_peer):
        """states(a={"b": "image-2", "c": "image-2"}, ...): each peer's record of the others."""
        return {peer: {"schema": attest.STATE_SCHEMA, "nonces": {}, "nodes": {
            node: {"measurement": {"label": v[0], "epoch": v[1]} if isinstance(v, tuple) else {"label": v, "epoch": 2}}
            for node, v in seen.items()}} for peer, seen in by_peer.items()}

    def test_current_is_retired_only_when_every_node_was_seen_on_next_by_a_peer(self):
        done = self.states(a={"b": "image-2", "c": "image-2"}, b={"a": "image-2", "c": "image-2"})
        self.assertEqual(rollout.retire_ready(self.manifest2, BOTH, done), {"a": "b", "b": "a", "c": "a"})
        lagging = self.states(a={"b": "image-2", "c": "image-1"}, b={"a": "image-2", "c": "image-1"})
        why = self.refused("NOT YET: retiring now would lock out c", rollout.retire_ready, self.manifest2, BOTH, lagging)
        self.assertIn("last verified on 'image-1' at epoch 2, not on image-2 at epoch 2", why)
        self.assertNotIn("lock out a", why)

    def test_a_node_does_not_vouch_for_itself_and_an_old_epoch_does_not_count(self):
        self_only = self.states(a={"a": "image-2", "b": "image-2", "c": "image-2"})
        self.refused("lock out a (no other node's state was given)", rollout.retire_ready, self.manifest2, BOTH, self_only)
        stale = self.states(a={"b": "image-2", "c": "image-2"}, b={"a": ("image-2", 1), "c": "image-2"})
        self.refused("lock out a (last verified on 'image-2' at epoch 1", rollout.retire_ready, self.manifest2, BOTH, stale)

    def test_refusals_about_the_inputs(self):
        self.refused("no verifier state was given", rollout.retire_ready, self.manifest2, BOTH, {})
        self.refused("state from nodes the manifest does not list: z", rollout.retire_ready, self.manifest2, BOTH, self.states(z={}))
        self.refused("is not the one the root approved", rollout.retire_ready, self.manifest2, NEXT, self.states(a={}))
        # a state file that is not a state file refuses; it does not crash
        for junk in ([], "x", {"nodes": []}, {"nodes": {"b": "x"}}, {"nodes": {"b": {"measurement": "image-2"}}}):
            with self.subTest(junk=repr(junk)):
                self.refused("NOT YET", rollout.retire_ready, self.manifest2, BOTH, {"a": junk})

    def test_a_node_that_may_do_nothing_is_not_waited_for(self):
        manifest = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), c="QUARANTINED")
        done = self.states(a={"b": "image-2"}, b={"a": "image-2"})
        self.assertEqual(rollout.retire_ready(manifest, BOTH, done), {"a": "b", "b": "a"})


def sign(manifest, key=hbt.ROOT, signer="root"):
    return {"manifest": manifest, "signature": {"signer": signer, "key": hbt.pub(key),
                                                "sig": key.sign(m.DOMAIN + m.canonical(manifest)).hex()}}


class OnSwtpm(unittest.TestCase):
    """Three software TPMs, a, b and c. Each is a node that boots an image and a peer that judges the
    other two: its own membership store anchored in its TPM, its own heartbeat counter, its own
    attestation verifier, and leases signed by its TPM. A "boot" restarts the TPM (PCRs zeroed, the reset
    counter up by one) and extends PCR 7 (a Secure Boot stand-in) and PCR 11 (the image).
    Where the tools are provisioned (REGALIA_EXPECT_SWTPM=1) a missing one is a failure, not a skip."""

    NODES = ("a", "b", "c")
    PCR7 = hashlib.sha256(b"secure boot stand-in").hexdigest()
    IMAGES = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("image-1", "image-2")}

    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_createak", "tpm2_quote", "tpm2_nvdefine", "tpm2_pcrextend", "openssl")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm, tpm2-tools and openssl are expected here and were not found")
            self.skipTest("needs swtpm, tpm2-tools and openssl")
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pid, self.tcti, self.names, self.session, self.boots = {}, {}, {}, {}, 0
        self.addCleanup(lambda: [self.stop(n) for n in list(self.pid)])
        for name in self.NODES:
            self.tcti[name] = "swtpm:path=%s/%s.sock" % (self.d, name)
            os.makedirs("%s/tpm-%s" % (self.d, name))
            os.mkdir("%s/%s" % (self.d, name))
            self.boot(name, "image-1")
            self.on(name, attest.node_init, "%s/%s" % (self.d, name))
            self.names[name] = {k: attest.name_of(attest.public_area(lt.slurp("%s/%s/%s.pub" % (self.d, name, k)), k)).hex()
                                for k in ("ek", "ak")}
        self.now = lt.T0 + 60
        self.clock = lambda: (self.now, True)
        self.root = hbt.pub(hbt.ROOT)
        self.sequence = 0
        self.store, self.freshness, self.signer, self.att = {}, {}, {}, {}
        for name in self.NODES:
            highwater = m.HighWater("0x1500016", tcti=self.tcti[name], lock_path="%s/%s-hw.lock" % (self.d, name))
            highwater.define()
            self.store[name] = m.Store("%s/%s-membership.json" % (self.d, name), self.root, highwater)
            counter = hb.Counter("0x1500018", tcti=self.tcti[name], lock_path="%s/%s-hb.lock" % (self.d, name))
            counter.define()
            self.freshness[name] = hb.Freshness(counter, self.clock, hb.TpmClock(tcti=self.tcti[name]), "%s/%s-freshness.json" % (self.d, name))
            self.signer[name] = lease.TpmSigner(tcti=self.tcti[name])

    # ---- the machines ----

    def stop(self, name):
        pid = self.pid.pop(name, None)
        if pid:
            subprocess.run(["tpm2_shutdown", "-c"], env=dict(os.environ, TPM2TOOLS_TCTI=self.tcti[name]), capture_output=True)
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
            time.sleep(0.3)

    def boot(self, name, image):
        """One boot of `name` into `image`: a new boot session."""
        self.stop(name)
        sock = "%s/%s.sock" % (self.d, name)
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=%s/tpm-%s" % (self.d, name), "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=%s/%s.pid" % (self.d, name)], check=True, capture_output=True)
        time.sleep(0.5)
        with open("%s/%s.pid" % (self.d, name)) as f:
            self.pid[name] = int(f.read())
        self.on(name, subprocess.run, ["tpm2_pcrextend", "7:sha256=" + self.PCR7, "11:sha256=" + self.IMAGES[image]], check=True, capture_output=True)
        self.boots += 1
        self.session[name] = hashlib.sha256(b"boot %d" % self.boots).hexdigest()

    def on(self, tpm, fn, *args, **kw):
        with unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI=self.tcti[tpm]):
            return fn(*args, **kw)

    @staticmethod
    def extended(digest):
        """A PCR that started at zero and was extended once."""
        return hashlib.sha256(bytes(32) + bytes.fromhex(digest)).hexdigest()

    # ---- what the root signs ----

    def reference(self, image, firmware):
        return {"label": image, "tpm_firmware_version": firmware, "pcrs": {"7": self.extended(self.PCR7), "11": self.extended(self.IMAGES[image])}}

    def doc(self, name, firmware, *images):
        return {"schema": measurements.SCHEMA, "name": name,
                "nodes": {n: {"accepted": [self.reference(i, firmware) for i in images]} for n in self.NODES}}

    def manifest(self, epoch, previous, document):
        return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": m.digest(previous) if previous else "",
                "policy_version": measurements.version(document), "issued_at": "2026-09-21T09:00:00Z", "revocation_keys": [hbt.pub(hbt.REVOKE)],
                "nodes": [{"node_id": n, "state": "ACTIVE", "ek_name": self.names[n]["ek"], "ak_name": self.names[n]["ak"],
                           "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": ("%02x" % (0xa0 + i)) * 32,
                           "hsm_serials": ["DENK04041%02d" % i]} for i, n in enumerate(self.NODES)]}

    def publish(self, manifest, document):
        """Every node accepts the root-signed manifest (durably, anchored in its TPM), gets a heartbeat for
        it, and rebuilds its attestation policy from the document that manifest commits to."""
        self.sequence += 1
        for name in self.NODES:
            self.assertEqual(self.store[name].commit(sign(manifest)), manifest)
            self.freshness[name].accept(hbt.beat(manifest, self.sequence, issued=self.now), manifest)
            self.verifier(name, manifest, document)
        self.manifest_now, self.document_now = manifest, document

    def verifier(self, peer, manifest, document):
        policy = replacement.attest_policy(manifest, measurements.bind(manifest, document), peer_id=peer)
        self.att[peer] = attest.Verifier(policy, "%s/%s-attest.json" % (self.d, peer))
        return self.att[peer]

    def enroll(self, peer, node):
        credential = self.att[peer].challenge(node, lt.slurp("%s/%s/ek.pub" % (self.d, node)), lt.slurp("%s/%s/ak.pub" % (self.d, node)))
        cred, secret = "%s/cred-%s-%s" % (self.d, peer, node), "%s/secret-%s-%s" % (self.d, peer, node)
        with open(cred, "wb") as f:
            f.write(credential)
        self.on(node, attest.node_activate, cred, secret)
        self.att[peer].enroll(node, lt.slurp(secret))

    # ---- what the nodes do ----

    def evidence(self, peer, node, manifest=None):
        manifest = manifest or self.manifest_now
        nonce, session = self.att[peer].nonce(node), self.session[node]
        paths = ("%s/q.msg" % self.d, "%s/q.sig" % self.d)
        key = b"ephemeral key of boot " + bytes.fromhex(session)
        self.on(node, attest.node_quote, node, manifest["epoch"], bytes.fromhex(session), key, nonce, [7, 11], *paths)
        return {"ephemeral_public": key.hex(), "nonce": nonce.hex(), "quote": lt.slurp(paths[0]).hex(), "signature": lt.slurp(paths[1]).hex()}

    def unlock(self, peer, node):
        """`peer` decides whether to help `node` boot: the #59 unlock decision."""
        return replacement.may_unlock(self.manifest_now, peer, node, self.session[node], self.evidence(peer, node),
                                      self.att[peer], self.freshness[peer])

    def vouch(self, peer, node):
        """A runtime lease for `node`, signed by `peer`'s TPM after it re-attested the node."""
        request = {"node_id": node, "session_id": self.session[node], "nonce": os.urandom(32).hex()}
        return lease.issue(self.manifest_now, peer, request, self.att[peer], self.evidence(peer, node), self.freshness[peer], self.signer[peer])

    def state(self, peer):
        with open("%s/%s-attest.json" % (self.d, peer)) as f:
            return json.load(f)

    def seen(self, peer, node):
        return self.state(peer)["nodes"][node].get("measurement", {}).get("label")

    def may_reboot(self, node, leases=None, **kw):
        if leases is None:
            leases = [self.vouch(peer, node) for peer in self.NODES if peer != node]
        return rollout.may_reboot(self.manifest_now, self.document_now, node, self.state(node), leases, self.now, **kw)

    def others(self, node):
        return [n for n in self.NODES if n != node]

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))
        return str(caught.exception)

    def test_an_update_rolls_through_three_nodes_and_the_old_image_is_then_refused(self):
        # ---- intake: the firmware version is read from a quote, the PCR values are computed ----
        probe = "%s/probe" % self.d
        self.on("a", attest.node_quote, "a", 1, bytes(32), b"k", bytes(32), [7, 11], probe + ".msg", probe + ".sig")
        firmware = attest.parse_quote(lt.slurp(probe + ".msg"))["firmware_version"]
        v1, v2, v3 = self.doc("v1", firmware, "image-1"), self.doc("v2", firmware, "image-1", "image-2"), self.doc("v3", firmware, "image-2")
        m1 = self.manifest(1, None, v1)
        m2 = self.manifest(2, m1, v2)
        m3 = self.manifest(3, m2, v3)

        # ---- 15.1: CURRENT. Every node is enrolled with both peers and unlocked on image-1 ----
        self.publish(m1, v1)
        for peer in self.NODES:
            for node in self.others(peer):
                self.enroll(peer, node)
                self.assertGreater(self.unlock(peer, node), 0)
                self.assertEqual(self.seen(peer, node), "image-1")
        # an image nobody approved yet: c boots image-2 before the root has signed anything
        self.boot("c", "image-2")
        self.refused("the subject's attestation is refused: the quoted PCR digest is not the expected PCR values", self.unlock, "a", "c")
        self.refused("the quoted PCR digest is not the expected PCR values", self.vouch, "b", "c")
        self.boot("c", "image-1")
        self.assertGreater(self.unlock("a", "c"), 0)                      # the fallback: CURRENT still boots

        # ---- 15.2/15.3: the root approves CURRENT and NEXT ----
        self.assertEqual(measurements.transition(v1, v2), "approve")
        self.publish(m2, v2)
        # 15.4: one node at a time, in order. Asked at the same moment, only a may go.
        self.assertEqual(self.may_reboot("a")["authorizers"], ["b", "c"])
        self.refused("WAIT: it is not b's turn. a updates first", self.may_reboot, "b")
        self.refused("WAIT: it is not c's turn. a updates first", self.may_reboot, "c")
        self.refused("NOT YET: retiring now would lock out a", rollout.retire_ready, m2, v2, {n: self.state(n) for n in self.NODES})

        # a updates. 15.5: its peers unlock it on NEXT, automatically, and it serves again.
        self.boot("a", "image-2")
        for peer in ("b", "c"):
            self.assertGreater(self.unlock(peer, "a"), 0)
            self.assertEqual(self.seen(peer, "a"), "image-2")
        held = [self.vouch(peer, "a") for peer in ("b", "c")]
        self.assertEqual([lease.verify(e, m2, self.now) for e in held], [300, 300])
        # a, on NEXT, still vouches for b and c on CURRENT: both sets work during the rollout
        self.assertEqual([lease.verify(self.vouch("a", n), m2, self.now) for n in ("b", "c")], [300, 300])
        why = self.refused("NOT YET: retiring now would lock out b", rollout.retire_ready, m2, v2, {n: self.state(n) for n in self.NODES})
        self.assertIn("c (last verified on 'image-1' at epoch 2", why)

        # 15.6: b's turn, since b has itself seen a back on NEXT. Without c's word it waits.
        self.refused("WAIT: no valid lease from c (none presented)", self.may_reboot, "b", [self.vouch("a", "b")])
        self.refused("WAIT: it is not c's turn. b updates first", self.may_reboot, "c")
        self.assertEqual(self.may_reboot("b")["authorizers"], ["a", "c"])
        self.boot("b", "image-2")
        self.assertGreater(self.unlock("a", "b"), 0)
        # b's new image fails and it falls back to CURRENT: still unlocked, because both are approved
        self.boot("b", "image-1")
        self.assertGreater(self.unlock("c", "b"), 0)
        self.assertEqual(self.seen("c", "b"), "image-1")
        self.refused("WAIT: it is not c's turn. b updates first", self.may_reboot, "c")   # c saw b fall back
        self.boot("b", "image-2")
        for peer in ("a", "c"):
            self.assertGreater(self.unlock(peer, "b"), 0)
        self.assertEqual(self.may_reboot("c")["authorizers"], ["a", "b"])
        self.boot("c", "image-2")
        for peer in ("a", "b"):
            self.assertGreater(self.unlock(peer, "c"), 0)

        # ---- 15.7: retire CURRENT, once every node was seen on NEXT by a peer ----
        self.assertEqual(sorted(rollout.retire_ready(m2, v2, {n: self.state(n) for n in self.NODES})), ["a", "b", "c"])
        self.assertEqual(measurements.transition(v2, v3), "retire")
        before_retirement = {n: lt.slurp(self.store[n].path) for n in self.NODES}
        old_lease_for_c = self.vouch("a", "c")
        self.publish(m3, v3)
        for peer, node in (("b", "a"), ("c", "b"), ("a", "c")):
            self.assertGreater(self.unlock(peer, node), 0)                # NEXT keeps working

        # ---- 15.8: the old image is booted again. Its peers refuse it. ----
        self.boot("c", "image-1")
        for peer in ("a", "b"):
            self.refused("the subject's attestation is refused: the quoted PCR digest is not the expected PCR values", self.unlock, peer, "c")
            self.refused("the quoted PCR digest is not the expected PCR values", self.vouch, peer, "c")
            self.assertEqual(self.seen(peer, "c"), "image-2")             # a refusal does not rewrite the record
        # the lease c held from before the retirement was issued under epoch 2 and is still inside its five minutes:
        # the lease bound, as lease.py states it. It is not renewed.
        self.assertEqual(lease.verify(old_lease_for_c, m3, self.now), 300)
        self.now += lease.MAX_LIFETIME
        self.refused("EXPIRED", lease.verify, old_lease_for_c, m3, self.now)

        # the older document, handed to a peer that holds the newer manifest
        self.refused("it is not the one the root approved, or it is an older or newer one", measurements.bind, m3, v2)
        # DISK ROLLBACK on peer a: its membership file restored to the chain that still approved image-1
        with open(self.store["a"].path, "wb") as f:
            f.write(before_retirement["a"])
        self.refused("ROLLBACK: the membership on disk is epoch 2 but the TPM high-water is 3", self.store["a"].load)
        # and the same file on a TPM that never saw epoch 3 would load: the anchor is what refuses
        self.assertEqual(m.accept_chain(None, m.load(before_retirement["a"], limit=m.MAX_CHAIN_BYTES), self.root)["epoch"], 2)

        # c boots NEXT again and is back
        self.boot("c", "image-2")
        self.assertGreater(self.unlock("b", "c"), 0)


if __name__ == "__main__":
    unittest.main()
