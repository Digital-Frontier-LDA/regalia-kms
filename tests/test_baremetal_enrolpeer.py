"""A node's enrolment, the peer's side (#190 steps 6 and 7; enrolpeer.py, the enrolment operations of sync.Server):
the AK challenge against the manifest's AK Name, and this peer's half of the node's LUKS path, wrapped to an
enrolment key the node's quote of its boot session binds. One secret per path, re-wrapped on a rerun; a capped
wrap journal per (target, boot session). The fixtures are the sync tests': b and c hold the chain, a heartbeat,
and node a's AK; the tunnel is a table."""
import os
import unittest
import unittest.mock

from cryptography.hazmat.primitives.asymmetric import rsa

from deploy.baremetal import attest, enrolpeer, sync, unlock
from deploy.baremetal import membership as m
import tests.test_baremetal_lease as lt
import tests.test_baremetal_sync as st


class Case(st.Case):
    def server(self, name):
        server = super().server(name)
        directory = os.path.join(self.d, "enrol-" + name)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.activated = []

        def activate(credential):
            self.activated.append(credential)
            return b"S" * 32
        server.enrol = enrolpeer.Peer(unlock.Contributions(os.path.join(directory, "contributions.json")),
                                      enrolpeer.Wraps(os.path.join(directory, "wraps.json")),
                                      lambda: (b"ek of " + name.encode(), b"ak of " + name.encode()), activate)
        return server

    def evidence(self, nonce, binding, session=lt.SESSION, node="a", manifest=None):
        """Node a's quote over its boot session, the peer's nonce and (when given) the enrolment key."""
        manifest = manifest or self.m1
        key = b"ephemeral key of boot " + bytes.fromhex(session)
        digest = attest.qualifying_data(node, manifest["epoch"], bytes.fromhex(session), key, bytes.fromhex(nonce), binding=binding)
        signed = self.keys[node].signer(ek_name=self.keys[node].ek_name)(digest)
        return {"ephemeral_public": key.hex(), "nonce": nonce, "quote": signed["quote"], "signature": signed["sig"]}

    def path(self, server="b", session=lt.SESSION, enrolment=None, bind=None):
        """One path request from a: (answer, the enrolment key object)."""
        enrolment = enrolment or unlock.Enrolment("a")
        nonce = self.ask(server, v=1, op="path-nonce")
        self.assertTrue(nonce["ok"], nonce)
        evidence = self.evidence(nonce["nonce"], enrolment.public if bind is None else bind, session=session)
        return self.ask(server, v=1, op="path", session_id=session, evidence=evidence, binding=enrolment.public.hex()), enrolment


class Path(Case):
    def test_a_bound_quote_gets_this_peers_half_and_a_rerun_gets_the_same_secret(self):
        answer, enrolment = self.path()
        self.assertTrue(answer["ok"], answer)
        epoch, secret = enrolment.open(answer["enrolment"], "b")
        self.assertEqual(epoch, self.m1["epoch"])
        self.assertEqual(secret, self.servers["b"].enrol.contributions.get("a", epoch))
        self.assertEqual(self.last()["outcome"], "ALLOW")
        # the target crashed before its token: it asks again, with a NEW enrolment key, and gets the SAME secret
        again, other = self.path()
        self.assertEqual(other.open(again["enrolment"], "b"), (epoch, secret))
        self.assertEqual(self.servers["b"].enrol.contributions.epochs("a"), [epoch])

    def test_the_enrolment_key_must_be_the_one_the_quote_binds(self):
        stranger = unlock.Enrolment("a")
        answer, _ = self.path(bind=stranger.public)            # quoted over another key than the one sent
        self.refusal("the value it must bind", answer)
        nonce = self.ask("b", v=1, op="path-nonce")["nonce"]
        evidence = self.evidence(nonce, stranger.public)
        self.refusal("binding must be lowercase hex", self.ask("b", v=1, op="path", session_id=lt.SESSION, evidence=evidence, binding=""))
        self.assertEqual(self.servers["b"].enrol.contributions.epochs("a"), [], "nothing minted for a refused request")

    def test_a_lease_style_quote_without_the_binding_is_refused(self):
        nonce = self.ask("b", v=1, op="path-nonce")["nonce"]
        enrolment = unlock.Enrolment("a")
        evidence = self.quote(nonce, self.m1)                  # the five-field transcript of a lease
        answer = self.ask("b", v=1, op="path", session_id=lt.SESSION, evidence=evidence, binding=enrolment.public.hex())
        self.refusal("the value it must bind", answer)

    def test_the_fourth_wrap_in_one_boot_session_is_refused_and_recorded(self):
        for _ in range(enrolpeer.WRAP_CAP):
            self.assertTrue(self.path()[0]["ok"])
            self.tick += 60                                    # the rate limit is not what this test is about
        answer, _ = self.path()
        self.refusal("asked for its path 3 times in this boot session", answer)
        self.assertEqual((self.last()["event"], self.last()["outcome"]), ("sync-path", "DENY"))

    def test_a_second_boot_session_in_the_same_boot_is_refused(self):
        self.assertTrue(self.path()[0]["ok"])
        self.refusal("a second boot session in the same boot", self.path(session=lt.OTHER_SESSION)[0])

    def test_a_key_that_is_not_rsa_3072_is_refused_before_any_tpm_or_disk_work(self):
        small = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        enrolment = unlock.Enrolment("a")
        enrolment.public = unlock._spki(small)
        self.refusal("RSA-3072", self.path(enrolment=enrolment)[0])

    def test_only_a_peer_that_may_authorize_and_is_live_contributes(self):
        b = self.servers["b"]
        with unittest.mock.patch.object(b.freshness, "live_until", side_effect=m.Refused("no live heartbeat")):
            self.refusal("no live heartbeat", self.path()[0])
        with unittest.mock.patch.object(m, "may", lambda manifest, node, what: not (node == "b" and what == "authorize")):
            self.refusal("b may not authorize", self.path()[0])
        with unittest.mock.patch.object(m, "may", lambda manifest, node, what: not (node == "a" and what == "request")):
            self.refusal("a may not be unlocked", self.path()[0])


class AkEnrolment(Case):
    def test_an_ak_enrolled_already_as_the_manifests_needs_no_challenge(self):
        a = self.keys["a"]
        answer = self.ask("b", v=1, op="ak-challenge", ek_public="ab" * 8, ak_public=a.ak_public.hex())
        self.assertEqual(answer, {"v": 1, "ok": True, "credential": None})

    def test_an_ak_the_manifest_does_not_name_is_refused(self):
        other = self.keys["c"].ak_public
        answer = self.ask("b", v=1, op="ak-challenge", ek_public="ab" * 8, ak_public=other.hex())
        self.assertFalse(answer["ok"])

    def test_this_nodes_identity_and_activation_are_answered_to_a_manifest_node(self):
        self.assertEqual(self.ask("b", v=1, op="ak-public"), {"v": 1, "ok": True, "ek_public": b"ek of b".hex(), "ak_public": b"ak of b".hex()})
        self.assertEqual(self.ask("b", v=1, op="ak-activate", credential="cc" * 16), {"v": 1, "ok": True, "secret": "53" * 32})
        self.assertEqual(self.activated, [b"\xcc" * 16])


class Target(Case):
    """with_peer, on node a, against b's real answering side: the LUKS header and cryptsetup stood in for."""

    class Verifier:
        def __init__(self, enrolled=None):
            self.ak, self.calls = enrolled, []

        def enrolled(self, peer):
            return self.ak

        def challenge(self, peer, ek, ak, replace=False, ak_name=None):
            self.calls.append(("challenge", peer, ek, ak, replace, ak_name))
            return b"credential for " + peer.encode()

        def enroll(self, peer, secret):
            self.calls.append(("enroll", peer, secret))

    def run_with(self, verifier, header=None, peer="b"):
        meta = header or {"keyslots": {"0": {}}, "tokens": {}}
        made = []

        def enrol_path(device, target, peer_id, epoch, local, sealed, contribution, existing, **kw):
            made.append((device, target, peer_id, epoch, local, sealed, contribution, existing))
            return 3

        def quote(epoch, session_id, session_key, nonce, binding):
            return self.evidence(nonce.hex(), binding, session=session_id)
        client = sync.Client("a", self.stores["a"], self.own, {"b": self.wire("b", "a"), "c": self.wire("c", "a")}, self.events.append)
        with unittest.mock.patch.object(unlock, "luks_meta", lambda device: meta), unittest.mock.patch.object(unlock, "enrol_path", enrol_path):
            result = enrolpeer.with_peer(self.m1, "a", peer, lambda op, **f: client._ask(peer, op, **f),
                                         lambda: (b"ek", self.keys["a"].ak_public), lambda credential: b"S" * 32, verifier,
                                         (lt.SESSION, b"ephemeral key of boot " + bytes.fromhex(lt.SESSION)), quote,
                                         b"L" * 32, "sealed", "/dev/root", b"recovery")
        return result, made

    def test_the_path_is_enrolled_with_the_peers_secret(self):
        verifier = self.Verifier(enrolled=self.entry("b")["ak_name"])
        result, made = self.run_with(verifier)
        self.assertEqual(result, {"path_epoch": self.m1["epoch"], "keyslot": 3})
        (device, target, peer, epoch, local, sealed, contribution, existing), = made
        self.assertEqual((device, target, peer, epoch, local, sealed, existing), ("/dev/root", "a", "b", 1, b"L" * 32, "sealed", b"recovery"))
        self.assertEqual(contribution, self.servers["b"].enrol.contributions.get("a", 1))
        self.assertEqual(verifier.calls, [], "the peer's AK was the manifest's already: no challenge")

    def test_the_peers_ak_is_enrolled_against_the_manifests_name(self):
        verifier = self.Verifier()
        self.run_with(verifier)
        self.assertEqual(verifier.calls, [("challenge", "b", b"ek of b", b"ak of b", False, self.entry("b")["ak_name"]),
                                          ("enroll", "b", b"S" * 32)])
        self.assertEqual(self.activated, [b"credential for b"])

    def test_a_path_already_in_the_header_is_not_asked_for_again(self):
        header = {"keyslots": {"0": {}, "1": {}}, "tokens": {"0": {"type": unlock.TOKEN_TYPE, "peer": "b", "target": "a"}}}
        result, made = self.run_with(self.Verifier(enrolled=self.entry("b")["ak_name"]), header)
        self.assertEqual((result, made), ({"path_epoch": None, "keyslot": None, "existing": True}, []))
        self.assertEqual(self.servers["b"].enrol.contributions.epochs("a"), [])

    def test_no_path_from_a_peer_that_may_not_authorize(self):
        with unittest.mock.patch.object(m, "may", lambda manifest, node, what: not (node == "b" and what == "authorize")):
            with self.assertRaisesRegex(m.Refused, "b may not authorize under epoch 1: no path from it"):
                self.run_with(self.Verifier())


class Gate(Case):
    def test_the_enrolment_ops_are_only_for_a_node_the_tunnel_identifies(self):
        self.denied("no WireGuard peer owns 2001:db8::1", self.ask("b", caller="2001:db8::1", v=1, op="ak-public"))
        self.denied("not pinned to a node", self.ask("b", caller="a2", v=1, op="path-nonce"))

    def test_a_source_with_no_enrolment_takes_none(self):
        self.servers["b"].enrol = None
        self.refusal("this source takes no enrolments", self.ask("b", v=1, op="ak-public"))

    def test_the_enrolment_class_cannot_starve_a_nodes_pulls_or_another_node(self):
        count = sync.RATE["enrol"][0]
        for _ in range(count):
            self.assertTrue(self.ask("b", v=1, op="ak-public")["ok"])
        self.refusal("RATE: more than %d enrol requests" % count, self.ask("b", v=1, op="ak-public"))
        self.assertTrue(self.pull("b")["ok"], "a's pulls still pass: the enrolment class is its own")
        self.assertTrue(self.ask("b", caller="c", v=1, op="ak-public")["ok"], "another node's enrolment is not affected")
        self.assertLess(count, sync.RATE["any"][0])


if __name__ == "__main__":
    unittest.main()
