"""deploy/baremetal/unlock.py (#67, Phase 7; #135): a KMS host's disk opens with its TPM and one peer, never
the TPM alone. PoC 7.1-7.7 and 7.9 as decisions on a real LUKS2 header (a file: no root, no device-mapper),
the #135 case (a retired image keeps its TPM half and gets no peer half), and each binding of the exchange
with its own refusal.

The TPM identities are OpenSSL P-256 keys and the stores are those of tests/test_baremetal_convergence.py;
the local contribution is "sealed" by a stand-in with a real credential header. The last class runs the
whole path on three software TPMs with systemd-creds and, as root, a real dm-crypt mapping
(e2e/peer-unlock-swtpm.sh)."""
import base64
import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from deploy.baremetal import attest, lease, replacement, unlock
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_convergence as ct
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt
import tests.test_baremetal_replacement as rt

PATH = os.environ.get("PATH", "") + os.pathsep + "/usr/sbin" + os.pathsep + "/sbin"
CRYPTSETUP = shutil.which("cryptsetup", path=PATH)
RECOVERY = b"cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb"
TPM2_ID = next(k for k, v in unlock.LOCAL_KEY_TYPES.items() if v == "tpm2")


def run(argv, **kw):
    if kw.get("input") is None:
        kw.setdefault("stdin", subprocess.DEVNULL)      # never the test runner's own stdin
    return subprocess.run(argv, env=dict(kw.pop("env", None) or os.environ, PATH=PATH), **kw)


def fake_seal(local):
    """A stand-in for systemd-creds: the TPM-only key-type id, then the secret. Only the header is real."""
    return base64.b64encode(bytes.fromhex(TPM2_ID) + local).decode()


def fake_unseal(sealed):
    return base64.b64decode(sealed)[16:]


class KeyPool:
    """RSA-3072 generation is the slow part of every boot session and enrolment. The keys are made once and
    handed out again in each test, in order: within one test every key is still a different one."""
    keys, generate = [], staticmethod(unlock.rsa.generate_private_key)

    def __init__(self):
        self.next = 0

    def __call__(self, public_exponent, key_size):
        if key_size != unlock.KEY_BITS:
            return self.generate(public_exponent=public_exponent, key_size=key_size)
        if self.next == len(self.keys):
            self.keys.append(self.generate(public_exponent=public_exponent, key_size=key_size))
        self.next += 1
        return self.keys[self.next - 1]


class Case(ct.Case):
    """a, b, c ACTIVE at epoch 1, each with its own store. b and c serve unlock requests; a is the target."""

    def setUp(self):
        super().setUp()
        pool = unittest.mock.patch.object(unlock.rsa, "generate_private_key", KeyPool())
        pool.start()
        self.addCleanup(pool.stop)
        self.stores["a"] = self.store("a")
        self.stores["a"].commit(self.e1)
        self.contributions = {p: unlock.Contributions(os.path.join(self.d, p + "-contributions.json")) for p in ("b", "c")}
        self.attesters = {p: self.peers[p]["attester"] for p in ("b", "c")}
        self.served = {p: unlock.Peer(p, self.stores[p], self.peers[p]["freshness"], lambda manifest, p=p: self.attesters[p],
                                      self.contributions[p], self.peers[p]["signer"], self.events.append, run=run) for p in ("b", "c")}
        self.wire = []
        self.boots = 0
        self.session = self.boot()

    def boot(self, node="a"):
        """A new boot of the target: a new session and key, and the TPM's reset counter one higher."""
        self.boots += 1
        return unlock.BootSession(node)

    def transport(self, peer):
        """One message to `peer` and its reply, as bytes each way; everything that crossed is kept in self.wire."""
        def send(raw):
            reply = json.dumps(self.served[peer].handle(raw)).encode()
            self.wire.append((peer, raw, reply))
            return reply
        return send

    def quote(self, signed_by="a", reset=None, **quoted):
        """Node a's TPM, as a quote function: by its AK under its EK, in the current boot. `quoted` overrides
        what the quote is really over; `signed_by` puts another node's AK behind it."""
        def quote(node, epoch, session_id, ephemeral_public, nonce):
            fields = dict(node_id=node, epoch=epoch, session_id=session_id, ephemeral_public=ephemeral_public, nonce=nonce)
            fields.update(quoted)
            signed = self.keys[signed_by].signer(ek_name=self.keys["a"].ek_name, reset=reset or self.boots)(attest.qualifying_data(*fields.values()))
            return bytes.fromhex(signed["quote"]), bytes.fromhex(signed["sig"])
        return quote

    def enrolled(self, peer, target="a"):
        """Peer `peer` mints its contribution for the target through the enrolment exchange; returns (epoch, secret)."""
        enrolment = unlock.Enrolment(target)
        wrapped = unlock.contribute(self.contributions[peer], self.stores[peer].load(), peer, target, enrolment.public, enrolment.fingerprint)
        return enrolment.open(json.loads(json.dumps(wrapped)), peer)

    def ask(self, peer, path, session=None, **kw):
        return unlock.ask(session or self.session, self.stores["a"], peer, path, self.transport(peer), self.quote(**kw), run=run)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises((m.Refused, attest.Refused)) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def denied(self, why):
        """The last decision the peers made was a denial for this reason (it is in the audit event only)."""
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        self.assertIn(why, self.events[-1]["reason"])


class Exchange(Case):
    """The protocol, without a disk: what a peer gives, to whom, and what the target accepts."""

    def test_poc_7_1_a_peer_gives_its_contribution_to_an_attested_node_and_the_decision_is_audited(self):
        epoch, secret = self.enrolled("b")
        self.assertEqual(epoch, 1)                                    # the manifest's epoch at enrolment
        self.assertEqual(self.ask("b", epoch), secret)
        self.assertTrue(self.session.consumed)
        self.assertEqual([(e["event"], e["subject"], e["peer"], e["outcome"]) for e in self.events],
                         [("unlock-challenge", "a", "b", "ALLOW"), ("unlock", "a", "b", "ALLOW")])
        # nothing secret crossed in the clear: not the contribution, in any encoding
        crossed = b"".join(raw + reply for _, raw, reply in self.wire)
        for encoded in (secret, secret.hex().encode(), base64.b64encode(secret)):
            self.assertNotIn(encoded, crossed)

    def test_poc_7_2_each_peer_holds_its_own_contribution(self):
        (eb, sb), (ec, sc) = self.enrolled("b"), self.enrolled("c")
        self.assertNotEqual(sb, sc)
        self.assertEqual(self.ask("c", ec), sc)
        self.assertEqual(self.contributions["b"].get("a", eb), sb)
        self.refused("this peer holds no contribution for a at path epoch 1", unlock.Contributions(self.d + "/none.json").get, "a", 1)

    def test_poc_7_3_the_first_valid_response_consumes_the_boot_session(self):
        (eb, sb), (ec, _) = self.enrolled("b"), self.enrolled("c")
        self.assertEqual(self.ask("b", eb), sb)
        # c answers too (it was asked at the same time): its valid response is not opened
        self.refused("this boot session has already accepted a response", self.ask, "c", ec)
        self.assertEqual(self.events[-1]["outcome"], "ALLOW")         # c did give it; the target dropped it

    def test_poc_7_5_a_fake_peer_cannot_deliver_an_authorization(self):
        epoch, secret = self.enrolled("b")
        genuine = self.transport("b")

        def forged(change):
            def send(raw):
                reply = json.loads(genuine(raw))
                return json.dumps(change(reply) if "response" in reply else reply).encode()
            return send

        def resigned(key, **fields):
            def change(reply):
                reply["response"].update(fields)
                reply["signature"] = self.keys[key].signer()(unlock.signed_digest(reply["response"]))
                return reply
            return change

        def edited(**fields):
            def change(reply):
                reply["response"].update(fields)
                return reply
            return change
        other = unlock.BootSession("a")
        cases = [
            ("the response is not signed by the AK the manifest names for b", resigned("c")),
            ("the response is from c, not from b, the peer that was asked", resigned("c", peer_id="c")),
            ("the peer answered for path epoch 2, not 1", edited(path_epoch=epoch + 1)),
            ("the peer answered for path epoch 2, not 1", resigned("b", path_epoch=epoch + 1)),
            ("the quote is not over this response", edited(ciphertext="00" * 384)),
            ("the response does not answer the request this boot session sent b", resigned("b", transcript_sha256="ab" * 32)),
            ("the response is for another node or another boot session", resigned("b", node_id="c")),
            ("the response is for another node or another boot session", resigned("b", session_id=other.session_id.hex())),
            ("decided under another manifest", resigned("b", epoch=2)),
            ("decided under another manifest", resigned("b", manifest_digest="cd" * 32)),
            ("the contribution does not decrypt", resigned("b", ciphertext=other._private.public_key().encrypt(
                secret, unlock._oaep(unlock.CONTRIBUTION_LABEL + bytes(32))).hex())),
            ("unlock reply fields mismatch", lambda reply: dict(reply, extra=1)),
            ("response fields mismatch", lambda reply: dict(reply, response=dict(reply["response"], extra=1))),
        ]
        for reason, change in cases:
            with self.subTest(reason):
                self.refused(reason, unlock.ask, self.session, self.stores["a"], "b", epoch, forged(change), self.quote(), run)
                self.assertFalse(self.session.consumed)               # an invalid response consumes nothing
        self.assertEqual(self.ask("b", epoch), secret)                # and the real peer still restores the node

    def test_poc_7_6_a_fake_node_gets_no_contribution(self):
        epoch, _ = self.enrolled("b")
        for why, kw in (("the quote's signature does not verify under the enrolled AK", dict(signed_by="c")),            # another TPM's AK
                        ("the quote is not bound to this transcript", dict(node_id="c")),
                        ("the quote is not bound to this transcript", dict(epoch=7)),
                        ("the quote is not bound to this transcript", dict(session_id=bytes(32))),
                        ("the quote is not bound to this transcript", dict(ephemeral_public=b"another key")),
                        ("the quote is not bound to this transcript", dict(nonce=bytes(32)))):
            with self.subTest(why, **{k: str(v) for k, v in kw.items()}):
                self.refused("unlock: the peer refused (DENIED)", self.ask, "b", epoch, **kw)
                self.denied(why)
                self.assertFalse(self.session.consumed)
        # a node the peer has never enrolled, and one that is not in the manifest at all
        self.refused("hello: the peer refused (DENIED)", unlock.ask, unlock.BootSession("c"), self.stores["a"], "b", epoch, self.transport("b"), self.quote(), run)
        self.refused("hello: the peer refused (DENIED)", unlock.ask, unlock.BootSession("x"), self.stores["a"], "b", epoch, self.transport("b"), self.quote(), run)
        self.denied("x may not be unlocked under epoch 1")
        # a refusal tells the requester its kind and nothing else
        self.assertEqual(json.loads(self.wire[-1][2]), {"v": 1, "error": "DENIED"})

    def test_poc_7_7_a_captured_exchange_is_useless_in_another_boot(self):
        epoch, secret = self.enrolled("b")
        self.assertEqual(self.ask("b", epoch), secret)
        _, request, response = self.wire[-1]
        # the captured request, sent again: its nonce is spent
        self.assertEqual(self.served["b"].handle(request), {"v": 1, "error": "DENIED"})
        self.denied("the nonce is not outstanding")
        # the captured response, handed to the next boot: another session, another key
        rebooted = self.boot()
        self.refused("the response is for another node or another boot session", unlock.ask, rebooted, self.stores["a"], "b", epoch,
                     lambda raw: response if b'"unlock"' in raw else self.transport("b")(raw), self.quote(), run)
        self.assertFalse(rebooted.consumed)
        self.refused("the contribution does not decrypt", unlock._decrypt, rebooted._private,
                     bytes.fromhex(json.loads(response)["response"]["ciphertext"]),
                     unlock.CONTRIBUTION_LABEL + bytes.fromhex(json.loads(response)["response"]["transcript_sha256"]))
        self.assertEqual(unlock.ask(rebooted, self.stores["a"], "b", epoch, self.transport("b"), self.quote(), run), secret)
        # the first boot's session, presented again after the reboot: the verifier remembers it
        stale = self.boots
        self.boots += 1
        replayed = copy.copy(self.session)
        replayed.consumed = False
        self.refused("unlock: the peer refused (DENIED)", self.ask, "b", epoch, session=replayed, reset=stale + 1)
        self.denied("a boot session or ephemeral key from an earlier boot was presented after a reboot")

    def test_a_request_changed_on_the_way_to_another_path_epoch_does_not_spend_the_session(self):
        """During a rotation the peer holds two contributions. The path epoch asked for is not in the quote, so
        whoever sits on the path can change it; the peer's answer is then valid, and for the wrong path."""
        old, _ = self.enrolled("b")
        new, secret = self.enrolled("b")
        self.assertEqual((old, new), (1, 2))
        genuine = self.transport("b")

        def downgraded(raw):
            message = json.loads(raw)
            if message["op"] == "unlock":
                message["path_epoch"] = old
            return genuine(json.dumps(message).encode())
        self.refused("the peer answered for path epoch 1, not 2", unlock.ask, self.session, self.stores["a"], "b", new, downgraded, self.quote(), run)
        self.assertEqual(self.events[-1]["outcome"], "ALLOW")         # the peer did answer, validly
        self.assertFalse(self.session.consumed)
        self.assertEqual(self.ask("b", new), secret)                  # the same boot still unlocks

    def test_a_node_far_behind_that_may_not_be_unlocked_is_sent_no_manifest(self):
        """More manifests behind than one message carries: the reply would hold manifests and no nonce yet.
        A node the peer will not unlock gets neither."""
        authority = self.stores["authority"]
        self.revoke(authority.load(), "QUARANTINED")
        for _ in range(unlock.ENVELOPES_PER_MESSAGE + 1):             # the root re-issues; a stays quarantined
            current = authority.load()
            authority.commit(rt.sign(dict(self.chain(current, current["nodes"]), policy_version="p%d" % (current["epoch"] + 1))))
        self.publish("b")
        self.assertGreater(self.stores["b"].load()["epoch"] - 1, unlock.ENVELOPES_PER_MESSAGE)
        behind = {"v": 1, "op": "hello", "node_id": "a", "summary": {"epoch": 1, "manifest_digest": m.digest(self.m1)}}
        self.assertEqual(self.served["b"].handle(json.dumps(behind).encode()), {"v": 1, "error": "DENIED"})
        self.denied("a may not be unlocked")
        # c, which may be unlocked, is brought forward message by message (it is not enrolled with b's verifier: no nonce at the end)
        reply = self.served["b"].handle(json.dumps(dict(behind, node_id="c")).encode())
        self.assertEqual((len(reply["envelopes"]), reply["nonce"]), (unlock.ENVELOPES_PER_MESSAGE, None))

    def test_an_unreachable_peer_is_one_refusal_and_the_next_peer_is_asked(self):
        epoch, secret = self.enrolled("c")
        for error in (ConnectionRefusedError("refused"), TimeoutError("timed out"), OSError("no route to host"), EOFError()):
            def dead(raw, error=error):
                raise error
            with self.subTest(type(error).__name__):
                self.refused("hello: the transport failed (%s)" % type(error).__name__, unlock.ask, self.session, self.stores["a"], "b", 1, dead, self.quote(), run)
        self.assertFalse(self.session.consumed)
        self.assertEqual(self.ask("c", epoch), secret)

    def test_a_second_session_in_one_boot_is_refused(self):
        epoch, _ = self.enrolled("b")
        self.ask("b", epoch)
        self.refused("unlock: the peer refused (DENIED)", self.ask, "b", epoch, session=unlock.BootSession("a"))
        self.denied("a second boot session in the same boot")

    def test_issue_135_a_retired_image_is_refused_by_every_peer(self):
        """The node boots an image the root has retired. Its TPM still releases the local contribution (the
        TPM's policy has no counter); the peers' reference values no longer list that image."""
        (eb, _), (ec, _) = self.enrolled("b"), self.enrolled("c")
        for peer in ("b", "c"):
            policy = {"schema": attest.POLICY_SCHEMA, "nodes": {"a": {"ek_name": self.keys["a"].ek_name, "tpm_firmware_version": "0" * 16,
                                                                      "pcrs": {"7": "00" * 32, "11": "5c" * 32}}}}
            self.attesters[peer] = attest.Verifier(policy, os.path.join(self.d, peer + "-attest-next.json"), now=lambda: self.now)
            self.enroll(self.attesters[peer], self.keys["a"].ak_public)
        for peer, epoch in (("b", eb), ("c", ec)):
            self.refused("unlock: the peer refused (DENIED)", self.ask, peer, epoch)
            self.denied("the quote covers PCRs [7], not the expected [7, 11]")
        self.assertFalse(self.session.consumed)

    def test_a_revoked_or_retired_node_gets_no_nonce_and_its_contributions_are_dropped(self):
        epoch, _ = self.enrolled("b")
        for state, kept in (("QUARANTINED", [epoch]), ("REVOKED_STOLEN", [])):
            with self.subTest(state):
                self.revoke(self.stores["authority"].load(), state)
                self.publish("b")
                self.refused("hello: the peer refused (DENIED)", self.ask, "b", epoch)
                self.denied("a may not be unlocked under epoch %d" % self.stores["b"].load()["epoch"])
                self.assertEqual(self.contributions["b"].epochs("a"), kept)       # stolen: gone for good
        self.assertEqual(self.stores["a"].load()["epoch"], 1)        # a refused node is told nothing, not even the manifests

    def test_a_peer_without_a_live_heartbeat_gives_nothing(self):
        epoch, _ = self.enrolled("b")
        self.later(hb.MAX_LIFETIME + 1)
        self.refused("hello: the peer refused (DENIED)", self.ask, "b", epoch)
        self.denied("heartbeat")
        # between the nonce and the quote, too: the decision is taken when the contribution is given
        self.beat(self.m1, issued=self.now)
        genuine = self.transport("b")

        def slow(raw):
            if b'"unlock"' in raw:
                self.later(hb.MAX_LIFETIME + 1)
            return genuine(raw)
        self.refused("unlock: the peer refused (DENIED)", unlock.ask, self.session, self.stores["a"], "b", epoch, slow, self.quote(), run)
        self.denied("heartbeat")

    def test_the_two_sides_converge_on_one_manifest_before_any_quote(self):
        epoch, secret = self.enrolled("b")
        # the peer is ahead (c was quarantined while a was down): a catches up inside the hello
        self.revoke(self.stores["authority"].load(), "QUARANTINED", node="c")
        self.publish("b")
        self.assertEqual(self.ask("b", epoch), secret)
        self.assertEqual((self.stores["a"].load()["epoch"], self.stores["a"].hw.value()), (2, 2))
        ops = [json.loads(raw)["op"] for _, raw, _ in self.wire]
        self.assertEqual(ops, ["hello", "unlock"])
        # the peer is behind: it takes the root-signed manifests from the node, and then has no heartbeat for them
        fresh = self.boot()
        self.wire.clear()
        self.assertEqual(self.stores["c"].load()["epoch"], 1)
        self.enrolled("c")
        self.refused("hello: the peer refused (DENIED)", unlock.ask, fresh, self.stores["a"], "c", 1, self.transport("c"), self.quote(), run)
        self.assertEqual([json.loads(raw)["op"] for _, raw, _ in self.wire], ["hello", "manifests", "hello"])
        self.assertEqual(self.stores["c"].load()["epoch"], 2)
        self.denied("c may not authorize under epoch 2")              # and it is the quarantined one

    def test_the_target_judges_the_peer_by_its_own_manifest(self):
        epoch, _ = self.enrolled("b")
        # a holds a manifest that quarantines b; b never got it and cannot take it from a here
        self.stores["a"].commit(self.revoke(self.stores["authority"].load(), "QUARANTINED", node="b"))
        self.served["b"].manifests = lambda message: {"v": 1, "summary": {}}
        self.refused("no contribution from b after 16 messages", self.ask, "b", epoch)
        manifest = self.stores["a"].load()
        self.session.expect("b", manifest, bytes(32))
        response = {"schema": unlock.RESPONSE_SCHEMA, "peer_id": "b", "node_id": "a", "epoch": 2, "manifest_digest": m.digest(manifest),
                    "session_id": self.session.session_id.hex(), "transcript_sha256": self.session.pending["b"], "path_epoch": epoch, "ciphertext": "00" * 384}
        envelope = {"response": response, "signature": self.keys["b"].signer()(unlock.signed_digest(response))}
        self.refused("b may not authorize under epoch 2", self.session.open, "b", envelope, manifest, epoch, run)

    def test_a_request_is_bounded_and_exact(self):
        peer = self.served["b"]
        hello = {"v": 1, "op": "hello", "node_id": "a", "summary": {"epoch": 1, "manifest_digest": m.digest(self.m1)}}
        self.assertIn("nonce", peer.handle(json.dumps(hello).encode()))
        invalid = {"v": 1, "error": "INVALID_REQUEST"}
        for raw in (b"", b"[]", b"{", b'{"v":1}', b'{"v":2,"op":"hello"}', b'{"v":true,"op":"hello"}', b'{"v":1,"op":"init"}', b'{"v":1,"op":7}',
                    b'{"v":1,"v":1,"op":"hello"}', b'{"v":1.0,"op":"hello"}', b" " * (unlock.MAX_BYTES + 1)):
            with self.subTest(raw[:30]):
                self.assertEqual(peer.handle(raw), invalid)
        denied = {"v": 1, "error": "DENIED"}
        for message in (dict(hello, extra=1), dict(hello, node_id="A"), dict(hello, node_id=7), dict(hello, summary={"epoch": 1}),
                        dict(hello, summary={"epoch": 1, "manifest_digest": "ff" * 32}),      # a CONFLICT: another manifest at our epoch
                        {"v": 1, "op": "manifests", "envelopes": [{}] * (unlock.ENVELOPES_PER_MESSAGE + 1)},
                        {"v": 1, "op": "manifests", "envelopes": [{"manifest": {}}]},
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 32, "path_epoch": 1},
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 32, "path_epoch": True, "evidence": {}},
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 31, "path_epoch": 1, "evidence": {}},
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 32, "path_epoch": 1, "evidence": None}):
            with self.subTest(str(message)[:60]):
                self.assertEqual(peer.handle(json.dumps(message).encode()), denied)

    def test_the_ephemeral_key_must_be_the_one_kind_a_contribution_is_encrypted_to(self):
        epoch, _ = self.enrolled("b")
        session = self.session
        session.ephemeral_public = b"not a public key at all"
        self.refused("unlock: the peer refused (DENIED)", self.ask, "b", epoch)
        self.denied("the recipient key is not a DER public key")
        small = unlock.rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.refused("the recipient key must be RSA-3072", unlock.recipient_key, unlock._spki(small))
        self.assertLessEqual(len(unlock.BootSession("a").ephemeral_public), 512)   # what attest.check_session allows


class Secrets(Case):
    """The credential, the peer's store, and enrolment."""

    def test_the_credential_needs_both_halves_and_names_its_path(self):
        local, peer = os.urandom(32), os.urandom(32)
        key = unlock.credential(local, peer, "a", "b", 1)
        self.assertEqual(len(base64.b64decode(key)), 32)
        self.assertEqual(key, unlock.credential(local, peer, "a", "b", 1))
        for other in (unlock.credential(os.urandom(32), peer, "a", "b", 1), unlock.credential(local, os.urandom(32), "a", "b", 1),
                      unlock.credential(local, peer, "a", "c", 1), unlock.credential(local, peer, "c", "b", 1),
                      unlock.credential(local, peer, "a", "b", 2), unlock.credential(peer, local, "a", "b", 1)):
            self.assertNotEqual(key, other)
        self.refused("the local contribution must be 32 bytes", unlock.credential, local[:31], peer, "a", "b", 1)
        self.refused("the peer contribution must be 32 bytes", unlock.credential, local, b"", "a", "b", 1)
        self.refused("path_epoch must be an integer >= 1", unlock.credential, local, peer, "a", "b", 0)
        self.refused("target is not a node ID", unlock.credential, local, peer, "a/../b", "b", 1)

    def test_the_peers_store_is_private_durable_and_never_reuses_a_path_epoch(self):
        store = self.contributions["b"]
        first = store.mint("a", 3)
        self.assertEqual(stat.S_IMODE(os.stat(store.path).st_mode), 0o600)
        self.assertEqual(store.get("a", 3), first)
        for epoch in (3, 2):
            self.refused("path epoch %d is not above the ones held for a (3)" % epoch, store.mint, "a", epoch)
        second = store.mint("a", 4)                                   # a rotation: both are held until the old keyslot is killed
        self.assertNotEqual(first, second)
        self.assertEqual(store.epochs("a"), [3, 4])
        self.assertEqual(store.drop("a", 3), [3])
        self.refused("this peer holds no contribution for a at path epoch 3", store.get, "a", 3)
        self.assertEqual(store.get("a", 4), second)
        for epoch in (5, 6, 7):
            store.mint("a", epoch)
        self.refused("4 contributions are held for a already", store.mint, "a", 8)
        os.chmod(store.path, 0o640)
        self.refused("is readable by others than its owner", store.get, "a", 4)
        os.chmod(store.path, 0o600)
        with open(store.path, "w") as f:
            f.write('{"schema": "%s", "targets": {"a": {"4": "zz"}}}' % unlock.STORE_SCHEMA)
        self.refused("contributions.a.4 must be 64 lowercase hex", store.get, "a", 4)
        self.refused("the random source did not give 32 bytes", unlock.Contributions(self.d + "/short.json", rand=lambda n: b"short").mint, "a", 1)
        self.assertFalse(os.path.exists(self.d + "/short.json"))

    def test_enrolment_reaches_one_key_once_and_only_for_a_node_that_may_be_unlocked(self):
        enrolment = unlock.Enrolment("a")
        store, manifest = self.contributions["b"], self.m1
        self.refused("the enrolment key is not the one whose fingerprint was given", unlock.contribute, store, manifest, "b", "a",
                     enrolment.public, unlock.Enrolment("a").fingerprint)
        self.assertEqual(store.epochs("a"), [])                       # nothing was created
        wrapped = unlock.contribute(store, manifest, "b", "a", enrolment.public, enrolment.fingerprint.upper() + "\n")
        self.assertEqual((wrapped["target"], wrapped["peer"], wrapped["path_epoch"]), ("a", "b", 1))
        self.refused("the contribution does not decrypt", unlock.Enrolment("a").open, wrapped, "b")       # another key
        self.refused("not from c for a", enrolment.open, wrapped, "c")
        self.refused("the contribution does not decrypt", enrolment.open, dict(wrapped, path_epoch=2), "b")   # the label binds the path
        self.refused("enrolment fields mismatch", enrolment.open, dict(wrapped, extra=1), "b")
        epoch, secret = enrolment.open(wrapped, "b")
        self.assertEqual((epoch, secret), (1, store.get("a", 1)))
        self.refused("this enrolment key has been used", enrolment.open, wrapped, "b")
        again = unlock.Enrolment("a")
        self.assertEqual(unlock.contribute(store, manifest, "b", "a", again.public, again.fingerprint)["path_epoch"], 2)   # a rotation
        for states, reason in ((dict(a="QUARANTINED"), "a may not be unlocked under epoch 1: no contribution for it"),
                               (dict(a="RETIRED"), "a may not be unlocked"), (dict(b="MAINTENANCE"), "b may not authorize under epoch 1")):
            self.refused(reason, unlock.contribute, store, self.manifest(**states), "b", "a", again.public, again.fingerprint)
        self.refused("a node is not its own peer", unlock.contribute, store, manifest, "b", "b", again.public, again.fingerprint)
        small = unlock._spki(unlock.rsa.generate_private_key(public_exponent=65537, key_size=2048))
        self.refused("the recipient key must be RSA-3072", unlock.contribute, store, manifest, "b", "a", small, hashlib.sha256(small).hexdigest())
        self.assertEqual(store.epochs("a"), [1, 2])

    def test_the_enrolment_key_lives_in_memory_only_and_is_destroyed_by_its_one_use(self):
        """The one-time private key is never written anywhere: making it, showing its public half and opening
        the contribution touch no file and run no program, and after the one use the object holds no key."""
        touched = []

        def no_files(*args, **kw):
            touched.append(args)
            raise AssertionError("the enrolment touched a file: %r" % (args[:1],))
        with unittest.mock.patch("builtins.open", no_files), unittest.mock.patch("os.open", no_files), \
                unittest.mock.patch("tempfile.mkstemp", no_files), unittest.mock.patch("subprocess.run", no_files):
            enrolment = unlock.Enrolment("a")
            self.assertEqual(enrolment.fingerprint, hashlib.sha256(enrolment.public).hexdigest())
            held = type(enrolment._private)
            secret = os.urandom(32)
            wrapped = {"schema": unlock.ENROLMENT_SCHEMA, "target": "a", "peer": "b", "path_epoch": 4,
                       "ciphertext": unlock.recipient_key(enrolment.public).encrypt(secret, unlock._oaep(unlock._enrolment_label("a", "b", 4))).hex()}
            self.assertEqual(enrolment.open(wrapped, "b"), (4, secret))
        self.assertEqual(touched, [])
        self.assertIsNone(enrolment._private)
        self.assertFalse(any(isinstance(v, held) for v in vars(enrolment).values()))
        # nothing on the object serializes the private key: one method, and four attributes
        self.assertEqual(sorted(n for n in dir(unlock.Enrolment) if not n.startswith("_")), ["open"])
        self.assertEqual(sorted(vars(enrolment)), ["_private", "fingerprint", "public", "target"])

    def test_a_local_contribution_must_be_sealed_to_the_tpm_alone(self):
        local = os.urandom(32)
        self.assertEqual(unlock.local_key_type(fake_seal(local)), "tpm2")
        for kind, name in (("faf7eb9341e3412ca1a436f95a29362f", "tpm2-with-public-key"),):
            self.assertEqual(unlock.local_key_type(base64.b64encode(bytes.fromhex(kind) + local).decode()), name)
        # the host key (what systemd-creds makes without root), host+tpm2 (needs the disk it unlocks), null, junk
        for kind in ("5a1c6a86df9d4096b1d5a65e0862f19a", "93a894094874449090caf2fc93cab553", "058469daf6f54324800549da0f8ea2fb", "00" * 16):
            self.refused("not a systemd credential sealed to the TPM alone", unlock.local_key_type, base64.b64encode(bytes.fromhex(kind) + local).decode())
        for junk in ("", "not base64 !", None, 7):
            self.refused("not a systemd credential sealed to the TPM alone", unlock.local_key_type, junk)

        def creds(kind, rc=0):
            return lambda argv, **kw: subprocess.CompletedProcess(argv, rc, base64.b64encode(bytes.fromhex(kind) + local), b"")
        self.assertEqual(unlock.local_key_type(unlock.seal_local(local, run=creds(TPM2_ID))), "tpm2")
        self.refused("systemd-creds did not seal to the TPM (it does that silently when it is not root)",
                     unlock.seal_local, local, run=creds("5a1c6a86df9d4096b1d5a65e0862f19a"))
        self.refused("systemd-creds made a tpm2 credential, not tpm2-with-public-key", unlock.seal_local, local, public_key="k.pem", run=creds(TPM2_ID))
        self.refused("systemd-creds could not seal", unlock.seal_local, local, run=creds(TPM2_ID, rc=1))
        self.refused("the TPM does not release the local contribution", unlock.unseal_local, "x",
                     run=lambda argv, **kw: subprocess.CompletedProcess(argv, 1, b"", b""))
        self.refused("the TPM does not release the local contribution", unlock.unseal_local, "x",
                     run=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"short", b""))


@unittest.skipUnless(CRYPTSETUP or os.environ.get("REGALIA_EXPECT_CRYPTSETUP") == "1", "cryptsetup is not installed")
class Disk(Case):
    """A real LUKS2 header in a file: the recovery keyslot, then one keyslot and one token per peer."""

    def setUp(self):
        self.assertTrue(CRYPTSETUP, "REGALIA_EXPECT_CRYPTSETUP=1 and cryptsetup is not on PATH")
        super().setUp()
        self.disk = os.path.join(self.d, "disk.img")
        with open(self.disk, "wb") as f:
            f.truncate(32 * 1024 * 1024)
        self.cryptsetup(["luksFormat", "--type", "luks2", "--batch-mode", *unlock.PBKDF, "--key-file", "-", self.disk], RECOVERY)
        self.cryptsetup(["token", "import", "--json-file", "-", self.disk], b'{"type":"systemd-recovery","keyslots":["0"]}')
        self.local = os.urandom(32)
        self.secrets = {}
        self.unsealed = []

    def cryptsetup(self, args, stdin=None):
        done = run(["cryptsetup", *args], input=stdin, capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def enrol(self, peer):
        epoch, self.secrets[peer] = self.enrolled(peer)
        return unlock.enrol_path(self.disk, "a", peer, epoch, self.local, fake_seal(self.local), self.secrets[peer], RECOVERY, run=run)

    def unseal(self, sealed):
        self.unsealed.append(sealed)
        return fake_unseal(sealed)

    def unlock(self, peers=("b", "c"), session=None, transports=None, unseal=None, **kw):
        transports = transports or {p: self.transport(p) for p in peers}
        return unlock.unlock(self.disk, session or self.session, self.stores["a"], transports, self.quote(**kw), unseal or self.unseal, run=run)

    def meta(self):
        return unlock.luks_meta(self.disk, run)

    def down(self, raw):
        raise ConnectionRefusedError("no route to host")

    def test_poc_7_1_to_7_4_either_peer_restores_the_node_and_without_a_peer_the_disk_stays_locked(self):
        self.assertEqual((self.enrol("b"), self.enrol("c")), (1, 2))
        self.assertEqual(unlock.judge_tokens(self.meta(), "a", ["b", "c"]),
                         (True, "peer-assisted unlock: b in keyslot 1 (path epoch 1), c in keyslot 2 (path epoch 1)", {"1", "2"}))
        self.assertEqual(self.unlock(), ("b", 1))                                            # 7.1
        self.assertEqual(self.unlock(session=self.boot()), ("b", 1))
        self.assertEqual(self.unlock(session=self.boot(), transports={"b": self.down, "c": self.transport("c")}), ("c", 2))   # 7.2, 7.3
        rebooted = self.boot()
        self.refused("the disk stays locked: b (path epoch 1): hello: the transport failed (ConnectionRefusedError); "
                     "c (path epoch 1): hello: the transport failed (ConnectionRefusedError)",
                     self.unlock, session=rebooted, transports={"b": self.down, "c": self.down})    # 7.4
        self.assertFalse(rebooted.consumed)                                                  # it may go on retrying
        self.assertEqual(self.unlock(session=rebooted), ("b", 1))

    def test_neither_half_alone_nor_another_path_opens_a_keyslot(self):
        slots = {p: self.enrol(p) for p in ("b", "c")}
        b, c = self.secrets["b"], self.secrets["c"]
        good = unlock.credential(self.local, b, "a", "b", 1)
        self.assertTrue(unlock.opens(self.disk, slots["b"], good, run))
        self.assertFalse(unlock.opens(self.disk, slots["c"], good, run))                     # the keyslots are independent
        wrong = [self.local, b, base64.b64encode(self.local), base64.b64encode(b), base64.b64encode(self.local + b),
                 unlock.credential(os.urandom(32), b, "a", "b", 1),                          # another TPM's half (PoC 7.8, 7.9)
                 unlock.credential(self.local, os.urandom(32), "a", "b", 1),                 # another peer's half
                 unlock.credential(self.local, c, "a", "b", 1),                              # c's contribution on b's path
                 unlock.credential(self.local, b, "a", "c", 1), unlock.credential(self.local, b, "a", "b", 2)]
        for key in wrong:
            for slot in slots.values():
                self.assertFalse(unlock.opens(self.disk, slot, key, run))
        self.assertTrue(unlock.opens(self.disk, 0, RECOVERY, run))                           # and the recovery key is untouched
        self.refused("cryptsetup could not test keyslot", unlock.opens, self.d + "/absent.img", 1, good, run)   # a tool failure is not a "no"

    def test_poc_7_8_on_another_machine_the_local_half_is_missing_and_no_peer_is_asked(self):
        self.enrol("b")

        def other_tpm(sealed):
            raise m.Refused("the TPM does not release the local contribution: another TPM, or a boot its policy does not accept")
        self.refused("the disk stays locked: b (path epoch 1): the TPM does not release the local contribution", self.unlock, ("b",), unseal=other_tpm)
        self.assertEqual(self.wire, [])
        # a TPM that releases something else: the peer helps, the keyslot does not open, and the session is spent
        self.refused("the credential derived with b's contribution does not open keyslot 1", self.unlock, ("b",), unseal=lambda sealed: os.urandom(32))
        self.assertTrue(self.session.consumed)

    def test_issue_135_the_local_half_still_unseals_for_a_retired_image_and_the_disk_stays_locked(self):
        self.enrol("b"), self.enrol("c")
        for peer in ("b", "c"):
            policy = {"schema": attest.POLICY_SCHEMA, "nodes": {"a": {"ek_name": self.keys["a"].ek_name, "tpm_firmware_version": "0" * 16,
                                                                      "pcrs": {"7": "5c" * 32}}}}
            self.attesters[peer] = attest.Verifier(policy, os.path.join(self.d, peer + "-attest-next.json"), now=lambda: self.now)
            self.enroll(self.attesters[peer], self.keys["a"].ak_public)
        self.refused("the disk stays locked: b (path epoch 1): unlock: the peer refused (DENIED); c (path epoch 1): unlock: the peer refused (DENIED)",
                     self.unlock)
        self.assertEqual(len(self.unsealed), 2)                                              # the TPM did its part, twice
        self.assertEqual([(e["event"], e["outcome"], e["reason"]) for e in self.events if e["event"] == "unlock"],
                         [("unlock", "DENY", "the subject's attestation is refused: the quoted PCR digest is not the expected PCR values")] * 2)

    def test_a_path_is_rotated_alone_and_the_old_one_stops_opening(self):
        self.enrol("b"), self.enrol("c")
        old = unlock.credential(self.local, self.secrets["b"], "a", "b", 1)
        new_slot = self.enrol("b")                                                           # path epoch 2, a new keyslot
        self.assertEqual(new_slot, 3)
        ok, why, _ = unlock.judge_tokens(self.meta(), "a")
        self.assertEqual((ok, why), (False, "tokens 1 and 3 are both for peer b: finish the rotation (kill the old keyslot, remove its token)"))
        self.assertEqual(self.unlock(("b",)), ("b", 3))                                      # the newest path is tried first
        self.assertEqual(json.loads(self.wire[-1][1])["path_epoch"], 2)
        self.assertEqual(unlock.remove_path(self.disk, "b", 1, run), 1)
        self.assertEqual(self.contributions["b"].drop("a", 1), [1])
        self.assertFalse(any(unlock.opens(self.disk, s, old, run) for s in (0, 2, 3)))
        self.assertNotIn("1", self.meta()["keyslots"])
        self.assertTrue(unlock.judge_tokens(self.meta(), "a", ["b", "c"])[0])
        self.assertEqual(self.unlock(("b",), session=self.boot()), ("b", 3))
        self.assertEqual(self.unlock(("c",), session=self.boot()), ("c", 2))                 # the other path never moved
        self.refused("the disk has 0 path tokens from b at path epoch 1", unlock.remove_path, self.disk, "b", 1, run)
        self.refused("the disk already has a path from c at path epoch 1", unlock.enrol_path, self.disk, "a", "c", 1, self.local,
                     fake_seal(self.local), self.secrets["c"], RECOVERY, run)

    def test_enrolment_needs_a_key_that_already_opens_the_disk_and_leaves_no_keyslot_without_a_token(self):
        epoch, secret = self.enrolled("b")
        before = self.meta()
        self.refused("cryptsetup luksAddKey failed", unlock.enrol_path, self.disk, "a", "b", epoch, self.local, fake_seal(self.local), secret, b"not the key", run)
        self.assertEqual(self.meta(), before)
        self.refused("not a systemd credential sealed to the TPM alone", unlock.enrol_path, self.disk, "a", "b", epoch, self.local,
                     base64.b64encode(bytes(16) + self.local).decode(), secret, RECOVERY, run)

        def no_import(argv, **kw):
            return subprocess.CompletedProcess(argv, 1, b"", b"") if argv[:3] == ["cryptsetup", "token", "import"] else run(argv, **kw)
        self.refused("cryptsetup token import failed (exit 1); keyslot 1 was removed again", unlock.enrol_path, self.disk, "a", "b", epoch, self.local,
                     fake_seal(self.local), secret, RECOVERY, no_import)
        self.assertEqual(self.meta()["keyslots"].keys(), before["keyslots"].keys())
        # the only keyslot is never removed
        solo = os.path.join(self.d, "solo.img")
        with open(solo, "wb") as f:
            f.truncate(32 * 1024 * 1024)
        self.cryptsetup(["luksFormat", "--type", "luks2", "--batch-mode", *unlock.PBKDF, "--key-file", "-", solo], RECOVERY)
        unlock.enrol_path(solo, "a", "b", epoch, self.local, fake_seal(self.local), secret, RECOVERY, run)
        self.cryptsetup(["luksKillSlot", "--batch-mode", solo, "0"])
        self.refused("keyslot 1 is the only one", unlock.remove_path, solo, "b", epoch, run)

    def test_no_key_reaches_an_argument_or_a_file(self):
        seen = []

        def watching(argv, **kw):
            seen.append(argv)
            return run(argv, **kw)
        epoch, secret = self.enrolled("b")
        unlock.enrol_path(self.disk, "a", "b", epoch, self.local, fake_seal(self.local), secret, RECOVERY, watching)
        unlock.unlock(self.disk, self.session, self.stores["a"], {"b": self.transport("b")}, self.quote(), self.unseal, run=watching)
        key = unlock.credential(self.local, secret, "a", "b", epoch)
        flat = " ".join(str(a) for argv in seen for a in argv).encode()
        for value in (key, RECOVERY, secret.hex().encode(), self.local.hex().encode()):
            self.assertNotIn(value, flat)
        self.assertEqual([n for n in os.listdir(self.d) if n.endswith((".key", ".tmp"))], [])

    def judged(self, change, node="a", peers=None):
        meta = self.meta()
        change(meta)
        ok, why, _ = unlock.judge_tokens(meta, node, peers)
        self.assertFalse(ok)
        return why

    def test_the_probe_judges_the_header(self):
        self.assertEqual(unlock.judge_tokens(self.meta(), "a"), (False, "no regalia-peer-unlock token: the disk has no peer-assisted keyslot (#67)", set()))
        self.enrol("b"), self.enrol("c")
        self.assertTrue(unlock.judge_tokens(self.meta(), "a")[0])
        path = lambda meta: meta["tokens"]["1"]
        self.assertIn("a systemd-tpm2 token is still enrolled (keyslot 0)",
                      self.judged(lambda meta: meta["tokens"].update({"9": {"type": "systemd-tpm2", "keyslots": ["0"], "tpm2-pcrs": [7]}})))
        self.assertIn("keyslot 1 is named by regalia-peer-unlock and systemd-recovery",
                      self.judged(lambda meta: meta["tokens"]["0"].update(keyslots=["1"])))
        self.assertIn("token 1 names keyslot 7, which does not exist", self.judged(lambda meta: path(meta).update(keyslots=["7"])))
        self.assertIn("token 1 is for node c, not a", self.judged(lambda meta: path(meta).update(target="c", peer="b")))
        self.assertIn("token 1 is for node a, not c", self.judged(lambda meta: None, node="c"))
        self.assertIn("tokens 1 and 2 are both for peer b", self.judged(lambda meta: meta["tokens"]["2"].update(peer="b")))
        self.assertIn("token 1: a path token names exactly one keyslot", self.judged(lambda meta: path(meta).update(keyslots=["1", "2"])))
        self.assertIn("token 1: a regalia-peer-unlock token of version 1 is expected", self.judged(lambda meta: path(meta).update(version=2)))
        self.assertIn("token 1: token fields mismatch", self.judged(lambda meta: path(meta).update(note="x")))
        self.assertIn("token 1: a node is not its own peer", self.judged(lambda meta: path(meta).update(peer="a")))
        self.assertIn("token 1: the local contribution is not a systemd credential sealed to the TPM alone",
                      self.judged(lambda meta: path(meta).update(local=base64.b64encode(bytes(48)).decode())))
        self.assertEqual(self.judged(lambda meta: None, peers=["b"]), "the disk has paths from b, c; the record says b")
        self.assertEqual(self.judged(lambda meta: None, peers=["b", "c", "d"]), "the disk has paths from b, c; the record says b, c, d")
        self.assertEqual(unlock.judge_tokens(None, "a")[0], False)
        # the recovery probe and this one account for every keyslot between them (host_probe.recovery_keyslots)
        from deploy.baremetal import host_probe
        self.assertEqual(host_probe.recovery_keyslots(self.meta())[0], True)
        self.assertEqual(unlock.judge_tokens(self.meta(), "a")[2] | {"0"}, set(self.meta()["keyslots"]))


class OnSwtpm(unittest.TestCase):
    """Three software TPMs (target a, peers b and c): real EKs and AKs, real quotes, the peers' responses
    signed by their TPMs, the local contribution sealed by systemd-creds to a's TPM, and a real LUKS2
    volume. Run as root by e2e/peer-unlock-swtpm.sh, which gives a loop device in REGALIA_UNLOCK_DEVICE: the
    volume is then mapped by dm-crypt and its filesystem read. Where the tools are provisioned
    (REGALIA_EXPECT_SWTPM=1) a missing one is a failure, not a skip."""
    TOOLS = ("swtpm", "tpm2_createak", "tpm2_quote", "tpm2_nvdefine", "tpm2_pcrextend", "openssl", "systemd-creds", "cryptsetup")

    def setUp(self):
        missing = [t for t in self.TOOLS if not shutil.which(t, path=PATH)]
        if missing or os.geteuid() != 0:
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("root, swtpm, tpm2-tools, openssl, systemd-creds and cryptsetup are expected here (missing: %s; uid %d)"
                          % (", ".join(missing) or "none", os.geteuid()))
            self.skipTest("needs root (systemd-creds seals to a TPM only as root), swtpm, tpm2-tools, systemd-creds and cryptsetup")
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pids, self.tcti, self.names = {}, {}, {}
        self.addCleanup(lambda: [os.kill(pid, 15) for pid in self.pids.values()])
        for name in ("a", "b", "c"):
            self.start(name)
            os.mkdir("%s/%s" % (self.d, name))
            self.on(name, attest.node_init, "%s/%s" % (self.d, name))
            self.names[name] = {k: attest.name_of(attest.public_area(lt.slurp("%s/%s/%s.pub" % (self.d, name, k)), k)).hex() for k in ("ek", "ak")}
        self.measure("a", "the approved image")
        self.now = lt.T0 + 60
        self.clock = lambda: (self.now, True)
        self.root = hbt.pub(hbt.ROOT)
        self.m1 = self.manifest(None)
        self.events, self.sequence, self.stores, self.fresh, self.attesters, self.contributions, self.served = [], 1, {}, {}, {}, {}, {}
        firmware = attest.parse_quote(self.quote_as("a", 1, bytes(32), b"k", bytes(32))[0])["firmware_version"]
        self.reference = {"tpm_firmware_version": firmware, "pcrs": {"7": self.pcr("a", 7), "11": self.pcr("a", 11)}}
        for name in ("a", "b", "c"):
            anchor = m.HighWater("0x1500016", tcti=self.tcti[name], lock_path="%s/%s-hw.lock" % (self.d, name))
            anchor.define()
            self.stores[name] = m.Store("%s/%s-membership.json" % (self.d, name), self.root, anchor)
            self.stores[name].commit(rt.sign(self.m1))
        for name in ("b", "c"):
            counter = hb.Counter("0x1500018", tcti=self.tcti[name], lock_path="%s/%s-seq.lock" % (self.d, name))
            counter.define()
            self.fresh[name] = hb.Freshness(counter, self.clock, hbt.simulated_ticks(self, self.tcti[name]), "%s/%s-freshness.json" % (self.d, name))
            self.fresh[name].accept(hbt.beat(self.m1, 1, issued=self.now), self.m1)
            self.contributions[name] = unlock.Contributions("%s/%s-contributions.json" % (self.d, name))
            self.served[name] = unlock.Peer(name, self.stores[name], self.fresh[name], lambda manifest, name=name: self.attester(name, manifest),
                                            self.contributions[name], lease.TpmSigner(tcti=self.tcti[name]), self.events.append, run=run)
            self.enroll_ak(self.attester(name, self.m1), name)
        self.device = os.environ.get("REGALIA_UNLOCK_DEVICE")
        self.mapped = bool(self.device)
        if not self.mapped:
            self.device = self.d + "/disk.img"
            with open(self.device, "wb") as f:
                f.truncate(32 * 1024 * 1024)
        self.name = "regalia-unlock-test-%d" % os.getpid()
        self.addCleanup(lambda: os.path.exists("/dev/mapper/" + self.name) and run(["cryptsetup", "close", self.name], capture_output=True))

    # -- the TPMs --
    def start(self, name):
        state, sock = "%s/tpm-%s" % (self.d, name), "%s/%s.sock" % (self.d, name)
        os.makedirs(state, exist_ok=True)
        for leftover in (sock, sock + ".ctrl"):
            if os.path.exists(leftover):
                os.unlink(leftover)
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + state, "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=%s/%s.pid" % (self.d, name)], check=True, capture_output=True)
        time.sleep(0.5)
        with open("%s/%s.pid" % (self.d, name)) as f:
            self.pids[name] = int(f.read())
        self.tcti[name] = "swtpm:path=" + sock

    def reboot(self, name, image):
        """Restart the TPM (PCRs back to zero, resetCount one higher) and measure `image` into it. An orderly
        TPM2_Shutdown first: a power cut counts as a failed authorization try, and after a few of them a TPM
        with default settings is in lockout and quotes nothing (deploy/baremetal/tpm-lockout.sh, #57)."""
        self.on(name, attest.tpm2, "shutdown", "-c")
        os.kill(self.pids[name], 15)
        time.sleep(0.5)
        self.start(name)
        self.measure(name, image)

    def measure(self, name, image):
        digest = hashlib.sha256(image.encode()).hexdigest()
        self.on(name, lambda: attest.tpm2("pcrextend", "7:sha256=" + hashlib.sha256(b"secure boot on").hexdigest(), "11:sha256=" + digest))

    def on(self, tpm, fn, *args):
        with unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI=self.tcti[tpm]):
            return fn(*args)

    def pcr(self, name, index):
        out = subprocess.run(["tpm2_pcrread", "sha256:%d" % index], env=dict(os.environ, TPM2TOOLS_TCTI=self.tcti[name]),
                             check=True, capture_output=True, text=True).stdout
        return out.split("0x")[-1].strip().lower()

    def quote_as(self, tpm, epoch, session_id, ephemeral_public, nonce, node_id=None):
        return unlock.tpm_quote([7, 11], tcti=self.tcti[tpm])(node_id or tpm, epoch, session_id, ephemeral_public, nonce)

    # -- membership and attestation --
    def manifest(self, previous, **states):
        nodes = [{"node_id": n, "state": states.get(n, "ACTIVE"), "ek_name": self.names[n]["ek"], "ak_name": self.names[n]["ak"],
                  "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": ("%02x" % (0xa0 + i)) * 32, "hsm_serials": ["DENK04041%02d" % i]}
                 for i, n in enumerate(("a", "b", "c"))]
        return {"schema": m.SCHEMA, "epoch": previous["epoch"] + 1 if previous else 1, "prev_digest": m.digest(previous) if previous else "",
                "policy_version": "p1", "issued_at": "2026-09-21T09:00:00Z", "revocation_keys": [hbt.pub(hbt.REVOKE)], "nodes": nodes}

    def attester(self, peer, manifest):
        """The peer's verifier under the policy its current manifest gives: every node that may still be
        unlocked or serve, pinned to the manifest's EK, with the reference measurements of the approved image."""
        measurements = {n["node_id"]: self.reference for n in manifest["nodes"]}
        return attest.Verifier(replacement.attest_policy(manifest, measurements, peer_id=peer), "%s/%s-attest.json" % (self.d, peer))

    def enroll_ak(self, attester, peer, tpm="a"):
        credential = attester.challenge("a", lt.slurp("%s/%s/ek.pub" % (self.d, tpm)), lt.slurp("%s/%s/ak.pub" % (self.d, tpm)))
        cred, secret = "%s/cred-%s" % (self.d, peer), "%s/secret-%s" % (self.d, peer)
        with open(cred, "wb") as f:
            f.write(credential)
        self.on(tpm, attest.node_activate, cred, secret)
        attester.enroll("a", lt.slurp(secret))

    # -- the target --
    def transport(self, peer):
        return lambda raw: json.dumps(self.served[peer].handle(raw)).encode()

    def unseal(self, tpm="a"):
        return lambda sealed: unlock.unseal_local(sealed, tpm2_device=self.tcti[tpm], run=run)

    def unlock(self, peers=("b", "c"), tpm="a", name=None):
        return unlock.unlock(self.device, unlock.BootSession("a"), self.stores["a"], {p: self.transport(p) for p in peers},
                             unlock.tpm_quote([7, 11], tcti=self.tcti[tpm]), self.unseal(tpm), name=name, run=run)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises((m.Refused, attest.Refused)) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def reasons(self, since):
        return [e["reason"] for e in self.events[since:] if e["outcome"] == "DENY"]

    def test_tpm_plus_one_peer_opens_the_disk_and_a_retired_image_a_stolen_disk_or_a_revoked_node_does_not(self):
        cs = lambda args, stdin=None: self.assertEqual(run(["cryptsetup", *args], input=stdin, capture_output=True).returncode, 0, args)
        cs(["luksFormat", "--type", "luks2", "--batch-mode", *unlock.PBKDF, "--key-file", "-", self.device], RECOVERY)
        cs(["token", "import", "--json-file", "-", self.device], b'{"type":"systemd-recovery","keyslots":["0"]}')
        if self.mapped:                                                # a filesystem with a marker, as a root volume has
            cs(["open", "--key-file", "-", self.device, self.name], RECOVERY)
            mnt = self.d + "/mnt"
            os.mkdir(mnt)
            for argv in (["mkfs.ext4", "-q", "/dev/mapper/" + self.name], ["mount", "/dev/mapper/" + self.name, mnt]):
                self.assertEqual(run(argv, capture_output=True).returncode, 0, argv)
            with open(mnt + "/marker", "w") as f:
                f.write("regalia-kms root volume marker")
            self.assertEqual(run(["umount", mnt], capture_output=True).returncode, 0)
            cs(["close", self.name])

        # enrolment: the local half sealed to a's TPM under the approved image's PCRs 7 and 11, one path per peer
        local = os.urandom(32)
        sealed = unlock.seal_local(local, pcrs="7+11", tpm2_device=self.tcti["a"], run=run)
        self.assertEqual(unlock.local_key_type(sealed), "tpm2")
        self.assertEqual(self.unseal()(sealed), local)
        for peer in ("b", "c"):
            enrolment = unlock.Enrolment("a")
            wrapped = unlock.contribute(self.contributions[peer], self.m1, peer, "a", enrolment.public, enrolment.fingerprint)
            epoch, secret = enrolment.open(wrapped, peer)
            unlock.enrol_path(self.device, "a", peer, epoch, local, sealed, secret, RECOVERY, run)
        del local, secret
        self.assertEqual(unlock.judge_tokens(unlock.luks_meta(self.device, run), "a", ["b", "c"])[:2],
                         (True, "peer-assisted unlock: b in keyslot 1 (path epoch 1), c in keyslot 2 (path epoch 1)"))

        # PoC 7.1: a reboots on the approved image; b restores it. Mapped for real when a block device is given.
        self.reboot("a", "the approved image")
        self.assertEqual(self.unlock(name=self.name if self.mapped else None), ("b", 1))
        if self.mapped:
            self.assertEqual(run(["mount", "-o", "ro", "/dev/mapper/" + self.name, self.d + "/mnt"], capture_output=True).returncode, 0)
            self.assertEqual(lt.slurp(self.d + "/mnt/marker"), b"regalia-kms root volume marker")
            self.assertEqual(run(["umount", self.d + "/mnt"], capture_output=True).returncode, 0)
            cs(["close", self.name])
        # PoC 7.2, 7.3: b is down; c restores it through its own keyslot
        self.reboot("a", "the approved image")
        self.assertEqual(self.unlock(peers=("c",)), ("c", 2))
        # PoC 7.4: no peer; the TPM half alone opens nothing
        self.reboot("a", "the approved image")
        self.refused("the disk stays locked: no peer to ask", self.unlock, peers=())

        # #135: a boots an image the peers' reference values do not list. Its TPM refuses the local half here
        # (it is bound to PCR 11 directly); with a SIGNED PCR 11 policy the TPM would release it for every image
        # ever signed, which is the case the next block makes.
        self.reboot("a", "a retired image")
        since = len(self.events)
        self.refused("the TPM does not release the local contribution", self.unlock)
        self.assertEqual(self.events[since:], [])                     # no peer was even asked
        # the same retired image, with the local half in hand (as a signed policy would give it): both peers refuse
        session = unlock.BootSession("a")
        for peer in ("b", "c"):
            self.refused("unlock: the peer refused (DENIED)", unlock.ask, session, self.stores["a"], peer, 1, self.transport(peer),
                         unlock.tpm_quote([7, 11], tcti=self.tcti["a"]), run)
        self.assertEqual(self.reasons(since), ["the subject's attestation is refused: the quoted PCR digest is not the expected PCR values"] * 2)
        self.assertFalse(session.consumed)

        # PoC 7.8, 7.9: the disk in another machine (c's TPM, booted on the approved image, claiming to be a)
        self.reboot("c", "the approved image")
        since = len(self.events)
        self.refused("the TPM does not release the local contribution", self.unlock, peers=("b",), tpm="c")
        self.refused("unlock: the peer refused (DENIED)", unlock.ask, unlock.BootSession("a"), self.stores["a"], "b", 1, self.transport("b"),
                     unlock.tpm_quote([7, 11], tcti=self.tcti["c"]), run)
        self.assertIn("the subject's attestation is refused", self.reasons(since)[-1])

        # the approved image again: restored. Then a is reported stolen: the revocation key alone, no root ceremony.
        self.reboot("a", "the approved image")
        self.assertEqual(self.unlock(), ("b", 1))
        m2 = self.manifest(self.m1, a="REVOKED_STOLEN")
        for peer in ("b", "c"):
            self.stores[peer].commit(rt.sign(m2, hbt.REVOKE, "revocation"))
            self.fresh[peer].accept(hbt.beat(m2, 2, issued=self.now), m2)
        self.reboot("a", "the approved image")
        since = len(self.events)
        self.refused("the disk stays locked: b (path epoch 1): hello: the peer refused (DENIED); c (path epoch 1): hello: the peer refused (DENIED)", self.unlock)
        self.assertEqual(self.reasons(since), ["a may not be unlocked under epoch 2"] * 2)
        self.assertEqual(self.stores["a"].load()["epoch"], 1)         # a refused node is told nothing
        self.assertEqual([self.contributions[p].epochs("a") for p in ("b", "c")], [[], []])       # and the peers' halves are gone
        # the recovery key still opens the volume: the manual path of a total outage (#77) does not go through a peer
        self.assertTrue(unlock.opens(self.device, 0, RECOVERY, run))


if __name__ == "__main__":
    unittest.main()
