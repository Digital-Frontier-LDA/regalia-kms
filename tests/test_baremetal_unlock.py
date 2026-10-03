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
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
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
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS = os.path.join(REPO, "tests", "vectors", "unlock-v1.json")
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
        self.pins = unlock.validate_boot_config(unlock.boot_config(self.m1, "a", "/dev/disk/by-partlabel/root", [7],
                                                                   {"b": "192.0.2.2:7443", "c": "192.0.2.3:7443"}))
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
        return unlock.ask(session or self.session, self.pins[peer], path, self.transport(peer), self.quote(**kw), run=run)

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
            ("the response was decided under epoch 2, not the epoch 1 the peer's hello stated", resigned("b", epoch=2)),
            ("the contribution does not decrypt", resigned("b", ciphertext=other._private.public_key().encrypt(
                secret, unlock._oaep(unlock.CONTRIBUTION_LABEL + bytes(32))).hex())),
            ("unlock reply fields mismatch", lambda reply: dict(reply, extra=1)),
            ("response fields mismatch", lambda reply: dict(reply, response=dict(reply["response"], extra=1))),
        ]
        for reason, change in cases:
            with self.subTest(reason):
                self.refused(reason, unlock.ask, self.session, self.pins["b"], epoch, forged(change), self.quote(), run)
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
        self.refused("hello: the peer refused (DENIED)", unlock.ask, unlock.BootSession("c"), self.pins["b"], epoch, self.transport("b"), self.quote(), run)
        self.refused("hello: the peer refused (DENIED)", unlock.ask, unlock.BootSession("x"), self.pins["b"], epoch, self.transport("b"), self.quote(), run)
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
        self.refused("the response is for another node or another boot session", unlock.ask, rebooted, self.pins["b"], epoch,
                     lambda raw: response if b'"unlock"' in raw else self.transport("b")(raw), self.quote(), run)
        self.assertFalse(rebooted.consumed)
        self.refused("the contribution does not decrypt", unlock._decrypt, rebooted._private,
                     bytes.fromhex(json.loads(response)["response"]["ciphertext"]),
                     unlock.CONTRIBUTION_LABEL + bytes.fromhex(json.loads(response)["response"]["transcript_sha256"]))
        self.assertEqual(unlock.ask(rebooted, self.pins["b"], epoch, self.transport("b"), self.quote(), run), secret)
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
        self.refused("the peer answered for path epoch 1, not 2", unlock.ask, self.session, self.pins["b"], new, downgraded, self.quote(), run)
        self.assertEqual(self.events[-1]["outcome"], "ALLOW")         # the peer did answer, validly
        self.assertFalse(self.session.consumed)
        self.assertEqual(self.ask("b", new), secret)                  # the same boot still unlocks

    def test_an_unreachable_peer_is_one_refusal_and_the_next_peer_is_asked(self):
        epoch, secret = self.enrolled("c")
        for error in (ConnectionRefusedError("refused"), TimeoutError("timed out"), OSError("no route to host"), EOFError()):
            def dead(raw, error=error):
                raise error
            with self.subTest(type(error).__name__):
                self.refused("hello: the transport failed (%s)" % type(error).__name__, unlock.ask, self.session, self.pins["b"], 1, dead, self.quote(), run)
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
        self.refused("unlock: the peer refused (DENIED)", unlock.ask, self.session, self.pins["b"], epoch, slow, self.quote(), run)
        self.denied("heartbeat")

    def test_the_target_quotes_the_epoch_the_peer_states_and_holds_no_manifest(self):
        epoch, secret = self.enrolled("b")
        # c was quarantined while a was down: b is at epoch 2, a's boot configuration is from epoch 1
        self.revoke(self.stores["authority"].load(), "QUARANTINED", node="c")
        self.publish("b")
        self.assertEqual(self.ask("b", epoch), secret)
        self.assertEqual([json.loads(raw)["op"] for _, raw, _ in self.wire], ["hello", "unlock"])
        self.assertEqual(json.loads(self.wire[0][1]), {"v": 1, "op": "hello", "node_id": "a"})
        self.assertEqual(sorted(json.loads(self.wire[0][2])), ["epoch", "nonce", "peer_id", "v"])
        self.assertEqual(json.loads(self.wire[1][2])["response"]["epoch"], 2)
        other = self.boot()
        self.refused("the hello reply is not version 1", unlock.ask, other, self.pins["b"], epoch,
                     lambda raw: json.dumps(dict(json.loads(self.transport("b")(raw)), v=2)).encode(), self.quote(), run)
        # a hello reply changed on the way to state another epoch: the quote is over it, and the peer refuses
        fresh, genuine = self.boot(), self.transport("b")

        def restated(raw):
            reply = json.loads(genuine(raw))
            if "nonce" in reply:
                reply["epoch"] = 1
            return json.dumps(reply).encode()
        self.refused("unlock: the peer refused (DENIED)", unlock.ask, fresh, self.pins["b"], epoch, restated, self.quote(), run)
        self.denied("the quote is not bound to this transcript")

    def test_the_target_accepts_only_the_peers_its_boot_configuration_names(self):
        epoch, secret = self.enrolled("b")
        other_ak = dict(self.pins["b"], ak_name=self.keys["c"].ak_name)
        self.refused("the response is not signed by the AK the manifest names for b", unlock.ask, self.session, other_ak, epoch, self.transport("b"), self.quote(), run)
        other_ek = dict(self.pins["b"], ek_name=self.keys["c"].ek_name)
        self.refused("the response is not signed by b's AK under the EK the manifest names", unlock.ask, self.session, other_ek, epoch, self.transport("b"), self.quote(), run)
        self.refused("the peer that answered is 'b', not c", unlock.ask, self.session, self.pins["c"], epoch, self.transport("b"), self.quote(), run)
        self.assertFalse(self.session.consumed)
        self.assertEqual(self.ask("b", epoch), secret)

    def test_the_boot_configuration_lists_the_peers_that_may_authorize(self):
        config = unlock.boot_config(self.m1, "a", "/dev/sda3", [11, 7, 7], {"c": "[2001:db8::3]:7443", "b": "porto.boot:7443"})
        self.assertEqual((config["node_id"], config["pcrs"], [p["node_id"] for p in config["peers"]]), ("a", [7, 11], ["b", "c"]))
        self.assertEqual(config["peers"][0], {"node_id": "b", "endpoint": "porto.boot:7443", "ek_name": self.keys["b"].ek_name, "ak_name": self.keys["b"].ak_name})
        self.assertEqual(list(unlock.validate_boot_config(json.loads(json.dumps(config)))), ["b", "c"])
        quarantined = unlock.boot_config(self.manifest(c="QUARANTINED"), "a", "/dev/sda3", [7], {"b": "192.0.2.2:1", "c": "192.0.2.3:1"})
        self.assertEqual([p["node_id"] for p in quarantined["peers"]], ["b"])
        self.refused("the manifest leaves a no peer with an address", unlock.boot_config, self.m1, "a", "/dev/sda3", [7], {})
        self.refused("x is not in the manifest", unlock.boot_config, self.m1, "x", "/dev/sda3", [7], {"b": "192.0.2.2:1"})
        for change, reason in ((dict(extra=1), "boot configuration fields mismatch"), (dict(schema="v0"), "schema must be"),
                               (dict(device="/dev/sda3; rm"), "device must be a plain path"), (dict(pcrs=[11, 7]), "pcrs must be an ascending list"),
                               (dict(pcrs=[]), "pcrs must be an ascending list"), (dict(pcrs=[24]), "pcrs must be an ascending list"),
                               (dict(peers=[]), "peers must list 1 to 8 peers"), (dict(peers=config["peers"][:1] * 2), "peer b is listed twice"),
                               (dict(node_id="b"), "is listed twice, or is the node itself"),
                               (dict(peers=[dict(config["peers"][0], endpoint="porto.boot")]), "peer.endpoint must be host:port"),
                               (dict(peers=[dict(config["peers"][0], endpoint="fd00::2:7000")]), "an IPv6 address in brackets"),
                               (dict(peers=[dict(config["peers"][0], endpoint="192.0.2.2:70000")]), "the port 1-65535"),
                               (dict(peers=[dict(config["peers"][0], endpoint="192.0.2.2:0")]), "the port 1-65535"),
                               (dict(peers=[dict(config["peers"][0], endpoint=7)]), "peer.endpoint must be host:port"),
                               (dict(peers=[dict(config["peers"][0], ak_name="000b" + "zz" * 32)]), "peer.ak_name must be a SHA-256 TPM Name"),
                               (dict(peers=[dict(config["peers"][0], extra=1)]), "peer fields mismatch")):
            with self.subTest(reason):
                self.refused(reason, unlock.validate_boot_config, dict(config, **change))

    def test_the_transport_is_one_bounded_request_per_connection(self):
        epoch, secret = self.enrolled("b")
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        endpoint = "127.0.0.1:%d" % listener.getsockname()[1]
        with unittest.mock.patch.object(unlock, "IO_TIMEOUT", 2):
            server = threading.Thread(target=unlock.serve, args=(self.served["b"], listener, 9), daemon=True)
            server.start()
            send = unlock.tcp_transport(endpoint)
            self.assertEqual(json.loads(send(b"{")), {"v": 1, "error": "INVALID_REQUEST"})
            self.assertEqual(json.loads(send(b"[" * 60000)), {"v": 1, "error": "INVALID_REQUEST"})
            # a sender of one byte now and then: the whole connection has the time limit, not each byte
            with socket.create_connection(listener.getsockname()) as dripping:
                started = time.monotonic()
                with self.assertRaises(OSError):
                    while time.monotonic() - started < 8:
                        dripping.sendall(b" ")
                        time.sleep(0.4)
                self.assertLess(time.monotonic() - started, 4)
            # a failure of the handler that nobody foresaw: audited by its kind, and the next request is served
            handle = self.served["b"].handle
            with unittest.mock.patch.object(self.served["b"], "handle", side_effect=ZeroDivisionError("a bug")):
                self.assertEqual(send(b"{}"), b"")
            self.assertEqual((self.events[-1]["event"], self.events[-1]["outcome"], self.events[-1]["reason"]), ("unlock-server-error", "ERROR", "ZeroDivisionError"))
            self.assertIs(self.served["b"].handle.__func__, handle.__func__)
            self.assertEqual(json.loads(send(b" " * (unlock.MAX_BYTES + 1))), {"v": 1, "error": "INVALID_REQUEST"})
            with socket.create_connection(listener.getsockname()) as stalled:      # says half a request and stalls: it costs itself only
                stalled.sendall(b'{"v":1,')
                time.sleep(2.5)
            socket.create_connection(listener.getsockname()).close()               # connects and leaves
            self.assertEqual(unlock.ask(self.session, self.pins["b"], epoch, send, self.quote(), run), secret)   # two connections
            server.join(10)
            self.assertFalse(server.is_alive())
        listener.close()
        self.refused("hello: the transport failed (ConnectionRefusedError)", unlock.ask, self.boot(), self.pins["b"], epoch, send, self.quote(), run)

    def test_both_clients_and_the_peer_agree_on_the_published_vectors(self):
        """tests/vectors/unlock-v1.json is what the native client (internal/unlock) is tested against as well:
        the transcript, the digest a response is signed over, the qualified name of an AK, the OAEP label
        and the credential, each from fixed inputs."""
        with open(VECTORS) as f:
            vectors = json.load(f)
        t = vectors["transcript"]
        raw = attest.transcript(t["node_id"], t["epoch"], bytes.fromhex(t["session_id"]), bytes.fromhex(t["ephemeral_public"]), bytes.fromhex(t["nonce"]))
        self.assertEqual((raw.hex(), hashlib.sha256(raw).hexdigest()), (t["bytes"], t["sha256"]))
        refused = vectors["transcripts_a_peer_must_refuse"]["variants"]
        self.assertEqual(sorted(x["changed"] for x in refused), ["ephemeral_public", "epoch", "node_id", "nonce", "session_id"])
        for x in refused:
            changed = attest.qualifying_data(x["node_id"], x["epoch"], bytes.fromhex(x["session_id"]), bytes.fromhex(x["ephemeral_public"]), bytes.fromhex(x["nonce"]))
            self.assertEqual(changed.hex(), x["sha256"])
            self.assertNotEqual(x["sha256"], t["sha256"])
            # the peer's verifier, given a quote over the first transcript: refused for each variant
            quote = self.keys["a"].signer()(bytes.fromhex(t["sha256"]))
            self.assertNotEqual(attest.parse_quote(bytes.fromhex(quote["quote"]))["extra_data"], changed)
        r = vectors["response"]
        self.assertEqual((m.canonical(r["response"]).decode(), unlock.signed_digest(r["response"]).hex()), (r["canonical"], r["signed_digest"]))
        unlock.validate_response(r["response"])
        q = vectors["qualified_name"]
        self.assertEqual(attest.qualified_name(bytes.fromhex(q["ek_name"]), bytes.fromhex(q["ak_name"])).hex(), q["qualified_name"])
        c = vectors["credential"]
        self.assertEqual(unlock.credential(bytes.fromhex(c["local"]), bytes.fromhex(c["contribution"]), c["target"], c["peer"], c["path_epoch"]).decode(), c["passphrase"])
        self.assertEqual((unlock.HKDF_INFO % (c["target"], c["peer"], c["path_epoch"])), c["info"])
        self.assertEqual((unlock.CONTRIBUTION_LABEL + bytes.fromhex(t["sha256"])).hex(), vectors["oaep_label"])
        self.assertEqual(unlock.RESPONSE_DOMAIN.hex(), vectors["response_domain"])

    def test_a_request_is_bounded_and_exact(self):
        peer = self.served["b"]
        hello = {"v": 1, "op": "hello", "node_id": "a"}
        self.assertIn("nonce", peer.handle(json.dumps(hello).encode()))
        invalid = {"v": 1, "error": "INVALID_REQUEST"}
        for raw in (b"", b"[]", b"{", b'{"v":1}', b'{"v":2,"op":"hello"}', b'{"v":true,"op":"hello"}', b'{"v":1,"op":"init"}', b'{"v":1,"op":7}',
                    b'{"v":1,"v":1,"op":"hello"}', b'{"v":1.0,"op":"hello"}', b'{"v":1,"op":"manifests","envelopes":[]}', b" " * (unlock.MAX_BYTES + 1),
                    b"[" * 60000):                                    # deeper than the JSON parser recurses: refused, not a crash
            with self.subTest(raw[:30]):
                self.assertEqual(peer.handle(raw), invalid)
        denied = {"v": 1, "error": "DENIED"}
        for message in (dict(hello, extra=1), dict(hello, node_id="A"), dict(hello, node_id=7), dict(hello, summary={"epoch": 1, "manifest_digest": ""}),
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 32, "path_epoch": 1},
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 32, "path_epoch": True, "evidence": {}},
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 31, "path_epoch": 1, "evidence": {}},
                        {"v": 1, "op": "unlock", "node_id": "a", "session_id": "00" * 32, "path_epoch": 1, "evidence": None}):
            with self.subTest(str(message)[:60]):
                self.assertEqual(peer.handle(json.dumps(message).encode()), denied)

    def test_a_request_must_name_the_node_the_tunnel_identified(self):
        """The boot mesh knows which node a connection comes from. A request made in another node's name is
        refused before the peer looks at it, and a connection from an address of no node is not answered."""
        epoch, secret = self.enrolled("b")
        peer, hello = self.served["b"], b'{"v":1,"op":"hello","node_id":"a"}'
        self.assertIn("nonce", peer.handle(hello, caller="a"))
        self.assertEqual(peer.handle(hello, caller="c"), {"v": 1, "error": "DENIED"})
        self.assertEqual((self.events[-1]["event"], self.events[-1]["subject"], self.events[-1]["outcome"]), ("unlock-caller", "a", "DENY"))
        self.assertIn("not the one the tunnel identified (c)", self.events[-1]["reason"])
        self.assertEqual(peer.handle(b'{"v":1,"op":"unlock","node_id":"a"}', caller="c"), {"v": 1, "error": "DENIED"})
        self.assertEqual(peer.handle(b'{"v":1,"op":"hello"}', caller="a"), {"v": 1, "error": "DENIED"})
        # over the transport: the address names the node
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        send = unlock.tcp_transport("127.0.0.1:%d" % listener.getsockname()[1])
        owners, seen = iter(["a", "c", None]), []
        server = threading.Thread(target=unlock.serve, args=(peer, listener, 4),
                                  kwargs={"caller": lambda address: seen.append(address) or next(owners, "a")}, daemon=True)
        server.start()
        self.assertIn("nonce", json.loads(send(hello)))                # the address is a's
        self.assertEqual(json.loads(send(hello)), {"v": 1, "error": "DENIED"})   # the address is c's, the request says a
        try:                                                          # an address of no node: closed, unanswered
            self.assertEqual(send(hello), b"")
        except OSError:
            pass                                                      # (closed before the request was read: a reset)
        self.assertIn("nonce", json.loads(send(hello)))                # and the server went on serving
        server.join(10)
        self.assertFalse(server.is_alive())
        self.assertEqual(seen, ["127.0.0.1"] * 4)
        # a dual-stack listener reports an IPv4 caller as ::ffff:a.b.c.d: the same node, not a stranger
        dual = socket.create_server(("::", 0), family=socket.AF_INET6, dualstack_ipv6=True)
        self.addCleanup(dual.close)
        mapped = []
        # and a sink that fails does not end the loop: the second connection is still served
        broken = unittest.mock.patch.object(peer, "audit", side_effect=OSError("the sink is down"))
        server = threading.Thread(target=unlock.serve, args=(peer, dual, 2), kwargs={"caller": lambda address: mapped.append(address) or "c"}, daemon=True)
        with broken:
            server.start()
            via = unlock.tcp_transport("127.0.0.1:%d" % dual.getsockname()[1])
            for _ in range(2):
                try:
                    via(hello)                                        # refused (c's address, a's name); the audit of it fails
                except OSError:
                    pass
            server.join(10)
        self.assertFalse(server.is_alive())
        self.assertEqual(mapped, ["127.0.0.1"] * 2)

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
        return unlock.unlock(self.disk, session or self.session, self.pins, transports, self.quote(**kw), unseal or self.unseal, run=run)

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
        unlock.unlock(self.disk, self.session, self.pins, {"b": self.transport("b")}, self.quote(), self.unseal, run=watching)
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


class Units(unittest.TestCase):
    """deploy/baremetal/initrd/: what the two units must say, whatever else changes in them. That they WORK
    is shown with a running systemd (OnSwtpm, e2e/peer-unlock-swtpm.sh)."""

    def unit(self, name):
        sections, current = {}, None
        with open(os.path.join(REPO, "deploy", "baremetal", "initrd", name)) as f:
            for line in f:
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    current = sections.setdefault(line[1:-1], [])
                elif line and not line.startswith("#"):
                    current.append(tuple(line.split("=", 1)))
        return sections

    def test_the_socket_is_the_one_crypttab_and_the_probe_know(self):
        socket_unit = dict(self.unit("regalia-unlock.socket")["Socket"])
        self.assertEqual(socket_unit["ListenStream"], unlock.KEY_SOCKET)
        self.assertEqual((socket_unit["SocketMode"], socket_unit["DirectoryMode"]), ("0600", "0700"))
        self.assertNotIn("Accept", socket_unit)                       # one service takes the listening socket itself

    def test_every_credential_of_the_initrd_is_unsealed_after_pcr_11_holds_the_initrd_phase(self):
        """A credential sealed to the image's initrd-phase PCR 11 signature opens only once systemd-pcrphase-initrd
        has extended "enter-initrd"; a unit that unseals one without that ordering fails when it wins the race."""
        here = os.path.join(REPO, "deploy/baremetal/initrd")
        loading = [n for n in sorted(os.listdir(here)) if n.endswith(".service")
                   and [k for k, _ in self.unit(n).get("Service", []) if k.startswith("LoadCredential")]]
        self.assertEqual(loading, ["regalia-unlock.service", "regalia-wg-boot.service"])   # a new one is checked too
        for name in loading:
            after = " ".join(v for k, v in self.unit(name)["Unit"] if k == "After").split()
            self.assertIn("systemd-pcrphase-initrd.service", after, name)
        # ... and that unit is IN the initrd: dracut adds the module only when one depends on it
        with open(os.path.join(here, "dracut/90regalia-unlock/module-setup.sh")) as f:
            module = f.read()
        depends = module[module.index("depends() {"):module.index("installkernel() {")]
        self.assertIn("systemd-pcrphase", re.search(r"^\s*echo (.*)$", depends, re.M).group(1).split())

    def test_the_key_socket_is_served_by_a_relay_that_holds_nothing_and_always_starts(self):
        """The recovery key's path does not depend on the real client starting (#66): the key socket's service is
        a relay with no credential, no TPM, no network and no dependency, in front of the real client's socket."""
        key = dict(self.unit("regalia-unlock.socket")["Socket"])
        core = dict(self.unit("regalia-unlock-core.socket")["Socket"])
        self.assertEqual((key["Service"], core["Service"]), ("regalia-unlock-relay.service", "regalia-unlock.service"))
        self.assertEqual((core["SocketMode"], core["DirectoryMode"]), ("0600", "0700"))
        relay = self.unit("regalia-unlock-relay.service")
        service, unit = relay["Service"], relay["Unit"]
        values = dict(service)
        self.assertEqual(values["ExecStart"], "/usr/bin/regalia-unlock -relay %s -relay-wait 330s" % core["ListenStream"])
        # the client's own budget ends its attempt before the relay stops waiting
        client = dict(self.unit("regalia-unlock.service")["Service"])["ExecStart"]
        self.assertTrue(client.endswith(" -budget 240s"), client)
        # no setting that adds dependencies on mounts or other units (systemd.exec: PrivateTmp, JoinsNamespaceOf, ...)
        for adds in ("PrivateTmp", "JoinsNamespaceOf", "RequiresMountsFor", "ReadWritePaths", "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem"):
            self.assertNotIn(adds, values)
        self.assertFalse([k for k, _ in service if "Credential" in k or k in ("DeviceAllow", "Environment", "EnvironmentFile", "User")])
        self.assertEqual((values["RestrictAddressFamilies"], values["PrivateNetwork"], values["DevicePolicy"], values["PrivateDevices"]),
                         ("AF_UNIX", "yes", "closed", "yes"))
        self.assertEqual((values["CapabilityBoundingSet"], values["NoNewPrivileges"], values["ProtectSystem"], values["LimitCORE"]), ("", "yes", "strict", "0"))
        # nothing it needs can fail: no Requires/Wants/BindsTo/Requisite/After, only what stops it at switch-root
        self.assertEqual(sorted(k for k, _ in unit if k not in ("Description", "Documentation")),
                         ["Before", "Conflicts", "DefaultDependencies"])
        self.assertEqual(dict(self.unit("regalia-unlock.service")["Unit"])["Requires"], "regalia-unlock-core.socket")

    def test_the_image_is_the_same_for_every_host(self):
        """Nothing per host is in the initrd (#66): every per-host file comes from the ESP, read by a fixed path
        under the stub's archive (/.extra/global_credentials), never from systemd's credential store, and the
        one crypttab line names the root partition by its GPT label."""
        here = os.path.join(REPO, "deploy/baremetal/initrd")
        secret = {"regalia-unlock.service": ["regalia.unlock-local"], "regalia-wg-boot.service": ["regalia.wg-boot-key"]}
        plain = {"regalia-unlock.service": ["regalia.unlock-config"],
                 "regalia-wg-boot.service": ["regalia.wg-boot-conf", "regalia.boot-nft", "regalia.boot-env"]}
        for name in secret:
            service = self.unit(name)["Service"]
            # each by its fixed path under the stub's archive: no credential is taken from systemd's store
            at = lambda names: ["%s:/.extra/global_credentials/%s.cred" % (n, n) for n in names]
            self.assertEqual([v for k, v in service if k == "LoadCredentialEncrypted"], at(secret[name]), name)
            self.assertEqual([v for k, v in service if k == "LoadCredential"], at(plain[name]), name)
            self.assertFalse([k for k, _ in service if k == "ImportCredential"], name)
        for name in sorted(os.listdir(here)) + ["dracut/90regalia-unlock/module-setup.sh"]:
            if os.path.isfile(os.path.join(here, name)):
                with open(os.path.join(here, name)) as f:
                    for number, line in enumerate(f, 1):
                        if not line.lstrip().startswith("#"):
                            self.assertNotIn("/etc/regalia", line, "%s:%d" % (name, number))
        with open(os.path.join(here, "dracut/90regalia-unlock/module-setup.sh")) as f:
            module = f.read()
        install = module[module.index("install() {"):]
        installed = re.findall(r"inst_(?:simple|multiple)\s+(?:-\S+\s+)?([^\n]+)", install)
        # from the build machine: programs, the module's own units and script, and the crypttab line IN THE MODULE
        self.assertEqual(installed, ["regalia-unlock wg nft ip sed cat sleep", "/usr/lib/regalia/wg-boot",
                                     '"${systemdsystemunitdir:?}/$unit"', '"${moddir:?}/crypttab" /etc/crypttab'])
        check = module[module.index("check() {"):module.index("depends() {")]
        self.assertIn('if [ -n "${hostonly-}" ]; then', check)
        # the second layer: no generator of units from credentials, and no credential imported by tmpfiles or sysctl
        self.assertIn('rm -f -- "${initdir:?}${systemdutildir:?}/system-generators/systemd-debug-generator"', install)
        loop = re.search(r"for service in ([^;]+); do", install).group(1).replace("\\\n", " ").split()
        self.assertEqual(loop, ["systemd-tmpfiles-setup.service", "systemd-tmpfiles-setup-dev-early.service", "systemd-tmpfiles-setup-dev.service",
                                "systemd-sysctl.service", "systemd-journald.service", "systemd-sysusers.service"])
        self.assertIn("printf '[Service]\\nImportCredential=\\n'", install)
        with open(os.path.join(here, "dracut/90regalia-unlock/crypttab")) as f:
            lines = [l.split() for l in f if l.strip() and not l.startswith("#")]
        self.assertEqual(lines, [["root", "PARTLABEL=regalia-root", unlock.KEY_SOCKET, "luks,x-initrd.attach"]])
        with open(os.path.join(here, "wg-boot")) as f:
            script = f.read()
        # every program the script runs is in the image: a check that runs a missing tool fails OPEN (seen: grep).
        # Every word in a command position (line start, after | ; & && || ( $( ` and after if/then/do/else/!) is a
        # shell builtin or keyword, a function of the script, or a program the module installs.
        code = "\n".join(re.sub(r"(^|\s)#.*$", r"\1", l) for l in script.splitlines())
        code = re.sub(r"\[![^\]]*\]", "", code)                       # glob classes in case patterns
        code = re.sub(r"(?m)(^\s*|\bin\s+)[^\s()]+\)", r"\1", code)        # case labels
        code = re.sub(r'"\([^"$]*\)"', '""', code)                     # a literal "(...)" in a string
        shipped = set(re.search(r"inst_multiple ([^\n]+)", install).group(1).split())
        functions = set(re.findall(r"(?m)^\s*([a-z_]+)\(\)\s*\{", code))
        builtins = {"set", "case", "esac", "in", "if", "then", "else", "elif", "fi", "while", "until", "do", "done", "for", "read",
                    "echo", "printf", "exit", "return", "trap", "local", "shift", "true", "false", "test", "[", "]", "[[", "break",
                    "continue", "export", "unset", "eval", "exec", ":", "{", "}", "!", "wait", "cd", "umask"}
        words = set()
        for match in re.finditer(r"(?:^|[|;&(`]|\$\(|\b(?:if|then|do|else|elif|while|until)\b|!)\s*(?=([A-Za-z_][\w.+-]*|\[))", code, re.M):   # (a lookahead: "if awk" yields both)
            words.add(match.group(1))
        words -= {w for w in words if re.fullmatch(r"[A-Za-z_]\w*", w) and re.search(r"\b%s=" % re.escape(w), code)}   # assignments
        unknown = sorted(words - builtins - functions - shipped)
        self.assertEqual(unknown, [], "the script runs programs the image does not hold")
        for tool in ("ip", "wg", "nft", "sed", "cat", "sleep"):
            self.assertIn(tool, shipped)
        for credential in ("regalia.wg-boot-key", "regalia.wg-boot-conf", "regalia.boot-nft", "regalia.boot-env"):
            self.assertRegex(script, r'(?m)^[^#\n]*/%s"' % re.escape(credential))

    def test_the_service_is_given_the_local_half_by_systemd_and_can_do_nothing_else(self):
        service = self.unit("regalia-unlock.service")["Service"]
        values = dict(service)
        self.assertEqual(values["ExecStart"], "/usr/bin/regalia-unlock -config %d/regalia.unlock-config -budget 240s")
        # the one place it may write: root's, 0755, kept after the unit ends (the lease service and the daemon use it)
        self.assertEqual((values["RuntimeDirectory"], values["RuntimeDirectoryMode"], values["RuntimeDirectoryPreserve"]), ("regalia", "0755", "yes"))
        self.assertNotIn("ReadWritePaths", values)
        self.assertEqual(values["LimitCORE"], "0")
        # it holds the local half and the session's key: systemd stops it before the root filesystem takes over
        unit = dict(self.unit("regalia-unlock.service")["Unit"])
        self.assertEqual((unit["Conflicts"], unit["Before"]), ("initrd-switch-root.target shutdown.target",) * 2)
        # ... and the dracut module refuses, in check() (which stops dracut; install() does not), a unit without those lines
        with open(os.path.join(REPO, "deploy/baremetal/initrd/dracut/90regalia-unlock/module-setup.sh")) as f:
            module = f.read()
        check = module[module.index("check() {"):module.index("depends() {")]
        for line in ("RuntimeDirectory=regalia", "RuntimeDirectoryPreserve=yes", "Conflicts=" + unit["Conflicts"]):
            self.assertIn("'%s'" % line, check)
            self.assertIn(line.split("=", 1)[1], (values | unit)[line.split("=", 1)[0]])
        self.assertEqual([k for k, _ in service if k.startswith("Exec")], ["ExecStart"])      # one program, no shell around it
        self.assertEqual(values["LoadCredentialEncrypted"], "%s:/.extra/global_credentials/%s.cred" % ((unlock.LOCAL_NAME,) * 2))   # decrypted: never in plain
        self.assertEqual([v for k, v in service if k == "LoadCredential"], ["regalia.unlock-config:/.extra/global_credentials/regalia.unlock-config.cred"])
        self.assertEqual((values["CapabilityBoundingSet"], values["NoNewPrivileges"], values["ProtectSystem"]), ("", "yes", "strict"))
        self.assertEqual(values["RestrictAddressFamilies"], "AF_UNIX AF_INET AF_INET6")
        self.assertEqual((values["DevicePolicy"], sorted(v for k, v in service if k == "DeviceAllow")), ("closed", ["/dev/tpmrm0 rw", "block-* r"]))
        for forbidden in ("User", "Restart", "EnvironmentFile", "Environment"):
            self.assertNotIn(forbidden, values)


class OnSwtpm(unittest.TestCase):
    """Three software TPMs (target a, peers b and c): real EKs and AKs, real quotes, the peers' responses
    signed by their TPMs, the local contribution sealed by systemd-creds to a's TPM, and a real LUKS2
    volume. Each step is made with the native pre-root client (cmd/regalia-unlock) over TCP, and with the
    reference client. Run as root by e2e/peer-unlock-swtpm.sh, which gives a loop device in REGALIA_UNLOCK_DEVICE: the
    volume is then mapped by dm-crypt and its filesystem read. Where the tools are provisioned
    (REGALIA_EXPECT_SWTPM=1) a missing one is a failure, not a skip."""
    TOOLS = ("swtpm", "tpm2_createak", "tpm2_quote", "tpm2_nvdefine", "tpm2_pcrextend", "openssl", "systemd-creds", "cryptsetup")
    """The native client (cmd/regalia-unlock) is REGALIA_UNLOCK_BIN, or is built here with `go`."""

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
        self.pins = unlock.validate_boot_config(unlock.boot_config(self.m1, "a", "/dev/disk/by-partlabel/root", [7, 11],
                                                                   {"b": "192.0.2.2:7443", "c": "192.0.2.3:7443"}))
        for name in ("b", "c"):
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
        self.client = os.environ.get("REGALIA_UNLOCK_BIN") or self.d + "/regalia-unlock"
        if not os.environ.get("REGALIA_UNLOCK_BIN"):
            built = run(["go", "build", "-o", self.client, "./cmd/regalia-unlock"], capture_output=True, text=True, cwd=REPO)
            self.assertEqual(built.returncode, 0, "the native client did not build (or set REGALIA_UNLOCK_BIN): " + built.stderr)
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
        return unlock.unlock(self.device, unlock.BootSession("a"), self.pins, {p: self.transport(p) for p in peers},
                             unlock.tpm_quote([7, 11], tcti=self.tcti[tpm]), self.unseal(tpm), name=name, run=run)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises((m.Refused, attest.Refused)) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def reasons(self, since):
        return [e["reason"] for e in self.events[since:] if e["outcome"] == "DENY"]

    # -- the native client (cmd/regalia-unlock), against the peers served over TCP --
    def serve(self):
        """b and c answer on 127.0.0.1; returns {peer: endpoint}. `dead` is an endpoint nobody listens on."""
        endpoints = {}
        for peer in ("b", "c"):
            listener = socket.create_server(("127.0.0.1", 0))
            self.addCleanup(listener.close)
            threading.Thread(target=unlock.serve, args=(self.served[peer], listener), daemon=True).start()
            endpoints[peer] = "127.0.0.1:%d" % listener.getsockname()[1]
        closed = socket.create_server(("127.0.0.1", 0))
        self.dead = "127.0.0.1:%d" % closed.getsockname()[1]
        closed.close()
        return endpoints

    def native(self, endpoints, *flags, tpm="a", mapped=False, config_text=None):
        """One boot's run of the pre-root client on TPM `tpm`, with this test in systemd's two roles.
        As the unit's manager: unseal the local half with the TPM (LoadCredentialEncrypted=; a refusal
        means the unit never starts) and pass it in a credentials directory, with the listening socket.
        As systemd-cryptsetup: wait on that socket for the key, and open the volume with it, mapped or as a
        test. Returns (exit code, stdout, stderr, the keyslot the key opened or None)."""
        config, creds, path = self.d + "/unlock.json", tempfile.mkdtemp(dir=self.d), self.d + "/key.sock"
        with open(config, "w") as f:
            f.write(config_text or json.dumps(unlock.boot_config(self.m1, "a", self.device, [7, 11], endpoints)))
        tokens = [t for _, t in unlock.path_tokens(unlock.luks_meta(self.device, run))]
        local = unlock.unseal_local(tokens[0]["local"], tpm2_device=self.tcti[tpm], run=run)     # Refused on another TPM
        with open(os.open(creds + "/" + unlock.LOCAL_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), "wb") as f:
            f.write(local)
        if os.path.exists(path):
            os.unlink(path)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(1)
        asker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        asker.connect(path)                                           # systemd-cryptsetup, waiting for its key

        def activated():                                              # sd_listen_fds: descriptor 3, for this process
            os.dup2(listener.fileno(), 3)
            os.set_inheritable(3, True)
            os.putenv("LISTEN_PID", str(os.getpid()))
        self.session_dir = self.d + "/run-regalia"                    # stands for /run/regalia: empty at every boot
        shutil.rmtree(self.session_dir, True)
        os.makedirs(self.session_dir)
        try:
            with unittest.mock.patch.dict(os.environ, LISTEN_FDS="1", CREDENTIALS_DIRECTORY=creds):
                done = subprocess.run([self.client, "-once", "-config", config, "-tpm", "unix:" + self.tcti[tpm][len("swtpm:path="):], "-wait", "0s",
                                       "-session-dir", self.session_dir, *flags],
                                      capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL, preexec_fn=activated, close_fds=False)
            listener.close()
            asker.settimeout(5)
            key, slot = asker.recv(4096), None                         # a run that gives no key answers with nothing, at once
            self.assertEqual(bool(key), done.returncode == 0, done.stderr)
            if key:
                args = [self.device, self.name] if mapped else ["--test-passphrase", self.device]
                opened = run(["cryptsetup", "open", "--key-file", "-", "-v", *args], input=key, capture_output=True)
                self.assertEqual(opened.returncode, 0, opened.stderr)
                slot = int(re.search(rb"Key slot (\d+) unlocked", opened.stdout).group(1))
            return done.returncode, done.stdout, done.stderr, slot
        finally:
            asker.close()
            listener.close()
            shutil.rmtree(creds)

    def left_session(self, directory):
        """(SHA-256 of the session ID, SHA-256 of the public key) from the two files the client left, checked
        for their form: what regalia-sync and the KMS daemon will read."""
        with open(directory + "/boot-session") as f:
            session = f.read()
        with open(directory + "/boot-session.pub") as f:
            public = f.read()
        self.assertRegex(session, r"\A[0-9a-f]{64}\n\Z")
        self.assertRegex(public, r"\A([0-9a-f]{2}){1,512}\n\Z")
        unlock.recipient_key(bytes.fromhex(public.strip()))            # the DER RSA-3072 key of the transcript
        for name in ("boot-session", "boot-session.pub"):
            self.assertEqual(stat.S_IMODE(os.stat(directory + "/" + name).st_mode), 0o644)
        return hashlib.sha256(bytes.fromhex(session.strip())).hexdigest(), hashlib.sha256(bytes.fromhex(public.strip())).hexdigest()

    def recorded_session(self, peer):
        """What `peer`'s attestation verifier recorded for node a's current boot: (session hash, key hash)."""
        with open("%s/%s-attest.json" % (self.d, peer)) as f:
            boot = json.load(f)["nodes"]["a"]["boot"]
        return boot["session"], boot["key"]

    def marker(self):
        """The mapped volume's filesystem mounts and holds the marker; then it is closed again."""
        self.assertEqual(run(["mount", "-o", "ro", "/dev/mapper/" + self.name, self.d + "/mnt"], capture_output=True).returncode, 0)
        self.assertEqual(lt.slurp(self.d + "/mnt/marker"), b"regalia-kms root volume marker")
        self.assertEqual(run(["umount", self.d + "/mnt"], capture_output=True).returncode, 0)
        self.assertEqual(run(["cryptsetup", "close", self.name], capture_output=True).returncode, 0)

    def enrolled_disk(self):
        """A LUKS2 volume with the recovery key, a filesystem holding a marker (on a block device), and one
        peer path each from b and c. Returns the peers' endpoints."""
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
        endpoints = self.serve()

        # enrolment. The local half is sealed to a's TPM under PCR 7 only, as the PIN is today: PCR 7 does not
        # change with the boot image, so the TPM releases this half to EVERY image (the gap of #135). The
        # image is judged by the peers, whose reference values hold PCR 11 as well.
        local = os.urandom(32)
        sealed = unlock.seal_local(local, pcrs="7", tpm2_device=self.tcti["a"], run=run)
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

        return endpoints

    def test_tpm_plus_one_peer_opens_the_disk_and_a_retired_image_a_stolen_disk_or_a_revoked_node_does_not(self):
        endpoints = self.enrolled_disk()

        # PoC 7.1: a reboots on the approved image; b restores it. First the reference client, then the
        # native one, which maps the volume for real when a block device is given.
        self.reboot("a", "the approved image")
        self.assertEqual(self.unlock(), ("b", 1))
        self.reboot("a", "the approved image")
        self.assertEqual(self.native(endpoints, mapped=self.mapped),
                         (0, "regalia-unlock: gave the key of %s for keyslot 1, through b\n" % self.device, "", 1))
        # what it left for the running system: the session and key b's verifier recorded for this boot, and who opened the disk
        self.assertEqual(self.left_session(self.session_dir), self.recorded_session("b"))
        with open(self.session_dir + "/key-given-through") as f:
            self.assertEqual(f.read(), "b 1\n")
        if self.mapped:
            self.marker()
        # PoC 7.2, 7.3: b is unreachable; c restores a through its own keyslot
        self.reboot("a", "the approved image")
        code, out, err, slot = self.native(dict(endpoints, b=self.dead), mapped=self.mapped)
        self.assertEqual((code, out, slot), (0, "regalia-unlock: gave the key of %s for keyslot 2, through c\n" % self.device, 2), err)
        self.assertIn("round 1, b (path epoch 1): hello: the transport failed (no connection)", err)
        if self.mapped:
            self.marker()
        self.reboot("a", "the approved image")
        self.assertEqual(self.unlock(peers=("c",)), ("c", 2))
        # PoC 7.4: no peer; the TPM half alone opens nothing, after a bounded number of rounds
        self.reboot("a", "the approved image")
        code, out, err, slot = self.native({"b": self.dead, "c": self.dead}, "-rounds", "2")
        self.assertEqual((code, out, slot), (1, "", None), err)
        # no peer was reached, so no quote was taken and no peer holds a session of this boot: nothing is on record
        self.assertEqual(os.listdir(self.session_dir), [])
        self.assertIn("regalia-unlock: the disk stays locked: no peer helped in 2 rounds", err)
        self.assertEqual(err.count("the transport failed (no connection)"), 4)
        self.refused("the disk stays locked: no peer to ask", self.unlock, peers=())
        self.assertFalse(os.path.exists("/dev/mapper/" + self.name))
        # a boot configuration that cannot be read: refused before any peer is asked, and the socket is still answered
        since = len(self.events)
        code, out, err, slot = self.native(endpoints, config_text='{"schema": "regalia.unlock-boot/v1"}}')
        self.assertEqual((code, out, slot, self.events[since:]), (1, "", None, []), err)
        self.assertEqual(err, "regalia-unlock: the boot configuration has trailing data\n")

        # #135: a boots an image the root has retired. Its TPM releases the local half all the same; both
        # peers refuse the quote, and the disk stays locked. With each client.
        self.reboot("a", "a retired image")
        since = len(self.events)
        code, out, err, slot = self.native(endpoints, "-rounds", "1")
        self.assertEqual((code, out, slot), (1, "", None), err)
        for peer in ("b", "c"):
            self.assertIn("round 1, %s (path epoch 1): unlock: the peer refused (DENIED)" % peer, err)
        self.assertNotIn("does not release the local contribution", err)
        refusal = "the subject's attestation is refused: the quoted PCR digest is not the expected PCR values"
        self.assertEqual(self.reasons(since), [refusal] * 2)
        self.assertNotIn("PCR", err)                                  # the reason stays with the peers
        self.reboot("a", "a retired image")
        since = len(self.events)
        self.refused("the disk stays locked: b (path epoch 1): unlock: the peer refused (DENIED); c (path epoch 1): unlock: the peer refused (DENIED)", self.unlock)
        self.assertEqual(self.reasons(since), [refusal] * 2)
        self.assertFalse(os.path.exists("/dev/mapper/" + self.name))

        # PoC 7.8, 7.9: the disk in another machine (c's TPM, booted on the approved image, claiming to be a)
        self.reboot("c", "the approved image")
        since = len(self.events)
        self.refused("the TPM does not release the local contribution", self.native, endpoints, tpm="c")   # systemd never starts the client
        self.assertEqual(self.events[since:], [])                     # without the local half no peer is even asked
        self.refused("unlock: the peer refused (DENIED)", unlock.ask, unlock.BootSession("a"), self.pins["b"], 1, self.transport("b"),
                     unlock.tpm_quote([7, 11], tcti=self.tcti["c"]), run)
        self.assertIn("the subject's attestation is refused", self.reasons(since)[-1])

        # the approved image again: restored. Then a is reported stolen: the revocation key alone, no root ceremony.
        self.reboot("a", "the approved image")
        self.assertEqual(self.native(endpoints)[::3], (0, 1))
        m2 = self.manifest(self.m1, a="REVOKED_STOLEN")
        for peer in ("b", "c"):
            self.stores[peer].commit(rt.sign(m2, hbt.REVOKE, "revocation"))
            self.fresh[peer].accept(hbt.beat(m2, 2, issued=self.now), m2)
        self.reboot("a", "the approved image")
        since = len(self.events)
        code, out, err, slot = self.native(endpoints, "-rounds", "1")
        self.assertEqual((code, out, slot), (1, "", None), err)
        for peer in ("b", "c"):
            self.assertIn("round 1, %s (path epoch 1): hello: the peer refused (DENIED)" % peer, err)
        self.assertEqual(self.reasons(since), ["a may not be unlocked under epoch 2"] * 2)
        self.assertEqual([self.contributions[p].epochs("a") for p in ("b", "c")], [[], []])       # and the peers' halves are gone
        # the recovery key still opens the volume: the manual path of a total outage (#77) does not go through a peer
        self.assertTrue(unlock.opens(self.device, 0, RECOVERY, run))


    @unittest.skipUnless(os.environ.get("REGALIA_UNLOCK_SYSTEMD") == "1", "needs a running systemd and a block device (e2e/peer-unlock-swtpm.sh)")
    def test_systemd_cryptsetup_takes_the_key_from_the_socket_and_gets_nothing_when_no_peer_helps(self):
        """The shipped units, started by the real systemd, and the real systemd-cryptsetup as the one that
        asks for the key: the crypttab key file is the socket. The only changes are in a drop-in, for what a
        test machine lacks: the software TPM, a credential that is passed plain (systemd itself can unseal
        only with the machine's own TPM), the path of the binary under test, and a read-only view of the
        test's directory."""
        self.assertTrue(self.mapped, "REGALIA_UNLOCK_DEVICE must name a block device")
        endpoints = self.enrolled_disk()
        cryptsetup = shutil.which("systemd-cryptsetup", path="/usr/lib/systemd:/usr/bin:/lib/systemd")
        self.assertTrue(cryptsetup, "systemd-cryptsetup is expected here")
        units, source = "/run/systemd/system", os.path.join(REPO, "deploy", "baremetal", "initrd")
        binary = "/usr/local/bin/regalia-unlock-e2e-%d" % os.getpid()
        inside = "/run/regalia-e2e-%d" % os.getpid()                  # where the unit sees the test's directory
        installed = [binary, units + "/regalia-unlock.socket", units + "/regalia-unlock.service", units + "/regalia-unlock.service.d", inside,
                     units + "/regalia-unlock-core.socket", units + "/regalia-unlock-relay.service", units + "/regalia-unlock-relay.service.d"]
        shipped = ("regalia-unlock.socket", "regalia-unlock-relay.service", "regalia-unlock-core.socket", "regalia-unlock.service")

        def remove():
            run(["systemctl", "stop", *shipped], capture_output=True)
            for path in installed + ([] if had_runtime_directory else ["/run/regalia"]):
                shutil.rmtree(path, True) if os.path.isdir(path) else os.path.exists(path) and os.unlink(path)
            run(["systemctl", "daemon-reload"], capture_output=True)
            run(["systemctl", "reset-failed", *shipped], capture_output=True)
        # The unit writes this boot's session into /run/regalia. On a machine that HAS one (a KMS host, a bench
        # host with the lease service) that would replace a live record: refused, before anything is installed.
        self.assertFalse(os.path.exists("/run/regalia"), "/run/regalia exists: this test must not run on a host that uses it")
        had_runtime_directory = False
        self.addCleanup(remove)
        shutil.copy(self.client, binary)
        os.chmod(binary, 0o700)
        for name in shipped:
            shutil.copy(os.path.join(source, name), units)
        os.mkdir(installed[3])
        os.mkdir(installed[7])
        relay_wait = 20
        with open(installed[7] + "/e2e.conf", "w") as f:                 # the binary under test, and a shorter bound
            f.write("[Service]\nExecStart=\nExecStart=%s -relay /run/regalia-unlock-core/core.sock -relay-wait %ds\n" % (binary, relay_wait))
        config, local = self.d + "/unlock.json", self.d + "/local"

        def boot(endpoints):
            """A new boot: the client of the last one is gone with its session, /run/regalia starts empty, and
            this boot's configuration and unsealed local half are what the next client will read."""
            run(["systemctl", "stop", "regalia-unlock.service"], capture_output=True)
            run(["systemctl", "reset-failed", "regalia-unlock.service"], capture_output=True)
            for name in ("boot-session", "boot-session.pub", "key-given-through"):
                if os.path.exists("/run/regalia/" + name):
                    os.unlink("/run/regalia/" + name)
            with open(config, "w") as f:
                json.dump(unlock.boot_config(self.m1, "a", self.device, [7, 11], endpoints), f)
            sealed = [t for _, t in unlock.path_tokens(unlock.luks_meta(self.device, run))][0]["local"]
            with open(os.open(local, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400), "wb") as f:
                f.write(unlock.unseal_local(sealed, tpm2_device=self.tcti["a"], run=run))
        with open(installed[3] + "/e2e.conf", "w") as f:
            f.write("[Service]\nExecStart=\nExecStart=%s -config %s/unlock.json -tpm unix:%s/a.sock -rounds 2 -wait 0s\n"
                    "LoadCredentialEncrypted=\nLoadCredential=\nLoadCredential=%s:%s\nBindReadOnlyPaths=%s:%s\n"
                    % (binary, inside, inside, unlock.LOCAL_NAME, local, self.d, inside))
        self.assertEqual(run(["systemctl", "daemon-reload"], capture_output=True).returncode, 0)
        started = run(["systemctl", "start", "regalia-unlock.socket", "regalia-unlock-core.socket"], capture_output=True, text=True)
        self.assertEqual(started.returncode, 0, started.stderr)
        self.assertTrue(stat.S_ISSOCK(os.stat(unlock.KEY_SOCKET).st_mode))
        self.assertEqual(stat.S_IMODE(os.stat(unlock.KEY_SOCKET).st_mode), 0o600)

        def attach():
            """systemd-cryptsetup, as crypttab would run it: the key file is the socket. No console to ask at."""
            started = time.monotonic()
            done = run([cryptsetup, "attach", self.name, self.device, unlock.KEY_SOCKET, "luks,headless=true,tries=1"],
                       capture_output=True, text=True, timeout=180)
            return done.returncode, time.monotonic() - started, done.stderr

        def state(unit, what):
            return run(["systemctl", "show", unit, "-p", what, "--value"], capture_output=True, text=True).stdout.strip()

        # 1  a reboots on the approved image: systemd starts the client on systemd-cryptsetup's connection, a
        #    peer helps, and systemd-cryptsetup maps the volume with the key it read from the socket
        self.reboot("a", "the approved image")
        boot(endpoints)
        code, took, err = attach()
        self.assertEqual(code, 0, err)
        self.marker()
        journal = run(["journalctl", "-u", "regalia-unlock.service", "-o", "cat", "--since", "-2min", "--no-pager"], capture_output=True, text=True).stdout
        self.assertIn("gave the key of %s for keyslot 1, through b" % self.device, journal)
        # the client stays, for the rest of this boot: it holds this boot's one session
        self.assertEqual(state("regalia-unlock.service", "ActiveState"), "active")
        # /run/regalia is root's and nobody else's to write, and holds the session b recorded
        directory = os.stat("/run/regalia")
        self.assertEqual((directory.st_uid, directory.st_gid, stat.S_IMODE(directory.st_mode)), (0, 0, 0o755))
        self.assertEqual(self.left_session("/run/regalia"), self.recorded_session("b"))
        with open("/run/regalia/key-given-through") as f:
            self.assertEqual(f.read(), "b 1\n")
        # the unit stopped (as at switch-root): the directory and its files remain, the process does not
        self.assertEqual(run(["systemctl", "stop", "regalia-unlock.service"], capture_output=True).returncode, 0)
        self.assertEqual((state("regalia-unlock.service", "ActiveState"), self.left_session("/run/regalia")), ("inactive", self.recorded_session("b")))

        # 2  no peer answers: systemd-cryptsetup gets nothing, gives up within a bound, maps nothing; the client
        #    stays, and nothing is on record (no quote was taken, so no peer holds a session of this boot)
        self.reboot("a", "the approved image")
        boot({"b": self.dead, "c": self.dead})
        code, took, err = attach()
        self.assertNotEqual(code, 0)
        self.assertLess(took, 60)
        self.assertFalse(os.path.exists("/dev/mapper/" + self.name))
        self.assertEqual((state("regalia-unlock.socket", "ActiveState"), state("regalia-unlock.service", "ActiveState")), ("active", "active"))
        self.assertEqual(os.listdir("/run/regalia"), [])
        self.systemd_refusal = (code, round(took, 1), err.strip().splitlines()[-1] if err.strip() else "")
        print("\nsystemd-cryptsetup with no key from the socket: exit %d after %.1fs: %s" % self.systemd_refusal, file=sys.stderr)

        # 3  THE CASE ONE SESSION PER BOOT EXISTS FOR. Both peers VERIFY this boot's quote (and so record its
        #    session) but give nothing: their contributions are out of reach for a moment. systemd-cryptsetup
        #    gets nothing. Then they can give again, and systemd-cryptsetup asks again IN THE SAME BOOT: the same
        #    process answers under the same session, both peers accept it, and the volume opens. A client that
        #    made a new session for the second attempt would have been refused by both.
        self.reboot("a", "the approved image")
        boot(endpoints)
        held = {p: self.served[p].contributions for p in ("b", "c")}
        for peer in ("b", "c"):
            self.served[peer].contributions = unlock.Contributions(self.d + "/none-%s.json" % peer)
        since = len(self.events)
        code, took, err = attach()
        self.assertNotEqual(code, 0)
        self.assertEqual([e["reason"] for e in self.events[since:] if e["outcome"] == "DENY"],
                         ["this peer holds no contribution for a at path epoch 1"] * 4)        # verified, then refused: 2 rounds x 2 peers
        recorded, pid = self.left_session("/run/regalia"), state("regalia-unlock.service", "MainPID")
        self.assertEqual(recorded, self.recorded_session("b"))
        self.assertEqual(recorded, self.recorded_session("c"))
        for peer in ("b", "c"):
            self.served[peer].contributions = held[peer]
        code, took, err = attach()
        self.assertEqual(code, 0, err)
        self.marker()
        self.assertEqual((state("regalia-unlock.service", "MainPID"), self.left_session("/run/regalia")), (pid, recorded))

        # 3b the client is started again IN THAT BOOT (a crash, an operator's restart): its session would be a
        #    second one. It finds the first on record, asks no peer, and gives nothing; the record stays the
        #    session both peers hold.
        self.assertEqual(run(["systemctl", "stop", "regalia-unlock.service"], capture_output=True).returncode, 0)
        since = len(self.events)
        code, took, err = attach()
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists("/dev/mapper/" + self.name))
        self.assertNotEqual(state("regalia-unlock.service", "MainPID"), pid)
        self.assertEqual((len(self.events), self.left_session("/run/regalia")), (since, recorded))
        journal = run(["journalctl", "-u", "regalia-unlock.service", "-o", "cat", "--since", "-1min", "--no-pager"], capture_output=True, text=True).stdout
        self.assertIn("an earlier unlock client of this boot presented another session", journal)

        # 4  a retired image: systemd-cryptsetup gets nothing, and the peers' refusal is in their audit
        self.reboot("a", "a retired image")
        boot(endpoints)
        since = len(self.events)
        code, took, err = attach()
        self.assertNotEqual(code, 0)
        self.assertFalse(os.path.exists("/dev/mapper/" + self.name))
        self.assertEqual(self.reasons(since), ["the subject's attestation is refused: the quoted PCR digest is not the expected PCR values"] * 4)

        # 5-8  THE REAL CLIENT FAILS, in four ways, and the console must still be asked: the relay on the key socket
        #      starts whatever happens to the real client and gives nothing, within its bound. (Before the relay,
        #      a real client that could not start left systemd-cryptsetup with a reset connection, and it failed
        #      without asking for the recovery key.)
        failing = installed[3] + "/zz-failing.conf"                     # after e2e.conf, which it overrides
        garbage = self.d + "/not-a-sealed-credential"
        with open(garbage, "w") as f:
            f.write("bm90IGEgY3JlZGVudGlhbA==\n")
        crash = ("import os, socket; s = socket.socket(fileno=3); c, _ = s.accept(); c.send(b'k' * 20); os._exit(1)")
        for label, conf, said in (
                ("a client that hangs", "[Service]\nExecStart=\nExecStart=/bin/sleep 600\n", "no answer within %ds" % relay_wait),
                ("a client that crashes mid-answer", "[Service]\nExecStart=\nExecStart=/usr/bin/python3 -c \"%s\"\n" % crash, "not one whole key"),
                ("a sealed credential that does not decrypt",
                 "[Service]\nLoadCredential=\nLoadCredentialEncrypted=\nLoadCredentialEncrypted=%s:%s\n" % (unlock.LOCAL_NAME, garbage), None),
                ("a credential file that is absent",
                 "[Service]\nLoadCredential=\nLoadCredential=%s:%s/absent\n" % (unlock.LOCAL_NAME, self.d), None)):
            with self.subTest(label):
                run(["systemctl", "stop", "regalia-unlock.service"], capture_output=True)
                with open(failing, "w") as f:
                    f.write(conf)
                self.assertEqual(run(["systemctl", "daemon-reload"], capture_output=True).returncode, 0)
                run(["systemctl", "reset-failed", *shipped], capture_output=True)
                self.assertEqual(run(["systemctl", "restart", "regalia-unlock-core.socket"], capture_output=True).returncode, 0)
                since_time = time.strftime("%Y-%m-%d %H:%M:%S")
                code, took, err = attach()
                self.assertNotEqual(code, 0)
                self.assertFalse(os.path.exists("/dev/mapper/" + self.name))
                self.assertIn("Failed to activate with key file", err)        # a key that did not fit: the console would ask
                self.assertNotIn("Connection reset", err)
                self.assertLess(took, relay_wait + 15)
                relayed = run(["journalctl", "-u", "regalia-unlock-relay.service", "-o", "cat", "--since", since_time, "--no-pager"],
                              capture_output=True, text=True).stdout
                self.assertIn("nothing is given, and the console asks for the recovery key", relayed)
                if said:
                    self.assertIn(said, relayed)
                self.assertEqual(state("regalia-unlock-relay.service", "ActiveState"), "active")
                print("%s: systemd-cryptsetup got nothing after %.1fs" % (label, took), file=sys.stderr)
        os.unlink(failing)


if __name__ == "__main__":
    unittest.main()
