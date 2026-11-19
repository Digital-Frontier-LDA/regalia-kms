"""The owner as the unlock peer of a single-node host (regalia-kms-dx7.5; docs/design/single-node.md 4.5, decision Q1):
deploy/baremetal/ownerunlock.py, the single-node boot configuration of unlock.py and cmd/regalia-unlock, the owner path of
enrolment, and owner.py's two commands.

  * the boot configuration: the owner is a peer only under single-node; multi-node keeps 1 to 8 node peers;
  * the exchange with software keys (lease tests' P-256 AKs, Ed25519 owner keys): the owner gives its contribution only to
    the manifest's one node, ACTIVE, on an image the measurements the manifest commits to still list; the node takes the
    response only signed by an owner key its boot configuration holds;
  * a real LUKS2 header in a file: one owner path beside the recovery keyslot, opened through the owner, never by the TPM's
    half alone, and the contribution written nowhere on the node;
  * OnSwtpm: the rehearsal on a software TPM, systemd-creds and a real LUKS2 volume, the owner key on SoftHSM, with the
    native client (cmd/regalia-unlock) and the reference one (e2e/peer-unlock-swtpm.sh runs it as root).

The owner cards' OpenPGP envelope is stood in for here (gpg is not run: a real card's decryption is dx7.13's hardware run)."""
import base64
import contextlib
import copy
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import unittest.mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import attest, enrol, enrolpeer, measurements, owner, ownerunlock, unlock
from deploy.baremetal import membership as m
from deploy.baremetal import node as node_module
import tests.test_baremetal_enrol_paths as ept
import tests.test_baremetal_lease as lt
from tests.test_baremetal_membership_v4 import OWNER_KEYS, STRANGER, pub, typed
from tests.test_baremetal_membership_v5 import MULTI, manifest5, one, single5
from tests.test_baremetal_membership_v4 import nodes4
from tests.test_baremetal_unlock import CRYPTSETUP, PATH, RECOVERY, REPO, KeyPool, fake_seal, fake_unseal, run

VECTOR = os.path.join(REPO, "tests", "vectors", "unlock-owner-v1.json")
OWNER_ENDPOINT = "192.0.2.9:7443"


def measured(pcr7="00" * 32, label="current", **more):
    """A measurement document that approves node a's image with these values (the lease tests' fake quote: PCR 7 zero)."""
    pcrs = dict({"7": pcr7}, **more)
    return {"schema": measurements.SCHEMA, "name": "approved-" + label,
            "nodes": {"a": {"accepted": [{"label": label, "tpm_firmware_version": "0" * 16, "pcrs": pcrs}]}}}


class SoftOwner:
    """An owner key in software (Ed25519), as p11sign.Pkcs11Signer(alg="ed25519") answers: public() and sign(message)."""

    def __init__(self, key):
        self.key, self.signed = key, []

    def public(self):
        return pub(self.key)

    def sign(self, message):
        self.signed.append(message)
        return self.key.sign(message)


class BootConfiguration(unittest.TestCase):
    """unlock.boot_config and validate_boot_config: the owner is a peer only under single-node."""

    def setUp(self):
        self.single = single5(1, "")
        self.multi = manifest5(1, "", nodes4(), MULTI)

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_a_single_node_host_s_one_peer_is_the_owner_with_the_manifest_s_owner_keys(self):
        config = unlock.boot_config(self.single, "a", "/dev/disk/by-partlabel/root", [11, 7], {"owner": OWNER_ENDPOINT, "b": "192.0.2.2:7443"})
        self.assertEqual(config, {"schema": unlock.BOOT_SINGLE_SCHEMA, "topology": m.SINGLE_NODE, "node_id": "a",
                                  "device": "/dev/disk/by-partlabel/root", "pcrs": [7, 11], "peers": [{"node_id": "owner", "endpoint": OWNER_ENDPOINT}],
                                  "owner_keys": [{"alg": "ed25519", "key": pub(k)} for k in OWNER_KEYS]})
        pins = unlock.validate_boot_config(json.loads(json.dumps(config)))
        self.assertEqual(list(pins), ["owner"])
        self.assertEqual(pins["owner"]["owner_keys"], config["owner_keys"])
        self.refused("a single-node host's one peer is the owner: no endpoint is given for it", unlock.boot_config, self.single, "a",
                     "/dev/x", [7], {"b": "192.0.2.2:7443"})
        p256_only = dict(self.single, owner_keys=[typed(STRANGER)])
        self.refused("the manifest names no ed25519 owner key", unlock.boot_config, p256_only, "a", "/dev/x", [7], {"owner": OWNER_ENDPOINT})

    def test_a_multi_node_configuration_keeps_one_to_eight_node_peers_and_never_the_owner(self):
        endpoints = {"b": "192.0.2.2:7443", "c": "192.0.2.3:7443", "owner": OWNER_ENDPOINT}
        config = unlock.boot_config(self.multi, "a", "/dev/x", [7], endpoints)
        self.assertEqual((config["schema"], sorted(config), [p["node_id"] for p in config["peers"]]),
                         (unlock.BOOT_SCHEMA, sorted(unlock.BOOT_KEYS), ["b", "c"]))
        pin = dict(config["peers"][0], node_id="owner")
        self.refused("the owner is a peer only in a single-node boot configuration", unlock.validate_boot_config, dict(config, peers=[pin]))
        self.refused("peers must list 1 to 8 peers", unlock.validate_boot_config, dict(config, peers=[]))
        many = [dict(config["peers"][0], node_id="n%d" % i) for i in range(9)]
        self.refused("peers must list 1 to 8 peers", unlock.validate_boot_config, dict(config, peers=many))
        self.refused("boot configuration fields mismatch", unlock.validate_boot_config, dict(config, owner_keys=[]))
        self.refused("the owner is a peer only", unlock.ask, unlock.BootSession.__new__(unlock.BootSession), pin, 1, None, None)

    def test_a_single_node_configuration_is_refused_unless_exact(self):
        good = unlock.boot_config(self.single, "a", "/dev/x", [7], {"owner": OWNER_ENDPOINT})
        key = good["owner_keys"][0]
        for reason, change in (
                ("is for the single-node topology", lambda c: c.update(topology="multi-node")),
                ("lists exactly one peer, the owner", lambda c: c.update(peers=c["peers"] * 2)),
                ("lists exactly one peer, the owner", lambda c: c.update(peers=[])),
                ("the one peer of a single-node boot configuration is owner", lambda c: c["peers"][0].update(node_id="b")),
                ("the owner peer fields mismatch", lambda c: c["peers"][0].update(ek_name="000b" + "11" * 32)),
                ("peer.endpoint must be host:port", lambda c: c["peers"][0].update(endpoint="owner.boot")),
                ("owner_keys must list 1 to 8 keys", lambda c: c.update(owner_keys=[])),
                ("owner_keys must list 1 to 8 keys", lambda c: c.update(owner_keys=[dict(key, key="%064x" % i) for i in range(9)])),
                ("owner_keys[1] is listed twice", lambda c: c.update(owner_keys=[key, key])),
                ("owner_keys[0] must be an ed25519 key", lambda c: c.update(owner_keys=[dict(key, alg="ecdsa-p256")])),
                ("owner_keys[0].key must be 64 lowercase hex", lambda c: c.update(owner_keys=[dict(key, key=key["key"].upper())])),
                ("node_id owner is the owner's name", lambda c: c.update(node_id="owner")),
                ("boot configuration fields mismatch", lambda c: c.pop("owner_keys")),
                ("boot configuration fields mismatch", lambda c: c.update(extra=1))):
            with self.subTest(reason):
                config = copy.deepcopy(good)
                change(config)
                self.refused(reason, unlock.validate_boot_config, config)


class Case(lt.Case):
    """A single-node manifest at epoch 1 whose node a is the lease tests' software TPM, under the measurement document
    measured(); the owner's verifier and its OwnerPeer, with an owner path minted through enrolment."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        pool = unittest.mock.patch.object(unlock.rsa, "generate_private_key", KeyPool())
        pool.start()
        self.addCleanup(pool.stop)
        self.events, self.wire, self.boots = [], [], 0
        self.doc = measured()
        self.m1 = self.single(1, "")
        self.signer = SoftOwner(OWNER_KEYS[0])
        self.attester = ownerunlock.verifier(self.m1, self.doc, self.d + "/attest.json")      # owner.py's --state is self.d
        self.epoch, self.secret, self.plain = self.enrolled()
        self.owner = ownerunlock.OwnerPeer(self.m1, self.attester, ownerunlock.read_plaintext(self.plain), self.signer, self.events.append)
        self.pins = unlock.validate_boot_config(unlock.boot_config(self.m1, "a", "/dev/disk/by-partlabel/root", [7], {"owner": OWNER_ENDPOINT}))
        self.session = self.boot()

    def single(self, epoch, prev, state="ACTIVE", document=None):
        node = dict(one("a", state), ek_name=self.keys["a"].ek_name, ak_name=self.keys["a"].ak_name)
        return single5(epoch, prev, [node], policy_version=measurements.version(document or self.doc))

    def enrolled(self, manifest=None, attester=None):
        """The owner path of node a through enrolment: (path epoch, contribution, the owner cards' plaintext)."""
        enrolment = unlock.Enrolment("a")
        request = ownerunlock.path_request("a", enrolment, self.keys["a"].ak_public)
        wrapped, plain = ownerunlock.contribute(manifest or self.m1, json.loads(json.dumps(request)), enrolment.fingerprint,
                                                attester or self.attester, os.urandom, ownerunlock.IssuedPaths(self.d + "/" + ownerunlock.ISSUED_FILE))
        epoch, secret = enrolment.open(json.loads(json.dumps(wrapped)), "owner")
        return epoch, secret, plain

    def boot(self, node="a"):
        self.boots += 1
        return unlock.BootSession(node)

    def transport(self, peer=None, change=None):
        peer = peer or self.owner

        def send(raw):
            reply = peer.handle(raw)
            if change is not None and "response" in reply:
                reply = change(reply)
            out = json.dumps(reply).encode()
            self.wire.append((raw, out))
            return out
        return send

    def quote(self, signed_by="a", reset=None):
        def quote(node, epoch, session_id, ephemeral_public, nonce):
            signed = self.keys[signed_by].signer(ek_name=self.keys["a"].ek_name, reset=reset or self.boots)(
                attest.qualifying_data(node, epoch, session_id, ephemeral_public, nonce))
            return bytes.fromhex(signed["quote"]), bytes.fromhex(signed["sig"])
        return quote

    def ask(self, session=None, pin=None, epoch=None, transport=None, **kw):
        return unlock.ask(session or self.session, pin or self.pins["owner"], epoch or self.epoch, transport or self.transport(),
                          self.quote(**kw), run=run)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises((m.Refused, attest.Refused)) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def denied(self, why):
        self.assertEqual(self.events[-1]["outcome"], "DENY")
        self.assertIn(why, self.events[-1]["reason"])


class Exchange(Case):
    def test_the_owner_gives_its_contribution_to_the_attested_node_signed_by_an_owner_key(self):
        self.assertEqual(self.epoch, 1)                                   # the manifest's epoch at enrolment
        self.assertEqual(self.ask(), self.secret)
        self.assertTrue(self.session.consumed)
        self.assertEqual(self.owner.signed, 1)
        self.assertEqual([(e["event"], e["subject"], e["peer"], e["outcome"]) for e in self.events],
                         [("unlock-challenge", "a", "owner", "ALLOW"), ("unlock", "a", "owner", "ALLOW")])
        reply = json.loads(self.wire[-1][1])
        self.assertEqual((reply["response"]["peer_id"], reply["signature"]["alg"], reply["signature"]["key"]),
                         ("owner", "ed25519", pub(OWNER_KEYS[0])))
        self.assertEqual(self.signer.signed, [unlock.owner_signed_message(reply["response"])])
        crossed = b"".join(raw + out for raw, out in self.wire)
        for encoded in (self.secret, self.secret.hex().encode(), base64.b64encode(self.secret)):
            self.assertNotIn(encoded, crossed)

    def test_enrolment_judges_the_request_before_anything_is_minted(self):
        enrolment = unlock.Enrolment("a")
        good = ownerunlock.path_request("a", enrolment, self.keys["a"].ak_public)
        never = lambda n: self.fail("a contribution was minted for a refused request")      # noqa: E731
        multi = dict(manifest5(1, "", nodes4(), MULTI), policy_version=self.m1["policy_version"])
        for i, (reason, manifest, request, fingerprint) in enumerate((
                ("the enrolment key is not the one whose fingerprint was given", self.m1, good, "00" * 32),
                ("the AK offered is not the one the manifest names", self.m1, dict(good, ak_public=self.keys["b"].ak_public.hex()), enrolment.fingerprint),
                ("only under the single-node profile", multi, good, enrolment.fingerprint),
                ("is MAINTENANCE under epoch 1, not ACTIVE", self.single(1, "", "MAINTENANCE"), good, enrolment.fingerprint),
                ("is not a node of the manifest", self.m1, dict(good, target="b"), enrolment.fingerprint),
                ("the path request fields mismatch", self.m1, dict(good, extra=1), enrolment.fingerprint),
                ("the path request is not a regalia.owner-path-request/v1", self.m1, dict(good, schema="x"), enrolment.fingerprint))):
            with self.subTest(reason):
                attester = ownerunlock.verifier(self.m1, self.doc, self.d + "/fresh-%d.json" % i)
                self.refused(reason, ownerunlock.contribute, manifest, request, fingerprint, attester, never,
                             ownerunlock.IssuedPaths(self.d + "/refused-paths.json"))
        self.assertFalse(os.path.exists(self.d + "/refused-paths.json"), "a refused request burns no path epoch")
        # the plaintext is exact: one canonical line for one target and path epoch
        self.assertEqual(ownerunlock.read_plaintext(self.plain), ("a", 1, self.secret))
        body = json.loads(self.plain)
        for reason, raw in (("is not one line", self.plain[:-1]), ("is not one line", b""),
                            ("not in canonical form", json.dumps(body, indent=1).encode() + b"\n"),
                            ("the decrypted contribution fields mismatch", m.canonical(dict(body, extra=1)) + b"\n"),
                            ("is not a regalia.owner-contribution/v1", m.canonical(dict(body, schema="x")) + b"\n")):
            with self.subTest(reason):
                self.refused(reason, ownerunlock.read_plaintext, raw)

    def test_a_node_that_is_not_active_is_refused(self):
        for state in ("MAINTENANCE", "QUARANTINED"):
            with self.subTest(state):
                held = self.single(2, m.digest(self.m1), state)
                self.refused("a is %s under epoch 2, not ACTIVE: the owner does not unlock it" % state,
                             ownerunlock.OwnerPeer, held, self.attester, ownerunlock.read_plaintext(self.plain), self.signer, self.events.append)
                # and the owner answering under it (its manifest changed since it started) denies the hello
                self.owner.manifest = held
                self.refused("the peer refused (DENIED)", self.ask, session=self.boot())
                self.denied("a is %s under epoch 2, not ACTIVE" % state)
        self.assertFalse(self.session.consumed)

    def test_an_image_the_manifest_no_longer_lists_is_refused(self):
        # epoch 2 commits to a document that approves another image only: the node still runs the old one
        newer = measured(pcr7="11" * 32, label="next")
        m2 = self.single(2, m.digest(self.m1), document=newer)
        attester = ownerunlock.verifier(m2, newer, self.d + "/attest.json")
        peer = ownerunlock.OwnerPeer(m2, attester, ownerunlock.read_plaintext(self.plain), self.signer, self.events.append)
        self.refused("the peer refused (DENIED)", self.ask, transport=self.transport(peer))
        self.denied("the quoted PCR digest is not the expected PCR values")
        self.assertFalse(self.session.consumed)
        # the old document is not taken in its place: the manifest commits to the newer one by digest
        self.refused("it is not the one the root approved", ownerunlock.verifier, m2, self.doc, self.d + "/attest.json")

    def test_the_owner_answers_only_its_node_its_path_epoch_and_its_tpm(self):
        self.refused("the peer refused (DENIED)", self.ask, epoch=2)
        self.denied("the node asks for path epoch 2; the contribution given is for path epoch 1")
        self.refused("the peer refused (DENIED)", self.ask, session=self.boot(), signed_by="b")
        self.denied("signature")
        self.refused("the peer refused (DENIED)", self.ask, session=self.boot("b"))
        self.denied("the contribution this tool holds is for a, not b")
        self.assertEqual(self.owner.signed, 0)
        self.assertEqual(self.ask(session=self.boot()), self.secret)

    def test_a_repair_gets_a_new_path_epoch_and_the_old_envelope_is_refused_unsigned(self):
        """A second contribution for the same node under the same manifest (its keyslot was repaired) is at a new path
        epoch: the old envelope then names an epoch the node's new token does not ask for, and nothing is signed for it."""
        epoch, secret, plain = self.enrolled()
        self.assertEqual((self.epoch, epoch), (1, 2))
        self.assertNotEqual(secret, self.secret)
        self.assertEqual(ownerunlock.read_plaintext(plain)[1], 2)
        self.refused("the peer refused (DENIED)", self.ask, epoch=2)                     # the owner still holds the OLD envelope
        self.denied("the node asks for path epoch 2; the contribution given is for path epoch 1")
        self.assertEqual(self.signer.signed, [])
        fresh = ownerunlock.OwnerPeer(self.m1, self.attester, ownerunlock.read_plaintext(plain), self.signer, self.events.append)
        self.assertEqual(self.ask(session=self.boot(), epoch=2, transport=self.transport(fresh)), secret)
        with open(self.d + "/" + ownerunlock.ISSUED_FILE) as f:
            self.assertEqual(json.load(f)["targets"], {"a": [1, 2]})

    def test_the_owner_key_must_be_one_of_the_manifest_s(self):
        self.refused("is not one of the manifest's ed25519 owner_keys", ownerunlock.OwnerPeer, self.m1, self.attester,
                     ownerunlock.read_plaintext(self.plain), SoftOwner(Ed25519PrivateKey.generate()), self.events.append)
        self.refused("only under the single-node profile", ownerunlock.OwnerPeer, dict(manifest5(1, "", nodes4(), MULTI)), self.attester,
                     ownerunlock.read_plaintext(self.plain), self.signer, self.events.append)

    def test_the_node_takes_a_response_only_signed_by_an_owner_key_its_configuration_holds(self):
        stranger = Ed25519PrivateKey.generate()

        def resigned(key, **fields):
            def change(reply):
                reply["response"].update(fields)
                reply["signature"] = {"alg": "ed25519", "key": pub(key), "sig": key.sign(unlock.owner_signed_message(reply["response"])).hex()}
                return reply
            return change

        def edited(**fields):
            def change(reply):
                reply["response"].update(fields)
                return reply
            return change
        cases = (
            ("not signed by one of the owner_keys the boot configuration holds", resigned(stranger)),
            ("the owner's signature does not verify over this response", edited(manifest_digest="ee" * 32)),
            ("the owner's response is signed with ed25519", lambda r: dict(r, signature=dict(r["signature"], alg="ecdsa-p256"))),
            ("signature fields mismatch", lambda r: dict(r, signature={"ak_public": "00", "quote": "00", "sig": "00"})),
            ("signature.sig must be 128 lowercase hex", lambda r: dict(r, signature=dict(r["signature"], sig="ZZ"))),
            ("the response is from b, not from owner", resigned(OWNER_KEYS[0], peer_id="b")))
        for reason, change in cases:
            with self.subTest(reason):
                session = self.boot()
                self.refused(reason, self.ask, session=session, transport=self.transport(change=change))
                self.assertFalse(session.consumed)
        # an owner key's signature is never a TPM's: a node pin of a multi-node configuration refuses it
        node_pin = {"node_id": "b", "endpoint": "192.0.2.2:7443", "ek_name": self.keys["b"].ek_name, "ak_name": self.keys["b"].ak_name}
        owner_signed = {"response": {"schema": unlock.RESPONSE_SCHEMA}, "signature": {"alg": "ed25519", "key": pub(OWNER_KEYS[0]), "sig": "00" * 64}}
        self.refused("signature fields mismatch", unlock.verify_signature, owner_signed, node_pin)
        session = self.boot()
        # a pin that names the owner without the single-node configuration's keys is refused before anything is sent
        self.refused("the owner is a peer only in a single-node boot configuration", self.ask, session=session,
                     pin={"node_id": "owner", "endpoint": OWNER_ENDPOINT, "ek_name": node_pin["ek_name"], "ak_name": node_pin["ak_name"]})

    def test_the_owner_signature_agrees_with_the_go_client_on_the_published_vector(self):
        with open(VECTOR) as f:
            vector = json.load(f)
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["seed"]))
        self.assertEqual((pub(key), vector["domain"].encode()), (vector["public"], unlock.OWNER_RESPONSE_DOMAIN))
        unlock.validate_response(vector["response"])
        self.assertEqual(m.canonical(vector["response"]).decode(), vector["canonical"])
        self.assertEqual(key.sign(unlock.owner_signed_message(vector["response"])).hex(), vector["signature"])
        unlock.verify_owner_signature({"response": vector["response"], "signature": {"alg": "ed25519", "key": vector["public"], "sig": vector["signature"]}},
                                      [{"alg": "ed25519", "key": vector["public"]}])


@unittest.skipUnless(CRYPTSETUP, "needs cryptsetup")
class Disk(Case):
    """A real LUKS2 header in a file: the recovery keyslot and one owner path, opened through the owner only."""

    def setUp(self):
        super().setUp()
        self.disk = os.path.join(self.d, "node", "disk.img")
        os.makedirs(os.path.dirname(self.disk))
        with open(self.disk, "wb") as f:
            f.truncate(32 * 1024 * 1024)
        self.cs(["luksFormat", "--type", "luks2", "--batch-mode", *unlock.PBKDF, "--key-file", "-", self.disk], RECOVERY)
        self.cs(["token", "import", "--json-file", "-", self.disk], b'{"type":"systemd-recovery","keyslots":["0"]}')
        self.local = os.urandom(32)
        self.given = []

    def cs(self, args, stdin=None):
        done = run(["cryptsetup", *args], input=stdin, capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    def exchange(self, request, fingerprint):
        """The owner's machine: owner.contribute's judgement and mint, with the cards' envelope kept in this test's memory."""
        attester = ownerunlock.verifier(self.m1, self.doc, self.d + "/attest.json")
        wrapped, plain = ownerunlock.contribute(self.m1, json.loads(json.dumps(request)), fingerprint, attester, os.urandom,
                                                ownerunlock.IssuedPaths(self.d + "/disk-owner-paths.json"))
        self.given.append(ownerunlock.read_plaintext(plain))
        return json.loads(json.dumps(wrapped))

    def enrol(self):
        return enrolpeer.request_owner_path(self.m1, "a", self.exchange, self.keys["a"].ak_public, self.local, fake_seal(self.local),
                                            self.disk, RECOVERY, run=run)

    def test_one_owner_path_beside_the_recovery_keyslot_opens_through_the_owner(self):
        self.assertEqual(self.enrol(), {"path_epoch": 1, "keyslot": 1})
        meta = unlock.luks_meta(self.disk, run)
        self.assertEqual(sorted(meta["keyslots"]), ["0", "1"])                              # the recovery key, the owner path
        self.assertEqual(unlock.judge_tokens(meta, "a", ["owner"]), (True, "peer-assisted unlock: owner in keyslot 1 (path epoch 1)", {"1"}))
        self.assertEqual(self.enrol(), {"path_epoch": None, "keyslot": None, "existing": True})   # again: nothing more
        _, epoch, secret = self.given[0]
        owner_peer = ownerunlock.OwnerPeer(self.m1, self.attester, ("a", epoch, secret), self.signer, self.events.append)
        self.assertEqual(unlock.unlock(self.disk, self.session, self.pins, {"owner": self.transport(owner_peer)}, self.quote(), fake_unseal, run=run),
                         ("owner", 1))

    def test_the_disk_never_opens_on_the_tpm_alone(self):
        self.enrol()
        _, epoch, secret = self.given[0]
        unsealed = []

        def unseal(sealed):                       # the TPM releases its half: this is the case #135 is about
            unsealed.append(sealed)
            return fake_unseal(sealed)

        def down(raw):
            raise ConnectionRefusedError("no route to host")
        self.refused("the disk stays locked: owner (path epoch 1): hello: the transport failed (ConnectionRefusedError)",
                     unlock.unlock, self.disk, self.session, self.pins, {"owner": down}, self.quote(), unseal, run=run)
        self.assertTrue(unsealed, "the local half was released, and still nothing opened")
        self.refused("the disk stays locked: no peer to ask", unlock.unlock, self.disk, self.session, self.pins, {}, self.quote(), unseal, run=run)
        # nothing made of the TPM's half alone opens the owner's keyslot, nor any keyslot but the recovery key's
        for key in (self.local, base64.b64encode(self.local), unlock.credential(self.local, bytes(32), "a", "owner", epoch),
                    unlock.credential(self.local, self.local, "a", "owner", epoch), unlock.credential(self.local, secret, "a", "owner", epoch + 1)):
            self.assertFalse(unlock.opens(self.disk, 1, key, run))
        self.assertTrue(unlock.opens(self.disk, 1, unlock.credential(self.local, secret, "a", "owner", epoch), run))
        self.assertFalse(self.session.consumed)

    def test_a_token_whose_keyslot_is_gone_is_removed_and_the_path_made_again(self):
        self.enrol()
        self.cs(["luksKillSlot", "--batch-mode", self.disk, "1"])                       # the keyslot goes; its token stays
        self.assertEqual(unlock.judge_tokens(unlock.luks_meta(self.disk, run), "a", ["owner"])[0], False)
        self.assertEqual(self.enrol(), {"path_epoch": 2, "keyslot": 1})                 # asked again, not "existing", at a new path epoch
        self.assertEqual(len(self.given), 2)
        meta = unlock.luks_meta(self.disk, run)
        self.assertEqual((sorted(meta["keyslots"]), len(unlock.path_tokens(meta))), (["0", "1"], 1))
        self.assertTrue(unlock.judge_tokens(meta, "a", ["owner"])[0])
        # a token naming several keyslots, one of them live, is never taken for stale: refused, kept, and nothing else removed
        meta = unlock.luks_meta(self.disk, run)
        (token_id, token), = unlock.path_tokens(meta)
        self.cs(["token", "import", "--json-file", "-", self.disk], m.canonical(dict(token, keyslots=[], path_epoch=5)))      # stale beside it
        self.cs(["token", "remove", "--token-id", token_id, self.disk])
        self.cs(["token", "import", "--json-file", "-", self.disk], m.canonical(dict(token, keyslots=["1", "0"])))
        self.refused("the owner token naming keyslot 1, 0 is malformed", self.enrol)
        self.assertEqual(len(unlock.path_tokens(unlock.luks_meta(self.disk, run))), 2, "neither token was removed")
        for tid, _ in unlock.path_tokens(unlock.luks_meta(self.disk, run)):
            self.cs(["token", "remove", "--token-id", tid, self.disk])
        self.cs(["token", "import", "--json-file", "-", self.disk], m.canonical(token))
        # a malformed owner token that names a live keyslot is neither taken for a live path nor removed: refused by name
        meta = unlock.luks_meta(self.disk, run)
        (token_id, token), = unlock.path_tokens(meta)
        self.cs(["token", "remove", "--token-id", token_id, self.disk])
        self.cs(["token", "import", "--json-file", "-", self.disk], m.canonical(dict(token, version=2)))
        self.refused("the owner token naming keyslot 1 is malformed", self.enrol)
        self.assertEqual(len(self.given), 2)
        self.cs(["token", "remove", "--token-id", unlock.path_tokens(unlock.luks_meta(self.disk, run))[0][0], self.disk])
        self.cs(["token", "import", "--json-file", "-", self.disk], m.canonical(token))
        # a live owner path over ANOTHER local half (a reseal) is refused by name, and nothing is written
        self.refused("over another local half (a reseal): remove it first", enrolpeer.request_owner_path, self.m1, "a", self.exchange,
                     self.keys["a"].ak_public, os.urandom(32), fake_seal(os.urandom(32)), self.disk, RECOVERY, run=run)
        self.assertEqual(len(self.given), 2)

    def test_a_cleanup_that_fails_part_way_says_what_it_removed(self):
        self.enrol()
        (token_id, token), = unlock.path_tokens(unlock.luks_meta(self.disk, run))
        self.cs(["luksKillSlot", "--batch-mode", self.disk, "1"])
        self.cs(["token", "import", "--json-file", "-", self.disk], m.canonical(dict(token, keyslots=[], path_epoch=5)))
        removals = []

        def failing_second(argv, **kw):
            if argv[:3] == ["cryptsetup", "token", "remove"]:
                removals.append(argv)
                if len(removals) == 2:
                    return subprocess.CompletedProcess(argv, 1, b"", b"")
            return run(argv, **kw)
        self.refused("could not be removed (exit 1); tokens %s were removed already. Run enrol paths again" % token_id,
                     enrolpeer.request_owner_path, self.m1, "a", self.exchange, self.keys["a"].ak_public, self.local, fake_seal(self.local),
                     self.disk, RECOVERY, run=failing_second)
        self.assertEqual(len(self.given), 1, "the owner was not asked")
        self.assertEqual(self.enrol(), {"path_epoch": 2, "keyslot": 1})          # the rerun starts from the header as it is

    def test_the_node_takes_an_owner_path_only_single_node_and_never_below_its_epoch(self):
        multi = dict(manifest5(1, "", nodes4(), MULTI))
        self.refused("only under the single-node profile", enrolpeer.request_owner_path, multi, "a", self.exchange, self.keys["a"].ak_public,
                     self.local, fake_seal(self.local), self.disk, RECOVERY, run=run)
        ahead = self.single(2, m.digest(self.m1))          # the node holds epoch 2; the owner answers from epoch 1
        self.refused("the owner answered path epoch 1, below this node's manifest epoch 2: refused, nothing was written",
                     enrolpeer.request_owner_path, ahead, "a", self.exchange, self.keys["a"].ak_public, self.local, fake_seal(self.local),
                     self.disk, RECOVERY, run=run)
        self.assertEqual(sorted(unlock.luks_meta(self.disk, run)["keyslots"]), ["0"])

    def test_the_contribution_is_written_nowhere_on_the_node(self):
        self.enrol()
        _, _, secret = self.given[0]
        forms = (secret, secret.hex().encode(), base64.b64encode(secret), secret.hex().upper().encode())
        for directory, _, names in os.walk(self.d):
            for name in names:
                with open(os.path.join(directory, name), "rb") as f:
                    data = f.read()
                for form in forms:
                    self.assertNotIn(form, data, os.path.join(directory, name))


class EnrolPaths(unittest.TestCase):
    """enrol.enrol_paths under single-node: the owner is the one peer, no AK step, local.bin goes once its path is in the
    header. The header and the owner exchange are stood in for (tests/test_baremetal_enrol_paths.py's fixture)."""

    setUp = ept.Paths.setUp
    path, recovery, state, local = ept.Paths.path, ept.Paths.recovery, ept.Paths.state, ept.Paths.local

    def test_a_single_node_host_enrols_one_owner_path_and_no_ak(self):
        with open(self.dir + "/bundle.json") as f:
            bundle = json.load(f)
        bundle["ak_public"] = "0123"
        with open(self.dir + "/bundle.json", "w") as f:
            json.dump(bundle, f)
        asked = []

        def owner_path(manifest, node_id, exchange, ak_public, local, sealed_local, device, recovery, run):
            asked.append((manifest["epoch"], node_id, exchange, ak_public, sealed_local, device, bytes(recovery)))
            self.path("owner", 1, sealed_local)
            return {"path_epoch": 1, "keyslot": 1}
        exchange = object()
        with unittest.mock.patch.object(ept.FakeNode, "manifest", lambda node: single5(1, "")), \
                unittest.mock.patch.object(enrolpeer, "request_owner_path", owner_path), \
                unittest.mock.patch.object(enrolpeer, "request_path", lambda *a, **k: self.fail("a node peer was asked")):
            missing = enrol.enrol_paths(self.dir, self.esp, self.recovery, aks=lambda config: self.fail("the AK step ran"), out=io.StringIO(),
                                        config_path="/etc/regalia/node.json", owner=exchange)
        self.assertEqual(missing, [])
        self.assertEqual(asked, [(1, "a", exchange, bytes.fromhex("0123"), self.sealed_local, enrol.ROOT_DEVICE, b"recovery key")])
        self.assertEqual(self.records, [["owner"]])
        self.assertFalse(os.path.exists(self.local()), "local.bin goes once the owner's path is in the header")
        self.assertEqual(self.state("paths"), "done")


class Record(unittest.TestCase):
    def test_the_enrolment_record_names_the_peers_aks_and_the_owner_by_its_path_only(self):
        nodes = m.validate(manifest5(1, "", nodes4(), MULTI))
        self.assertEqual(enrol.record_peers(nodes, ["b", "c"]), [{"peer": p, "ak_name": nodes[p]["ak_name"]} for p in ("b", "c")])
        self.assertEqual(enrol.record_peers(m.validate(single5(1, "")), ["owner"]), [])


class OwnerCommands(Case):
    """owner.py contribute and unlock, as functions: the envelope first, then the wrap; one response given, then it stops."""

    def test_contribute_writes_the_cards_envelope_first_then_the_wrap(self):
        out = self.d + "/owner"
        os.makedirs(out)
        enrolment = unlock.Enrolment("a")
        request = ownerunlock.path_request("a", enrolment, self.keys["a"].ak_public)
        calls = []

        def gpg(argv, input=None, **kw):
            calls.append((argv, input))
            with open(argv[argv.index("--output") + 1], "w") as f:
                f.write("-----BEGIN PGP MESSAGE-----\n")
            return subprocess.CompletedProcess(argv, 0, b"", b"")
        cards = ["A" * 40, "B" * 40]
        epoch = owner.contribute_path(self.m1, self.doc, request, enrolment.fingerprint, out, cards, out + "/env.asc", out + "/wrapped.json",
                                      run=gpg, say=lambda *a: None)
        self.assertEqual(epoch, 1)
        (argv, plain), = calls
        self.assertEqual([argv[i + 1] for i, a in enumerate(argv) if a == "--recipient"], ["A" * 40 + "!", "B" * 40 + "!"])
        with open(out + "/wrapped.json") as f:
            self.assertEqual(enrolment.open(json.load(f), "owner"), ownerunlock.read_plaintext(plain)[1:])
        # neither output is overwritten, and gpg failing gives the node nothing
        self.refused("exists already: nothing was made", owner.contribute_path, self.m1, self.doc, request, enrolment.fingerprint, out, cards,
                     out + "/env.asc", out + "/other.json", run=gpg)
        failing = lambda argv, **kw: subprocess.CompletedProcess(argv, 2, b"", b"")      # noqa: E731
        self.refused("gpg could not encrypt the contribution", owner.contribute_path, self.m1, self.doc, request, enrolment.fingerprint, out,
                     cards, out + "/env2.asc", out + "/wrapped2.json", run=failing)
        self.assertFalse(os.path.exists(out + "/wrapped2.json"))
        silent = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"", b"")      # noqa: E731  (says done, writes nothing)
        self.refused("gpg wrote no envelope", owner.contribute_path, self.m1, self.doc, request, enrolment.fingerprint, out, cards,
                     out + "/env4.asc", out + "/wrapped4.json", run=silent)
        self.assertFalse(os.path.exists(out + "/wrapped4.json"))
        self.refused("exactly the two owner cards", owner.contribute_path, self.m1, self.doc, request, enrolment.fingerprint, out,
                     cards[:1], out + "/env3.asc", out + "/wrapped3.json", run=gpg)

    def test_the_listen_address_names_its_family(self):
        self.assertEqual(owner.listen_address("192.0.2.9:7443"), (socket.AF_INET, "192.0.2.9", 7443))
        self.assertEqual(owner.listen_address("[fd00::9]:7443"), (socket.AF_INET6, "fd00::9", 7443))
        for bad in ("fd00::9:7443", "owner.boot:7443", "192.0.2.9", "[fd00::9]:70000", ""):
            with self.subTest(bad):
                self.refused("--listen is", owner.listen_address, bad)

    def test_a_response_whose_sending_fails_does_not_count(self):
        """The first signed response cannot be sent: it is recorded and the owner keeps serving; the node's next request
        is answered, and only then is the contribution GIVEN."""
        import queue
        requests = queue.Queue()

        class Conn:
            def __init__(self, raw, answer, listener):
                self.raw, self.answer, self.listener = raw, answer, listener

            def settimeout(self, t):
                pass

            def recv(self, n):
                raw, self.raw = self.raw, b""
                return raw

            def sendall(self, data):
                if self.listener.failures and b'"response"' in data:
                    self.listener.failures -= 1
                    self.answer.put(None)
                    raise BrokenPipeError("the node went away")
                self.answer.put(data)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        class Listener:
            failures = 1                                              # the first signed response's sending fails

            def getsockname(self):
                return ("192.0.2.9", 7443)

            def settimeout(self, t):
                pass

            def accept(self):
                try:
                    raw, answer = requests.get(timeout=0.2)
                except queue.Empty:
                    raise socket.timeout() from None
                return Conn(raw, answer, self), ("192.0.2.1", 1)

        def transport(raw):
            answer = queue.Queue()
            requests.put((raw, answer))
            data = answer.get(timeout=30)
            if data is None:
                raise ConnectionResetError("reset")
            return data
        said, done, stopping = [], [], threading.Event()
        worker = threading.Thread(target=lambda: done.append(owner.serve_unlock(self.m1, self.doc, self.d, self.plain, self.signer, Listener(),
                                                                                say=said.append, stop=stopping.is_set)), daemon=True)
        worker.start()
        self.refused("unlock: the transport failed (ConnectionResetError)", self.ask, transport=transport)
        self.assertFalse(self.session.consumed)
        self.assertEqual(self.ask(transport=transport), self.secret)  # the same boot session, asked again
        stopping.set()
        worker.join(30)
        self.assertEqual(done, [1])                                   # the failed send did not count
        events = [json.loads(line) for line in said if line.startswith("{")]
        self.assertIn(("unlock-send", "ERROR"), [(e["event"], e["outcome"]) for e in events])
        self.assertEqual([line[:30] for line in said if line.startswith(("SENT", "STOPPED"))],
                         ["SENT: signed response 1 to a, ", "STOPPED: 1 signed response(s) "])

    def serve_in_thread(self, signer, stopping):
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        said, outcome = [], []

        def run_it():
            try:
                outcome.append(owner.serve_unlock(self.m1, self.doc, self.d, self.plain, signer, listener, say=said.append, stop=stopping.is_set))
            except m.Refused as refusal:
                outcome.append(refusal)
        worker = threading.Thread(target=run_it, daemon=True)
        worker.start()
        wire = []
        tcp = unlock.tcp_transport("127.0.0.1:%d" % listener.getsockname()[1])

        def transport(raw):
            reply = tcp(raw)
            wire.append(json.loads(reply))
            return reply
        return worker, said, outcome, transport, wire

    def test_a_latched_pin_stops_the_owner_and_the_node_hears_only_denied(self):
        class Latching(SoftOwner):
            latched = None

            def sign(self, message):
                self.latched = {"reason": "CKR_PIN_INCORRECT", "serial": "test", "at": 0}
                raise m.Refused("the token refused the PIN (CKR_PIN_INCORRECT): latched, no further attempt is made; reset the token's counter")
        stopping = threading.Event()
        self.addCleanup(stopping.set)
        worker, said, outcome, transport, wire = self.serve_in_thread(Latching(OWNER_KEYS[0]), stopping)
        self.refused("unlock: the peer refused (DENIED)", self.ask, transport=transport)
        self.assertEqual(wire[-1], {"v": 1, "error": "DENIED"})                          # nothing of the latch on the wire
        worker.join(10)
        self.assertFalse(worker.is_alive(), "the owner went on serving with a signer that cannot sign")
        self.assertIsInstance(outcome[0], m.Refused)
        self.assertIn("its PIN is latched", str(outcome[0]))
        self.assertIn("CKR_PIN_INCORRECT", str(outcome[0]))
        self.assertTrue(any(line.startswith("HALTED: the owner key signs nothing more: the token refused the PIN") for line in said), said)
        # and a token latched before the owner starts is refused before anything is served
        already = Latching(OWNER_KEYS[0])
        already.latched = {"reason": "CKR_PIN_LOCKED"}
        self.refused("refused its PIN before (latched: CKR_PIN_LOCKED)", ownerunlock.OwnerPeer, self.m1, self.attester,
                     ownerunlock.read_plaintext(self.plain), already, self.events.append)

    def test_a_signing_failure_that_is_not_a_latch_is_recorded_and_serving_goes_on(self):
        class OnceFailing(SoftOwner):
            failed = False

            def sign(self, message):
                if not self.failed:
                    self.failed = True
                    raise m.Refused("the touch timed out")
                return super().sign(message)
        stopping = threading.Event()
        self.addCleanup(stopping.set)
        worker, said, outcome, transport, wire = self.serve_in_thread(OnceFailing(OWNER_KEYS[0]), stopping)
        self.refused("unlock: the peer refused (DENIED)", self.ask, transport=transport)
        self.assertEqual(self.ask(transport=transport), self.secret)                    # asked again, in the same boot session
        stopping.set()
        worker.join(20)
        self.assertEqual(outcome, [1])
        events = [json.loads(line) for line in said if line.startswith("{")]
        self.assertIn(("unlock-sign", "ERROR", "the touch timed out"), [(e["event"], e["outcome"], e["reason"]) for e in events])

    def test_unlock_keeps_serving_after_a_response_is_sent_until_it_is_stopped(self):
        """A response written in full is not known to have arrived (the exchange has no acknowledgement): the owner goes on
        answering, here a second request, until it is stopped."""
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        said, done, stopping = [], [], threading.Event()
        worker = threading.Thread(target=lambda: done.append(owner.serve_unlock(self.m1, self.doc, self.d, self.plain, self.signer, listener,
                                                                                say=said.append, stop=stopping.is_set)), daemon=True)
        worker.start()
        endpoint = "127.0.0.1:%d" % listener.getsockname()[1]
        self.assertEqual(self.ask(transport=unlock.tcp_transport(endpoint)), self.secret)
        self.assertEqual(self.ask(session=self.boot(), transport=unlock.tcp_transport(endpoint)), self.secret)   # still answering
        stopping.set()
        worker.join(20)
        self.assertEqual(done, [2])
        self.assertTrue(said[0].startswith("LISTENING for a (path epoch 1, manifest epoch 1)"))
        self.assertEqual(said[-1], "STOPPED: 2 signed response(s) sent to a")

    def test_unlock_ends_at_its_time_and_says_when_nothing_was_sent(self):
        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        self.refused("no signed response was sent to a while this ran", owner.serve_unlock, self.m1, self.doc, self.d, self.plain, self.signer,
                     listener, say=lambda line: None, serve_for=0.2)


class OnSwtpm(unittest.TestCase):
    """The rehearsal: node a on a software TPM (real EK, AK and quotes over PCRs 7 and 11), its local half sealed by
    systemd-creds, a real LUKS2 volume, the owner key on SoftHSM (Ed25519, CKM_EDDSA), the owner served over TCP by
    owner.serve_unlock, and the native client (cmd/regalia-unlock) and the reference one. Run as root by
    e2e/peer-unlock-swtpm.sh; where the tools are provisioned (REGALIA_EXPECT_SWTPM=1) a missing one fails."""
    TOOLS = ("swtpm", "tpm2_createak", "tpm2_quote", "tpm2_pcrextend", "openssl", "systemd-creds", "cryptsetup", "softhsm2-util", "pkcs11-tool")

    from tests.test_baremetal_unlock import OnSwtpm as _Peers
    start, reboot, measure, on, pcr, native = _Peers.start, _Peers.reboot, _Peers.measure, _Peers.on, _Peers.pcr, _Peers.native
    del _Peers

    def setUp(self):
        from tests.test_baremetal_p11sign import SOFTHSM, PyKCS11
        missing = [t for t in self.TOOLS if not shutil.which(t, path=PATH)] + ([] if PyKCS11 and SOFTHSM else ["PyKCS11 and SoftHSM"])
        if missing or os.geteuid() != 0:
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("root, swtpm, tpm2-tools, systemd-creds, cryptsetup, SoftHSM and PyKCS11 are expected here (missing: %s; uid %d)"
                          % (", ".join(missing) or "none", os.geteuid()))
            self.skipTest("needs root, swtpm, tpm2-tools, systemd-creds, cryptsetup, SoftHSM and PyKCS11")
        import gc
        gc.collect()
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pids, self.tcti = {}, {}
        self.addCleanup(lambda: [os.kill(pid, 15) for pid in self.pids.values()])
        self.start("a")
        os.mkdir(self.d + "/a")
        self.on("a", attest.node_init, self.d + "/a")
        names = {k: attest.name_of(attest.public_area(lt.slurp("%s/a/%s.pub" % (self.d, k)), k)).hex() for k in ("ek", "ak")}
        self.ak_public = lt.slurp(self.d + "/a/ak.pub")
        self.measure("a", "the approved image")
        firmware = attest.parse_quote(unlock.tpm_quote([7, 11], tcti=self.tcti["a"])("a", 1, bytes(32), b"k", bytes(32))[0])["firmware_version"]
        self.doc = {"schema": measurements.SCHEMA, "name": "approved", "nodes": {"a": {"accepted": [
            {"label": "current", "tpm_firmware_version": firmware, "pcrs": {"7": self.pcr("a", 7), "11": self.pcr("a", 11)}}]}}}
        # the owner key: an Ed25519 key on a SoftHSM token (test keys only), signing in process through PKCS#11
        os.makedirs(self.d + "/tokens")
        with open(self.d + "/softhsm2.conf", "w") as f:
            f.write("directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" % self.d)
        patch = unittest.mock.patch.dict(os.environ, {"SOFTHSM2_CONF": self.d + "/softhsm2.conf"})
        patch.start()
        self.addCleanup(patch.stop)
        self.pin = "%08d" % (int.from_bytes(os.urandom(4), "big") % 10 ** 8)
        subprocess.run(["softhsm2-util", "--init-token", "--free", "--label", "owner-test", "--so-pin", "12345678", "--pin", self.pin],
                       check=True, capture_output=True)
        listing = subprocess.run(["pkcs11-tool", "--module", SOFTHSM, "--list-slots"], check=True, capture_output=True, text=True).stdout
        serial = next(line.split(":", 1)[1].strip() for line in listing.splitlines() if "serial num" in line)
        subprocess.run(["pkcs11-tool", "--module", SOFTHSM, "--token-label", "owner-test", "--login", "--pin", "env:P", "--keypairgen",
                        "--key-type", "EC:edwards25519", "--id", "03", "--label", "owner"], check=True, capture_output=True, env=dict(os.environ, P=self.pin))
        from deploy.baremetal import p11sign
        self.signer = p11sign.Pkcs11Signer(SOFTHSM, serial, "03", None, only_token=True, pin=lambda: self.pin, alg="ed25519")
        node = dict(one("a"), ek_name=names["ek"], ak_name=names["ak"])
        self.m1 = single5(1, "", [node], policy_version=measurements.version(self.doc),
                          owner_keys=[{"alg": "ed25519", "key": self.signer.public()}, {"alg": "ed25519", "key": pub(OWNER_KEYS[1])}])
        m.validate(self.m1)
        self.device = os.environ.get("REGALIA_UNLOCK_DEVICE")
        self.mapped = False                     # the volume is tested, not mapped (the peers' rehearsal maps it)
        if not self.device:
            self.device = self.d + "/disk.img"
            with open(self.device, "wb") as f:
                f.truncate(32 * 1024 * 1024)
        self.name = "regalia-owner-test-%d" % os.getpid()
        self.client = os.environ.get("REGALIA_UNLOCK_BIN") or self.d + "/regalia-unlock"
        if not os.environ.get("REGALIA_UNLOCK_BIN"):
            built = run(["go", "build", "-o", self.client, "./cmd/regalia-unlock"], capture_output=True, text=True, cwd=REPO)
            self.assertEqual(built.returncode, 0, "the native client did not build (or set REGALIA_UNLOCK_BIN): " + built.stderr)
        self.state = self.d + "/owner-state"
        os.makedirs(self.state)
        self.cards = {}                         # the owner cards' envelope, stood in for: its plaintext, in memory

    # -- the owner's machine --
    def gpg(self, argv, input=None, **kw):
        out = argv[argv.index("--output") + 1]
        self.cards[out] = input
        with open(out, "w") as f:
            f.write("-----BEGIN PGP MESSAGE-----\n(a stand-in: no card in this test)\n")
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    def exchange(self, request, fingerprint):
        envelope, wrapped = self.d + "/owner-env.asc", self.d + "/owner-wrapped.json"
        owner.contribute_path(self.m1, self.doc, json.loads(json.dumps(request)), fingerprint, self.state, ["A" * 40, "B" * 40], envelope, wrapped,
                              run=self.gpg, say=lambda *a: None)
        with open(wrapped) as f:
            return json.load(f)

    def serve(self, manifest=None):
        """The owner's machine answers on 127.0.0.1 (owner.py unlock) until the test ends; returns its endpoint."""
        listener = socket.create_server(("127.0.0.1", 0))
        stopping = threading.Event()
        self.addCleanup(listener.close)
        self.addCleanup(stopping.set)
        self.said = []

        def answer():
            with contextlib.suppress(m.Refused, attest.Refused, OSError):
                owner.serve_unlock(manifest or self.m1, self.doc, self.state, self.cards[self.d + "/owner-env.asc"], self.signer, listener,
                                   say=self.said.append, stop=stopping.is_set)
        threading.Thread(target=answer, daemon=True).start()
        return "127.0.0.1:%d" % listener.getsockname()[1]

    def config(self, endpoint):
        return json.dumps(unlock.boot_config(self.m1, "a", self.device, [7, 11], {"owner": endpoint}))

    def reference(self, endpoint):
        pins = unlock.validate_boot_config(json.loads(self.config(endpoint)))
        return unlock.unlock(self.device, unlock.BootSession("a"), pins, {"owner": unlock.tcp_transport(endpoint)},
                             unlock.tpm_quote([7, 11], tcti=self.tcti["a"]), lambda sealed: unlock.unseal_local(sealed, tpm2_device=self.tcti["a"], run=run),
                             run=run)

    def test_the_owner_unlocks_the_single_node_host_and_the_tpm_alone_never_does(self):
        cs = lambda args, stdin=None: self.assertEqual(run(["cryptsetup", *args], input=stdin, capture_output=True).returncode, 0, args)  # noqa: E731
        cs(["luksFormat", "--type", "luks2", "--batch-mode", *unlock.PBKDF, "--key-file", "-", self.device], RECOVERY)
        cs(["token", "import", "--json-file", "-", self.device], b'{"type":"systemd-recovery","keyslots":["0"]}')
        local = os.urandom(32)
        sealed = unlock.seal_local(local, pcrs="7", tpm2_device=self.tcti["a"], run=run)
        # 1. enrolment: one owner path beside the recovery keyslot; the contribution travels wrapped, and stays nowhere
        self.assertEqual(enrolpeer.request_owner_path(self.m1, "a", self.exchange, self.ak_public, local, sealed, self.device, RECOVERY, run=run),
                         {"path_epoch": 1, "keyslot": 1})
        meta = unlock.luks_meta(self.device, run)
        self.assertEqual(sorted(meta["keyslots"]), ["0", "1"])
        self.assertTrue(unlock.judge_tokens(meta, "a", ["owner"])[0])
        # 2. a boot on the approved image: the native client, over TCP, to the owner signing on SoftHSM
        self.reboot("a", "the approved image")
        rc, out, err, slot = self.native(None, "-attempts", "3", config_text=self.config(self.serve()))
        self.assertEqual((rc, slot), (0, 1), err)
        self.assertTrue(any(line.startswith("SENT: signed response 1 to a") for line in self.said), self.said)
        # 3. the reference client, on the next boot
        self.reboot("a", "the approved image")
        self.assertEqual(self.reference(self.serve()), ("owner", 1))
        # 4. the TPM alone: it releases its half (PCR 7 holds), and with no owner nothing opens
        self.reboot("a", "the approved image")
        self.assertEqual(unlock.unseal_local(sealed, tpm2_device=self.tcti["a"], run=run), local)
        closed = socket.create_server(("127.0.0.1", 0))
        dead = "127.0.0.1:%d" % closed.getsockname()[1]
        closed.close()
        with self.assertRaises(m.Refused) as caught:
            self.reference(dead)
        self.assertIn("the disk stays locked", str(caught.exception))
        rc, out, err, slot = self.native(None, "-attempts", "1", config_text=self.config(dead))
        self.assertEqual((rc, slot), (1, None), err)
        for key in (local, base64.b64encode(local), unlock.credential(local, bytes(32), "a", "owner", 1)):
            self.assertFalse(unlock.opens(self.device, 1, key, run))
        # 5. #135: a retired image (another PCR 11). The TPM still releases the local half; the owner refuses the quote
        self.reboot("a", "a retired image")
        self.assertEqual(unlock.unseal_local(sealed, tpm2_device=self.tcti["a"], run=run), local)
        endpoint = self.serve()
        rc, out, err, slot = self.native(None, "-attempts", "1", config_text=self.config(endpoint))
        self.assertEqual((rc, slot), (1, None), err)
        denied = [json.loads(line) for line in self.said if line.startswith("{")]
        self.assertEqual((denied[-1]["event"], denied[-1]["outcome"]), ("unlock", "DENY"))
        self.assertIn("PCR 11 is", denied[-1]["reason"])        # the native client's version 2 names the PCR that differs
        with self.assertRaises(m.Refused) as caught:
            self.reference(endpoint)
        self.assertIn("the disk stays locked: owner (path epoch 1): unlock: the peer refused (DENIED)", str(caught.exception))
        # 6. a node not ACTIVE: the owner's tool refuses to answer for it at all
        held = single5(2, m.digest(self.m1), [dict(self.m1["nodes"][0], state="MAINTENANCE")], policy_version=self.m1["policy_version"],
                       owner_keys=self.m1["owner_keys"])
        with self.assertRaises(m.Refused) as caught, socket.socket() as never_bound:
            owner.serve_unlock(held, self.doc, self.state, self.cards[self.d + "/owner-env.asc"], self.signer, never_bound)
        self.assertIn("a is MAINTENANCE under epoch 2, not ACTIVE", str(caught.exception))
        # nothing of the contribution on the node's side: not in the header, not in the sealed credential
        secret = ownerunlock.read_plaintext(self.cards[self.d + "/owner-env.asc"])[2]
        forms = (secret, secret.hex().encode(), base64.b64encode(secret))
        keep, tail = max(len(form) for form in forms) - 1, b""
        with open(self.device, "rb") as f:                            # in bounded chunks: the device may be large
            for chunk in iter(lambda: f.read(1 << 20), b""):
                window = tail + chunk
                for form in forms:
                    self.assertNotIn(form, window)
                tail = window[-keep:]


if __name__ == "__main__":
    unittest.main()
