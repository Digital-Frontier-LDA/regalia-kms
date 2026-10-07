"""Membership schema v4 (#199: no authority host): the nodes' TPM signing keys and the owner's approval keys
as parties, the signer rules and their floors, quorum-signed restrictive changes, and the move from v3.
tests/vectors/make-membership-v4.py records the accept() calls made here for the Go port."""
import copy
import json
import pathlib
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
from deploy.baremetal import replacement
import tests.test_baremetal_heartbeat as hbt
from tests.test_baremetal_membership import ROOT, ROOT_PUB, REVOKE, REVOKE_PUB, node, sign

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "membership-v4.json"


def p256(n):
    """A fixed P-256 key per number: the vectors are made from the same keys every time."""
    return ec.derive_private_key(0x5EED0000 + n, ec.SECP256R1())


def ed25519(n):
    """A fixed Ed25519 key per number: an owner's approval key (#126: Ed25519 on the YubiKey's OpenPGP applet)."""
    return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)


def pub(key):
    if isinstance(key, Ed25519PrivateKey):
        return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()


def typed(key):
    return {"alg": "ed25519" if isinstance(key, Ed25519PrivateKey) else "ecdsa-p256", "key": pub(key)}


def p256_sig(key, message, high=False):
    """r || s, low-S unless asked otherwise; an Ed25519 key's own signature."""
    if isinstance(key, Ed25519PrivateKey):
        return key.sign(message).hex()
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    if (s > m.P256_ORDER // 2) != high:
        s = m.P256_ORDER - s
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


NODE_KEYS = {nid: p256(i) for i, nid in enumerate(("a", "b", "c", "d"))}
OWNER_KEYS = [ed25519(10 + i) for i in range(3)]
STRANGER = p256(99)
K_A = p256(60)                                                   # the anchor-policy authority (#361)
CARD_RECORD = {"sequence": 1, "digest": "ca" * 32}               # the card ceremony's record (#405): a placeholder digest


def ssh(i):
    return "%02x" % (0xd0 + i) * 32


def nodes4(**states):
    out = []
    for i, nid in enumerate(("a", "b", "c")):
        n = dict(node(nid, states.get(nid, "ACTIVE"), i), ssh_host_pub=ssh(i), signing_key=typed(NODE_KEYS[nid]))
        out.append(n)
    return out


def manifest4(epoch, prev, nodes, **fields):
    man = {"schema": m.SCHEMA_V4, "epoch": epoch, "prev_digest": prev, "policy_version": "p1", "issued_at": "2026-10-04T09:00:00Z",
           "heartbeat_max_lifetime_s": 21600, "owner_heartbeat_lifetime_s": 3600, "owner_keys": [typed(k) for k in OWNER_KEYS],
           "heartbeat_signers": {"threshold": 2, "parties": ["a", "b", "c", "owner"]},
           "activation_signers": {"threshold": 2, "parties": ["a", "b", "c"]},
           "revocation_signers": [{"threshold": 2, "parties": ["a", "b", "c"]}, {"threshold": 1, "parties": ["owner"]}],
           "anchor_policy_key": typed(K_A), "card_record": dict(CARD_RECORD), "nodes": nodes}
    man.update(fields)
    return man


def manifest3(epoch, prev, nodes):
    return {"schema": m.SCHEMA_V3, "epoch": epoch, "prev_digest": prev, "policy_version": "p1", "issued_at": "2026-10-04T08:00:00Z",
            "heartbeat_max_lifetime_s": 21600, "revocation_keys": [REVOKE_PUB], "nodes": nodes}


def quorum(man, *signers, high=False):
    """A quorum envelope: each signer a (party, private key) pair."""
    message = m.DOMAIN + m.canonical(man)
    return {"manifest": man, "signatures": [{"party": party, "key": pub(key), "sig": p256_sig(key, message, high)} for party, key in signers]}


A, B, C = ("a", NODE_KEYS["a"]), ("b", NODE_KEYS["b"]), ("c", NODE_KEYS["c"])
O1, O2 = ("owner", OWNER_KEYS[0]), ("owner", OWNER_KEYS[1])


class Case(unittest.TestCase):
    def setUp(self):
        self.first = m.accept(None, sign(manifest4(1, "", nodes4()), ROOT), ROOT_PUB)

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def next(self, **states):
        return manifest4(2, m.digest(self.first), nodes4(**states))

    def changed(self, change):
        man = self.next()
        change(man)
        return man


class Format(Case):
    def test_a_v4_manifest_names_its_signers_and_the_root_signs_it(self):
        self.assertEqual((self.first["schema"], m.may(self.first, "a", "authorize")), (m.SCHEMA_V4, True))
        self.assertEqual(m.validate(self.first)["a"]["signing_key"], typed(NODE_KEYS["a"]))

    def invalid(self, reason, change, base=None):
        """A first manifest with one change, signed by the root: refused by the format alone (through
        accept(), so the vectors carry it)."""
        man = copy.deepcopy(base or self.first)
        change(man)
        self.refused(reason, m.accept, None, sign(man, ROOT), ROOT_PUB)

    def valid(self, man):
        self.assertEqual(m.accept(None, sign(man, ROOT), ROOT_PUB), man)

    def test_the_floors_are_the_format_s(self):
        for name, change, reason in (
                ("a heartbeat threshold of 1", lambda x: x["heartbeat_signers"].update(threshold=1), "heartbeat_signers.threshold must be from 2"),
                ("an activation threshold of 1", lambda x: x["activation_signers"].update(threshold=1), "activation_signers.threshold must be from 2"),
                ("an activation rule of the owner alone", lambda x: x.update(activation_signers={"threshold": 1, "parties": ["owner"]}),
                 "activation_signers.threshold must be from 2 to the number of its parties (1)"),
                ("no activation rule", lambda x: x.pop("activation_signers"), "manifest fields mismatch"),
                ("a heartbeat rule of the owner alone", lambda x: x.update(heartbeat_signers={"threshold": 1, "parties": ["owner"]}),
                 "heartbeat_signers.threshold must be from 2 to the number of its parties (1)"),
                ("a node revocation rule at 1", lambda x: x["revocation_signers"][0].update(threshold=1), "revocation_signers[0].threshold must be from 2"),
                ("the owner and a node at 1", lambda x: x["revocation_signers"][1].update(parties=["owner", "a"]),
                 "revocation_signers[1].threshold must be from 2"),
                ("a threshold above its parties", lambda x: x["heartbeat_signers"].update(threshold=5), "number of its parties (4)"),
                ("a threshold true", lambda x: x["heartbeat_signers"].update(threshold=True), "heartbeat_signers.threshold must be an integer"),
                ("a threshold as text", lambda x: x["heartbeat_signers"].update(threshold="2"), "heartbeat_signers.threshold must be an integer"),
                ("an unknown party", lambda x: x["heartbeat_signers"]["parties"].append("z"), "names 'z', which is neither a node"),
                ("a party twice", lambda x: x["revocation_signers"][0]["parties"].append("a"), "revocation_signers[0].parties must be distinct"),
                ("no parties", lambda x: x["heartbeat_signers"].update(parties=[]), "heartbeat_signers.parties must be a non-empty list"),
                ("an extra rule field", lambda x: x["heartbeat_signers"].update(weight=1), "heartbeat_signers fields mismatch"),
                ("no revocation rule", lambda x: x.update(revocation_signers=[]), "revocation_signers must be a list of one to 4 rules"),
                ("five revocation rules", lambda x: x.update(revocation_signers=[{"threshold": 1, "parties": ["owner"]}] * 5),
                 "revocation_signers must be a list of one to 4 rules")):
            with self.subTest(name):
                self.invalid(reason, change)
        # the owner alone may revoke, at 1; a stricter cluster may need more
        ok = copy.deepcopy(self.first)
        ok.update(heartbeat_signers={"threshold": 3, "parties": ["a", "b", "c", "owner"]}, revocation_signers=[{"threshold": 3, "parties": ["a", "b", "c"]}])
        self.valid(ok)

    def test_the_owner_s_keys_and_the_signing_keys(self):
        for name, change, reason in (
                ("no owner key", lambda x: x.update(owner_keys=[]), "owner_keys must be a list of one to 8 keys"),
                ("nine owner keys", lambda x: x.update(owner_keys=[typed(p256(30 + i)) for i in range(9)]), "owner_keys must be a list of one to 8 keys"),
                ("a bare owner key", lambda x: x.update(owner_keys=[pub(OWNER_KEYS[0])]), "owner_keys[0] must be a typed key"),
                ("an owner key twice", lambda x: x.update(owner_keys=[typed(OWNER_KEYS[0])] * 2), "owner_keys[1] is already used (owner_keys[0])"),
                ("an owner key that is a node's", lambda x: x["owner_keys"].append(typed(NODE_KEYS["a"])), "owner_keys[3] is already used (signing_key of a)"),
                ("an owner key that is a node's SSH host key", lambda x: x["owner_keys"].append({"alg": "ed25519", "key": ssh(0)}),
                 "owner_keys[3] is already used (ssh_host_pub of a)"),
                ("an owner key of an unknown alg", lambda x: x["owner_keys"].append({"alg": "rsa", "key": "00" * 32}), "owner_keys[3]: alg must be one of ed25519, ecdsa-p256"),
                ("an Ed25519 owner key of 130 hex", lambda x: x["owner_keys"].append({"alg": "ed25519", "key": pub(NODE_KEYS["d"])}), "an ed25519 key must be 64 lowercase hex"),
                ("one signing key on two nodes", lambda x: x["nodes"][1].update(signing_key=typed(NODE_KEYS["a"])), "signing_key of b is already used (signing_key of a)"),
                # (a placeholder of the right length: refused before any value is read, and a real point here
                # would read as a credential to the secret scanner, in the vectors)
                ("a bare signing key", lambda x: x["nodes"][0].update(signing_key="04" + "11" * 64), "nodes[0].signing_key must be a typed key"),
                ("an Ed25519 signing key", lambda x: x["nodes"][0].update(signing_key={"alg": "ed25519", "key": "00" * 32}), "alg must be one of ecdsa-p256"),
                ("a point off the curve", lambda x: x["nodes"][0].update(signing_key={"alg": "ecdsa-p256", "key": "04" + "01" * 64}), "not a point on P-256"),
                ("an active node without a signing key", lambda x: x["nodes"][0].pop("signing_key"), "nodes[0] fields mismatch: missing=['signing_key']"),
                ("a node named owner", lambda x: x["nodes"][0].update(node_id="owner"), "'owner' is the owner's party name"),
                ("revocation keys under v4", lambda x: x.update(revocation_keys=[]), "manifest fields mismatch"),
                ("no owner heartbeat bound", lambda x: x.pop("owner_heartbeat_lifetime_s"), "manifest fields mismatch"),
                ("an owner heartbeat bound below 300 s", lambda x: x.update(owner_heartbeat_lifetime_s=299), "owner_heartbeat_lifetime_s must be an integer from 300"),
                ("an owner heartbeat bound above the heartbeat bound", lambda x: x.update(owner_heartbeat_lifetime_s=21601), "to heartbeat_max_lifetime_s"),
                ("an owner heartbeat bound true", lambda x: x.update(owner_heartbeat_lifetime_s=True), "owner_heartbeat_lifetime_s must be an integer")):
            with self.subTest(name):
                self.invalid(reason, change)

    def test_the_root_is_never_a_party(self):
        """d9: one device is never both the payload root and a quorum party (D28)."""
        self.invalid("owner_keys[3] is a pinned root key: the payload root is never a quorum party",
                     lambda x: x["owner_keys"].append({"alg": "ed25519", "key": ROOT_PUB}))
        # a P-256 root (#156) that is also a node's signing key
        root = p256(50)
        man = copy.deepcopy(self.first)
        man["nodes"][0]["signing_key"] = typed(root)
        envelope = {"manifest": man, "signature": {"signer": "root", "key": pub(root), "sig": p256_sig(root, m.DOMAIN + m.canonical(man))}}
        self.refused("signing_key of a is a pinned root key", m.accept, None, envelope, [ROOT_PUB, typed(root)])

    def test_a_tombstone_keeps_the_fields_it_had(self):
        retired = copy.deepcopy(self.first)
        retired["nodes"][2]["state"] = "RETIRED"
        self.valid(retired)                                                   # retired under v4: keeps its signing key
        before = copy.deepcopy(retired)
        before["nodes"][2].pop("signing_key")                                 # retired before v4: never had one
        self.valid(before)
        older = copy.deepcopy(before)
        older["nodes"][2].pop("ssh_host_pub")                                 # retired under v1
        self.valid(older)
        self.invalid("nodes[2] fields mismatch", lambda x: (x["nodes"][2].pop("signing_key"), x["nodes"][2].update(state="QUARANTINED")))
        # a v3 manifest cannot carry what v4 adds
        v3 = manifest3(1, "", [dict(n) for n in nodes4()])
        self.refused("nodes[0] fields mismatch: missing=[] unknown=['signing_key']", m.validate, v3)


class MoveToV4(Case):
    def setUp(self):
        v3nodes = [{k: v for k, v in n.items() if k != "signing_key"} for n in nodes4(c="RETIRED")]
        self.m3 = m.accept(None, sign(manifest3(1, "", v3nodes), ROOT), ROOT_PUB)

    def v4(self, nodes=None):
        nodes = nodes or [n if n["node_id"] != "c" else {k: v for k, v in n.items() if k != "signing_key"} for n in nodes4(c="RETIRED")]
        return manifest4(2, m.digest(self.m3), nodes)

    def test_the_root_moves_a_v3_chain_to_v4_and_the_revocation_key_ends_there(self):
        m4 = m.accept(self.m3, sign(self.v4(), ROOT), ROOT_PUB)
        self.assertEqual((m4["schema"], "revocation_keys" in m4), (m.SCHEMA_V4, False))
        # the v3 revocation key can sign nothing under v4
        following = manifest4(3, m.digest(m4), m4["nodes"])
        following["nodes"][0] = dict(following["nodes"][0], state="QUARANTINED")
        self.refused("the signing revocation key is not named by the current manifest", m.accept, m4, sign(following, REVOKE, "revocation"), ROOT_PUB)
        # nor can it sign a heartbeat: under v4 a single-key heartbeat is not one at all
        beat = hbt.beat(m4, 1, key=REVOKE)
        self.refused("envelope fields mismatch: missing=['signatures'] unknown=['signature']", hb.signed, beat, m4)

    def test_nothing_moves_a_chain_back_from_v4(self):
        """#242 B3 keys the anchor's layout on the tip's schema (v4: policy only), so a v3 epoch after v4 would bring the
        owner-written layout back: refused, even signed by the root (24)."""
        m4 = m.accept(self.m3, sign(self.v4(), ROOT), ROOT_PUB)
        back = manifest3(3, m.digest(m4), [{k: v for k, v in n.items() if k != "signing_key"} for n in m4["nodes"]])
        self.refused("schema regalia.membership/v3 cannot follow regalia.membership/v4: the schema only moves forward",
                     m.accept, m4, sign(back, ROOT), ROOT_PUB)

    def test_only_the_root_moves_to_v4(self):
        self.refused("only the root can change the schema (regalia.membership/v3 to regalia.membership/v4)",
                     m.accept, self.m3, sign(self.v4(), REVOKE, "revocation"), ROOT_PUB)
        self.refused("needs a current regalia.membership/v4 manifest", m.accept, self.m3, quorum(self.v4(), A, B), ROOT_PUB)

    def test_the_tombstone_retired_under_v3_stays_as_it_was(self):
        c = self.v4()["nodes"][2]
        self.assertNotIn("signing_key", c)
        self.refused("tombstone: c is RETIRED and its fields cannot change", m.accept, self.m3,
                     sign(self.v4([n for n in nodes4(c="RETIRED")]), ROOT), ROOT_PUB)


class Quorum(Case):
    def accepted(self, man, *signers):
        return m.accept(self.first, quorum(man, *signers), ROOT_PUB)

    def test_two_nodes_or_the_owner_alone_make_a_restrictive_change(self):
        for signers in ((A, B), (B, C), (A, B, C), (O1,), (O2,), (A, O1)):
            with self.subTest(signers=[p for p, _ in signers]):
                self.assertEqual(self.accepted(self.next(c="QUARANTINED"), *signers)["nodes"][2]["state"], "QUARANTINED")

    def test_one_node_is_not_a_quorum(self):
        for signers in ((A,), (C,)):
            with self.subTest(signers=[p for p, _ in signers]):
                self.refused("the manifest's signatures meet no revocation_signers rule of the current manifest (counting: %s)" % signers[0][0],
                             self.accepted, self.next(c="QUARANTINED"), *signers)

    def test_a_node_that_does_not_count_does_not_make_a_quorum(self):
        quarantined = m.accept(self.first, quorum(self.next(c="QUARANTINED"), O1), ROOT_PUB)
        following = manifest4(3, m.digest(quarantined), nodes4(c="QUARANTINED", b="MAINTENANCE"))
        self.refused("meet no revocation_signers rule of the current manifest (counting: a)", m.accept, quarantined, quorum(following, A, C), ROOT_PUB)
        self.assertEqual(m.accept(quarantined, quorum(following, A, B), ROOT_PUB)["epoch"], 3)
        # its signature must still verify: a bad one is refused, not ignored
        bad = quorum(following, A, B, C)
        bad["signatures"][2]["sig"] = bad["signatures"][1]["sig"]
        self.refused("signatures[2], c) signature does not verify", m.accept, quarantined, bad, ROOT_PUB)

    def test_every_signature_is_checked(self):
        man = self.next(c="QUARANTINED")
        for name, envelope, reason in (
                ("a party twice", quorum(man, A, A), "party 'a' is named twice"),
                ("the owner twice, by two keys", quorum(man, O1, O2), "party 'owner' is named twice"),
                ("a key that is not the party's", quorum(man, A, ("b", NODE_KEYS["c"])), "signatures[1]: the key is not b's signing_key"),
                ("an unknown party", quorum(man, A, ("z", STRANGER)), "'z' is not a node of the current manifest"),
                ("a stranger as the owner", quorum(man, ("owner", STRANGER)), "the key is not one of the current manifest's owner_keys"),
                ("a high-S signature", quorum(man, A, B, high=True), "is not a low-S P-256 signature"),
                ("no signature", {"manifest": man, "signatures": []}, "signatures must be a list of one to 16"),
                ("seventeen signatures", {"manifest": man, "signatures": quorum(man, A)["signatures"] * 17}, "signatures must be a list of one to 16"),
                ("an extra field", dict(quorum(man, A, B), signature={}), "envelope fields mismatch"),
                ("a signature with an extra field", {"manifest": man, "signatures": [dict(quorum(man, A)["signatures"][0], signer="root")]},
                 "signatures[0] fields mismatch"),
                ("a signature over another manifest", {"manifest": man, "signatures": quorum(self.next(b="QUARANTINED"), A, B)["signatures"]},
                 "signature does not verify")):
            with self.subTest(name):
                self.refused(reason, m.accept, self.first, envelope, ROOT_PUB)

    def test_a_quorum_only_restricts_and_never_touches_the_signers(self):
        for name, change, reason in (
                ("a node made ACTIVE from MAINTENANCE", None, "widens capabilities"),
                ("a lower heartbeat threshold", lambda x: x["heartbeat_signers"].update(threshold=3), "cannot change heartbeat_signers"),
                ("an activation party dropped", lambda x: x["activation_signers"]["parties"].pop(), "cannot change activation_signers"),
                ("a revocation rule dropped", lambda x: x["revocation_signers"].pop(), "cannot change revocation_signers"),
                ("an owner key added", lambda x: x["owner_keys"].append(typed(STRANGER)), "cannot change owner_keys"),
                ("the owner's heartbeat bound", lambda x: x.update(owner_heartbeat_lifetime_s=7200), "cannot change owner_heartbeat_lifetime_s"),
                ("the heartbeat bound", lambda x: x.update(heartbeat_max_lifetime_s=7200, owner_heartbeat_lifetime_s=3600), "cannot change heartbeat_max_lifetime_s"),
                ("the policy", lambda x: x.update(policy_version="p2"), "cannot change the policy version"),
                ("a signing key", lambda x: x["nodes"][0].update(signing_key=typed(STRANGER)), "cannot change signing_key of a"),
                ("a node added", lambda x: x["nodes"].append(dict(node("d", "ACTIVE", 3), ssh_host_pub=ssh(3), signing_key=typed(NODE_KEYS["d"]))),
                 "cannot add or remove nodes")):
            with self.subTest(name):
                if change is None:
                    current = m.accept(self.first, quorum(self.next(a="MAINTENANCE"), O1), ROOT_PUB)
                    man = manifest4(3, m.digest(current), nodes4())
                    self.refused(reason, m.accept, current, quorum(man, B, C), ROOT_PUB)
                    continue
                self.refused("a revocation quorum " + reason if reason.startswith("cannot") else reason, m.accept, self.first,
                             quorum(self.changed(change), A, B), ROOT_PUB)

    def test_the_root_changes_the_signers(self):
        man = self.changed(lambda x: (x["heartbeat_signers"].update(threshold=3), x["owner_keys"].pop(),
                                      x.update(card_record={"sequence": 2, "digest": "cb" * 32})))
        self.assertEqual(m.accept(self.first, sign(man, ROOT), ROOT_PUB)["heartbeat_signers"]["threshold"], 3)

    def test_a_retired_tombstone_is_terminal_for_a_quorum_too(self):
        retired = m.accept(self.first, quorum(self.next(c="RETIRED"), O1), ROOT_PUB)
        back = manifest4(3, m.digest(retired), nodes4(c="QUARANTINED"))
        self.refused("tombstone: c is RETIRED, which is terminal for every signer", m.accept, retired, sign(back, ROOT), ROOT_PUB)


class AnchorPolicyAndCardRecord(Case):
    """#361: K_A, set at genesis, never changed by any signer; #405: the card ceremony's record, the root's alone,
    whose sequence rises when it changes and without which owner_keys do not change."""

    invalid = Format.invalid

    def test_the_fields_are_validated(self):
        for name, change, reason in (
                ("no anchor policy key", lambda x: x.pop("anchor_policy_key"), "manifest fields mismatch"),
                ("no card record", lambda x: x.pop("card_record"), "manifest fields mismatch"),
                # a placeholder, as for the bare signing key above: refused before any value is read
                ("a bare anchor policy key", lambda x: x.update(anchor_policy_key="04" + "11" * 64), "anchor_policy_key must be a typed key"),
                ("an Ed25519 anchor policy key", lambda x: x.update(anchor_policy_key={"alg": "ed25519", "key": "00" * 32}),
                 "anchor_policy_key: alg must be one of ecdsa-p256"),
                ("an anchor policy key off the curve", lambda x: x.update(anchor_policy_key={"alg": "ecdsa-p256", "key": "04" + "01" * 64}),
                 "not a point on P-256"),
                ("the anchor policy key a node's signing key", lambda x: x.update(anchor_policy_key=typed(NODE_KEYS["b"])),
                 "anchor_policy_key is already used (signing_key of b)"),
                ("the anchor policy key an owner key", lambda x: x["owner_keys"].append(typed(K_A)),
                 "anchor_policy_key is already used (owner_keys[3])"),
                ("a card record with an extra field", lambda x: x["card_record"].update(at="x"), "card_record fields mismatch"),
                ("a card record without a digest", lambda x: x["card_record"].pop("digest"), "card_record fields mismatch"),
                ("a card record sequence 0", lambda x: x["card_record"].update(sequence=0), "card_record.sequence must be an integer from 1"),
                ("a card record sequence true", lambda x: x["card_record"].update(sequence=True), "card_record.sequence must be an integer from 1"),
                ("a card record sequence 2^31", lambda x: x["card_record"].update(sequence=2 ** 31), "card_record.sequence must be an integer from 1"),
                ("a card record digest in capitals", lambda x: x["card_record"].update(digest="CA" * 32), "card_record.digest must be 64 lowercase hex"),
                ("a card record digest short", lambda x: x["card_record"].update(digest="ca" * 31), "card_record.digest must be 64 lowercase hex")):
            with self.subTest(name):
                self.invalid(reason, change)

    def test_the_anchor_policy_key_is_not_the_root(self):
        man = copy.deepcopy(self.first)
        man["anchor_policy_key"] = typed(p256(50))
        envelope = {"manifest": man, "signature": {"signer": "root", "key": pub(p256(50)),
                                                   "sig": p256_sig(p256(50), m.DOMAIN + m.canonical(man))}}
        self.refused("anchor_policy_key is a pinned root key", m.accept, None, envelope, [ROOT_PUB, typed(p256(50))])

    def test_no_signer_changes_the_anchor_policy_key(self):
        man = self.changed(lambda x: x.update(anchor_policy_key=typed(STRANGER)))
        reason = "anchor_policy_key is set at genesis and never changes, for any signer"
        self.refused(reason, m.accept, self.first, sign(man, ROOT), ROOT_PUB)
        self.refused(reason, m.accept, self.first, quorum(man, A, B), ROOT_PUB)
        self.refused(reason, m.accept, self.first, quorum(man, O1), ROOT_PUB)

    def test_a_quorum_cannot_change_the_card_record(self):
        man = self.changed(lambda x: x.update(card_record={"sequence": 2, "digest": "cb" * 32}))
        self.refused("a revocation quorum cannot change card_record", m.accept, self.first, quorum(man, A, B), ROOT_PUB)

    def test_the_root_moves_the_card_record_forward_only(self):
        later = {"sequence": 3, "digest": "cb" * 32}
        current = m.accept(self.first, sign(self.changed(lambda x: x.update(card_record=later)), ROOT), ROOT_PUB)
        self.assertEqual(current["card_record"], later)
        for name, record in (("the same sequence, another digest", {"sequence": 3, "digest": "cc" * 32}),
                             ("a lower sequence", {"sequence": 2, "digest": "cc" * 32})):
            with self.subTest(name):
                man = manifest4(3, m.digest(current), nodes4(), card_record=record)
                self.refused("card_record changes only to a later card ceremony's record (sequence %d after 3)" % record["sequence"],
                             m.accept, current, sign(man, ROOT), ROOT_PUB)

    def test_owner_keys_change_only_with_a_new_card_record(self):
        man = self.changed(lambda x: x["owner_keys"].pop())
        self.refused("owner_keys change only with a new card_record", m.accept, self.first, sign(man, ROOT), ROOT_PUB)

    def test_the_move_from_v3_sets_both(self):
        """v3 has neither field; the root's v3 -> v4 step is where K_A and the card record are first set."""
        v3 = m.accept(None, sign(manifest3(1, "", [{k: v for k, v in n.items() if k != "signing_key"} for n in nodes4()]), ROOT), ROOT_PUB)
        v4 = m.accept(v3, sign(manifest4(2, m.digest(v3), nodes4()), ROOT), ROOT_PUB)
        self.assertEqual((v4["anchor_policy_key"], v4["card_record"]), (typed(K_A), CARD_RECORD))


class Replacement(Case):
    def replaced(self, rules=None):
        d = dict(node("d", "ACTIVE", 3), ssh_host_pub=ssh(3), signing_key=typed(NODE_KEYS["d"]))
        man = manifest4(2, m.digest(self.first), nodes4(c="RETIRED") + [d],
                        heartbeat_signers={"threshold": 2, "parties": ["a", "b", "d", "owner"]},
                        activation_signers={"threshold": 2, "parties": ["a", "b", "d"]},
                        revocation_signers=[{"threshold": 2, "parties": ["a", "b", "d"]}, {"threshold": 1, "parties": ["owner"]}])
        if rules:
            rules(man)
        return man

    def test_the_new_node_takes_the_old_one_s_place_in_the_rules(self):
        replacement.check_replacement(self.first, self.replaced(), "c", "d")
        m.accept(self.first, sign(self.replaced(), ROOT), ROOT_PUB)

    def test_nothing_else_changes_in_the_rules_or_the_keys(self):
        for name, change, reason in (
                ("the old node kept in the rules", lambda x: x["heartbeat_signers"].update(parties=["a", "b", "c", "owner"]),
                 "a replacement names d in place of c in heartbeat_signers and changes nothing else there"),
                ("the old node kept in the activation rule", lambda x: x["activation_signers"].update(parties=["a", "b", "c"]),
                 "a replacement names d in place of c in activation_signers"),
                ("a threshold changed", lambda x: x["revocation_signers"][0].update(threshold=3),
                 "a replacement names d in place of c in revocation_signers"),
                ("an owner key changed", lambda x: x["owner_keys"].pop(), "a replacement does not change owner_keys"),
                ("the new node with the old one's signing key", lambda x: x["nodes"][3].update(signing_key=typed(NODE_KEYS["c"])),
                 "signing_key of d is already used (signing_key of c)")):
            with self.subTest(name):
                self.refused(reason, replacement.check_replacement, self.first, self.replaced(change), "c", "d")


def restored(document):
    """A vector's document as accept() takes it: every "public" written for the secret scanner is "key" again."""
    if isinstance(document, dict):
        return {("key" if k == "public" else k): restored(v) for k, v in document.items()}
    if isinstance(document, list):
        return [restored(v) for v in document]
    return document


class Vectors(unittest.TestCase):
    def test_the_shared_vectors_are_what_this_python_decides(self):
        """tests/vectors/membership-v4.json, which the Go port reads, replayed here: a vector the Python no
        longer decides the same way fails, so the file cannot drift from the code."""
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
