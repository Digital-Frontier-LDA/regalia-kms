"""Typed revocation keys: Ed25519, or ECDSA P-256 for a key held on the HSM (#199, decided on #199
2026-10-03). The algorithm comes from the manifest's entry only."""
import json
import pathlib
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from deploy.baremetal import heartbeat as hb, membership as m
import tests.test_baremetal_heartbeat as hbt

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "typed-keys-p256.json"


def v3(man, life=hb.MAX_LIFETIME):
    """A regalia.membership/v3 manifest from a v1 one: v2's fields (each node's SSH host key, the heartbeat
    lifetime), where typed keys are allowed."""
    nodes = [dict(n, ssh_host_pub=("%02x" % (0xd0 + i)) * 32) for i, n in enumerate(man["nodes"])]
    return dict(man, schema=m.SCHEMA_V3, heartbeat_max_lifetime_s=life, nodes=nodes)


def p256():
    key = ec.generate_private_key(ec.SECP256R1())
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    return key, {"alg": "ecdsa-p256", "key": point}


def sign_p256(key, message, high=False):
    """r || s, low-S (as the authority's signer normalises), or deliberately high-S."""
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(hashes.SHA256())))
    s = min(s, m.P256_ORDER - s)
    if high:
        s = m.P256_ORDER - s
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def p256_beat(man, sequence, key, entry, issued=hbt.T0, high=False):
    body = {"schema": hb.SCHEMA, "epoch": man["epoch"], "sequence": sequence, "issued_at": hbt.stamp(issued),
            "expires_at": hbt.stamp(issued + hb.MAX_LIFETIME), "manifest_digest": m.digest(man)}
    return {"heartbeat": body, "signature": {"key": entry["key"], "sig": sign_p256(key, hb.DOMAIN + m.canonical(body), high)}}


class Case(unittest.TestCase):
    def setUp(self):
        self.key, self.entry = p256()
        self.man = v3(hbt.manifest(keys=[hbt.pub(hbt.REVOKE), self.entry]))

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Entries(Case):
    def test_a_bare_key_is_ed25519_and_a_typed_one_is_what_it_says(self):
        self.assertEqual(m.revocation_entry(hbt.pub(hbt.REVOKE)), ("ed25519", hbt.pub(hbt.REVOKE)))
        self.assertEqual(m.revocation_entry(self.entry), ("ecdsa-p256", self.entry["key"]))
        m.validate(self.man)

    def test_a_malformed_entry_makes_the_manifest_invalid(self):
        x = self.entry["key"][2:66]
        for label, entry, reason in (("unknown alg", dict(self.entry, alg="ecdsa-p384"), "alg must be one of"),
                                     ("a P-256 key given as 64 hex", {"alg": "ecdsa-p256", "key": x}, "must be 130 lowercase hex"),
                                     ("compressed", {"alg": "ecdsa-p256", "key": "02" + x + "00" * 32}, "uncompressed point"),
                                     ("off the curve", {"alg": "ecdsa-p256", "key": "04" + "11" * 64}, "not a point on P-256"),
                                     ("the point at infinity", {"alg": "ecdsa-p256", "key": "00" * 65}, "uncompressed point"),
                                     ("an extra field", dict(self.entry, note="x"), "fields mismatch"),
                                     ("uppercase", dict(self.entry, key=self.entry["key"].upper()), "lowercase hex"),
                                     ("twice", None, "must be distinct")):
            with self.subTest(label):
                keys = [self.entry, dict(self.entry)] if entry is None else [entry]
                self.refused(reason, m.validate, v3(hbt.manifest(keys=keys)))

    def test_a_typed_key_needs_schema_v3(self):
        """The Go accept() in the initrd knows only Ed25519 until it is ported: a typed key under v1 or v2
        must make the manifest invalid everywhere, never be misread."""
        self.refused("needs schema regalia.membership/v3", m.validate, hbt.manifest(keys=[self.entry]))
        v2 = dict(v3(hbt.manifest(keys=[self.entry])), schema=m.SCHEMA_V2)
        self.refused("needs schema regalia.membership/v3", m.validate, v2)
        m.validate(dict(v2, revocation_keys=[hbt.pub(hbt.REVOKE)]))        # v2 with bare keys: as before


class Heartbeats(Case):
    def test_a_p256_heartbeat_verifies_by_the_entry(self):
        self.assertEqual(hb.verify(p256_beat(self.man, 1, self.key, self.entry), self.man)["sequence"], 1)
        self.assertEqual(hb.verify(hbt.beat(self.man, 2), self.man)["sequence"], 2)          # the Ed25519 key still works

    def test_the_algorithm_comes_from_the_entry_never_the_signature(self):
        # an Ed25519 signature presented under the P-256 key, and a P-256 signature under the Ed25519 key
        ed = hbt.beat(self.man, 1)
        crossed = {"heartbeat": ed["heartbeat"], "signature": {"key": self.entry["key"], "sig": ed["signature"]["sig"]}}
        self.refused("does not verify", hb.verify, crossed, self.man)
        p = p256_beat(self.man, 1, self.key, self.entry)
        crossed = {"heartbeat": p["heartbeat"], "signature": {"key": hbt.pub(hbt.REVOKE), "sig": p["signature"]["sig"]}}
        self.refused("does not verify", hb.verify, crossed, self.man)

    def test_high_s_is_refused_and_low_s_taken(self):
        self.refused("does not verify", hb.verify, p256_beat(self.man, 1, self.key, self.entry, high=True), self.man)
        hb.verify(p256_beat(self.man, 1, self.key, self.entry), self.man)
        zero = p256_beat(self.man, 1, self.key, self.entry)
        zero["signature"]["sig"] = "00" * 64
        self.refused("does not verify", hb.verify, zero, self.man)

    def test_a_key_the_manifest_does_not_name_is_refused(self):
        other_key, other = p256()
        self.refused("not a revocation key named", hb.verify, p256_beat(self.man, 1, other_key, other), self.man)


class Manifests(Case):
    def test_a_p256_revocation_key_signs_a_restrictive_change(self):
        candidate = dict(self.man, epoch=2, prev_digest=m.digest(self.man), nodes=[dict(n, state="QUARANTINED") if n["node_id"] == "c" else n
                                                                                for n in self.man["nodes"]])
        envelope = {"manifest": candidate, "signature": {"signer": "revocation", "key": self.entry["key"],
                                                         "sig": sign_p256(self.key, m.DOMAIN + m.canonical(candidate))}}
        manifest, signer = m.verify_envelope(envelope, hbt.pub(hbt.ROOT), self.man)
        self.assertEqual((manifest["epoch"], signer), (2, "revocation"))
        envelope["signature"]["sig"] = sign_p256(self.key, m.DOMAIN + m.canonical(candidate), high=True)
        self.refused("does not verify", m.verify_envelope, envelope, hbt.pub(hbt.ROOT), self.man)

    def test_only_the_root_introduces_or_changes_a_revocation_key(self):
        _, newer = p256()
        candidate = dict(self.man, epoch=2, prev_digest=m.digest(self.man), revocation_keys=self.man["revocation_keys"] + [newer])
        by_revocation = {"manifest": candidate, "signature": {"signer": "revocation", "key": self.entry["key"],
                                                              "sig": sign_p256(self.key, m.DOMAIN + m.canonical(candidate))}}
        manifest, signer = m.verify_envelope(by_revocation, hbt.pub(hbt.ROOT), self.man)    # signature fine...
        self.refused("cannot change the revocation keys", m._restrictive, self.man, manifest)  # ...the change is not
        root = {"manifest": candidate, "signature": {"signer": "root", "key": hbt.pub(hbt.ROOT),
                                                     "sig": hbt.ROOT.sign(m.DOMAIN + m.canonical(candidate)).hex()}}
        self.assertEqual(m.verify_envelope(root, hbt.pub(hbt.ROOT), self.man)[1], "root")

    def test_a_bare_hex_root_pin_is_ed25519_and_names_only_itself(self):
        envelope = {"manifest": self.man, "signature": {"signer": "root", "key": self.entry["key"],
                                                        "sig": sign_p256(self.key, m.DOMAIN + m.canonical(self.man))}}
        self.refused("not the pinned root", m.verify_envelope, envelope, self.entry["key"][:64])


class Root(Case):
    """#156: the root on an offline Nitrokey too. The pinned root is one entry or a list; the algorithm comes
    from the pinned entry; a typed root signs only v3."""

    def root_envelope(self, man, key, entry):
        return {"manifest": man, "signature": {"signer": "root", "key": entry["key"], "sig": sign_p256(key, m.DOMAIN + m.canonical(man))}}

    def test_a_p256_root_signs_the_first_v3_manifest(self):
        key, entry = p256()
        first = m.accept(None, self.root_envelope(self.man, key, entry), entry)
        self.assertEqual((first["epoch"], first["schema"]), (1, m.SCHEMA_V3))
        self.assertEqual(m.accept(None, self.root_envelope(self.man, key, entry), [hbt.pub(hbt.ROOT), entry])["epoch"], 1)   # a root set

    def test_a_typed_root_cannot_sign_a_v2_manifest(self):
        key, entry = p256()
        v2 = dict(self.man, schema=m.SCHEMA_V2, revocation_keys=[hbt.pub(hbt.REVOKE)])
        self.refused("needs schema regalia.membership/v3", m.accept, None, self.root_envelope(v2, key, entry), entry)

    def test_the_root_s_algorithm_comes_from_the_pinned_entry(self):
        key, entry = p256()
        ed = {"manifest": self.man, "signature": {"signer": "root", "key": entry["key"],
                                                  "sig": hbt.ROOT.sign(m.DOMAIN + m.canonical(self.man)).hex()}}
        self.refused("does not verify", m.accept, None, ed, entry)                           # an Ed25519 signature under a P-256 root
        self.refused("not the pinned root", m.accept, None, self.root_envelope(self.man, key, entry), hbt.pub(hbt.ROOT))

    def test_a_malformed_root_pin_is_refused(self):
        for bad in ([], {"alg": "ecdsa-p256", "key": "00" * 65}, [hbt.pub(hbt.ROOT), hbt.pub(hbt.ROOT)], "AB" * 32):
            with self.subTest(bad=bad), self.assertRaises(m.Refused):
                m.root_entries(bad)


class Vectors(unittest.TestCase):
    """Fixed vectors, so another implementation (the Go port of accept(), ed's B3) checks the same bytes."""

    def test_the_vectors(self):
        doc = json.loads(VECTORS.read_text())
        for case in doc["cases"]:
            with self.subTest(case["name"]):
                message = bytes.fromhex(case["message"])
                if case["valid"]:
                    m.verify_revocation(case["alg"], case["key"], message, case["sig"], "vector")
                else:
                    with self.assertRaises(m.Refused):
                        m.verify_revocation(case["alg"], case["key"], message, case["sig"], "vector")
        for case in doc["manifests"]:
            with self.subTest(case["name"]):
                if case["valid"]:
                    self.assertEqual(m.accept(None, case["envelope"], case["root"])["epoch"], 1)
                else:
                    with self.assertRaises(m.Refused):
                        m.accept(None, case["envelope"], case["root"])


if __name__ == "__main__":
    unittest.main()
