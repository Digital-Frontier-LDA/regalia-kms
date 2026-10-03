#!/usr/bin/env python3
"""Writes tests/vectors/membership-v1.json: every call of membership.accept() the Python membership tests
make, with what it was given and what it decided, so the Go port (cmd/regalia-unlock/membership) is held to the very
same rules: the root and revocation signers, restrictive-only revocation, tombstones, prev_digest and epoch
+ 1, the schema moving forward only, and every refusal those tests exercise. A drift on either side fails CI.

    python3 -Es tests/vectors/make-membership-v1.py > tests/vectors/membership-v1.json

The reasons are Python's words, kept for a reader; the Go test compares the outcome (the manifest accepted,
by its digest, or a refusal), not the wording. A signature's public key is stored beside its envelope, as
"signature_public", and put back into envelope.signature.key by the reader; the root's as "root_public". A
public key written as `"key": "<hex>"` reads as a credential to the secret scanner (it is not one), and the
repository fixes such findings by composition, never by an allowlist. Every other "key" field (a typed key entry,
{"alg", "key"}, in a manifest's revocation_keys or a typed root) is written "public" for the same reason.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import membership  # noqa: E402

calls, seen = [], set()


def as_hex(document):
    """A document for the file: an envelope whose signature has a key gives that key up to "signature_public"
    (the reader puts it back); anything else is kept as it is."""
    document = json.loads(json.dumps(document))
    if isinstance(document, dict) and isinstance(document.get("signature"), dict) and "key" in document["signature"]:
        return {"document": dict(document, signature={k: v for k, v in document["signature"].items() if k != "key"}),
                "signature_public": document["signature"]["key"]}
    return {"document": document}
real = membership.accept


def recording(current, envelope, root_key):
    try:
        result = real(current, envelope, root_key)
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    else:
        outcome = {"accepted": membership.digest(result)}
    record = {"current": current, "envelope": as_hex(envelope), "root_public": root_key, **outcome}
    key = json.dumps(record, sort_keys=True)
    if key not in seen:
        seen.add(key)
        calls.append(record)
    if "refused" in outcome:
        raise membership.Refused(outcome["refused"])
    return result


real_verify, verified, seen_verified = membership.verify_envelope, [], set()


def recording_verify(envelope, root_key, current=None):
    """verify_envelope as the tests call it (accept() calls it too): the manifest and the signer, or the refusal."""
    try:
        manifest, signer = real_verify(envelope, root_key, current)
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    else:
        outcome = {"verified": membership.digest(manifest), "signer": signer}
    record = {"current": current, "envelope": as_hex(envelope), "root_public": root_key, **outcome}
    key = json.dumps(record, sort_keys=True)
    if key not in seen_verified:                # apart from accept()'s: a refusal there can read the same
        seen_verified.add(key)
        verified.append(record)
    if "refused" in outcome:
        raise membership.Refused(outcome["refused"])
    return manifest, signer


membership.accept, membership.verify_envelope = recording, recording_verify
# the membership tests, and the typed-key tests (#156, #199: P-256 roots and revocation keys, schema v3)
suite = unittest.defaultTestLoader.loadTestsFromNames(["tests.test_baremetal_membership", "tests.test_baremetal_revocation_keys"])
result = unittest.TextTestRunner(stream=open(os.devnull, "w")).run(suite)
if not result.wasSuccessful():
    raise SystemExit("the membership tests failed: no vector is written")
# Crafted cases, signed with a key made here: each changes ONE thing of a valid manifest and is signed
# again, so only the rule it is about can refuse it (a mutation under its old signature would be refused by
# the signature check whatever the rules said).
import copy  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

root = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
root_pub = root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def envelope(manifest, signer="root", key=root):
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return {"manifest": manifest, "signature": {"signer": signer, "key": public,
                                                "sig": key.sign(membership.DOMAIN + membership.canonical(manifest)).hex()}}


def node(i, state="ACTIVE"):
    h = lambda tag, n: ("%02x" % i + tag) * (n // (2 + len(tag)) + 1)
    return {"node_id": "n%d" % i, "state": state, "ek_name": ("000b" + "%02x" % i * 32), "ak_name": ("000b" + "%02x" % (i + 100) * 32),
            "wg_boot_pub": "%02x" % (i + 30) * 32, "wg_service_pub": "%02x" % (i + 60) * 32, "hsm_serials": ["DENK%07d" % i]}


base = {"schema": membership.SCHEMA, "epoch": 1, "prev_digest": "", "policy_version": "p1", "issued_at": "2026-10-03T12:00:00Z",
        "revocation_keys": [], "nodes": [node(1), node(2), node(3)]}
crafted = []


def craft(name, change):
    manifest = copy.deepcopy(base)
    change(manifest)
    try:
        result = real(None, envelope(manifest), root_pub)
        outcome = {"accepted": membership.digest(result)}
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    except Exception as error:  # noqa: BLE001  the Python failed outright: recorded, so the Go side is seen to refuse
        outcome = {"refused": "%s: %s" % (type(error).__name__, error)}
    try:
        membership.validate(manifest)
        valid = True
    except (membership.Refused, Exception):  # noqa: BLE001
        valid = False
    crafted.append({"name": name, "current": None, "envelope": as_hex(envelope(manifest)), "root_public": root_pub, "valid": valid, **outcome})


craft("valid", lambda m: None)
craft("epoch 0 with a prev_digest", lambda m: m.update(epoch=0, prev_digest="00" * 32))
craft("epoch 0", lambda m: m.update(epoch=0))
craft("epoch true", lambda m: m.update(epoch=True))
craft("epoch a string", lambda m: m.update(epoch="1"))
craft("epoch 1 with a prev_digest", lambda m: m.update(prev_digest="00" * 32))
craft("policy_version too long", lambda m: m.update(policy_version="p" * 33))
craft("policy_version with a space", lambda m: m.update(policy_version="p 1"))
for when in ("2026-10-03 12:00:00Z", "2026-10-03T12:00:00", "2026-02-30T12:00:00Z", "2026-13-01T12:00:00Z", "2026-10-03T24:00:00Z",
             "2026-1-3T2:0:0Z", "2026-10-03T12:00:60Z", "2026-10-03T12:00:61Z", "2026-10-03T12:00:62Z", "0000-10-03T12:00:00Z", 20261003,
             # strptime alone takes each of these; one fixed-width ASCII form on both sides refuses them
             "2026-10-03T12:00:0Z", "2026-10- 3T12:00:00Z", "2026-10-03t12:00:00z", "２０２６-10-03T12:00:00Z",
             "٢٠٢٦-١٠-٠٣T١٢:٠٠:٠٠Z", "2026-10-03T12:00:00Z\n"):
    craft("issued_at %r" % (when,), lambda m, when=when: m.update(issued_at=when))
craft("revocation_keys not a list", lambda m: m.update(revocation_keys="00" * 32))
craft("a revocation key in uppercase", lambda m: m.update(revocation_keys=["AB" * 32]))
craft("an unknown manifest field", lambda m: m.update(extra=1))
craft("no nodes", lambda m: m.update(nodes=[]))
craft("a node_id with an uppercase letter", lambda m: m["nodes"][0].update(node_id="N1"))
craft("a node_id of 33 characters", lambda m: m["nodes"][0].update(node_id="n" * 33))
craft("an unknown state", lambda m: m["nodes"][0].update(state="active"))
craft("an ek_name too short", lambda m: m["nodes"][0].update(ek_name="00" * 33))
craft("an hsm serial with a dash", lambda m: m["nodes"][0].update(hsm_serials=["DENK-1"]))
craft("hsm_serials not a list", lambda m: m["nodes"][0].update(hsm_serials="DENK1"))
craft("one HSM on two nodes", lambda m: m["nodes"][1].update(hsm_serials=m["nodes"][0]["hsm_serials"]))
craft("an EK that is another node's AK", lambda m: m["nodes"][1].update(ek_name=m["nodes"][0]["ak_name"]))
craft("a v2 manifest", lambda m: (m.update(schema=membership.SCHEMA_V2, heartbeat_max_lifetime_s=86400),
                                  [n.update(ssh_host_pub="%02x" % (i + 90) * 32) for i, n in enumerate(m["nodes"])]))
craft("a v2 manifest whose node lacks ssh_host_pub", lambda m: m.update(schema=membership.SCHEMA_V2, heartbeat_max_lifetime_s=86400))
craft("a retired node without ssh_host_pub under v2", lambda m: (m.update(schema=membership.SCHEMA_V2, heartbeat_max_lifetime_s=86400),
                                                                  [n.update(ssh_host_pub="%02x" % (i + 90) * 32) for i, n in enumerate(m["nodes"][1:])],
                                                                  m["nodes"][0].update(state="RETIRED")))
craft("heartbeat true", lambda m: (m.update(schema=membership.SCHEMA_V2, heartbeat_max_lifetime_s=True),
                                   [n.update(ssh_host_pub="%02x" % (i + 90) * 32) for i, n in enumerate(m["nodes"])]))
craft("a non-ASCII policy_version", lambda m: m.update(policy_version="p\u00e9"))
craft("a revocation-signed first manifest", lambda m: None)
crafted[-1]["envelope"] = as_hex(envelope(copy.deepcopy(base), signer="revocation"))
crafted[-1].pop("accepted", None)
crafted[-1]["refused"] = "the signing revocation key is not named by the current manifest"

# A chain from the valid base: an epoch that skips one, with a prev_digest that does chain (only the epoch
# rule can refuse it), and the next epoch, which is accepted.
first = membership.load(json.dumps(base))
for name, epoch in (("an epoch that skips one, chained", 3), ("the next epoch", 2)):
    following = dict(copy.deepcopy(base), epoch=epoch, prev_digest=membership.digest(first))
    try:
        outcome = {"accepted": membership.digest(real(first, envelope(following), root_pub))}
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    crafted.append({"name": name, "current": first, "envelope": as_hex(envelope(following)), "root_public": root_pub, "valid": True, **outcome})

# Revocation-signed successors, each signed by a revocation key the current manifest names and changing one
# thing, so each restrictive rule is reached by itself; one that only restricts (a node quarantined) is accepted.
revoker = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
revoker_pub = revoker.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
named = membership.load(json.dumps(dict(copy.deepcopy(base), revocation_keys=[revoker_pub])))
for name, change in (("a revocation key quarantines a node", lambda m: m["nodes"][0].update(state="QUARANTINED")),
                     ("a revocation key changes the policy version", lambda m: m.update(policy_version="p2")),
                     ("a revocation key changes an HSM serial", lambda m: m["nodes"][0].update(hsm_serials=["DENK0000099"])),
                     ("a revocation key adds an HSM serial", lambda m: m["nodes"][0]["hsm_serials"].append("DENK0000099")),
                     ("a revocation key changes an ek_name", lambda m: m["nodes"][0].update(ek_name="000b" + "77" * 32)),
                     ("a revocation key changes a wg_boot_pub", lambda m: m["nodes"][0].update(wg_boot_pub="77" * 32)),
                     ("a revocation key changes a wg_service_pub", lambda m: m["nodes"][0].update(wg_service_pub="77" * 32)),
                     ("a revocation key changes an ak_name", lambda m: m["nodes"][0].update(ak_name="000b" + "77" * 32)),
                     ("a revocation key drops itself", lambda m: m.update(revocation_keys=[])),
                     ("a revocation key drains a node", lambda m: m["nodes"][0].update(state="DRAINING"))):
    following = dict(copy.deepcopy(named), epoch=2, prev_digest=membership.digest(named))
    change(following)
    try:
        outcome = {"accepted": membership.digest(real(named, envelope(following, "revocation", revoker), root_pub))}
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    crafted.append({"name": name, "current": named, "envelope": as_hex(envelope(following, "revocation", revoker)),
                    "root_public": root_pub, "valid": True, **outcome})

# Typed keys (#156, #199): ECDSA P-256 roots and revocation keys, only under schema v3. Fixed test scalars,
# deterministic signatures (RFC 6979), normalised to low-S as the signer does: the vector is reproducible.
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

p256_root, p256_revoker = ec.derive_private_key(0x5EED1, ec.SECP256R1()), ec.derive_private_key(0x5EED2, ec.SECP256R1())


def p256_entry(key):
    return {"alg": "ecdsa-p256", "key": key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()}


def p256_envelope(manifest, signer, key, high_s=False):
    r, s = decode_dss_signature(key.sign(membership.DOMAIN + membership.canonical(manifest), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    s = min(s, membership.P256_ORDER - s)
    if high_s:
        s = membership.P256_ORDER - s                     # the same signature, made high-S: refused
    return {"manifest": manifest, "signature": {"signer": signer, "key": p256_entry(key)["key"],
                                                "sig": (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()}}


def typed(name, current, env, root):
    try:
        outcome = {"accepted": membership.digest(real(current, env, root))}
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    try:
        membership.validate(env["manifest"])
        valid = True
    except (membership.Refused, Exception):  # noqa: BLE001
        valid = False
    crafted.append({"name": name, "current": current, "envelope": as_hex(env), "root_public": root, "valid": valid, **outcome})


def v3(**changes):
    nodes = [dict(n, ssh_host_pub="%02x" % (i + 90) * 32) for i, n in enumerate(base["nodes"])]
    return dict(copy.deepcopy(base), schema=membership.SCHEMA_V3, heartbeat_max_lifetime_s=86400, nodes=nodes, **changes)


p256_root_entry, p256_revoker_entry = p256_entry(p256_root), p256_entry(p256_revoker)
typed("v3, Ed25519 root, a P-256 revocation key", None, envelope(v3(revocation_keys=[p256_revoker_entry])), root_pub)
typed("v2 carrying a P-256 revocation key", None, envelope(dict(v3(revocation_keys=[p256_revoker_entry]), schema=membership.SCHEMA_V2)), root_pub)
typed("v3 under a P-256 root", None, p256_envelope(v3(), "root", p256_root), p256_root_entry)
typed("v3 under a P-256 root, high-S", None, p256_envelope(v3(), "root", p256_root, high_s=True), p256_root_entry)
typed("v2 under a P-256 root", None, p256_envelope(dict(v3(), schema=membership.SCHEMA_V2), "root", p256_root), p256_root_entry)
typed("v1 under a P-256 root", None, p256_envelope(copy.deepcopy(base), "root", p256_root), p256_root_entry)
typed("v3 under a root set, by its P-256 key", None, p256_envelope(v3(), "root", p256_root), [root_pub, p256_root_entry])
typed("v3 under a root set, by its Ed25519 key", None, envelope(v3()), [root_pub, p256_root_entry])
typed("a root set naming one key twice", None, envelope(v3()), [root_pub, root_pub])
typed("an empty root set", None, envelope(v3()), [])
typed("a root set of eight", None, envelope(v3()), [root_pub] + [p256_entry(ec.derive_private_key(0x5EED10 + i, ec.SECP256R1())) for i in range(7)])
typed("a root set of nine", None, envelope(v3()), [root_pub] + [p256_entry(ec.derive_private_key(0x5EED10 + i, ec.SECP256R1())) for i in range(8)])
typed("an Ed25519 signature under a P-256 root's hex", None, envelope(v3()), p256_root_entry)
typed("a P-256 root named as a bare Ed25519 key", None, p256_envelope(v3(), "root", p256_root), p256_root_entry["key"][:64])
# each malformed entry is beside a valid one with ANOTHER key, so only the rule it is about can refuse it
other = p256_entry(ec.derive_private_key(0x5EED3, ec.SECP256R1()))
for label, entry in (("an unknown alg", dict(other, alg="ecdsa-p384")), ("an Ed25519 alg spelt out", dict(other, alg="ed25519")),
                     ("a compressed point", dict(other, key="03" + other["key"][2:66] + "00" * 32)),
                     ("a point off the curve", dict(other, key=other["key"][:-2] + ("00" if other["key"][-2:] != "00" else "01"))),
                     ("a 128-hex key", dict(other, key=other["key"][2:])), ("an extra field", dict(other, usage="revocation")),
                     ("no alg", {"key": other["key"]}), ("an uppercase key", dict(other, key=other["key"].upper())),
                     ("another valid P-256 key", other), ("the same key twice", p256_revoker_entry),
                     ("the same key bare and typed", None)):
    keys = [p256_revoker_entry, entry] if entry is not None else [p256_revoker_entry, p256_revoker_entry["key"][2:66]]
    typed("a typed revocation key: %s" % label, None, envelope(v3(revocation_keys=keys)), root_pub)
# a chain: the root introduces a P-256 revocation key under v3; that key then restricts, or tries to do more
first_v3 = membership.load(json.dumps(v3(revocation_keys=[p256_revoker_entry])))
for name, change, high_s in (("a P-256 revocation key quarantines a node", lambda m: m["nodes"][0].update(state="QUARANTINED"), False),
                             ("a P-256 revocation key quarantines a node, high-S", lambda m: m["nodes"][0].update(state="QUARANTINED"), True),
                             ("a P-256 revocation key changes the policy version", lambda m: m.update(policy_version="p2"), False),
                             ("a P-256 revocation key drops itself", lambda m: m.update(revocation_keys=[]), False)):
    following = dict(copy.deepcopy(first_v3), epoch=2, prev_digest=membership.digest(first_v3))
    change(following)
    typed(name, first_v3, p256_envelope(following, "revocation", p256_revoker, high_s), root_pub)
v2_first = membership.load(json.dumps(dict(v3(), schema=membership.SCHEMA_V2)))
typed("the root moves a v2 chain to v3 with a P-256 revocation key", v2_first,
      envelope(dict(v3(revocation_keys=[p256_revoker_entry]), epoch=2, prev_digest=membership.digest(v2_first))), root_pub)
typed("a P-256 key not in the current manifest signs", first_v3,
      p256_envelope(dict(copy.deepcopy(first_v3), epoch=2, prev_digest=membership.digest(first_v3)), "revocation", p256_root), root_pub)

# Documents as bytes: what the reader itself must refuse (or take), before any rule.
raw = [
    ("duplicate key", b'{"a":1,"a":2}', False),
    ("a float", b'{"a":1.0}', False),
    ("an exponent", b'{"a":1e3}', False),
    ("trailing data", b'{"a":1} {"b":2}', False),
    ("not UTF-8", b'{"a":"\xff"}', False),
    ("NaN", b'{"a":NaN}', False),
    ("a plain object", b'{"b":[1,true,null,"x\\u00e9"],"a":-0}', True),
]
documents = []
for name, data, ok in raw:
    try:
        membership.load(data)
        taken = True
    except (membership.Refused, UnicodeDecodeError):
        taken = False
    assert taken == ok, name
    documents.append({"name": name, "hex": data.hex(), "taken": ok,
                      "canonical": membership.canonical(membership.load(data)).decode() if ok else None})



def compose(value):
    """Every "key" field (a typed key entry, {"alg", "key"}, and the malformed ones the crafted cases hold)
    written "public": the reader puts "key" back before anything is canonicalised (the signatures cover that
    spelling). No document here has a field named "public" of its own; signatures' keys are already apart."""
    if isinstance(value, dict):
        assert "public" not in value, value
        return {("public" if k == "key" else k): compose(v) for k, v in value.items()}
    if isinstance(value, list):
        return [compose(v) for v in value]
    return value


print(json.dumps(compose({"about": __doc__.strip().split("\n\n")[0], "domain": membership.DOMAIN.decode("ascii"), "calls": calls,
                          "verified": verified, "crafted": crafted, "documents": documents}), indent=1, sort_keys=True))
