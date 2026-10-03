#!/usr/bin/env python3
"""Writes tests/vectors/membership-v1.json: every call of membership.accept() the Python membership tests
make, with what it was given and what it decided, so the Go port (cmd/regalia-unlock/membership) is held to the very
same rules: the root and revocation signers, restrictive-only revocation, tombstones, prev_digest and epoch
+ 1, the schema moving forward only, and every refusal those tests exercise. A drift on either side fails CI.

    python3 -Es tests/vectors/make-membership-v1.py > tests/vectors/membership-v1.json

The reasons are Python's words, kept for a reader; the Go test compares the outcome (the manifest accepted,
by its digest, or a refusal), not the wording.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from deploy.baremetal import membership  # noqa: E402

calls, seen = [], set()
real = membership.accept


def recording(current, envelope, root_key):
    try:
        result = real(current, envelope, root_key)
    except membership.Refused as refusal:
        outcome = {"refused": str(refusal)}
    else:
        outcome = {"accepted": membership.digest(result)}
    record = {"current": current, "envelope": envelope, "root_key": root_key, **outcome}
    key = json.dumps(record, sort_keys=True)
    if key not in seen:
        seen.add(key)
        calls.append(record)
    if "refused" in outcome:
        raise membership.Refused(outcome["refused"])
    return result


membership.accept = recording
suite = unittest.defaultTestLoader.loadTestsFromName("tests.test_baremetal_membership")
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
    crafted.append({"name": name, "current": None, "envelope": envelope(manifest), "root_key": root_pub, "valid": valid, **outcome})


craft("valid", lambda m: None)
craft("epoch 0 with a prev_digest", lambda m: m.update(epoch=0, prev_digest="00" * 32))
craft("epoch 0", lambda m: m.update(epoch=0))
craft("epoch true", lambda m: m.update(epoch=True))
craft("epoch a string", lambda m: m.update(epoch="1"))
craft("epoch 1 with a prev_digest", lambda m: m.update(prev_digest="00" * 32))
craft("policy_version too long", lambda m: m.update(policy_version="p" * 33))
craft("policy_version with a space", lambda m: m.update(policy_version="p 1"))
for when in ("2026-10-03 12:00:00Z", "2026-10-03T12:00:00", "2026-02-30T12:00:00Z", "2026-13-01T12:00:00Z", "2026-10-03T24:00:00Z",
             "2026-1-3T2:0:0Z", "2026-10-03T12:00:60Z", "2026-10-03T12:00:61Z", "2026-10-03T12:00:62Z", "0000-10-03T12:00:00Z", 20261003):
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
crafted[-1]["envelope"] = envelope(copy.deepcopy(base), signer="revocation")
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
    crafted.append({"name": name, "current": first, "envelope": envelope(following), "root_key": root_pub, "valid": True, **outcome})

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

print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "domain": membership.DOMAIN.decode("ascii"), "calls": calls,
                  "crafted": crafted, "documents": documents}, indent=1, sort_keys=True))
