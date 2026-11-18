#!/usr/bin/env python3
"""Write custody-slot-rules-v1.json: manifests that the daemon and CI must judge alike.

regalia-kms-wd6. registry.Load (Go) and tools/custody_manifest.py (CI) each refuse a manifest
that:
- spells a driver-parsed object_id any way but lowercase hex ("object-id");
- assigns one declared hardware slot to two objects ("slot");
- binds a secret's KEK where an object declaring unwrap can reach it ("secret-kek",
  regalia-kms-091).

Before wd6 only the daemon did, so CI passed manifests the daemon then refused at start.

Each case is a whole manifest and the one verdict both validators must reach. `refused` is
null when the manifest must load, or a phrase the refusal must contain. The phrase is the same
in both languages, so a validator that refuses for some other reason fails the case instead of
passing it. Both suites read this one file: TestCustodySlotRuleVectors in
internal/registry/custody_slot_vectors_test.go and tests/test_custody_slot_vectors.py.

Every object is staging, so one binding is a complete object in both validators, and every
other field is one both accept. A case violates exactly one rule.

Run from the repository root: python3 -Es tests/vectors/make-custody-slot-rules-v1.py
"""
import copy
import json
import pathlib

KEY_A = "sha256:" + "a" * 64
KEY_B = "sha256:" + "b" * 64
FINGERPRINT = "sha256:" + "c" * 64

OBJECT_ID = "lowercase hex"
SLOT = "also assigned to"
SECRET_KEK = "declares unwrap"


def recovery():
    return {"mode": "shamir-2-of-3", "authority_id": "vector-root", "minimum_replicas": 2, "status": "planned"}


def common(object_id, kind, custody, algorithm, operations):
    return {
        "id": object_id, "name": object_id, "kind": kind, "classification": "restricted",
        "environment": "staging", "owner": "platform", "purpose": object_id, "custody": custody,
        "algorithm": algorithm, "operations": operations, "policy_id": "vector-policy",
        "bindings": [], "recovery": recovery(),
        "rotation": {"maximum_age_days": 90, "last_rotated": None},
        "migration": {"status": "planned", "source": "vector"},
        "verification": {"status": "planned", "last_verified": None, "evidence": "regalia-kms-wd6"},
    }


def nitrokey(device, object_id, serial=None, label=None, public_key=None, kek=False):
    binding = {"site": "sitea", "backend": "nitrokey-pkcs11", "device_id": device, "object_id": object_id,
               "public_fingerprint": FINGERPRINT, "state": "planned"}
    if serial is not None:
        binding["device_serial"] = serial
    if label is not None:
        binding["token_label"] = label
    if public_key is not None:
        binding["public_key_sha256"] = public_key
    if kek:
        binding["kek_algorithm"] = "rsa2048"
        binding["kek_version"] = "1"
    return binding


def secret(binding, object_id="vector-secret"):
    item = common(object_id, "api-token", "hardware-envelope", "opaque", ["release-secret"])
    item["bindings"] = [dict(binding, kek_algorithm="rsa2048", kek_version="1")]
    return item


def keyed(object_id, operation, binding, algorithm="rsa2048"):
    item = common(object_id, "asymmetric-key", "direct-hardware", algorithm, [operation])
    item["bindings"] = [binding]
    return item


def unwrap(binding, object_id="vector-unwrap"):
    return keyed(object_id, "unwrap", binding)


def yubikey(backend, object_id, algorithm):
    binding = {"site": "sitea", "backend": backend, "device_id": "yk-1", "device_serial": "35000001",
               "object_id": object_id, "public_fingerprint": FINGERPRINT, "state": "planned",
               "pin_policy": "once", "touch_policy": "never"}
    if backend == "yubikey-openpgp":
        binding["token_label"] = "OpenPGP card (User PIN (sig))"
    return keyed("vector-yubikey", "sign", binding, algorithm)


SECRET = nitrokey("nk-1", "01", serial="S1", public_key=KEY_A)
DEVAUT_ONLY = nitrokey("nk-1", "0a", serial="S1")

CASES = [
    # object-id: the drivers parse these, so only one spelling names a key.
    ("a canonical PKCS#11 object id", [unwrap(nitrokey("nk-2", "0a", serial="S2"))], None),
    ("a canonical PKCS#11 object id of 64 bytes", [unwrap(nitrokey("nk-2", "ab" * 64, serial="S2"))], None),
    ("a canonical PIV slot", [yubikey("yubikey-piv", "9c", "p256")], None),
    ("a canonical OpenPGP-applet object id", [yubikey("yubikey-openpgp", "03", "ed25519")], None),
    ("an upper-case PKCS#11 object id", [unwrap(nitrokey("nk-2", "0A", serial="S2"))], OBJECT_ID),
    ("an odd-length PKCS#11 object id", [unwrap(nitrokey("nk-2", "a", serial="S2"))], OBJECT_ID),
    ("a 0x-prefixed PKCS#11 object id", [unwrap(nitrokey("nk-2", "0x0a", serial="S2"))], OBJECT_ID),
    ("a named PKCS#11 object id", [unwrap(nitrokey("nk-2", "slot-1", serial="S2"))], OBJECT_ID),
    ("a PKCS#11 object id of 65 bytes", [unwrap(nitrokey("nk-2", "ab" * 65, serial="S2"))], OBJECT_ID),
    ("an upper-case PIV slot", [yubikey("yubikey-piv", "9C", "p256")], OBJECT_ID),
    ("a 0x-prefixed PIV slot", [yubikey("yubikey-piv", "0x9c", "p256")], OBJECT_ID),
    ("a zero-padded PIV slot", [yubikey("yubikey-piv", "09c", "p256")], OBJECT_ID),
    ("an upper-case OpenPGP-applet object id", [yubikey("yubikey-openpgp", "0A", "ed25519")], OBJECT_ID),
    # review F1, probes A and B: re-casing the object id reached the secret's KEK.
    ("probe A: the secret pins its key, the unwrap object re-cases object_id",
     [secret(nitrokey("nk-1", "0a", serial="S1", public_key=KEY_A)), unwrap(nitrokey("nk-2", "0A", serial="S1"))], OBJECT_ID),
    ("probe B: the secret pins DevAut only, the unwrap object re-cases object_id and pins the key",
     [secret(DEVAUT_ONLY), unwrap(nitrokey("nk-2", "0A", serial="S1", public_key=KEY_A))], OBJECT_ID),

    # slot: one declared slot is (site, device_id, object_id, token_label).
    ("two objects on two declared slots",
     [keyed("vector-sign-a", "sign", nitrokey("nk-1", "01")), keyed("vector-sign-b", "sign", nitrokey("nk-1", "02"))], None),
    ("two objects on two labelled tokens of one declared slot",
     [keyed("vector-sign-a", "sign", nitrokey("nk-1", "01", label="Token one")),
      keyed("vector-sign-b", "sign", nitrokey("nk-1", "01", label="Token two"))], None),
    ("the same declared slot at two sites",
     [keyed("vector-sign-a", "sign", nitrokey("nk-1", "01")),
      keyed("vector-sign-b", "sign", dict(nitrokey("nk-1", "01"), site="siteb"))], None),
    ("two objects on one declared slot",
     [keyed("vector-sign-a", "sign", nitrokey("nk-1", "01")), keyed("vector-sign-b", "sign", nitrokey("nk-1", "01"))], SLOT),
    ("two objects on one labelled token",
     [keyed("vector-sign-a", "sign", nitrokey("nk-1", "01", label="Token one")),
      keyed("vector-sign-b", "sign", nitrokey("nk-1", "01", label="Token one"))], SLOT),
    ("an unlabelled binding shares a slot with a labelled one",
     [keyed("vector-sign-a", "sign", nitrokey("nk-1", "01", label="Token one")),
      keyed("vector-sign-b", "sign", nitrokey("nk-1", "01"))], SLOT),
    ("the plain shared slot of a secret and an unwrap object is answered by the slot rule first",
     [secret(SECRET), unwrap(nitrokey("nk-1", "01", serial="S1"))], SLOT),

    # secret-kek (regalia-kms-091): a secret's KEK must not be reachable through unwrap.
    ("another card", [secret(SECRET), unwrap(nitrokey("nk-2", "01", serial="S2", public_key=KEY_B))], None),
    ("another key on the same card", [secret(SECRET), unwrap(nitrokey("nk-2", "02", serial="S1", public_key=KEY_B))], None),
    ("an unpinned card with no serial", [secret(SECRET), unwrap(nitrokey("nk-2", "01"))], None),
    ("the other labelled token of the same card",
     [secret(nitrokey("nk-1", "01", serial="S1", label="Token one", public_key=KEY_A)),
      unwrap(nitrokey("nk-2", "01", serial="S1", label="Token two", public_key=KEY_B))], None),
    ("a sign key aliasing a secret's KEK",
     [secret(SECRET), keyed("vector-sign", "sign", nitrokey("nk-2", "01", serial="S1", public_key=KEY_A))], None),
    ("the same card under another device id",
     [secret(SECRET), unwrap(nitrokey("nk-2", "01", serial="S1", public_key=KEY_B))], SECRET_KEK),
    ("the same card, the unwrap binding unlabelled and unpinned",
     [secret(SECRET), unwrap(nitrokey("nk-2", "01", serial="S1"))], SECRET_KEK),
    ("the same public key on another card",
     [secret(SECRET), unwrap(nitrokey("nk-2", "09", serial="S2", public_key=KEY_A))], SECRET_KEK),
    ("a labelled token of the card whose secret binding is unlabelled",
     [secret(SECRET), unwrap(nitrokey("nk-2", "01", serial="S1", label="Other token", public_key=KEY_B))], SECRET_KEK),
    ("the unwrap object listed first",
     [unwrap(nitrokey("nk-2", "01", serial="S1")), secret(SECRET)], SECRET_KEK),
    ("probe B': the secret pins DevAut only, the unwrap object pins the key on the same slot",
     [secret(DEVAUT_ONLY), unwrap(nitrokey("nk-2", "0a", serial="S1", public_key=KEY_A))], SECRET_KEK),
    ("the same slot, neither binding pinning a key",
     [secret(DEVAUT_ONLY), unwrap(nitrokey("nk-2", "0a", serial="S1"))], SECRET_KEK),
    # review F2: another object's pin says which key the secret's slot holds.
    ("F2 control: the secret's slot is pinned to another key",
     [secret(DEVAUT_ONLY), keyed("vector-sign", "sign", nitrokey("nk-3", "0a", serial="S1", public_key=KEY_B)),
      unwrap(nitrokey("nk-2", "09", serial="S2", public_key=KEY_A))], None),
    ("F2: an unwrap binding pins the key another object pins in the secret's slot",
     [secret(DEVAUT_ONLY), keyed("vector-sign", "sign", nitrokey("nk-3", "0a", serial="S1", public_key=KEY_A)),
      unwrap(nitrokey("nk-2", "09", serial="S2", public_key=KEY_A))], SECRET_KEK),
]


def main():
    cases = []
    for name, objects, refused in CASES:
        cases.append({
            "name": name,
            "refused": refused,
            "manifest": {"schema_version": 1, "manifest_id": "custody-slot-rules-v1",
                         "generated_at": "2026-11-11T00:00:00Z", "objects": copy.deepcopy(objects)},
        })
    names = [case["name"] for case in cases]
    assert len(names) == len(set(names)), "case names must be unique: each suite reports by name"
    document = {
        "vector": "custody-slot-rules-v1",
        "generator": "tests/vectors/make-custody-slot-rules-v1.py",
        "site": "sitea",
        "cases": cases,
    }
    out = pathlib.Path(__file__).resolve().parent / "custody-slot-rules-v1.json"
    out.write_text(json.dumps(document, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print("%s: %d cases (%d refused)" % (out.name, len(cases), sum(1 for c in cases if c["refused"])))


if __name__ == "__main__":
    main()
