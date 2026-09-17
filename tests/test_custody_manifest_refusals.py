"""Validator refusals that had no test.

The custody manifest is a PROMISE: anything it admits is something an operator may commission and
expect to work. Every rule here is one an unenforced version of would let a manifest through that
the daemon, the drivers or the ceremony cannot actually honour -- and the failure then arrives
when somebody needs the key.

These are the `fail(...)` branches the existing suite does not reach.
"""

import unittest

from tools.custody_manifest import ManifestError, validate_manifest
from tests.test_custody_manifest import direct_key, manifest_with


def fido_credential():
    """A valid FIDO custody record: non-exportable credentials, two enrollments, two sites."""
    return {
        "id": "admin-console-fido",
        "name": "Administrative console FIDO",
        "kind": "fido-credential",
        "classification": "critical",
        "environment": "production",
        "owner": "operations",
        "purpose": "administrator-authentication",
        "custody": "fido-multi-enrollment",
        "algorithm": "device-managed",
        "operations": ["authenticate"],
        "policy_id": "admin-console",
        "bindings": [
            {"site": "custodian-a", "backend": "fido2", "device_id": "fido-a",
             "object_id": "01", "key_check": "sha256:" + "1" * 64, "state": "planned"},
            {"site": "custodian-b", "backend": "fido2", "device_id": "fido-b",
             "object_id": "01", "key_check": "sha256:" + "2" * 64, "state": "planned"},
        ],
        "recovery": {"mode": "multi-enrollment", "status": "planned"},
        "rotation": {"maximum_age_days": 365, "last_rotated": None},
        "migration": {"status": "planned", "source": "external:console"},
        "verification": {"status": "planned", "last_verified": None, "evidence": "issue:23"},
    }


class ManifestRefusalTests(unittest.TestCase):
    def assert_refused(self, obj, message):
        with self.assertRaisesRegex(ManifestError, message):
            validate_manifest(manifest_with(obj))

    def test_the_fixtures_are_valid(self):
        """The control. Every refusal below is otherwise satisfied by a validator that refuses
        everything, and the suite would pin nothing."""
        validate_manifest(manifest_with(direct_key()))
        validate_manifest(manifest_with(fido_credential()))

    def test_fido_custody_requires_the_fido_kind_and_only_fido2_bindings(self):
        """A FIDO custody record describes credentials nothing here operates. Letting it carry
        another kind, or a binding on a real backend, would put an object the daemon must treat as
        inventory back onto a routing path -- which is the defect #130 fixed on the daemon side.
        The manifest is where it should have been refused first."""
        wrong_kind = fido_credential()
        wrong_kind["kind"] = "asymmetric-key"
        self.assert_refused(wrong_kind, "FIDO custody requires kind=fido-credential")

        # The other half of that clause -- a non-fido2 binding under FIDO custody -- is refused
        # EARLIER, by the capability matrix, and this test says so rather than claiming the FIDO
        # rule caught it. `device-managed/authenticate` is advertised by fido2 alone, so any other
        # backend fails "backend does not support ..." before the custody clause is reached.
        #
        # The clause is therefore defence in depth against a future backend that advertised
        # device-managed. It stays, and nothing here pretends to exercise it.
        wrong_backend = fido_credential()
        wrong_backend["bindings"][1]["backend"] = "nitrokey-pkcs11"
        self.assert_refused(wrong_backend, "backend does not support device-managed/authenticate")

    def test_a_fido2_binding_outside_fido_custody_is_refused(self):
        """The inverse: a fido2 binding on an object whose custody says it is operated would
        promise a provider that does not exist.

        Refused by the capability matrix rather than by the custody clause, and the assertion
        names that. fido2 advertises only `device-managed/authenticate`, so a fido2 binding on a
        signing key fails "backend does not support secp256k1/sign" first. Asserting the custody
        message would pin a layer that is not doing the work -- and would start failing, with a
        misleading diagnosis, the day the matrix changed.
        """
        smuggled = direct_key()
        smuggled["bindings"][0]["backend"] = "fido2"
        self.assert_refused(smuggled, "backend does not support secp256k1/sign")

    def test_shamir_recovery_requires_exactly_two_replicas(self):
        """4-of-6 shares are useless if the material they reconstruct exists in one place. The
        rule is `== 2`, not `>= 2`, so both directions are driven."""
        for replicas in (1, 3, 0, None, "2"):
            with self.subTest(replicas=replicas):
                obj = direct_key()
                obj["recovery"]["minimum_replicas"] = replicas
                self.assert_refused(obj, "minimum_replicas")

    def test_rotation_age_must_be_a_positive_integer(self):
        """Zero or a negative maximum age is a rotation deadline already in the past for every
        object, which would make the deadline meaningless rather than strict. A string is the
        JSON-authoring slip that would otherwise compare oddly."""
        for age in (0, -1, "365", None, 1.5):
            with self.subTest(age=age):
                obj = direct_key()
                obj["rotation"]["maximum_age_days"] = age
                self.assert_refused(obj, "maximum_age_days")

    def test_identifiers_and_purposes_must_be_kebab_case(self):
        """The id and purpose reach the registry, the policy engine and the audit journal as
        keys. Anything that needs quoting or normalising is a value two of those three might
        disagree about."""
        for bad in ("Prod Wallet", "prod_wallet_signer", "PROD-WALLET", "ab", "x" * 64, ""):
            with self.subTest(identifier=bad):
                obj = direct_key()
                obj["id"] = bad
                self.assert_refused(obj, r"\.id")
            with self.subTest(purpose=bad):
                obj = direct_key()
                obj["purpose"] = bad
                self.assert_refused(obj, r"\.purpose")

    def test_operations_must_be_a_non_empty_string_list(self):
        """An object with no operations is one nothing may do anything with, which is a manifest
        entry that cannot be commissioned -- and an operations value that is not a list of strings
        is one the registry would iterate into something unintended."""
        for operations in ([], "sign", [""], ["sign", 1], None, {}):
            with self.subTest(operations=operations):
                obj = direct_key()
                obj["operations"] = operations
                self.assert_refused(obj, "operations")

    def test_a_fingerprint_must_be_sha256_and_64_lowercase_hex(self):
        """The fingerprint is how a commissioned key is recognised. Uppercase hex, a truncated
        digest, or another algorithm are all values that look like a fingerprint and identify
        nothing -- and a comparison against them would silently never match."""
        for bad in (
            "sha256:" + "A" * 64,
            "sha256:" + "a" * 63,
            "sha256:" + "a" * 65,
            "sha1:" + "a" * 64,
            "a" * 64,
            "sha256:",
        ):
            with self.subTest(fingerprint=bad):
                obj = direct_key()
                obj["bindings"][0]["public_fingerprint"] = bad
                self.assert_refused(obj, "sha256 followed by 64 lowercase hex digits")


if __name__ == "__main__":
    unittest.main()
