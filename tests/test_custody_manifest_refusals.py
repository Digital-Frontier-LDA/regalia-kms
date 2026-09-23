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
        # True is in this list on purpose: isinstance(True, int) is true and True >= 1, so
        # "maximum_age_days": true was accepted and read as ONE DAY, putting every object past its
        # rotation deadline immediately. envelope_max_age_days already excluded bool, and two
        # bounds disagreeing about the same authoring slip is how one of them gets trusted.
        for age in (0, -1, "365", None, 1.5, True, False):
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


    def test_a_commissioned_nitrokey_fingerprint_must_be_a_string(self):
        """Truthiness is not a type. A dict or a list here is truthy, reaches the regex and raises
        TypeError -- a traceback out of a validator whose entire contract is that a bad manifest
        produces a named refusal. The sibling public_fingerprint check already required a string."""
        for bad in ({"a": 1}, ["sha256:" + "a" * 64], 12345, True):
            with self.subTest(devaut=bad):
                obj = direct_key()
                obj["bindings"][0]["backend"] = "nitrokey-pkcs11"
                obj["bindings"][0]["state"] = "active"
                obj["bindings"][0]["device_serial"] = "DENK0404144"
                obj["bindings"][0]["devaut_fingerprint"] = bad
                self.assert_refused(obj, "devaut_fingerprint")

    def _nitrokey(self, **pins):
        obj = direct_key()
        b = obj["bindings"][0]
        b.update(backend="nitrokey-pkcs11", state="active", device_serial="DENK0404144")
        b.pop("devaut_fingerprint", None)
        b.update(pins)
        return obj

    def test_a_commissioned_nitrokey_may_be_pinned_by_its_public_key_alone(self):
        """ADR-0002 D1. A genuine SmartCard-HSM cannot expose its DevAut through PKCS#11, so a
        binding pinned by serial + public_key_sha256 must be admitted -- or no real Nitrokey could
        ever be commissioned. Mirrors nitrokeyIdentityPinned in the daemon's registry."""
        validate_manifest(manifest_with(self._nitrokey(public_key_sha256="sha256:" + "c" * 64)))

    def test_a_commissioned_nitrokey_needs_one_of_the_two_pins(self):
        """The advisory public_fingerprint every binding carries does NOT stand in for a pin."""
        self.assert_refused(self._nitrokey(), "devaut_fingerprint or public_key_sha256")

    def test_a_public_key_pin_on_a_symmetric_key_is_refused(self):
        obj = self._nitrokey(public_key_sha256="sha256:" + "c" * 64)
        obj["algorithm"] = "aes-256"
        obj["operations"] = ["unwrap"]
        self.assert_refused(obj, "symmetric key has no public half")

    def test_a_public_key_pin_must_be_a_sha256_string(self):
        for bad in ("not-a-digest", "SHA256:" + "c" * 64, {"a": 1}, 12345):
            with self.subTest(pin=bad):
                self.assert_refused(self._nitrokey(public_key_sha256=bad), "public_key_sha256")


if __name__ == "__main__":
    unittest.main()
