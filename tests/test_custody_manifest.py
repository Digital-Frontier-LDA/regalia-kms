import copy
import datetime
import json
import tempfile
import unittest
from pathlib import Path

from tests.source_lexing import shell_code

import tools.custody_manifest as custody_manifest
from tools.custody_manifest import (
    BACKENDS,
    CLASSIFICATIONS,
    CUSTODY_MODES,
    KINDS,
    STATES,
    ManifestError,
    load_and_validate,
    validate_manifest,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "config" / "custody-manifest.example.json"
SCHEMA = ROOT / "config" / "custody-manifest.schema.json"


def direct_key():
    return {
        "id": "prod-wallet-signer",
        "name": "Production wallet signer",
        "kind": "asymmetric-key",
        "classification": "critical",
        "environment": "production",
        "owner": "treasury",
        "purpose": "cosmos-transaction",
        "custody": "direct-hardware",
        "algorithm": "secp256k1",
        "operations": ["sign"],
        "policy_id": "cosmos-hot-wallet",
        "bindings": [
            {
                "site": "lisbon",
                "backend": "nitrokey-pkcs11",
                "device_id": "nitrokey-lisbon",
                "object_id": "01",
                "public_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "state": "planned",
            },
            {
                "site": "porto",
                "backend": "nitrokey-pkcs11",
                "device_id": "nitrokey-porto",
                "object_id": "01",
                "public_fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "state": "planned",
            },
        ],
        "recovery": {
            "mode": "shamir-4-of-6",
            "authority_id": "company-root-2026",
            "minimum_replicas": 2,
            "status": "planned",
        },
        "rotation": {"maximum_age_days": 365, "last_rotated": None},
        "migration": {"status": "planned", "source": "external:tx-signer"},
        "verification": {"status": "planned", "last_verified": None, "evidence": "issue:27"},
    }


def manifest_with(*objects):
    return {
        "schema_version": 1,
        "manifest_id": "regalia-company-custody",
        "generated_at": "2026-09-03T00:00:00Z",
        "objects": list(objects),
    }


class CustodyManifestTests(unittest.TestCase):
    def assert_invalid(self, manifest, message):
        with self.assertRaisesRegex(ManifestError, message):
            validate_manifest(manifest)

    def test_repository_example_is_valid(self):
        loaded = load_and_validate(EXAMPLE)
        self.assertGreaterEqual(len(loaded["objects"]), 4)

    def test_published_schema_matches_validator_enums(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        object_properties = schema["$defs"]["custodyObject"]["properties"]
        binding_properties = schema["$defs"]["binding"]["properties"]
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertEqual(set(object_properties["kind"]["enum"]), KINDS)
        self.assertEqual(set(object_properties["classification"]["enum"]), CLASSIFICATIONS)
        self.assertEqual(set(object_properties["custody"]["enum"]), CUSTODY_MODES)
        self.assertEqual(set(binding_properties["backend"]["enum"]), BACKENDS)
        # binding.state was the one enum here with no guard on either side, and it is the one that
        # diverged: #160 added "revoked" to the Go loader and to neither this validator nor the
        # schema, so the daemon accepted a manifest CI refused. The Go mirror of this assertion is
        # TestBindingStatesMatchThePublishedSchema.
        self.assertEqual(set(binding_properties["state"]["enum"]), STATES)

    def test_duplicate_object_ids_are_rejected(self):
        obj = direct_key()
        self.assert_invalid(manifest_with(obj, copy.deepcopy(obj)), "duplicate object id")

    def test_envelope_max_age_is_optional_and_must_be_a_positive_count_of_days(self):
        """The bound on how old an envelope may be at release.

        OMITTING IT MEANS UNBOUNDED, and that is the case worth protecting: a lifetime bound is the
        one control here that causes an outage by working correctly, so every existing manifest must
        keep loading unchanged. Zero and negative are refused rather than read as "expire
        everything", because "no bound" already has a spelling and it is absence.

        Checked here as well as in the JSON schema because CI and the daemon must refuse the same
        manifest — the Go loader reads this field too, and a manifest one of them accepts and the
        other rejects is the failure mode #6 keeps producing.
        """
        obj = direct_key()
        self.assertNotIn("envelope_max_age_days", obj["rotation"])
        validate_manifest(manifest_with(obj))

        obj["rotation"]["envelope_max_age_days"] = 90
        validate_manifest(manifest_with(copy.deepcopy(obj)))

        for value in (0, -1, "ninety", 1.5, True):
            with self.subTest(value=value):
                bad = copy.deepcopy(obj)
                bad["rotation"]["envelope_max_age_days"] = value
                self.assert_invalid(manifest_with(bad), "positive integer of days")

    def test_the_schema_publishes_the_envelope_bound_the_validator_accepts(self):
        """A field the validator takes and the schema forbids is a manifest nothing can write.

        `rotation` is `additionalProperties: false`, so the schema is not silent about unknown
        keys — it rejects them. The two must agree or the field is unusable in practice.
        """
        schema = json.loads(SCHEMA.read_text())
        properties = schema["$defs"]["rotation"]["properties"]
        self.assertIn("envelope_max_age_days", properties,
                      "the validator accepts envelope_max_age_days and the schema rejects it as an unknown property")
        self.assertNotIn("envelope_max_age_days", schema["$defs"]["rotation"]["required"],
                         "the bound must stay optional: requiring it would expire envelopes for every existing object")
        self.assertEqual(properties["envelope_max_age_days"].get("minimum"), 1,
                         "the schema must refuse zero the way the validator does")

    def test_verified_object_requires_timestamp_and_evidence(self):
        obj = direct_key()
        obj["verification"] = {"status": "verified", "last_verified": None, "evidence": "drill:1"}
        self.assert_invalid(manifest_with(obj), "require a timestamp")
        # DERIVED FROM TODAY, NOT WRITTEN DOWN. validate_object refuses a verified object whose
        # last_verified is older than VERIFICATION_MAX_AGE_DAYS, so a literal timestamp turns this
        # test into a time bomb: it passes until the date crosses that bound and then fails with
        # no code change, in a suite whose failures are supposed to mean something broke.
        recent = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        obj["verification"] = {"status": "verified", "last_verified": recent, "evidence": "drill:1"}
        validate_manifest(manifest_with(obj))

    def test_secret_bearing_field_names_are_rejected_at_any_depth(self):
        obj = direct_key()
        obj["recovery"]["mnemonic"] = "abandon " * 12
        self.assert_invalid(manifest_with(obj), "forbidden secret-bearing field")

    def test_private_material_patterns_are_rejected_in_strings(self):
        obj = direct_key()
        # Composed rather than written whole, like the shapes below. The VALUE is the same
        # one main has; only the form changed, and it changed for a reason that is not
        # visible here. On main this literal is not flagged -- gitleaks' private-key rule
        # spans lines and there is no closing anchor within range. The headers this change
        # adds further down supply one, so the rule began matching from a line nobody
        # edited. A scanner finding that depends on what is written elsewhere in the file
        # is not something a diff review can predict, which is why the whole tree is scanned.
        obj["migration"]["source"] = "-----BEGIN " + "PRIVATE KEY-----"
        self.assert_invalid(manifest_with(obj), "private material")

    def test_production_direct_key_requires_two_distinct_bindings(self):
        obj = direct_key()
        obj["bindings"] = obj["bindings"][:1]
        self.assert_invalid(manifest_with(obj), "at least 2 hardware bindings")

    def test_production_direct_key_bindings_must_have_distinct_devices(self):
        obj = direct_key()
        obj["bindings"][1]["device_id"] = obj["bindings"][0]["device_id"]
        self.assert_invalid(manifest_with(obj), "distinct devices")

    def test_direct_hardware_custody_cannot_use_software_backend(self):
        obj = direct_key()
        obj["bindings"][0]["backend"] = "software"
        self.assert_invalid(manifest_with(obj), "unsupported backend")

    def test_object_without_a_public_key_can_use_a_key_check(self):
        """An object with no public half proves its identity with a key check.

        This used aes-256/unwrap, which the capability table advertised and the
        PKCS#11 driver refuses -- so the fixture exercised a binding no daemon
        would accept. `opaque` is the non-public-key algorithm a backend
        actually implements. Symmetric keys remain unimplementable until a
        driver supports one; that is a real gap, not a schema question, and it
        should not be papered over by a fixture.

        The move to opaque/release-secret did not escape that problem, only
        relocated it: release-secret unwraps on the card too, and "opaque" is
        no more acceptable to the driver than aes-256 was. The binding now
        names the KEK in its slot, which is the thing the token is asked for.
        """
        obj = direct_key()
        obj.update(kind="opaque-secret", algorithm="opaque", operations=["release-secret"])
        for binding in obj["bindings"]:
            del binding["public_fingerprint"]
            binding["key_check"] = "sha256:" + "f" * 64
            binding["kek_algorithm"] = "rsa2048"
            binding["kek_version"] = "1"
        validate_manifest(manifest_with(obj))

    def test_release_secret_binding_must_name_a_kek_the_backend_can_unwrap_with(self):
        """A commissioned secret must name the key that can actually open it.

        Without this, an opaque object passed every check in CI and in the
        daemon, then failed at its first release with a retryable error that
        would never stop being retried. The Go loader enforces the same rule;
        a manifest CI accepts and the daemon refuses is the same defect facing
        the other way.
        """
        def opaque(kek, version="1"):
            obj = direct_key()
            obj.update(kind="opaque-secret", algorithm="opaque", operations=["release-secret"])
            for binding in obj["bindings"]:
                if kek is not None:
                    binding["kek_algorithm"] = kek
                if version is not None:
                    binding["kek_version"] = version
            return manifest_with(obj)

        self.assert_invalid(opaque(None), "must name the kek_algorithm")
        self.assert_invalid(opaque("ed25519"), "cannot unwrap with kek_algorithm")
        self.assert_invalid(opaque("opaque"), "cannot unwrap with kek_algorithm")
        # Rotation needs a generation to compare against: without one, an envelope wrapped under a
        # superseded key opens on whatever replaced it in the same slot.
        self.assert_invalid(opaque("rsa2048", version=None), "must name the kek_version")
        # A named-but-unusable version is a different mistake from an absent one: reporting both as
        # "must name the kek_version" tells an operator to supply a field they can see.
        self.assert_invalid(opaque("rsa2048", version="has space"), "must match")
        with self.assertRaises(ManifestError) as caught:
            validate_manifest(opaque("rsa2048", version="has space"))
        self.assertNotIn("must name the kek_version", str(caught.exception))
        validate_manifest(opaque("rsa2048"))

    def test_malformed_kek_fields_are_manifest_errors_not_tracebacks(self):
        """A validator must never crash on the input it exists to reject.

        kek_algorithm went straight into a dict lookup and kek_version into a
        regex, so a list or an object raised TypeError. An operator reading a
        traceback cannot tell whether the manifest is wrong or the checker is.
        """
        for field in ("kek_algorithm", "kek_version"):
            for value in ([], {}, 7, "", ["rsa2048"], {"a": 1}):
                obj = direct_key()
                obj.update(kind="opaque-secret", algorithm="opaque", operations=["release-secret"])
                for binding in obj["bindings"]:
                    binding["kek_algorithm"] = "rsa2048"
                    binding["kek_version"] = "1"
                    binding[field] = value
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ManifestError):
                        validate_manifest(manifest_with(obj))

    def test_release_secret_is_refused_on_backends_the_table_does_not_admit(self):
        """The JSON Schema cannot express this; both validators can and do.

        `release-secret` appears only under nitrokey-pkcs11 in the capability
        table, so binding it to a YubiKey satisfies the schema and then fails.
        The schema could only catch it by duplicating the table, which #73
        removed for good reasons -- so the containment lives here and in
        registry.validateBinding, both of which read the exported table.
        """
        for backend in ("yubikey-piv", "yubikey-openpgp"):
            obj = direct_key()
            obj.update(kind="opaque-secret", algorithm="opaque", operations=["release-secret"])
            for binding in obj["bindings"]:
                binding.update(backend=backend, kek_algorithm="rsa2048", kek_version="1",
                               pin_policy="once", touch_policy="never", device_serial="yubi-1")
                binding.pop("devaut_fingerprint", None)
            with self.subTest(backend=backend):
                self.assert_invalid(manifest_with(obj), "does not support opaque/release-secret")

    def test_every_declared_private_pattern_is_refused_in_a_plain_string(self):
        """One sample per pattern, in `notes`, which no field-name rule would catch.

        The patterns were added together and only the PEM path was exercised, so most of
        them were declared and never shown to fire. No count is written here: an earlier
        version said "four of the six" and went stale the moment a seventh pattern was
        added, which is a small instance of the thing this test exists to prevent -- a
        statement about a set that nothing reconciles with the set. A list of detectors where most
        entries are untested is the same shape as a matrix advertising an operation with
        no endpoint: the entry is the claim, and nothing checks it.

        Samples only -- the pattern sources are never written here. My first version keyed
        this by the pattern string, which meant spelling out `-----BEGIN OPENSSH PRIVATE
        KEY-----` as a dict key, and the repository's own secret scan flagged the test
        that exists to catch pasted credentials. Matching each sample against the compiled
        patterns gives the same bidirectional coverage without restating them.
        """
        samples = [
            "-----BEGIN " + "EC PRIVATE KEY-----",
            "AGE-SECRET-KEY-1" + "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ",
            "ghp_" + "0123456789abcdef0123456789abcdef0123",
            "github_pat_" + "11ABCDEFG0aBcDeFgHiJkL_mNoPqRsTuVwXyZ",
            "AKIA" + "IOSFODNN7EXAMPLE",
            "xoxb-" + "1234567890-abcdefghij",
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
        ]

        # Every compiled pattern must fire on something here. A pattern with no sample is a
        # detector nobody has seen work, which is what four of these were.
        for pattern in custody_manifest.PRIVATE_PATTERNS:
            self.assertTrue(any(pattern.search(sample) for sample in samples),
                            f"the pattern {pattern.pattern!r} matches none of the samples: it is "
                            "declared and has never been shown to fire")

        # And every sample must be refused by the validator, which is the property that
        # matters -- a pattern that matches in isolation but is never consulted is worse.
        for sample in samples:
            with self.subTest(sample=sample[:24]):
                obj = direct_key()
                obj["notes"] = sample
                self.assert_invalid(manifest_with(obj), "private material")

    def test_the_shapes_the_secret_scan_selftest_plants_are_refused(self):
        """Two lists that disagree about what a secret looks like.

        The manifest's contract is metadata and public identifiers only. That was
        a field-name denylist plus two value patterns, so `private_key` was caught
        and a token pasted into `notes` was not -- measured: a GitHub token, an AWS
        key id, a base64 key and a BIP-39 phrase were all accepted.

        This is NOT the repository's secret scanner. gitleaks runs over full
        history on every push with no path filter and is the line of defence; this
        is the fast local one, so an operator hears about it before the push.

        But the two must not disagree about the obvious shapes, and the self-test
        inside .github/workflows/secret-scan.yml is the only place that writes down
        what this repository considers a planted credential. Its shapes are read
        from the workflow rather than copied, so a canary added there and not here
        fails.
        """
        selftest = (ROOT / ".github" / "workflows" / "secret-scan.yml").read_text(encoding="utf-8")
        # The workflow builds its canary at run time, so what it CONTAINS is the
        # marker: it assembles a PEM header from split tokens (deliberately, so the
        # workflow file is not itself a matchable secret) and fills it with
        # `openssl rand`. The values below are this test's claim about what that
        # produces. Asserting both the marker and the value removes the guess rather
        # than relocating it: a marker alone passes while pinned to a shape nothing
        # plants, and the test still goes green because the validator refuses
        # everything.
        planted = {
            "openssl rand": [
                "-----BEGIN " + "OPENSSH PRIVATE KEY-----",  # what the workflow assembles
                "-----BEGIN " + "PRIVATE KEY-----",          # PKCS#8, the shape a key file usually carries
            ],
        }
        for marker in planted:
            self.assertIn(
                marker, selftest,
                f"the secret-scan self-test no longer plants {marker!r}; this test is pinned to a "
                f"shape it does not use, so it proves nothing")

        for marker, values in planted.items():
            for value in values:
                obj = direct_key()
                obj["notes"] = value
                with self.subTest(shape=marker, value=value[:24]):
                    self.assert_invalid(manifest_with(obj), "private material")

        # Control: an ordinary note must still pass, or the assertions above would
        # hold for a validator that refuses every note.
        obj = direct_key()
        obj["notes"] = "rotated 2026-09-01 by platform"
        validate_manifest(manifest_with(obj))

    def test_kek_algorithm_is_refused_where_the_object_already_names_its_key(self):
        """Two answers to "what key is in this slot" invite them to disagree."""
        control = direct_key()
        validate_manifest(manifest_with(control))  # without the field, this loads

        obj = direct_key()
        obj["bindings"][0]["kek_algorithm"] = "rsa2048"
        self.assert_invalid(manifest_with(obj), "only meaningful for release-secret")

        versioned = direct_key()
        versioned["bindings"][0]["kek_version"] = "1"
        self.assert_invalid(manifest_with(versioned), "only meaningful for release-secret")

    def test_binding_requires_public_fingerprint_or_key_check(self):
        obj = direct_key()
        del obj["bindings"][0]["public_fingerprint"]
        self.assert_invalid(manifest_with(obj), "public_fingerprint or key_check")

    def test_every_yubikey_backend_requires_pin_without_touch(self):
        for backend in ("yubikey-piv", "yubikey-openpgp"):
            obj = direct_key()
            obj["algorithm"] = "ed25519"
            obj["bindings"][0]["backend"] = backend
            obj["bindings"][0]["pin_policy"] = "once"
            obj["bindings"][0]["touch_policy"] = "always"
            self.assert_invalid(manifest_with(obj), "touch_policy=never")

    def test_commissioned_nitrokey_requires_serial_and_devaut_pin(self):
        obj = direct_key()
        obj["bindings"][0]["state"] = "active"
        self.assert_invalid(manifest_with(obj), "device_serial and devaut_fingerprint")

    def test_commissioned_yubikey_requires_serial_pin(self):
        obj = direct_key()
        obj["algorithm"] = "p256"
        obj["bindings"][0].update(backend="yubikey-piv", state="active", pin_policy="once", touch_policy="never")
        self.assert_invalid(manifest_with(obj), "device_serial")

    def test_yubikey_piv_does_not_claim_ed25519(self):
        obj = direct_key()
        obj["algorithm"] = "ed25519"
        for binding in obj["bindings"]:
            binding.update(backend="yubikey-piv", pin_policy="once", touch_policy="never")
        self.assert_invalid(manifest_with(obj), "does not support ed25519/sign")

    def test_fido_continuity_requires_two_enrollments(self):
        obj = direct_key()
        obj.update(
            id="github-admin-fido",
            kind="fido-credential",
            custody="fido-multi-enrollment",
            algorithm="device-managed",
            operations=["authenticate"],
        )
        obj["bindings"] = obj["bindings"][:1]
        obj["bindings"][0]["backend"] = "fido2"
        obj["recovery"]["mode"] = "multi-enrollment"
        self.assert_invalid(manifest_with(obj), "at least 2 hardware bindings")

    def test_exception_requires_expiry_approval_and_reason(self):
        obj = direct_key()
        obj.update(custody="exception", bindings=[])
        obj["recovery"] = {"mode": "exception", "status": "accepted"}
        obj["exception"] = {"reason": "vendor limitation"}
        self.assert_invalid(manifest_with(obj), "exception requires")

    def test_unknown_fields_fail_closed(self):
        obj = direct_key()
        obj["fallback_backend"] = "software"
        self.assert_invalid(manifest_with(obj), "unknown fields")

    def test_invalid_json_reports_a_safe_parse_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text('{"objects": [SECRET]}', encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "invalid JSON") as error:
                load_and_validate(path)
            self.assertNotIn("SECRET", str(error.exception))


if __name__ == "__main__":
    unittest.main()
