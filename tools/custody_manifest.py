#!/usr/bin/env python3
"""Validate the non-secret Regalia custody manifest using only the stdlib."""

from __future__ import annotations

import argparse
import json
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn


class ManifestError(ValueError):
    """A safe-to-display manifest validation error."""


TOP_FIELDS = {"schema_version", "manifest_id", "generated_at", "objects"}
OBJECT_FIELDS = {
    "id", "name", "kind", "classification", "environment", "owner", "purpose", "custody", "algorithm", "operations",
    "policy_id", "bindings", "recovery", "rotation", "migration", "verification", "exception", "notes",
}
BINDING_FIELDS = {
    "site", "backend", "device_id", "object_id", "public_fingerprint", "key_check", "state",
    "pin_policy", "touch_policy", "device_serial", "devaut_fingerprint", "public_key_sha256", "kek_algorithm",
    "kek_version",
}
RECOVERY_FIELDS = {"mode", "authority_id", "minimum_replicas", "status", "last_drill"}
# envelope_max_age_days is optional: absent means an envelope of this object never ages out.
# It is NOT the same bound as maximum_age_days, which is measured from last_rotated and governs
# the key. This one is measured from each envelope's own created_at and governs the ciphertext,
# so an object rotated exactly on schedule can still be releasing envelopes sealed years ago.
ROTATION_FIELDS = {"maximum_age_days", "last_rotated", "envelope_max_age_days"}
MIGRATION_FIELDS = {"status", "source", "owner_repository"}
EXCEPTION_FIELDS = {"reason", "expires", "approved_by"}
VERIFICATION_FIELDS = {"status", "last_verified", "evidence"}

KINDS = {
    "asymmetric-key", "symmetric-key", "opaque-secret", "password", "api-token", "seed",
    "certificate", "fido-credential", "sops-recipient",
}
CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "critical"}
VERIFICATION_STATES = {"planned", "verified", "failed", "overdue"}
ENVIRONMENTS = {"production", "staging", "development"}
CUSTODY_MODES = {"direct-hardware", "hardware-envelope", "fido-multi-enrollment", "exception"}
BACKENDS = {"nitrokey-pkcs11", "yubikey-piv", "yubikey-openpgp", "fido2"}
STATES = {"planned", "qualified", "active", "standby", "retired", "revoked"}
# THE COMMISSIONED SUBSET: states in which a device actually exists and holds the credential.
#
# Separate from STATES because it answers a different question. "Is this a state?" is spelled by
# STATES; "does this state mean a device exists?" is spelled here. registry.commissionedStates is
# the Go half of the same rule. It was written inline twice below and is now named once, because
# tools/fido_continuity.py needs the same answer and a third copy is how the capability table
# drifted before #73 removed it.
COMMISSIONED_STATES = {"qualified", "active", "standby"}
# Must accept exactly what an envelope KEK reference can carry; registry.kekVersionPattern is the
# Go half of the same rule.
KEK_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
RECOVERY_MODES = {"shamir-4-of-6", "multi-enrollment", "rebuild-public", "exception"}
RECOVERY_STATES = {"planned", "tested", "accepted", "overdue"}
MIGRATION_STATES = {"planned", "in-progress", "migrated", "exception", "not-applicable"}
# The backend capability table is NOT defined here.
#
# It used to be, and it disagreed with the daemon's. registry.Capabilities() in Go decided what the
# service accepts while this literal decided what CI accepts: Python had no p256 or p384 for
# nitrokey-pkcs11 at all, so this validator rejected manifests the daemon supports; it lacked
# certificate-sign and key-agreement everywhere; and it still carried aes-256/unwrap after the
# PKCS#11 driver was shown to refuse it. A manifest could pass review and fail at the daemon, or
# fail review while being perfectly serviceable.
#
# The Go matrix is the source. It is exported to config/backend-capabilities.json by a Go test that
# fails when the file drifts, and read here. Syncing two literals by hand would only have postponed
# the next divergence.
_CAPABILITIES_PATH = Path(__file__).resolve().parents[1] / "config" / "backend-capabilities.json"


def _load_capabilities() -> dict[str, dict[str, set[str]]]:
    try:
        raw = json.loads(_CAPABILITIES_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        # `go -C <module>` rather than a bare `go test`: this validator is normally run from the
        # repository root (`python3 -m tools.custody_manifest ...`), so a command that assumes
        # kms/ is the working directory would fail for the person reading the message.
        module = _CAPABILITIES_PATH.parents[1]
        raise SystemExit(
            f"cannot read backend capabilities from {_CAPABILITIES_PATH}: {error}. Regenerate with: "
            f"REGALIA_UPDATE_CAPABILITIES=1 go -C {module} test ./internal/registry -run GeneratedCapabilityFile"
        ) from error
    return {
        backend: {algorithm: set(operations) for algorithm, operations in algorithms.items()}
        for backend, algorithms in raw.items()
    }


CAPABILITIES = _load_capabilities()

FORBIDDEN_FIELD_NAMES = {
    "secret", "secret_value", "value", "plaintext", "pin", "puk", "password_value",
    "private_key", "mnemonic", "seed_phrase", "recovery_phrase", "api_key", "token_value",
}
# Credential SHAPES, checked in every string value rather than only in fields named like secrets.
#
# The manifest's contract is metadata and public identifiers only, and a field-name denylist keeps
# that promise for `private_key` while a token pasted into `notes` walks straight through. Measured
# before this list grew: a GitHub token, an AWS key id, a 32-byte base64 key and a BIP-39 phrase in
# `notes` were all accepted; only the PEM control was refused.
#
# THIS IS NOT THE REPOSITORY'S SECRET SCANNER AND MUST NOT BE MISTAKEN FOR IT. gitleaks runs over
# full history on every push with no path filter and carries its own ruleset (`useDefault = true`,
# so the rules are in the binary rather than in .gitleaks.toml, which is why this cannot derive from
# it and has to be its own list). That scan is the line of defence; this is the fast local one, and
# it exists so an operator validating a manifest hears about it before the push rather than after.
#
# The two shapes tools/secret-scan-selftest.sh plants — a PEM private key and a ghp_ token — are
# both here on purpose, and test_the_shapes_the_secret_scan_selftest_plants_are_refused holds them
# together, because two lists that disagree about what a secret looks like is the defect this
# manifest exists to avoid having about custody.
PRIVATE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"AGE-SECRET-KEY-1", re.IGNORECASE),
    # GitHub classic personal-access, OAuth, user-to-server, server-to-server and refresh
    # tokens, which all use a two-letter prefix and 36+ characters.
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
    # Fine-grained personal-access tokens, which do NOT match the rule above: the prefix is
    # the word github_pat_ rather than two letters, and the body carries underscores. The
    # comment above used to say "personal-access tokens" and mean only the classic shape,
    # which is the same overclaim this change exists to fix one level up -- a stated scope
    # wider than the checked one, in the list of things that check scopes.
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
)
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
FINGERPRINT_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")


def fail(path: str, message: str) -> NoReturn:
    raise ManifestError(f"{path}: {message}")


def require_dict(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(path, "must be an object")
    return value


def require_fields(value: dict[str, Any], required: set[str], allowed: set[str], path: str) -> None:
    missing = sorted(required - value.keys())
    if missing:
        fail(path, f"missing required fields: {', '.join(missing)}")
    unknown = sorted(value.keys() - allowed)
    if unknown:
        fail(path, f"unknown fields: {', '.join(unknown)}")


def require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        fail(path, "must be a non-empty string")
    return value


def require_enum(value: Any, choices: set[str], path: str) -> str:
    result = require_string(value, path)
    if result not in choices:
        fail(path, f"must be one of: {', '.join(sorted(choices))}")
    return result


# VERIFICATION_MAX_AGE_DAYS bounds how long a commissioning attestation stands without being
# re-made. A year matches the rotation defaults the example manifest uses.
VERIFICATION_MAX_AGE_DAYS = 365


def _today() -> date:
    """Today in UTC. A single point so tests can reason about the boundary."""
    return datetime.now(timezone.utc).date()


def validate_date(value: Any, path: str, *, timestamp: bool = False) -> None:
    text = require_string(value, path)
    try:
        if timestamp:
            datetime.fromisoformat(text.replace("Z", "+00:00"))
        else:
            date.fromisoformat(text)
    except ValueError:
        fail(path, "must be an ISO-8601 date" + ("/timestamp" if timestamp else ""))


def scan_for_secrets(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_FIELD_NAMES:
                fail(f"{path}.{key}", "forbidden secret-bearing field")
            scan_for_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_for_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in PRIVATE_PATTERNS):
            fail(path, "contains private material")


def validate_binding(binding: Any, path: str) -> dict[str, Any]:
    item = require_dict(binding, path)
    require_fields(
        item,
        {"site", "backend", "device_id", "object_id", "state"},
        BINDING_FIELDS,
        path,
    )
    require_string(item["site"], f"{path}.site")
    backend = require_string(item["backend"], f"{path}.backend")
    if backend not in BACKENDS:
        fail(f"{path}.backend", "unsupported backend")
    require_string(item["device_id"], f"{path}.device_id")
    require_string(item["object_id"], f"{path}.object_id")
    fingerprints = [name for name in ("public_fingerprint", "key_check") if name in item]
    if not fingerprints:
        fail(path, "requires public_fingerprint or key_check")
    for name in fingerprints:
        fingerprint = require_string(item[name], f"{path}.{name}")
        if not FINGERPRINT_PATTERN.fullmatch(fingerprint):
            fail(f"{path}.{name}", "must be sha256 followed by 64 lowercase hex digits")
    require_enum(item["state"], STATES, f"{path}.state")

    if backend == "nitrokey-pkcs11" and item["state"] in COMMISSIONED_STATES:
        # ADR-0002 D1: the serial, plus a DevAut fingerprint OR public_key_sha256 (the commissioned
        # public key, which the daemon enforces on every use). A genuine SmartCard-HSM cannot expose
        # its DevAut through PKCS#11, so requiring it made every real Nitrokey unbindable. Mirrors
        # nitrokeyIdentityPinned in internal/registry/registry.go.
        if not item.get("device_serial") or not (item.get("devaut_fingerprint") or item.get("public_key_sha256")):
            fail(path, "commissioned Nitrokey requires device_serial and devaut_fingerprint or public_key_sha256")
        # require_string first, exactly as the public_fingerprint check above does. Truthiness is
        # not a type: `{"a": 1}` and `["sha256:…"]` are both truthy, reach fullmatch and raise
        # TypeError — a traceback out of a validator whose whole contract is that a bad manifest
        # produces a named refusal.
        require_string(item["device_serial"], f"{path}.device_serial")
        for pin in ("devaut_fingerprint", "public_key_sha256"):
            if pin in item:
                value = require_string(item[pin], f"{path}.{pin}")
                if not FINGERPRINT_PATTERN.fullmatch(value):
                    fail(f"{path}.{pin}", "must be sha256 followed by 64 lowercase hex digits")

    if backend in {"yubikey-piv", "yubikey-openpgp"}:
        if item["state"] in COMMISSIONED_STATES and not item.get("device_serial"):
            fail(path, "commissioned YubiKey requires device_serial")
        if item.get("touch_policy") != "never":
            fail(path, "YubiKey binding requires touch_policy=never")
        if item.get("pin_policy") not in {"once", "always"}:
            fail(path, "YubiKey binding requires pin_policy=once or always")
    elif "pin_policy" in item or "touch_policy" in item:
        fail(path, "PIN/touch policy fields are valid only for YubiKey backends")
    return item


def validate_object(raw: Any, path: str) -> str:
    item = require_dict(raw, path)
    required = {
        "id", "name", "kind", "classification", "environment", "owner", "purpose", "custody", "algorithm", "operations",
        "policy_id", "bindings", "recovery", "rotation", "migration", "verification",
    }
    require_fields(item, required, OBJECT_FIELDS, path)
    object_id = require_string(item["id"], f"{path}.id")
    if not ID_PATTERN.fullmatch(object_id):
        fail(f"{path}.id", "must be a lowercase kebab-case identifier (3-63 characters)")
    require_string(item["name"], f"{path}.name")
    kind = require_enum(item["kind"], KINDS, f"{path}.kind")
    require_enum(item["classification"], CLASSIFICATIONS, f"{path}.classification")
    environment = require_enum(item["environment"], ENVIRONMENTS, f"{path}.environment")
    require_string(item["owner"], f"{path}.owner")
    purpose = require_string(item["purpose"], f"{path}.purpose")
    if not ID_PATTERN.fullmatch(purpose):
        fail(f"{path}.purpose", "must be a lowercase kebab-case identifier (3-63 characters)")
    custody = require_enum(item["custody"], CUSTODY_MODES, f"{path}.custody")
    require_string(item["algorithm"], f"{path}.algorithm")
    require_string(item["policy_id"], f"{path}.policy_id")

    operations = item["operations"]
    if not isinstance(operations, list) or not operations or not all(isinstance(x, str) and x for x in operations):
        fail(f"{path}.operations", "must be a non-empty string list")
    if len(set(operations)) != len(operations):
        fail(f"{path}.operations", "must not contain duplicates")

    bindings = item["bindings"]
    if not isinstance(bindings, list):
        fail(f"{path}.bindings", "must be a list")
    checked_bindings = [validate_binding(value, f"{path}.bindings[{i}]") for i, value in enumerate(bindings)]
    for index, binding in enumerate(checked_bindings):
        supported = CAPABILITIES.get(binding["backend"], {}).get(item["algorithm"], set())
        unsupported = sorted(set(operations) - supported)
        if unsupported:
            fail(f"{path}.bindings[{index}]", f"backend does not support {item['algorithm']}/{','.join(unsupported)}")
        # AN OPAQUE SECRET HAS NO ALGORITHM OF ITS OWN; THE KEK THAT PROTECTS IT DOES.
        #
        # `opaque` is the only algorithm the matrix admits for release-secret, because an API token
        # is not a key. Serving it still unwraps a data key ON THE CARD, and the drivers gate on the
        # key in the slot -- PKCS#11 accepts rsa2048/3072/4096, PIV accepts rsa2048. A binding that
        # named only "opaque" was commissioned here and then failed at its first release forever, as
        # a retryable error. The daemon enforces this in registry.validateBinding; this is the same
        # rule, because a manifest CI accepts and the daemon refuses is the defect in the other
        # direction. Unlike the capability table above, the rule does not follow from the exported
        # file -- it has to be stated in both places, and the Go tests and these tests both pin it.
        # TYPE-CHECK BEFORE USE. These two arrived as a new field pair and inherited none of the
        # validation the fields around them have: kek_algorithm went straight into a dict lookup and
        # kek_version into a regex, so a manifest supplying a list or an object raised TypeError
        # rather than ManifestError. A validator that crashes on malformed input fails in the one way
        # a validator must not -- an operator reading a traceback cannot tell whether their manifest
        # is wrong or the checker is broken.
        kek = binding.get("kek_algorithm")
        kek_version = binding.get("kek_version")
        if "release-secret" in operations:
            if kek is None:
                fail(f"{path}.bindings[{index}]", "release-secret binding must name the kek_algorithm of the wrapping key in its slot")
            kek = require_string(kek, f"{path}.bindings[{index}].kek_algorithm")
            if "unwrap" not in CAPABILITIES.get(binding["backend"], {}).get(kek, set()):
                fail(f"{path}.bindings[{index}]", f"backend cannot unwrap with kek_algorithm {kek}, so this binding could never release a secret")
            # A KEK version that selects nothing is not rotation: without it, an envelope wrapped
            # under a superseded key opens on whatever replaced it in the same slot.
            if kek_version is None:
                fail(f"{path}.bindings[{index}]", "release-secret binding must name the kek_version of the wrapping key in its slot")
            # A named-but-unusable version is a different mistake from an absent one, and telling an
            # operator to name a field they just named sends them looking in the wrong place.
            kek_version = require_string(kek_version, f"{path}.bindings[{index}].kek_version")
            if not KEK_VERSION.fullmatch(kek_version):
                fail(f"{path}.bindings[{index}].kek_version", f"must match {KEK_VERSION.pattern} to be nameable by an envelope's KEK reference")
        elif kek is not None or kek_version is not None:
            fail(f"{path}.bindings[{index}]", f"kek_algorithm and kek_version are only meaningful for release-secret; {item['algorithm']} already names the key in this slot")

    if environment == "production" and custody != "exception" and len(checked_bindings) < 2:
        fail(f"{path}.bindings", "production object requires at least 2 hardware bindings")
    devices = [binding["device_id"] for binding in checked_bindings]
    if len(devices) != len(set(devices)):
        fail(f"{path}.bindings", "bindings must use distinct devices")
    if custody == "fido-multi-enrollment" and (kind != "fido-credential" or any(b["backend"] != "fido2" for b in checked_bindings)):
        fail(path, "FIDO custody requires kind=fido-credential and only fido2 bindings")
    if custody == "fido-multi-enrollment":
        # SEPARATE CUSTODY, NOT MERELY SEPARATE DEVICES. FIDO credentials are non-exportable, so
        # continuity comes only from independent enrollments — and two tokens in one person's
        # drawer or one site are a single loss event, which is exactly the failure multi-enrollment
        # is supposed to survive. Distinct device ids alone do not establish that.
        sites = [binding.get("site") for binding in checked_bindings]
        if len(set(sites)) < 2:
            fail(f"{path}.bindings", "FIDO enrollments must be held in separate custody: at least two distinct sites")
    if custody != "fido-multi-enrollment" and any(b["backend"] == "fido2" for b in checked_bindings):
        fail(path, "fido2 bindings require fido-multi-enrollment custody")

    recovery = require_dict(item["recovery"], f"{path}.recovery")
    require_fields(recovery, {"mode", "status"}, RECOVERY_FIELDS, f"{path}.recovery")
    recovery_mode = require_enum(recovery["mode"], RECOVERY_MODES, f"{path}.recovery.mode")
    require_enum(recovery["status"], RECOVERY_STATES, f"{path}.recovery.status")
    if recovery_mode == "shamir-4-of-6":
        require_string(recovery.get("authority_id"), f"{path}.recovery.authority_id")
        if recovery.get("minimum_replicas") != 2:
            fail(f"{path}.recovery.minimum_replicas", "must equal 2")
    if custody in {"direct-hardware", "hardware-envelope"} and recovery_mode != "shamir-4-of-6":
        fail(path, "hardware custody requires shamir-4-of-6 recovery")
    if custody == "fido-multi-enrollment" and recovery_mode != "multi-enrollment":
        fail(path, "FIDO custody requires multi-enrollment recovery")

    rotation = require_dict(item["rotation"], f"{path}.rotation")
    require_fields(rotation, {"maximum_age_days", "last_rotated"}, ROTATION_FIELDS, f"{path}.rotation")
    # Checked here as well as in the schema because CI and the daemon must refuse the same
    # manifest: a bound of zero or a negative one reads as "expire everything immediately", and
    # the way to say "no bound" is to omit the field.
    if "envelope_max_age_days" in rotation:
        value = rotation["envelope_max_age_days"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            fail(f"{path}.rotation.envelope_max_age_days",
                 "must be a positive integer of days; omit it to leave envelope lifetime unbounded")
    # `isinstance(True, int)` is true and `True >= 1`, so a manifest saying
    # "maximum_age_days": true was read as ONE DAY and put every object past its rotation deadline
    # immediately. The sibling check on envelope_max_age_days already excluded bool; two bounds
    # disagreeing about the same authoring slip is how one of them gets trusted.
    if (not isinstance(rotation["maximum_age_days"], int)
            or isinstance(rotation["maximum_age_days"], bool)
            or rotation["maximum_age_days"] < 1):
        fail(f"{path}.rotation.maximum_age_days", "must be a positive integer of days")
    if rotation["last_rotated"] is not None:
        validate_date(rotation["last_rotated"], f"{path}.rotation.last_rotated")

    migration = require_dict(item["migration"], f"{path}.migration")
    require_fields(migration, {"status", "source"}, MIGRATION_FIELDS, f"{path}.migration")
    require_enum(migration["status"], MIGRATION_STATES, f"{path}.migration.status")
    require_string(migration["source"], f"{path}.migration.source")

    verification = require_dict(item["verification"], f"{path}.verification")
    require_fields(verification, VERIFICATION_FIELDS, VERIFICATION_FIELDS, f"{path}.verification")
    verification_status = require_enum(verification["status"], VERIFICATION_STATES, f"{path}.verification.status")
    require_string(verification["evidence"], f"{path}.verification.evidence")
    if verification["last_verified"] is not None:
        validate_date(verification["last_verified"], f"{path}.verification.last_verified", timestamp=True)
    if verification_status == "verified" and verification["last_verified"] is None:
        fail(f"{path}.verification.last_verified", "verified objects require a timestamp")
    # STALENESS IS COMPUTED, NOT DECLARED. "overdue" was an unreachable enum value: nothing ever
    # compared last_verified to today, so an object verified years ago still read as "verified".
    # An attestation with no expiry is an assertion about the past presented as the present.
    if verification_status == "verified" and verification["last_verified"] is not None:
        verified_at = datetime.fromisoformat(
            require_string(verification["last_verified"], f"{path}.verification.last_verified").replace("Z", "+00:00")
        ).date()
        if verified_at < _today() - timedelta(days=VERIFICATION_MAX_AGE_DAYS):
            fail(
                f"{path}.verification.last_verified",
                f"verification is older than {VERIFICATION_MAX_AGE_DAYS} days; re-verify the object or set status=overdue",
            )

    if custody == "exception":
        exception = require_dict(item.get("exception"), f"{path}.exception")
        missing_exception = sorted(EXCEPTION_FIELDS - exception.keys())
        if missing_exception:
            fail(f"{path}.exception", "exception requires reason, expires, and approved_by")
        require_fields(exception, EXCEPTION_FIELDS, EXCEPTION_FIELDS, f"{path}.exception")
        require_string(exception["reason"], f"{path}.exception.reason")
        require_string(exception["approved_by"], f"{path}.exception.approved_by")
        validate_date(exception["expires"], f"{path}.exception.expires")
        # A TIME-BOUNDED EXCEPTION MUST ACTUALLY BE BOUND BY TIME. The date was format-checked and
        # never compared to today, so an exception approved once validated forever — the
        # "time-bounded" part was decorative, and the manifest kept asserting an approval that had
        # lapsed. An expired exception is a manifest that no longer describes an approved state.
        if date.fromisoformat(require_string(exception["expires"], f"{path}.exception.expires")) < _today():
            fail(f"{path}.exception.expires", "exception has expired; re-approve it or move the object to a supported custody mode")
    elif "exception" in item:
        fail(f"{path}.exception", "is allowed only when custody=exception")
    return object_id


def validate_manifest(raw: Any) -> dict[str, Any]:
    scan_for_secrets(raw)
    manifest = require_dict(raw, "manifest")
    require_fields(manifest, TOP_FIELDS, TOP_FIELDS, "manifest")
    if manifest["schema_version"] != 1:
        fail("manifest.schema_version", "unsupported version")
    require_string(manifest["manifest_id"], "manifest.manifest_id")
    validate_date(manifest["generated_at"], "manifest.generated_at", timestamp=True)
    objects = manifest["objects"]
    if not isinstance(objects, list) or not objects:
        fail("manifest.objects", "must be a non-empty list")
    seen: set[str] = set()
    for index, item in enumerate(objects):
        object_id = validate_object(item, f"manifest.objects[{index}]")
        if object_id in seen:
            fail(f"manifest.objects[{index}].id", f"duplicate object id: {object_id}")
        seen.add(object_id)
    return manifest


def load_and_validate(path: Path | str) -> dict[str, Any]:
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ManifestError(f"{source}: invalid JSON at line {error.lineno}, column {error.colno}") from None
    except OSError as error:
        raise ManifestError(f"{source}: cannot read manifest ({error.strerror or 'I/O error'})") from None
    return validate_manifest(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        manifest = load_and_validate(args.manifest)
    except ManifestError as error:
        print(f"INVALID: {error}")
        return 1
    print(f"VALID: {args.manifest} ({len(manifest['objects'])} objects, schema v1)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
