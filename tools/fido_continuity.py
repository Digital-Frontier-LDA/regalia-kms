#!/usr/bin/env python3
"""Refuse a FIDO credential retirement that would leave an account without continuity.

A FIDO credential is born on its authenticator and never leaves it. There is no share-based path
back (`registry.validateFIDOContinuity`, `doc/RUNBOOK-DISASTER-RECOVERY.md`), so continuity comes
only from independent enrollments and the manifest is the only record of where they are.

THE DANGEROUS STEP IS NOT LOSING A CREDENTIAL. IT IS RETIRING ONE ON PURPOSE.

Losing one is survivable by design and the runbook covers it. Retiring one is a deliberate act
against a live identity provider, taken by someone who believes another enrollment will still work
-- and that belief comes from the manifest. If the manifest is wrong, or if it is right and
describes enrollments nobody has actually created, the de-enrollment removes the last working
credential and locks the account. Nothing gives it back: re-issuance of the identity is the only
path, which is what the disaster-recovery runbook already says about the loss case.

So this tool answers one question before anybody touches an identity provider:

    after this retirement, does the object still satisfy its own continuity rules?

# WHY THIS IS A DIFFERENTIAL AND NOT A LIST OF CHECKS

The rules for a FIDO object already exist, in `custody_manifest.validate_object`: FIDO custody
requires kind `fido-credential`, only `fido2` bindings, at least two bindings, at least two
DISTINCT SITES (separate custody, not merely separate devices), and recovery mode
`multi-enrollment`. Restating any of them here would be a second copy that drifts -- the defect
#73 removed when the Go and Python capability tables disagreed and a manifest could pass review
while failing at the daemon.

Instead this builds the object AS IT WOULD BE after the retirement and runs the existing validator
on it. Two arms:

    baseline  -- the object as it stands today MUST validate
    projected -- the object with the retiring binding removed MUST also validate

The baseline arm is what makes the result attributable. Without it, a refusal cannot distinguish
"this retirement breaks continuity" from "this manifest was already broken", and those need
different people to act. With it, the difference between the arms is caused by the retirement by
construction.

A consequence worth stating plainly, because it is the operational rule this enforces:

    RETIRING ONE OF TWO ENROLLMENTS ALWAYS FAILS.

Two enrollments minus one is one, and one violates the object's own two-distinct-sites rule. The
replacement must be enrolled FIRST, so the count never drops below the documented minimum. That is
the same shape as rotating a SOPS recipient -- add the new one, verify, then remove the old -- and
it is the difference between a rotation and an outage.

# WHAT THIS TOOL CANNOT DO, WHICH IS THE PART THAT MATTERS

It reads a JSON file. It cannot see an authenticator, cannot enumerate what an identity provider
believes, and cannot tell whether the surviving enrollment it just approved physically exists. A
manifest that confidently describes two credentials nobody ever created will pass every check here.

That is why a pass prints the surviving enrollments and requires a human to confirm each one
against the physical world before the destructive step. The tool moves the failure from "after
de-enrollment, silently" to "before de-enrollment, out loud" -- it does not remove it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tools.custody_manifest import (
    COMMISSIONED_STATES,
    ManifestError,
    validate_object,
)

FIDO_CUSTODY = "fido-multi-enrollment"
# THE CONTINUITY MINIMUM IS A COUNT OF SITES, NOT OF CREDENTIALS.
#
# Two credentials in one drawer are one loss event, which is exactly what multi-enrollment is
# supposed to survive, so the site count is the one that carries the meaning.
#
# It was written as two checks -- at least two commissioned enrollments AND at least two distinct
# sites -- until a mutation battery showed the enrollment half could not fail on its own. The sites
# are derived from the survivors, so len(sites) <= len(survivors) always, and requiring two sites
# already requires two survivors to hold them. There is no manifest that satisfies the site rule and
# violates the count rule. A condition no input can make fire alone is an operand no test can pin,
# which is the defect class #237 exists to remove, so it is gone rather than kept for symmetry.
MINIMUM_SITES = 2


class RetirementRefused(Exception):
    """The retirement must not proceed. The message says which rule refused it."""


def _object_by_id(manifest: dict[str, Any], object_id: str) -> dict[str, Any]:
    for item in manifest.get("objects", []):
        if isinstance(item, dict) and item.get("id") == object_id:
            return item
    known = sorted(
        str(o.get("id")) for o in manifest.get("objects", []) if isinstance(o, dict) and o.get("id")
    )
    raise RetirementRefused(
        f"no object {object_id!r} in this manifest. Known objects: {', '.join(known) or '(none)'}"
    )


def _commissioned(bindings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Bindings whose state means a credential actually exists on a device.

    `planned` is not one of them, and this is the rule the base validator does not make. Its
    two-distinct-sites check counts bindings, so an object with two `planned` enrollments satisfies
    "separate custody" while holding zero usable credentials. That is fine for a manifest that
    describes intent; it is not fine as the thing standing between a de-enrollment and a lockout.
    """
    return [b for b in bindings if b.get("state") in COMMISSIONED_STATES]


def _describe(binding: dict[str, Any]) -> str:
    return (
        f"site={binding.get('site')} device_id={binding.get('device_id')} "
        f"credential={binding.get('object_id')} state={binding.get('state')}"
    )


def plan_retirement(manifest: dict[str, Any], object_id: str, device_id: str) -> list[dict[str, Any]]:
    """Return the surviving enrollments, or raise RetirementRefused.

    The order of the checks is the order of the questions, and each refusal names a different
    person's problem: is this the right kind of object, is the manifest sound before we start, does
    it know about the device you are retiring, and does continuity survive the removal.
    """
    item = _object_by_id(manifest, object_id)

    custody = item.get("custody")
    if custody != FIDO_CUSTODY:
        raise RetirementRefused(
            f"object {object_id!r} has custody {custody!r}, not {FIDO_CUSTODY!r}. This tool is only "
            "for credentials that cannot be re-derived; anything with a share-based recovery path "
            "follows the Shamir procedure in doc/RUNBOOK-DISASTER-RECOVERY.md instead."
        )

    # BASELINE ARM. Without it a refusal below cannot distinguish "this retirement breaks
    # continuity" from "this manifest was already broken", and those are different people's
    # problems. It also means the projected arm's failure is caused by the retirement by
    # construction rather than by argument.
    try:
        validate_object(json.loads(json.dumps(item)), f"objects[{object_id}]")
    except ManifestError as error:
        raise RetirementRefused(
            f"the manifest does not validate as it stands, before any retirement: {error}. "
            "Fix that first -- until it validates, nothing here can attribute a refusal to the "
            "retirement rather than to the existing defect."
        ) from error

    bindings = item.get("bindings", [])
    retiring = [b for b in bindings if b.get("device_id") == device_id]
    if not retiring:
        present = sorted(str(b.get("device_id")) for b in bindings)
        raise RetirementRefused(
            f"object {object_id!r} has no binding for device {device_id!r}; it names "
            f"{', '.join(present) or '(none)'}. Either you are about to de-enroll a credential this "
            "manifest does not know about -- in which case the manifest is not describing reality "
            "and that is the finding -- or the device id is a typo."
        )

    projected = json.loads(json.dumps(item))
    projected["bindings"] = [b for b in bindings if b.get("device_id") != device_id]

    # PROJECTED ARM. Every FIDO rule comes from the existing validator; none is restated here.
    try:
        validate_object(projected, f"objects[{object_id}] after retiring {device_id}")
    except ManifestError as error:
        raise RetirementRefused(
            f"after retiring {device_id!r} the object would no longer validate: {error}\n"
            "Enroll the replacement FIRST, so the enrollment count never drops below the documented "
            "minimum, then retire this one. Retiring one of two enrollments always fails here, "
            "because one is not two distinct sites."
        ) from error

    # The rule the base validator cannot make: a surviving binding must be one where a credential
    # actually exists. `planned` describes an intention, and an intention cannot authenticate.
    survivors = _commissioned(projected["bindings"])
    sites = {b.get("site") for b in survivors}
    if len(sites) < MINIMUM_SITES:
        planned = [b for b in projected["bindings"] if b.get("state") not in COMMISSIONED_STATES]
        detail = ""
        if planned:
            detail = (
                f" {len(planned)} surviving binding(s) are not commissioned "
                f"({', '.join(sorted(str(b.get('state')) for b in planned))}), and a binding that "
                "describes an intention cannot authenticate."
            )
        raise RetirementRefused(
            f"after retiring {device_id!r} only {len(survivors)} commissioned enrollment(s) at "
            f"{len(sites)} site(s) would remain; continuity needs {MINIMUM_SITES} distinct sites, "
            f"because two credentials in one custody are one loss event.{detail}"
        )
    return survivors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refuse a FIDO retirement that would leave an account without continuity.",
    )
    # POSITIONAL, matching `python3 -m tools.custody_manifest <manifest>`. An operator who has
    # run one of these has run the other, and a second calling convention for the same artifact is
    # a paper cut every single time.
    parser.add_argument("manifest", help="path to the custody manifest")
    parser.add_argument("--object", required=True, help="object id of the FIDO credential")
    parser.add_argument("--retiring", required=True, help="device_id of the enrollment being retired")
    arguments = parser.parse_args()

    try:
        manifest = json.loads(Path(arguments.manifest).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"REFUSED: cannot read the manifest: {error}", file=sys.stderr)
        return 1

    try:
        survivors = plan_retirement(manifest, arguments.object, arguments.retiring)
    except RetirementRefused as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1

    print(f"MANIFEST OK: retiring {arguments.retiring} from {arguments.object} leaves "
          f"{len(survivors)} commissioned enrollment(s):")
    for binding in survivors:
        print(f"  - {_describe(binding)}")
    print()
    print("THIS IS NOT AUTHORIZATION TO DE-ENROLL. What was checked is the manifest's internal")
    print("consistency: this tool has not seen an authenticator and cannot tell whether the")
    print("enrollments above physically exist. Before the destructive step, a second person must")
    print("confirm each surviving enrollment against the identity provider and against the token")
    print("in hand. See doc/RUNBOOK-FIDO-RETIREMENT.md; the de-enrollment itself needs the account")
    print("owner's authorization and is not run by an agent.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
