"""The retirement guard must refuse every way a de-enrollment can end in a lockout.

Every fixture here is grown from the SHIPPED example object rather than written from scratch, so a
schema change that invalidates real manifests invalidates these too. A hand-built fixture drifts
into a shape the validator would never see, and then these tests pass against a manifest nobody
could actually write.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import os
import unittest
from pathlib import Path

from tools.custody_manifest import ManifestError, validate_object
from tools.fido_continuity import RetirementRefused, plan_retirement

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "config" / "custody-manifest.example.json"
FIDO_OBJECT = "github-org-admin-fido"


def _example_object() -> dict:
    manifest = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    for item in manifest["objects"]:
        if item["id"] == FIDO_OBJECT:
            return json.loads(json.dumps(item))
    raise AssertionError(
        f"the example manifest no longer contains {FIDO_OBJECT}; these tests grow every fixture "
        "from it and would otherwise be testing a shape the repository does not ship"
    )


def _binding(site: str, suffix: str, state: str) -> dict:
    return {
        "site": site,
        "backend": "fido2",
        "device_id": f"fido-admin-{suffix}",
        "object_id": f"github-enrollment-{suffix}",
        "public_fingerprint": "sha256:" + (suffix[0] * 64),
        "state": state,
    }


def _manifest_with(bindings: list[dict]) -> dict:
    item = _example_object()
    item["bindings"] = bindings
    return {
        "schema_version": 1,
        "manifest_id": "test",
        "generated_at": "2026-09-11T00:00:00Z",
        "objects": [item],
    }


class RetirementGuard(unittest.TestCase):
    def test_the_fixtures_are_valid_before_any_retirement(self):
        """The control. Every refusal below is meaningless if the baseline never validated.

        This is the arm that makes the others attributable: without it, a refusal could be the
        fixture's fault and every test would still be green.
        """
        for name, bindings in {
            "two planned (the shipped example)": _example_object()["bindings"],
            "three commissioned at three sites": [
                _binding("custodian-a", "a", "active"),
                _binding("custodian-b", "b", "active"),
                _binding("custodian-c", "c", "active"),
            ],
        }.items():
            with self.subTest(name):
                item = _manifest_with(bindings)["objects"][0]
                try:
                    validate_object(item, "objects[0]")
                except ManifestError as error:
                    self.fail(f"fixture {name!r} does not validate: {error}")

    def test_retiring_one_of_two_enrollments_is_always_refused(self):
        """Two minus one is one, and one is not two distinct sites.

        The operational rule this enforces: enroll the replacement FIRST so the count never drops
        below the documented minimum. It is the same shape as rotating a SOPS recipient, and it is
        the difference between a rotation and an outage.
        """
        manifest = _manifest_with([
            _binding("custodian-a", "a", "active"),
            _binding("custodian-b", "b", "active"),
        ])
        with self.assertRaises(RetirementRefused) as caught:
            plan_retirement(manifest, FIDO_OBJECT, "fido-admin-a")
        self.assertIn("Enroll the replacement FIRST", str(caught.exception))

    def test_retiring_one_of_three_commissioned_enrollments_is_allowed(self):
        """The known-good arm.

        Every refusal test above and below passes just as well against a guard that refuses
        everything. This is the one that says the procedure is possible at all, and it returns the
        survivors a human then has to confirm physically.
        """
        manifest = _manifest_with([
            _binding("custodian-a", "a", "active"),
            _binding("custodian-b", "b", "active"),
            _binding("custodian-c", "c", "standby"),
        ])
        survivors = plan_retirement(manifest, FIDO_OBJECT, "fido-admin-a")
        self.assertEqual(
            {b["device_id"] for b in survivors}, {"fido-admin-b", "fido-admin-c"})

    def test_a_surviving_planned_enrollment_does_not_count_as_continuity(self):
        """The rule the base validator cannot make, and the reason this tool adds one at all.

        Three bindings at three distinct sites, two of them `planned`. After retiring the only
        commissioned one, validate_object is PERFECTLY HAPPY -- two bindings, two distinct sites,
        all fido2 -- and the account has nothing that can authenticate. `planned` describes an
        intention, and an intention cannot log in.

        The assertion on validate_object is the load-bearing half: it proves this case reaches the
        guard's own rule rather than being caught upstream, which is TESTING.md 17.
        """
        manifest = _manifest_with([
            _binding("custodian-a", "a", "active"),
            _binding("custodian-b", "b", "planned"),
            _binding("custodian-c", "c", "planned"),
        ])
        projected = json.loads(json.dumps(manifest["objects"][0]))
        projected["bindings"] = [b for b in projected["bindings"] if b["device_id"] != "fido-admin-a"]
        try:
            validate_object(projected, "objects[0]")
        except ManifestError as error:
            self.fail(
                "the projected object was refused by the base validator, so this test no longer "
                f"exercises the commissioned-state rule it exists for: {error}")

        with self.assertRaises(RetirementRefused) as caught:
            plan_retirement(manifest, FIDO_OBJECT, "fido-admin-a")
        self.assertIn("cannot authenticate", str(caught.exception))

    def test_two_surviving_enrollments_in_one_custody_are_not_continuity(self):
        """Separate custody, not merely separate devices — and this is the only case that proves it.

        Two commissioned enrollments survive, at the SAME site, and the projected object still
        validates because a third `planned` binding elsewhere keeps the base validator's
        two-distinct-sites rule satisfied. So the count is fine, the manifest is fine, and both
        working credentials are in one drawer: one loss event away from the lockout this whole
        procedure exists to prevent.

        A mutation battery is what produced this test. Setting MINIMUM_SITES to 1 survived every
        other case in this file, because in all of them the base validator refused first — the
        guard's own rule was never the thing being measured. That is TESTING.md 17: a guard you
        cannot make fail because something upstream already refused.

        The assertion on validate_object is therefore load-bearing rather than decorative; without
        it this test would silently drift back into measuring the upstream rule.
        """
        manifest = _manifest_with([
            _binding("custodian-a", "a", "active"),
            _binding("custodian-a", "b", "active"),
            _binding("custodian-b", "c", "planned"),
            _binding("custodian-c", "d", "active"),
        ])
        projected = json.loads(json.dumps(manifest["objects"][0]))
        projected["bindings"] = [b for b in projected["bindings"] if b["device_id"] != "fido-admin-d"]
        try:
            validate_object(projected, "objects[0]")
        except ManifestError as error:
            self.fail(
                "the projected object was refused upstream, so this test no longer reaches the "
                f"guard's own site rule: {error}")

        with self.assertRaises(RetirementRefused) as caught:
            plan_retirement(manifest, FIDO_OBJECT, "fido-admin-d")
        message = str(caught.exception)
        self.assertIn("1 site(s)", message)
        self.assertIn("one loss event", message)

    def test_a_device_the_manifest_does_not_know_is_refused(self):
        """Either the manifest is not describing reality, or the id is a typo.

        Both need a human before a de-enrollment, and the message says which two they are rather
        than reporting a generic failure.
        """
        manifest = _manifest_with([
            _binding("custodian-a", "a", "active"),
            _binding("custodian-b", "b", "active"),
            _binding("custodian-c", "c", "active"),
        ])
        with self.assertRaises(RetirementRefused) as caught:
            plan_retirement(manifest, FIDO_OBJECT, "fido-admin-z")
        self.assertIn("does not know about", str(caught.exception))

    def test_an_object_with_a_recovery_path_is_sent_to_the_shamir_procedure(self):
        """This tool is only for credentials that cannot be re-derived."""
        manifest = _manifest_with([_binding("custodian-a", "a", "active")])
        manifest["objects"][0]["custody"] = "direct-hardware"
        with self.assertRaises(RetirementRefused) as caught:
            plan_retirement(manifest, FIDO_OBJECT, "fido-admin-a")
        self.assertIn("RUNBOOK-DISASTER-RECOVERY", str(caught.exception))

    def test_an_already_broken_manifest_is_not_blamed_on_the_retirement(self):
        """The baseline arm, which is what makes every other refusal attributable.

        Without it, "this retirement breaks continuity" and "this manifest was already broken" are
        the same message, and they need different people to act.
        """
        manifest = _manifest_with([
            _binding("custodian-a", "a", "active"),
            _binding("custodian-b", "b", "active"),
            _binding("custodian-c", "c", "active"),
        ])
        manifest["objects"][0]["recovery"]["mode"] = "shamir-4-of-6"
        with self.assertRaises(RetirementRefused) as caught:
            plan_retirement(manifest, FIDO_OBJECT, "fido-admin-a")
        self.assertIn("before any retirement", str(caught.exception))

    def test_an_unknown_object_lists_what_the_manifest_holds(self):
        manifest = _manifest_with([_binding("custodian-a", "a", "active")])
        with self.assertRaises(RetirementRefused) as caught:
            plan_retirement(manifest, "no-such-object", "fido-admin-a")
        self.assertIn(FIDO_OBJECT, str(caught.exception))


class CommandLine(unittest.TestCase):
    """The CLI arms must differ from EACH OTHER, not merely from success.

    Six arms that all return the same argparse usage error look like six passing refusals. The
    manifest argument is positional, matching `python3 -m tools.custody_manifest <manifest>`;
    an arm that accidentally passes `--manifest` fails for the wrong reason and would be
    indistinguishable from a real refusal without this.
    """

    def _run(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-m", "tools.fido_continuity", *arguments],
            cwd=ROOT, capture_output=True, text=True)

    def _manifest_file(self, directory: str, name: str, bindings: list[dict]) -> str:
        """Each arm gets its OWN file.

        The first version of this test wrote both manifests to one path, so the second overwrote
        the first and the two arms ran against identical input -- one fixture, two arms, pinning
        neither. It was caught by the assertion that the arms differ FROM EACH OTHER; asserting
        each arm's own expected value would have reported it as an ordinary refusal.
        """
        path = Path(directory) / name
        path.write_text(json.dumps(_manifest_with(bindings)), encoding="utf-8")
        return str(path)

    def test_the_pass_and_the_refusal_differ_in_exit_code_and_in_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            allowed = self._manifest_file(directory, "three-enrollments.json", [
                _binding("custodian-a", "a", "active"),
                _binding("custodian-b", "b", "active"),
                _binding("custodian-c", "c", "active"),
            ])
            refused = self._manifest_file(directory, "two-enrollments.json", [
                _binding("custodian-a", "a", "active"),
                _binding("custodian-b", "b", "active"),
            ])
            self.assertNotEqual(
                Path(allowed).read_text(), Path(refused).read_text(),
                "the two arms are the same file, so they cannot distinguish anything")
            good = self._run(allowed, "--object", FIDO_OBJECT, "--retiring", "fido-admin-a")
            bad = self._run(refused, "--object", FIDO_OBJECT, "--retiring", "fido-admin-a")

        self.assertEqual(bad.returncode, 1, bad.stderr)
        self.assertIn("REFUSED", bad.stderr)
        self.assertNotIn("usage:", bad.stderr,
                         "the refusal was argparse, not the guard: the arm never reached the rule")
        self.assertEqual(good.returncode, 0, good.stderr)
        # A pass must be visibly a different thing, and must not read as authorization.
        self.assertNotEqual(good.returncode, bad.returncode)
        self.assertIn("NOT AUTHORIZATION", good.stdout)
        self.assertIn("second person must", good.stdout)

    def test_a_missing_manifest_is_refused_rather_than_traced(self):
        result = self._run("/nonexistent/manifest.json", "--object", FIDO_OBJECT, "--retiring", "x")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot read the manifest", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_manifest_that_is_not_an_object_is_refused_rather_than_traced(self):
        """json.loads accepts any JSON document. `[]` and `"x"` parse cleanly and then die in
        `manifest.get(...)` with an AttributeError — a traceback on the same read path the test
        above exists to keep free of them. The file is well-formed JSON, so the read succeeded;
        what failed is the assumption about its shape, and that has to be stated."""
        for document in ("[]", '"x"', "42", "null"):
            with self.subTest(document=document):
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
                    handle.write(document)
                    path = handle.name
                try:
                    result = self._run(path, "--object", FIDO_OBJECT, "--retiring", "x")
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("REFUSED", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                finally:
                    os.unlink(path)


if __name__ == "__main__":
    unittest.main()
