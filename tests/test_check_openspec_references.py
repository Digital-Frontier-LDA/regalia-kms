import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.check_openspec_references import (
    AUTHORING, COVERAGE, DELTA, Files, IntegrityError, MAIN,
    PROPOSED, REGISTRY, ReferenceChecker, sha256,
)


class StaticProduct:
    revision = "a" * 40
    tree = "b" * 40
    data = b"package example\n\tvalue := 1\n"

    def require_blob(self, name):
        if name != "code.go":
            raise IntegrityError("MISSING_PINNED_BLOB", name)

    def read(self, name):
        self.require_blob(name)
        return self.data


class ReferenceIntegrity(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.product = StaticProduct()
        self.case_file = COVERAGE + "reconciled-cases.json"
        self.candidate_record = COVERAGE + "test-candidate.json"
        self.candidate_file = "wire_test.go"
        self.raw_file = COVERAGE + "runtime-interface-ledger.json"
        self.external_contract = COVERAGE + "upstream-contract.json"
        self.cache_file = COVERAGE + "external-sources/example/key.proto"
        self.license_file = COVERAGE + "external-sources/example/LICENSE"
        self.spec_path = DELTA + "runtime/example/spec.md"
        self.proposal_path = PROPOSED + "baremetal/example/spec.md"
        self.write(COVERAGE + "capability-catalog.json",
                   [{"path": "runtime/example", "prefix": "KMS-EX", "owner": "runtime", "scope": "fixture"}])
        spec = ("### Requirement: KMS-EX-001 First\n\n#### Scenario: Shared name\n\n"
                "### Requirement: KMS-EX-002 Second\n\n#### Scenario: Only in second\n")
        self.write(self.spec_path, "## ADDED Requirements\n\n" + spec)
        self.write(MAIN + "runtime/example/spec.md", "## Requirements\n\n" + spec)
        self.write(self.proposal_path,
                   "## ADDED Requirements\n\n### Requirement: KMS-GEN-001 Example\n\n#### Scenario: Proposed only\n")
        self.write(self.raw_file, self.pinned(cases=[{"id": "example"}, {"id": "planned"}]))
        self.write(self.candidate_file, "package example\n// new test\n")
        self.write(self.candidate_record, {
            "schemaVersion": 1, "productSourceRevision": self.product.revision, "productSourceTree": self.product.tree,
            "candidateTestPath": self.candidate_file, "candidateTestSha256": self.hash(self.candidate_file),
            "cases": ["example"],
        })
        ext_data = b"syntax = \"proto3\";\n"
        license_data = b"Fixture notice\n"
        self.write(self.cache_file, ext_data)
        self.write(self.license_file, license_data)
        self.external = ("official/example", "c"*40, "wire/key.proto")
        repo, rev, path = self.external
        self.external_url = f"https://github.com/{repo}/blob/{rev}/{path}"
        external_source = {"repository": repo, "revision": rev, "repositoryPath": path,
                           "gitBlob": self.git_blob(ext_data), "sha256": sha256(ext_data),
                           "cachePath": self.cache_file, "url": self.external_url}
        self.write(self.external_contract, {"schemaVersion": 1, "provenance": {
            "repository": repo, "commit": rev, "files": {"key.proto": {
                "repoPath": path, "gitBlob": self.git_blob(ext_data), "sha256": sha256(ext_data),
                "url": self.external_url, "size": len(ext_data),
            }},
        }})
        self.write(REGISTRY, {"schemaVersion": 1, "contracts": [{
            "sourceRecord": self.external_contract, "sources": [external_source],
            "license": {"repositoryPath": "LICENSE", "gitBlob": self.git_blob(license_data),
                        "sha256": sha256(license_data), "cachePath": self.license_file,
                        "url": f"https://github.com/{repo}/blob/{rev}/LICENSE"},
        }]})
        for name, (label, _) in AUTHORING.items():
            requirements = []
            if name == "runtime.json":
                for ident, title in (("KMS-EX-001", "First"), ("KMS-EX-002", "Second")):
                    requirements.append({
                        "id": ident, "title": title, "capability": "runtime/example",
                        "status": "UNVERIFIED", "rationale": "fixture", "tests": [], "beads": [],
                        "executionEvidence": [], "sources": [{"path": "code.go", "line": 2, "symbol": "fixture"}],
                    })
            self.write(COVERAGE + name, self.pinned(owner=label, requirements=requirements, sourceAreas=[], knownGaps=[]))
        self.case = {
            "id": "example", "owner": "runtime", "classification": "test_gap",
            "origin": {"path": self.raw_file, "caseId": "example"},
            "scenarioRefs": [{"path": self.spec_path, "requirementId": "KMS-EX-001",
                              "scenario": "Shared name", "relation": "direct"}],
            "workflowContextScenarioRefs": [{"path": self.spec_path, "requirementId": "KMS-EX-002",
                                              "scenario": "Only in second", "relationship": "trigger-context"}],
            "enforcingSource": [{"path": "code.go", "line": 2, "sha256": sha256(self.product.data)}],
            "assertions": [],
            "supportingContractTraceGroups": [
                {"path": "code.go", "role": "enforcing", "fileSha256": sha256(self.product.data),
                 "anchors": [{"line": 2, "text": "value := 1"}]},
                {"path": "code.go", "role": "enforcing", "sha256": sha256(self.product.data),
                 "anchors": [{"line": 2, "text": "\tvalue := 1", "lineSha256": sha256(b"\tvalue := 1")}]},
            ],
            "candidateAssertionGroups": {
                "sourceStatus": "candidate only", "baseRevision": self.product.revision,
                "groups": [{"path": self.candidate_file, "role": "scratch_test_candidate",
                            "sha256": self.hash(self.candidate_file),
                            "anchors": [{"line": 2, "text": "// new test"}]}],
            },
            "externalContractSourceGroups": [{
                "repository": repo, "revision": rev, "repositoryPath": path, "url": self.external_url,
                "role": "official_upstream_source", "scope": "fixture", "fileSha256": sha256(ext_data),
                "anchors": [{"line": 1, "text": ext_data.decode().strip()}],
            }],
            "previousScenarioRefs": [{"path": "formerly.md", "requirementId": "old", "scenario": "Old"}],
            "legacyAssertionRefs": [{"path": "old_test.go", "line": 500}],
            "executionEvidence": [{"status": "pass", "reviewer": "forged example"}],
        }
        self.proposed_case = {
            "id": "planned", "owner": "runtime", "classification": "proposed",
            "origin": {"path": self.raw_file, "caseId": "planned"},
            "scenarioRefs": [{"path": self.proposal_path, "requirementId": "KMS-GEN-001",
                              "scenario": "Proposed only", "relation": "proposed_only"}],
            "enforcingSource": [], "assertions": [],
        }

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, str):
            path.write_text(value)
        elif isinstance(value, bytes):
            path.write_bytes(value)
        else:
            path.write_text(json.dumps(value))

    def hash(self, name):
        return sha256((self.root / name).read_bytes())

    def pinned(self, **fields):
        return {"schemaVersion": 1, "sourceRevision": self.product.revision, "sourceTree": self.product.tree, **fields}

    def git_blob(self, data):
        return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()

    def edit_json(self, name, edit):
        value = json.loads((self.root / name).read_text())
        edit(value)
        self.write(name, value)

    def check(self, cases=None):
        files = (self.raw_file, self.candidate_record, self.external_contract)
        self.write(self.case_file, self.pinned(
            cases=[self.case, self.proposed_case] if cases is None else cases,
            inputDigests={Path(path).name: self.hash(path) for path in files},
            localTestCandidates=[{"path": self.candidate_record, "sha256": self.hash(self.candidate_record),
                                  "qualification": "candidate fixture"}],
            previousLocalTestCandidates=[{"path": "old-record.json", "sha256": "ignore historical input"}],
        ))
        return ReferenceChecker(Files(self.root), self.product).check()

    def rejected(self, code, **kwargs):
        with self.assertRaises(IntegrityError) as caught:
            self.check(**kwargs)
        self.assertEqual(caught.exception.code, code)

    def test_reference_integrity_has_no_authority(self):
        result = self.check()
        self.assertTrue(result["referenceIntegrity"])
        self.assertFalse(result["coverageComplete"])
        self.assertEqual(result["verificationAuthority"], "not-assessed")
        self.assertEqual(result["counts"]["canonicalCases"], 2)
        self.assertEqual(result["counts"]["baselineRequirements"], 2)
        for name in ("authoringRows", "baselineScenarios"):
            self.assertEqual(result["counts"][name], 2)
        for name in ("directScenarioRefs", "contextScenarioRefs", "proposedOnlyScenarioRefs", "previousScenarioRefsExcluded",
                     "legacyAssertionRefsExcluded", "rawHashedAnchors", "externalGroups", "candidateFiles", "candidateGroups"):
            self.assertEqual(result["counts"][name], 1, name)
        self.assertEqual(result["counts"]["strippedAnchors"], 3)

    def test_scenario_must_belong_to_named_requirement(self):
        self.case["scenarioRefs"][0]["scenario"] = "Only in second"
        self.rejected("SCENARIO_NOT_UNDER_REQUIREMENT")

    def test_proposal_cannot_be_used_as_direct_baseline_ref(self):
        self.proposed_case["scenarioRefs"][0]["relation"] = "direct"
        self.rejected("PROPOSED_SCENARIO_SCOPE")

    def test_main_and_delta_identities_must_agree(self):
        path = MAIN + "runtime/example/spec.md"
        self.write(path, (self.root / path).read_text().replace("Shared name", "Renamed"))
        self.rejected("MAIN_DELTA_IDENTITY_MISMATCH")

    def test_duplicate_case_id_is_refused(self):
        self.rejected("DUPLICATE_CASE_ID", cases=[self.case, self.case])

    def test_duplicate_requirement_id_is_refused(self):
        path = MAIN + "runtime/example/spec.md"
        with (self.root / path).open("a") as f:
            f.write("\n### Requirement: KMS-EX-001 Repeated\n")
        self.rejected("DUPLICATE_REQUIREMENT_ID")

    def test_missing_authoring_row(self):
        self.edit_json(COVERAGE + "runtime.json", lambda value: value["requirements"].pop())
        self.rejected("MISSING_AUTHORING_ROW")

    def test_flat_source_hash_must_match_pinned_bytes(self):
        self.case["enforcingSource"][0]["sha256"] = "0"*64
        self.rejected("SOURCE_HASH_MISMATCH")

    def test_no_snapshot_fallback_for_missing_product_blob(self):
        self.write("missing.go", "pretend product")
        self.case["enforcingSource"][0]["path"] = "missing.go"
        self.rejected("MISSING_PINNED_BLOB")

    def test_anchors_respect_source_line_bounds(self):
        self.case["supportingContractTraceGroups"][0]["anchors"][0]["line"] = 30
        self.rejected("LINE_OUT_OF_RANGE")

    def test_stripped_anchor_compares_text(self):
        self.case["supportingContractTraceGroups"][0]["anchors"][0]["text"] = "value := 2"
        self.rejected("ANCHOR_TEXT_MISMATCH")

    def test_hashed_anchor_is_raw_not_stripped(self):
        self.case["supportingContractTraceGroups"][1]["anchors"][0]["text"] = "value := 1"
        self.rejected("ANCHOR_TEXT_MISMATCH")

    def test_line_hash_not_just_text(self):
        self.case["supportingContractTraceGroups"][1]["anchors"][0]["lineSha256"] = "f"*64
        self.rejected("ANCHOR_LINE_HASH_MISMATCH")

    def test_group_file_hash_supports_both_declared_spellings(self):
        self.case["supportingContractTraceGroups"][0]["fileSha256"] = "f"*64
        self.rejected("SOURCE_HASH_MISMATCH")

    def test_candidate_record_file_hash_must_match(self):
        self.write(self.candidate_file, "package example\n// new test\n// unanchored edit\n")
        self.rejected("CANDIDATE_HASH_MISMATCH")

    def test_candidate_group_must_match_its_record_hash(self):
        self.case["candidateAssertionGroups"]["groups"][0]["sha256"] = "0"*64
        self.rejected("CANDIDATE_GROUP_HASH_MISMATCH")

    def test_candidate_reference_must_be_bound_to_case(self):
        self.edit_json(self.candidate_record, lambda value: value["cases"].append("unknown"))
        self.rejected("CANDIDATE_CASE_LINK_MISMATCH")

    def test_candidate_group_rejects_a_record_for_another_case(self):
        self.edit_json(self.candidate_record, lambda value: value.update(cases=["planned"]))
        self.rejected("CANDIDATE_CASE_SCOPE")

    def test_external_revision_must_match_bound_official_source(self):
        self.case["externalContractSourceGroups"][0]["revision"] = "d"*40
        self.rejected("EXTERNAL_REFERENCE_UNBOUND")

    def test_external_reference_hash_must_match_its_binding(self):
        self.case["externalContractSourceGroups"][0]["fileSha256"] = "0"*64
        self.rejected("EXTERNAL_REFERENCE_BINDING_MISMATCH")

    def test_registry_path_id_must_match_contract(self):
        self.edit_json(REGISTRY, lambda v: v["contracts"][0]["sources"][0].update(repositoryPath="elsewhere.proto"))
        self.rejected("EXTERNAL_REGISTRY_BINDING_MISMATCH")

    def test_external_cache_cannot_be_replaced_with_snapshot_blob(self):
        self.write(self.cache_file, "syntax = \"proto2\";\n")
        self.rejected("EXTERNAL_CACHE_HASH_MISMATCH")

    def test_entrypoint_has_no_path_escape(self):
        self.case["scenarioRefs"][0]["path"] = "../outside.md"
        self.rejected("UNSAFE_PATH")

    def test_snapshot_refuses_symlink_even_if_data_matches(self):
        path = self.root / self.candidate_file
        data = path.read_bytes()
        path.unlink()
        self.write("copy.go", data)
        path.symlink_to("copy.go")
        self.rejected("SYMLINK_PATH")


    def schema_documents(self):
        return (
            self.case_file, COVERAGE + "runtime.json", self.raw_file,
            self.candidate_record, REGISTRY, self.external_contract,
        )

    def reject_schema_versions(self, versions):
        self.check()  # All six documents allow the integer version 1.
        for path in self.schema_documents():
            original = (self.root / path).read_bytes()
            for version in versions:
                with self.subTest(path=path, version=version):
                    self.edit_json(path, lambda doc: doc.update(schemaVersion=version))
                    try:
                        with self.assertRaises(IntegrityError) as caught:
                            if path == self.case_file:
                                ReferenceChecker(Files(self.root), self.product).check()
                            else:
                                # Refresh the fixture's aggregate hashes so schema
                                # validation, not unrelated hash drift, decides.
                                self.check()
                        self.assertEqual(caught.exception.code, "SCHEMA_VERSION")
                        self.assertEqual(caught.exception.where, path)
                    finally:
                        self.write(path, original)

    def test_boolean_schema_versions_are_refused_in_all_six_documents(self):
        self.reject_schema_versions((True, False))

    def test_float_string_and_other_schema_versions_are_refused(self):
        self.reject_schema_versions((1.0, "1", 0, 2))

    def test_non_finite_json_constants_are_refused_in_opaque_authoring_metadata(self):
        path = COVERAGE + "runtime.json"
        original = (self.root / path).read_bytes()
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                self.write(path, original.replace(b'"rationale": "fixture"', f'"rationale": {token}'.encode(), 1))
                try:
                    self.rejected("INVALID_JSON_CONSTANT")
                finally:
                    self.write(path, original)

    def test_duplicate_json_keys_remain_refused(self):
        path = COVERAGE + "runtime.json"
        original = (self.root / path).read_text()
        self.write(path, '{"schemaVersion": 1, ' + original[1:])
        self.rejected("DUPLICATE_JSON_KEY")



class ReferenceEntrypoint(unittest.TestCase):
    script = Path(__file__).resolve().parents[1] / "tools/check_openspec_references.py"

    def invoke(self, arguments, env=None):
        return subprocess.run(
            [sys.executable, "-BEs", str(self.script), *arguments],
            capture_output=True, text=True, env=env, timeout=15,
        )

    def test_missing_unknown_and_shortened_options_are_usage_errors(self):
        required = ["--snapshot", "/absent", "--source-repo", "/absent", "--source-revision", "a" * 40]
        for args in (required[:-2], required + ["--unknown"], ["--snap", *required[1:]],
                     [*required[:2], "--source-rep", *required[3:]],
                     [*required[:4], "--source-rev", required[5]]):
            with self.subTest(args=args):
                result = self.invoke(args)
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertEqual(result.stdout, "")
                self.assertIn("usage:", result.stderr)

    def test_help_is_text_and_does_not_access_inputs_or_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "git-accessed"
            git = root / "git"
            git.write_text('#!/bin/sh\n: > "$GIT_MARKER"\nexit 92\n')
            git.chmod(0o700)
            env = {**os.environ, "PATH": f"{root}{os.pathsep}{os.environ['PATH']}", "GIT_MARKER": str(marker)}
            for args in (["-h"], ["--snapshot", str(root / "missing"), "--source-repo", str(root),
                                   "--source-revision", "a" * 40, "--help"]):
                with self.subTest(args=args):
                    result = self.invoke(args, env)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertIn("usage:", result.stdout)
                    for option in ("--snapshot", "--source-repo", "--source-revision"):
                        self.assertIn(option, result.stdout)
                    self.assertFalse(marker.exists())

    def test_full_options_reach_checking_and_emit_json_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            absent = str(Path(directory) / "absent")
            result = self.invoke(["--snapshot", absent, "--source-repo", absent, "--source-revision", "a" * 40])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "")
        payload = json.loads(result.stdout)
        self.assertIs(payload["referenceIntegrity"], False)
        self.assertIs(payload["coverageComplete"], False)
        self.assertEqual(payload["verificationAuthority"], "not-assessed")
        self.assertEqual(payload["error"]["code"], "INPUT_SHAPE_OR_READ_ERROR")



if __name__ == "__main__":
    unittest.main()
