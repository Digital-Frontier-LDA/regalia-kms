#!/usr/bin/env python3
"""Validate declared OpenSpec references without assessing evidence or authority."""

import argparse
from collections import Counter
from functools import cache
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess


COVERAGE = "openspec/coverage/"
MAIN = "openspec/specs/"
DELTA = "openspec/changes/document-kms-spec-baseline/specs/"
PROPOSED = "openspec/changes/close-single-node-no-history-bootstrap/specs/"
REGISTRY = COVERAGE + "external-sources/registry.json"
AUTHORING = {
    "runtime.json": ("runtime", "runtime"),
    "baremetal.json": ("baremetal", "baremetal"),
    "runtime-scenario-supplement.json": ("runtime-parent-supplement", "runtime"),
    "baremetal-scenario-supplement.json": ("baremetal-parent-supplement", "baremetal"),
    "workflow-authoring-supplement.json": ("runtime", "runtime"),
}
PRODUCT_GROUPS = (
    "supportingContractTraceGroups", "assertionGroups",
    "relatedStructuralAssertionGroups",
)
CASE_METADATA = set("""
    interfaceId facet outcome classification reviewStatus evidenceTier executionEvidence gaps
    owner input classificationProvenance resolutionReasoning remainingEvidenceGap
    priorExecutionStatus assertionGap previousGaps previousInput previousOutcome
    scopeNote routeConfiguration
    decisionNeeded observedAtPin unresolvedOriginalScope
    verificationScope previousScenarioRefs legacyAssertionRefs assertionInterpretation
    outsideProof verificationProof unsupportedResidual acceptedQualifiedScope
    compatibilityLimits scopeDecision priorPartialContract priorUnsupportedResidual
""".split())
CASE_REFERENCE_FIELDS = {
    "id", "origin", "scenarioRefs", "workflowContextScenarioRefs",
    "enforcingSource", "assertions", "relatedComponentAssertionGroups",
    "externalContractSourceGroups", "candidateAssertionGroups", "acceptedQualifiedContracts",
    "workflowDeclarationContract", "relatedAssertionGroupIds", *PRODUCT_GROUPS,
}


class IntegrityError(ValueError):
    def __init__(self, code, where):
        super().__init__(f"{code}: {where}")
        self.code = code
        self.where = where


def require(condition, code, where):
    if not condition:
        raise IntegrityError(code, where)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_JSON_KEY", key)
        result[key] = value
    return result


def shape(record, required, optional, where):
    require(isinstance(record, dict), "OBJECT_REQUIRED", where)
    keys = set(record)
    require(required <= keys, "MISSING_FIELD", f"{where}: {sorted(required - keys)}")
    require(keys <= required | optional, "UNKNOWN_FIELD", f"{where}: {sorted(keys - required - optional)}")


def require_schema_v1(document, where):
    version = document.get("schemaVersion")
    require(type(version) is int and version == 1, "SCHEMA_VERSION", where)


def sequence(value, where):
    require(isinstance(value, list), "ARRAY_REQUIRED", where)
    return value


def string(value, where):
    require(isinstance(value, str) and value.strip(), "STRING_REQUIRED", where)
    return value


def check_hex(value, length, where):
    require(isinstance(value, str) and re.fullmatch(f"[a-f0-9]{{{length}}}", value),
            "INVALID_DIGEST", where)
    return value


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest(data, expected, code, where):
    require(sha256(data) == check_hex(expected, 64, where), code, where)


def relative(value):
    value = string(value, "relative path")
    parts = value.split("/")
    require(not any(p in {"", ".", ".."} for p in parts)
            and not any(c in value for c in "\0\r\n\\:"), "UNSAFE_PATH", value)
    return PurePosixPath(value)


class Files:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.hashes = {}
        self.contents = {}

    def path(self, name):
        path = self.root
        for part in relative(name).parts:
            path /= part
            require(not path.is_symlink(), "SYMLINK_PATH", name)
        return path

    def read(self, name):
        if name not in self.contents:
            path = self.path(name)
            require(path.is_file(), "MISSING_SNAPSHOT_FILE", name)
            data = path.read_bytes()
            self.hashes[name] = sha256(data)
            self.contents[name] = data
        return self.contents[name]

    def json(self, name):
        def reject_constant(token):
            raise IntegrityError("INVALID_JSON_CONSTANT", f"{name}: {token}")

        try:
            return json.loads(self.read(name), object_pairs_hook=unique_pairs, parse_constant=reject_constant)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise IntegrityError("INVALID_JSON", f"{name}: {exc}") from exc

    def specs(self, prefix):
        root = self.path(prefix.rstrip("/"))
        require(root.is_dir(), "MISSING_SPEC_ROOT", prefix)
        return {f.relative_to(root).parent.as_posix(): f.relative_to(self.root).as_posix()
                for f in root.rglob("spec.md")}


class GitSource:
    """A local-only reader over regular blobs in the explicitly named revision."""

    def __init__(self, repo, revision):
        self.repo = Path(repo).resolve(strict=True)
        self.revision = check_hex(revision, 40, "product revision")
        self.env = {
            **{key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "",
        }
        self.tree = self.git("rev-parse", "--verify", f"{revision}^{{tree}}").decode().strip()
        require(self.git("cat-file", "-t", revision) == b"commit\n", "SOURCE_NOT_COMMIT", revision)
        self.blobs = {}
        for row in self.git("ls-tree", "-rz", self.tree).split(b"\0"):
            if row:
                fields, name = row.split(b"\t", 1)
                mode, kind, oid = fields.decode().split()
                if kind == "blob" and mode in {"100644", "100755"}:
                    self.blobs[name.decode()] = oid

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repo), *args], env=self.env,
                                capture_output=True, timeout=30)
        require(result.returncode == 0, "LOCAL_GIT_READ_FAILED", " ".join(args))
        return result.stdout

    def require_blob(self, path):
        relative(path)
        require(path in self.blobs, "MISSING_PINNED_BLOB", path)

    @cache
    def read(self, path):
        self.require_blob(path)
        return self.git("cat-file", "blob", self.blobs[path])


def spec_identity(data, where):
    requirements = {}
    scenarios = None
    fence = None
    section = None
    for line in data.decode().splitlines():
        marker = re.match(r"^\s*(\x60{3,}|~{3,})", line)
        if marker:
            token = marker[1]
            if fence:
                if token[0] == fence[0] and len(token) >= len(fence) and not line[marker.end():].strip():
                    fence = None
            else:
                fence = token
            continue
        if fence:
            continue
        if line.startswith("## "):
            section = line
            scenarios = None
        if line.startswith("### Requirement:"):
            require(section in {"## Requirements", "## ADDED Requirements"},
                    "REQUIREMENT_OUTSIDE_SECTION", where)
            heading = re.fullmatch(r"### Requirement: (\S+) (\S.*)", line)
            require(heading is not None, "INVALID_REQUIREMENT_HEADING", where)
            ident, title = heading.groups()
            require(ident not in requirements, "DUPLICATE_REQUIREMENT_ID", f"{where}: {ident}")
            scenarios = set()
            requirements[ident] = (title.strip(), scenarios)
        if line.startswith("#### Scenario:"):
            name = string(line.removeprefix("#### Scenario:").strip(), where)
            require(scenarios is not None, "SCENARIO_WITHOUT_REQUIREMENT", f"{where}: {name}")
            require(name not in scenarios, "DUPLICATE_SCENARIO_IDENTITY", f"{where}: {name}")
            scenarios.add(name)
    require(not fence and requirements, "INVALID_SPEC_STRUCTURE", where)
    return requirements


def source_line(lines, line_number, where):
    require(type(line_number) is int and 0 < line_number <= len(lines),
            "LINE_OUT_OF_RANGE", f"{where}:{line_number}")
    return lines[line_number - 1]


def file_hash(record, where, required):
    keys = {"sha256", "fileSha256"} & record.keys()
    require(len(keys) == 1 or not keys and not required, "FILE_HASH_SHAPE", where)
    return check_hex(record[next(iter(keys))], 64, where) if keys else None


class ReferenceChecker:
    def __init__(self, files, product):
        self.files = files
        self.product = product
        self.count = Counter()
        self.specs = {}
        self.requirements = {}
        self.catalog = {}
        self.cases = {}
        self.current_candidates = {}
        self.externals = {}
        self.contract_records = set()
        self.ledger_links = {}

    def pinned(self, doc, path):
        require_schema_v1(doc, path)
        require(doc.get("sourceRevision") == self.product.revision, "SOURCE_PIN_MISMATCH", path)
        if "sourceTree" in doc:
            require(doc["sourceTree"] == self.product.tree, "SOURCE_TREE_MISMATCH", path)

    @cache
    def spec(self, path):
        return spec_identity(self.files.read(path), path)

    def check_specs(self):
        for row in sequence(self.files.json(COVERAGE + "capability-catalog.json"), "catalog"):
            shape(row, {"path", "prefix", "owner", "scope"}, set(), "catalog row")
            cap = relative(row["path"]).as_posix()
            require(cap not in self.catalog, "DUPLICATE_CAPABILITY", cap)
            self.catalog[cap] = row
        for prefix in (MAIN, DELTA):
            spec_files = self.files.specs(prefix)
            require(set(spec_files) == set(self.catalog), "CATALOG_SPEC_SET",
                    f"{prefix} missing={sorted(set(self.catalog)-set(spec_files))} "
                    f"extra={sorted(set(spec_files)-set(self.catalog))}")
        for cap, entry in self.catalog.items():
            main = self.spec(f"{MAIN}{cap}/spec.md")
            delta_path = f"{DELTA}{cap}/spec.md"
            delta = self.spec(delta_path)
            require(main == delta, "MAIN_DELTA_IDENTITY_MISMATCH", cap)
            for ident, (title, names) in main.items():
                require(ident not in self.requirements, "DUPLICATE_REQUIREMENT_ID", ident)
                prefix = string(entry["prefix"], cap)
                require(re.fullmatch(re.escape(prefix) + r"-\d{3,}", ident),
                        "REQUIREMENT_PREFIX_MISMATCH", ident)
                self.requirements[ident] = (cap, title, entry["owner"])
                self.count["baselineScenarios"] += len(names)
            self.specs[delta_path] = delta
            self.specs[f"{MAIN}{cap}/spec.md"] = main
        self.count["capabilities"] = len(self.catalog)
        self.count["baselineRequirements"] = len(self.requirements)

    @cache
    def product_lines(self, path):
        data = self.product.read(path)
        return data, data.decode().splitlines()

    def locator(self, ref, where, kind):
        shape(ref, {"path", "line"}, {"symbol", "supports", "testSymbol", "sha256", "fileSha256", "text"}, where)
        path = relative(ref["path"]).as_posix()
        data, lines = self.product_lines(path)
        observed = source_line(lines, ref["line"], path)
        expected = file_hash(ref, where, required=False)
        if expected is not None:
            digest(data, expected, "SOURCE_HASH_MISMATCH", path)
        if "text" in ref:
            require(ref["text"] == observed, "SOURCE_TEXT_MISMATCH", f"{path}:{ref['line']}")
        self.count[kind] += 1
        self.count["hashedFlatLocators"] += expected is not None

    def check_authoring(self):
        authored = set()
        for name, (declared_owner, owner) in AUTHORING.items():
            path = COVERAGE + name
            doc = self.files.json(path)
            shape(doc, {"schemaVersion", "sourceRevision", "owner", "requirements", "sourceAreas", "knownGaps"},
                  {"sourceTree"}, path)
            self.pinned(doc, path)
            require(doc["owner"] == declared_owner, "AUTHORING_OWNER_MISMATCH", path)
            for row in sequence(doc["requirements"], path):
                shape(row, {"id", "capability", "title", "status", "sources", "tests", "rationale",
                            "executionEvidence", "beads"}, {"caseIds"}, path)
                ident = string(row["id"], path)
                require(ident not in authored, "DUPLICATE_AUTHORING_ID", ident)
                require(self.requirements.get(ident) == (row["capability"], row["title"], owner),
                        "AUTHORING_IDENTITY_MISMATCH", ident)
                authored.add(ident)
                for role in ("sources", "tests"):
                    for ref in sequence(row[role], ident):
                        self.locator(ref, ident, "authoringLocators")
                for case_id in sequence(row.get("caseIds", []), ident):
                    require(case_id in self.cases, "UNKNOWN_AUTHORING_CASE", f"{ident}: {case_id}")
                    self.count["authoringCaseLinks"] += 1
            for area in sequence(doc["sourceAreas"], path):
                for source_path in sequence(area["paths"], path):
                    self.product.require_blob(source_path)
                    self.count["authoringSourcePaths"] += 1
                for cap in sequence(area["capabilities"], path):
                    require(cap in self.catalog, "UNKNOWN_AUTHORING_CAPABILITY", cap)
            for gap in sequence(doc["knownGaps"], path):
                for cap in sequence(gap["capabilities"], path):
                    require(cap in self.catalog, "UNKNOWN_AUTHORING_CAPABILITY", cap)
        require(authored == set(self.requirements), "MISSING_AUTHORING_ROW",
                ", ".join(sorted(set(self.requirements)-authored)))
        self.count["authoringRows"] = len(authored)


    def load_cases(self):
        path = COVERAGE + "reconciled-cases.json"
        doc = self.files.json(path)
        shape(doc, {"schemaVersion", "sourceRevision", "sourceTree", "cases", "inputDigests",
                    "localTestCandidates", "previousLocalTestCandidates"},
              {"discoveryClosed", "coverageComplete", "ciEnforced", "coverageClaim",
               "summary", "discovery", "historicalProofAcceptance"}, path)
        self.pinned(doc, path)
        for row in sequence(doc["cases"], path):
            shape(row, {"id", "origin", "scenarioRefs", "enforcingSource", "assertions",
                        "classification", "owner"},
                  CASE_REFERENCE_FIELDS | CASE_METADATA, path)
            ident = string(row["id"], path)
            require(ident not in self.cases, "DUPLICATE_CASE_ID", ident)
            self.cases[ident] = row
        self.count["canonicalCases"] = len(self.cases)
        for filename, expected in doc["inputDigests"].items():
            relative(filename)
            require("/" not in filename, "INVALID_COVERAGE_INPUT", filename)
            input_path = COVERAGE + filename
            digest(self.files.read(input_path), expected, "COVERAGE_INPUT_HASH_MISMATCH", input_path)
            self.ledger_links[input_path] = expected
        self.count["aggregateInputDigests"] = len(self.ledger_links)
        if "historicalProofAcceptance" in doc:
            pointer = doc["historicalProofAcceptance"]
            shape(pointer, {"path", "sha256", "profile", "scope"}, set(), path)
            self.require_ledger_link(pointer["path"], pointer["sha256"])
            self.count["historicalMetadataPointers"] += 1
        self.count["historicalCandidatePointersExcluded"] = len(sequence(doc["previousLocalTestCandidates"], path))
        return doc

    def require_ledger_link(self, path, expected=None):
        relative(path)
        require(path in self.ledger_links, "UNBOUND_COVERAGE_INPUT", path)
        if expected is not None:
            require(expected == self.ledger_links[path], "COVERAGE_INPUT_POINTER_HASH_MISMATCH", path)

    @cache
    def raw_ids(self, path):
        self.require_ledger_link(path)
        doc = self.files.json(path)
        self.pinned(doc, path)
        rows = sequence(doc["cases"], path)
        values = {string(row["id"], path) for row in rows}
        require(len(values) == len(rows), "DUPLICATE_ORIGIN_CASE_ID", path)
        return values

    def check_candidates(self, records):
        for pointer in sequence(records, "localTestCandidates"):
            shape(pointer, {"path", "sha256", "qualification"}, set(), "candidate pointer")
            path = pointer["path"]
            self.require_ledger_link(path, pointer["sha256"])
            record = self.files.json(path)
            require_schema_v1(record, path)
            require((record.get("productSourceRevision"), record.get("productSourceTree"))
                    == (self.product.revision, self.product.tree), "CANDIDATE_SOURCE_PIN_MISMATCH", path)
            if "testFiles" in record:
                require(not ({"candidateTestPath", "candidateTestSha256"} & record.keys())
                        and isinstance(record["testFiles"], dict), "CANDIDATE_FILE_SHAPE", path)
                files = record["testFiles"]
            else:
                require({"candidateTestPath", "candidateTestSha256"} <= record.keys(),
                        "CANDIDATE_FILE_SHAPE", path)
                files = {record["candidateTestPath"]: record["candidateTestSha256"]}
            require(files, "CANDIDATE_FILE_SHAPE", path)
            if "upstreamSourceRecord" in record:
                self.require_ledger_link(record["upstreamSourceRecord"])
            ids = sequence(record["cases"], path)
            require(len(ids) == len(set(ids)) and all(i in self.cases for i in ids),
                    "CANDIDATE_CASE_LINK_MISMATCH", path)
            for name, expected in files.items():
                name = relative(name).as_posix()
                require(re.search(r"(?:_test\.go|(?:^|/)test_[^/]+\.py)$", name),
                        "NOT_TEST_CANDIDATE_PATH", name)
                data = self.files.read(name)
                digest(data, expected, "CANDIDATE_HASH_MISMATCH", name)
                require(name not in self.current_candidates, "DUPLICATE_CANDIDATE_PATH", name)
                self.current_candidates[name] = (data, expected, set(ids))
                self.count["candidateFiles"] += 1
            self.count["candidateRecords"] += 1
            self.count["candidateCaseLinks"] += len(ids)

    def check_external_registry(self):
        registry = self.files.json(REGISTRY)
        shape(registry, {"schemaVersion", "contracts"}, set(), REGISTRY)
        require_schema_v1(registry, REGISTRY)
        for record in sequence(registry["contracts"], REGISTRY):
            shape(record, {"sourceRecord", "license", "sources"}, set(), REGISTRY)
            source_path = record["sourceRecord"]
            self.require_ledger_link(source_path)
            require(source_path not in self.contract_records, "DUPLICATE_EXTERNAL_SOURCE_RECORD", source_path)
            self.contract_records.add(source_path)
            upstream_doc = self.files.json(source_path)
            require_schema_v1(upstream_doc, source_path)
            upstream = upstream_doc["provenance"]
            repository = string(upstream["repository"], source_path)
            require(re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", repository),
                    "EXTERNAL_REPOSITORY_SHAPE", repository)
            revision = check_hex(upstream["commit"], 40, source_path)
            frozen = {v["repoPath"]: v for v in upstream["files"].values()}
            require(len(frozen) == len(upstream["files"]), "DUPLICATE_EXTERNAL_PATH", source_path)
            observed = set()
            for item in sequence(record["sources"], REGISTRY):
                shape(item, {"repository", "revision", "repositoryPath", "gitBlob", "sha256", "cachePath", "url"}, set(), REGISTRY)
                name = relative(item["repositoryPath"]).as_posix()
                binding = (item["repository"], item["revision"], name)
                require(binding not in self.externals, "DUPLICATE_EXTERNAL_BINDING", str(binding))
                expected = frozen.get(name, {})
                require(binding[:2] == (repository, revision)
                        and all(item[k] == expected.get(k) for k in ("gitBlob", "sha256", "url")),
                        "EXTERNAL_REGISTRY_BINDING_MISMATCH", str(binding))
                data = self.cached_external(item, repository, revision)
                require(len(data) == expected["size"], "EXTERNAL_SIZE_MISMATCH", name)
                self.externals[binding] = (data, item["sha256"], item["url"])
                observed.add(name)
                self.count["externalCachedSources"] += 1
            require(observed == set(frozen), "EXTERNAL_CACHE_SET_MISMATCH", source_path)
            license_ref = record["license"]
            shape(license_ref, {"repositoryPath", "gitBlob", "sha256", "cachePath", "url"}, set(), REGISTRY)
            require(license_ref["repositoryPath"] == "LICENSE", "EXTERNAL_LICENSE_BINDING", source_path)
            self.cached_external(license_ref, repository, revision)
            self.count["externalLicenseFiles"] += 1

    def cached_external(self, item, repository, revision):
        path = relative(item["cachePath"]).as_posix()
        require(path.startswith(COVERAGE+"external-sources/") and path != REGISTRY,
                "EXTERNAL_CACHE_PATH", path)
        direct = f"https://github.com/{repository}/blob/{revision}/{item['repositoryPath']}"
        require(direct == item["url"], "EXTERNAL_URL_MISMATCH", path)
        data = self.files.read(path)
        digest(data, item["sha256"], "EXTERNAL_CACHE_HASH_MISMATCH", path)
        blob_id = hashlib.sha1(f"blob {len(data)}\0".encode()+data).hexdigest()
        require(blob_id == check_hex(item["gitBlob"], 40, path), "EXTERNAL_GIT_BLOB_MISMATCH", path)
        return data

    def scenario(self, ref, case, context=False):
        shape(ref, {"path", "requirementId", "scenario"}, {"relation", "relationship"}, case["id"])
        path = relative(ref["path"]).as_posix()
        proposed = path.startswith(PROPOSED)
        if context:
            require("relation" not in ref and ref.get("relationship") in
                    {"trigger-context", "workflow-wide context"}, "SCENARIO_RELATION", case["id"])
        else:
            require("relationship" not in ref and ref.get("relation") in
                    {None, "direct", "related_only", "proposed_only"}, "SCENARIO_RELATION", case["id"])
        relation = ref.get("relation")
        if proposed:
            legacy_baremetal = case["owner"] == "baremetal" and relation is None
            require(not context and case["classification"] == "proposed"
                    and (relation == "proposed_only" or legacy_baremetal), "PROPOSED_SCENARIO_SCOPE", path)
            index = self.spec(path)
            key = "proposedOnlyScenarioRefs"
        else:
            require(path in self.specs and relation != "proposed_only",
                    "SCENARIO_PATH_SCOPE", path)
            index = self.specs[path]
            if context:
                key = "contextScenarioRefs"
            else:
                key = "relatedScenarioRefs" if relation == "related_only" else "directScenarioRefs"
        requirement = string(ref["requirementId"], path)
        name = string(ref["scenario"], path)
        require(requirement in index, "SCENARIO_REQUIREMENT_NOT_FOUND", f"{path}: {requirement}")
        require(name in index[requirement][1], "SCENARIO_NOT_UNDER_REQUIREMENT",
                f"{case['id']}: {path} / {requirement} / {name}")
        self.count[key] += 1

    def anchors(self, data, ref, where):
        lines = data.decode().splitlines()
        anchors = sequence(ref["anchors"], where)
        require(anchors, "EMPTY_ANCHORS", where)
        for anchor in anchors:
            shape(anchor, {"line", "text"}, {"lineSha256"}, where)
            actual = source_line(lines, anchor["line"], where)
            label = f"{where}:{anchor['line']}"
            if "lineSha256" in anchor:
                require(anchor["text"] == actual, "ANCHOR_TEXT_MISMATCH", label)
                digest(actual.encode(), anchor["lineSha256"], "ANCHOR_LINE_HASH_MISMATCH", label)
                self.count["rawHashedAnchors"] += 1
            else:
                require(anchor["text"] == actual.strip(), "ANCHOR_TEXT_MISMATCH", label)
                self.count["strippedAnchors"] += 1

    def group(self, ref, case, candidate=False):
        shape(ref, {"path", "role", "anchors"}, {"sha256", "fileSha256", "symbol", "scope", "meaning"}, case)
        path = relative(ref["path"]).as_posix()
        expected = file_hash(ref, path, required=True)
        if ref["role"] == "scratch_test_candidate":
            require(candidate and path in self.current_candidates, "UNDECLARED_CANDIDATE_REFERENCE", path)
            data, registered, case_ids = self.current_candidates[path]
            require(case in case_ids, "CANDIDATE_CASE_SCOPE", case)
            require(expected == registered, "CANDIDATE_GROUP_HASH_MISMATCH", path)
            self.count["candidateGroups"] += 1
        else:
            require(not candidate or ref["role"] == "existing_assertion", "CANDIDATE_ROLE_SHAPE", path)
            data = self.product.read(path)
            digest(data, expected, "SOURCE_HASH_MISMATCH", path)
            self.count["productGroups"] += 1
        self.anchors(data, ref, path)

    def external_group(self, ref):
        shape(ref, {"repository", "revision", "repositoryPath", "url", "role", "scope", "anchors"},
              {"fileSha256", "sha256"}, "typed external reference")
        path = relative(ref["repositoryPath"]).as_posix()
        ident = (ref["repository"], ref["revision"], path)
        require(ident in self.externals, "EXTERNAL_REFERENCE_UNBOUND", str(ident))
        data, expected, url = self.externals[ident]
        require(file_hash(ref, path, required=True) == expected and ref["url"] == url,
                "EXTERNAL_REFERENCE_BINDING_MISMATCH", str(ident))
        self.anchors(data, ref, path)
        self.count["externalGroups"] += 1

    @cache
    def shared_assertion_group(self, key):
        path = COVERAGE + "runtime-api-gap-batch1-proposal.json"
        self.require_ledger_link(path)
        doc = self.files.json(path)
        self.pinned(doc, path)
        groups = doc["relatedAssertionGroups"]
        require(key in groups, "UNKNOWN_RELATED_GROUP", key)
        refs = sequence(groups[key]["groups"], key)
        require(refs, "EMPTY_RELATED_GROUP", key)
        for ref in refs:
            self.group(ref, key)
        self.count["distinctReferencedRelatedGroups"] += 1

    def case_context(self, case):
        ident = case["id"]
        for note in sequence(case.get("acceptedQualifiedContracts", []), ident):
            shape(note, {"capability", "requirementId", "scenario", "when", "then"}, set(), ident)
            path = DELTA + relative(note["capability"]).as_posix() + "/spec.md"
            require(any((r["path"], r["requirementId"], r["scenario"])
                        == (path, note["requirementId"], note["scenario"]) for r in case["scenarioRefs"]),
                    "QUALIFIED_CONTRACT_LINK_MISMATCH", ident)
            self.count["qualifiedContractLinks"] += 1
        if "workflowDeclarationContract" in case:
            path = case["workflowDeclarationContract"]["precondition"]["file"]
            self.product.require_blob(path)
            require(any(ref["path"] == path for ref in case.get("supportingContractTraceGroups", [])),
                    "UNBOUND_WORKFLOW_CONTRACT_SOURCE", ident)
            self.count["workflowContractSourceLinks"] += 1
        for key in sequence(case.get("relatedAssertionGroupIds", []), ident):
            self.shared_assertion_group(string(key, ident))
            self.count["relatedGroupLinks"] += 1

    def check_case_refs(self):
        for ident, case in self.cases.items():
            origin = case["origin"]
            shape(origin, {"path", "caseId"}, set(), ident)
            owner = case["owner"]
            require(owner in {"runtime", "baremetal"}, "UNKNOWN_CASE_OWNER", ident)
            require(origin["path"] == COVERAGE + f"{owner}-interface-ledger.json"
                    and origin["caseId"] == ident and ident in self.raw_ids(origin["path"]),
                    "CASE_ORIGIN_MISMATCH", ident)
            self.count["caseOrigins"] += 1
            for field in ("enforcingSource", "assertions"):
                for ref in sequence(case[field], ident):
                    self.locator(ref, ident, "canonicalLocators")
            for field in PRODUCT_GROUPS:
                for ref in sequence(case.get(field, []), ident):
                    self.group(ref, ident)
            for ref in sequence(case.get("relatedComponentAssertionGroups", []), ident):
                if "reference" in ref:
                    shape(ref, {"id", "reference"}, set(), ident)
                    ref = ref["reference"]
                self.group(ref, ident)
            for ref in sequence(case.get("externalContractSourceGroups", []), ident):
                self.external_group(ref)
            if "candidateAssertionGroups" in case:
                group = case["candidateAssertionGroups"]
                shape(group, {"sourceStatus", "baseRevision", "groups"}, set(), ident)
                require(group["baseRevision"] == self.product.revision, "CANDIDATE_SOURCE_PIN_MISMATCH", ident)
                for ref in sequence(group["groups"], ident):
                    self.group(ref, ident, candidate=True)
            for ref in sequence(case["scenarioRefs"], ident):
                self.scenario(ref, case)
            for ref in sequence(case.get("workflowContextScenarioRefs", []), ident):
                self.scenario(ref, case, context=True)
            self.case_context(case)
            self.count["previousScenarioRefsExcluded"] += len(sequence(case.get("previousScenarioRefs", []), ident))
            self.count["legacyAssertionRefsExcluded"] += len(sequence(case.get("legacyAssertionRefs", []), ident))
            if "verificationProof" in case:
                proof = case["verificationProof"]
                require(proof["caseId"] == ident, "HISTORICAL_POINTER_CASE_MISMATCH", ident)
                for role in ("acceptance", "resolution"):
                    self.require_ledger_link(proof[f"{role}Path"], proof[f"{role}Sha256"])
                    self.count["historicalMetadataPointers"] += 1

    def check(self):
        self.check_specs()
        canonical = self.load_cases()
        self.check_authoring()
        self.check_candidates(canonical["localTestCandidates"])
        self.check_external_registry()
        self.check_case_refs()
        return {**boundary(), "referenceIntegrity": True, "counts": dict(sorted(self.count.items())),
                "productSourceRevision": self.product.revision, "productSourceTree": self.product.tree,
                "snapshotInputsSha256": dict(sorted(self.files.hashes.items()))}


def boundary():
    return {"verificationAuthority": "not-assessed", "coverageComplete": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--snapshot", required=True, help="Frozen local documentation directory")
    parser.add_argument("--source-repo", required=True, help="Explicit local Git repository with the product commit")
    parser.add_argument("--source-revision", required=True, help="Full product commit ID")
    args = parser.parse_args(argv)
    try:
        product = GitSource(args.source_repo, args.source_revision)
        result = ReferenceChecker(Files(args.snapshot), product).check()
    except IntegrityError as exc:
        result = {**boundary(), "referenceIntegrity": False, "error": {"code": exc.code, "where": exc.where}}
    except (OSError, UnicodeError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as exc:
        result = {**boundary(), "referenceIntegrity": False, "error": {"code": "INPUT_SHAPE_OR_READ_ERROR", "where": str(exc)}}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["referenceIntegrity"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
