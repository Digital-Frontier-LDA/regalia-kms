"""Check the required non-authorizing envelope emitted by the CI reference command."""
import json
from pathlib import Path
import sys


path, revision, tree, *tooling = sys.argv[1:]
if len(tooling) not in (0, 2):
    raise SystemExit("Expected no tooling pin or an exact tooling revision and tree")
result = json.loads(Path(path).read_bytes())
if not (
    result.get("referenceIntegrity") is True
    and result.get("verificationAuthority") == "not-assessed"
    and result.get("coverageComplete") is False
    and result.get("productSourceRevision") == revision
    and result.get("productSourceTree") == tree
):
    raise SystemExit("OpenSpec reference result did not match the required integrity envelope and product pin")

tooling_fields = ("toolingSourceRevision", "toolingSourceTree")
observed = [result[key] for key in tooling_fields if key in result]
if observed != tooling:
    raise SystemExit("OpenSpec reference result did not match the required tooling pin")
