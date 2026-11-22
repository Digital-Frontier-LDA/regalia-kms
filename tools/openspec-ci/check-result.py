"""Check the required non-authorizing envelope emitted by the CI reference command."""
import json
from pathlib import Path
import sys


path, revision, tree = sys.argv[1:]
result = json.loads(Path(path).read_bytes())
if not (
    result.get("referenceIntegrity") is True
    and result.get("verificationAuthority") == "not-assessed"
    and result.get("coverageComplete") is False
    and result.get("productSourceRevision") == revision
    and result.get("productSourceTree") == tree
):
    raise SystemExit("OpenSpec reference result did not match the required integrity envelope and product pin")
