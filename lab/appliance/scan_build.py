"""Scan the exact filesystem exported by a passing appliance build."""

import argparse
import json
import hashlib
from pathlib import Path
import re
import subprocess

from deploy.images.scan import scan
from deploy.images.verify import VerificationError, hash_regular, read_regular, require


def scan_build(build: Path, scanners: Path, output: Path, commit: str) -> dict:
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "full expected source commit required")
    report_data = read_regular(build / "build-report.json")
    report_hash = hashlib.sha256(report_data).hexdigest()
    report = json.loads(report_data)
    require(report.get("schema") == "regalia.appliance-build/v1" and report.get("status") == "passed"
            and report.get("source_commit") == commit, "build did not pass for the expected source")
    exports = report.get("export")
    require(isinstance(exports, dict), "build exports are missing")
    # Refuse substituted filesystem/binary bytes before invoking any scanner.
    for name in ("rootfs.tar.gz", "regalia-kms"):
        digest, _ = hash_regular(build / "export" / name, "sha256")
        require(exports.get(name) == digest, "export differs from passing build")
    result = scan(build / "export/rootfs.tar.gz", scanners, output)
    require(result["rootfs_sha256"] == exports["rootfs.tar.gz"], "scan does not bind the build export")
    require(hash_regular(build / "build-report.json", "sha256")[0] == report_hash, "build report changed during scan")
    binding = {"schema": "regalia.build-scan-binding/v1", "source_commit": commit,
               "build_report_sha256": report_hash,
               "rootfs_sha256": exports["rootfs.tar.gz"], "binary_sha256": exports["regalia-kms"],
               "scan_report_sha256": hash_regular(output / "scan-report.json", "sha256")[0],
               "status": result["status"], "release_admissible": result["status"] == "passed",
               "production_approved": False}
    (output / "build-binding.json").write_text(json.dumps(binding, sort_keys=True, indent=2) + "\n")
    return binding


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build", "tools", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        result = scan_build(args.build, args.tools, args.output, args.commit)
        print(json.dumps(result, indent=2))
        return 0 if result["release_admissible"] else 1
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
