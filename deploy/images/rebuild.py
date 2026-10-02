"""Rebuild a Go executable twice from independent source and compiler caches."""

import argparse
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

from .release import compare
from .verify import VerificationError, require


ROOT = Path(__file__).resolve().parents[2]


def rebuild(commit: str, output: Path) -> dict:
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "full source commit required")
    require(not output.exists() and not output.is_symlink(), "rebuild output already exists")
    output.mkdir(parents=True, mode=0o700)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GO")}
    environment.update(GOENV="off", GOWORK="off", CGO_ENABLED="1", GOSUMDB="sum.golang.org",
                       GOPROXY="https://proxy.golang.org", GOTOOLCHAIN="auto")
    flags = "-buildid= -X main.version=appliance-lab-" + commit
    # Apple's external linker emits a per-link UUID; it changes the signed Mach-O
    # bytes despite identical code. Explicitly omit that optional debugger UUID.
    if platform.system() == "Darwin":
        flags += " -extldflags=-Wl,-no_uuid"
    report = {"schema": "regalia.binary-repeatability/v1", "status": "failed", "source_commit": commit,
              "scope": "Same toolchain and host; independent source paths and compiler caches"}
    try:
        with tempfile.TemporaryDirectory(prefix="regalia-independent-builds-") as temporary:
            root = Path(temporary)
            archive = root / "source.tar"
            subprocess.run(["git", "archive", "--format=tar", "--output", str(archive), commit], cwd=ROOT, check=True)
            for name in ("first", "second"):
                source = root / name
                source.mkdir()
                with tarfile.open(archive) as sources:
                    sources.extractall(source, filter="data")
                target = output / name
                target.mkdir()
                environment["GOCACHE"] = str(root / (name + "-cache"))
                subprocess.run(["go", "mod", "verify"], cwd=source, env=environment, check=True)
                subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags",
                                flags,
                                "-o", str(target / "regalia-kms"), "./cmd/regalia-kms"],
                               cwd=source, env=environment, timeout=900, check=True)
            report["comparison"] = compare(output / "first", output / "second")
            report["go_version"] = subprocess.run(["go", "version"], cwd=ROOT, env=environment,
                                                  check=True, capture_output=True, text=True).stdout.strip()
            report["status"] = "identical"
        return report
    finally:
        (output / "rebuild-report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(rebuild(args.commit, args.output.absolute()), sort_keys=True, indent=2))
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")
