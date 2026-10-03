"""Collect a completed appliance and its final filesystem scan for signing."""

import argparse
import json
from pathlib import Path
import shutil
import tempfile

from deploy.images.release import prepare
from deploy.images.verify import read_regular, require


def collect(build: Path, scan: Path, destination: Path, commit: str, ref: str):
    require(not destination.exists() and not destination.is_symlink(), "release output already exists")
    scanner = json.loads(read_regular(scan / "scan-report.json"))
    require(scanner.get("status") == "passed", "scan is blocked or failed; no release may be collected")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".regalia-release-", dir=destination.parent))
    try:
        payload = staging / "payload"
        payload.mkdir()
        for source in [build / "regalia-debian13-amd64.qcow2", build / "build-report.json",
                       build / "export/rootfs.tar.gz", build / "export/regalia-kms",
                       build / "acceptance.log", build / "normal-boot.log", *scan.iterdir()]:
            require(source.is_file() and not source.is_symlink(), "release input must be a regular file")
            require(not (payload / source.name).exists(), "duplicate release artifact basename")
            shutil.copyfile(source, payload / source.name)
        manifest = prepare(payload, commit, ref)
        (staging / "release.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build", "scan", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--ref", required=True)
    args = parser.parse_args()
    collect(args.build, args.scan, args.output, args.commit, args.ref)
