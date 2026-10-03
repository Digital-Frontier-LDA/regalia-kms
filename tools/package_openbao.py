#!/usr/bin/env python3
"""Package checksum-bound development plugins from a clean commit; never publish."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "adapters/openbao"
BINARY = "openbao-plugin-kms-regalia"
TARGETS = ("linux_amd64", "linux_arm64")


def run(*args, cwd=ROOT, env=None):
    return subprocess.check_output(args, cwd=cwd, env=env, text=True).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def document(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def verify(output):
    checks = (output / "checksums.txt").read_text().splitlines()
    for line in checks:
        expected, name = line.split("  ", 1)
        if Path(name).name != name or digest((output / name).read_bytes()) != expected:
            raise SystemExit("Package checksum verification failed")
    manifest = json.loads((output / "manifest.json").read_bytes())
    if manifest["qualification"] != "development-only":
        raise SystemExit("This packager does not create production releases")
    if len(manifest["artifacts"]) != len(TARGETS):
        raise SystemExit("Unexpected target count")
    for artifact in manifest["artifacts"]:
        if Path(artifact["archive"]).name != artifact["archive"] or artifact["target"] not in TARGETS:
            raise SystemExit("Unexpected archive name or target")
        with tarfile.open(output / artifact["archive"], "r:gz") as archive:
            members = archive.getmembers()
            if [m.name for m in members] != [BINARY, "compatibility.json", "LICENSE"] or any(not m.isfile() for m in members):
                raise SystemExit("Unexpected package contents")
            binary = archive.extractfile(members[0]).read()
            metadata = json.load(archive.extractfile(members[1]))
            if digest(binary) != artifact["binary_sha256"] or metadata != artifact:
                raise SystemExit("Binary identity verification failed")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if args.verify:
        result = verify(output)
        print(f"Verified {len(result['artifacts'])} development packages")
        return
    if run("git", "status", "--porcelain", "--untracked-files=normal"):
        raise SystemExit("Packaging requires a clean committed checkout")
    commit = run("git", "rev-parse", "HEAD")
    epoch = int(run("git", "show", "-s", "--format=%ct", "HEAD"))
    go_version = run("go", "env", "GOVERSION", cwd=MODULE)
    if go_version != "go1.26.6":
        raise SystemExit("Reproducible packages require Go 1.26.6")
    version = "v0.1.0-dev." + commit[:12]
    output.mkdir(parents=True, exist_ok=False)
    artifacts = []
    for target in TARGETS:
        goos, goarch = target.split("_")
        binary_path = output / (BINARY + "-" + target)
        env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0", GOWORK="off", GOFLAGS="-mod=readonly", GOAMD64="v1", GOARM64="v8.0")
        symbol = "github.com/Digital-Frontier-LDA/regalia-kms/adapters/openbao"
        run("go", "build", "-trimpath", "-buildvcs=false", "-ldflags",
            f"-s -w -X {symbol}.BuildVersion={version} -X {symbol}.BuildCommit={commit}",
            "-o", str(binary_path), "./cmd/" + BINARY, cwd=MODULE, env=env)
        binary = binary_path.read_bytes()
        binary_path.unlink()
        archive_name = f"{BINARY}_{version}_{target}.tar.gz"
        artifact = {"archive": archive_name, "binary_sha256": digest(binary), "target": target,
                    "version": version, "source_commit": commit, "go_version": go_version,
                    "openbao_test_target": "2.7.1", "wrapping_sdk": "2.9.0", "plugin_sdk": "2.4.0",
                    "qualification": "development-only", "pki_supported": False}
        with (output / archive_name).open("wb") as file:
            with gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name, value, mode in ((BINARY, binary, 0o755), ("compatibility.json", document(artifact), 0o644), ("LICENSE", (ROOT / "LICENSE").read_bytes(), 0o644)):
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.mode, entry.mtime = len(value), mode, epoch
                        archive.addfile(entry, io.BytesIO(value))
        artifacts.append(artifact)
    (output / "manifest.json").write_bytes(document({"schema_version": 1, "qualification": "development-only", "artifacts": artifacts}))
    names = sorted([a["archive"] for a in artifacts] + ["manifest.json"])
    (output / "checksums.txt").write_text("".join(f"{digest((output / name).read_bytes())}  {name}\n" for name in names))
    verify(output)
    print(f"Built and verified {len(artifacts)} packages at {version}")


if __name__ == "__main__":
    main()
