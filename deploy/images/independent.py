"""Compare builds from separate Linux runner instances under the same inputs."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile

from .release import compare
from .verify import VerificationError, hash_regular, read_regular, require


ROOT = Path(__file__).resolve().parents[2]


def capture(command, *, cwd=ROOT, env=None):
    return subprocess.check_output(command, cwd=cwd, env=env, text=True, timeout=600).strip()


def build(commit: str, output: Path) -> dict:
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "full source commit required")
    require(platform.system() == "Linux", "independent runner qualification requires Linux")
    require(not output.exists() and not output.is_symlink(), "output already exists")
    output.mkdir(parents=True, mode=0o700)
    report = {"schema": "regalia.independent-binary/v1", "status": "failed", "production_approved": False}
    try:
        environment = {key: value for key, value in os.environ.items() if not key.startswith("GO")}
        environment.update(GOENV="off", GOWORK="off", CGO_ENABLED="1", GOSUMDB="sum.golang.org",
                           GOPROXY="https://proxy.golang.org", GOTOOLCHAIN="auto", GOAMD64="v1", CC="gcc")
        flags = "-buildid= -X main.version=appliance-lab-" + commit
        with tempfile.TemporaryDirectory(prefix="regalia-runner-build-") as temporary:
            folder = Path(temporary)
            archive, source = folder / "source.tar", folder / "source"
            subprocess.run(["git", "archive", "--format=tar", "--output", str(archive), commit], cwd=ROOT, check=True)
            source.mkdir()
            with tarfile.open(archive) as handle:
                handle.extractall(source, filter="data")
            environment.update(GOCACHE=str(folder / "cache"), GOMODCACHE=str(folder / "modules"),
                               GOPATH=str(folder / "gopath"))
            subprocess.run(["go", "mod", "download"], cwd=source, env=environment, check=True, timeout=600)
            subprocess.run(["go", "mod", "verify"], cwd=source, env=environment, check=True, timeout=600)
            payload = output / "payload"
            payload.mkdir()
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", flags,
                            "-o", str(payload / "regalia-kms"), "./cmd/regalia-kms"],
                           cwd=source, env=environment, check=True, timeout=900)
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            require(re.fullmatch(r"[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot) is not None,
                    "missing Linux runner boot identity")
            report.update(status="passed", source_commit=commit, source_archive_sha256=hash_regular(archive, "sha256")[0],
                          host_boot_id=boot, platform={"system": "Linux", "architecture": platform.machine()},
                          flags=flags, toolchain={"go": capture(["go", "version"], cwd=source, env=environment),
                          "gcc": capture(["gcc", "--version"]).splitlines()[0],
                          "ld": capture(["ld", "--version"]).splitlines()[0]},
                          binary_sha256=hash_regular(payload / "regalia-kms", "sha256")[0])
        return report
    finally:
        (output / "build.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


def verify(first: Path, second: Path, commit: str) -> dict:
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "full expected commit required")
    left, right = [json.loads(read_regular(path / "build.json")) for path in (first, second)]
    for report, path in ((left, first), (right, second)):
        require(report.get("schema") == "regalia.independent-binary/v1" and report.get("status") == "passed"
                and report.get("source_commit") == commit, "independent build did not pass for expected source")
        require(report.get("binary_sha256") == hash_regular(path / "payload/regalia-kms", "sha256")[0],
                "independent binary differs from report")
        require(isinstance(report.get("host_boot_id"), str) and
                re.fullmatch(r"[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}", report["host_boot_id"]) is not None,
                "runner boot identity is invalid")
    require(left["host_boot_id"] != right["host_boot_id"], "builds did not use distinct Linux boot instances")
    for name in ("source_archive_sha256", "platform", "flags", "toolchain"):
        require(name in left and name in right and left[name] == right[name], "independent build inputs differ")
    comparison = compare(first / "payload", second / "payload")
    require(set(comparison["artifacts"]) == {"regalia-kms"}, "unexpected independent build artifact")
    return {"schema": "regalia.independent-comparison/v1", "status": "identical", "source_commit": commit,
            "comparison": comparison, "runner_boot_ids": [left["host_boot_id"], right["host_boot_id"]],
            "scope": "Separate Linux runner instances; same CI provider and toolchain, not independent trust authorities",
            "production_approved": False, "disk_reproducibility": "not-established"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    builder = modes.add_parser("build")
    builder.add_argument("--output", type=Path, required=True)
    verifier = modes.add_parser("verify")
    verifier.add_argument("first", type=Path)
    verifier.add_argument("second", type=Path)
    verifier.add_argument("--output", type=Path, required=True)
    for mode in (builder, verifier):
        mode.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.mode == "build":
            result = build(args.commit, args.output.resolve())
        else:
            result = verify(args.first, args.second, args.commit)
            with args.output.open("x") as handle:
                json.dump(result, handle, indent=2)
                handle.write("\n")
        print(json.dumps(result, indent=2))
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
