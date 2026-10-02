"""Install pinned scanners only after publisher signature and checksum checks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

from .fetch_debian import download
from .verify import VerificationError, hash_regular, read_regular, require, run


POLICY = Path(__file__).with_name("tools-policy.json")


def checksum(data: bytes, name: str) -> str:
    entries = {}
    for line in data.decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._+-]*)", line)
        require(match is not None, "unsafe tool checksum entry")
        digest, entry = match.groups()
        require(entry not in entries, "duplicate tool checksum entry")
        entries[entry] = digest
    require(name in entries, "tool archive absent from signed checksums")
    return entries[name]


def install(destination: Path, policy_path: Path = POLICY, target: str | None = None) -> dict:
    policy = json.loads(read_regular(policy_path))
    require(policy.get("schema") == "regalia.scanner-tools/v1", "invalid scanner policy")
    if target is None:
        architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64"}.get(platform.machine())
        target = f"{platform.system().lower()}_{architecture}"
    require(target in {"darwin_arm64", "linux_amd64", "linux_arm64"}, "unsupported scanner platform")
    require(not destination.exists() and not destination.is_symlink(), "scanner destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".verified-scanners-", dir=destination.parent))
    report = {"schema": "regalia.scanner-install/v1", "status": "verified", "platform": target,
              "policy_sha256": hashlib.sha256(read_regular(policy_path)).hexdigest(), "tools": {}}
    try:
        for name in ("syft", "grype"):
            entry = policy["tools"][name]
            version = entry["version"]
            require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is not None, "unversioned scanner")
            identity = f"https://github.com/anchore/{name}/.github/workflows/release.yaml@refs/heads/main"
            require(entry["identity"] == identity and policy["issuer"] == "https://token.actions.githubusercontent.com",
                    "unexpected scanner publisher identity")
            prefix = f"{name}_{version}"
            archive_name = f"{prefix}_{target}.tar.gz"
            base = f"https://github.com/anchore/{name}/releases/download/v{version}/"
            metadata = staging / name
            metadata.mkdir()
            checksums = metadata / f"{prefix}_checksums.txt"
            download(base + checksums.name, checksums, 4 * 1024 ** 2)
            verify = ["cosign", "verify-blob", str(checksums), "--certificate-identity", identity,
                      "--certificate-oidc-issuer", policy["issuer"]]
            if entry["proof"] == "bundle":
                bundle = metadata / (checksums.name + ".sigstore.json")
                download(base + bundle.name, bundle, 4 * 1024 ** 2)
                verify += ["--bundle", str(bundle)]
            else:
                require(entry["proof"] == "certificate", "unsupported publisher proof")
                for suffix, flag in ((".pem", "--certificate"), (".sig", "--signature")):
                    proof = metadata / (checksums.name + suffix)
                    download(base + proof.name, proof, 4 * 1024 ** 2)
                    verify += [flag, str(proof)]
            # Default certificate and transparency verification remains enabled.
            run(verify, timeout=180)
            expected = checksum(read_regular(checksums), archive_name)
            require(expected == entry["archives"][target], "signed archive differs from reviewed digest pin")
            archive_path = metadata / archive_name
            download(base + archive_name, archive_path, 256 * 1024 ** 2)
            actual, _ = hash_regular(archive_path, "sha256")
            require(actual == expected, "scanner archive checksum mismatch")
            # Never extract an archive tree or execute a release installer script.
            # Read only the expected regular executable, rejecting duplicate names.
            with tarfile.open(archive_path) as archive:
                candidates = [member for member in archive.getmembers() if member.name == name]
                require(len(candidates) == 1 and candidates[0].isfile()
                        and 0 < candidates[0].size <= 256 * 1024 ** 2, "invalid scanner executable")
                with archive.extractfile(candidates[0]) as executable:
                    binary = executable.read()
            executable_path = staging / name / "bin"
            executable_path.write_bytes(binary)
            executable_path.chmod(0o700)
            report["tools"][name] = {"version": version, "identity": identity, "issuer": policy["issuer"],
                                     "archive_sha256": expected, "binary_sha256": hashlib.sha256(binary).hexdigest()}
            archive_path.unlink()
        (staging / "verification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        require(not destination.exists() and not destination.is_symlink(), "scanner destination appeared")
        os.rename(staging, destination)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def verified_executable(directory: Path, name: str) -> Path:
    require(name in {"syft", "grype"}, "unknown scanner")
    report = json.loads(read_regular(directory / "verification.json"))
    policy = json.loads(read_regular(POLICY))
    require(report.get("status") == "verified" and report.get("policy_sha256") == hashlib.sha256(read_regular(POLICY)).hexdigest(),
            "scanner installation policy has changed")
    require(report["tools"][name]["version"] == policy["tools"][name]["version"], "unexpected scanner version")
    # The local install directory and its executable hash record must remain under
    # operator custody, just like the verifier and policy themselves.
    path = directory / name / "bin"
    actual, _ = hash_regular(path, "sha256")
    require(actual == report["tools"][name]["binary_sha256"], "installed scanner executable changed")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(install(args.output.absolute()), sort_keys=True, indent=2))
    except (VerificationError, OSError, subprocess.SubprocessError, ValueError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
