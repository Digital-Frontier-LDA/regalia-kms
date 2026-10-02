"""Inventory a final root filesystem and block release on scanner failures."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

from .tools import verified_executable
from .verify import VerificationError, hash_regular, read_regular, require


SEVERITIES = {"Unknown": 0, "Negligible": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def compact_spdx(document: dict) -> dict:
    """Retain every package while leaving file inventory in the full SBOM."""
    require(document.get("spdxVersion") == "SPDX-2.3" and isinstance(document.get("packages"), list),
            "invalid SPDX document")
    result = json.loads(json.dumps(document))
    identifiers = {package["SPDXID"] for package in result["packages"]}
    require(len(identifiers) == len(result["packages"]), "duplicate SPDX package identifiers")
    identifiers.update({result["SPDXID"], "NONE", "NOASSERTION"})
    for package in result["packages"]:
        package["filesAnalyzed"] = False
        package["licenseConcluded"] = "NOASSERTION"
        for key in ("licenseInfoFromFiles", "packageVerificationCode", "hasFiles"):
            package.pop(key, None)
    result.pop("files", None)
    result["relationships"] = [relation for relation in result.get("relationships", [])
        if relation["spdxElementId"] in identifiers and relation["relatedSpdxElement"] in identifiers]
    return result


def project_rootfs(archive_path: Path, destination: Path, *, limit: int = 4 * 1024 ** 3) -> dict:
    """Project regular files for cataloging, without materializing archive links."""
    size = count = 0
    skipped = Counter()
    with tarfile.open(archive_path) as archive:
        for member in archive:
            count += 1
            require(count <= 150_000, "root filesystem has too many members")
            parts = PurePosixPath(member.name).parts
            require(not member.name.startswith("/") and ".." not in parts, "unsafe root filesystem archive path")
            path = destination.joinpath(*parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                skipped["links" if member.issym() or member.islnk() else "special_files"] += 1
                continue
            size += member.size
            require(0 <= member.size and size <= limit, "root filesystem projection exceeds size limit")
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, path.open("xb") as target:
                shutil.copyfileobj(source, target)
            path.chmod(0o600)
    return {"members": count, "regular_bytes": size, "skipped": dict(skipped)}


def verdict(result: dict, returncode: int, threshold: str) -> tuple[str, dict]:
    require(threshold in {"Medium", "High", "Critical"}, "invalid vulnerability threshold")
    require(isinstance(result.get("matches"), list) and isinstance(result.get("descriptor"), dict),
            "scanner did not return a complete result")
    db = result["descriptor"].get("db", {})
    status = db.get("status", {}) if isinstance(db, dict) else {}
    require(isinstance(status, dict) and status.get("valid") is True, "scanner database is not valid")
    try:
        built = datetime.fromisoformat(status["built"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - built).total_seconds()
    except (KeyError, ValueError, TypeError) as error:
        raise VerificationError("missing database freshness evidence") from error
    require(-300 <= age <= 120 * 3600, "scanner database is stale or from the future")
    counts = Counter()
    for match in result["matches"]:
        require(isinstance(match, dict) and isinstance(match.get("vulnerability"), dict), "invalid scanner finding")
        severity = match["vulnerability"].get("severity")
        require(severity in SEVERITIES, "unknown vulnerability severity")
        counts[severity] += 1
    require(returncode in {0, 2}, "vulnerability scanner failed")
    blocked = any(SEVERITIES[severity] >= SEVERITIES[threshold] for severity in counts)
    require(returncode != 2 or blocked, "scanner rejected scan without qualifying findings")
    return ("blocked" if blocked else "passed"), dict(counts)


def scan(rootfs: Path, tools: Path, output: Path, threshold: str = "High") -> dict:
    require(not output.exists() and not output.is_symlink(), "scan output already exists")
    syft, grype = (verified_executable(tools, name) for name in ("syft", "grype"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    digest, byte_count = hash_regular(rootfs, "sha256")
    report = {"schema": "regalia.image-scan/v1", "status": "failed", "rootfs_sha256": digest,
              "rootfs_bytes": byte_count, "fail_on": threshold, "production_approved": False,
              "tools": json.loads(read_regular(tools / "verification.json"))}
    try:
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("GRYPE_", "SYFT_"))}
        environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
        config = output / "scanner-config.json"
        config.write_text('{"ignore": [], "exclude": [], "only-fixed": false}\n')
        with tempfile.TemporaryDirectory(prefix="regalia-rootfs-projection-") as temporary:
            probe = Path(temporary) / ".case-probe"
            probe.mkdir()
            try:
                (probe / "lower").write_text("")
                with (probe / "LOWER").open("x"):
                    pass
            except FileExistsError as error:
                raise VerificationError("Linux scanning needs a case-sensitive filesystem; use lab.appliance.scan_docker") from error
            finally:
                shutil.rmtree(probe)
            report["projection"] = project_rootfs(rootfs, Path(temporary))
            # No code from the image is executed; package databases and regular
            # ELF/Go binaries are cataloged from a link-free private projection.
            subprocess.run([str(syft), "--config", str(config), "dir:" + temporary,
                            "-o", "syft-json=" + str(output / "sbom.syft.json"),
                            "-o", "spdx-json=" + str(output / "sbom.spdx.json"),
                            "-o", "cyclonedx-json=" + str(output / "sbom.cdx.json")],
                           check=True, timeout=900, stdout=subprocess.DEVNULL, env=environment)
        sbom = json.loads(read_regular(output / "sbom.syft.json", 128 * 1024 ** 2))
        require(isinstance(sbom.get("artifacts"), list) and bool(sbom["artifacts"]), "empty filesystem SBOM")
        require(sbom.get("distro", {}).get("id") == "debian" and str(sbom["distro"].get("version", "")).startswith("13"),
                "SBOM did not identify Debian 13")
        report["packages"] = len(sbom["artifacts"])
        full_spdx = json.loads(read_regular(output / "sbom.spdx.json", 128 * 1024 ** 2))
        package_spdx = json.dumps(compact_spdx(full_spdx), sort_keys=True, separators=(",", ":")).encode()
        require(len(package_spdx) <= 16 * 1024 ** 2, "package SBOM exceeds GitHub attestation size limit")
        (output / "sbom.attestation.spdx.json").write_bytes(package_spdx + b"\n")
        environment.update(GRYPE_DB_VALIDATE_AGE="true", GRYPE_DB_MAX_ALLOWED_BUILT_AGE="120h",
                           GRYPE_CHECK_FOR_APP_UPDATE="false")
        if os.environ.get("REGALIA_SCANNER_CACHE"):
            environment["GRYPE_DB_CACHE_DIR"] = os.environ["REGALIA_SCANNER_CACHE"]
        with (output / "vulnerabilities.json").open("w") as results:
            completed = subprocess.run([str(grype), "--config", str(config), "sbom:" + str(output / "sbom.syft.json"),
                                        "--fail-on", threshold.lower(), "--output", "json"],
                                       env=environment, timeout=900, stdout=results)
        result = json.loads(read_regular(output / "vulnerabilities.json", 128 * 1024 ** 2))
        status, report["findings"] = verdict(result, completed.returncode, threshold)
        report["database"] = result["descriptor"]["db"]
        after, _ = hash_regular(rootfs, "sha256")
        require(after == digest, "root filesystem changed during scan")
        report["evidence"] = {path.name: hash_regular(path, "sha256")[0] for path in output.iterdir()}
        report["status"] = status
        return report
    finally:
        (output / "scan-report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fail-on", choices=("Medium", "High", "Critical"), default="High")
    args = parser.parse_args()
    try:
        report = scan(args.rootfs.absolute(), args.tools.absolute(), args.output.absolute(), args.fail_on)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if report["status"] == "passed" else 1
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"REFUSED: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
