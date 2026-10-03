"""Join scanner evidence to Debian's tracker for review, without granting waivers."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .fetch_debian import download
from .verify import VerificationError, read_regular, require


TRACKER = "https://security-tracker.debian.org/tracker/data/json"
LIMIT = 128 * 1024 * 1024


@lru_cache(maxsize=4096)
def at_least(installed: str, fixed: str) -> bool:
    # Delegate epochs, tilde ordering and Debian revisions to dpkg. These are
    # data arguments; no package contents, shell commands or maintainer scripts run.
    for version in (installed, fixed):
        require(isinstance(version, str) and len(version) <= 256
                and re.fullmatch(r"[0-9][A-Za-z0-9.+:~\-]*", version) is not None,
                "invalid Debian version")
    result = subprocess.run(["dpkg", "--compare-versions", installed, "ge", fixed],
                            capture_output=True, timeout=10)
    require(result.returncode in {0, 1} and not result.stderr, "Debian version comparison failed")
    return result.returncode == 0


def source_identity(package: dict, packages: list[dict]) -> tuple[str, str, str]:
    metadata = package.get("metadata", {})
    if package.get("type") == "deb":
        return (metadata.get("source") or package["name"],
                metadata.get("sourceVersion") or package["version"], "dpkg-source")
    if package.get("type") == "linux-kernel":
        paths = {location["path"] for location in package.get("locations", [])}
        owners = [candidate for candidate in packages
                  if candidate.get("type") == "deb"
                  and candidate.get("name") in {"linux-image-" + package["version"],
                                                "linux-binary-" + package["version"]}
                  and paths.intersection(file["path"] for file in candidate.get("metadata", {}).get("files", []))]
        if len(owners) == 1:
            owner = owners[0]
            source = owner.get("metadata", {}).get("source") or owner["name"]
            if source in {"linux", "linux-signed-amd64"}:
                # Signed image wrapper source versions differ from Linux source
                # versions. Debian's image *binary* version names the Linux build.
                # File ownership is a review candidate, not independent proof of
                # binary integrity or patch applicability.
                return "linux", owner["version"], "kernel-package-ownership-candidate"
    return "", "", "unmapped"


def summarize(sbom: dict, findings: dict, tracker: dict) -> dict:
    require(isinstance(tracker, dict) and isinstance(sbom.get("artifacts"), list)
            and isinstance(findings.get("matches"), list), "incomplete triage inputs")
    require(sbom.get("distro", {}).get("id") == "debian"
            and str(sbom.get("distro", {}).get("versionID", "")).split(".")[0] == "13",
            "triage requires Debian 13 inventory")
    packages = sbom["artifacts"]
    index = {package["id"]: package for package in packages}
    require(len(index) == len(packages), "duplicate inventory identifiers")
    groups = {}
    for match in findings["matches"]:
        vulnerability, artifact = match["vulnerability"], match["artifact"]
        require(artifact["id"] in index, "finding absent from bound inventory")
        package = index[artifact["id"]]
        require(all(artifact.get(field) == package.get(field) for field in ("name", "version", "type")),
                "finding and inventory package disagree")
        if vulnerability["severity"] not in {"Critical", "High"}:
            continue
        cve = vulnerability["id"]
        require(re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", cve) is not None, "unsupported advisory identifier")
        source, version, mapping = source_identity(package, packages)
        key = (source or package["name"], cve, version, mapping)
        if key not in groups:
            data = tracker.get(source, {}).get(cve, {}).get("releases", {}).get("trixie", {})
            require(isinstance(data, dict), "malformed Debian tracker record")
            status, fixed = data.get("status", "unknown"), data.get("fixed_version")
            classification = "unmapped" if not source else "tracker-unknown"
            if status == "resolved" and fixed == "0":
                classification = "vendor-not-affected-candidate"
            elif status == "resolved" and fixed and version:
                classification = ("vendor-fixed-candidate" if at_least(version, fixed)
                                  else "update-required")
            elif status == "open":
                classification = "vendor-open"
            groups[key] = {"source": source or None, "source_version": version or None,
                           "mapping": mapping, "cve": cve, "classification": classification,
                           "debian": data, "tracker_url": "https://security-tracker.debian.org/tracker/" + cve,
                           "matches": 0, "packages": set(), "namespaces": set(),
                           "severities": set(), "scanner_fix_states": set()}
        row = groups[key]
        row["matches"] += 1
        row["packages"].add(package["name"])
        row["namespaces"].add(vulnerability.get("namespace", ""))
        row["severities"].add(vulnerability["severity"])
        row["scanner_fix_states"].add(vulnerability.get("fix", {}).get("state", "unknown"))
    rows = []
    for key in sorted(groups):
        row = groups[key]
        for field in ("packages", "namespaces", "severities", "scanner_fix_states"):
            row[field] = sorted(row[field])
        rows.append(row)
    return {"schema": "regalia.image-triage/v1", "status": "review-required",
            "production_approved": False, "waivers": [],
            "blocking_matches": sum(row["matches"] for row in rows),
            "unique_cves": len({row["cve"] for row in rows}),
            "review_groups": len(rows),
            "classification_matches": {classification: sum(row["matches"] for row in rows
                if row["classification"] == classification) for classification in {row["classification"] for row in rows}},
            "findings": rows}


def markdown(report: dict) -> str:
    sources = defaultdict(lambda: {"matches": 0, "cves": set(), "classes": Counter()})
    for row in report["findings"]:
        source = sources[row["source"] or "unmapped"]
        source["matches"] += row["matches"]
        source["cves"].add(row["cve"])
        source["classes"][row["classification"]] += row["matches"]
    lines = ["# Debian image vulnerability review", "", "## Security Findings", "",
             f"{report['blocking_matches']} High/Critical matches; {report['unique_cves']} distinct CVEs.",
             "No waivers are granted. The original scan verdict remains authoritative.", "",
             "| Source | Matches | Distinct CVEs | Review classification (matches) |",
             "| --- | ---: | ---: | --- |"]
    for name, source in sorted(sources.items(), key=lambda item: (-item[1]["matches"], item[0])):
        # Names originate in external inventories; escape Markdown delimiters.
        name = name.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
        classes = ", ".join(f"{key}: {value}" for key, value in sorted(source["classes"].items()))
        lines.append(f"| {name} | {source['matches']} | {len(source['cves'])} | {classes} |")
    lines += ["", "## Checks Performed", "", "Inventory and findings match their scan-report hashes. "
              "Debian source versions are compared using dpkg, including epochs and backports.", "",
              "## Residual Risk", "", "The tracker snapshot relies on HTTPS, without a detached publisher signature. "
              "Kernel file ownership and vendor-fixed results are review candidates; they do not establish "
              "patch applicability, image integrity or exploitability. Tracker status may change.", "",
              "## Recommendation", "", "Review candidates against package changelogs and reachable code. "
              "Remove unnecessary packages or rebuild with authenticated updates. Preserve the release block "
              "until an explicit, separately reviewed policy authorizes any exception.", ""]
    return "\n".join(lines)


def triage(evidence: Path, output: Path, tracker_path: Path | None = None) -> dict:
    require(not output.exists() and not output.is_symlink(), "triage output already exists")
    scan_bytes = read_regular(evidence / "scan-report.json")
    scan = json.loads(scan_bytes)
    require(scan.get("schema") == "regalia.image-scan/v1" and scan.get("status") in {"blocked", "passed"},
            "triage requires a completed scan")
    inputs = {}
    for name in ("sbom.syft.json", "vulnerabilities.json"):
        data = read_regular(evidence / name, LIMIT)
        require(hashlib.sha256(data).hexdigest() == scan["evidence"][name], "triage evidence hash mismatch")
        inputs[name] = json.loads(data)
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".image-triage-", dir=output.parent))
    try:
        snapshot = staging / "debian-tracker.json"
        fetched = None
        if tracker_path:
            snapshot.write_bytes(read_regular(tracker_path, LIMIT))
        else:
            download(TRACKER, snapshot, LIMIT)
            fetched = datetime.now(timezone.utc).isoformat()
        tracker_bytes = read_regular(snapshot, LIMIT)
        report = summarize(inputs["sbom.syft.json"], inputs["vulnerabilities.json"], json.loads(tracker_bytes))
        report.update({"scan_status": scan["status"], "rootfs_sha256": scan["rootfs_sha256"],
                       "scan_report_sha256": hashlib.sha256(scan_bytes).hexdigest(),
                       "tracker": {"url": TRACKER if fetched else None, "fetched_at": fetched,
                                   "sha256": hashlib.sha256(tracker_bytes).hexdigest(),
                                   "authentication": "HTTPS" if fetched else "operator-supplied"}})
        (staging / "triage.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        (staging / "triage.md").write_text(markdown(report))
        require(not output.exists() and not output.is_symlink(), "triage output appeared during review")
        staging.rename(output)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tracker", type=Path, help="Use an operator-supplied snapshot instead of HTTPS download")
    args = parser.parse_args()
    try:
        report = triage(args.evidence, args.output, args.tracker)
        print(json.dumps({key: value for key, value in report.items() if key != "findings"}, sort_keys=True, indent=2))
    except (VerificationError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
