"""Scan Linux root filesystems without macOS filename case collisions."""

import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import tempfile

from deploy.images import tools
from deploy.images.verify import require


ROOT = Path(__file__).resolve().parents[2]


def scan(rootfs: Path, scanners: Path, output: Path):
    environment = dict(os.environ)
    environment.pop("DOCKER_DEFAULT_PLATFORM", None)
    image = json.loads(subprocess.run(["docker", "image", "inspect", "regalia-bootstrap-lab:dev"],
                                     check=True, capture_output=True, text=True, env=environment).stdout)[0]
    architecture = image["Architecture"]
    require(architecture in {"amd64", "arm64"}, "unsupported development runner architecture")
    if not scanners.exists():
        tools.install(scanners, target="linux_" + architecture)
    report = json.loads((scanners / "verification.json").read_text())
    require(report["platform"] == "linux_" + architecture, "scanner platform differs from runner")
    require(not output.exists() and not output.is_symlink(), "scan output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    # Only this owned output directory is writable from the container. A private
    # Linux overlay receives the filesystem projection, avoiding the host's case
    # folding. No Docker socket, hardware device or user home is mounted.
    with tempfile.TemporaryDirectory(prefix="regalia-scan-source-") as temporary:
        context = Path(temporary)
        sources = context / "deploy/images"
        sources.mkdir(parents=True)
        for name in ("__init__.py", "scan.py", "tools.py", "verify.py", "fetch_debian.py", "tools-policy.json"):
            shutil.copyfile(ROOT / "deploy/images" / name, sources / name)
        # The minimal lab runner has no CA package. Supply the trusted HOST root
        # store, never certificates from the untrusted image being scanned.
        roots = context / "trusted-roots.pem"
        if platform.system() == "Darwin":
            roots.write_bytes(subprocess.run(["security", "find-certificate", "-a", "-p",
                "/System/Library/Keychains/SystemRootCertificates.keychain"], check=True, capture_output=True).stdout)
        else:
            shutil.copyfile("/etc/ssl/certs/ca-certificates.crt", roots)
        require(b"BEGIN CERTIFICATE" in roots.read_bytes(), "trusted host CA store is empty")
        roots_digest = hashlib.sha256(roots.read_bytes()).hexdigest()
        command = ["docker", "run", "--rm", "--pull=never", "--platform", "linux/" + architecture,
                   "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", f"{os.getuid()}:{os.getgid()}",
                   "--pids-limit", "128", "--memory", "3g", "--env", "REGALIA_SCANNER_CACHE=/tmp/regalia-grype-db", "--workdir", "/workspace",
                   "--env", "SSL_CERT_FILE=/workspace/trusted-roots.pem",
                   "--mount", f"type=bind,src={context},dst=/workspace,readonly",
                   "--mount", f"type=bind,src={rootfs},dst=/input/rootfs.tar.gz,readonly",
                   "--mount", f"type=bind,src={scanners},dst=/scanners,readonly",
                   "--mount", f"type=bind,src={output},dst=/results", "--entrypoint", "python3", image["Id"],
                   "-m", "deploy.images.scan", "/input/rootfs.tar.gz", "--tools", "/scanners", "--output", "/results/evidence"]
        result = subprocess.run(command, env=environment, timeout=1800)
    evidence = output / "evidence"
    require((evidence / "scan-report.json").is_file(), "Docker scanner produced no evidence")
    (output / "runner.json").write_text(json.dumps({"image_id": image["Id"], "architecture": architecture,
        "scope": "development-only Docker runner; publisher authentication not established",
        "production_approved": False, "trusted_host_roots_sha256": roots_digest,
        "scanner_exit_code": result.returncode}, sort_keys=True, indent=2) + "\n")
    require(result.returncode in {0, 1}, "Docker scanner failed unexpectedly")
    return result.returncode


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(scan(args.rootfs.resolve(), args.tools.absolute(), args.output.absolute()))
