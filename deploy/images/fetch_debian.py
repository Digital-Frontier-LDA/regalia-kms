#!/usr/bin/env python3
"""Download and authenticate pinned Debian installer media before publication."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

from .verify import VerificationError, require, verify_gpg


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require(newurl.startswith("https://"), "non-HTTPS download redirect rejected")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path, limit: int) -> None:
    require(url.startswith("https://"), "downloads must use HTTPS")
    opener = urllib.request.build_opener(HTTPSRedirects())
    with opener.open(url, timeout=30) as response, destination.open("xb") as output:
        require(response.geturl().startswith("https://"), "non-HTTPS response rejected")
        size = 0
        for block in iter(lambda: response.read(1024 * 1024), b""):
            size += len(block)
            require(size <= limit, "download exceeds size limit")
            output.write(block)


def fetch(destination: Path, policy_path: Path) -> dict:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    fields = {"schema", "version", "architecture", "image", "base_url", "checksum",
              "signature", "key_url", "primary_fingerprint"}
    require(isinstance(policy, dict) and set(policy) == fields, "invalid Debian media policy fields")
    require(policy["schema"] == "regalia.debian-media/v1" and policy["architecture"] == "amd64",
            "unsupported Debian media policy")
    require(isinstance(policy["version"], str)
            and re.fullmatch(r"13\.[0-9]+\.[0-9]+", policy["version"]) is not None,
            "an explicit Debian 13 release is required")
    require(policy["image"] == f"debian-{policy['version']}-amd64-netinst.iso"
            and policy["base_url"] == f"https://cdimage.debian.org/debian-cd/{policy['version']}/amd64/iso-cd/"
            and policy["checksum"] == "SHA512SUMS" and policy["signature"] == "SHA512SUMS.sign",
            "unexpected Debian media source")
    require(isinstance(policy["key_url"], str) and policy["key_url"].startswith("https://www.debian.org/CD/"),
            "unexpected Debian signing-key source")
    destination = destination.absolute()
    require(not destination.exists() and not destination.is_symlink(), "output directory already exists")
    require(destination.parent.is_dir(), "output parent directory must already exist")
    # Only rename a fully verified directory; interrupted downloads leave no usable
    # output. Caller must use an operator-owned parent, never a shared writable path.
    staging = Path(tempfile.mkdtemp(prefix=".regalia-media-", dir=destination.parent))
    try:
        download(policy["key_url"], staging / "debian-cd.pub", 4 * 1024 * 1024)
        for name in (policy["checksum"], policy["signature"]):
            download(policy["base_url"] + name, staging / name, 4 * 1024 * 1024)
        download(policy["base_url"] + policy["image"], staging / policy["image"], 2 * 1024 ** 3)
        report = verify_gpg(staging / policy["image"], staging / policy["checksum"],
                            staging / policy["signature"], staging / "debian-cd.pub",
                            policy["primary_fingerprint"])
        report.update({"publisher": "Debian CD", "source_url": policy["base_url"] + policy["image"],
                       "release": policy["version"], "architecture": policy["architecture"]})
        (staging / "verification.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        # The output parent is required to be private to the caller; do not let
        # another run's existing output silently be replaced.
        require(not destination.exists() and not destination.is_symlink(), "output directory appeared during fetch")
        os.rename(staging, destination)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--policy", type=Path, default=Path(__file__).with_name("debian-policy.json"))
    args = parser.parse_args()
    try:
        print(json.dumps(fetch(args.output, args.policy), sort_keys=True, indent=2))
        return 0
    except (VerificationError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
