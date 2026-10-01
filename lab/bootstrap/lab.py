"""Disposable software-only bootstrap experiments; never production evidence."""

import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


def main():
    report = {
        "schema_version": 1,
        "evidence_class": "emulated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "architecture": platform.machine(),
        "source_commit": os.environ.get("REGALIA_LAB_COMMIT", "unknown"),
        "debian_version": Path("/etc/debian_version").read_text().strip(),
        "packages": Path("/opt/packages.tsv").read_text().splitlines(),
        "checks": [],
    }
    for tool in ["swtpm", "tpm2_quote", "tpm2_checkquote", "cryptsetup", "wg"]:
        result = subprocess.run(["which", tool], capture_output=True, check=True)
        assert result.stdout
    print("PASS Debian 13 arm64/amd64 lab toolchain")
    report["checks"].append({"name": "toolchain", "status": "passed"})
    Path(os.environ["REGALIA_LAB_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
