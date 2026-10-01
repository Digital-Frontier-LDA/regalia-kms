"""Disposable software-only bootstrap experiments; never production evidence."""

import json
import os
import platform
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


def run(*args, env=None, data=None, required=True):
    result = subprocess.run(list(map(str, args)), input=data, env=env,
                            capture_output=True, timeout=60)
    if required and result.returncode:
        # Output can contain plaintext unsealed material. Never include it in errors.
        raise RuntimeError(f"{args[0]} failed (exit {result.returncode})")
    return result


class TPM:
    def __init__(self, root, name):
        self.root = root / name
        self.root.mkdir(mode=0o700)
        self.name = name
        self.process = None
        self.socket = self.root / "tpm.sock"
        self.env = dict(os.environ, TPM2TOOLS_TCTI=f"swtpm:path={self.socket}")

    def start(self):
        state = self.root / "state"
        state.mkdir()
        self.process = subprocess.Popen([
            "swtpm", "socket", "--tpm2", "--tpmstate", f"dir={state}",
            "--server", f"type=unixio,path={self.socket}",
            "--ctrl", f"type=unixio,path={self.socket}.ctrl",
            "--flags", "not-need-init,startup-clear",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            if self.process.poll() is not None:
                raise RuntimeError(f"swtpm {self.name} exited before startup")
            if self.socket.exists() and self.call("tpm2_getcap", "properties-fixed", required=False).returncode == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"swtpm {self.name} startup timed out")
        self.call("tpm2_createek", "-G", "rsa", "-c", "0x81010001", "-Q")
        self.call("tpm2_createak", "-C", "0x81010001", "-G", "rsa", "-g", "sha256",
                  "-s", "rsassa", "-c", self.root / "ak.ctx", "-u", self.root / "ak.pem", "-f", "pem", "-Q")
        self.call("tpm2_evictcontrol", "-C", "o", "-c", self.root / "ak.ctx", "0x81010002", "-Q")
        self.call("tpm2_flushcontext", "-t")

    def call(self, *args, **kwargs):
        return run(*args, env=self.env, **kwargs)

    def quote(self, challenge, prefix):
        paths = [self.root / f"{prefix}.{suffix}" for suffix in ["msg", "sig", "pcrs"]]
        self.call("tpm2_quote", "-c", "0x81010002", "-l", "sha256:7", "-q", challenge.hex(),
                  "-m", paths[0], "-s", paths[1], "-o", paths[2], "-g", "sha256", "-Q")
        return paths

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=5)


def verify_quote(public, paths, challenge):
    return run("tpm2_checkquote", "-u", public, "-m", paths[0], "-s", paths[1],
               "-f", paths[2], "-g", "sha256", "-q", challenge.hex(),
               env=dict(os.environ, TPM2TOOLS_TCTI="none"), required=False).returncode == 0


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
    nodes = []
    try:
        with tempfile.TemporaryDirectory(prefix="regalia-lab-") as directory:
            root = Path(directory)
            for name in ["A", "B"]:
                node = TPM(root, name)
                nodes.append(node)
                node.start()
            a, b = nodes
            challenge = os.urandom(32)
            quote = a.quote(challenge, "fresh")
            cases = [
                ("fresh quote verifies against enrolled AK", verify_quote(a.root / "ak.pem", quote, challenge)),
                ("quote replay fails with fresh challenge", not verify_quote(a.root / "ak.pem", quote, os.urandom(32))),
                ("substituted TPM identity is rejected", not verify_quote(b.root / "ak.pem", quote, challenge)),
            ]
            for name, passed in cases:
                report["checks"].append({"name": name, "status": "passed" if passed else "failed"})
                print(("PASS " if passed else "FAIL ") + name)
                if not passed:
                    raise RuntimeError(name)
    finally:
        for node in nodes:
            node.close()
    Path(os.environ["REGALIA_LAB_REPORT"]).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
