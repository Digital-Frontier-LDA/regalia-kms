"""Trusted host orchestration; prints only sanitized software-lab evidence."""

import hashlib
import json
import os
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NODES = "ABC"
PROJECT = f"regalia-bootstrap-mesh-{os.getpid()}"
COMPOSE = ["docker", "compose", "--project-name", PROJECT, "--file", str(ROOT / "compose.network.yaml")]


def command(*args, data=None, required=True, timeout=120):
    result = subprocess.run([*COMPOSE, *args], input=data, capture_output=True, timeout=timeout)
    if required and result.returncode:
        raise RuntimeError(f"mesh command {args[0]} failed (exit {result.returncode})")
    return result


def control(node, op, **fields):
    result = command("exec", "-T", "--user", "10000:10000", node.lower(),
                     "python3", "/opt/network.py", "control",
                     data=json.dumps(dict(fields, op=op)).encode())
    return json.loads(result.stdout)["result"]


def admin(node, *args):
    return command("exec", "-T", "--user", "0:0", node.lower(), *args)


def main():
    report = {"schema_version": 1, "evidence_class": "emulated-network",
              "timestamp": datetime.now(timezone.utc).isoformat(), "status": "failed", "checks": [],
              "source_commit": os.environ.get("REGALIA_LAB_COMMIT", "unknown"),
              "platform": os.environ["REGALIA_LAB_PLATFORM"],
              "swtpm_seccomp": os.environ["REGALIA_LAB_SWTPM_SECCOMP"],
              "image_id": os.environ["REGALIA_LAB_IMAGE_ID"],
              "sources_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                 for name in ["lab.py", "peer.py", "network.py", "mesh.py", "compose.network.yaml", "Dockerfile"]}}

    def check(name, passed):
        report["checks"].append({"name": name, "status": "passed" if passed else "failed"})
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise RuntimeError("mesh assertion failed")

    try:
        command("up", "--detach", "--no-build", "--pull", "never")
        identities = {}
        for node in NODES:
            for _ in range(60):
                try:
                    identities[node] = control(node, "identity")
                    break
                except RuntimeError:
                    time.sleep(0.5)
            else:
                raise RuntimeError(f"node {node} startup timed out")
            check(f"{node} service has no effective capabilities", identities[node]["uid"] == 10000
                  and int(identities[node]["caps"], 16) == 0)
        for node in NODES:
            for peer in NODES:
                if node == peer:
                    continue
                index = NODES.index(peer) + 1
                admin(node, "wg", "set", "wg-bootstrap", "peer", identities[peer]["wg_public"],
                      "allowed-ips", f"10.77.91.{index}/32", "endpoint", f"10.89.91.{index}:51820",
                      "persistent-keepalive", "1")
        signing = {}
        for node in NODES:
            targets = {peer: {field: identities[peer][field] for field in ["ak_pem", "approved_pcr"]}
                       for peer in NODES if peer != node}
            signing[node] = control(node, "enroll", targets=targets)["peer_public_key"]
        for node in NODES:
            control(node, "pins", pins={peer: signing[peer] for peer in NODES if peer != node})
        recovery = {node: control(node, "disk")["recovery_key"] for node in NODES}
        check("all three disposable LUKS images are commissioned over WireGuard", len(recovery) == 3)
        control("A", "lock")
        check("B bootstraps A over WireGuard", control("A", "bootstrap", peers=["B"]) == {"active": True, "via": "B"})
        report["packages"] = command("exec", "-T", "a", "cat", "/opt/packages.tsv").stdout.decode().splitlines()
        report["status"] = "passed"
    finally:
        cleanup = command("down", "--volumes", "--remove-orphans", required=False)
        report["cleanup"] = "passed" if cleanup.returncode == 0 else "failed"
        if cleanup.returncode:
            report["status"] = "failed"
        (ROOT / ".artifacts/network-report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "passed":
        raise RuntimeError("mesh run failed")


if __name__ == "__main__":
    main()
