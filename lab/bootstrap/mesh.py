"""Trusted host orchestration; prints only sanitized software-lab evidence."""

import hashlib
import json
import os
import subprocess
import signal
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


def probe(node, host, port, payload, raw=False):
    code = '''import http.client,json,sys
c=http.client.HTTPConnection(sys.argv[1],int(sys.argv[2]),timeout=1)
try:
 c.request("POST","/bootstrap",body=sys.argv[3],headers={"Content-Type":"application/json"})
 r=c.getresponse(); raw=r.read(65537)
 print(json.dumps({"reachable":True,"response":json.loads(raw)}))
except OSError:
 print(json.dumps({"reachable":False}))
finally:
 c.close()
'''
    return json.loads(command("exec", "-T", "--user", "10000:10000", node.lower(),
                              "python3", "-c", code, host, str(port), payload if raw else json.dumps(payload)).stdout)


def main():
    def interrupted(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
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
        for node in NODES:
            for peer in NODES:
                if node == peer:
                    continue
                control(node, "lock")
                check(f"{peer} bootstraps {node} over WireGuard",
                      control(node, "bootstrap", peers=[peer]) == {"active": True, "via": peer})
        for node in NODES:
            control(node, "lock")
            result = control(node, "bootstrap", peers=[peer for peer in NODES if peer != node])
            check(f"either available peer restores {node}", result["active"] and result["via"] != node)
        for survivor in NODES:
            locked = [node for node in NODES if node != survivor]
            for node in locked:
                control(node, "lock")
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda node: control(node, "bootstrap", peers=[survivor]), locked))
            check(f"{survivor} concurrently restores both other nodes",
                  all(result == {"active": True, "via": survivor} for result in results))
        for first in NODES:
            for node in NODES:
                control(node, "lock")
            for node in NODES:
                result = control(node, "bootstrap", peers=[peer for peer in NODES if peer != node])
                check(f"total outage before manual {first}: {node} stays locked", not result["active"])
            check(f"wrong recovery credential cannot seed {first}",
                  not control(first, "manual", key=os.urandom(64).hex())["active"])
            check(f"manual LUKS recovery seeds {first}", control(first, "manual", key=recovery[first])["active"])
            for node in NODES:
                if node == first:
                    continue
                check(f"manually recovered {first} restores {node}",
                      control(node, "bootstrap", peers=[first]) == {"active": True, "via": first})
        for node in NODES:
            handshakes = admin(node, "wg", "show", "wg-bootstrap", "latest-handshakes").stdout.decode().splitlines()
            check(f"{node} has actual WireGuard handshakes with both peers", len(handshakes) == 2
                  and all(int(line.split()[1]) > 0 for line in handshakes))
        check("cleartext bootstrap is blocked on the bridge", not probe("A", "10.89.91.2", 8443,
              {"op": "challenge", "node_id": "A"})["reachable"])
        check("peer cannot access local fixture control", not probe("A", "10.77.91.2", 9444,
              {"op": "identity"})["reachable"])
        check("WireGuard identity cannot substitute another node ID", probe("A", "10.77.91.2", 8443,
              {"op": "challenge", "node_id": "C"})["response"] == {"error": {"code": "DENIED"}})
        check("bootstrap endpoint refuses remote commissioning", probe("A", "10.77.91.2", 8443,
              {"op": "init"})["response"] == {"error": {"code": "DENIED"}})
        check("network endpoint rejects malformed node identity", probe("A", "10.77.91.2", 8443,
              {"op": "challenge", "node_id": []})["response"] == {"error": {"code": "INVALID_REQUEST"}})
        admin("B", "ip", "link", "set", "wg-bootstrap", "down")
        started = time.monotonic()
        result = control("A", "bootstrap", peers=["B", "C"])
        elapsed = time.monotonic() - started
        check("reachable C restores A without waiting for unreachable B", result == {"active": True, "via": "C"}
              and elapsed < 3.5)
        admin("C", "ip", "link", "set", "wg-bootstrap", "down")
        check("both unreachable peers leave A locked", not control("A", "bootstrap", peers=["B", "C"])["active"])
        for node in "BC":
            admin(node, "ip", "link", "set", "wg-bootstrap", "up")

        def restored(node, peers):
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                result = control(node, "bootstrap", peers=peers)
                if result["active"]:
                    return True
                time.sleep(0.2)
            return False

        check("healed network restores A autonomously", restored("A", ["B", "C"]))
        admin("A", "ip", "route", "add", "unreachable", "10.77.91.2/32")
        check("wrong route refuses the selected peer", not control("A", "bootstrap", peers=["B"])["active"])
        check("other peer survives a wrong route", control("A", "bootstrap", peers=["B", "C"]) == {"active": True, "via": "C"})
        admin("A", "ip", "route", "del", "10.77.91.2/32")
        admin("B", "wg", "set", "wg-bootstrap", "peer", identities["A"]["wg_public"], "remove")
        check("missing WireGuard peer identity blocks bootstrap", not control("A", "bootstrap", peers=["B"])["active"])
        admin("B", "wg", "set", "wg-bootstrap", "peer", identities["A"]["wg_public"],
              "allowed-ips", "10.77.91.1/32", "endpoint", "10.89.91.1:51820", "persistent-keepalive", "1")
        check("restored WireGuard enrollment restores A", restored("A", ["B"]))
        control("B", "drop_response")
        check("lost grant leaves target locked", not control("A", "bootstrap", peers=["B"])["active"])
        check("fresh challenge recovers after a lost grant", control("A", "bootstrap", peers=["B"])["active"])
        check("network endpoint bounds oversized bodies", probe("A", "10.77.91.2", 8443,
              {"op": "challenge", "node_id": "A", "padding": "x" * 65536})["response"]
              == {"error": {"code": "INVALID_REQUEST"}})
        check("network endpoint refuses duplicate JSON fields", probe("A", "10.77.91.2", 8443,
              '{"op":"challenge","node_id":"A","node_id":"C"}', raw=True)["response"]
              == {"error": {"code": "INVALID_REQUEST"}})

        def policy(states, epoch=1, nodes=NODES):
            for node in nodes:
                control(node, "policy", nodes=states, epoch=epoch)

        active = {node: "ACTIVE" for node in NODES}
        revoked_a = dict(active, A="REVOKED_STOLEN")
        policy(revoked_a, epoch=2, nodes="BC")
        check("current peers refuse a revoked requester with a stale local view",
              not control("A", "bootstrap", peers=["B", "C"])["active"])
        # Reproduce the freshness gap; this is an observed limitation, not a security pass.
        policy(active, epoch=1, nodes="B")
        stale = control("A", "bootstrap", peers=["B"])["active"]
        report["limitations_observed"] = {"stale_target_and_authorizer_can_bootstrap": stale}
        check("stale membership authorization risk is reproduced", stale)
        policy(dict(active, B="REVOKED_STOLEN"), epoch=2, nodes="A")
        check("target refuses a locally revoked authorizer even if that peer is stale",
              not control("A", "bootstrap", peers=["B"])["active"])
        policy(active, epoch=2, nodes="C")
        check("current non-revoked peer restores target", control("A", "bootstrap", peers=["C"])["active"])
        policy(active, epoch=2, nodes="A")
        check("target refuses a known older peer epoch", not control("A", "bootstrap", peers=["B"])["active"])
        policy(active, epoch=2)
        check("matching current epochs restore target", control("A", "bootstrap", peers=["B"])["active"])
        maintenance = dict(active, A="MAINTENANCE")
        policy(maintenance, epoch=3)
        check("MAINTENANCE node can receive bootstrap", control("A", "bootstrap", peers=["B"])["active"])
        check("MAINTENANCE node cannot authorize another node", not control("B", "bootstrap", peers=["A"])["active"])
        check("ACTIVE peer recovers the remaining node", control("B", "bootstrap", peers=["C"])["active"])
        policy(active, epoch=4)
        control("A", "extend_pcr")
        check("changed target PCR prevents bootstrap despite healthy reachable peers",
              control("A", "bootstrap", peers=["B", "C"]) == {"active": False, "reason": "local_policy"})
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
