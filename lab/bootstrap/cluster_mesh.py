"""Trusted orchestration of signed policy, access leases, devices and chaos."""

import copy
import hashlib
import json
import os
import signal
import time
import tempfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519

from mesh import ROOT, NODES, admin, command
from peer import Refusal, ak_digest, apply_manifest, canonical
from tokens import Clock, FRESHNESS_DOMAIN, freshness, signed_token
from leases import verify_service
from cryptography.hazmat.primitives import serialization


class Authority:
    def __init__(self, identities):
        self.keys = {name: ed25519.Ed25519PrivateKey.generate()
                     for name in ["membership_root", "revocation", "freshness"]}
        self.pins = {name: self.keys[name].public_key().public_bytes_raw().hex()
                     for name in ["membership_root", "revocation"]}
        self.pins["cluster_id"] = os.urandom(32).hex()
        self.manifest = {"version": 1, "cluster_id": self.pins["cluster_id"], "epoch": 1,
                         "previous_digest": "00" * 32, "nodes": {
                             node: {"state": "ACTIVE", "ak_sha256": ak_digest(identity["ak_pem"]),
                                    "approved_pcr": identity["approved_pcr"]}
                             for node, identity in identities.items()}}

    def envelope(self, manifest=None, authority="membership_root"):
        payload = {"authority": authority, "manifest": manifest or self.manifest}
        return dict(payload, signature=self.keys[authority].sign(
            b"regalia-bootstrap-lab/v1/membership\0" + canonical(payload)).hex())

    def update(self, changes, authority="membership_root"):
        previous = self.manifest
        self.manifest = dict(copy.deepcopy(previous), epoch=previous["epoch"] + 1,
                             previous_digest=hashlib.sha256(canonical(previous)).hexdigest())
        for node, state in changes.items():
            self.manifest["nodes"][node]["state"] = state
        return self.envelope(authority=authority)

    def fresh(self, ttl=20000, manifest=None):
        manifest = manifest or self.manifest
        now = int(time.time() * 1000)
        payload = {"version": 1, "cluster_id": self.pins["cluster_id"], "epoch": manifest["epoch"],
                   "manifest_digest": hashlib.sha256(canonical(manifest)).hexdigest(),
                   "not_before": now - 10, "expires_at": now + ttl}
        return signed_token(self.keys["freshness"], FRESHNESS_DOMAIN, payload)


class Cluster:
    def __init__(self, report):
        self.report = report
        self.client_clock = Clock()
        self.client_directory = tempfile.TemporaryDirectory(prefix="regalia-client-")

    def check(self, label, valid):
        self.report["checks"].append({"name": label, "status": "passed" if valid else "failed"})
        print(("PASS " if valid else "FAIL ") + label, flush=True)
        if not valid:
            raise RuntimeError("cluster assertion failed")

    def rpc(self, node, op, **values):
        result = command("exec", "-T", "--user", "10000:10000", node.lower(),
                         "python3", "/opt/cluster.py", "control",
                         data=canonical(dict(values, op=op)), required=False)
        if result.returncode:
            raise RuntimeError("cluster control failed")
        response = json.loads(result.stdout)
        if set(response) == {"error"} and response["error"].get("code") in ["DENIED", "INVALID_REQUEST"]:
            raise Refusal(response["error"]["code"])
        if set(response) != {"result"}:
            raise RuntimeError("invalid cluster control response")
        return response["result"]

    def denied(self, label, function):
        try:
            function()
            valid = False
        except Refusal:
            valid = True
        self.check(label, valid)

    def relay(self, source, target, op, **values):
        return self.rpc(source, "relay", peer=target, command=dict(values, op=op))

    def publish(self, envelope, nodes=NODES, source="C"):
        from pathlib import Path
        apply_manifest({"op": "apply_manifest", "envelope": envelope}, self.client_policy,
                       Path(self.client_directory.name) / "policy.json")
        for node in nodes:
            result = self.relay(source, node, "apply_manifest", envelope=envelope)
            expected = {"epoch": envelope["manifest"]["epoch"],
                        "manifest_digest": hashlib.sha256(canonical(envelope["manifest"])).hexdigest()}
            if result != expected:
                raise RuntimeError("signed policy delivery was not acknowledged")

    def fresh(self, nodes=NODES, ttl=20000):
        envelope = self.authority.fresh(ttl)
        for node in nodes:
            if self.relay("C", node, "install_freshness", envelope=envelope) != {"epoch": self.authority.manifest["epoch"]}:
                raise RuntimeError("freshness delivery was not acknowledged")

    def sync(self, node, source="C"):
        for _ in range(16):
            epoch = self.rpc(node, "status")["epoch"]
            batch = self.relay(node, source, "get_manifests", after_epoch=epoch)["manifests"]
            if not batch:
                return
            for envelope in batch:
                self.relay(source, node, "apply_manifest", envelope=envelope)
        raise RuntimeError("bounded policy catch-up exhausted")

    def sign(self, node, message=None, request_id=None, source="C"):
        message = message or os.urandom(32)
        request_id = request_id or os.urandom(16).hex()
        reply = self.rpc(source, "service_request", peer=node,
                         command={"op": "sign", "message": message.hex(), "request_id": request_id})
        return reply, request_id, message

    def verify(self, node, reply, request_id, message):
        freshness(self.authority.fresh(), self.authority.keys["freshness"].public_key().public_bytes_raw(),
                  self.client_policy, self.client_clock)
        public = serialization.load_der_public_key(bytes.fromhex(self.identities[node]["device_public"]))
        return verify_service(reply, public, {peer: bytes.fromhex(pin) for peer, pin in self.signing.items()},
                              self.client_policy, self.client_clock, node, request_id, message)

    def start(self):
        command("up", "--detach", "--no-build", "--pull", "never")
        identities = {}
        for node in NODES:
            for _ in range(60):
                try:
                    identities[node] = self.rpc(node, "identity")
                    break
                except RuntimeError:
                    time.sleep(0.5)
            else:
                raise RuntimeError("cluster startup timed out")
            self.check(f"{node} drops all service capabilities", identities[node]["uid"] == 10000
                       and int(identities[node]["caps"], 16) == 0)
            self.check(f"{node} has distinct boot and runtime WireGuard identities",
                       identities[node]["wg_public"] != identities[node]["service_wg_public"])
        self.identities = identities
        for node in NODES:
            for peer in NODES:
                if node == peer:
                    continue
                index = NODES.index(peer) + 1
                for interface, field, prefix, port in [
                        ("wg-bootstrap", "wg_public", "10.77.91", 51820),
                        ("wg-service", "service_wg_public", "10.78.91", 51821)]:
                    admin(node, "wg", "set", interface, "peer", identities[peer][field],
                          "allowed-ips", f"{prefix}.{index}/32", "endpoint", f"10.89.91.{index}:{port}",
                          "persistent-keepalive", "1")
        self.authority = Authority(identities)
        self.client_policy = {"epoch": 0, "manifest": None, "manifest_digest": "00" * 32,
                              "authorities": self.authority.pins, "targets": {}, "nodes": {}}
        self.signing = {}
        for node in NODES:
            targets = {peer: {field: identities[peer][field] for field in ["ak_pem", "approved_pcr"]}
                       for peer in NODES if peer != node}
            self.signing[node] = self.rpc(node, "enroll", targets=targets, authorities=self.authority.pins,
                freshness_public=self.authority.keys["freshness"].public_key().public_bytes_raw().hex())["peer_public_key"]
        self.publish(self.authority.envelope())
        self.fresh()
        for node in NODES:
            self.rpc(node, "pins", pins={peer: self.signing[peer] for peer in NODES if peer != node})
        self.recovery = {node: self.rpc(node, "disk")["recovery_key"] for node in NODES}
        self.check("signed policy and fresh authority enable all three real LUKS fixtures", len(self.recovery) == 3)


def main():
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    report = {"schema_version": 1, "evidence_class": "emulated-cluster", "status": "failed", "checks": [],
              "timestamp": datetime.now(timezone.utc).isoformat(), "source_commit": os.environ["REGALIA_LAB_COMMIT"],
              "image_id": os.environ["REGALIA_LAB_IMAGE_ID"], "platform": os.environ["REGALIA_LAB_PLATFORM"],
              "sources_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in [
                  "cluster.py", "cluster_mesh.py", "tokens.py", "leases.py", "device.py", "policy_cases.py",
                  "runtime_cases.py", "device_cases.py", "chaos_cases.py", "peer.py", "network.py", "lab.py", "mesh.py",
                  "Dockerfile", "compose.network.yaml", "run-cluster.sh", "run-network.sh", "harness-requirements.txt"]},
              "docker_daemon_platform": os.environ["REGALIA_LAB_DAEMON_PLATFORM"],
              "swtpm_seccomp": os.environ["REGALIA_LAB_SWTPM_SECCOMP"]}
    cluster = Cluster(report)
    try:
        cluster.start()
        from policy_cases import policy_cases
        policy_cases(cluster)
        from runtime_cases import runtime_cases
        runtime_cases(cluster)
        from device_cases import device_cases
        device_cases(cluster)
        from chaos_cases import chaos_cases
        chaos_cases(cluster)
        report["packages"] = command("exec", "-T", "a", "cat", "/opt/packages.tsv").stdout.decode().splitlines()
        report["status"] = "passed"
    finally:
        cleanup = command("down", "--volumes", "--remove-orphans", required=False)
        report["cleanup"] = "passed" if cleanup.returncode == 0 else "failed"
        if cleanup.returncode:
            report["status"] = "failed"
        cluster.client_directory.cleanup()
        (ROOT / ".artifacts/cluster-report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "passed":
        raise RuntimeError("cluster run failed")


if __name__ == "__main__":
    main()
