"""Trusted orchestration of signed policy, access leases, devices and chaos."""

import copy
import hashlib
import json
import os
import signal
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import ed25519

from mesh import ROOT, NODES, admin, command
from peer import Refusal, ak_digest, canonical
from tokens import Clock, FRESHNESS_DOMAIN, signed_token


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
        for node in nodes:
            self.relay(source, node, "apply_manifest", envelope=envelope)

    def fresh(self, nodes=NODES, ttl=20000):
        envelope = self.authority.fresh(ttl)
        for node in nodes:
            self.relay("C", node, "install_freshness", envelope=envelope)

    def sync(self, node, source="C"):
        for _ in range(16):
            epoch = self.rpc(node, "status")["epoch"]
            batch = self.relay(node, source, "get_manifests", after_epoch=epoch)["manifests"]
            if not batch:
                return
            for envelope in batch:
                self.relay(source, node, "apply_manifest", envelope=envelope)
        raise RuntimeError("bounded policy catch-up exhausted")

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
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    report = {"schema_version": 1, "evidence_class": "emulated-cluster", "status": "failed", "checks": [],
              "timestamp": datetime.now(timezone.utc).isoformat(), "source_commit": os.environ["REGALIA_LAB_COMMIT"],
              "image_id": os.environ["REGALIA_LAB_IMAGE_ID"], "platform": os.environ["REGALIA_LAB_PLATFORM"],
              "sources_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in [
                  "cluster.py", "cluster_mesh.py", "tokens.py", "policy_cases.py", "peer.py", "network.py", "Dockerfile"]}}
    cluster = Cluster(report)
    try:
        cluster.start()
        from policy_cases import policy_cases
        policy_cases(cluster)
        report["packages"] = command("exec", "-T", "a", "cat", "/opt/packages.tsv").stdout.decode().splitlines()
        report["status"] = "passed"
    finally:
        cleanup = command("down", "--volumes", "--remove-orphans", required=False)
        report["cleanup"] = "passed" if cleanup.returncode == 0 else "failed"
        if cleanup.returncode:
            report["status"] = "failed"
        (ROOT / ".artifacts/cluster-report.json").write_text(json.dumps(report, indent=2) + "\n")
    if report["status"] != "passed":
        raise RuntimeError("cluster run failed")


if __name__ == "__main__":
    main()
