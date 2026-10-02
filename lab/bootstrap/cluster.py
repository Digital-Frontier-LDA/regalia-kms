"""Disposable signed-policy cluster; local fixture controls never cross the mesh."""

import argparse
import hashlib
import http.client
import json
import os
import threading
import time
from pathlib import Path

from network import BoundedServer, Node, address, configure, exchange
from peer import Refusal, canonical, fields, hex_bytes
from tokens import Clock, freshness
from device import Device
from leases import LEASE_DOMAIN, LEASE_FIELDS, REQUEST_DOMAIN, REQUEST_FIELDS, SERVICE_DOMAIN, service_statement, verify_lease
from tokens import signed_token, verified_token
from cryptography.hazmat.primitives.asymmetric import ed25519


def service_address(node):
    return "10.78.91." + str("ABC".index(node) + 1)


class ClusterNode(Node):
    def __init__(self, node_id, key, public, service_public):
        super().__init__(node_id, key, public)
        self.service_public = service_public
        self.clock = Clock()
        self.freshness_pin = None
        self.freshness_token = None
        self.history = []
        self.admin = Admin(self)
        self.device = Device(self.root)
        self.lease = None
        self.lease_challenges = {}
        self.runtime = Runtime(self)
        self.service = Service(self)
        self.lease_lifetime = 1500

    def invalidate(self):
        self.lease = None
        self.lease_challenges = {}
        self.device.logout()

    def ready(self):
        self.current()
        if not self.active or not self.device.present or self.lease is None:
            raise Refusal()
        verify_lease(self.lease, self.pins, self.policy(), self.clock, self.node_id,
                     self.device.fingerprint, self.generation)
        if self.device.session is None:
            raise Refusal()
        return True

    def sweep(self):
        while True:
            time.sleep(0.1)
            with self.lock:
                if self.lease is not None:
                    try:
                        self.ready()
                    except Refusal:
                        self.invalidate()

    def policy(self):
        return json.loads(self.state.read_bytes())

    def current(self):
        if self.freshness_pin is None or self.freshness_token is None:
            raise Refusal()
        return freshness(self.freshness_token, self.freshness_pin, self.policy(), self.clock)

    def release(self, command, source):
        with self.lock:
            self.current()
            return super().release(command, source)

    def grant(self, peer_id, session, session_id):
        with self.lock:
            self.current()
        return super().grant(peer_id, session, session_id)

    def bootstrap(self, peers):
        with self.lock:
            self.invalidate()
            try:
                self.current()
            except Refusal:
                self.active = False
                return {"active": False, "reason": "freshness"}
        result = super().bootstrap(peers)
        with self.lock:
            try:
                self.current()
            except Refusal:
                self.active = False
                return {"active": False, "reason": "freshness"}
        return result

    def renew(self, peers):
        if not isinstance(peers, list) or not peers or not all(isinstance(p, str) and p in self.pins for p in peers):
            raise Refusal("INVALID_REQUEST")
        with self.lock:
            self.current()
            policy = self.policy()
            if not self.active or policy["nodes"][self.node_id] != "ACTIVE" or not self.device.present:
                raise Refusal()
            generation = self.generation
            key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(policy["signing_key"]))
        for peer in peers:
            try:
                challenge = exchange(service_address(peer), 8445, {"op": "lease_challenge", "node_id": self.node_id},
                                     timeout=1, route="/lease")
                fields(challenge, {"challenge_id", "nonce"})
                hex_bytes(challenge["challenge_id"], 16)
                hex_bytes(challenge["nonce"], 32)
                request = {"version": 1, "cluster_id": policy["authorities"]["cluster_id"],
                           "node_id": self.node_id, "issuer_id": peer, "epoch": policy["epoch"],
                           "manifest_digest": policy["manifest_digest"], "boot_generation": generation,
                           "service_public": self.device.fingerprint, **challenge}
                response = exchange(service_address(peer), 8445, {"op": "renew_lease",
                    "envelope": signed_token(key, REQUEST_DOMAIN, request)}, timeout=1, route="/lease")
                with self.lock:
                    self.current()
                    verify_lease(response, self.pins, self.policy(), self.clock, self.node_id,
                                 self.device.fingerprint, self.generation)
                    if response["payload"]["issuer_id"] != peer or response["payload"]["challenge_id"] != challenge["challenge_id"]:
                        raise Refusal()
                    if self.generation != generation or not self.active:
                        raise Refusal()
                    self.device.authenticate()
                    self.lease = response
                return {"lease": response, "via": peer}
            except (Refusal, OSError, http.client.HTTPException, TimeoutError):
                continue
        raise Refusal()

    def control(self, command):
        op = command["op"]
        if op == "enroll":
            fields(command, {"op", "targets", "authorities", "freshness_public"})
            self.freshness_pin = hex_bytes(command["freshness_public"], 32)
            return self.worker({"op": "init", "peer_id": self.node_id,
                                "targets": command["targets"], "authorities": command["authorities"]})["result"]
        if op == "identity":
            return dict(super().identity(), service_wg_public=self.service_public, device_public=self.device.der.hex(),
                        device_attributes=self.device.attributes, private_unreadable=self.device.private_unreadable)
        if op == "policy":
            raise Refusal()  # Unsigned mutation belongs only to the original fixtures.
        if op == "drop_admin_reply":
            self.admin.drop_next = True
            return {}
        if op == "relay":
            fields(command, {"op", "peer", "command"})
            if command["peer"] not in list("ABC"):
                raise Refusal("INVALID_REQUEST")
            try:
                return exchange(service_address(command["peer"]), 8444, command["command"], route="/membership")
            except (OSError, http.client.HTTPException, TimeoutError):
                return {"transport_failed": True}
        if op == "manual":
            self.current()
        if op == "lock":
            with self.lock:
                self.invalidate()
        if op == "renew":
            fields(command, {"op", "peers"})
            return self.renew(command["peers"])
        if op == "runtime_request":
            fields(command, {"op", "peer", "command"})
            if command["peer"] not in list("ABC"):
                raise Refusal("INVALID_REQUEST")
            return exchange(service_address(command["peer"]), 8445, command["command"], route="/lease")
        if op == "service_request":
            # This proxy issues requests as this node's runtime WireGuard identity.
            fields(command, {"op", "peer", "command"})
            if command["peer"] not in list("ABC"):
                raise Refusal("INVALID_REQUEST")
            return exchange(service_address(command["peer"]), 8446, command["command"], route="/kms")
        if op == "prepare_lease_request":
            fields(command, {"op", "peer"})
            peer = command["peer"]
            if peer not in list("ABC") or peer == self.node_id:
                raise Refusal("INVALID_REQUEST")
            with self.lock:
                self.current()
                policy = self.policy()
                challenge = exchange(service_address(peer), 8445, {"op": "lease_challenge", "node_id": self.node_id}, route="/lease")
                fields(challenge, {"challenge_id", "nonce"})
                body = {"version": 1, "cluster_id": policy["authorities"]["cluster_id"], "epoch": policy["epoch"],
                        "manifest_digest": policy["manifest_digest"], "node_id": self.node_id, "issuer_id": peer,
                        "boot_generation": self.generation, "service_public": self.device.fingerprint, **challenge}
                key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(policy["signing_key"]))
                return {"op": "renew_lease", "envelope": signed_token(key, REQUEST_DOMAIN, body)}
        if op == "adopt_lease":
            fields(command, {"op", "lease"})
            with self.lock:
                self.current()
                if not self.active:
                    raise Refusal()
                verify_lease(command["lease"], self.pins, self.policy(), self.clock, self.node_id,
                             self.device.fingerprint, self.generation)
                self.device.authenticate()
                self.lease = command["lease"]
            return {}
        if op == "clock_fault":
            fields(command, {"op", "offset"})
            if type(command["offset"]) is not int or abs(command["offset"]) > 86400000:
                raise Refusal("INVALID_REQUEST")
            with self.lock:
                self.clock.offset = command["offset"]
            return {}
        if op == "clock_reset":
            with self.lock:
                self.clock.offset = 0
                self.clock.reset()
                self.freshness_token = None
                self.invalidate()
                self.generation += 1
            return {}
        if op in ["device_remove", "device_insert"]:
            with self.lock:
                self.invalidate()
                self.generation += 1
                getattr(self.device, "remove" if op == "device_remove" else "insert")()
            return {}
        if op == "malicious_sign":
            # Trusted fault instrumentation; never available on a runtime route.
            fields(command, {"op", "request_id", "message", "lease"})
            with self.lock:
                self.device.authenticate()
                statement = service_statement(self.node_id, command["request_id"], hex_bytes(command["message"], maximum=4096), command["lease"])
                signature = self.device.sign(SERVICE_DOMAIN + canonical(statement))
                self.device.logout()
                return {"statement": statement, "lease": command["lease"], "signature": signature.hex()}
        if op == "device_probe":
            with self.lock:
                try:
                    self.device.slot()
                    visible = True
                except Refusal:
                    visible = False
                return {"token_visible": visible}
        if op == "device_auth_probe":
            with self.lock:
                self.ready()
                refused = self.device.logout_probe()
                self.invalidate()
                return {"refused": refused}
        if op == "device_bad_pin":
            with self.lock:
                self.invalidate()
                return {"refused": self.device.wrong_pin_probe()}
        if op == "status":
            try:
                self.current()
                fresh = True
            except Refusal:
                fresh = False
            policy = self.policy()
            try:
                ready = self.ready()
            except Refusal:
                ready = False
            return dict(super().control(command), fresh=fresh, epoch=policy["epoch"],
                        manifest_digest=policy["manifest_digest"], nodes=policy["nodes"],
                        service_ready=ready, device_session=self.device.session is not None,
                        device_present=self.device.present)
        return super().control(command)


class Admin:
    def __init__(self, node):
        self.node, self.drop_next = node, False

    def release(self, command, source):
        if source not in [service_address(node) for node in "ABC"]:
            raise Refusal()
        with self.node.lock:
            if command["op"] == "apply_manifest":
                before = self.node.policy()["manifest_digest"]
                result = self.node.worker(command)
                if "error" in result:
                    raise Refusal(result["error"]["code"])
                if result["result"]["manifest_digest"] != before:
                    self.node.history.append(command["envelope"])
                    self.node.history = self.node.history[-64:]
                    from peer import persist
                    persist(self.node.root / "history.json", self.node.history)
                    self.node.freshness_token = None
                    self.node.invalidate()
                    self.node.generation += 1
                    if self.node.policy()["nodes"][self.node.node_id] not in ["ACTIVE", "MAINTENANCE"]:
                        self.node.active = False
                return result
            if command["op"] == "get_manifests":
                fields(command, {"op", "after_epoch"})
                epoch = command["after_epoch"]
                if type(epoch) is not int or not 0 <= epoch < 2 ** 64:
                    raise Refusal("INVALID_REQUEST")
                return {"result": {"manifests": [item for item in self.node.history
                         if item["manifest"]["epoch"] > epoch][:8]}}
            if command["op"] == "install_freshness":
                fields(command, {"op", "envelope"})
                freshness(command["envelope"], self.node.freshness_pin, self.node.policy(), self.node.clock)
                self.node.freshness_token = command["envelope"]
                return {"result": {"epoch": self.node.policy()["epoch"]}}
            raise Refusal()


class Runtime:
    drop_next = False

    def __init__(self, node):
        self.node = node

    def permitted(self, node_id, source):
        if not isinstance(node_id, str) or node_id not in self.node.pins or source != service_address(node_id):
            raise Refusal()
        self.node.current()
        policy = self.node.policy()
        if not self.node.active or policy["nodes"][self.node.node_id] != "ACTIVE" or policy["nodes"][node_id] != "ACTIVE":
            raise Refusal()
        return policy

    def release(self, command, source):
        node = self.node
        with node.lock:
            if command["op"] == "lease_challenge":
                fields(command, {"op", "node_id"})
                self.permitted(command["node_id"], source)
                node.lease_challenges = {key: value for key, value in node.lease_challenges.items() if value["expires"] > time.monotonic()}
                if len(node.lease_challenges) >= 16:
                    raise Refusal()
                challenge, nonce = os.urandom(16).hex(), os.urandom(32).hex()
                node.lease_challenges[challenge] = {"node_id": command["node_id"], "nonce": nonce, "expires": time.monotonic() + 5}
                return {"result": {"challenge_id": challenge, "nonce": nonce}}
            if command["op"] != "renew_lease":
                raise Refusal()
            fields(command, {"op", "envelope"})
            envelope = command["envelope"]
            fields(envelope, {"payload", "signature"})
            request = envelope["payload"]
            fields(request, REQUEST_FIELDS)
            policy = self.permitted(request["node_id"], source)
            challenge_id = hex_bytes(request["challenge_id"], 16).hex()
            hex_bytes(request["nonce"], 32)
            hex_bytes(request["service_public"], 32)
            pending = node.lease_challenges.get(challenge_id)
            if (pending is None or pending["node_id"] != request["node_id"] or pending["nonce"] != request["nonce"]):
                raise Refusal()
            del node.lease_challenges[challenge_id]
            if pending["expires"] <= time.monotonic():
                raise Refusal()
            verified_token(envelope, node.pins[request["node_id"]], REQUEST_DOMAIN, REQUEST_FIELDS)
            if (type(request["version"]) is not int or request["version"] != 1
                    or type(request["epoch"]) is not int or request["epoch"] != policy["epoch"]
                    or request["cluster_id"] != policy["authorities"]["cluster_id"]
                    or request["issuer_id"] != node.node_id or request["manifest_digest"] != policy["manifest_digest"]
                    or type(request["boot_generation"]) is not int or not 0 <= request["boot_generation"] < 2 ** 64):
                raise Refusal()
            now = node.clock.now()
            payload = {key: value for key, value in request.items() if key != "nonce"}
            payload.update(not_before=now - 5, expires_at=min(now + node.lease_lifetime, node.current()["expires_at"]))
            key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(policy["signing_key"]))
            return {"result": signed_token(key, LEASE_DOMAIN, payload)}


class Service:
    drop_next = False

    def __init__(self, node):
        self.node = node

    def release(self, command, source):
        fields(command, {"op", "request_id", "message"})
        if command["op"] != "sign" or source not in [service_address(node) for node in "ABC"]:
            raise Refusal()
        hex_bytes(command["request_id"], 16)
        message = hex_bytes(command["message"], maximum=4096)
        with self.node.lock:
            self.node.ready()
            lease = self.node.lease
            statement = service_statement(self.node.node_id, command["request_id"], message, lease)
            signature = self.node.device.sign(SERVICE_DOMAIN + canonical(statement))
            self.node.ready()  # Expiry during an operation never yields an authorized response.
            return {"result": {"statement": statement, "lease": lease, "signature": signature.hex()}}


def main():
    import sys
    from peer import MAX_INPUT, parse_command
    if sys.argv[1:] == ["control"]:
        try:
            command = parse_command(sys.stdin.buffer.read(MAX_INPUT + 1))
            print(json.dumps({"result": exchange("127.0.0.1", 9444, command, timeout=60)}))
        except Refusal as error:
            print(json.dumps({"error": {"code": error.code}}))
        except Exception:
            print(json.dumps({"error": {"code": "INTERNAL"}}))
            return 1
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node", choices=list("ABC"))
    args = parser.parse_args()
    os.umask(0o077)
    key, public, runtime_public = configure(args.node, service=True)
    node = ClusterNode(args.node, key, public, runtime_public)
    servers = [BoundedServer((address(args.node), 8443), node),
               BoundedServer((service_address(args.node), 8444), node.admin,
                             route="/membership", drop_ops=("apply_manifest",)),
               BoundedServer((service_address(args.node), 8445), node.runtime, route="/lease"),
               BoundedServer((service_address(args.node), 8446), node.service, route="/kms"),
               BoundedServer(("127.0.0.1", 9444), node, local=True)]
    try:
        threading.Thread(target=node.sweep, daemon=True).start()
        for server in servers[:-1]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        servers[-1].serve_forever()
    finally:
        node.device.logout()
        for server in servers[:-1]:
            server.shutdown()
        node.tpm.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
