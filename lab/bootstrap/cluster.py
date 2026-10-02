"""Disposable signed-policy cluster; local fixture controls never cross the mesh."""

import argparse
import hashlib
import http.client
import json
import os
import threading
from pathlib import Path

from network import BoundedServer, Node, address, configure, exchange
from peer import Refusal, canonical, fields, hex_bytes
from tokens import Clock, freshness


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

    def control(self, command):
        op = command["op"]
        if op == "enroll":
            fields(command, {"op", "targets", "authorities", "freshness_public"})
            self.freshness_pin = hex_bytes(command["freshness_public"], 32)
            return self.worker({"op": "init", "peer_id": self.node_id,
                                "targets": command["targets"], "authorities": command["authorities"]})["result"]
        if op == "identity":
            return dict(super().identity(), service_wg_public=self.service_public)
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
        if op == "status":
            try:
                self.current()
                fresh = True
            except Refusal:
                fresh = False
            policy = self.policy()
            return dict(super().control(command), fresh=fresh, epoch=policy["epoch"],
                        manifest_digest=policy["manifest_digest"], nodes=policy["nodes"])
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
               BoundedServer(("127.0.0.1", 9444), node, local=True)]
    try:
        for server in servers[:-1]:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        servers[-1].serve_forever()
    finally:
        for server in servers[:-1]:
            server.shutdown()
        node.tpm.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
