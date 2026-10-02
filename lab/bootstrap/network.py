"""Disposable WireGuard mesh node and private fixture control client."""

import argparse
import http.client
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from lab import TPM, derive_credential, run, tpm_refused
from peer import BootSession, MAX_INPUT, Refusal, canonical, hex_bytes, parse_command, qualification

NODES = {node: index for index, node in enumerate("ABC", 1)}


def address(node, plane="wg"):
    return f"10.77.91.{NODES[node]}" if plane == "wg" else f"10.89.91.{NODES[node]}"


def exchange(host, port, command, timeout=4, route="/bootstrap"):
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.request("POST", route, body=canonical(command),
                           headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT or response.status != 200:
            raise Refusal()
        result = parse_command_response(raw)
        if set(result) == {"error"}:
            error = result["error"]
            if isinstance(error, dict) and error.get("code") in ["DENIED", "INVALID_REQUEST"]:
                raise Refusal(error["code"])
            raise RuntimeError("remote endpoint failed")
        if set(result) != {"result"}:
            raise Refusal()
        return result["result"]
    finally:
        connection.close()


def parse_command_response(raw):
    from peer import unique_object
    result = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(result, dict):
        raise Refusal()
    return result


def configure(node, service=False):
    """Only the startup process configures its own container namespace."""
    key = run("wg", "genkey").stdout
    public = run("wg", "pubkey", data=key).stdout.decode().strip()
    key_file = Path("/tmp/wg-commissioning.key")
    key_file.write_bytes(key)
    try:
        run("ip", "link", "add", "wg-bootstrap", "type", "wireguard")
        run("ip", "address", "add", address(node) + "/24", "dev", "wg-bootstrap")
        run("wg", "set", "wg-bootstrap", "listen-port", "51820", "private-key", key_file)
        run("ip", "link", "set", "wg-bootstrap", "up")
    finally:
        key_file.unlink(missing_ok=True)
    service_public = None
    if service:
        service_key = run("wg", "genkey").stdout
        service_public = run("wg", "pubkey", data=service_key).stdout.decode().strip()
        key_file.write_bytes(service_key)
        try:
            run("ip", "link", "add", "wg-service", "type", "wireguard")
            run("ip", "address", "add", f"10.78.91.{NODES[node]}/24", "dev", "wg-service")
            run("wg", "set", "wg-service", "listen-port", "51821", "private-key", key_file)
            run("ip", "link", "set", "wg-service", "up")
        finally:
            key_file.unlink(missing_ok=True)
    rules = b'''table inet lab {
      chain input { type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        iifname "eth0" ip saddr 10.89.91.0/24 udp dport 51820 accept
        iifname "wg-bootstrap" ip saddr 10.77.91.0/24 tcp dport 8443 accept
      }
      chain output { type filter hook output priority 0; policy drop;
        oifname "lo" accept
        ct state established,related accept
        oifname "eth0" ip daddr 10.89.91.0/24 udp dport 51820 accept
        oifname "wg-bootstrap" ip daddr 10.77.91.0/24 tcp dport 8443 accept
      }
      chain forward { type filter hook forward priority 0; policy drop; }
    }'''
    if service:
        rules = rules.replace(b"udp dport 51820", b"udp dport {51820,51821}")
        for direction, subnet in [(b"iifname", b"saddr"), (b"oifname", b"daddr")]:
            original = direction + b' "wg-bootstrap" ip ' + subnet + b" 10.77.91.0/24 tcp dport 8443 accept"
            extra = direction + b' "wg-service" ip ' + subnet + b" 10.78.91.0/24 tcp dport {8444,8445,8446} accept"
            rules = rules.replace(original, original + b"\n        " + extra)
    run("nft", "-f", "-", data=rules)
    os.setgroups([])
    os.setgid(10000)
    os.setuid(10000)
    return (key, public, service_public) if service else (key, public)


class Node:
    def __init__(self, node_id, key, public):
        self.node_id, self.public = node_id, public
        self.root = Path("/tmp/node")
        self.root.mkdir(mode=0o700)
        self.tpm = TPM(self.root, node_id)
        self.tpm.start()
        self.tpm.prepare_storage()
        self.tpm.seal("wg", key, "0x81010004")
        self.tpm.seal("local", os.urandom(32), "0x81010005")
        self.state = self.root / "peer.json"
        self.disk = self.root / "disk.luks"
        self.pins = {}
        self.active = True  # Trusted commissioning starts healthy peers.
        self.lock = threading.RLock()
        self.boot_lock = threading.Lock()
        self.drop_next = False
        self.generation = 0
        self.guest_material = None

    def worker(self, command):
        result = subprocess.run(["python3", "/opt/peer.py", "--state", str(self.state)],
                                input=canonical(command), capture_output=True, timeout=25)
        if result.returncode:
            raise RuntimeError("peer worker failed")
        return parse_command_response(result.stdout)

    def identity(self):
        caps = [line.split()[1] for line in Path("/proc/self/status").read_text().splitlines()
                if line.startswith("CapEff:")][0]
        return {"node_id": self.node_id, "wg_public": self.public, "uid": os.getuid(), "caps": caps,
                "ak_pem": (self.tpm.root / "ak.pem").read_text(),
                "approved_pcr": (self.tpm.root / "approved.pcr").read_bytes().hex()}

    def release(self, command, source):
        if command.get("op") not in ["challenge", "authorize"]:
            raise Refusal()
        request = command.get("request", {}) if command["op"] == "authorize" else command
        if not isinstance(request, dict):
            raise Refusal("INVALID_REQUEST")
        node_id = request.get("node_id")
        if not isinstance(node_id, str) or node_id not in NODES:
            raise Refusal("INVALID_REQUEST")
        if source != address(node_id):
            raise Refusal()
        with self.lock:
            if not self.active:
                raise Refusal()
            return self.worker(command)

    def grant(self, peer_id, session, session_id):
        challenge = exchange(address(peer_id), 8443, {"op": "challenge", "node_id": self.node_id})
        with self.lock:
            policy = json.loads(self.state.read_bytes())
            if policy["nodes"].get(peer_id) != "ACTIVE" or challenge.get("manifest_epoch") != policy["epoch"]:
                raise Refusal()
        request = session.request(challenge, session_id)
        quote = self.tpm.quote(qualification(request), "mesh-" + request["challenge_id"])
        try:
            return exchange(address(peer_id), 8443, {"op": "authorize", "request": request,
                            "quote": quote[0].read_bytes().hex(), "signature": quote[1].read_bytes().hex()})
        finally:
            for file in quote:
                file.unlink(missing_ok=True)

    def accepts(self, key):
        result = run("cryptsetup", "open", "--type", "luks2", "--test-passphrase",
                     "--key-file", "-", self.disk, data=key, required=False)
        if result.returncode not in [0, 2]:
            raise RuntimeError("LUKS check failed")
        return result.returncode == 0

    def prepare_disk(self):
        local = self.tpm.unseal("0x81010005")
        if local.returncode:
            raise Refusal()
        keys = []
        for peer_id in sorted(self.pins):
            session = BootSession(self.pins, self.node_id)
            grant = self.grant(peer_id, session, os.urandom(16).hex())
            keys.append(derive_credential(local.stdout, session.open(grant), peer_id, self.node_id))
        with self.disk.open("wb") as disk:
            disk.truncate(64 * 1024 * 1024)
        pbkdf = ["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"]
        run("cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", *pbkdf,
            "--key-file", "-", self.disk, data=keys[0])
        recovery = os.urandom(64)
        temporary = self.root / "existing.key"
        temporary.write_bytes(keys[0])
        try:
            for key in [keys[1], recovery]:
                run("cryptsetup", "luksAddKey", *pbkdf, "--key-file", temporary,
                    "--new-keyfile", "-", self.disk, data=key)
        finally:
            temporary.unlink(missing_ok=True)
        return {"recovery_key": recovery.hex()}

    def bootstrap(self, peers):
        if not isinstance(peers, list) or not peers or len(peers) != len(set(peers)) or not set(peers) <= set(self.pins):
            raise Refusal("INVALID_REQUEST")
        with self.boot_lock:
            with self.lock:
                self.active = False
                self.generation += 1
                generation = self.generation
                policy = json.loads(self.state.read_bytes())
                if policy["nodes"].get(self.node_id) not in ["ACTIVE", "MAINTENANCE"]:
                    return {"active": False, "reason": "membership"}
                peers = [peer for peer in peers if policy["nodes"].get(peer) == "ACTIVE"]
                if not peers:
                    return {"active": False, "reason": "no_valid_peer"}
            local = self.tpm.unseal("0x81010005")
            wg = self.tpm.unseal("0x81010004")
            if local.returncode or wg.returncode:
                for result in [local, wg]:
                    if result.returncode:
                        tpm_refused(result, 0x99D)
                return {"active": False, "reason": "local_policy"}
            if run("wg", "pubkey", data=wg.stdout).stdout.decode().strip() != self.public:
                raise RuntimeError("sealed network identity mismatch")
            session = BootSession(self.pins, self.node_id)
            session_id = os.urandom(16).hex()
            pool = ThreadPoolExecutor(max_workers=len(peers))
            attempts = {pool.submit(self.grant, peer, session, session_id): peer for peer in peers}
            try:
                for future in as_completed(attempts):
                    peer_id = attempts[future]
                    try:
                        contribution = session.open(future.result())
                        credential = derive_credential(local.stdout, contribution, peer_id, self.node_id)
                        if not self.accepts(credential):
                            raise Refusal()
                    except (Refusal, OSError, http.client.HTTPException, TimeoutError):
                        continue
                    with self.lock:
                        if self.generation != generation:
                            return {"active": False, "reason": "cancelled"}
                        self.active = True
                    return {"active": True, "via": peer_id}
                return {"active": False, "reason": "no_valid_peer"}
            finally:
                pool.shutdown(wait=False, cancel_futures=True)

    def control(self, command):
        op = command["op"]
        if op == "identity":
            return self.identity()
        if op == "status":
            return {"active": self.active, "generation": self.generation}
        if op == "enroll":
            return self.worker({"op": "init", "peer_id": self.node_id, "targets": command["targets"]})["result"]
        if op == "pins":
            self.pins = {node: hex_bytes(key, 32) for node, key in command["pins"].items()}
            return {}
        if op == "disk":
            return self.prepare_disk()
        if op == "bootstrap":
            return self.bootstrap(command["peers"])
        if op == "lock":
            with self.lock:
                self.generation += 1
                self.active = False
            return {"active": False}
        if op == "manual":
            key = hex_bytes(command["key"], 64)
            with self.lock:
                if json.loads(self.state.read_bytes())["nodes"].get(self.node_id) not in ["ACTIVE", "MAINTENANCE"]:
                    raise Refusal()
                if self.accepts(key):
                    self.generation += 1
                    self.active = True
                    return {"active": True, "manual": True}
            return {"active": False, "reason": "wrong_recovery_key"}
        if op == "policy":
            with self.lock:
                state = json.loads(self.state.read_bytes())
                state["nodes"] = command["nodes"]
                state["epoch"] = command.get("epoch", state["epoch"])
                from peer import persist
                persist(self.state, state)
                self.generation += 1
                if state["nodes"].get(self.node_id) not in ["ACTIVE", "MAINTENANCE"]:
                    self.active = False
            return {}
        if op == "drop_response":
            self.drop_next = True
            return {}
        if op == "extend_pcr":
            self.tpm.call("tpm2_pcrextend", "7:sha256=" + os.urandom(32).hex())
            return {}
        if op == "guest_prepare":
            self.guest_material = [self.tpm.unseal(handle).stdout for handle in ["0x81010004", "0x81010005"]]
            if [len(value) for value in self.guest_material] != [45, 32]:
                raise RuntimeError("guest commissioning material unavailable")
            return {}
        if op == "tpm_restart":
            self.tpm.restart()
            return {}
        if op == "guest_rebind":
            pcr = hex_bytes(command["pcr7"], 32)
            expected = self.tpm.root / "guest-approved.pcr"
            expected.write_bytes(pcr)
            self.tpm.call("tpm2_createpolicy", "--policy-pcr", "-l", "sha256:7", "-f", expected,
                          "-L", self.tpm.root / "pcr.policy", "-Q")
            for name, value, handle in zip(["wg", "local"], self.guest_material, ["0x81010004", "0x81010005"]):
                self.tpm.call("tpm2_evictcontrol", "-C", "o", "-c", handle, "-Q")
                self.tpm.seal(name, value, handle)
            self.guest_material = None
            return {}
        if op == "guest_approve":
            with self.lock:
                state = json.loads(self.state.read_bytes())
                state["targets"]["A"]["approved_pcr"] = hex_bytes(command["pcr7"], 32).hex()
                from peer import persist
                persist(self.state, state)
            return {}
        raise Refusal("INVALID_REQUEST")


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, endpoint, node, local=False, route="/bootstrap", drop_ops=("authorize",)):
        self.node, self.local = node, local
        self.route, self.drop_ops = route, drop_ops
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(endpoint, Handler)

    def get_request(self):
        socket, source = super().get_request()
        socket.settimeout(3)
        return socket, source

    def process_request(self, request, source):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, source)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, source):
        try:
            super().process_request_thread(request, source)
        finally:
            self.slots.release()

    def handle_error(self, request, source):
        pass  # Do not log exception/tool details from client-controlled requests.


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.path != self.server.route or len(lengths) != 1 or self.headers.get("Transfer-Encoding"):
                raise Refusal("INVALID_REQUEST")
            size = int(lengths[0])
            if not 0 < size <= MAX_INPUT:
                raise Refusal("INVALID_REQUEST")
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise Refusal("INVALID_REQUEST")
            command = parse_command(raw)
            if self.server.local:
                result = {"result": self.server.node.control(command)}
            else:
                result = self.server.node.release(command, self.client_address[0])
                if command["op"] in self.server.drop_ops and "result" in result and self.server.node.drop_next:
                    self.server.node.drop_next = False
                    self.close_connection = True
                    return
        except Refusal as error:
            result = {"error": {"code": error.code}}
        except (ValueError, OSError, TimeoutError):
            result = {"error": {"code": "INVALID_REQUEST"}}
        except Exception:
            result = {"error": {"code": "INTERNAL"}}
        body = canonical(result)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    if sys.argv[1:] == ["control"]:
        command = parse_command(sys.stdin.buffer.read(MAX_INPUT + 1))
        print(json.dumps({"result": exchange("127.0.0.1", 9444, command, timeout=60)}))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node", choices=NODES)
    args = parser.parse_args()
    os.umask(0o077)
    key, public = configure(args.node)
    node = Node(args.node, key, public)
    del key
    bootstrap = BoundedServer((address(args.node), 8443), node)
    local = BoundedServer(("127.0.0.1", 9444), node, local=True)
    threading.Thread(target=bootstrap.serve_forever, daemon=True).start()
    print(f"READY {args.node}: unprivileged WireGuard bootstrap service", flush=True)
    try:
        local.serve_forever()
    finally:
        bootstrap.shutdown()
        node.tpm.close()


if __name__ == "__main__":
    main()
