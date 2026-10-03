"""Bounded local IPC and standard crypto for a disposable peer experiment."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import yaml

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

MAX_INPUT = 65536
REQUEST_FIELDS = {"node_id", "peer_id", "manifest_epoch", "boot_session_id",
                  "ephemeral_public_key", "peer_nonce", "challenge_id"}
RESPONSE_FIELDS = {"version", "peer_id", "request_digest", "ciphertext", "signature"}
NODE_STATES = {"ACTIVE", "MAINTENANCE", "DRAINING", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"}


class Refusal(Exception):
    def __init__(self, code="DENIED"):
        self.code = code


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def qualification(request):
    return hashlib.sha256(canonical(request)).digest()


def fields(value, expected):
    if not isinstance(value, dict) or set(value) != expected:
        raise Refusal("INVALID_REQUEST")


def hex_bytes(value, size=None, maximum=4096):
    if not isinstance(value, str) or not value or len(value) > maximum * 2 or len(value) % 2:
        raise Refusal("INVALID_REQUEST")
    if re.fullmatch("[0-9a-f]+", value) is None:
        raise Refusal("INVALID_REQUEST")
    data = bytes.fromhex(value)
    if size is not None and len(data) != size:
        raise Refusal("INVALID_REQUEST")
    return data


def oaep(digest):
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
                        label=b"regalia-bootstrap-lab/v1/contribution\0" + digest)


def signed_response(private, recipient, request, secret):
    digest = qualification(request)
    response = {"version": 1, "peer_id": request["peer_id"], "request_digest": digest.hex(),
                "ciphertext": recipient.encrypt(secret, oaep(digest)).hex()}
    response["signature"] = private.sign(b"regalia-bootstrap-lab/v1/response\0" + canonical(response)).hex()
    return response


class BootSession:
    def __init__(self, pins, node_id="A"):
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        self.pins = pins
        self.requests = {}
        self.consumed = False
        self.node_id = node_id

    def request(self, challenge, session_id):
        fields(challenge, {"peer_id", "peer_nonce", "manifest_epoch", "challenge_id"})
        public = self.private.public_key().public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo)
        request = dict(challenge, node_id=self.node_id, boot_session_id=session_id,
                       ephemeral_public_key=public.hex())
        self.requests[request["peer_id"]] = request
        return request

    def open(self, response):
        fields(response, RESPONSE_FIELDS)
        peer_id = response["peer_id"]
        if self.consumed or type(response["version"]) is not int or response["version"] != 1:
            raise Refusal()
        if not isinstance(peer_id, str) or peer_id not in self.pins or peer_id not in self.requests:
            raise Refusal()
        digest = qualification(self.requests[peer_id])
        if hex_bytes(response["request_digest"], 32) != digest:
            raise Refusal()
        unsigned = {key: value for key, value in response.items() if key != "signature"}
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(self.pins[peer_id]).verify(
                hex_bytes(response["signature"], 64), b"regalia-bootstrap-lab/v1/response\0" + canonical(unsigned))
            secret = self.private.decrypt(hex_bytes(response["ciphertext"], 384), oaep(digest))
        except (InvalidSignature, ValueError):
            raise Refusal() from None
        if len(secret) != 32:
            raise Refusal()
        self.consumed = True
        return secret


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("INVALID_REQUEST")
        result[key] = value
    return result


def parse_command(raw):
    if len(raw) > MAX_INPUT:
        raise Refusal("INVALID_REQUEST")
    try:
        command = json.loads(raw, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise Refusal("INVALID_REQUEST") from None
    if not isinstance(command, dict) or not isinstance(command.get("op"), str):
        raise Refusal("INVALID_REQUEST")
    return command


def persist(path, state):
    temporary = path.with_suffix(".next")
    with temporary.open("wb") as output:
        output.write(canonical(state))
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def permitted(state, node_id):
    nodes = state["nodes"]
    if "authorities" in state and state["manifest"] is None:
        raise Refusal()
    if node_id not in state["targets"] or nodes.get(node_id) not in ["ACTIVE", "MAINTENANCE"]:
        raise Refusal()
    if nodes.get(state["peer_id"]) != "ACTIVE":
        raise Refusal()


def commission(command, path):
    expected = {"op", "peer_id", "targets"}
    if "authorities" in command:
        expected.add("authorities")
    fields(command, expected)
    if path.exists() or command["peer_id"] not in ["A", "B", "C"]:
        raise Refusal()
    targets = command["targets"]
    if not isinstance(targets, dict) or not targets or not set(targets) <= {"A", "B", "C"}:
        raise Refusal("INVALID_REQUEST")
    if command["peer_id"] in targets:
        raise Refusal("INVALID_REQUEST")
    for target in targets.values():
        fields(target, {"ak_pem", "approved_pcr"})
        if not isinstance(target["ak_pem"], str) or len(target["ak_pem"]) > 2048:
            raise Refusal("INVALID_REQUEST")
        try:
            ak = serialization.load_pem_public_key(target["ak_pem"].encode())
        except ValueError:
            raise Refusal("INVALID_REQUEST") from None
        if not isinstance(ak, rsa.RSAPublicKey) or ak.key_size < 2048:
            raise Refusal("INVALID_REQUEST")
        hex_bytes(target["approved_pcr"], 32)
    signing = ed25519.Ed25519PrivateKey.generate()
    state = {"peer_id": command["peer_id"], "epoch": 1, "nodes": {"A": "ACTIVE", "B": "ACTIVE", "C": "ACTIVE"},
             "targets": targets, "pending": {}, "signing_key": signing.private_bytes_raw().hex(),
             "contributions": {node: os.urandom(32).hex() for node in targets}}
    if "authorities" in command:
        pins = command["authorities"]
        fields(pins, {"cluster_id", "membership_root", "revocation"})
        for value in pins.values():
            hex_bytes(value, 32)
        if pins["membership_root"] == pins["revocation"]:
            raise Refusal("INVALID_REQUEST")
        state.update(authorities=pins, epoch=0, manifest=None, manifest_digest="00" * 32)
    persist(path, state)
    return {"peer_public_key": signing.public_key().public_bytes_raw().hex()}


def ak_digest(pem):
    key = serialization.load_pem_public_key(pem.encode())
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def apply_manifest(command, state, path):
    fields(command, {"op", "envelope"})
    envelope = command["envelope"]
    fields(envelope, {"authority", "manifest", "signature"})
    authority = envelope["authority"]
    if not isinstance(authority, str) or authority not in ["membership_root", "revocation"]:
        raise Refusal("INVALID_REQUEST")
    if "authorities" not in state:
        raise Refusal()
    manifest = envelope["manifest"]
    fields(manifest, {"version", "cluster_id", "epoch", "previous_digest", "nodes"})
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise Refusal("INVALID_REQUEST")
    if type(manifest["epoch"]) is not int or not 0 < manifest["epoch"] < 2 ** 64:
        raise Refusal("INVALID_REQUEST")
    hex_bytes(manifest["cluster_id"], 32)
    hex_bytes(manifest["previous_digest"], 32)
    fields(manifest["nodes"], {"A", "B", "C"})
    for node in manifest["nodes"].values():
        fields(node, {"state", "ak_sha256", "approved_pcr"})
        if not isinstance(node["state"], str) or node["state"] not in NODE_STATES:
            raise Refusal("INVALID_REQUEST")
        hex_bytes(node["ak_sha256"], 32)
        hex_bytes(node["approved_pcr"], 32)
    signature = hex_bytes(envelope["signature"], 64)
    signed = {"authority": authority, "manifest": manifest}
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(state["authorities"][authority])).verify(
            signature, b"regalia-bootstrap-lab/v1/membership\0" + canonical(signed))
    except InvalidSignature:
        raise Refusal() from None
    if manifest["cluster_id"] != state["authorities"]["cluster_id"]:
        raise Refusal()
    digest = hashlib.sha256(canonical(manifest)).hexdigest()
    result = {"epoch": manifest["epoch"], "manifest_digest": digest}
    if manifest["epoch"] == state["epoch"] and digest == state["manifest_digest"]:
        return result
    if (manifest["epoch"] != state["epoch"] + 1
            or manifest["previous_digest"] != state["manifest_digest"]):
        raise Refusal()
    for name, enrolled in state["targets"].items():
        if manifest["nodes"][name]["ak_sha256"] != ak_digest(enrolled["ak_pem"]):
            raise Refusal()
    if authority == "revocation":
        previous = state["manifest"]
        if previous is None:
            raise Refusal()
        changed = False
        for name, node in manifest["nodes"].items():
            old = previous["nodes"][name]
            if node["ak_sha256"] != old["ak_sha256"] or node["approved_pcr"] != old["approved_pcr"]:
                raise Refusal()
            if node["state"] != old["state"]:
                if (old["state"] in {"RETIRED", "REVOKED_STOLEN"}
                        or node["state"] not in {"QUARANTINED", "RETIRED", "REVOKED_STOLEN"}):
                    raise Refusal()
                changed = True
        if not changed:
            raise Refusal()
    state.update(epoch=manifest["epoch"], manifest=manifest, manifest_digest=digest, pending={},
                 nodes={name: node["state"] for name, node in manifest["nodes"].items()})
    for name, enrolled in state["targets"].items():
        enrolled["approved_pcr"] = manifest["nodes"][name]["approved_pcr"]
    persist(path, state)
    return result


def checked_request(request):
    fields(request, REQUEST_FIELDS)
    if (request["node_id"] not in ["A", "B", "C"] or request["peer_id"] not in ["A", "B", "C"]
            or request["node_id"] == request["peer_id"]):
        raise Refusal()
    if type(request["manifest_epoch"]) is not int or not 0 < request["manifest_epoch"] < 2 ** 64:
        raise Refusal("INVALID_REQUEST")
    for field, size in [("boot_session_id", 16), ("challenge_id", 16), ("peer_nonce", 32)]:
        hex_bytes(request[field], size)
    try:
        key = serialization.load_der_public_key(hex_bytes(request["ephemeral_public_key"], maximum=1024))
    except ValueError:
        raise Refusal("INVALID_REQUEST") from None
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 3072 or key.public_numbers().e != 65537:
        raise Refusal("INVALID_REQUEST")
    return key


def verify_attestation(state, request, command):
    enrolled = state["targets"][request["node_id"]]
    with tempfile.TemporaryDirectory(prefix="regalia-verifier-") as directory:
        root = Path(directory)
        message, signature, public, pcr = [root / name for name in ["quote", "signature", "ak.pem", "pcr"]]
        message.write_bytes(hex_bytes(command["quote"], maximum=4096))
        signature.write_bytes(hex_bytes(command["signature"], maximum=1024))
        public.write_text(enrolled["ak_pem"])
        pcr.write_bytes(bytes.fromhex(enrolled["approved_pcr"]))
        result = subprocess.run([
            "tpm2_checkquote", "-u", str(public), "-m", str(message), "-s", str(signature),
            "-f", str(pcr), "-l", "sha256:7", "-g", "sha256", "-q", qualification(request).hex(),
        ], env=dict(os.environ, TPM2TOOLS_TCTI="none"), capture_output=True, timeout=10)
        if result.returncode == 1:
            raise Refusal()
        if result.returncode != 0:
            raise RuntimeError("quote verifier failed")
        decoded = subprocess.run(["tpm2_print", "-t", "TPMS_ATTEST", str(message)],
                                 capture_output=True, timeout=10)
        if decoded.returncode != 0 or len(decoded.stdout) > 16384:
            raise Refusal()
        # Use the established TPM decoder, not a custom binary TPM parser.
        # BaseLoader retains hex-looking scalars and leading zeroes as strings.
        attestation = yaml.load(decoded.stdout, Loader=yaml.BaseLoader)
        expected = {"count": "1", "pcrSelections": {"0": {
            "hash": "11 (sha256)", "sizeofSelect": "3", "pcrSelect": "800000"}}}
        if (attestation.get("magic") != "ff544347" or attestation.get("type") != "8018"
                or attestation.get("attested", {}).get("quote", {}).get("pcrSelect") != expected):
            raise Refusal()


def execute(command, path):
    if command["op"] == "init":
        return commission(command, path)
    if command["op"] not in ["challenge", "authorize", "apply_manifest"]:
        raise Refusal("INVALID_REQUEST")
    state = json.loads(path.read_bytes())
    if command["op"] == "apply_manifest":
        return apply_manifest(command, state, path)
    now = time.monotonic()
    if command["op"] == "challenge":
        fields(command, {"op", "node_id"})
        permitted(state, command["node_id"])
        state["pending"] = {key: value for key, value in state["pending"].items() if value["expires"] > now}
        if len(state["pending"]) >= 16:
            raise Refusal()
        challenge_id, nonce = os.urandom(16).hex(), os.urandom(32).hex()
        state["pending"][challenge_id] = {"node_id": command["node_id"], "nonce": nonce, "expires": now + 30}
        persist(path, state)
        return {"peer_id": state["peer_id"], "manifest_epoch": state["epoch"],
                "challenge_id": challenge_id, "peer_nonce": nonce}
    fields(command, {"op", "request", "quote", "signature"})
    request = command["request"]
    recipient = checked_request(request)
    permitted(state, request["node_id"])
    if request["peer_id"] != state["peer_id"] or request["manifest_epoch"] != state["epoch"]:
        raise Refusal()
    pending = state["pending"].get(request["challenge_id"])
    if pending is None or pending["node_id"] != request["node_id"] or pending["nonce"] != request["peer_nonce"]:
        raise Refusal()
    # Burn an owned challenge before expensive work, even if verification fails.
    del state["pending"][request["challenge_id"]]
    persist(path, state)
    if pending["expires"] <= now:
        raise Refusal()
    verify_attestation(state, request, command)
    signing = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(state["signing_key"]))
    return signed_response(signing, recipient, request, bytes.fromhex(state["contributions"][request["node_id"]]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        command = parse_command(sys.stdin.buffer.read(MAX_INPUT + 1))
        with args.state.with_suffix(".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            result = execute(command, args.state)
        print(json.dumps({"result": result}))
    except Refusal as error:
        print(json.dumps({"error": {"code": error.code}}))
    except Exception:
        # Internal details and captured subprocess output may contain secrets.
        print(json.dumps({"error": {"code": "INTERNAL"}}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
