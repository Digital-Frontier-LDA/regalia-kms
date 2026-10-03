"""Peer access leases and client-side policy/time verification, separate from fencing."""

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from peer import Refusal, canonical, fields, hex_bytes
from tokens import verified_token, window

LEASE_DOMAIN = b"regalia-bootstrap-lab/v1/access-lease\0"
REQUEST_DOMAIN = b"regalia-bootstrap-lab/v1/lease-request\0"
SERVICE_DOMAIN = b"regalia-bootstrap-lab/v1/service-response\0"
LEASE_FIELDS = {"version", "cluster_id", "node_id", "issuer_id", "epoch", "manifest_digest",
                "boot_generation", "service_public", "challenge_id", "not_before", "expires_at"}
REQUEST_FIELDS = (LEASE_FIELDS - {"not_before", "expires_at"}) | {"nonce"}


def verify_lease(envelope, pins, policy, clock, node_id, service_public, generation=None):
    fields(envelope, {"payload", "signature"})
    body = envelope["payload"]
    fields(body, LEASE_FIELDS)
    issuer = body["issuer_id"]
    if not isinstance(issuer, str) or issuer not in pins or issuer == node_id:
        raise Refusal()
    body = verified_token(envelope, pins[issuer], LEASE_DOMAIN, LEASE_FIELDS)
    if type(body["version"]) is not int or body["version"] != 1:
        raise Refusal("INVALID_REQUEST")
    if (body["node_id"] != node_id or body["cluster_id"] != policy["authorities"]["cluster_id"]
            or type(body["epoch"]) is not int or body["epoch"] != policy["epoch"]
            or body["manifest_digest"] != policy["manifest_digest"] or body["service_public"] != service_public):
        raise Refusal()
    if type(body["boot_generation"]) is not int or not 0 <= body["boot_generation"] < 2 ** 64:
        raise Refusal("INVALID_REQUEST")
    if generation is not None and body["boot_generation"] != generation:
        raise Refusal()
    if policy["nodes"].get(node_id) != "ACTIVE" or policy["nodes"].get(issuer) != "ACTIVE":
        raise Refusal()
    for name, size in [("service_public", 32), ("manifest_digest", 32), ("challenge_id", 16), ("cluster_id", 32)]:
        hex_bytes(body[name], size)
    window(body, clock, maximum=5000)
    return body


def service_statement(node_id, request_id, message, lease):
    return {"node_id": node_id, "request_id": request_id, "message_digest": hashlib.sha256(message).hexdigest(),
            "lease_digest": hashlib.sha256(canonical(lease)).hexdigest()}


def verify_service(reply, public, pins, policy, clock, node_id, request_id, message):
    fields(reply, {"statement", "lease", "signature"})
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    verify_lease(reply["lease"], pins, policy, clock, node_id, hashlib.sha256(der).hexdigest())
    expected = service_statement(node_id, request_id, message, reply["lease"])
    if reply["statement"] != expected:
        raise Refusal()
    try:
        public.verify(hex_bytes(reply["signature"], 256), SERVICE_DOMAIN + canonical(expected),
                      padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise Refusal() from None
    return True
