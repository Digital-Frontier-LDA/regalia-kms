"""Standard signatures and explicit trusted-time windows for software experiments."""

import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from peer import Refusal, canonical, fields, hex_bytes

MAX_WINDOW_MS = 30000


class Clock:
    def __init__(self):
        self.offset = 0
        self.reset()

    def reset(self):
        self.wall = int(time.time() * 1000) + self.offset
        self.monotonic = time.monotonic()
        self.failed = False

    def now(self):
        wall = int(time.time() * 1000) + self.offset
        expected = self.wall + int((time.monotonic() - self.monotonic) * 1000)
        if abs(wall - expected) > 2000:
            self.failed = True
        if self.failed:
            raise Refusal()
        return wall


def signed_token(key, domain, payload):
    return {"payload": payload, "signature": key.sign(domain + canonical(payload)).hex()}


def verified_token(envelope, pin, domain, expected_fields):
    fields(envelope, {"payload", "signature"})
    payload = envelope["payload"]
    fields(payload, expected_fields)
    signature = hex_bytes(envelope["signature"], 64)
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pin).verify(signature, domain + canonical(payload))
    except InvalidSignature:
        raise Refusal() from None
    return payload


def window(payload, clock, maximum=MAX_WINDOW_MS):
    start, end = payload["not_before"], payload["expires_at"]
    if type(start) is not int or type(end) is not int or not 0 <= start < end < 2 ** 63:
        raise Refusal("INVALID_REQUEST")
    if end - start > maximum:
        raise Refusal()
    if not start <= clock.now() < end:
        raise Refusal()


FRESHNESS_DOMAIN = b"regalia-bootstrap-lab/v1/freshness\0"
FRESHNESS_FIELDS = {"version", "cluster_id", "epoch", "manifest_digest", "not_before", "expires_at"}


def freshness(envelope, pin, policy, clock):
    payload = verified_token(envelope, pin, FRESHNESS_DOMAIN, FRESHNESS_FIELDS)
    if type(payload["version"]) is not int or payload["version"] != 1:
        raise Refusal("INVALID_REQUEST")
    if type(payload["epoch"]) is not int or payload["epoch"] != policy["epoch"]:
        raise Refusal()
    hex_bytes(payload["cluster_id"], 32)
    hex_bytes(payload["manifest_digest"], 32)
    if (payload["cluster_id"] != policy["authorities"]["cluster_id"]
            or payload["manifest_digest"] != policy["manifest_digest"]):
        raise Refusal()
    window(payload, clock)
    return payload
