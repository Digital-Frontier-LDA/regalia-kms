"""Cross-process peer authorization scenarios for the software bootstrap lab."""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from peer import BootSession, Refusal, canonical, oaep, qualification, signed_response


class Peer:
    def __init__(self, root, peer_id, target, authorities=None):
        self.state = root / f"peer-{peer_id}.json"
        self.peer_id = peer_id
        command = {"op": "init", "peer_id": peer_id,
                   "targets": {"A": {"ak_pem": (target.root / "ak.pem").read_text(),
                                     "approved_pcr": (target.root / "approved.pcr").read_bytes().hex()}}}
        if authorities is not None:
            command["authorities"] = authorities
        result = self.invoke(command)
        self.pin = bytes.fromhex(result["result"]["peer_public_key"])

    def invoke(self, command=None, raw=None):
        result = subprocess.run([sys.executable, "/opt/peer.py", "--state", str(self.state)],
                                input=canonical(command) if raw is None else raw,
                                capture_output=True, timeout=30)
        if result.returncode != 0:
            raise RuntimeError("peer subprocess failed")
        response = json.loads(result.stdout)
        if not isinstance(response, dict) or set(response) not in [{"result"}, {"error"}]:
            raise RuntimeError("invalid peer response")
        return response

    def fixture_update(self, **changes):
        state = json.loads(self.state.read_bytes())
        state.update(changes)
        self.state.write_bytes(canonical(state))

    def challenge(self):
        return self.invoke({"op": "challenge", "node_id": "A"})["result"]


def refused(function):
    try:
        function()
    except Refusal:
        return True
    return False


def flipped(value):
    data = bytearray.fromhex(value)
    data[-1] ^= 1
    return data.hex()


def peer_cases(root, target, other, verifier):
    peers = {name: Peer(root, name, target) for name in ["B", "C"]}
    pins = {name: peer.pin for name, peer in peers.items()}
    cases, granted = [], {}

    def authorization(peer, session=None, signer=None, selection="sha256:7"):
        session = session or BootSession(pins)
        request = session.request(peer.challenge(), os.urandom(16).hex())
        quote = (signer or target).quote(qualification(request), "grant-" + request["challenge_id"], selection)
        command = {"op": "authorize", "request": request,
                   "quote": quote[0].read_bytes().hex(), "signature": quote[1].read_bytes().hex()}
        return session, command, quote

    def denied(peer, command):
        return peer.invoke(command) == {"error": {"code": "DENIED"}}

    for name, peer in peers.items():
        session, command, _ = authorization(peer)
        envelope = peer.invoke(command)["result"]
        secret = session.open(envelope)
        granted[name] = secret
        cases.extend([
            (f"verifier {name} releases a signed session-encrypted contribution", len(secret) == 32),
            (f"verifier {name} rejects a consumed challenge", denied(peer, command)),
            (f"target rejects duplicate {name} response consumption", refused(lambda: session.open(envelope))),
        ])

    peer = peers["B"]
    session, command, _ = authorization(peer)
    envelope = peer.invoke(command)["result"]
    for field in ["ciphertext", "signature", "request_digest"]:
        altered = dict(envelope, **{field: flipped(envelope[field])})
        cases.append((f"target rejects altered response {field}", refused(lambda: session.open(altered))))
    cases.append(("target rejects substituted authorizer", refused(lambda: session.open(dict(envelope, peer_id="C")))))
    forged = signed_response(ed25519.Ed25519PrivateKey.generate(), session.private.public_key(), command["request"], os.urandom(32))
    cases.append(("target rejects an unregistered peer signing key", refused(lambda: session.open(forged))))
    try:
        rsa.generate_private_key(public_exponent=65537, key_size=3072).decrypt(
            bytes.fromhex(envelope["ciphertext"]), oaep(qualification(command["request"])))
        wrong_recipient_rejected = False
    except ValueError:
        wrong_recipient_rejected = True
    cases.append(("another boot private key cannot decrypt the contribution", wrong_recipient_rejected))
    cases.append(("invalid responses preserve the valid pending session", session.open(envelope) == granted["B"]))

    next_session, fresh, _ = authorization(peer)
    replay = dict(fresh, quote=command["quote"], signature=command["signature"])
    cases.append(("verifier rejects an old quote in a fresh challenge", denied(peer, replay)))
    cases.append(("target rejects an old response in a new boot session", refused(lambda: next_session.open(envelope))))

    both = BootSession(pins)
    _, b_command, _ = authorization(peers["B"], both)
    _, c_command, _ = authorization(peers["C"], both)
    b_response = peers["B"].invoke(b_command)["result"]
    c_response = peers["C"].invoke(c_command)["result"]
    both.open(b_response)
    cases.append(("first valid response prevents consuming a later peer response", refused(lambda: both.open(c_response))))

    _, wrong_ak, _ = authorization(peer, signer=other)
    cases.append(("verifier rejects a quote from a different TPM", denied(peer, wrong_ak)))
    _, wrong_selection, quote = authorization(peer, selection="sha256:0")
    # The two initial software PCRs are both zero: a digest check alone is insufficient.
    authentic = verifier(target.root / "ak.pem", quote, qualification(wrong_selection["request"]),
                         target.root / "approved.pcr", selection="sha256:0")
    cases.append(("verifier checks PCR selection even when raw PCR digest matches", authentic and denied(peer, wrong_selection)))
    for field in ["quote", "signature"]:
        _, command, _ = authorization(peer)
        command[field] = flipped(command[field])
        cases.append((f"verifier rejects tampered authorization {field}", denied(peer, command)))

    _, old_epoch, _ = authorization(peer)
    peer.fixture_update(epoch=2)
    cases.append(("verifier rejects a request after its policy epoch advances", denied(peer, old_epoch)))
    peer.fixture_update(epoch=1)
    _, expired, _ = authorization(peer)
    state = json.loads(peer.state.read_bytes())
    state["pending"][expired["request"]["challenge_id"]]["expires"] = 0
    peer.fixture_update(pending=state["pending"])
    cases.append(("verifier refuses an expired challenge", denied(peer, expired)))

    for state in ["DRAINING", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"]:
        _, command, _ = authorization(peer)
        peer.fixture_update(nodes={"A": state, "B": "ACTIVE", "C": "ACTIVE"})
        cases.append((f"verifier denies requester state {state}", denied(peer, command)))
        peer.fixture_update(nodes={"A": "ACTIVE", "B": "ACTIVE", "C": "ACTIVE"})
    peer.fixture_update(nodes={"A": "MAINTENANCE", "B": "ACTIVE", "C": "ACTIVE"})
    maintenance, command, _ = authorization(peer)
    cases.append(("MAINTENANCE requester may receive bootstrap", maintenance.open(peer.invoke(command)["result"]) == granted["B"]))
    peer.fixture_update(nodes={"A": "ACTIVE", "B": "ACTIVE", "C": "ACTIVE"})
    for state in ["MAINTENANCE", "DRAINING", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"]:
        _, command, _ = authorization(peer)
        peer.fixture_update(nodes={"A": "ACTIVE", "B": state, "C": "ACTIVE"})
        cases.append((f"verifier denies authorizer state {state}", denied(peer, command)))
        peer.fixture_update(nodes={"A": "ACTIVE", "B": "ACTIVE", "C": "ACTIVE"})

    _, concurrent, _ = authorization(peer)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: peer.invoke(concurrent), range(2)))
    cases.append(("concurrent workers issue exactly one grant per challenge", sum("result" in result for result in results) == 1
                  and sum(result == {"error": {"code": "DENIED"}} for result in results) == 1))
    for label, raw in [
        ("duplicate JSON fields", b'{"op":"challenge","op":"authorize","node_id":"A"}'),
        ("unknown IPC fields", b'{"op":"challenge","node_id":"A","extra":true}'),
        ("null request body", b'{"op":"authorize","request":null,"quote":"00","signature":"00"}'),
        ("oversized IPC body", b'{"op":"challenge","node_id":"A"}' + b' ' * 65536),
        ("malformed JSON", b'{'),
    ]:
        cases.append((f"verifier refuses {label}", peer.invoke(raw=raw) == {"error": {"code": "INVALID_REQUEST"}}))
    for label, change in [("boolean epoch", {"manifest_epoch": True}),
                          ("malformed recipient key", {"ephemeral_public_key": "00"}),
                          ("unknown request field", {"extra": True})]:
        _, command, _ = authorization(peer)
        command["request"].update(change)
        cases.append((f"verifier refuses {label}", peer.invoke(command) == {"error": {"code": "INVALID_REQUEST"}}))
    _, command, _ = authorization(peer)
    command["quote"] = {"path": "/etc/passwd"}
    cases.append(("client cannot substitute a verifier filesystem path", peer.invoke(command) == {"error": {"code": "INVALID_REQUEST"}}))
    peer.fixture_update(pending={})
    for _ in range(16):
        peer.challenge()
    cases.append(("pending challenge count is bounded", peer.invoke({"op": "challenge", "node_id": "A"}) == {"error": {"code": "DENIED"}}))
    return cases, granted["B"], granted["C"]
