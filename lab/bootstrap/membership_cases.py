"""Signed software policy exercised through actual peer subprocesses and quotes."""

import copy
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives.asymmetric import ed25519

from peer import BootSession, ak_digest, canonical, qualification
from peer_cases import Peer, flipped


def membership_cases(root, target):
    root = root / "membership"
    root.mkdir()
    keys = {name: ed25519.Ed25519PrivateKey.generate() for name in ["membership_root", "revocation"]}
    pins = {name: key.public_key().public_bytes_raw().hex() for name, key in keys.items()}
    pins["cluster_id"] = os.urandom(32).hex()
    peer = Peer(root, "B", target, pins)
    cases = []

    def envelope(manifest, authority="membership_root", key=None):
        signed = {"authority": authority, "manifest": manifest}
        signature = (key or keys[authority]).sign(b"regalia-bootstrap-lab/v1/membership\0" + canonical(signed))
        return dict(signed, signature=signature.hex())

    def apply(signed):
        return peer.invoke({"op": "apply_manifest", "envelope": signed})

    def reject(label, signed, code="DENIED"):
        before = peer.state.read_bytes()
        result = apply(signed)
        cases.append((label, result == {"error": {"code": code}} and before == peer.state.read_bytes()))

    def successor(manifest):
        return dict(copy.deepcopy(manifest), epoch=manifest["epoch"] + 1,
                    previous_digest=hashlib.sha256(canonical(manifest)).hexdigest())

    manifest = {"version": 1, "cluster_id": pins["cluster_id"], "epoch": 1,
                "previous_digest": "00" * 32,
                "nodes": {name: {"state": "ACTIVE", "ak_sha256": hashlib.sha256(name.encode()).hexdigest(),
                                  "approved_pcr": "00" * 32} for name in ["A", "B", "C"]}}
    manifest["nodes"]["A"]["ak_sha256"] = ak_digest((target.root / "ak.pem").read_text())
    manifest["nodes"]["A"]["approved_pcr"] = (target.root / "approved.pcr").read_bytes().hex()
    cases.append(("signed-policy peer denies bootstrap before genesis",
                  peer.invoke({"op": "challenge", "node_id": "A"}) == {"error": {"code": "DENIED"}}))
    reject("revocation authority cannot commission genesis", envelope(manifest, "revocation"))
    reject("membership rejects unknown signer without changing state",
           envelope(manifest, key=ed25519.Ed25519PrivateKey.generate()))
    altered = envelope(manifest)
    altered["signature"] = flipped(altered["signature"])
    reject("membership rejects altered signature without changing state", altered)
    genesis = envelope(manifest)
    expected = {"epoch": 1, "manifest_digest": hashlib.sha256(canonical(manifest)).hexdigest()}
    cases.append(("root-signed genesis installs the enrolled policy", apply(genesis) == {"result": expected}))
    snapshot = peer.state.read_bytes()
    cases.append(("authenticated current manifest replay is idempotent",
                  apply(genesis) == {"result": expected} and peer.state.read_bytes() == snapshot))
    tampered = copy.deepcopy(genesis)
    tampered["manifest"]["nodes"]["A"]["state"] = "RETIRED"
    reject("membership rejects payload tampering under a recorded signature", tampered)
    relabeled = dict(genesis, authority="revocation")
    reject("membership signature binds the authority role", relabeled)
    different_cluster = successor(manifest)
    different_cluster["cluster_id"] = os.urandom(32).hex()
    reject("membership rejects a valid signature for another cluster", envelope(different_cluster))
    wrong_identity = successor(manifest)
    wrong_identity["nodes"]["A"]["ak_sha256"] = "ff" * 32
    reject("root cannot silently replace a locally commissioned AK", envelope(wrong_identity))
    skipped = successor(manifest)
    skipped["epoch"] += 1
    reject("membership rejects a skipped epoch", envelope(skipped))
    wrong_chain = successor(manifest)
    wrong_chain["previous_digest"] = "ff" * 32
    reject("membership rejects a conflicting predecessor", envelope(wrong_chain))
    conflict = copy.deepcopy(manifest)
    conflict["nodes"]["C"]["state"] = "QUARANTINED"
    reject("membership rejects a different body at the accepted epoch", envelope(conflict))
    for field, value in [("version", True), ("epoch", True), ("epoch", 0), ("epoch", 2 ** 64),
                         ("previous_digest", "00"), ("cluster_id", "GG" * 32)]:
        malformed = successor(manifest)
        malformed[field] = value
        reject(f"membership rejects malformed {field} value {value}", envelope(malformed), "INVALID_REQUEST")
    for label, mutate in [
            ("unknown field", lambda m: m.update(extra=1)),
            ("missing node", lambda m: m["nodes"].pop("C")),
            ("unknown node", lambda m: m["nodes"].update(D=m["nodes"]["C"])),
            ("unknown state", lambda m: m["nodes"]["A"].update(state="COMPROMISED")),
            ("state type", lambda m: m["nodes"]["A"].update(state=[])),
            ("PCR type", lambda m: m["nodes"]["A"].update(approved_pcr=7)),
    ]:
        malformed = successor(manifest)
        mutate(malformed)
        reject("membership rejects " + label, envelope(malformed), "INVALID_REQUEST")
    session = BootSession({"B": peer.pin})
    request = session.request(peer.challenge(), os.urandom(16).hex())
    quote = target.quote(qualification(request), "signed-membership")
    authorization = {"op": "authorize", "request": request,
                     "quote": quote[0].read_bytes().hex(), "signature": quote[1].read_bytes().hex()}
    secret = session.open(peer.invoke(authorization)["result"])
    cases.append(("signed ACTIVE policy authorizes a fresh TPM quote", len(secret) == 32))
    revoked = successor(manifest)
    revoked["nodes"]["A"]["state"] = "REVOKED_STOLEN"
    pending_session = BootSession({"B": peer.pin})
    pending = pending_session.request(peer.challenge(), os.urandom(16).hex())
    pending_quote = target.quote(qualification(pending), "before-revocation")
    old_authorization = {"op": "authorize", "request": pending,
                         "quote": pending_quote[0].read_bytes().hex(), "signature": pending_quote[1].read_bytes().hex()}
    accepted = apply(envelope(revoked, "revocation"))
    state = json.loads(peer.state.read_bytes())
    cases.append(("restrictive signed revocation advances epoch and clears pending challenges",
                  accepted.get("result", {}).get("epoch") == 2 and not state["pending"]
                  and pending["challenge_id"] not in state["pending"]))
    cases.append(("signed revocation blocks an already attested pending request",
                  peer.invoke(old_authorization) == {"error": {"code": "DENIED"}}))
    cases.append(("signed revocation denies new bootstrap requests",
                  peer.invoke({"op": "challenge", "node_id": "A"}) == {"error": {"code": "DENIED"}}))
    reject("persisted epoch rejects signed rollback across verifier restarts", genesis)
    restored = successor(revoked)
    restored["nodes"]["A"]["state"] = "ACTIVE"
    reject("revocation authority cannot restore a stolen node", envelope(restored, "revocation"))
    cases.append(("membership root can restore trust explicitly",
                  apply(envelope(restored)).get("result", {}).get("epoch") == 3
                  and peer.challenge()["manifest_epoch"] == 3))
    quarantined_peer = successor(restored)
    quarantined_peer["nodes"]["B"]["state"] = "QUARANTINED"
    cases.append(("signed peer quarantine removes its authority to bootstrap an ACTIVE target",
                  apply(envelope(quarantined_peer, "revocation")).get("result", {}).get("epoch") == 4
                  and peer.invoke({"op": "challenge", "node_id": "A"}) == {"error": {"code": "DENIED"}}))
    retired = successor(quarantined_peer)
    retired["nodes"]["B"]["state"] = "ACTIVE"
    retired["nodes"]["A"]["state"] = "RETIRED"
    cases.append(("root can restore a peer while retaining target retirement",
                  apply(envelope(retired)).get("result", {}).get("epoch") == 5
                  and peer.invoke({"op": "challenge", "node_id": "A"}) == {"error": {"code": "DENIED"}}))
    relaxing = successor(retired)
    relaxing["nodes"]["A"]["state"] = "QUARANTINED"
    reject("revocation authority cannot undo terminal retirement", envelope(relaxing, "revocation"))
    restored = successor(retired)
    restored["nodes"]["A"]["state"] = "ACTIVE"
    cases.append(("root can explicitly restore a retired identity",
                  apply(envelope(restored)).get("result", {}).get("epoch") == restored["epoch"]
                  and peer.challenge()["manifest_epoch"] == restored["epoch"]))
    for field in ["ak_sha256", "approved_pcr"]:
        changed = successor(restored)
        changed["nodes"]["C"][field] = "ff" * 32
        changed["nodes"]["A"]["state"] = "QUARANTINED"
        reject("revocation authority cannot change " + field, envelope(changed, "revocation"))
    for state in ["MAINTENANCE", "DRAINING"]:
        changed = successor(restored)
        changed["nodes"]["A"]["state"] = state
        reject("revocation authority cannot grant state " + state, envelope(changed, "revocation"))
    reject("revocation authority cannot publish a no-op epoch", envelope(successor(restored), "revocation"))
    measurements = successor(restored)
    measurements["nodes"]["A"]["approved_pcr"] = "ff" * 32
    cases.append(("membership root can approve a new measurement policy",
                  apply(envelope(measurements)).get("result", {}).get("epoch") == measurements["epoch"]))
    changed_session = BootSession({"B": peer.pin})
    changed_request = changed_session.request(peer.challenge(), os.urandom(16).hex())
    changed_quote = target.quote(qualification(changed_request), "after-policy-change")
    cases.append(("signed measurement policy is enforced by actual TPM quote verification",
                  peer.invoke({"op": "authorize", "request": changed_request,
                               "quote": changed_quote[0].read_bytes().hex(),
                               "signature": changed_quote[1].read_bytes().hex()}) == {"error": {"code": "DENIED"}}))
    final = successor(measurements)
    final["nodes"]["A"]["state"] = "REVOKED_STOLEN"
    cases.append(("revocation signer can revoke after a root measurement update",
                  apply(envelope(final, "revocation")).get("result", {}).get("epoch") == final["epoch"]))
    competitors = [successor(final), successor(final)]
    competitors[0]["nodes"]["B"]["state"] = "QUARANTINED"
    competitors[1]["nodes"]["C"]["state"] = "RETIRED"
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(apply, [envelope(m, "revocation") for m in competitors]))
    winners = [index for index, response in enumerate(responses) if "result" in response]
    winner = json.loads(peer.state.read_bytes())
    cases.append(("racing signed conflicting updates accept exactly one complete policy",
                  len(winners) == 1 and responses[1 - winners[0]] == {"error": {"code": "DENIED"}}
                  and winner["manifest"] == competitors[winners[0]]
                  and winner["manifest_digest"] == hashlib.sha256(canonical(winner["manifest"])).hexdigest()))
    # Deliberate trusted-host attack: restoring all software state defeats its high-water mark.
    peer.state.write_bytes(snapshot)
    rollback_session = BootSession({"B": peer.pin})
    rollback_request = rollback_session.request(peer.challenge(), os.urandom(16).hex())
    rollback_quote = target.quote(qualification(rollback_request), "restored-policy-file")
    rollback_reply = peer.invoke({"op": "authorize", "request": rollback_request,
                                 "quote": rollback_quote[0].read_bytes().hex(),
                                 "signature": rollback_quote[1].read_bytes().hex()})
    rollback_possible = rollback_session.open(rollback_reply["result"]) == secret
    cases.append(("observed limitation: full state-file restore permits previously revoked bootstrap", rollback_possible))
    return cases, {"membership_state_rollback_is_possible": rollback_possible}
