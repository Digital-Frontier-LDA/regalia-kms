"""Peer renewals and independent client refusal using actual PKCS#11 responses."""

import copy
import os
import time

from mesh import admin, probe


def runtime_cases(c):
    c.fresh()
    for node in "ABC":
        identity = c.identities[node]
        c.check(f"{node} generates a local sensitive non-extractable PKCS11 key",
                identity["device_attributes"] == {"local": True, "sensitive": True, "extractable": False}
                and identity["private_unreadable"])
        c.check(f"{node} disk readiness does not imply KMS readiness", c.rpc(node, "status")["active"]
                and not c.rpc(node, "status")["service_ready"])
        c.denied(f"{node} refuses signing before a service lease", lambda: c.sign(node))
        peers = [peer for peer in "ABC" if peer != node]
        lease = c.rpc(node, "renew", peers=peers)
        reply, request, message = c.sign(node)
        c.check(f"{node} authenticates PKCS11 only after a valid peer lease", c.verify(node, reply, request, message)
                and lease["via"] in peers and c.rpc(node, "status")["service_ready"])
    c.rpc("A", "renew", peers=["B"])
    cached, request, message = c.sign("A")
    for field in ["signature", "statement", "lease"]:
        altered = copy.deepcopy(cached)
        if field == "statement":
            altered[field]["message_digest"] = "ff" * 32
        elif field == "lease":
            altered[field]["payload"]["node_id"] = "C"
        else:
            altered[field] = "00" * 256
        c.denied("external client rejects altered " + field, lambda: c.verify("A", altered, request, message))
    c.denied("external client binds response to its own fresh request", lambda: c.verify("A", cached, os.urandom(16).hex(), message))
    admin("B", "ip", "link", "set", "wg-service", "down")
    try:
        renewed = c.rpc("A", "renew", peers=["B", "C"])
        reply, nonce, data = c.sign("A")
        c.check("C renews A when runtime peer B is unreachable", renewed["via"] == "C" and c.verify("A", reply, nonce, data))
    finally:
        admin("B", "ip", "link", "set", "wg-service", "up")
    time.sleep(1.7)
    status = c.rpc("A", "status")
    c.check("expiry stops readiness and closes the authenticated PKCS11 session",
            not status["service_ready"] and not status["device_session"] and status["active"])
    c.denied("expired access lease prevents normal signing", lambda: c.sign("A"))
    c.denied("independent client rejects an expired cached response", lambda: c.verify("A", reply, nonce, data))
    malicious = c.rpc("A", "malicious_sign", request_id=nonce, message=data.hex(), lease=renewed["lease"])
    c.denied("independent client rejects a cryptographically valid bypass signature with an expired lease",
             lambda: c.verify("A", malicious, nonce, data))
    c.rpc("A", "renew", peers=["C"])
    before_reboot, old_nonce, old_data = c.sign("A")
    c.rpc("A", "lock")
    c.check("logical reboot drops lease and HSM authentication", not c.rpc("A", "status")["device_session"])
    c.rpc("A", "bootstrap", peers=["C"])
    c.denied("disk recovery requires new runtime authorization", lambda: c.sign("A"))
    c.rpc("A", "renew", peers=["C"])
    c.check("fresh runtime authorization restores service after reboot", c.verify("A", *c.sign("A")))
    for offset in [-60000, 60000]:
        c.rpc("A", "clock_fault", offset=offset)
        c.denied(f"clock jump {offset} cannot obtain a lease", lambda: c.rpc("A", "renew", peers=["C"]))
        c.denied(f"clock jump {offset} stops signing", lambda: c.sign("A"))
        c.rpc("A", "clock_reset")
        c.fresh(nodes="A")
        c.rpc("A", "renew", peers=["C"])
    c.client_clock.offset = -60000
    c.denied("independent client detects its own rollback clock fault", lambda: c.verify("A", *c.sign("A")))
    c.client_clock.offset = 0
    c.client_clock.reset()
    c.rpc("A", "renew", peers=["C"])
    valid, nonce, message = c.sign("A")
    c.publish(c.authority.update({"A": "REVOKED_STOLEN"}, authority="revocation"))
    c.fresh()
    c.denied("running revoked node cannot renew", lambda: c.rpc("A", "renew", peers=["B", "C"]))
    c.denied("current client rejects a revoked node before cached lease expiry", lambda: c.verify("A", valid, nonce, message))
    c.check("signed revocation closes the existing device session", not c.rpc("A", "status")["device_session"])
    c.publish(c.authority.update({"A": "ACTIVE"}))
    c.fresh()
    c.rpc("A", "bootstrap", peers=["C"])
    c.rpc("A", "renew", peers=["C"])
    c.check("explicit root recovery restores running-node service", c.verify("A", *c.sign("A")))
    c.check("bootstrap identity cannot reach service plane", not probe("B", "10.77.91.1", 8446, {})["reachable"])
    c.check("cleartext bridge cannot reach signing service", not probe("B", "10.89.91.1", 8446, {})["reachable"])
