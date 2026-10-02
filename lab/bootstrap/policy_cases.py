"""Real signed policy delivery, catch-up and bounded stale-partition behavior."""

import copy
import time

from mesh import probe


def policy_cases(c):
    for node in "ABC":
        for peer in "ABC":
            if peer == node:
                continue
            c.fresh()
            c.check(f"signed policy: {peer} restores {node}",
                    c.rpc(node, "bootstrap", peers=[peer]) == {"active": True, "via": peer})
    original = c.authority.envelope()
    c.publish(original)
    c.check("idempotent signed manifest preserves current freshness",
            all(c.rpc(node, "status")["fresh"] for node in "ABC"))
    tampered = copy.deepcopy(original)
    tampered["signature"] = ("00" if tampered["signature"][:2] != "00" else "01") + tampered["signature"][2:]
    before = c.rpc("B", "status")
    c.denied("mesh rejects a forged administrative signature", lambda: c.relay("A", "B", "apply_manifest", envelope=tampered))
    c.check("forged mesh update leaves policy and boot generation unchanged", c.rpc("B", "status") == before)
    c.denied("cluster disables unsigned fixture policy changes", lambda: c.rpc("A", "policy", nodes={node: "ACTIVE" for node in "ABC"}))
    c.denied("administrative route cannot invoke local control", lambda: c.relay("A", "B", "lock"))
    c.check("bootstrap plane cannot access runtime membership", not probe("A", "10.77.91.2", 8444, {})["reachable"])
    c.check("cleartext bridge cannot access membership", not probe("A", "10.89.91.2", 8444, {})["reachable"])
    c.check("bootstrap route denies signed administrative updates",
            probe("A", "10.77.91.2", 8443, {"op": "apply_manifest", "envelope": original}).get("response")
            == {"error": {"code": "DENIED"}})
    maintenance = c.authority.update({"A": "MAINTENANCE"})
    c.publish(maintenance, nodes="AC")
    c.rpc("B", "drop_admin_reply")
    lost = c.relay("C", "B", "apply_manifest", envelope=maintenance)
    committed = c.rpc("B", "status")
    c.check("lost administrative response still commits exactly one signed update",
            lost == {"transport_failed": True} and committed["epoch"] == 2 and not committed["fresh"])
    c.relay("C", "B", "apply_manifest", envelope=maintenance)
    c.check("retry after interrupted delivery is idempotent", c.rpc("B", "status") == committed)
    c.fresh()
    c.check("signed MAINTENANCE policy permits receiving disk bootstrap", c.rpc("A", "bootstrap", peers=["B"])["active"])
    c.check("signed MAINTENANCE policy denies authorizing a peer", not c.rpc("B", "bootstrap", peers=["A"])["active"])
    c.publish(c.authority.update({"A": "ACTIVE"}))
    c.fresh()
    c.rpc("B", "bootstrap", peers=["C"])
    c.publish(c.authority.update({"B": "MAINTENANCE"}), nodes="BC")
    latest = c.authority.update({"B": "ACTIVE"})
    c.publish(latest, nodes="BC")
    c.denied("lagging node rejects a skipped signed epoch", lambda: c.relay("C", "A", "apply_manifest", envelope=latest))
    c.sync("A")
    c.check("bounded signed catch-up installs every missing epoch", c.rpc("A", "status")["epoch"] == 5)
    c.fresh()
    malformed = copy.deepcopy(c.authority.fresh())
    malformed["payload"]["epoch"] = 4
    c.denied("freshness proof rejects payload tampering", lambda: c.relay("C", "B", "install_freshness", envelope=malformed))
    c.fresh(ttl=1500)
    revoked = c.authority.update({"A": "REVOKED_STOLEN"}, authority="revocation")
    c.publish(revoked, nodes="C")
    c.fresh(nodes="C")
    current_proof = c.authority.fresh()
    c.denied("stale policy cannot install a proof for a new manifest",
             lambda: c.relay("C", "B", "install_freshness", envelope=current_proof))
    time.sleep(1.7)
    c.check("stale target cannot bootstrap after freshness expires", c.rpc("A", "bootstrap", peers=["B"])
            == {"active": False, "reason": "freshness"})
    c.check("stale authorizer cannot bootstrap after freshness expires", c.rpc("B", "bootstrap", peers=["A"])
            == {"active": False, "reason": "freshness"})
    c.sync("A")
    c.sync("B")
    c.fresh()
    c.check("current signed revocation denies disk bootstrap", not c.rpc("A", "bootstrap", peers=["B", "C"])["active"])
    c.check("non-revoked node recovers after policy catch-up", c.rpc("B", "bootstrap", peers=["C"])["active"])
    c.publish(c.authority.update({"A": "ACTIVE"}))
    c.fresh()
    c.check("explicit root trust restoration permits recovery", c.rpc("A", "bootstrap", peers=["B"])["active"])
