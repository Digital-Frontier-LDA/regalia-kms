"""Actual token/session failures and protocol replay boundaries over the service mesh."""

import copy
from concurrent.futures import ThreadPoolExecutor

from peer import Refusal


def device_cases(c):
    for node in "ABC":
        c.fresh()
        peer = next(p for p in "ABC" if p != node)
        cached = c.rpc(node, "renew", peers=[peer])["lease"]
        c.check(f"{node} actual PKCS11 logout refuses private signing",
                c.rpc(node, "device_auth_probe")["refused"])
        c.check(f"{node} actual module rejects a wrong operational PIN", c.rpc(node, "device_bad_pin")["refused"])
        c.rpc(node, "renew", peers=[peer])
        c.rpc(node, "device_remove")
        status = c.rpc(node, "status")
        c.check(f"{node} removal leaves OS online but token unavailable", status["active"] and not status["service_ready"]
                and not status["device_session"] and not c.rpc(node, "device_probe")["token_visible"])
        c.denied(f"{node} removed token cannot obtain service authorization", lambda: c.rpc(node, "renew", peers=[peer]))
        c.denied(f"{node} removed token cannot sign", lambda: c.sign(node))
        c.rpc(node, "device_insert")
        c.check(f"{node} reinsertion enumerates token without authenticating it", c.rpc(node, "device_probe")["token_visible"]
                and not c.rpc(node, "status")["device_session"])
        c.denied(f"{node} reinsertion cannot reuse an earlier lease", lambda: c.rpc(node, "adopt_lease", lease=cached))
        c.denied(f"{node} reinsertion still requires fresh peer authorization", lambda: c.sign(node))
        c.rpc(node, "renew", peers=[peer])
        c.check(f"{node} fresh peer authorization restores the same token key", c.verify(node, *c.sign(node)))
    c.fresh()
    request = c.rpc("A", "prepare_lease_request", peer="B")

    def grant():
        try:
            return c.rpc("A", "runtime_request", peer="B", command=request)
        except Refusal:
            return {"refused": True}

    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(lambda _: grant(), range(2)))
    c.check("racing runtime requests consume one issuer challenge exactly once",
            sum("payload" in reply for reply in replies) == 1 and sum(reply == {"refused": True} for reply in replies) == 1)
    c.denied("runtime authorization cannot replay a consumed request",
             lambda: c.rpc("A", "runtime_request", peer="B", command=request))
    request = c.rpc("A", "prepare_lease_request", peer="B")
    altered = copy.deepcopy(request)
    altered["envelope"]["signature"] = "00" * 64
    c.denied("runtime issuer rejects a forged request signature",
             lambda: c.rpc("A", "runtime_request", peer="B", command=altered))
    c.denied("forged owned request also consumes its challenge",
             lambda: c.rpc("A", "runtime_request", peer="B", command=request))
    request = c.rpc("A", "prepare_lease_request", peer="B")
    c.denied("WireGuard runtime identity cannot submit another node's lease request",
             lambda: c.rpc("C", "runtime_request", peer="B", command=request))
    c.check("legitimate runtime identity retains its challenge after source mismatch",
            "payload" in c.rpc("A", "runtime_request", peer="B", command=request))
