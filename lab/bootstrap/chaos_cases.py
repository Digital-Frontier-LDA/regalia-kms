"""Seeded software faults; cryptographic secrets always use OS randomness."""

import copy
import os
import random
import time

from mesh import admin, probe

KINDS = ["runtime_partition", "bootstrap_partition", "lost_response", "single_reboot", "two_reboot",
         "total_outage", "revoke", "policy_conflict", "parser", "clock", "token", "authority_expiry", "pcr_fault"]


def schedule(seed, steps):
    if not len(KINDS) <= steps <= 256 or not 0 <= seed < 2 ** 64:
        raise ValueError("seed/step count outside lab bounds")
    rng = random.Random(seed)
    kinds = KINDS + rng.choices(KINDS, k=steps - len(KINDS))
    rng.shuffle(kinds)
    return [{"kind": kind, "node": rng.choice("ABC"), "variant": rng.randrange(3)} for kind in kinds]


def chaos_cases(c):
    seed = int(os.environ.get("REGALIA_CHAOS_SEED", "20261002"))
    steps = int(os.environ.get("REGALIA_CHAOS_STEPS", "36"))
    actions = schedule(seed, steps)
    c.report["chaos"] = {"seed": seed, "steps": steps, "actions": []}

    def recover(node, peers):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = c.rpc(node, "bootstrap", peers=peers)
            if result["active"]:
                return True
            time.sleep(0.2)
        return False

    for index, action in enumerate(actions):
        kind, node = action["kind"], action["node"]
        peers = [other for other in "ABC" if other != node]
        peer, survivor = peers[action["variant"] % 2], peers[1 - action["variant"] % 2]
        label = f"chaos {index + 1}/{steps}: {kind} on {node}"
        record = dict(action, step=index + 1, status="failed")
        c.report["chaos"]["actions"].append(record)
        started = time.monotonic()
        c.fresh()
        c.rpc(node, "renew", peers=peers)
        c.check(label + " starts with a verified live service", c.verify(node, *c.sign(node)))
        if kind in ["runtime_partition", "bootstrap_partition"]:
            interface = "wg-service" if kind == "runtime_partition" else "wg-bootstrap"
            admin(peer, "ip", "link", "set", interface, "down")
            try:
                if kind == "runtime_partition":
                    renewal = c.rpc(node, "renew", peers=[peer, survivor])
                    c.check(label + " uses the reachable renewal peer", renewal["via"] == survivor)
                else:
                    c.check(label + " rejects the unreachable bootstrap peer", not c.rpc(node, "bootstrap", peers=[peer])["active"])
                    c.check(label + " recovers through the surviving peer", recover(node, [survivor]))
                    c.rpc(node, "renew", peers=[survivor])
                c.check(label + " returns a valid service response", c.verify(node, *c.sign(node, source=survivor)))
            finally:
                admin(peer, "ip", "link", "set", interface, "up")
        elif kind == "lost_response":
            c.rpc(peer, "drop_response")
            c.check(label + " stays closed after a lost grant", not c.rpc(node, "bootstrap", peers=[peer])["active"])
            c.check(label + " recovers with a fresh challenge", recover(node, [peer]))
        elif kind in ["single_reboot", "two_reboot"]:
            targets = [node] if kind == "single_reboot" else [node, peer]
            for target in targets:
                c.rpc(target, "lock")
                c.check(label + f" closes {target}'s device", not c.rpc(target, "status")["device_session"])
            for target in targets:
                c.check(label + f" survivor restores {target}", recover(target, [survivor]))
        elif kind == "total_outage":
            for target in "ABC":
                c.rpc(target, "lock")
            for target in "ABC":
                c.check(label + f" keeps {target} locked", not c.rpc(target, "bootstrap", peers=[p for p in "ABC" if p != target])["active"])
            c.check(label + " requires a real offline LUKS recovery path", c.rpc(node, "manual", key=c.recovery[node])["active"])
            for target in peers:
                c.check(label + f" one seed restores {target}", recover(target, [node]))
        elif kind == "revoke":
            c.publish(c.authority.update({node: "REVOKED_STOLEN"}, authority="revocation"))
            c.fresh()
            c.denied(label + " rejects runtime renewal", lambda: c.rpc(node, "renew", peers=peers))
            c.check(label + " rejects disk bootstrap", not c.rpc(node, "bootstrap", peers=peers)["active"])
            c.publish(c.authority.update({node: "ACTIVE"}))
            c.fresh()
            c.check(label + " needs explicit root restoration", recover(node, peers))
        elif kind == "policy_conflict":
            good = c.authority.update({node: "MAINTENANCE"})
            fork = copy.deepcopy(good["manifest"])
            fork["nodes"][node]["state"] = "QUARANTINED"
            c.publish(good)
            c.denied(label + " rejects a signed fork at the accepted epoch",
                     lambda: c.relay("C", peer, "apply_manifest", envelope=c.authority.envelope(fork)))
            c.publish(c.authority.update({node: "ACTIVE"}))
            c.fresh()
        elif kind == "parser":
            bodies = ['{"op":"get_manifests","after_epoch":0,"after_epoch":1}', '{broken',
                      '{"op":"get_manifests","after_epoch":true}']
            result = probe(node, "10.78.91." + str("ABC".index(peer) + 1), 8444,
                           bodies[action["variant"]], raw=True, route="/membership")
            c.check(label + " rejects the malformed administrative request", result.get("response")
                    == {"error": {"code": "INVALID_REQUEST"}})
        elif kind == "clock":
            c.rpc(node, "clock_fault", offset=-60000 if action["variant"] % 2 else 60000)
            try:
                c.denied(label + " refuses signing under a clock fault", lambda: c.sign(node))
                c.denied(label + " refuses renewal under a clock fault", lambda: c.rpc(node, "renew", peers=peers))
            finally:
                c.rpc(node, "clock_reset")
            c.fresh()
        elif kind == "token":
            c.rpc(node, "device_remove")
            try:
                c.denied(label + " refuses service with the token absent", lambda: c.sign(node))
            finally:
                c.rpc(node, "device_insert")
            c.denied(label + " reinsertion does not authorize service", lambda: c.sign(node))
        elif kind == "authority_expiry":
            c.fresh(ttl=3000)
            time.sleep(3.3)
            c.denied(label + " stops service when policy freshness expires", lambda: c.sign(node))
            c.check(label + " stops stale disk authorization", not c.rpc(node, "bootstrap", peers=peers)["active"])
            c.fresh()
            c.check(label + " recovers after fresh authority returns", recover(node, peers))
        elif kind == "pcr_fault":
            c.rpc(node, "extend_pcr")
            c.check(label + " recognizes a genuine TPM policy refusal", c.rpc(node, "bootstrap", peers=peers)
                    == {"active": False, "reason": "local_policy"})
            c.rpc(node, "tpm_restart")
            c.check(label + " recovers after emulated cold PCR reset", recover(node, peers))
        else:
            raise RuntimeError("unknown chaos operation")
        c.fresh()
        c.rpc(node, "renew", peers=peers)
        service_valid = c.verify(node, *c.sign(node))
        states = [c.rpc(target, "status") for target in "ABC"]
        c.check(label + " finishes with verified service and healthy peers", service_valid
                and all(state["active"] and not state["agent_error"] for state in states))
        record["status"] = "passed"
        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
