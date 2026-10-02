#!/usr/bin/env python3
"""Replacing a node, and keeping its retired hardware out (#76, Phase 16 of #59).

A node that failed for good is replaced by ONE root-signed manifest: it enrolls the new node under a new
node ID with a new EK, AK, WireGuard keys and HSM serials, and moves the old one to RETIRED (REVOKED_STOLEN
if the hardware is gone). The old entry stays in the manifest for ever: membership.accept() treats a
terminal entry as a tombstone that no signer may drop, alter or revive, so the per-manifest uniqueness
rule refuses every later reuse of its identities.

What this module adds is the other half: once a peer has accepted that manifest, the old hardware must be
refused by every decision the peer makes, and the new node must pass them.

  * attest_policy(manifest, measurements): the peer's attestation policy is BUILT FROM the manifest. Only
    nodes that may still be unlocked or serve are in it, each pinned to the manifest's EK Name. A retired
    node is then unknown to attest.py (no challenge, no nonce, no quote accepted), and a retired TPM that
    presents itself as the new node fails on the EK.
  * may_unlock(...): the bootstrap decision for a requester: the membership matrix and the peer's
    freshness (heartbeat.authorize), and a fresh quote from the requester verified under the EK and AK the
    manifest names for it (lease.reattest).
  * check_replacement(current, candidate, old_id, new_id): what the root's operator asserts before
    signing, and a peer may assert after accepting: the old node is terminal, the new one shares no
    identity with any node the manifest has ever listed, and nobody else changed.

Runtime leases need nothing new: lease.issue() and lease.verify() already judge subject and issuer by
the verifier's current manifest.

NOT HERE: restoring the service keys onto the new node's HSM (the DKEK domain, #64), configuring WireGuard
peers on real hosts, and the physical rehearsal.
"""
from deploy.baremetal import attest, heartbeat, lease, membership

Refused, require = membership.Refused, membership.require

TERMINAL = ("RETIRED", "REVOKED_STOLEN")


def attest_policy(manifest, measurements, peer_id=None):
    """The attestation policy a peer holds under `manifest`. `measurements` maps a node ID to that node's
    reference values, {"tpm_firmware_version": ..., "pcrs": {...}} (attest.py's policy fields, without the
    EK). Every node that may `request` or `serve` gets an entry pinned to the manifest's EK Name; `peer_id`
    (the peer itself) is left out. A node that may be attested but has no reference values is a refusal,
    not an omission: the peer would otherwise refuse it at boot for a reason nobody configured."""
    require(isinstance(measurements, dict), "measurements must map node IDs to reference values")
    nodes, policy = membership.validate(manifest), {}
    for node_id, node in nodes.items():
        if node_id == peer_id or not membership.CAPABILITIES[node["state"]] & {"request", "serve"}:
            continue
        reference = measurements.get(node_id)
        require(isinstance(reference, dict), "no reference measurements for %s, which the manifest lets attest" % node_id)
        membership.exact(reference, ("tpm_firmware_version", "pcrs"), "measurements of %s" % node_id)
        policy[node_id] = dict(reference, ek_name=node["ek_name"])
    require(policy, "the manifest leaves no node this peer could attest")
    document = {"schema": attest.POLICY_SCHEMA, "nodes": policy}
    try:
        attest.validate_policy(document)
    except attest.Refused as refusal:
        raise Refused("the attestation policy is refused: %s" % refusal)
    return document


def may_unlock(manifest, peer_id, requester_id, session_id, evidence, attester, freshness):
    """Whether `peer_id` gives `requester_id` its bootstrap contribution: the requester may be unlocked and
    the peer may authorize under a live heartbeat, and the requester has just proved, with a fresh quote,
    that it is the hardware the manifest names. Returns the seconds of freshness left."""
    heartbeat.authorize(manifest, peer_id, requester_id, freshness)   # before any evidence is consumed
    membership.hex_field(session_id, 64, "session_id")
    # The freshness of the unlock is the attester-issued nonce inside `evidence` (good once, two minutes);
    # no nonce chosen by the requester takes part.
    lease.reattest(attester, evidence, requester_id, session_id, manifest, membership.validate(manifest)[requester_id])
    # and again, after it: the verification takes time, and the answer must hold when it is given
    return heartbeat.authorize(manifest, peer_id, requester_id, freshness)


def identities(node):
    """Every value that identifies a node's hardware: its TPM names, its WireGuard keys, its HSM serials."""
    return {node[k] for k in membership.IDENTITY_KEYS} | {"hsm:" + s for s in node["hsm_serials"]}


def check_replacement(current, candidate, old_id, new_id):
    """`candidate` replaces `old_id` by `new_id` and does nothing else. Raises Refused with the reason."""
    old, new = membership.validate(current), membership.validate(candidate)
    require(candidate["epoch"] == current["epoch"] + 1 and candidate["prev_digest"] == membership.digest(current),
            "the replacement must be the next manifest: epoch %d, chained to the current one" % (current["epoch"] + 1))
    require(old_id in old, "%s is not in the current manifest" % old_id)
    require(new_id not in old, "%s is already a node: a replacement gets a new node ID" % new_id)
    require(old_id in new and new[old_id]["state"] in TERMINAL, "%s must stay listed, as RETIRED or REVOKED_STOLEN" % old_id)
    require(new_id in new and membership.CAPABILITIES[new[new_id]["state"]], "%s must be enrolled in a state that can do something" % new_id)
    used = set().union(*(identities(node) for node in old.values()))
    reused = sorted(identities(new[new_id]) & used)
    require(not reused, "%s reuses an identity the manifest already lists: %s" % (new_id, ", ".join(reused)))
    require(set(new) == set(old) | {new_id}, "a replacement adds %s and nothing else" % new_id)
    for node_id, node in old.items():
        if node_id == old_id:
            require({k: v for k, v in new[node_id].items() if k != "state"} == {k: v for k, v in node.items() if k != "state"},
                    "the retired entry of %s must keep its identities" % old_id)
        else:
            require(new[node_id] == node, "a replacement does not change %s" % node_id)
    for k in ("policy_version", "revocation_keys"):
        require(candidate[k] == current[k], "a replacement does not change %s" % k)
