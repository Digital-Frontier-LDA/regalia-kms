#!/usr/bin/env python3
"""Signed cluster membership with rollback-safe epochs (#68, Phase 8 of #59).

A manifest names every node, its identities and its state. Peers decide who may be unlocked, who may
authorize an unlock and who may serve from the newest manifest they have accepted, never from what a
node claims (THREE-SITE-THREAT-MODEL.md S2, ADR-0002 D23).

    envelope = {"manifest": {...}, "signature": {"signer": "root" | "revocation", "key": "<hex Ed25519 public key>",
                                                 "sig": "<hex Ed25519 signature>"}}

    manifest = {"schema": "regalia.membership/v1", "epoch": <int >= 1>, "prev_digest": "<64 hex, or "" at epoch 1>",
                "policy_version": "<text>", "issued_at": "YYYY-MM-DDTHH:MM:SSZ",
                "revocation_keys": ["<hex Ed25519 public key>", ...],
                "nodes": [{"node_id": ..., "state": ..., "ek_name": ..., "ak_name": ..., "wg_boot_pub": ...,
                           "wg_service_pub": ..., "hsm_serials": [...]}]}

Signed message: b"regalia-membership/v1\\0" + canonical JSON of the manifest (sorted keys, no spaces,
ASCII). Parsing refuses duplicate keys, unknown or missing fields, floats and non-ASCII names, so one
document has exactly one meaning.

Transition rules (accept(current, candidate)):
  * the epoch rises by exactly one and prev_digest is the digest of the current manifest: a strict hash
    chain, so two different manifests at one epoch (a conflict) cannot both be accepted, and a node that
    missed manifests catches up by verifying the chain in order (accept_chain);
  * the ROOT key (pinned, offline) may make any change: enroll, replace, change identities, change the
    revocation keys, restore trust;
  * a REVOCATION key (named by the root in the current manifest) may only make RESTRICTIVE changes:
    the same nodes, identities, policy version and revocation keys, and each node's capabilities a
    subset of what they were;
  * the TPM-backed high-water mark (HighWater) must never exceed the accepted epoch on disk: a disk
    restored to an older manifest is refused at load, and recovered by fetching the newer chain.

Capabilities by state (the #59 matrix): ACTIVE serves, requests bootstrap and authorizes peers;
MAINTENANCE only requests; DRAINING only serves; QUARANTINED, RETIRED and REVOKED_STOLEN nothing.
"""
import datetime
import hashlib
import json
import re
import subprocess

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = "regalia.membership/v1"
DOMAIN = b"regalia-membership/v1\0"
MAX_BYTES = 256 * 1024
CAPABILITIES = {
    "ACTIVE": frozenset({"serve", "request", "authorize"}),
    "MAINTENANCE": frozenset({"request"}),
    "DRAINING": frozenset({"serve"}),
    "QUARANTINED": frozenset(), "RETIRED": frozenset(), "REVOKED_STOLEN": frozenset(),
}
MANIFEST_KEYS = ("schema", "epoch", "prev_digest", "policy_version", "issued_at", "revocation_keys", "nodes")
NODE_KEYS = ("node_id", "state", "ek_name", "ak_name", "wg_boot_pub", "wg_service_pub", "hsm_serials")
IDENTITY_KEYS = ("ek_name", "ak_name", "wg_boot_pub", "wg_service_pub")


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        require(k not in out, "duplicate field %r" % k)
        out[k] = v
    return out


def _no_float(text):
    raise Refused("floats are not allowed (%s)" % text)


def load(raw):
    require(isinstance(raw, (bytes, str)) and len(raw) <= MAX_BYTES, "a manifest envelope is at most 256 KiB")
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_float=_no_float, parse_constant=_no_float)
    except ValueError as error:
        raise Refused("not valid JSON: %s" % error)


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(manifest):
    return hashlib.sha256(canonical(manifest)).hexdigest()


def _exact(value, keys, label):
    require(isinstance(value, dict), "%s must be an object" % label)
    missing, unknown = set(keys) - set(value), set(value) - set(keys)
    require(not missing and not unknown, "%s fields mismatch: missing=%s unknown=%s" % (label, sorted(missing), sorted(unknown)))


def _hex(value, n, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % n, value) is not None, "%s must be %d lowercase hex" % (label, n))


def validate(manifest):
    """Schema and uniqueness. Returns the manifest's nodes by ID."""
    _exact(manifest, MANIFEST_KEYS, "manifest")
    require(manifest["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    e = manifest["epoch"]
    require(isinstance(e, int) and not isinstance(e, bool) and e >= 1, "epoch must be an integer >= 1")
    if e == 1:
        require(manifest["prev_digest"] == "", "epoch 1 has no previous manifest (prev_digest \"\")")
    else:
        _hex(manifest["prev_digest"], 64, "prev_digest")
    require(isinstance(manifest["policy_version"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,32}", manifest["policy_version"]),
            "policy_version must be a short name")
    try:
        datetime.datetime.strptime(manifest["issued_at"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        raise Refused("issued_at must be UTC, YYYY-MM-DDTHH:MM:SSZ")
    keys = manifest["revocation_keys"]
    require(isinstance(keys, list) and len(set(keys)) == len(keys), "revocation_keys must be a list of distinct keys")
    for k in keys:
        _hex(k, 64, "a revocation key")
    nodes = manifest["nodes"]
    require(isinstance(nodes, list) and nodes, "nodes must be a non-empty list")
    by_id, seen = {}, {}
    for i, node in enumerate(nodes):
        _exact(node, NODE_KEYS, "nodes[%d]" % i)
        require(isinstance(node["node_id"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node["node_id"]),
                "nodes[%d].node_id must be a short lowercase name" % i)
        require(node["node_id"] not in by_id, "duplicate node_id %r" % node["node_id"])
        require(node["state"] in CAPABILITIES, "nodes[%d].state %r is not a known state" % (i, node["state"]))
        _hex(node["ek_name"], 68, "nodes[%d].ek_name" % i)
        _hex(node["ak_name"], 68, "nodes[%d].ak_name" % i)
        _hex(node["wg_boot_pub"], 64, "nodes[%d].wg_boot_pub" % i)
        _hex(node["wg_service_pub"], 64, "nodes[%d].wg_service_pub" % i)
        require(isinstance(node["hsm_serials"], list) and all(isinstance(s, str) and re.fullmatch(r"[A-Za-z0-9]{1,32}", s)
                                                             for s in node["hsm_serials"]), "nodes[%d].hsm_serials" % i)
        # No identity may belong to two nodes: a substituted TPM, key or token would otherwise pass as another.
        for k in IDENTITY_KEYS:
            require((k, node[k]) not in seen, "%s of %s is also %s's" % (k, node["node_id"], seen.get((k, node[k]))))
            seen[(k, node[k])] = node["node_id"]
        for s in node["hsm_serials"]:
            require(("hsm", s) not in seen, "HSM %s is listed for two nodes" % s)
            seen[("hsm", s)] = node["node_id"]
        by_id[node["node_id"]] = node
    return by_id


def verify_envelope(envelope, root_key, current=None):
    """The manifest inside an envelope, if its signature is by the pinned root key or by a revocation key
    named in the CURRENT manifest (never one named by the candidate itself). Returns (manifest, signer)."""
    _exact(envelope, ("manifest", "signature"), "envelope")
    sig = envelope["signature"]
    _exact(sig, ("signer", "key", "sig"), "signature")
    require(sig["signer"] in ("root", "revocation"), "signer must be root or revocation")
    _hex(sig["key"], 64, "signature.key")
    _hex(sig["sig"], 128, "signature.sig")
    if sig["signer"] == "root":
        require(sig["key"] == root_key, "the signature names a root key that is not the pinned root")
    else:
        require(current is not None and sig["key"] in current["revocation_keys"],
                "the signing revocation key is not named by the current manifest")
    manifest = envelope["manifest"]
    validate(manifest)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["key"])).verify(bytes.fromhex(sig["sig"]), DOMAIN + canonical(manifest))
    except (InvalidSignature, ValueError):
        raise Refused("the manifest signature does not verify")
    return manifest, sig["signer"]


def _restrictive(current, candidate):
    """A revocation-signed change: identities, policy and keys unchanged; capabilities only shrink."""
    require(candidate["policy_version"] == current["policy_version"], "a revocation key cannot change the policy version")
    require(candidate["revocation_keys"] == current["revocation_keys"], "a revocation key cannot change the revocation keys")
    old, new = validate(current), validate(candidate)
    require(set(old) == set(new), "a revocation key cannot add or remove nodes")
    for nid, node in new.items():
        for k in IDENTITY_KEYS + ("hsm_serials",):
            require(node[k] == old[nid][k], "a revocation key cannot change %s of %s" % (k, nid))
        require(CAPABILITIES[node["state"]] <= CAPABILITIES[old[nid]["state"]],
                "%s: %s -> %s widens capabilities; only the root can do that" % (nid, old[nid]["state"], node["state"]))


def accept(current, envelope, root_key):
    """The next manifest, if `envelope` may follow `current` (None at enrollment, where only a
    root-signed epoch-1 manifest is accepted)."""
    candidate, signer = verify_envelope(envelope, root_key, current)
    if current is None:
        require(signer == "root" and candidate["epoch"] == 1, "the first manifest must be the root-signed epoch 1")
        return candidate
    if candidate["epoch"] == current["epoch"]:
        if digest(candidate) == digest(current):
            return current                 # the same manifest delivered again: nothing changes
        raise Refused("CONFLICT: a different manifest at epoch %d: record an incident" % candidate["epoch"])
    require(candidate["epoch"] == current["epoch"] + 1,
            "epoch %d does not follow %d (fetch the missing manifests and accept them in order)" % (candidate["epoch"], current["epoch"]))
    require(candidate["prev_digest"] == digest(current), "prev_digest does not chain to the current manifest")
    if signer == "revocation":
        _restrictive(current, candidate)
    return candidate


def accept_chain(current, envelopes, root_key):
    for env in envelopes:
        current = accept(current, env, root_key)
    return current


def may(manifest, node_id, action):
    """Whether node_id may `serve`, `request` (be unlocked) or `authorize` (give a contribution)."""
    node = validate(manifest).get(node_id)
    return bool(node) and action in CAPABILITIES[node["state"]]


class HighWater:
    """The highest accepted epoch in a TPM NV counter (TPM_NT_COUNTER), outside restorable disk state.
    `advance(epoch)` increments until the counter reads `epoch` (bounded); `check(disk_epoch)` refuses a
    disk manifest older than the counter, after a restore or a crash between advance and the disk write.
    Recovery is to fetch the chain from a peer up to at least the counter's value."""

    MAX_JUMP = 1000

    def __init__(self, index, tcti=None, run=subprocess.run):
        self.index, self.run, self.env = index, run, ({"TPM2TOOLS_TCTI": tcti} if tcti else None)

    def _tpm(self, *args):
        import os
        env = dict(os.environ, **self.env) if self.env else None
        return self.run(["tpm2_" + args[0], *args[1:]], capture_output=True, env=env)

    def define(self):
        r = self._tpm("nvdefine", self.index, "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread|authwrite")
        require(r.returncode == 0, "cannot define the NV counter %s" % self.index)

    def value(self):
        r = self._tpm("nvread", self.index, "-C", "o")
        if r.returncode != 0:
            return 0                       # a counter that was never incremented reads as unwritten
        require(len(r.stdout) == 8, "unexpected NV counter size")
        return int.from_bytes(r.stdout, "big")

    def advance(self, epoch):
        now = self.value()
        require(epoch >= now, "refusing to accept epoch %d below the TPM high-water %d" % (epoch, now))
        require(epoch - now <= self.MAX_JUMP, "epoch jump %d exceeds the bound %d: anomaly" % (epoch - now, self.MAX_JUMP))
        while now < epoch:
            r = self._tpm("nvincrement", self.index, "-C", "o")
            require(r.returncode == 0, "cannot increment the NV counter")
            nxt = self.value()
            require(nxt == now + 1, "the NV counter did not advance by one (%d -> %d)" % (now, nxt))
            now = nxt
        return now

    def check(self, disk_epoch):
        hw = self.value()
        require(disk_epoch >= hw, "ROLLBACK: the manifest on disk is epoch %d but the TPM high-water is %d; "
                "fetch the chain from a peer" % (disk_epoch, hw))
        return hw
