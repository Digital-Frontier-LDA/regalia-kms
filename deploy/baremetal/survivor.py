#!/usr/bin/env python3
"""The lone survivor (ADR-0002 D32 item 6, D28.6 amendment 5 kept; #432 item (e)): with the other servers fenced, one
server serves STATELESS operations under ONE owner authorization, and the owner can still disable keys meanwhile.

THE AUTHORIZATION. One owner signature (owner.py sign-survivor, off the nodes), never renewed per lease:

    {"schema": "regalia.survivor-authorization/v1", "node_id", "quarantine_epoch", "quarantine_digest",
     "not_before", "expires_at", "fenced"}       signed over AUTH_DOMAIN + canonical, {"party": "owner", "key", "sig"}

It holds (verify_authorization) only against the CURRENT manifest, and only while that manifest IS the quarantine
manifest (epoch and digest): any new epoch ends it, a returning server's included, because lifting a quarantine is a
root-signed epoch above it. Every other node of the manifest has stopped counting (QUARANTINED, REVOKED_STOLEN,
RETIRED) and the survivor counts. Its life is at most MAX_AUTHORIZATION_S (7 days, amendment 5's default; #459 makes
it the manifest's recovery_authorization_max_s). `fenced` is the owner's typed attestation that the others are powered
off or cut off until they hold that epoch (D32.6: it rules out the other two forming a majority, disabling a key,
and the survivor still using it). The owner's tool records nothing on the nodes; the survivor's admission takes it
(regalia-kms-d9's both directions on #432):
  * it enters recovery only while it holds no unexpired normal (peer-issued) lease;
  * it leaves recovery at the first normal lease; stateful operations resume once its watch has caught up.
Nothing has to be reconciled after: the survivor commits nothing (stateful keys wait for a majority, D32).

THE DIRECTIVE (regalia-kms-d9's addition, agreed by 24): during a recovery that may last days, the owner can still
kill a compromised key. An owner-signed directive names an object and a state that is ONLY "disabled" or
"destroyed", never "enabled" (DIRECTIVE_STATES). The survivor applies it at once (Directives: a state only ever
rises, enabled < disabled < destroyed) and the majority commits it on its return as a key-state change. Re-enabling a
key is D25's approvers' act on the majority, never a directive's.

Not built here (#432 item (e), part 2): the survivor's admission mode, the daemon's stateless-only gate in it (ed),
and the directive's commit on the majority's return. LIMITATIONS.md says so.
"""
import json
import os
import re
import tempfile

from deploy.baremetal import heartbeat, membership

Refused, require = membership.Refused, membership.require

AUTH_SCHEMA = "regalia.survivor-authorization/v1"
AUTH_DOMAIN = b"regalia-survivor-authorization/v1\0"
AUTH_KEYS = ("schema", "node_id", "quarantine_epoch", "quarantine_digest", "not_before", "expires_at", "fenced")
MAX_AUTHORIZATION_S = 7 * 24 * 3600
MAX_FENCED_BYTES = 512
DIRECTIVE_SCHEMA = "regalia.survivor-directive/v1"
DIRECTIVE_DOMAIN = b"regalia-survivor-directive/v1\0"
DIRECTIVE_KEYS = ("schema", "object_id", "state", "quarantine_epoch", "quarantine_digest", "issued_at", "reason")
DIRECTIVE_STATES = ("disabled", "destroyed")       # never "enabled": a directive only takes away
RANK = {"enabled": 0, "disabled": 1, "destroyed": 2}
NODE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
NAME = re.compile(r"[\x21-\x7e]{1,256}")


def _text(value, label, limit=MAX_FENCED_BYTES):
    require(isinstance(value, str) and value.strip() and len(value.encode()) <= limit and value.isprintable(),
            "%s must be printable text of at most %d bytes" % (label, limit))


def _epoch_bound(body, label):
    require(isinstance(body["quarantine_epoch"], int) and not isinstance(body["quarantine_epoch"], bool) and body["quarantine_epoch"] >= 1,
            "%s's quarantine_epoch must be an integer >= 1" % label)
    membership.hex_field(body["quarantine_digest"], 64, "%s's quarantine_digest" % label)


def _owner_signed(current, raw, signature, what):
    parties = membership.counting_parties(current, raw, [signature], what)
    require(parties == {membership.OWNER}, "the %s is not the owner's" % what)


def _at_quarantine(current, body, what):
    require(current["epoch"] == body["quarantine_epoch"] and membership.digest(current) == body["quarantine_digest"],
            "the %s is for epoch %d's manifest; this node's is epoch %d: a new epoch ends it" % (what, body["quarantine_epoch"], current["epoch"]))


# ---- the authorization ----

def validate_authorization(auth):
    """Schema only. Returns (not_before, expires_at) in seconds."""
    membership.exact(auth, AUTH_KEYS, "the survivor authorization")
    require(auth["schema"] == AUTH_SCHEMA, "schema must be %s" % AUTH_SCHEMA)
    require(isinstance(auth["node_id"], str) and NODE_ID.fullmatch(auth["node_id"]) is not None, "node_id must be a node ID")
    _epoch_bound(auth, "the authorization")
    _text(auth["fenced"], "fenced")
    start, expires = heartbeat.parse_time(auth["not_before"], "not_before"), heartbeat.parse_time(auth["expires_at"], "expires_at")
    require(start < expires, "the authorization's expires_at must be after its not_before")
    require(expires - start <= MAX_AUTHORIZATION_S, "a survivor authorization lives at most %d s (this one: %d)" % (MAX_AUTHORIZATION_S, expires - start))
    return start, expires


def authorization_message(auth):
    validate_authorization(auth)
    return AUTH_DOMAIN + membership.canonical(auth)


def verify_authorization(signed, current, node_id=None):
    """The authorization in `signed` ({"authorization", "signature"}) if it holds against the CURRENT manifest (module
    docstring), else Refused. With `node_id`, it must be that node's."""
    membership.exact(signed, ("authorization", "signature"), "the signed survivor authorization")
    auth = signed["authorization"]
    validate_authorization(auth)
    _owner_signed(current, authorization_message(auth), signed["signature"], "survivor authorization")
    _at_quarantine(current, auth, "survivor authorization")
    nodes = membership.validate(current)
    survivor = auth["node_id"]
    require(survivor in nodes and nodes[survivor]["state"] not in membership.NOT_COUNTING,
            "%s does not count under epoch %d: it is no survivor" % (survivor, current["epoch"]))
    loose = sorted(n for n, node in nodes.items() if n != survivor and node["state"] not in membership.NOT_COUNTING)
    require(not loose, "a lone survivor needs every other node quarantined, revoked or retired under epoch %d; %s %s not"
            % (current["epoch"], ", ".join(loose), "is" if len(loose) == 1 else "are"))
    if node_id is not None:
        require(survivor == node_id, "the survivor authorization is for %s, not %s" % (survivor, node_id))
    return auth


def in_force(signed, current, node_id, now):
    """The authorization's expiry (seconds) if it holds for `node_id` at `now` (its authenticated seconds), else Refused."""
    auth = verify_authorization(signed, current, node_id)
    start, expires = validate_authorization(auth)
    require(start <= now + heartbeat.FUTURE_SKEW, "the survivor authorization starts at %s, ahead of this node's clock" % auth["not_before"])
    require(now < expires, "EXPIRED: the survivor authorization ended at %s: the owner signs a new one, or the servers return" % auth["expires_at"])
    return expires


def _stamp(seconds):
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(seconds)))


def make_authorization(tip, survivor, how, now, confirm, open_signer, life_s=None):
    """The owner's survivor authorization (owner.py sign-survivor, off the nodes). `tip`: the survivor's newest manifest,
    verified from the pinned root by the caller: the quarantine manifest. `how`: what was done to the other servers.
    Refused unless every other node has stopped counting in `tip` and the line naming survivor, epoch and expiry is
    typed. Returns {"authorization", "signature"}."""
    nodes = membership.validate(tip)
    others = sorted(n for n in nodes if n != survivor)
    _text(how, "how the other servers are fenced")
    life = MAX_AUTHORIZATION_S if life_s is None else int(life_s)
    require(0 < life <= MAX_AUTHORIZATION_S, "a survivor authorization lives at most %d s" % MAX_AUTHORIZATION_S)
    auth = {"schema": AUTH_SCHEMA, "node_id": survivor, "quarantine_epoch": tip["epoch"], "quarantine_digest": membership.digest(tip),
            "not_before": _stamp(now), "expires_at": _stamp(now + life),
            "fenced": "%s: %s; they will not rejoin until they hold epoch %d" % (", ".join(others), how.strip(), tip["epoch"])}
    validate_authorization(auth)
    loose = sorted(n for n in others if nodes[n]["state"] not in membership.NOT_COUNTING)
    require(not loose, "quarantine %s first (a root- or owner-signed epoch): a survivor is authorized only once every other server "
            "has stopped counting" % ", ".join(loose))
    require(survivor in nodes and nodes[survivor]["state"] not in membership.NOT_COUNTING, "%s does not count under epoch %d" % (survivor, tip["epoch"]))
    want = "authorize %s alone %d until %s" % (survivor, tip["epoch"], auth["expires_at"])
    shown = ("A SURVIVOR AUTHORIZATION: %s serves ALONE, stateless operations only, until %s or until any new epoch, under epoch %d:\n"
             "  attested: %s\n  If any of %s is alive and can reach another server, or rejoins before it holds epoch %d, two sides can\n"
             "  act on key state. STOP if so.\nType exactly: %s\n> " % (survivor, auth["expires_at"], tip["epoch"], auth["fenced"],
                                                                       ", ".join(others), tip["epoch"], want))
    require((confirm(shown) or "").strip() == want, "the line typed is not this authorization's: nothing is signed")
    owners = {e["key"] for e in tip["owner_keys"] if e["alg"] == "ed25519"}
    signer = open_signer()
    require(signer.public() in owners, "the token's key is not one of the tip manifest's owner_keys: nothing is signed")
    signed = {"authorization": auth, "signature": {"party": membership.OWNER, "key": signer.public(),
                                                   "sig": signer.sign(authorization_message(auth)).hex()}}
    verify_authorization(signed, tip, survivor)
    return signed


# ---- the directive: disable-only ----

def validate_directive(directive):
    membership.exact(directive, DIRECTIVE_KEYS, "the survivor directive")
    require(directive["schema"] == DIRECTIVE_SCHEMA, "schema must be %s" % DIRECTIVE_SCHEMA)
    require(isinstance(directive["object_id"], str) and NAME.fullmatch(directive["object_id"]) is not None, "object_id must be a name")
    require(directive["state"] in DIRECTIVE_STATES, "a directive only disables or destroys (%s), never %r: re-enabling a key is D25's "
            "approvers' act on the majority" % (", ".join(DIRECTIVE_STATES), directive["state"]))
    _epoch_bound(directive, "the directive")
    heartbeat.parse_time(directive["issued_at"], "issued_at")
    _text(directive["reason"], "reason")


def directive_message(directive):
    validate_directive(directive)
    return DIRECTIVE_DOMAIN + membership.canonical(directive)


def verify_directive(signed, at_quarantine):
    """The directive in `signed` if the owner signed it under the manifest it names (`at_quarantine`: the chain's
    manifest at its quarantine_epoch, verified by the caller), else Refused. Judged against that manifest, not the
    current one, so the majority can still verify and commit it after the recovery's epoch has passed."""
    membership.exact(signed, ("directive", "signature"), "the signed survivor directive")
    directive = signed["directive"]
    _owner_signed(at_quarantine, directive_message(directive), signed["signature"], "survivor directive")
    _at_quarantine(at_quarantine, directive, "survivor directive")
    return directive


def make_directive(tip, object_id, state, reason, now, confirm, open_signer):
    """The owner's directive (owner.py sign-directive, off the nodes): `object_id` disabled or destroyed, under the
    quarantine manifest `tip`. Returns {"directive", "signature"}."""
    directive = {"schema": DIRECTIVE_SCHEMA, "object_id": object_id, "state": state, "quarantine_epoch": tip["epoch"],
                 "quarantine_digest": membership.digest(tip), "issued_at": _stamp(now), "reason": reason}
    validate_directive(directive)
    want = "%s %s" % (state, object_id)
    shown = ("A SURVIVOR DIRECTIVE under epoch %d: the key %s becomes %s at once on the survivor, and on the majority when it returns.\n"
             "  reason: %s\n  %s\nType exactly: %s\n> " % (tip["epoch"], object_id, state.upper(), reason,
                                                           "DESTROYED IS FINAL." if state == "destroyed" else "Re-enabling it later takes D25's approvers.", want))
    require((confirm(shown) or "").strip() == want, "the line typed is not this directive's: nothing is signed")
    owners = {e["key"] for e in tip["owner_keys"] if e["alg"] == "ed25519"}
    signer = open_signer()
    require(signer.public() in owners, "the token's key is not one of the tip manifest's owner_keys: nothing is signed")
    signed = {"directive": directive, "signature": {"party": membership.OWNER, "key": signer.public(),
                                                    "sig": signer.sign(directive_message(directive)).hex()}}
    verify_directive(signed, tip)
    return signed


class Directives:
    """The survivor's applied directives, {object_id: state}, in `path` (its state directory). A state only ever rises
    (enabled < disabled < destroyed): applying a directive that would lower one changes nothing. The daemon refuses every
    key named here (not built: ed)."""

    def __init__(self, path):
        self.path = path

    def held(self):
        try:
            with open(self.path, "rb") as f:
                raw = f.read(1024 * 1024 + 1)
        except FileNotFoundError:
            return {}
        require(len(raw) <= 1024 * 1024, "the directives file is oversized")
        states = membership.load(raw)
        require(isinstance(states, dict) and all(isinstance(k, str) and v in DIRECTIVE_STATES for k, v in states.items()),
                "the directives file is not {object_id: disabled|destroyed}")
        return states

    def apply(self, directive):
        """Apply a VERIFIED directive. Returns the object's state after it (the higher of the held and the directed)."""
        validate_directive(directive)
        states = self.held()
        before = states.get(directive["object_id"], "enabled")
        after = directive["state"] if RANK[directive["state"]] > RANK[before] else before
        if after != before:
            states[directive["object_id"]] = after
            directory = os.path.dirname(os.path.abspath(self.path))
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".directives-")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(states, f, sort_keys=True)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, self.path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
        return after
