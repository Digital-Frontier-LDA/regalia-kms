#!/usr/bin/env python3
"""The external collector's D25 check (ADR-0002 D32, #432; regalia-kms-1e's item): every approval-gated signature a
server's audit stream records names EXACTLY ONE committed spend, and that spend is the one the signature was made under.

A server spends an approval in etcd (deploy/baremetal/opstate.py: a `spend` entry at nonces/<sha256(nonce)>, created
only) BEFORE its HSM signs, and its audit line for the signature CARRIES that spend and the session entry that vouches
for the spend's signing key (agreed with regalia-kms-48 on #492 and regalia-kms-ed's lane; spends and sessions are
garbage-collected from etcd, so a line must verify against the membership chain alone, a late or replayed backlog too):

    "detail": {"spend": {"key": "/regalia/v1/nonces/<hex>", "mod_revision": <int>, "entry_sha256": "<64 hex>",
                         "value": {"entry": {...}, "signatures": [...]}},
               "session": {"key": "/regalia/v1/sessions/<node>/<boot>/<key>", "value": {"entry": {...}, "signature": ...}},
               "payload_sha256": "<64 hex>", "approvals": [<internal/approval.Approval as received>, ...]}

At most MAX_DETAIL bytes (internal/audit's maxDetail, 48 KiB): a spend entry is at most 4096 bytes and a spend counts at
most 64 approvals, which fits.

check() refuses a signature, by name, unless:
  * its line carries a spend whose entry hashes to entry_sha256 and lives at that key, signed by a session key that the
    carried session entry vouches for under the chain (opstate.verify_session, its window), the entry inside it;
  * the spend's node is the server whose stream recorded the signature, and its principal, object, purpose and
    payload are the signature's own;
  * the signature's time lies in [the spend's at, at + MAX_REQUEST_LIFE_S]: two signed times, not the collector's clock
    (regalia-kms-ed's lane). Where the collector watched the spend's create live, it also checks `at` against its own
    clock on arrival (opstate.fresh) and that the line's revision and entry are what etcd committed;
  * the approvals the line carries are the ones the spend counted (opstate.check_approvals: each signed by its
    approver over the request's v3 binding, for THAT node, the threshold met), and exactly the approvers the daemon
    recorded as verified;
  * no other signature, on any server, names the same spend: the nonce key is the request's, so pairing across every
    stream catches a double spend even when etcd's copy is gone.
A spend no signature names is not a fault: a lapse between commit and sign burns it (opstate.may_sign), and a sign
that failed after its spend writes no signature line. Those the collector watched are counted, so a run of burns shows.

Which signatures are approval-gated is the POLICY's to say (`gated(event)`), never the line's: a gated signature whose
line names no spend is the very thing this check exists to catch.

CURRENT LIMITATIONS: detection, not prevention (a root on a server can sign through PKCS#11 outside the gate, and this
is how that is found, ADR-0002 D32). A line's own spend proves its node signed that spend, not that etcd committed it:
only a collector that watched the create sees that (the cross-check); a replayed backlog without the watch proves
single use across the lines it holds, not against etcd. It judges the streams the collector received; a server that
withholds its stream is the completeness check's to find (audit_complete).
"""
import datetime

from deploy.baremetal import membership, opstate

Refused, require = membership.Refused, membership.require

SPEND_REF = ("key", "mod_revision", "entry_sha256", "value")
SESSION_REF = ("key", "value")
MAX_DETAIL = 48 << 10


def _when(text, what):
    """An RFC 3339 time (the audit event's, Go's RFC3339Nano, or the entries' whole seconds) as Unix seconds."""
    require(isinstance(text, str) and text.endswith("Z"), "%s is not an RFC 3339 UTC time" % what)
    try:
        return datetime.datetime.fromisoformat(text[:-1] + "+00:00").timestamp()
    except ValueError:
        raise Refused("%s is not an RFC 3339 UTC time" % what) from None


def _carried(event, chain, approver_sets):
    """The spend an approval-gated event's line carries, verified against the chain alone, with the line's detail."""
    rid = event.get("request_id")
    detail = event.get("detail")
    require(isinstance(detail, dict) and isinstance(detail.get("spend"), dict),
            "request %s: an approval-gated signature whose audit line names no spend" % rid)
    require(len(membership.canonical(detail)) <= MAX_DETAIL, "request %s's detail is over %d bytes" % (rid, MAX_DETAIL))
    ref = detail["spend"]
    membership.exact(ref, SPEND_REF, "request %s's spend" % rid)
    require(isinstance(ref["key"], str) and ref["key"].startswith(opstate.PREFIX + "nonces/"), "request %s names a spend outside nonces/" % rid)
    require(isinstance(ref["mod_revision"], int) and not isinstance(ref["mod_revision"], bool) and ref["mod_revision"] >= 1,
            "request %s's spend revision is not a revision" % rid)
    membership.hex_field(ref["entry_sha256"], 64, "request %s's spend entry_sha256" % rid)
    membership.hex_field(detail.get("payload_sha256"), 64, "request %s's payload_sha256" % rid)
    require(isinstance(detail.get("approvals"), list), "request %s's line carries no approvals" % rid)
    require(isinstance(detail.get("session"), dict), "request %s's line carries no session entry for its spend's key" % rid)
    membership.exact(detail["session"], SESSION_REF, "request %s's session" % rid)
    session, valid_until = opstate.verify_session(detail["session"]["key"], detail["session"]["value"], chain)

    def sessions(node_id, boot_id, key, at):
        t = _when(at, "the spend's at")
        return (session["node_id"], session["boot_id"], session["session_key"]) == (node_id, boot_id, key) and \
            _when(session["issued_at"], "the session's issued_at") <= t and (valid_until is None or t < _when(valid_until, "valid_until"))
    entry = opstate.verify(ref["key"], ref["value"], sessions, approver_sets)
    require(entry["kind"] == "spend", "request %s names %s, which is not a spend" % (rid, ref["key"]))
    require(opstate.entry_digest(entry) == ref["entry_sha256"], "request %s's spend entry does not hash to its entry_sha256" % rid)
    return ref, detail, entry


def check(streams, chain, gated, approver_sets, watched=None):
    """`streams`: {node_id: [audit events, as the collector holds them]}; `chain`: the verified membership chain (oldest
    first), whose signing keys vouch for the sessions; `gated(event)`: whether the policy gates that event's purpose;
    `approver_sets` as opstate.verify takes them; `watched`: the spends the collector saw created live, {etcd key:
    {"value", "mod_revision", "arrived": unix seconds on its authenticated clock}}, or None for a replayed backlog.
    Returns {"signatures": n, "watched": n, "burned": [watched keys no signature names]}, or Refused at the first fault."""
    paired = {}
    signatures = 0
    for node_id in sorted(streams):
        for event in streams[node_id]:
            if not (event.get("decision") == "allow" and event.get("outcome") == "success" and gated(event)):
                continue
            signatures += 1
            rid = event.get("request_id")
            ref, detail, entry = _carried(event, chain, approver_sets)
            require(entry["node_id"] == node_id, "request %s was signed on %s under a spend %s committed for %s"
                    % (rid, node_id, ref["key"], entry["node_id"]))
            for field, mine in (("principal", event.get("principal")), ("object_id", event.get("object_id")),
                                ("purpose", event.get("purpose")), ("payload_sha256", detail["payload_sha256"])):
                require(entry[field] == mine, "request %s's %s is %r; its spend's is %r" % (rid, field, mine, entry[field]))
            signed, spent = _when(event.get("timestamp"), "request %s's timestamp" % rid), _when(entry["at"], "the spend's at")
            require(spent <= signed <= spent + opstate.MAX_REQUEST_LIFE_S, "request %s was signed at %s, outside [%s, %s + %d s] of its spend"
                    % (rid, event.get("timestamp"), entry["at"], entry["at"], opstate.MAX_REQUEST_LIFE_S))
            if watched is not None:
                held = watched.get(ref["key"])
                require(held is not None, "request %s on %s carries the spend %s, which the collector never saw committed"
                        % (rid, node_id, ref["key"]))
                require(held["mod_revision"] == ref["mod_revision"] and held["value"] == ref["value"],
                        "request %s carries %s at revision %d; etcd committed another entry or revision (%d)"
                        % (rid, ref["key"], ref["mod_revision"], held["mod_revision"]))
                opstate.fresh(entry, held["arrived"])
            counted = opstate.check_approvals(entry, detail["approvals"], approver_sets)
            require(counted == sorted(event.get("verified_approvers") or []),
                    "request %s recorded approvers %s; the approvals behind its spend are %s's"
                    % (rid, sorted(event.get("verified_approvers") or []), counted))
            require(ref["key"] not in paired, "the spend %s is named by two signatures: %s and %s"
                    % (ref["key"], paired.get(ref["key"]), rid))
            paired[ref["key"]] = rid
    watched = watched or {}
    spends = [k for k in watched if k.startswith(opstate.PREFIX + "nonces/")]
    return {"signatures": signatures, "watched": len(spends), "burned": sorted(k for k in spends if k not in paired)}
