#!/usr/bin/env python3
"""Recount: give a heartbeat sequence counter a new TPM definition when it is unusable (#244), for a node's
heartbeat counter (heartbeat.Counter, nv_heartbeat) or the revocation authority's own sequence counter
(authority.py, nv_sequence). The membership anchor has reanchor.py; this is its counterpart for the
counters that have no record.

A sequence counter refuses a heartbeat at or below what it holds (a replay). Since #182 a counter or base
whose NV attributes are not exactly this software's is refused as Unusable, and so is a counter whose
index is gone: every heartbeat is then refused, by design, and nothing a peer sends can repair it.

A NEW COUNTER FORGETS WHAT THE TPM KNEW, so it is fenced as reanchor.py is:

  * AN OPERATOR, ON THE HOST, by hand. Nothing calls this from a service.
  * A USABLE COUNTER IS NEVER RESET: if it reads and its attributes are this software's, this refuses.
  * A TPM THAT DOES NOT ANSWER IS NOT RECOUNTED: only an index the TPM says is missing or wrong is.
  * NEVER BELOW WHAT IS KNOWN. The new counter is defined AT a floor: the highest of what the old counter
    still reads (whatever its attributes), and every heartbeat given that verifies (heartbeat.signed: well
    formed, signed by a revocation key the CURRENT manifest names, any epoch). At least one such heartbeat
    is required: the node's own held heartbeat (its freshness state), or the authority's latest published
    or pending one. A heartbeat signed by nobody the manifest names raises nothing. The next genuine
    heartbeat is above the floor; nothing at or below it is ever accepted again.
  * VERIFIED FIRST, TYPED, RECORDED: everything is checked before anything changes; the operator types a
    phrase naming the index and the floor; the request is appended to the audit log before anything is
    asked or changed, then the outcome (ALLOW, DENY, or INCOMPLETE: run it again).

    python3 -Es -m deploy.baremetal.recount --membership /var/lib/regalia-sync/membership.json --root-key HEX \\
        --tpm-index 0x1500018 --heartbeat /var/lib/regalia-sync/freshness.json --audit-log /var/log/regalia/recount.jsonl \\
        --tcti device:/dev/tpmrm0

It needs the TPM's owner authorization, as defining the counter did.
"""
import argparse
import json
import os
import re
import sys
import time

from deploy.baremetal import heartbeat, membership

Refused, require = membership.Refused, membership.require


class Incomplete(Exception):
    """The counter was being replaced and the operation did not finish: run the command again."""


def envelopes_in(document):
    """The heartbeat envelopes a file holds: a bare envelope (the authority's heartbeat.json or pending
    file), or a node's freshness state ({"envelope": ...})."""
    if isinstance(document, dict) and "heartbeat" in document:
        return [document]
    if isinstance(document, dict) and isinstance(document.get("envelope"), dict):
        return [document["envelope"]]
    return []


def plan(counter, manifest, documents):
    """What a recount would do, verified without changing anything: {"reason": why the counter is unusable,
    "old": what the old counter still reads or None, "held": [(sequence, epoch), ...] of the verified
    heartbeats, "floor": the new counter's value}."""
    # A counter keeps no record, so HighWater.unusable() (which judges the record too) is not the test: the
    # counter's own read is. Unusable means the counter itself is wrong; any other refusal (a TPM that does
    # not answer) says nothing about it and is raised.
    try:
        counter.value()
        reason = None
    except membership.Unusable as unusable:
        reason = str(unusable)
    require(reason is not None, "the counter is usable: it is not reset")
    old, _ = counter.remains()
    held = []
    for document in documents:
        for envelope in envelopes_in(document):
            try:
                body, _, _ = heartbeat.signed(envelope, manifest)
            except Refused:
                continue                          # signed by nobody the manifest names: it raises nothing
            held.append((body["sequence"], body["epoch"]))
    require(held, "no heartbeat given verifies against the current manifest: the floor cannot be known. Give the node's "
            "freshness state, or the authority's latest heartbeat")
    floor = max([old or 0] + [sequence for sequence, _ in held])
    return {"reason": reason, "old": old, "held": sorted(held), "floor": floor}


def phrase(index, planned):
    return "recount %s at %d" % (index, planned["floor"])


def recount(counter, manifest, documents, typed, sink):
    """Plan, record the request, check what the operator typed, redefine the counter at the floor, record
    the outcome. Returns the new counter's value."""
    def event(kind, planned, **more):
        return dict({"event": kind, "peer": "operator", "index": counter.index, "floor": planned.get("floor", 0),
                     "old": planned.get("old"), "held": planned.get("held", []), "counter_was": planned.get("reason", "")}, **more)

    try:
        planned = plan(counter, manifest, documents)
    except Refused as refusal:
        sink(event("recount", {}, outcome="DENY", reason=str(refusal)[:240]))
        raise
    sink(event("recount-requested", planned))
    began = []
    try:
        require(typed(dict(planned)) == phrase(counter.index, planned), "not confirmed: the phrase typed is not %r" % phrase(counter.index, planned))
        with membership._exclusive(counter.lock_path):
            defined = counter._defined()
            for index in (counter.index, counter.base_index):
                if int(index, 16) in defined:
                    began.append(index)
                    require(counter._tpm("nvundefine", index, "-C", "o").returncode == 0, "cannot delete NV index %s" % index)
            began.append("define")
            counter._define_counter(planned["floor"])
        value = counter.value()
        require(value == planned["floor"], "the new counter reads %d, not the floor %d" % (value, planned["floor"]))
    except BaseException as failure:
        if not began:
            sink(event("recount", planned, outcome="DENY", reason=str(failure)[:240] or type(failure).__name__))
            raise
        sink(event("recount", planned, outcome="INCOMPLETE", reason=str(failure)[:240] or type(failure).__name__))
        raise Incomplete(str(failure) or type(failure).__name__) from failure
    sink(event("recount", planned, outcome="ALLOW", reason=""))
    return value


def _read_json(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return membership.load(os.read(fd, limit + 1), limit)
    finally:
        os.close(fd)


def main(argv=None, ask=None, counter_for=None):
    """Exit status: 0 done; 1 refused, nothing changed; 2 usage; 3 INCOMPLETE: run it again."""
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.recount", description=__doc__.splitlines()[0])
    ap.add_argument("--membership", required=True, help="the membership chain this host holds (its store's file)")
    ap.add_argument("--root-key", required=True, help="the pinned membership root key")
    ap.add_argument("--tpm-index", required=True, help="the counter's NV index (a node's nv_heartbeat, or the authority's nv_sequence)")
    ap.add_argument("--heartbeat", action="append", default=[], metavar="FILE",
                    help="a node's freshness state, or the authority's heartbeat or pending file; at least one, repeat for more")
    ap.add_argument("--audit-log", required=True, help="the file the audit events are appended to")
    ap.add_argument("--tcti", help="the TPM, as a TCTI (e.g. device:/dev/tpmrm0); default: tpm2-tools' default TPM")
    args = ap.parse_args(argv)
    tpm = args.tcti or "the default TPM"

    def record(event):
        line = json.dumps(dict(event, tpm=tpm, time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())), sort_keys=True)
        fd = os.open(args.audit_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (line + "\n").encode())
            os.fsync(fd)
        finally:
            os.close(fd)

    def typed(planned):
        print("TPM: %s, NV index %s." % (tpm, args.tpm_index))
        print("The sequence counter is unusable: %s" % planned["reason"])
        print("The old counter %s." % ("cannot be read" if planned["old"] is None else "reads %d" % planned["old"]))
        for sequence, epoch in planned["held"]:
            print("A verified heartbeat: sequence %d, epoch %d." % (sequence, epoch))
        print("Recounting DELETES this counter and defines a new one reading %d: nothing at or below it is accepted again." % planned["floor"])
        try:
            return (ask or input)("Type exactly: %s\n> " % phrase(args.tpm_index, planned))
        except EOFError:
            return None

    try:
        require(re.fullmatch(r"0x[0-9a-fA-F]{1,8}", args.tpm_index) is not None, "--tpm-index must be 0x and up to 8 hex digits")
        require("TPM2TOOLS_TCTI" not in os.environ, "TPM2TOOLS_TCTI is set in the environment: name the TPM with --tcti instead, or unset it")
        require(args.heartbeat, "give at least one --heartbeat file")
        chain = _read_json(args.membership, membership.MAX_CHAIN_BYTES)
        require(isinstance(chain, list) and chain, "the membership file holds no chain")
        manifest = membership.accept_chain(None, chain, args.root_key)
        documents = [_read_json(path, heartbeat.MAX_BYTES * 2) for path in args.heartbeat]
        counter = (counter_for or (lambda index, tcti: heartbeat.Counter(index, tcti)))(args.tpm_index, args.tcti)
        value = recount(counter, manifest, documents, typed, record)
    except Incomplete as failure:
        print("INCOMPLETE: %s: run it again" % failure, file=sys.stderr)
        return 3
    except (Refused, OSError, ValueError) as failure:
        print("REFUSED: %s" % failure, file=sys.stderr)
        return 1
    print("the counter %s now reads %d" % (args.tpm_index, value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
