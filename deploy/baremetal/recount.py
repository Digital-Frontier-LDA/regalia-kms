#!/usr/bin/env python3
"""Recount: give a node's heartbeat sequence counter (heartbeat.Counter, nv_heartbeat) a new TPM definition
when it is unusable (#244). The membership anchor has reanchor.py; this is its counterpart for the counter
that has no record. (#199 retired the revocation authority and its own sequence counter.)

A sequence counter refuses a heartbeat at or below what it holds (a replay). Since #182 a counter or base
whose NV attributes are not exactly this software's is refused as Unusable, and so is a counter whose
index is gone: every heartbeat is then refused, by design, and nothing a peer sends can repair it.

A NEW COUNTER FORGETS WHAT THE TPM KNEW, so it is fenced as reanchor.py is:

  * AN OPERATOR, ON THE HOST, by hand, from the HOST'S OWN CONFIGURATION (node.json): the TPM, the
    counter's index (nv_heartbeat), the membership anchor's (nv_epoch) and the chain all come from it. There is no free index: the counter can never be pointed at the anchor.
  * THE TPM AND THE CHAIN ARE PROVEN THE HOST'S: before anything, the chain on disk is verified from the
    root key AND against the membership anchor on the same TPM (#182's lock-free check). A wrong TPM, or a
    stale or forked chain (whose old revocation key could otherwise sign its way to a floor), is refused.
  * NOTHING ELSE TOUCHES THE COUNTER MEANWHILE: regalia-sync (the service that advances it) must be
    stopped, and recount takes the counter's own lock, built by the same code the service uses.
  * A USABLE COUNTER IS NEVER RESET (judged by the counter's own read: a counter keeps no record).
  * A TPM THAT DOES NOT ANSWER IS NOT RECOUNTED: only an index the TPM says is missing or wrong is.
  * NEVER BELOW WHAT IS KNOWN, EVEN ACROSS A CUT. The new counter is defined AT a floor: the highest of
    what the old counter still reads (whatever its attributes), every given heartbeat that verifies
    against the current manifest (heartbeat.signed; a stranger's raises nothing; at least one is needed),
    and every floor an earlier run planned for this index. That last is written, and fsynced, to a
    root-only file in the state directory BEFORE the first index is deleted: a run cut after deleting
    the old counter (which then reads nothing) cannot let the rerun plan lower. Floors only rise.
  * VERIFIED FIRST, TYPED, RECORDED: everything is checked before anything changes; the operator types a
    phrase naming the index and the floor; the request is appended to the audit log before anything is
    asked or changed, then the outcome (ALLOW, DENY, or INCOMPLETE: run it again).

The heartbeats a floor is taken from: the node's own freshness state (by default). If it is lost, the nodes'
latest heartbeat is in any other node's freshness state: give that file with --heartbeat.

When the membership anchor is unusable too (a replaced TPM), the chain cannot be proven and this refuses:
re-anchor first (reanchor.py), then recount.

    python3 -Es -m deploy.baremetal.recount --config /etc/regalia/node.json --audit-log /var/log/regalia/recount.jsonl

It needs the TPM's owner authorization, as defining the counter did.
"""
import argparse
import json
import os
import re
import sys
import time

from deploy.baremetal import heartbeat, membership, trails

Refused, require = membership.Refused, membership.require


class Incomplete(Exception):
    """The counter was being replaced and the operation did not finish: run the command again."""


def envelopes_in(document):
    """The heartbeat envelopes a file holds: a bare envelope, or a node's freshness state ({"envelope": ...})."""
    if isinstance(document, dict) and "heartbeat" in document:
        return [document]
    if isinstance(document, dict) and isinstance(document.get("envelope"), dict):
        return [document["envelope"]]
    return []


def carried(path):
    """The floor earlier runs planned for this counter (0 if none): floors only rise. Refused if the file
    exists and cannot be read: a lost floor is exactly what it guards against."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return 0
    try:
        document = membership.load(os.read(fd, 4096), 4096)
    finally:
        os.close(fd)
    require(isinstance(document, dict) and isinstance(document.get("floor"), int) and document["floor"] >= 0, "%s is not a recount floor" % path)
    return document["floor"]


def carry(path, floor):
    """Write the planned floor, durably, before anything is deleted (0600, atomically)."""
    import tempfile
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".recount-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps({"floor": floor}).encode())
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    entry = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(entry)
    finally:
        os.close(entry)


def current(chain, root_key, anchor):
    """The current manifest: the chain verified from the root key AND against the membership anchor on
    this TPM, so the TPM is proven the host's and the chain the one it anchored (not stale, not a fork)."""
    manifest = membership.accept_chain(None, chain, root_key)
    manifests = [e["manifest"] for e in chain]

    def digest_of(epoch):
        require(epoch <= len(manifests), "the chain ends at epoch %d, below this TPM's anchor %d: not the current chain" % (len(manifests), epoch))
        return membership.digest(manifests[epoch - 1]) if epoch else membership.HighWater.ZERO
    anchor.verify(digest_of, lock=False)
    return manifest


def plan(counter, manifest, documents, prior=0):
    """What a recount would do, verified without changing anything: {"reason": why the counter is unusable,
    "old": what the old counter still reads or None, "held": [(sequence, epoch), ...] of the verified
    heartbeats, "prior": the floor an earlier run planned, "floor": the new counter's value}."""
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
            "freshness state, or another node's")
    floor = max([old or 0, prior] + [sequence for sequence, _ in held])
    return {"reason": reason, "old": old, "held": sorted(held), "prior": prior, "floor": floor}


def phrase(index, planned):
    return "recount %s at %d" % (index, planned["floor"])


def recount(counter, manifest, documents, typed, sink, floor_path):
    """Plan, record the request, check what the operator typed, carry the floor, redefine the counter at the
    floor, record the outcome. Returns the new counter's value."""
    def event(kind, planned, **more):
        return dict({"event": kind, "peer": "operator", "index": counter.index, "floor": planned.get("floor", 0),
                     "old": planned.get("old"), "held": planned.get("held", []), "counter_was": planned.get("reason", "")}, **more)

    try:
        planned = plan(counter, manifest, documents, carried(floor_path))
    except BaseException as refusal:              # any failure to plan is recorded, an OSError on the floor file too
        sink(event("recount", {}, outcome="DENY", reason=str(refusal)[:240] or type(refusal).__name__))
        raise
    sink(event("recount-requested", planned))
    began = []
    try:
        require(typed(dict(planned)) == phrase(counter.index, planned), "not confirmed: the phrase typed is not %r" % phrase(counter.index, planned))
        carry(floor_path, planned["floor"])           # durable BEFORE anything is deleted: a cut cannot lower it
        with membership._exclusive(counter.lock_path):
            defined = counter._defined()
            for index in counter._indices():
                if int(index, 16) in defined:
                    began.append(index)
                    require(counter._tpm("nvundefine", index, "-C", "o").returncode == 0, "cannot delete NV index %s" % index)
            began.append("define")
            counter._define_at(planned["floor"])           # under the same lock; no increment loop up to the floor
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


def main(argv=None, ask=None, run=None):
    """Exit status: 0 done; 1 refused, nothing changed; 2 usage; 3 INCOMPLETE: run it again."""
    from deploy.baremetal import node
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.recount", description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True, help="this host's node.json")
    ap.add_argument("--heartbeat", action="append", default=[], metavar="FILE",
                    help="another heartbeat to take the floor from (e.g. another node's freshness state); repeatable")
    ap.add_argument("--audit-log", default=trails.where("recount"),
                    help="the audit trail (default %(default)s, its place in trails.py's registry)")
    args = ap.parse_args(argv)

    def record(event):                 # hash-chained, whole or not at all, never through a link (trails.py, #278)
        try:
            trails.append(args.audit_log, dict(event, time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        except trails.Refused as refused:  # an unwritable trail, as an OSError from the file would be
            raise OSError(str(refused)) from refused

    try:
        require("TPM2TOOLS_TCTI" not in os.environ, "TPM2TOOLS_TCTI is set in the environment: the TPM is the configuration's; unset it")
        raw = _read_json(args.config, 64 * 1024)
        require(isinstance(raw, dict) and raw.get("schema") == node.SCHEMA, "--config must be a node configuration")
        import subprocess
        run = run or subprocess.run
        cfg = node.validate(raw)
        index, defaults = cfg["nv_heartbeat"], [os.path.join(cfg["state_dir"], "freshness.json")]
        counter = node.heartbeat_counter(cfg, run)                # the service's own construction and lock
        active = run(["systemctl", "is-active", "regalia-sync.service"], capture_output=True, timeout=10)
        status = active.stdout.decode(errors="replace").strip()
        # only a stopped service passes: "activating", "deactivating", "reloading" or a systemctl that failed
        # (no answer) count as running
        require(status in ("inactive", "failed"), "regalia-sync is not stopped (%s): it advances this counter; stop it first "
                "(systemctl stop regalia-sync)" % (status or "no answer from systemctl"))
        state = cfg["state_dir"]
        missing = [path for path in args.heartbeat if not os.path.exists(path)]
        require(not missing, "--heartbeat %s does not exist" % ", ".join(missing))
        # a node's anchor may be written by policy (#242): read it with the node's approved-image policy
        anchor = membership.HighWater(cfg["nv_epoch"], cfg["tcti"], run, lock_path=os.path.join(state, "highwater.lock"),
                                      policy=lambda: node.image_policy(cfg))
        chain = _read_json(os.path.join(state, "membership.json"), membership.MAX_CHAIN_BYTES)
        require(isinstance(chain, list) and chain, "the host holds no membership chain")
        manifest = current(chain, cfg["root_key"], anchor)
        documents = [_read_json(path, heartbeat.MAX_BYTES * 2) for path in [p for p in defaults if os.path.exists(p)] + args.heartbeat]
        tpm = cfg["tcti"] or "the default TPM"

        def typed(planned):
            print("TPM: %s, the counter's NV index %s (from %s)." % (tpm, index, args.config))
            print("The sequence counter is unusable: %s" % planned["reason"])
            print("The old counter %s." % ("cannot be read" if planned["old"] is None else "reads %d" % planned["old"]))
            if planned["prior"]:
                print("An earlier run planned a floor of %d." % planned["prior"])
            for sequence, epoch in planned["held"]:
                print("A verified heartbeat: sequence %d, epoch %d." % (sequence, epoch))
            print("Recounting DELETES this counter and defines a new one reading %d: nothing at or below it is accepted again." % planned["floor"])
            try:
                return (ask or input)("Type exactly: %s\n> " % phrase(index, planned))
            except EOFError:
                return None
        value = recount(counter, manifest, documents, typed, record, os.path.join(state, "recount-floor-%s.json" % index))
    except Incomplete as failure:
        print("INCOMPLETE: %s: run it again" % failure, file=sys.stderr)
        return 3
    except (Refused, OSError, ValueError) as failure:
        print("REFUSED: %s" % failure, file=sys.stderr)
        return 1
    print("the counter %s now reads %d" % (index, value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
