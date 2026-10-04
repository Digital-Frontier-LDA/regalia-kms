#!/usr/bin/env python3
"""Update: the acting half of a rolling image update (#75, Phase 15; KERNEL-UPDATE.md, step 3). rollout.py
reads and decides, and never changes anything; this sets the firmware's BootNext and reboots the host into
its new image (apply), makes the image the host came up on its default (promote), and removes a retired
image's boot entry (forget). Run on the node, as root, by hand.

    python3 -Es -m deploy.baremetal.update apply   --config /etc/regalia/node.json --entry 0003 [--esp /efi] [--deadline-minutes 15]
    python3 -Es -m deploy.baremetal.update promote --config /etc/regalia/node.json [--esp /efi]
    python3 -Es -m deploy.baremetal.update forget  --config /etc/regalia/node.json --entry 0001 [--esp /efi]
    python3 -Es -m deploy.baremetal.update status  --config /etc/regalia/node.json [--esp /efi] [--json] [--require-promoted]

APPLY refuses unless all of this holds, from the host's own state, never from files an operator collected:
  1  the manifest is this node's published chain, verified from the root key and against the TPM's
     high-water (node.manifest, as the root services read it), and the measurement document is the one it
     commits to;
  2  the set this host RUNS is read from its TPM: its PCRs, as booted, match exactly one set the document
     accepts for it (an image the manifest does not approve matches none);
  3  rollout.may_reboot says yes, on LIVE leases: this node asks each other node that may authorize for a
     lease for this boot session NOW, once each, and again once each after the phrase is typed (so a slow
     confirmation never arms BootNext on old evidence). That is two nonce and two lease requests per peer,
     inside sync's per-caller limit (6 in 60 s) with the admission service's own renewals; a peer whose
     bucket is full refuses, and apply then refuses too. Those leases are evidence for this decision only: they are held in a
     root-only directory of their own under /run, never the admission service's, and deleted when the
     command exits. A peer that refuses is reported, and not asked again;
  4  BootOrder starts with the entry this host booted (the fallback after the one trial boot), and the
     entry's image, read from the ESP this host booted from, measures NEXT's PCR 11 in each phase
     (bootnext.trial, which checks this again before it writes BootNext).
Then it prints the plan and the deadline, asks for a typed phrase, records the request (and which peers'
leases justified it) on the update trail, sets BootNext, records that, and reboots. ONCE BOOTNEXT IS ARMED,
anything that stops the reboot (the trail write, a failed `systemctl reboot`) clears it again and reads that
back: an armed BootNext never outlives the apply that set it. A run killed in between is closed by the next
run of this tool (close_cut), which clears BootNext first. Until then a reset takes the trial boot: user space
cannot close that window without a boot-time hook, and a power cut there is simply the trial boot, a moment
after both peers vouched. The leases are judged again after the phrase is typed: a slow confirmation does not
reboot on leases that have run out.

THE DEADLINE. BootNext is used once. If the host has not come back up on the new image by the deadline
printed (its peers have not unlocked it, or it hangs), the operator resets it through the iLO (Power:
Reset): that boot follows BootOrder, which still starts with the current image, which is still approved,
and its peers unlock it. Nothing resets a hung trial boot by itself: a hardware watchdog armed across the
reboot is a rehearsal item for the DL360s (#65), not something this tool sets up.

PROMOTE refuses unless the host runs its target set (from the TPM), BootCurrent's image measures that set,
and at least one peer has just given this boot session a lease (it re-attested this boot, booted, under
this epoch). Then BootCurrent goes first in BootOrder. Promote every node before the root signs the retire:
a node whose BootOrder still starts with the retired image boots it at its next reset, and is refused.

FORGET refuses unless the entry's image measures none of the sets the document still accepts for this host
(the retired image, after the retire), and the entry is neither the one booted, the first, nor BootNext.

STATUS reads only: BootCurrent, BootNext, BootOrder, which approved set each entry's image measures, the set
the host runs and whether it is PROMOTED (the first entry is the target image and no BootNext is armed).
With --require-promoted it exits 1 otherwise: the check before the retire (KERNEL-UPDATE.md, 4.3).

Every exit is on the update trail (trails.py's "update"): a change is REQUESTED before it and answered ALLOW
or FAILED; a refusal or a phrase that does not match is a DENY with its reason; a trail that cannot be
written stops the command before anything changes.
"""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from deploy.baremetal import attest, bootnext, measurements, membership, rollout, trails

Refused, require = membership.Refused, membership.require

DEFAULT_ESP = "/efi"
DEFAULT_DEADLINE_MINUTES = 15


# ---- what the host runs ----

def running_set(document, node_id, read_pcrs):
    """The one set of `node_id`'s accepted sets whose booted values its PCRs hold now. `read_pcrs(selection)`
    returns {"<pcr>": hex} for the PCRs given (the TPM's, SHA-256)."""
    sets = measurements.validate(document)
    require(node_id in sets, "the measurements have no entry for %s" % node_id)
    selection = attest.selection(sets[node_id][0])
    now = read_pcrs(selection)
    require(isinstance(now, dict) and set(now) == {str(i) for i in selection}, "the TPM did not give PCRs %s" % selection)
    matches = [entry for entry in sets[node_id]
               if attest.values(entry, "system" if "phases" in entry else None) == now]
    require(matches, "this host's PCRs match none of the sets the manifest approves for %s (%s): it runs an image that is not "
            "approved, or it has not finished booting" % (node_id, ", ".join(e["label"] for e in sets[node_id])))
    require(len(matches) == 1, "this host's PCRs match %s alike: which image it runs cannot be told" % ", ".join(e["label"] for e in matches))
    return matches[0]


def authorizers(manifest, node_id):
    return [n for n in sorted(membership.validate(manifest)) if n != node_id and membership.may(manifest, n, "authorize")]


def fresh_leases(host, manifest, peers, session):
    """({peer: lease envelope}, {peer: why it gave none}): each peer asked once, in a private directory. A peer
    that does not answer (down, its tunnel gone) is "unreachable" and does not vouch; the others are still asked."""
    leases, refused = {}, {}
    work = tempfile.mkdtemp(dir=host.private_root, prefix="regalia-update-")
    try:
        os.chmod(work, 0o700)
        for peer in peers:
            try:
                leases[peer] = host.lease_from(peer, manifest, session, os.path.join(work, "lease-%s.json" % peer))
            except Refused as refusal:
                refused[peer] = str(refusal)
            except (OSError, ValueError) as failure:
                refused[peer] = "unreachable (%s: %s)" % (type(failure).__name__, failure)
    finally:
        shutil.rmtree(work, ignore_errors=True)            # this exact directory, made above: the leases go with it
    return leases, refused


def _phrase(*words):
    return " ".join(words)


def _utc(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---- what is recorded ----
#
# Every exit is on the update trail. A change is a REQUESTED event written before it (trails.unanswered pairs
# them), answered by ALLOW when it is done or FAILED when it raised. A refusal before any change, and a phrase
# that does not match, are a DENY of their own, with the reason. A run cut after its REQUESTED is closed by the
# next run as INCOMPLETE (close_cut), and if it was an apply, any BootNext it may have left armed is cleared.

def _quietly(record, event):
    """Record `event` on a path that is already failing: a second failure must not hide the first."""
    try:
        record(event)
    except Exception:          # noqa: BLE001 - the trail's own failure is the operator's to see next; the first reason wins
        pass


def _denied(record, event, failure):
    _quietly(record, dict(event, outcome="DENY", reason=str(failure) or type(failure).__name__))


def _armed(record, event, what, stuck):
    """The worst state: BootNext may be armed, the host was not rebooted, and clearing it failed. Recorded
    CRITICAL, and raised with what to do; the command exits non-zero."""
    message = ("CRITICAL: %s AND BootNext could not be cleared (%s). BootNext may be armed: the next reset of this host would "
               "trial-boot the new image with no fresh leases. Clear it now, by hand: `efibootmgr --delete-bootnext`, and check "
               "`efibootmgr` shows no BootNext" % (what, stuck))
    _quietly(record, dict(event, outcome="CRITICAL", reason=message))
    raise Refused(message)


def _change(record, event, act):
    """REQUESTED, `act()`, then ALLOW; FAILED (and the exception) if it raises. Returns (act's result, the request seq)."""
    seq = record(dict(event, outcome="REQUESTED"))
    try:
        done = act()
    except BaseException as failure:
        _quietly(record, dict(event, request=seq, outcome="FAILED", reason=str(failure) or type(failure).__name__))
        raise
    return done, seq


def close_cut(host, path, record, say=print):
    """Close the last REQUESTED event on the trail at `path` that no later event answers: its run was killed
    (SIGKILL, a power cut) before it said what happened. Recorded INCOMPLETE. If it was an apply, BootNext
    may be armed with nobody watching: it is cleared (and read back) first."""
    cut = trails.unanswered(path)
    if cut is None:
        return None
    event = {"event": cut.get("event"), "node_id": cut.get("node_id"), "request": cut.get("seq"), "outcome": "INCOMPLETE",
             "reason": "the run that made this request ended before it recorded what happened"}
    if cut.get("event") == "update-apply":
        armed = host.boot()["next"]
        bootnext.clear_next(host.run)
        event["bootnext_cleared"] = armed
        say("an earlier apply was cut after its request (seq %s); BootNext %s." % (cut.get("seq"), "was %s and is cleared" % armed if armed else "was not set"))
    record(event)
    return event


# ---- the four commands ----

def apply(host, entry, esp, typed, record, deadline_minutes=DEFAULT_DEADLINE_MINUTES, say=print):
    """See the module text. Returns the BootNext outcome; the host is then rebooted (host.reboot)."""
    event = {"event": "update-apply", "node_id": host.node_id, "entry": entry}
    try:
        require(isinstance(deadline_minutes, int) and 5 <= deadline_minutes <= 120, "the deadline is 5 to 120 minutes")
        manifest = host.manifest()
        document = host.document(manifest)
        measurements.bind(manifest, document)
        node_id = host.node_id
        running = running_set(document, node_id, host.pcrs)
        target = measurements.target(document, node_id)
        require(running["label"] != target["label"], "%s already runs its target %s: there is nothing to apply" % (node_id, target["label"]))
        session = host.session()
        leases, refused = fresh_leases(host, manifest, authorizers(manifest, node_id), session)
        event.update({"from": running["label"], "to": target["label"], "epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest),
                      "lease_issuers": sorted(leases), "no_lease": refused})
        now = host.now()
        try:
            verdict = rollout.may_reboot(manifest, document, node_id, running["label"], session, host.own_state(), list(leases.values()),
                                         now, run=host.run)
        except Refused as refusal:
            raise Refused("%s%s" % (refusal, "".join("; %s gave no lease: %s" % (p, refused[p]) for p in sorted(refused)))) from None
        boot = host.boot()
        # the fallback: once BootNext is used, the firmware follows BootOrder, which must start with the image running now
        require(boot["order"][:1] == [boot["current"]], "BootOrder starts with %s, not with Boot%s, the image this host runs: after the "
                "trial boot a reset would not come back to it (efibootmgr --bootorder %s,…)" % (",".join(boot["order"][:1]) or "nothing",
                                                                                               boot["current"], boot["current"]))
        bootnext.measures(bootnext.image(esp, entry, boot, **host.where), target)       # shown before the phrase; trial() checks again
    except (Refused, attest.Refused, OSError, ValueError) as failure:
        _denied(record, event, failure)
        raise
    deadline = int(time.time()) + 60 * deadline_minutes
    current = boot["current"]
    event.update({"booted": current, "authorizers": verdict["authorizers"], "deadline": deadline})
    say("%s runs %s (Boot%s). Its peers %s vouch for this boot (the shortest lease has %d s left)."
        % (node_id, running["label"], current, " and ".join(verdict["authorizers"]), verdict["seconds"]))
    say("Boot%s's image measures %s in every phase. BootNext := %s, then this host reboots." % (entry, target["label"], entry))
    say("DEADLINE %s: if %s is not back up on %s by then (no peer has unlocked it, or it hangs), reset it through the iLO "
        "(Power: Reset). BootNext is used once: that boot follows BootOrder, Boot%s, %s, still approved, and its peers unlock it."
        % (_utc(deadline), node_id, target["label"], current, running["label"]))
    phrase = _phrase("reboot", node_id, "into", target["label"])
    answer = typed("type %r to go on: " % phrase).strip()
    if answer != phrase:
        failure = Refused("not confirmed: nothing was changed")
        _denied(record, dict(event, aborted=True), failure)
        raise failure
    # The leases vouch for this boot NOW, for a few minutes. Once the operator has answered, they are asked for
    # again and may_reboot judges the fresh ones on the authenticated clock: a slow confirmation never arms
    # BootNext on evidence from before it
    try:
        leases, refused = fresh_leases(host, manifest, authorizers(manifest, node_id), session)
        event.update({"lease_issuers": sorted(leases), "no_lease": refused})
        verdict = rollout.may_reboot(manifest, document, node_id, running["label"], session, host.own_state(), list(leases.values()),
                                     host.now(), run=host.run)
        event["authorizers"] = verdict["authorizers"]
    except (Refused, attest.Refused, OSError, ValueError) as failure:
        failure = Refused("the peers' leases no longer allow it after the confirmation (%s%s): nothing was changed; run apply again"
                          % (failure, "".join("; %s gave no lease: %s" % (p, refused[p]) for p in sorted(refused))))
        _denied(record, dict(event, expired=True), failure)
        raise failure from None

    def arm():
        try:
            return bootnext.trial(entry, esp, target, host.run, **host.where)
        except BaseException as failure:
            try:
                bootnext.clear_next(host.run)          # a write that did not read back may have left something armed
            except (Refused, OSError) as stuck:
                _armed(record, event, "setting BootNext failed (%s)" % failure, stuck)
            raise
    done, seq = _change(record, event, arm)
    # BootNext is armed. From here, anything that stops the reboot disarms it: an armed BootNext must never outlive
    # the apply that set it (a later reset would trial-boot NEXT with no fresh leases and nobody watching).
    try:
        record(dict(event, request=seq, outcome="ALLOW", measured=done["measured"]))
        say("BootNext is %s. Rebooting." % entry)
        host.reboot()
    except BaseException as failure:
        try:
            bootnext.clear_next(host.run)
        except (Refused, OSError) as stuck:
            _armed(record, event, "the reboot did not happen (%s)" % (str(failure) or type(failure).__name__), stuck)
        _quietly(record, dict(event, request=seq, outcome="BOOTNEXT-CLEARED", reason=str(failure) or type(failure).__name__))
        raise Refused("the reboot did not happen (%s); BootNext is cleared, nothing is armed" % (str(failure) or type(failure).__name__)) from None
    return done


def promote(host, esp, typed, record, say=print):
    event = {"event": "update-promote", "node_id": host.node_id}
    try:
        manifest = host.manifest()
        document = host.document(manifest)
        measurements.bind(manifest, document)
        node_id = host.node_id
        running, target = running_set(document, node_id, host.pcrs), measurements.target(document, node_id)
        require(running["label"] == target["label"], "%s runs %s, not its target %s: only the image it came up on is promoted, and "
                "only once it is the target" % (node_id, running["label"], target["label"]))
        boot = host.boot()
        current = boot["current"]
        event.update({"entry": current, "set": target["label"], "epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest)})
        bootnext.measures(bootnext.image(esp, current, boot, **host.where), target)
        leases, refused = fresh_leases(host, manifest, authorizers(manifest, node_id), host.session())
        event.update({"lease_issuers": sorted(leases), "no_lease": refused})
        require(leases, "no peer gave this boot a lease (%s): nobody has seen %s up on %s yet"
                % ("; ".join("%s: %s" % (p, refused[p]) for p in sorted(refused)) or "no peer may authorize", node_id, target["label"]))
    except (Refused, attest.Refused, OSError, ValueError) as failure:
        _denied(record, event, failure)
        raise
    if boot["order"][:1] == [current]:
        say("Boot%s (%s) is already first in BootOrder." % (current, target["label"]))
        return boot
    say("%s runs %s from Boot%s; %s gave this boot a lease. BootOrder := %s first." % (node_id, target["label"], current, " and ".join(sorted(leases)), current))
    phrase = _phrase("make", current, "the default on", node_id)
    if typed("type %r to go on: " % phrase).strip() != phrase:
        failure = Refused("not confirmed: nothing was changed")
        _denied(record, dict(event, aborted=True), failure)
        raise failure
    after, seq = _change(record, event, lambda: bootnext.promote(current, host.run))
    record(dict(event, request=seq, outcome="ALLOW", order=after["order"]))
    return after


def forget(host, entry, esp, typed, record, say=print):
    event = {"event": "update-forget", "node_id": host.node_id, "entry": entry}
    try:
        manifest = host.manifest()
        document = host.document(manifest)
        measurements.bind(manifest, document)
        node_id = host.node_id
        event.update({"epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest)})
        data = bootnext.image(esp, entry, host.boot(), **host.where)
        for accepted in measurements.validate(document)[node_id]:
            try:
                bootnext.measures(data, accepted)
            except Refused:
                continue
            raise Refused("Boot%s's image is %s, which the manifest still approves for %s: it is not retired" % (entry, accepted["label"], node_id))
        event["measured"] = bootnext.measured(data)
    except (Refused, attest.Refused, OSError, ValueError) as failure:
        _denied(record, event, failure)
        raise
    phrase = _phrase("remove", entry, "from", node_id)
    if typed("type %r to go on: " % phrase).strip() != phrase:
        failure = Refused("not confirmed: nothing was changed")
        _denied(record, dict(event, aborted=True), failure)
        raise failure
    after, seq = _change(record, event, lambda: bootnext.remove(entry, host.run))
    record(dict(event, request=seq, outcome="ALLOW"))
    return after


def status(host, esp):
    """Read-only: BootCurrent, BootNext, BootOrder, and which approved set each entry's image measures (on the
    booted ESP), the set the host runs, its target, and whether it is PROMOTED (BootOrder's first entry is the
    target image: a reset boots it). Changes nothing and records nothing."""
    manifest = host.manifest()
    document = host.document(manifest)
    measurements.bind(manifest, document)
    node_id = host.node_id
    sets, target = measurements.validate(document)[node_id], measurements.target(document, node_id)
    boot = host.boot()
    entries = {}
    for number, entry in sorted(boot["entries"].items()):
        if entry["path"] is None:
            continue
        try:
            data = bootnext.image(esp, number, boot, **host.where)
        except (Refused, OSError) as failure:
            entries[number] = "unreadable here (%s)" % failure
            continue
        labels = []
        for accepted in sets:
            try:
                bootnext.measures(data, accepted)
                labels.append(accepted["label"])
            except Refused:
                pass
        entries[number] = labels[0] if labels else "not approved"
    try:
        running = running_set(document, node_id, host.pcrs)["label"]
    except Refused as failure:
        running = "unknown (%s)" % failure
    first = boot["order"][0] if boot["order"] else None
    return {"node_id": node_id, "epoch": manifest["epoch"], "current": boot["current"], "next": boot["next"], "order": boot["order"],
            "entries": entries, "running": running, "target": target["label"],
            "promoted": first is not None and entries.get(first) == target["label"] and boot["next"] is None}


# ---- the host ----

class Host:
    """This node, as its services see it: the configuration, the store, the TPM, the sync client."""
    private_root = "/run"

    def __init__(self, cfg, run=subprocess.run):
        from deploy.baremetal import node
        self._node_module, self.node, self.run = node, node.Node(cfg, run=run), run
        self.node_id, self.where = self.node.node_id, {}

    def manifest(self):
        return self.node.manifest()          # the published chain, verified from the root key and against the TPM anchor

    def document(self, manifest):
        """The measurement document `manifest` commits to, from this node's store by digest (#332): refused when it
        is not held. Never another epoch's."""
        return measurements.held(self.node.documents(), manifest)

    def pcrs(self, selection):
        with tempfile.TemporaryDirectory(prefix="regalia-update-pcrs-") as d:
            out = os.path.join(d, "pcrs.bin")
            done = self.run(["tpm2_pcrread", "-T", self.node.tcti, "sha256:" + ",".join(str(i) for i in selection), "-o", out],
                            capture_output=True, timeout=30)
            require(done.returncode == 0, "tpm2_pcrread failed (exit %s)" % done.returncode)
            with open(out, "rb") as f:
                raw = f.read(32 * len(selection) + 1)
        require(len(raw) == 32 * len(selection), "tpm2_pcrread gave %d bytes for %d PCRs" % (len(raw), len(selection)))
        return {str(i): raw[32 * k:32 * (k + 1)].hex() for k, i in enumerate(sorted(selection))}

    def session(self):
        self._session = self._node_module.boot_session(self.node.runtime)
        return self._session[0]

    def own_state(self):
        with open(self.node.path("attest.json"), "rb") as f:
            return membership.load(f.read(4 * 1024 * 1024 + 1), limit=4 * 1024 * 1024)

    def now(self):
        from deploy.baremetal import heartbeat
        return heartbeat.authenticated_now(self.node.clock(), self.node.tpm_clock(), None)[0]

    def lease_from(self, peer, manifest, session, state_path):
        from deploy.baremetal import lease, sync
        session_id, public = self._session
        require(session_id == session, "the boot session changed while asking")
        holder = lease.Holder(self.node_id, session_id, self.node.clock(), self.node.tpm_clock(), state_path, run=self.run)
        sources = self.node.sources(manifest)
        require(peer in sources, "%s is not a peer this node can reach" % peer)

        class Manifest:
            load = staticmethod(lambda: manifest)
        client = sync.Client(self.node_id, Manifest, None, {peer: sources[peer]}, lambda event: None)
        envelope = client.renewer(peer, self.node.quote(session_id, public))(holder.request())
        holder.install(envelope, manifest, prefer=True)        # verified: signature, this node, this session, this epoch
        return envelope

    def boot(self):
        return bootnext.state(self.run)

    def reboot(self):
        done = self.run(["systemctl", "reboot"], capture_output=True, text=True, timeout=30)
        require(done.returncode == 0, "systemctl reboot failed (exit %s): %s" % (done.returncode, (done.stderr or "").strip()[:200]))


def main(argv=None, typed=None, run=None):
    """Exit status: 0 done; 1 refused, nothing changed; 2 usage."""
    from deploy.baremetal import node
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.update", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("apply", "promote", "forget", "status"):
        c = sub.add_parser(name)
        c.add_argument("--config", required=True, help="this node's node.json")
        c.add_argument("--esp", default=DEFAULT_ESP, help="where the ESP this host booted from is mounted (default %(default)s)")
        c.add_argument("--audit-log", default=trails.where("update"), help="the update trail (default %(default)s)")
        if name == "status":
            c.add_argument("--json", action="store_true", help="one JSON object")
            c.add_argument("--require-promoted", action="store_true",
                           help="exit 1 unless BootOrder's first entry is the target image and no BootNext is armed (before the retire)")
        if name in ("apply", "forget"):
            c.add_argument("--entry", required=True, metavar="XXXX", help="the Boot#### entry (four hex digits, as efibootmgr shows it)")
        if name == "apply":
            c.add_argument("--deadline-minutes", type=int, default=DEFAULT_DEADLINE_MINUTES,
                           help="after this, an operator resets a trial boot that has not come up (default %(default)s)")
    args = ap.parse_args(argv)

    def record(event):
        try:
            return trails.append(args.audit_log, dict(event, time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        except trails.Refused as refused:
            raise OSError(str(refused)) from refused
    try:
        require(os.geteuid() == 0, "run it as root: it reads the TPM and writes the firmware's boot variables")
        require("TPM2TOOLS_TCTI" not in os.environ, "TPM2TOOLS_TCTI is set in the environment: the TPM is the configuration's; unset it")
        host = Host(node.load(args.config), run=run or subprocess.run)
        ask = typed or input
        if args.command == "status":
            found = status(host, args.esp)
            if args.json:
                print(json.dumps(found, sort_keys=True))
            else:
                print("%(node_id)s runs %(running)s; target %(target)s; BootCurrent %(current)s, BootNext %(next)s, BootOrder %(order)s" % dict(
                    found, order=",".join(found["order"]), next=found["next"] or "unset"))
                for number, label in sorted(found["entries"].items()):
                    print("  Boot%s  %s" % (number, label))
                print("PROMOTED: a reset boots %s" % found["target"] if found["promoted"] else
                      "NOT PROMOTED: BootOrder's first entry is not %s, or BootNext is armed" % found["target"])
            return 0 if found["promoted"] or not args.require_promoted else 1
        close_cut(host, args.audit_log, record)
        if args.command == "apply":
            apply(host, args.entry, args.esp, ask, record, args.deadline_minutes)
        elif args.command == "promote":
            promote(host, args.esp, ask, record)
        else:
            forget(host, args.entry, args.esp, ask, record)
    except (Refused, attest.Refused, OSError, ValueError) as failure:
        print("%s: NO: %s" % (args.command, failure), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
