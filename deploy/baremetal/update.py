#!/usr/bin/env python3
"""Update: the acting half of a rolling image update (#75, Phase 15; KERNEL-UPDATE.md, step 3). rollout.py
reads and decides, and never changes anything; this sets the firmware's BootNext and reboots the host into
its new image (apply), makes the image the host came up on its default (promote), and removes a retired
image's boot entry (forget). Run on the node, as root, by hand.

    python3 -Es -m deploy.baremetal.update apply   --config /etc/regalia/node.json --entry 0003 [--esp /efi] [--deadline-minutes 15]
    python3 -Es -m deploy.baremetal.update promote --config /etc/regalia/node.json [--esp /efi]
    python3 -Es -m deploy.baremetal.update forget  --config /etc/regalia/node.json --entry 0001 [--esp /efi]

APPLY refuses unless all of this holds, from the host's own state, never from files an operator collected:
  1  the manifest is the one this node's store holds (verified from the root key and against the TPM's
     high-water, as the services load it) and the measurement document is the one it commits to;
  2  the set this host RUNS is read from its TPM: its PCRs, as booted, match exactly one set the document
     accepts for it (an image the manifest does not approve matches none);
  3  rollout.may_reboot says yes, on LIVE leases: this node asks each other node that may authorize for a
     lease for this boot session NOW, once each (sync's per-caller limit is not approached: one nonce and
     one lease request per peer). Those leases are evidence for this decision only: they are held in a
     root-only directory of their own under /run, never the admission service's, and deleted when the
     command exits. A peer that refuses is reported, and not asked again;
  4  BootOrder starts with the entry this host booted (the fallback after the one trial boot), and the
     entry's image, read from the ESP this host booted from, measures NEXT's PCR 11 in each phase
     (bootnext.trial, which checks this again before it writes BootNext).
Then it prints the plan and the deadline, asks for a typed phrase, records the request (and which peers'
leases justified it) on the update trail, sets BootNext, records that, and reboots.

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

Every change is preceded by a REQUEST record on the update trail (trails.py's "update") and followed by its
outcome; a trail that cannot be written stops the command before anything changes.
"""
import argparse
import datetime
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
    """({peer: lease envelope}, {peer: why it gave none}): each peer asked once, in a private directory."""
    leases, refused = {}, {}
    work = tempfile.mkdtemp(dir=host.private_root, prefix="regalia-update-")
    try:
        os.chmod(work, 0o700)
        for peer in peers:
            try:
                leases[peer] = host.lease_from(peer, manifest, session, os.path.join(work, "lease-%s.json" % peer))
            except Refused as refusal:
                refused[peer] = str(refusal)
    finally:
        shutil.rmtree(work, ignore_errors=True)            # this exact directory, made above: the leases go with it
    return leases, refused


def _phrase(*words):
    return " ".join(words)


def _utc(seconds):
    return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---- the three commands ----

def apply(host, entry, esp, typed, record, deadline_minutes=DEFAULT_DEADLINE_MINUTES, say=print):
    """See the module text. Returns the BootNext outcome; the host is then rebooted (host.reboot)."""
    require(isinstance(deadline_minutes, int) and 5 <= deadline_minutes <= 120, "the deadline is 5 to 120 minutes")
    manifest, document = host.manifest(), host.document()
    measurements.bind(manifest, document)
    node_id = host.node_id
    running = running_set(document, node_id, host.pcrs)
    target = measurements.target(document, node_id)
    require(running["label"] != target["label"], "%s already runs its target %s: there is nothing to apply" % (node_id, target["label"]))
    session = host.session()
    leases, refused = fresh_leases(host, manifest, authorizers(manifest, node_id), session)
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
    deadline = int(time.time()) + 60 * deadline_minutes
    current = boot["current"]
    say("%s runs %s (Boot%s). Its peers %s vouch for this boot (the shortest lease has %d s left)."
        % (node_id, running["label"], current, " and ".join(verdict["authorizers"]), verdict["seconds"]))
    say("Boot%s's image measures %s in every phase. BootNext := %s, then this host reboots." % (entry, target["label"], entry))
    say("DEADLINE %s: if %s is not back up on %s by then (no peer has unlocked it, or it hangs), reset it through the iLO "
        "(Power: Reset). BootNext is used once: that boot follows BootOrder, Boot%s, %s, still approved, and its peers unlock it."
        % (_utc(deadline), node_id, target["label"], current, running["label"]))
    phrase = _phrase("reboot", node_id, "into", target["label"])
    require(typed("type %r to go on: " % phrase).strip() == phrase, "not confirmed: nothing was changed")
    event = {"event": "update-apply", "node_id": node_id, "entry": entry, "from": running["label"], "to": target["label"],
             "booted": current, "epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest),
             "lease_issuers": sorted(leases), "authorizers": verdict["authorizers"], "deadline": deadline}
    record(dict(event, outcome="REQUEST"))
    try:
        done = bootnext.trial(entry, esp, target, host.run, **host.where)
    except (Refused, OSError) as failure:
        record(dict(event, outcome="DENY", reason=str(failure)))
        raise
    record(dict(event, outcome="BOOTNEXT", measured=done["measured"]))
    say("BootNext is %s. Rebooting." % entry)
    host.reboot()
    return done


def promote(host, esp, typed, record, say=print):
    manifest, document = host.manifest(), host.document()
    measurements.bind(manifest, document)
    node_id = host.node_id
    running, target = running_set(document, node_id, host.pcrs), measurements.target(document, node_id)
    require(running["label"] == target["label"], "%s runs %s, not its target %s: only the image it came up on is promoted, and only "
            "once it is the target" % (node_id, running["label"], target["label"]))
    boot = host.boot()
    current = boot["current"]
    bootnext.measures(bootnext.image(esp, current, boot, **host.where), target)
    leases, refused = fresh_leases(host, manifest, authorizers(manifest, node_id), host.session())
    require(leases, "no peer gave this boot a lease (%s): nobody has seen %s up on %s yet"
            % ("; ".join("%s: %s" % (p, refused[p]) for p in sorted(refused)) or "no peer may authorize", node_id, target["label"]))
    if boot["order"][:1] == [current]:
        say("Boot%s (%s) is already first in BootOrder." % (current, target["label"]))
        return boot
    say("%s runs %s from Boot%s; %s gave this boot a lease. BootOrder := %s first." % (node_id, target["label"], current, " and ".join(sorted(leases)), current))
    phrase = _phrase("make", current, "the default on", node_id)
    require(typed("type %r to go on: " % phrase).strip() == phrase, "not confirmed: nothing was changed")
    event = {"event": "update-promote", "node_id": node_id, "entry": current, "set": target["label"], "epoch": manifest["epoch"],
             "manifest_digest": membership.digest(manifest), "lease_issuers": sorted(leases)}
    record(dict(event, outcome="REQUEST"))
    after = bootnext.promote(current, host.run)
    record(dict(event, outcome="PROMOTED", order=after["order"]))
    return after


def forget(host, entry, esp, typed, record, say=print):
    manifest, document = host.manifest(), host.document()
    measurements.bind(manifest, document)
    node_id = host.node_id
    boot = host.boot()
    data = bootnext.image(esp, entry, boot, **host.where)
    for accepted in measurements.validate(document)[node_id]:
        try:
            bootnext.measures(data, accepted)
        except Refused:
            continue
        raise Refused("Boot%s's image is %s, which the manifest still approves for %s: it is not retired" % (entry, accepted["label"], node_id))
    phrase = _phrase("remove", entry, "from", node_id)
    require(typed("type %r to go on: " % phrase).strip() == phrase, "not confirmed: nothing was changed")
    event = {"event": "update-forget", "node_id": node_id, "entry": entry, "epoch": manifest["epoch"],
             "manifest_digest": membership.digest(manifest), "measured": bootnext.measured(data)}
    record(dict(event, outcome="REQUEST"))
    after = bootnext.remove(entry, host.run)
    record(dict(event, outcome="REMOVED"))
    return after


# ---- the host ----

class Host:
    """This node, as its services see it: the configuration, the store, the TPM, the sync client."""
    private_root = "/run"

    def __init__(self, cfg, run=subprocess.run):
        from deploy.baremetal import node
        self._node_module, self.node, self.run = node, node.Node(cfg, run=run), run
        self.node_id, self.where = self.node.node_id, {}

    def manifest(self):
        return self.node.store().load()

    def document(self):
        with open(self.node.cfg["measurements"], "rb") as f:
            return measurements.load(f.read(measurements.MAX_BYTES + 1))

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
        self.run(["systemctl", "reboot"], timeout=30)


def main(argv=None, typed=None, run=None):
    """Exit status: 0 done; 1 refused, nothing changed; 2 usage."""
    from deploy.baremetal import node
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.update", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("apply", "promote", "forget"):
        c = sub.add_parser(name)
        c.add_argument("--config", required=True, help="this node's node.json")
        c.add_argument("--esp", default=DEFAULT_ESP, help="where the ESP this host booted from is mounted (default %(default)s)")
        c.add_argument("--audit-log", default=trails.where("update"), help="the update trail (default %(default)s)")
        if name != "promote":
            c.add_argument("--entry", required=True, metavar="XXXX", help="the Boot#### entry (four hex digits, as efibootmgr shows it)")
        if name == "apply":
            c.add_argument("--deadline-minutes", type=int, default=DEFAULT_DEADLINE_MINUTES,
                           help="after this, an operator resets a trial boot that has not come up (default %(default)s)")
    args = ap.parse_args(argv)

    def record(event):
        try:
            trails.append(args.audit_log, dict(event, time=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        except trails.Refused as refused:
            raise OSError(str(refused)) from refused
    try:
        require(os.geteuid() == 0, "run it as root: it reads the TPM and writes the firmware's boot variables")
        require("TPM2TOOLS_TCTI" not in os.environ, "TPM2TOOLS_TCTI is set in the environment: the TPM is the configuration's; unset it")
        host = Host(node.load(args.config), run=run or subprocess.run)
        ask = typed or input
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
