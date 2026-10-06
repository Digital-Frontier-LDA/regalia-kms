#!/usr/bin/env python3
"""A fenced server's return to the survivor's etcd (ADR-0002 D32, #432; the owner's one-server decision, G5). After a
take-over (takeover.py) the survivor's etcd is a cluster of one at state epoch N, and the returning servers' own data
holds a history it does not: their divergent tail. Once the root's lift epoch counts a returning node again, it comes
back one node at a time, AS AN ETCD LEARNER: a voting member added to a cluster of one would make the quorum two at
once, and the survivor would commit nothing until the newcomer caught up. A learner counts for no quorum and is
promoted only once etcd says it is in sync (measured on etcd 3.6.15, regalia-kms-2f).

    on the survivor:   python3 -Es -m deploy.baremetal.rejoin --config node.json admit   --node R
    on R:              python3 -Es -m deploy.baremetal.rejoin --config node.json join    --initial-cluster S=...,R=... --member-id ID
    on the survivor:   python3 -Es -m deploy.baremetal.rejoin --config node.json promote --node R
    on R:              python3 -Es -m deploy.baremetal.rejoin --config node.json finish
    (on the survivor, a learner that never syncs: ... abandon --node R)

ADMIT (survivor). Refused while the take-over's drop-in is in force (takeover.forcing, regalia-kms-d9: its next restart
would force a new cluster again and drop R), while any other learner or unstarted member exists (one at a time), if R
does not count under the current manifest, or if R is already a voting member. `etcdctl member add R --learner` at
R's mesh URL; it says the initial-cluster R starts with (the members NOW, from etcd's answer, never the manifest's)
and the learner's member ID. Run again, it finds R's learner and says the same.

JOIN (R), with what admit said. Stops regalia-kms, then etcd. THE EXPORT (G5): the old backend's revision (etcdutl,
offline) and the SHA-256 of its db are recorded FIRST (regalia-kms-05: a crash after the rename must not lose the digest),
then the data directory is renamed to regalia-etcd.divergent-e<epoch>-r<revision>: kept, never deleted, never replayed.
It is the evidence the reconciliation reads (RECOVERY-RECONCILIATION.md). A record without its directory is a crash
between the two: the rename completes. The configuration is
the node's checked one (etcdconf.check) with that initial-cluster, every name a member under the current manifest at
its own mesh URL, and initial-cluster-state "existing"; etcd ignores both once its data directory exists, so it stays.
etcd starts and must answer as a learner of the cluster, holding the store's state-epoch entry, verified and bound to
it (opstate.verify_state_epoch), and as the member ID admit said. Then a marker beside the data directory names that
learner and epoch. Run again, the directory is kept only if its marker names this learner (05): one from after the
export that does not (a learner abandoned and admitted again, a crash before the marker) is set aside as
regalia-etcd.abandoned-e<epoch>-<n>, kept, and etcd starts afresh. The divergent tail is exported once.

PROMOTE (survivor). `etcdctl member promote`, retried while etcd answers that the learner is not yet in sync, bounded.
etcd itself decides "in sync": it promotes a learner whose match index is at least 90% of the leader's
(readyPercentThreshold, server/etcdserver/server.go in v3.6.15), never forced. Raft keeps that safe; the cost is that
the survivor's commits, now needing two of two, wait while R catches up the rest.

THE TWO-OF-TWO WINDOW (05). From R's promotion until the third node is promoted, the cluster is two voting members:
losing either stops every commit until the third is promoted, or another take-over. One learner at a time is
etcd's default (--max-learners 1, which etcdconf renders by leaving it out); admitting the third as a learner before
promoting R would shorten the window and is not done.
FINISH (R). R answers as a voting member of the cluster, holding the state-epoch entry: the daemon starts, and its
leases name the same (cluster, state epoch) as the survivor's.
"""
import argparse
import hashlib
import json
import os
import sys
import time

from deploy.baremetal import etcdconf, membership, opstate, takeover as tk

Refused, require = membership.Refused, membership.require
say = tk.say

DIVERGENT = etcdconf.DATA_DIR + ".divergent-e%d-r%d"
JOINED = etcdconf.DATA_DIR + ".joined.json"          # beside the data directory: which learner it is, for which epoch
MEMBER_ID = __import__("re").compile(r"[0-9a-f]{1,16}")
NOT_IN_SYNC = "can only promote a learner member which is in sync with leader"
PROMOTE_TRIES, PROMOTE_PAUSE_S = 60, 5           # five minutes for a learner to catch up
JOIN_TRIES, JOIN_PAUSE_S = 60, 2


def _ctl(host, *args):
    return tk._json(host.run([tk.ETCDCTL, "--endpoints", tk.ENDPOINT] + list(args) + ["-w", "json"]), "etcdctl " + " ".join(args[:2]))


def _members(host):
    return _ctl(host, "member", "list")["members"]


def _url(manifest, node_id):
    nodes = etcdconf.members(manifest)
    require(node_id in nodes, "%s is not an etcd member under epoch %d" % (node_id, manifest["epoch"]))
    return etcdconf.peer_url(nodes[node_id])


def _initial_cluster(members, joining):
    """name=url for each member etcd holds; the unstarted learner has no name yet, and is `joining`."""
    return ",".join("%s=%s" % (m.get("name") or joining, m["peerURLs"][0]) for m in members)


def admit(host, chain, me, node):
    current = chain[-1]
    require(node != me, "a node does not admit itself")
    _url(current, me)
    url = _url(current, node)
    require(not tk.forcing(host), "%s still carries the take-over drop-in: finish the take-over before any member returns" % tk.UNIT)
    members = _members(host)
    mine = [m for m in members if m["peerURLs"] == [url]]
    others = [m for m in members if m not in mine]
    pending = [m.get("name") or "an unstarted member" for m in others if m.get("isLearner") or not m.get("name")]
    require(not pending, "%s is still joining: one node at a time" % ", ".join(pending))
    if mine:
        require(mine[0].get("isLearner"), "%s is already a voting member" % node)
        member_id = "%x" % mine[0]["ID"]
        say("%s is already admitted as a learner" % node)
    else:
        added = _ctl(host, "member", "add", node, "--learner", "--peer-urls=" + url)
        members, member_id = added["members"], "%x" % added["member"]["ID"]
        say("%s admitted as a learner at %s" % (node, url))
    line = _initial_cluster(members, node)
    say("INITIAL-CLUSTER: %s" % line)
    say("MEMBER-ID: %s" % member_id)
    return line, member_id


def _parse_initial(line, manifest, me):
    pairs = [part.split("=", 1) for part in line.split(",")]
    require(all(len(p) == 2 for p in pairs), "initial-cluster is name=url, comma-separated")
    names = [p[0] for p in pairs]
    require(len(set(names)) == len(names) and me in names, "initial-cluster names each member once, this node included")
    for name, url in pairs:
        require(url == _url(manifest, name), "initial-cluster gives %s at %s; the manifest's mesh URL is %s" % (name, url, _url(manifest, name)))
    return line


def _state(host, chain):
    """(status header, is learner, state epoch entry) of this node's etcd, the entry verified and bound to the store."""
    status = tk._json(host.run([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "endpoint", "status", "-w", "json"]), "etcdctl endpoint status")
    require(isinstance(status, list) and len(status) == 1, "etcdctl endpoint status answered %d endpoints" % len(status or []))
    header = status[0]["Status"]["header"]
    got = tk._json(host.run([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "get", opstate.STATE_EPOCH_KEY, "--consistency=s", "-w", "json"]),
                   "etcdctl get")
    kvs = got.get("kvs") or []
    require(kvs, "this node's etcd holds no state-epoch entry: it has not caught up with the survivor's store")
    import base64
    entry = opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, json.loads(base64.b64decode(kvs[0]["value"])), chain, None,
                                       ("%016x" % header["cluster_id"], kvs[0]["mod_revision"]))
    return header, bool(status[0]["Status"].get("isLearner")), entry


def _beside(host, infix):
    """The names beside the data directory that begin with its own name plus `infix`."""
    base = os.path.basename(etcdconf.DATA_DIR) + infix
    return sorted(p for p in host.listdir(os.path.dirname(etcdconf.DATA_DIR)) if p.startswith(base))


def _dir_of(name):
    return os.path.join(os.path.dirname(etcdconf.DATA_DIR), name)


def _prepare(host, me, epoch, member_id):
    """The data directory etcd is to start on: the joined one (its marker names this learner, regalia-kms-05), or none
    (the old one exported, or a stale one set aside). Returns the export's path when this run made it."""
    if not host.exists(etcdconf.DATA_DIR):
        return None
    if host.exists(JOINED):
        try:
            marker = json.loads(host.read(JOINED))
        except ValueError:
            marker = {}
        if marker == {"epoch": epoch, "member_id": member_id}:
            say("the data directory is learner %s's, joined at epoch %d: kept" % (member_id, epoch))
            return None
    exported = [p for p in _beside(host, ".divergent-e%d-" % epoch) if not p.endswith(".json")]
    if exported:
        # the old data is already exported: this directory came after it (a learner abandoned, a crash before its
        # marker), never the divergent tail. Set aside, kept, and etcd starts afresh as this learner
        aside = _dir_of("%s.abandoned-e%d-%d" % (os.path.basename(etcdconf.DATA_DIR), epoch, len(_beside(host, ".abandoned-e%d-" % epoch)) + 1))
        host.rename(etcdconf.DATA_DIR, aside)          # its marker, if any, names another learner: replaced once this one answers
        say("a data directory from after the export, not learner %s's, set aside at %s (kept)" % (member_id, aside))
        return None
    records = _beside(host, ".divergent-e%d-" % epoch)
    if records:
        # the record written, the rename not (a crash between the two): the rename completes, by the record's path
        record = json.loads(host.read(_dir_of(records[0])))
        export = record["kept_at"]
    else:
        backend = tk._json(host.run([tk.ETCDUTL, "snapshot", "status", tk.BACKEND, "-w", "json"]), "etcdutl snapshot status")
        revision = backend.get("revision")
        require(isinstance(revision, int) and revision >= 0, "the old backend's revision is unreadable: refused, nothing moved")
        export = DIVERGENT % (epoch, revision)
        record = {"node_id": me, "epoch": epoch, "revision": revision, "db_sha256": host.sha256(tk.BACKEND), "kept_at": export}
        host.write(export + ".json", json.dumps(record, sort_keys=True) + "\n", mode=0o600)     # first: a crash keeps the digest
    host.rename(etcdconf.DATA_DIR, export)
    say("EXPORTED: the divergent tail, revision %d, db sha256 %s, kept at %s" % (record["revision"], record["db_sha256"], export))
    return export


def join(host, chain, me, line, member_id):
    current = chain[-1]
    _parse_initial(line, current, me)
    require(isinstance(member_id, str) and MEMBER_ID.fullmatch(member_id) is not None, "the member ID is the hex admit said")
    for unit in (tk.DAEMON, tk.UNIT):
        say("%s stopped (%s)" % (unit, tk._stop(host, unit)))
    export = _prepare(host, me, current["epoch"], member_id)
    config = etcdconf.check(host.read(etcdconf.CONFIG_PATH))
    require(config["name"] == me, "etcd's configuration is %s's, not %s's" % (config["name"], me))
    config["initial-cluster"], config["initial-cluster-state"] = line, "existing"
    text = json.dumps(config, indent=1, sort_keys=True) + "\n"
    etcdconf.check(text)
    host.write(etcdconf.CONFIG_PATH, text)          # root's, 0644, as rendered: no secret in it, and etcd may not rewrite it
    tk._start(host, tk.UNIT)
    for attempt in range(JOIN_TRIES):
        try:
            header, learner, entry = _state(host, chain)
            break
        except Refused:
            if attempt == JOIN_TRIES - 1:
                raise
            host.sleep(JOIN_PAUSE_S)
    require("%x" % header["member_id"] == member_id, "this node's etcd answers as member %x, not the learner %s admit made"
            % (header["member_id"], member_id))
    require(learner, "this node's etcd answers as a voting member before any promotion: not the learner admit made")
    host.write(JOINED, json.dumps({"epoch": current["epoch"], "member_id": member_id}, sort_keys=True) + "\n", mode=0o600)
    say("%s is learner %s of cluster %016x at state epoch %d: now, on the survivor, promote it" % (me, member_id, header["cluster_id"],
                                                                                                 entry["state_epoch"]))
    return export


def promote(host, chain, me, node):
    url = _url(chain[-1], node)
    found = [m for m in _members(host) if m["peerURLs"] == [url]]
    require(found, "%s is not a member: admit it first" % node)
    if not found[0].get("isLearner"):
        say("%s is already a voting member" % node)
        return
    member = "%x" % found[0]["ID"]
    for attempt in range(PROMOTE_TRIES):
        done = host.run([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "member", "promote", member])
        if done.returncode == 0:
            break
        why = (done.stderr or done.stdout or "").strip()
        require(NOT_IN_SYNC in why, "etcdctl member promote %s failed: %s" % (member, why[-300:]))
        require(attempt < PROMOTE_TRIES - 1, "%s is still not in sync after %d s: run promote again, or abandon it"
                % (node, PROMOTE_TRIES * PROMOTE_PAUSE_S))
        host.sleep(PROMOTE_PAUSE_S)
    found = [m for m in _members(host) if m["peerURLs"] == [url]]
    require(found and not found[0].get("isLearner"), "%s is not a voting member after its promotion" % node)
    say("%s promoted: a voting member" % node)


def finish(host, chain, me):
    header, learner, entry = _state(host, chain)
    require(not learner, "this node is still a learner: promote it on the survivor first")
    tk._start(host, tk.DAEMON)
    say("%s is a voting member of cluster %016x at state epoch %d; %s started" % (me, header["cluster_id"], entry["state_epoch"], tk.DAEMON))


def abandon(host, chain, me, node):
    url = _url(chain[-1], node)
    found = [m for m in _members(host) if m["peerURLs"] == [url]]
    require(found, "%s is not a member" % node)
    require(found[0].get("isLearner"), "%s is a voting member: abandon removes only a learner" % node)
    done = host.run([tk.ETCDCTL, "--endpoints", tk.ENDPOINT, "member", "remove", "%x" % found[0]["ID"]])
    require(done.returncode == 0, "etcdctl member remove failed (%d)" % done.returncode)
    say("%s's learner removed; admit it again when it is ready" % node)


class Host(tk.Host):
    def exists(self, path):
        return os.path.lexists(path)

    def listdir(self, path):
        return os.listdir(path)

    def rename(self, src, dst):
        require(not os.path.lexists(dst), "%s exists: refused, nothing moved" % dst)
        os.rename(src, dst)
        fd = os.open(os.path.dirname(dst), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def sha256(self, path):
        digest = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                digest.update(block)
        return digest.hexdigest()

    def sleep(self, seconds):
        time.sleep(seconds)


def audited_command(host, chain, me, command, node=None, line=None, member_id=None, record=None):
    """One rejoin command between its REQUEST and its outcome on the survivor trail (G6, takeover.audited)."""
    fields = {"node_id": me, "subject": node or me, "epoch": chain[-1]["epoch"]}

    def act():
        if command == "admit":
            got_line, got_id = admit(host, chain, me, node)
            return {"initial_cluster": got_line, "member_id": got_id}
        if command == "join":
            export = join(host, chain, me, line, member_id)
            done = {"member_id": member_id, "exported": export or ""}
            if export:
                record_ = json.loads(host.read(export + ".json"))
                done.update(divergent_revision=record_["revision"], divergent_db_sha256=record_["db_sha256"])
            return done
        if command == "finish":
            finish(host, chain, me)
            return {}
        {"promote": promote, "abandon": abandon}[command](host, chain, me, node)
        return {}
    return tk.audited(record, "rejoin-" + command, fields, act)


def main(argv=None, host=None, record=None):
    from deploy.baremetal import trails
    parser = argparse.ArgumentParser(prog="rejoin", description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", required=True, help="the node's configuration (node.json)")
    parser.add_argument("--audit-log", default=trails.where("survivor"),
                        help="the survivor trail (default %(default)s, its place in trails.py's registry)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("admit", "promote", "abandon"):
        sub.add_parser(name).add_argument("--node", required=True, help="the returning node")
    j = sub.add_parser("join")
    j.add_argument("--initial-cluster", required=True, help="what admit said, on the survivor")
    j.add_argument("--member-id", required=True, help="the learner's member ID, as admit said it")
    sub.add_parser("finish")
    args = parser.parse_args(argv)
    from deploy.baremetal import node as nodemod
    try:
        node = nodemod.load(args.config)
        host = host or Host()
        chain = tk.chain_of(nodemod.read_published(node.path(nodemod.PUBLISHED)), node.cfg["root_key"])
        require(chain[-1]["epoch"] == node.manifest()["epoch"], "the published chain's tip is not the anchored manifest")
        audited_command(host, chain, node.node_id, args.command, node=getattr(args, "node", None),
                        line=getattr(args, "initial_cluster", None), member_id=getattr(args, "member_id", None),
                        record=record or tk.trail_writer(args.audit_log))
    except tk.Unrecorded as done:
        say(str(done))
        return 3
    except (Refused, OSError, ValueError, KeyError) as refused:
        say("REFUSED: %s" % refused)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
