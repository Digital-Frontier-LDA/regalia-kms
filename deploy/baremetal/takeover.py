#!/usr/bin/env python3
"""The lone survivor's etcd take-over (ADR-0002 D32, #432; the owner's one-server decision, 2026-10-05: "everything
must remain active, even with only one server"). With two of three servers fenced and the owner's "full" survivor
authorization installed (survivor.py), the survivor's etcd has no quorum, so no stateful operation can commit. This
command makes the survivor's etcd a cluster of one, and marks the history it holds as the survivor's:

    python3 -Es -m deploy.baremetal.takeover --config /etc/regalia/node.json run --authorization FILE

At the survivor's console, by root. Every step is refused unless the one before it held, and each says so on stdout
(the journal, G6):

  1. THE SCOPE. The authorization verifies against this node's current manifest, names this node, and its full scope
     is in force now (survivor.in_force): the fenced side's last spendable request has expired.
  2. WHAT THIS NODE APPLIED. applied.json (the daemon's, internal/opstate/publish.go) names the etcd cluster and the
     highest revision this node acted on, in this boot (its boot_id is this one's). Read before etcd stops.
  3. THE DAEMON, THEN A GRACEFUL STOP (regalia-kms-ed, A). regalia-kms.service is stopped first (regalia-kms-62): once
     etcd takes writes again it would write its session entry, and the state epoch is to be the first write. Then
     `systemctl stop` lets etcd flush its backend. is-active must then say each unit is not running (exit 3,
     "inactive" or "failed"; exit 4 is a unit that does not exist, refused). A refusal before step 5 starts both
     again, as they were.
  4. THE REVISION CHECK (ed, A): the stopped backend's own revision (`etcdutl snapshot status`, read offline) is at
     least what this node applied. Less is not this node's store (a wrong disk, a restored copy): refused.
  5. THE FORCE. A runtime drop-in (/run, gone at the next boot) points regalia-etcd.service at a copy of its checked
     configuration (etcdconf.check) with "force-new-cluster": true, which etcdconf.check refuses in the normal one.
     etcd keeps its cluster ID, member ID and revision (measured on 3.6.15) and drops every other member.
  6. ALONE AND WHOLE. etcd answers with this node as its only member, the cluster applied.json named, and a revision
     no lower than the backend's.
  7. THE FIRST WRITE: the state-epoch entry (opstate.verify_state_epoch), the owner's authorization inside it, signed
     by this node's TPM signing key, put only if the key's version is still what was read (etcdctl txn). A value
     already at the key is verified first, bound to this store (62): one that does not verify is refused.
  8. BACK TO NORMAL. The drop-in is removed, systemd reloaded, etcd restarted on its normal configuration, and the
     unit's DropInPaths read back without it (regalia-kms-d9): a drop-in left in place would force a new cluster
     again at the next restart and silently drop members added since. Until that read-back, the take-over has not
     finished, and forcing() refuses a member add (the rejoin's own check). Then the daemon starts.

The forced configuration is etcd's to read: in /run/regalia-etcd, a setgid regalia-etcd-client directory, a file root
makes would carry that group, so it is written regalia-etcd:regalia-etcd, 0600 (d9).

A crash or refusal from step 5 on leaves etcd and the daemon stopped, and the next run takes it from there: the drop-in is in /run only, a force run
twice on one member is the same one-member cluster, and the state-epoch put is a compare on the version it read
(a second run finds the entry and stops: "already taken over at epoch N").

With the daemon stopped, nothing writes before step 7. Once it runs again, its gate takes a stateful operation in
recovery only when the store holds the authorization's own state epoch (regalia-kms-62, internal/opstate). The rejoin of the fenced servers (wipe,
member add, G5's export first) is not this command's.
"""
import argparse
import json
import os
import subprocess
import sys

from deploy.baremetal import etcdconf, membership, opstate, survivor

Refused, require = membership.Refused, membership.require

UNIT = "regalia-etcd.service"
DAEMON = "regalia-kms.service"
BOOT_ID = "/proc/sys/kernel/random/boot_id"
DROPIN_DIR = "/run/systemd/system/regalia-etcd.service.d"
DROPIN = DROPIN_DIR + "/50-takeover.conf"
TAKEOVER_CONFIG = "/run/regalia-etcd/takeover.conf.yml"
ETCD, ETCDCTL, ETCDUTL = "/usr/bin/etcd", "/usr/bin/etcdctl", "/usr/bin/etcdutl"
BACKEND = etcdconf.DATA_DIR + "/member/snap/db"
ENDPOINT = etcdconf.client_endpoint()                 # unix:///run/regalia-etcd/client.sock:0, derived (05 on #513)
APPLIED = "/run/regalia-state/applied.json"
APPLIED_FIELDS = ("boot_id", "boottime_ns", "cluster_id", "revision", "state_epoch")
MAX_FILE_BYTES = 256 * 1024
ETCD_USER = "regalia-etcd"


def say(text):
    print("TAKEOVER: " + text, flush=True)


def dropin():
    return "[Service]\nExecStart=\nExecStart=%s --config-file %s\n" % (ETCD, TAKEOVER_CONFIG)


def forced(config_text, node_id):
    """The normal configuration, checked, with force-new-cluster added: the take-over's one-off copy."""
    config = etcdconf.check(config_text)
    require(config["name"] == node_id, "etcd's configuration is %s's, not %s's" % (config["name"], node_id))
    config["force-new-cluster"] = True
    return json.dumps(config, indent=1, sort_keys=True) + "\n"


def applied(text):
    """applied.json: (cluster_id 16 hex, revision, state_epoch, boot_id)."""
    doc = json.loads(text)
    membership.exact(doc, APPLIED_FIELDS, "applied.json")
    membership.hex_field(doc["cluster_id"], 16, "applied.json's cluster_id")
    for k in ("revision", "state_epoch"):
        require(isinstance(doc[k], int) and not isinstance(doc[k], bool) and doc[k] >= 0, "applied.json's %s must be an integer from 0" % k)
    require(isinstance(doc["boot_id"], str), "applied.json's boot_id must be a string")
    return doc["cluster_id"], doc["revision"], doc["state_epoch"], doc["boot_id"]


def _json(done, what):
    require(done.returncode == 0, "%s failed (%d): %s" % (what, done.returncode, (done.stderr or done.stdout or "").strip()[-300:]))
    try:
        return json.loads(done.stdout)
    except ValueError:
        raise Refused("%s did not answer JSON" % what) from None


def alone(host, node_id, cluster_id, at_least):
    """etcd answers as a cluster of this node only, the cluster named, at a revision of at least `at_least`."""
    status = _json(host.run([ETCDCTL, "--endpoints", ENDPOINT, "endpoint", "status", "-w", "json"]), "etcdctl endpoint status")
    require(isinstance(status, list) and len(status) == 1, "etcdctl endpoint status answered %d endpoints" % len(status or []))
    header = status[0]["Status"]["header"]
    members = _json(host.run([ETCDCTL, "--endpoints", ENDPOINT, "member", "list", "-w", "json"]), "etcdctl member list")["members"]
    require([m.get("name") for m in members] == [node_id], "etcd's members are %s, not %s alone" % (sorted(m.get("name") for m in members), node_id))
    got = "%016x" % header["cluster_id"]
    require(got == cluster_id, "etcd answers as cluster %s; this node applied cluster %s" % (got, cluster_id))
    require(header["revision"] >= at_least, "etcd answers at revision %d, below the %d its backend held" % (header["revision"], at_least))
    return header["revision"]


def forcing(host):
    """Whether systemd still runs regalia-etcd.service with the take-over's drop-in (read back, not assumed). A member
    add while it does would be undone by the next restart's force-new-cluster: the rejoin refuses it."""
    done = host.run(["systemctl", "show", "--property=DropInPaths", "--value", UNIT])
    require(done.returncode == 0, "systemctl show %s failed (%d)" % (UNIT, done.returncode))
    return DROPIN in (done.stdout or "").split()


def current_state_epoch(host, chain, cluster_id):
    """(version, entry or None) of the state-epoch key as etcd holds it now, the entry verified and bound to this store
    (62): a value there that does not verify is refused, never taken for "already taken over"."""
    got = _json(host.run([ETCDCTL, "--endpoints", ENDPOINT, "get", opstate.STATE_EPOCH_KEY, "-w", "json"]), "etcdctl get")
    kvs = got.get("kvs") or []
    if not kvs:
        return 0, None
    import base64
    try:
        value = json.loads(base64.b64decode(kvs[0]["value"]))
    except ValueError:
        raise Refused("the state-epoch key holds something that is not JSON: refused, never overwritten") from None
    entry = opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, value, chain, None, (cluster_id, kvs[0]["mod_revision"]))
    return kvs[0]["version"], entry


def put_state_epoch(host, value, version):
    """Txn: if the key's version is still `version`, put the value. True if it committed."""
    script = 'version("%s") = "%d"\n\nput %s %s\n\n\n' % (opstate.STATE_EPOCH_KEY, version, opstate.STATE_EPOCH_KEY,
                                                          json.dumps(json.dumps(value, sort_keys=True, separators=(",", ":"))))
    done = _json(host.run([ETCDCTL, "--endpoints", ENDPOINT, "txn", "-w", "json"], input=script), "etcdctl txn")
    return done.get("succeeded") is True


def _stop(host, unit):
    done = host.run(["systemctl", "stop", unit])
    require(done.returncode == 0, "systemctl stop %s failed (%d)" % (unit, done.returncode))
    done = host.run(["systemctl", "is-active", unit])
    state = (done.stdout or "").strip()
    require(done.returncode == 3 and state in ("inactive", "failed"), "%s is not stopped (is-active: %d, %r)" % (unit, done.returncode, state))
    return state


def _start(host, *units, verb="start"):
    for argv in [["systemctl", "daemon-reload"]] + [["systemctl", verb, u] for u in units]:
        done = host.run(argv)
        require(done.returncode == 0, "%s failed (%d)" % (" ".join(argv), done.returncode))


def run(host, signed, chain, node_id, now, sign):
    """The take-over (module docstring), on `host` (run(argv, input=None) -> CompletedProcess; read, write, remove a
    path). `chain`: the verified membership chain, oldest first, its last the current manifest. `sign(raw)`: r || s hex
    by this node's signing key. Returns the state epoch the store holds."""
    current = chain[-1]
    # 1. the scope
    _, scope = survivor.in_force(signed, current, node_id, now)
    auth = signed["authorization"]
    require(scope == "full", "the full scope begins at %s; until then this node serves stateless operations only, and its etcd "
            "stays as it is" % survivor._stamp(survivor.full_from(auth)) if auth["scope"] == "full"
            else "the owner's authorization is stateless: a take-over needs \"full\"")
    say("the owner's full-scope authorization for %s at epoch %d is in force" % (node_id, current["epoch"]))
    # 2. what this node applied, before etcd stops: this boot's (applied.json is in /run, so another boot's cannot be
    # there; checked all the same, 62)
    cluster_id, applied_revision, _, boot = applied(host.read(APPLIED))
    require(boot == host.read(BOOT_ID).strip(), "applied.json is from boot %s, not this one" % boot)
    say("this node applied revision %d of cluster %s" % (applied_revision, cluster_id))
    # 3. the daemon, then etcd, stopped (62: the daemon would write its session entry the moment etcd took writes
    # again, and the state epoch is to be the first write)
    say("%s stopped (%s)" % (DAEMON, _stop(host, DAEMON)))
    try:
        say("etcd stopped (%s)" % _stop(host, UNIT))
        # 4. the revision check, offline
        backend = _json(host.run([ETCDUTL, "snapshot", "status", BACKEND, "-w", "json"]), "etcdutl snapshot status")
        held = backend.get("revision")
        require(isinstance(held, int) and held >= applied_revision, "the backend on disk is at revision %r, below the %d this node "
                "applied: it is not this node's store" % (held, applied_revision))
        say("the backend holds revision %d" % held)
        forced_text = forced(host.read(etcdconf.CONFIG_PATH), node_id)
    except Refused:
        # nothing forced yet: etcd and the daemon go back as they were (no stranding), and the refusal is said
        _start(host, UNIT, DAEMON)
        raise
    # 5. the force. From here a refusal leaves both stopped and the drop-in in /run: running the take-over again is
    # the way on (each step takes the state the last left), and a reboot drops the drop-in
    host.write(TAKEOVER_CONFIG, forced_text, owner=ETCD_USER, mode=0o600)
    host.write(DROPIN, dropin())
    _start(host, UNIT)
    # 6. alone and whole
    revision = alone(host, node_id, cluster_id, held)
    say("etcd is a cluster of %s alone (cluster %s, revision %d)" % (node_id, cluster_id, revision))
    # 7. the first write
    version, previous = current_state_epoch(host, chain, cluster_id)
    if previous is not None and previous["state_epoch"] == auth["quarantine_epoch"]:
        say("already taken over at epoch %d" % previous["state_epoch"])
    else:
        entry = {"schema": opstate.STATE_EPOCH_SCHEMA, "state_epoch": auth["quarantine_epoch"], "node_id": node_id, "authorization": signed,
                 "cluster_id": cluster_id, "revision_before": revision, "issued_at": survivor._stamp(now)}
        value = {"entry": entry, "signature": sign(opstate.state_epoch_message(entry))}
        opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, value, chain, previous)
        require(put_state_epoch(host, value, version), "the state-epoch key changed while this ran: run again")
        say("state epoch %d written, the first write after revision %d" % (auth["quarantine_epoch"], revision))
    # 8. back to normal, then the daemon
    host.remove(DROPIN)
    host.remove(TAKEOVER_CONFIG)
    _start(host, UNIT, verb="restart")
    require(not forcing(host), "%s still carries the take-over drop-in after its removal: the take-over has not finished" % UNIT)
    alone(host, node_id, cluster_id, revision)
    _start(host, DAEMON)
    say("etcd runs on its normal configuration, %s alone, at state epoch %d; %s started" % (node_id, auth["quarantine_epoch"], DAEMON))
    return auth["quarantine_epoch"]


class Host:
    """The real host: commands, and files written whole (a temporary file, fsynced, renamed)."""

    def run(self, argv, input=None):
        return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=120, check=False)

    def read(self, path):
        with open(path, "rb") as f:
            data = f.read(MAX_FILE_BYTES + 1)
        require(len(data) <= MAX_FILE_BYTES, "%s is over %d bytes" % (path, MAX_FILE_BYTES))
        return data.decode()

    def write(self, path, text, owner=None, mode=0o644):
        os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        if owner is not None:
            import pwd
            user = pwd.getpwnam(owner)
            os.fchown(fd, user.pw_uid, user.pw_gid)          # never the setgid directory's group
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def remove(self, path):
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def chain_of(envelopes, root_key):
    """The verified manifests of a published chain, oldest first."""
    require(isinstance(envelopes, list) and envelopes, "the membership chain must be a non-empty list of envelopes")
    out, current = [], None
    for env in envelopes:
        current = membership.accept(current, env, root_key)
        out.append(current)
    return out


def main(argv=None, host=None, now=None, signer=None):
    parser = argparse.ArgumentParser(prog="takeover", description=__doc__.split("\n\n")[0])
    parser.add_argument("--config", required=True, help="the node's configuration (node.json)")
    sub = parser.add_subparsers(dest="command", required=True)
    go = sub.add_parser("run", help="take etcd over as the lone survivor")
    go.add_argument("--authorization", required=True, help="the owner's signed survivor authorization (JSON)")
    args = parser.parse_args(argv)
    from deploy.baremetal import node as nodemod
    try:
        node = nodemod.load(args.config)
        host = host or Host()
        signed = json.loads(host.read(args.authorization))
        chain = chain_of(nodemod.read_published(node.path(nodemod.PUBLISHED)), node.cfg["root_key"])
        require(chain[-1]["epoch"] == node.manifest()["epoch"], "the published chain's tip is not the anchored manifest")
        if signer is None:
            from deploy.baremetal import signkey
            pem = host.read(signkey.PCR_PUBLIC_KEY_PATH).encode()
            signer = lambda raw: signkey.sign(raw, pem, node.tcti, node.run)  # noqa: E731
        clock = now if now is not None else node.clock()()
        run(host, signed, chain, node.node_id, clock, signer)
    except (Refused, OSError, ValueError, KeyError) as refused:
        say("REFUSED: %s" % refused)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
