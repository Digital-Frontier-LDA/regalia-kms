#!/usr/bin/env python3
"""A single-node host's etcd restore from a snapshot, which raises the state epoch before the daemon runs again
(regalia-kms-dx7.6, docs/design/single-node.md 4.8).

One node's operational state (spends, Cosmos sequences, key state) rests on one disk. A snapshot restored after that
disk is lost brings back an OLDER history: a spend or a sequence used since the snapshot could be used again. So a
restored store must never be taken for the live history: its first write is a state-epoch entry
(opstate.verify_state_epoch) whose epoch R the owner names in a signed restore statement, above a floor that survives
the node's loss, and the KMS daemon starts only once the store holds it.

THE OWNER, off the nodes (`sign-statement`). The floor F is the higher of the collector's highest recorded state epoch
for the cluster (typed by the owner, read from the collector) and this tool's LEDGER of the restore epochs it has issued
for the cluster (by its genesis digest). R = F + 1 is written to the ledger BEFORE the card signs, so each R is issued
once: restoring one snapshot twice gives two epochs, and a statement that was never used burns its number. The
statement names the node, the manifest it is signed under (single-node, by its digest), R and F, the snapshot's SHA-256
and a window of at most opstate.RESTORE_MAX_LIFE_S.

    python3 -Es -m deploy.baremetal.restore sign-statement --chain CHAIN --root-key ROOT --node-id N --snapshot-sha256 H \
        --collector-epoch E --ledger FILE --out FILE --module .. --serial ..

THE NODE, at its console, by root (`run`). Each step is refused unless the one before it held, and says so on stdout:

  1. THE STATEMENT holds (opstate.verify_restore) under this node's current manifest, which is single-node (a multi-node
     cluster's etcd comes back by a take-over and a rejoin), and now is inside its window.
  2. THE SNAPSHOT is the one it names (SHA-256), and etcd's configuration is the single-node one (etcdconf.check).
  3. THE DAEMON, THEN etcd, STOPPED. A refusal from here until step 5 starts both again, as they were.
  4. THE RESTORE INTO STAGING: `etcdutl snapshot restore` into STAGING (inside etcd's state directory), with the member
     name, peer URL, initial cluster and token of the checked configuration. The live data directory is not touched.
  5. etcd ON THE STAGING STORE: a runtime drop-in (/run: gone at the next boot) points regalia-etcd.service at a copy of
     the checked configuration whose data-dir is STAGING, and nothing else changed. etcd answers as this one member.
  6. THE RAISE: the store's state-epoch entry, if any, is read and verified; R must be above it, or the restore is
     REFUSED and the daemon stays stopped. The entry carrying the statement, signed by this node's TPM key, is written
     with a compare on the version read (etcdctl txn), and read back.
  7. THE EXCHANGE: etcd stopped, the drop-in removed, then the staging and the live member directories exchanged in one
     rename (renameat2 RENAME_EXCHANGE; a plain rename when there is no live store), the directory then fsynced: the live
     directory is either the old store or the restored one that holds R, never anything between. The old store is kept,
     in STAGING, for the operator to remove.
  8. THE DAEMON ONLY ON A RAISED EPOCH: etcd restarted on its normal configuration, the drop-in read back absent, the
     state epoch read back from the live store; only if it is R is the daemon started.

A crash or a refusal from step 5 on leaves the daemon stopped. A reboot drops the drop-in, and etcd comes back on the
live directory: the old store before step 7, the restored one holding R after it. A second run refuses while STAGING
exists: the operator looks at it first.
"""
import argparse
import hashlib
import json
import os
import sys
import time

from deploy.baremetal import etcdconf, heartbeat, membership, opstate, takeover

Refused, require = membership.Refused, membership.require

UNIT, DAEMON = takeover.UNIT, takeover.DAEMON
ETCDCTL, ETCDUTL, ENDPOINT = takeover.ETCDCTL, takeover.ETCDUTL, takeover.ENDPOINT
DROPIN = takeover.DROPIN_DIR + "/50-restore.conf"
RESTORE_CONFIG = "/run/regalia-etcd/restore.conf.yml"
STAGING = etcdconf.DATA_DIR + "/restore"              # inside the unit's StateDirectory: etcd may write there, nobody else
MEMBER = etcdconf.DATA_DIR + "/member"
ETCD_USER = takeover.ETCD_USER
SKEW_S = heartbeat.FUTURE_SKEW
LEDGER_SCHEMA = "regalia.restore-ledger/v1"
MAX_SNAPSHOT_BYTES = etcdconf.QUOTA_BYTES + 64 * 1024 ** 2


def say(text):
    print("RESTORE: " + text, flush=True)


def stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


# ---- the owner's side ----

class Ledger:
    """The restore epochs this tool has issued, per cluster (its genesis digest): {"schema", "clusters": {digest: [R, ...]}}.
    issue() writes the new epoch before the statement is signed (whole or not at all: a temporary file, fsynced, renamed),
    so no epoch is issued twice, even after a crash or a refused touch."""

    def __init__(self, path):
        self.path = path

    def read(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                doc = membership.load(f.read().encode(), membership.MAX_BYTES)
        except FileNotFoundError:
            return {"schema": LEDGER_SCHEMA, "clusters": {}}
        membership.exact(doc, ("schema", "clusters"), "the restore ledger")
        require(doc["schema"] == LEDGER_SCHEMA and isinstance(doc["clusters"], dict), "the restore ledger is not a %s" % LEDGER_SCHEMA)
        for cluster, issued in doc["clusters"].items():
            membership.hex_field(cluster, 64, "the restore ledger's cluster")
            require(isinstance(issued, list) and all(type(r) is int and r >= 1 for r in issued) and issued == sorted(set(issued)),
                    "the restore ledger's epochs for %s are not a rising list of epochs" % cluster[:16])
        return doc

    def issue(self, cluster, floor):
        """R above `floor` and above every epoch issued for `cluster`, recorded; returns (R, the floor used)."""
        doc = self.read()
        issued = doc["clusters"].get(cluster, [])
        used = max([floor] + issued)
        epoch = used + 1
        doc["clusters"][cluster] = issued + [epoch]
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(doc, sort_keys=True, indent=1) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        return epoch, used


def statement_body(chain, node_id, snapshot_sha256, epoch, floor, now, life_s=6 * 3600):
    """The restore statement (opstate.RESTORE_FIELDS) for `node_id` under the chain's tip, checked as the node will."""
    tip = chain[-1]
    require(membership.profile(tip) == membership.SINGLE_NODE, "an etcd restore is the %s profile's; epoch %d is %s"
            % (membership.SINGLE_NODE, tip["epoch"], membership.profile(tip)))
    require(isinstance(life_s, int) and 0 < life_s <= opstate.RESTORE_MAX_LIFE_S, "a restore statement lives 1 to %d s"
            % opstate.RESTORE_MAX_LIFE_S)
    statement = {"schema": opstate.RESTORE_SCHEMA, "node_id": node_id, "manifest_epoch": tip["epoch"], "manifest_digest": membership.digest(tip),
                 "state_epoch": epoch, "floor": floor, "snapshot_sha256": snapshot_sha256,
                 "not_before": stamp(now), "expires_at": stamp(now + life_s)}
    opstate.restore_message(statement)
    return statement


def shown(statement):
    digest = hashlib.sha256(opstate.restore_message(statement)).hexdigest()
    text = ("AN ETCD RESTORE for the owner to sign:\n  node          %s\n  manifest      epoch %d (%s)\n  state epoch   %d, above the floor %d\n"
            "  snapshot      SHA-256 %s\n  valid         %s to %s\n  signs         SHA-256 %s"
            % (statement["node_id"], statement["manifest_epoch"], statement["manifest_digest"][:16], statement["state_epoch"],
               statement["floor"], statement["snapshot_sha256"], statement["not_before"], statement["expires_at"], digest))
    return text, digest


def make_statement(chain, node_id, snapshot_sha256, collector_epoch, ledger, now, confirm, open_signer, life_s=6 * 3600, say=print):
    """The owner's signed restore statement: R from the ledger above the collector's epoch, recorded before the touch; the
    owner types R and the first 8 hex digits of what is signed. Refused, with nothing signed, otherwise."""
    require(type(collector_epoch) is int and collector_epoch >= 0, "the collector's highest state epoch is an integer from 0")
    membership.hex_field(snapshot_sha256, 64, "the snapshot's SHA-256")
    tip = chain[-1]
    statement_body(chain, node_id, snapshot_sha256, 1, 0, now, life_s)          # the checks, before an epoch is spent
    owners = [e["key"] for e in tip["owner_keys"] if e["alg"] == "ed25519"]
    signer = open_signer()
    require(signer.public() in owners, "the token's key %s... is not one of the manifest's owner_keys: nothing is signed" % signer.public()[:16])
    epoch, floor = ledger.issue(membership.digest(chain[0]), collector_epoch)
    statement = statement_body(chain, node_id, snapshot_sha256, epoch, floor, now, life_s)
    text, digest = shown(statement)
    words = (confirm(text) or "").strip().lower().split()
    require(len(words) == 2 and words[0] == str(epoch) and len(words[1]) == 8 and digest.startswith(words[1]),
            "the state epoch and digest typed are not this statement's: nothing is signed (epoch %d stays issued)" % epoch)
    say("Touch the key now (it signs when touched).")
    sig = signer.sign(opstate.restore_message(statement)).hex()
    signed = {"restore": statement, "signature": {"party": membership.OWNER, "key": signer.public(), "sig": sig}}
    opstate.verify_restore(signed, chain, node_id)
    return signed


# ---- the node's side ----

def staged_config(config_text):
    """The checked single-node configuration with its data-dir moved to STAGING, and nothing else changed."""
    config = etcdconf.check(config_text, membership.SINGLE_NODE)
    config["data-dir"] = STAGING
    return json.dumps(config, indent=1, sort_keys=True) + "\n"


def dropin():
    return "[Service]\nExecStart=\nExecStart=%s --config-file %s\n" % (takeover.ETCD, RESTORE_CONFIG)


def one_member(host, node_id):
    """(cluster_id hex, revision) of etcd answering as `node_id` alone."""
    status = takeover._json(host.run([ETCDCTL, "--endpoints", ENDPOINT, "endpoint", "status", "-w", "json"]), "etcdctl endpoint status")
    require(isinstance(status, list) and len(status) == 1, "etcdctl endpoint status answered %d endpoints" % len(status or []))
    header = status[0]["Status"]["header"]
    members = takeover._json(host.run([ETCDCTL, "--endpoints", ENDPOINT, "member", "list", "-w", "json"]), "etcdctl member list")["members"]
    require([m.get("name") for m in members] == [node_id], "etcd's members are %s, not %s alone" % (sorted(m.get("name") for m in members), node_id))
    return "%016x" % header["cluster_id"], header["revision"]


def held_epoch(host, chain, cluster_id):
    """(version, the store's verified state-epoch entry or None)."""
    return takeover.current_state_epoch(host, chain, cluster_id)


def run(host, signed, chain, node_id, snapshot, now, sign, facts=None):
    """The restore (module docstring) on `host` (takeover.Host's interface, and sha256(path)). `chain`: the verified
    membership chain, oldest first. `snapshot`: the snapshot file's path. `sign(raw)`: r || s hex by this node's signing
    key. Returns the state epoch the store holds when the daemon starts."""
    facts = {} if facts is None else facts
    current = chain[-1]
    # 1. the statement
    require(membership.profile(current) == membership.SINGLE_NODE, "an etcd restore is refused under the %s profile (epoch %d): a "
            "multi-node cluster's etcd comes back by a take-over and a rejoin" % (membership.profile(current), current["epoch"]))
    statement = opstate.verify_restore(signed, chain, node_id)
    require(statement["manifest_epoch"] == current["epoch"], "the restore statement is for epoch %d; this node's manifest is epoch %d: "
            "a new epoch ends it" % (statement["manifest_epoch"], current["epoch"]))
    start = heartbeat.parse_time(statement["not_before"], "not_before")
    end = heartbeat.parse_time(statement["expires_at"], "expires_at")
    require(start - SKEW_S <= now < end, "the restore statement is valid from %s to %s, not now" % (statement["not_before"], statement["expires_at"]))
    epoch = statement["state_epoch"]
    say("the owner's restore statement to state epoch %d (above the floor %d) holds" % (epoch, statement["floor"]))
    # 2. the snapshot and the configuration
    require(host.sha256(snapshot) == statement["snapshot_sha256"], "the snapshot %s is not the one the statement names" % snapshot)
    config_text = host.read(etcdconf.CONFIG_PATH)
    config = etcdconf.check(config_text, membership.SINGLE_NODE)
    require(config["name"] == node_id, "etcd's configuration is %s's, not %s's" % (config["name"], node_id))
    staged = staged_config(config_text)
    require(not host.exists(STAGING), "%s exists, left by an earlier restore: look at it, move it away, then run again" % STAGING)
    # 3. the daemon, then etcd
    say("%s stopped (%s)" % (DAEMON, takeover._stop(host, DAEMON)))
    try:
        say("etcd stopped (%s)" % takeover._stop(host, UNIT))
        # 4. the restore, into staging
        url = config["initial-advertise-peer-urls"]
        done = host.run([ETCDUTL, "snapshot", "restore", snapshot, "--data-dir", STAGING, "--name", node_id, "--initial-cluster",
                         config["initial-cluster"], "--initial-cluster-token", config["initial-cluster-token"], "--initial-advertise-peer-urls", url])
        require(done.returncode == 0, "etcdutl snapshot restore failed (%d): %s" % (done.returncode, (done.stderr or done.stdout or "").strip()[-300:]))
        done = host.run(["chown", "-R", "--no-dereference", "%s:%s" % (ETCD_USER, ETCD_USER), STAGING])
        require(done.returncode == 0, "chown of %s failed (%d)" % (STAGING, done.returncode))
    except Refused:
        _start(host, UNIT, DAEMON)
        raise
    say("the snapshot is restored into %s; the live store is untouched" % STAGING)
    facts.update(staged=True)
    # 5. etcd on the staging store. From here a refusal leaves the daemon stopped
    host.write(RESTORE_CONFIG, staged, owner=ETCD_USER, mode=0o600)
    host.write(DROPIN, dropin())
    _start(host, UNIT)
    cluster_id, revision = one_member(host, node_id)
    facts.update(cluster_id=cluster_id, revision_before=revision)
    # 6. the raise
    version, previous = held_epoch(host, chain, cluster_id)
    held = previous["state_epoch"] if previous is not None else 0
    require(epoch > held, "REFUSED: the restored store holds state epoch %d, and the statement's %d does not raise it: the daemon is not "
            "started (the owner issues a new statement)" % (held, epoch))
    entry = {"schema": opstate.STATE_EPOCH_SCHEMA, "state_epoch": epoch, "node_id": node_id, "authorization": signed,
             "cluster_id": cluster_id, "revision_before": revision, "issued_at": stamp(now)}
    value = {"entry": entry, "signature": sign(opstate.state_epoch_message(entry))}
    opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, value, chain, previous)
    require(takeover.put_state_epoch(host, value, version), "the state-epoch key changed while this ran: the daemon is not started")
    _, now_held = held_epoch(host, chain, cluster_id)
    require(now_held is not None and now_held["state_epoch"] == epoch, "the staging store does not hold state epoch %d after its write: "
            "the daemon is not started" % epoch)
    say("state epoch %d written over %d, the first write after revision %d" % (epoch, held, revision))
    # 7. the exchange
    takeover._stop(host, UNIT)
    host.remove(DROPIN)
    host.remove(RESTORE_CONFIG)
    try:
        host.exchange(STAGING + "/member", MEMBER)
    except OSError as error:
        raise Refused("the exchange of %s/member and %s failed (%s): the live store is as it was; the daemon is not started"
                      % (STAGING, MEMBER, error)) from None
    facts.update(exchanged=True)
    say("the restored store is live; the store it replaced is kept in %s" % STAGING)
    # 8. the daemon, only on a raised epoch
    _start(host, UNIT, verb="restart")
    require(not takeover.forcing(host) and not restoring(host), "%s still carries a drop-in after its removal: the daemon is not started" % UNIT)
    live_cluster, _ = one_member(host, node_id)
    _, live = held_epoch(host, chain, live_cluster)
    require(live is not None and live["state_epoch"] == epoch, "the live store holds state epoch %s, not %d: the daemon is not started"
            % (live["state_epoch"] if live else "none", epoch))
    _start(host, DAEMON)
    facts.update(state_epoch=epoch)
    say("etcd runs on its normal configuration at state epoch %d; %s started" % (epoch, DAEMON))
    return epoch


def restoring(host):
    """Whether systemd still runs regalia-etcd.service with this restore's drop-in (read back, not assumed)."""
    done = host.run(["systemctl", "show", "--property=DropInPaths", "--value", UNIT])
    require(done.returncode == 0, "systemctl show %s failed (%d)" % (UNIT, done.returncode))
    return DROPIN in (done.stdout or "").split()


def _start(host, *units, verb="start"):
    takeover._start(host, *units, verb=verb)


RENAME_EXCHANGE = 2                     # linux/fs.h
AT_FDCWD = -100


class Host(takeover.Host):
    def exists(self, path):
        return os.path.lexists(path)

    def exchange(self, staged, live):
        """`staged` becomes `live` in one rename: the two exchanged (renameat2 RENAME_EXCHANGE) when `live` exists, else
        renamed into place; then their directory fsynced. Never a moment with no live directory."""
        import ctypes
        if os.path.lexists(live):
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.renameat2(AT_FDCWD, os.fsencode(staged), AT_FDCWD, os.fsencode(live), RENAME_EXCHANGE) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code), live)
        else:
            os.rename(staged, live)
        for directory in {os.path.dirname(staged), os.path.dirname(live)}:
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def sha256(self, path):
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                size += len(block)
                require(size <= MAX_SNAPSHOT_BYTES, "the snapshot is over %d bytes" % MAX_SNAPSHOT_BYTES)
                h.update(block)
        return h.hexdigest()


def main(argv=None, host=None, now=None, signer=None):
    parser = argparse.ArgumentParser(prog="restore", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    go = sub.add_parser("run", help="(root, at the node's console) restore etcd from a snapshot and raise the state epoch")
    go.add_argument("--config", required=True, help="the node's configuration (node.json)")
    go.add_argument("--statement", required=True, help="the owner's signed restore statement (JSON)")
    go.add_argument("--snapshot", required=True, help="the etcd snapshot the statement names")
    s = sub.add_parser("sign-statement", help="(off the nodes) the owner's restore statement, its epoch from the ledger")
    s.add_argument("--chain", required=True, help="the node's signed chain")
    s.add_argument("--root-key", required=True, help="the pinned root, as manifest.py takes it")
    s.add_argument("--node-id", required=True)
    s.add_argument("--snapshot-sha256", required=True)
    s.add_argument("--collector-epoch", type=int, required=True, help="the collector's highest recorded state epoch for the cluster")
    s.add_argument("--ledger", required=True, help="this tool's ledger of issued restore epochs (kept by the owner)")
    s.add_argument("--life-s", type=int, default=6 * 3600)
    s.add_argument("--out", required=True)
    for flag, kw in (("--module", {"required": True}), ("--serial", {"required": True}), ("--key-id", {}), ("--key-label", {}),
                     ("--opensc-conf", {})):
        s.add_argument(flag, **kw)
    args = parser.parse_args(argv)
    try:
        if args.command == "sign-statement":
            from deploy.baremetal import keyfd, manifest as manifest_tool, owner, p11sign
            owner.off_the_nodes()
            envelopes = manifest_tool.read_json(args.chain, 4 * 1024 * 1024)
            chain = takeover.chain_of(envelopes, manifest_tool.root_key(args.root_key))

            def pin():
                typed = keyfd.tty_secret("The approval key's PIN (not shown): ", "the PIN", limit=64)
                try:
                    return typed.decode("ascii")
                finally:
                    keyfd.zero(typed)

            def open_signer():
                return signer or p11sign.Pkcs11Signer(args.module, args.serial, args.key_id, None, opensc_conf=args.opensc_conf,
                                                      key_label=args.key_label, only_token=True, pin=pin, alg="ed25519")

            def confirm(text):
                print(text)
                return keyfd.tty_line("Type the state epoch and the first 8 hex digits of the SHA-256: ")
            signed = make_statement(chain, args.node_id, args.snapshot_sha256, args.collector_epoch, Ledger(args.ledger),
                                    now if now is not None else int(time.time()), confirm, open_signer, life_s=args.life_s)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as f:
                json.dump(signed, f, sort_keys=True)
            print("WRITTEN: %s, state epoch %d, valid until %s; give it to %s with the snapshot (restore run)"
                  % (args.out, signed["restore"]["state_epoch"], signed["restore"]["expires_at"], args.node_id))
            return 0
        from deploy.baremetal import node as nodemod
        node = nodemod.load(args.config)
        host = host or Host()
        signed = json.loads(host.read(args.statement))
        chain = takeover.chain_of(nodemod.read_published(node.path(nodemod.PUBLISHED)), node.cfg["root_key"])
        require(chain[-1]["epoch"] == node.manifest()["epoch"], "the published chain's tip is not the anchored manifest")
        if signer is None:
            from deploy.baremetal import signkey
            pem = host.read(signkey.PCR_PUBLIC_KEY_PATH).encode()
            signer = lambda raw: signkey.sign(raw, pem, node.tcti, node.run)  # noqa: E731
        run(host, signed, chain, node.node_id, args.snapshot, now if now is not None else node.clock()(), signer)
    except (Refused, OSError, ValueError, KeyError) as refused:
        say("REFUSED: %s" % refused)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
