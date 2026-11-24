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
  3. THE DAEMON, THEN etcd, STOPPED. A refusal from here until step 5 starts both again, as they were (with a live store;
     with none, neither: see THE BOOT GUARD).
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

THE LIVE STORE'S EPOCH. R must also raise the epoch the live store holds, read before anything stops (etcd is started
on it for the read if it was stopped; a store etcd will not start on is refused). Only when the live store is gone (the
lost disk) is it not read: then the statement's floor stands for it, and nothing on the node can enforce single use. The
restored store's state-epoch entry keeps the signed statement whole, so deleting the input file enforces nothing either.
Single use is then the OWNER'S PROCEDURE:
  * a statement handed to the node is CONSUMED, whatever happens next: after a restore whose outcome is unknown (an
    interruption, a crash, a refusal after the services stopped) the owner treats it as consumed and signs a new one
    (sign-statement issues the next epoch from the ledger) before any retry; the same statement is never given again;
  * its window is at most opstate.RESTORE_MAX_LIFE_S, which bounds how long a copy of it could be replayed.
What remains is detection, not prevention, and only in part: the collector's spend audit (spendaudit.py) flags an approval
spent twice in the streams it receives; it does not detect every history replayed under one epoch, and the collector is
not yet running (LIMITATIONS.md).

A crash or a refusal from step 5 on leaves the daemon stopped. A reboot drops the drop-in, and etcd comes back on the
live directory: the old store before step 7, the restored one holding R after it. A second run refuses while STAGING
exists: the operator looks at it first.

THE BOOT GUARD (regalia-kms-dx7.26). With no live store, etcd started at a boot would form a new, empty cluster and the
daemon serve on it at state epoch 0. So before step 3 stops anything, the run writes PENDING (/etc/regalia/restore-pending,
by its /var name, its directory fsynced): while it exists neither unit starts (units/*/10-restore-pending.conf). The
drop-in of step 5 resets those conditions for etcd alone; step 7 removes PENDING once the exchange is done, before etcd's
restart. Every refusal keeps it. `enrol commit` writes it too for a single-node replacement, and `mark-pending` by hand.
"""
import argparse
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import time

from deploy.baremetal import etcdconf, heartbeat, membership, opstate, takeover

Refused, require = membership.Refused, membership.require

UNIT, DAEMON = takeover.UNIT, takeover.DAEMON
ETCDCTL, ETCDUTL, ENDPOINT = takeover.ETCDCTL, takeover.ETCDUTL, takeover.ENDPOINT
DROPIN = takeover.DROPIN_DIR + "/50-restore.conf"
# regalia-kms-dx7.26: while it exists neither etcd nor the daemon starts, at any boot (units/*/10-restore-pending.conf).
# Written by its /var name before a lost-disk restore stops anything, removed once the restored store is exchanged in
PENDING, STORED_PENDING = etcdconf.RESTORE_PENDING, etcdconf.STORED_RESTORE_PENDING
PENDING_SCHEMA = "regalia.restore-pending/v1"
RESTORE_CONFIG = "/run/regalia-etcd/restore.conf.yml"
STAGING = etcdconf.DATA_DIR + "/restore"              # inside the unit's StateDirectory: etcd may write there, nobody else
MEMBER = etcdconf.DATA_DIR + "/member"
# one restore at a time on a host: held from before run() starts until it returns or its recovery is done
RESTORE_LOCK = "/run/lock/regalia-restore.lock"
# the snapshot as hashed: copied while its digest is computed, and only this copy is restored (never the path again)
VERIFIED_SNAPSHOT = etcdconf.DATA_DIR + "/restore.snapshot"
ETCD_USER = takeover.ETCD_USER
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
        """R above `floor` and above every epoch issued for `cluster`, recorded; returns (R, the floor used). The read, the
        increment and the durable write (the file and its directory fsynced) are one step under an exclusive lock on
        `path`.lock, released before the card is touched: a second signer waits, then reads R and issues R + 1."""
        lock = os.open(self.path + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            doc = self.read()
            issued = doc["clusters"].get(cluster, [])
            used = max([floor, *issued])
            epoch = used + 1
            doc["clusters"][cluster] = [*issued, epoch]
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(doc, sort_keys=True, indent=1) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            directory = os.open(os.path.dirname(os.path.abspath(self.path)), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)                  # the rename survives a power loss before anything is signed
            finally:
                os.close(directory)
            return epoch, used
        finally:
            os.close(lock)                           # the lock goes with the descriptor


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
    """The runtime drop-in that runs etcd on STAGING. Its empty ConditionPathExists= resets every condition read before it,
    the restore-pending marker's included (10-restore-pending.conf sorts before 50-restore.conf, whatever the directory:
    systemd reads drop-ins in file-name order), and lists the unit's own two gates again."""
    return ("[Unit]\nConditionPathExists=\nConditionPathExists=%s\nConditionPathExists=/etc/regalia/node.json\n"
            "[Service]\nExecStart=\nExecStart=%s --config-file %s\n" % (etcdconf.CONFIG_PATH, takeover.ETCD, RESTORE_CONFIG))


def _pending_metric(pending):
    """The boot guard's metric (regalia-kms-dx7.9's RegaliaRestorePending), published by the node at every boot and here at
    mark/clear. The node runs as regalia-sync and cannot write root's metrics directory, so root writes the file whole in
    its own mode; the gauge's value is the marker's existence and nothing the marker's content says. Never raises: a
    metrics write must not stand between the marker and the boot guard it names."""
    from deploy.baremetal import metrics
    try:
        text = metrics.render("restore", [("regalia_restore_pending", {}, 1 if pending else 0)])
        metrics.write(metrics.path("restore", "pending.prom"), text)
    except Exception:                             # noqa: BLE001 - see above
        pass


def mark_pending(host, reason, now):
    """The restore-pending marker, written whole and its directory fsynced: from here a reboot starts neither etcd nor the
    daemon. Its content is for the operator; the units read only that it exists. The metric says it is held now, not at
    the next boot: RegaliaRestorePending names the cause of the SingleNodeDown a held host raises."""
    host.write(STORED_PENDING, json.dumps({"schema": PENDING_SCHEMA, "reason": reason, "written_at": stamp(now)}, sort_keys=True) + "\n")
    host.sync_dir(os.path.dirname(STORED_PENDING))
    _pending_metric(True)


def clear_pending(host):
    host.remove(STORED_PENDING)
    host.sync_dir(os.path.dirname(STORED_PENDING))
    _pending_metric(False)


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


class NotDurable(OSError):
    """The exchange's rename completed, and the fsync of its directory after it did not: the restored store is live, and
    whether the rename survives a power loss is not known."""


def _state(host, unit):
    """`unit`'s state as systemctl reads it back now, by the state it prints and not its exit code alone (is-active exits 3
    for "activating" and "deactivating" too): "running" (active), "stopped" (inactive or failed), or "unknown", with the
    state systemctl gave, for anything in between or a read that failed."""
    try:
        done = host.run(["systemctl", "is-active", unit])
    except (subprocess.SubprocessError, OSError):
        return "unknown (is-active could not be run)"
    state = (done.stdout or "").strip()
    if done.returncode == 0 and state == "active":
        return "running"
    if done.returncode == 3 and state in ("inactive", "failed"):
        return "stopped"
    return "unknown (%s)" % (membership.printable(state, 40) or "exit %d" % done.returncode)


def _first_steps_back(host, error, live=True):
    """Before etcd runs on staging, a refusal (or a command that timed out, or a file error) starts etcd and the daemon
    again on the live store, untouched, as they were. With no live store neither is started: etcd would form a new empty
    cluster, and the restore-pending marker holds both skipped (a start would be skipped, and still exit 0).
    The refusal stays the one raised; a start that fails is added to it, with each unit's state as read back."""
    try:
        host.remove(VERIFIED_SNAPSHOT)          # only a copy: the snapshot itself is where it was, and a retry is not blocked
    except OSError:
        pass
    failed = []
    for unit in ((UNIT, DAEMON) if live else ()):
        try:
            _start(host, unit)
        except (Refused, subprocess.SubprocessError, OSError) as again:
            failed.append("%s: %s" % (unit, _reason(again)))
    if failed:
        states = ", ".join("%s %s" % (unit, _state(host, unit)) for unit in (UNIT, DAEMON))
        raise Refused("%s; and starting again failed (%s): as read back, %s; the live store is untouched and %s is kept for "
                      "inspection" % (_reason(error), "; ".join(failed), states, STAGING)) from error
    if not live:
        raise Refused("%s; %s and %s are left stopped, and %s holds them so at every boot until a restore exchanges a store "
                      "holding a raised state epoch" % (_reason(error), UNIT, DAEMON, PENDING)) from error
    if isinstance(error, Refused):
        raise error
    raise Refused("%s; started again on the untouched live store: %s" % (_reason(error), ", ".join(
        "%s %s" % (unit, _state(host, unit)) for unit in (UNIT, DAEMON)))) from error


def _off_staging(host, error, live=True):
    """Once etcd ran on staging and before the exchange, a refusal puts etcd back on the live store: stopped, the drop-in
    and its configuration removed, systemd reloaded, started on its normal configuration. The daemon stays stopped and
    STAGING is kept for inspection. The refusal stays the one raised; a step that fails is added to it."""
    failed = []
    steps = [lambda: takeover._stop(host, UNIT), lambda: host.remove(DROPIN), lambda: host.remove(RESTORE_CONFIG),
             lambda: require(host.run(["systemctl", "daemon-reload"]).returncode == 0, "systemctl daemon-reload failed")]
    if live:                                    # never restart etcd onto a missing live store: it would form an empty cluster
        steps.append(lambda: _start(host, UNIT, verb="restart"))
    for step in steps:
        try:
            step()
        except (Refused, subprocess.SubprocessError, OSError) as again:
            failed.append(_reason(again))
    if failed and not live:
        raise Refused("%s; and the cleanup failed (%s): remove %s and %s and reload systemd by hand, and leave %s and %s STOPPED: "
                      "there is no live store, and etcd started now would form a new, empty cluster" % (_reason(error), "; ".join(failed),
                                                                                                        DROPIN, RESTORE_CONFIG, UNIT, DAEMON)) from error
    if failed:
        raise Refused("%s; and putting etcd back on its live store failed (%s): remove %s, reload systemd and restart %s by hand; "
                      "the daemon is stopped" % (_reason(error), "; ".join(failed), DROPIN, UNIT)) from error
    if not live:
        raise Refused("%s; etcd is left stopped (there is no live store to put it back on) and so is the daemon; %s is kept, "
                      "and %s holds both stopped at every boot" % (_reason(error), STAGING, PENDING)) from error
    raise Refused("%s; etcd is back on its live store, the daemon is left stopped (start %s once %s has been looked at)"
                  % (_reason(error), DAEMON, STAGING)) from error


def _active(host, unit):
    """Whether `unit` runs (systemctl is-active: 0), or not (3); anything else is a refusal, never read as either."""
    done = host.run(["systemctl", "is-active", unit])
    require(done.returncode in (0, 3), "systemctl is-active %s failed (%d)" % (unit, done.returncode))
    return done.returncode == 0


def _reason(error):
    return str(error) if isinstance(error, Refused) else "%s: %s" % (type(error).__name__, error)


def run(host, signed, chain, node_id, snapshot, now, sign, facts=None, clock=None):
    """The restore (module docstring) on `host` (takeover.Host's interface, and exists, copy_verified, exchange). `chain`:
    the verified membership chain, oldest first. `snapshot`: the snapshot file's path. `now`: authenticated unix seconds;
    `clock()`: a fresh authenticated reading for the entry's issued_at (default: `now`). `sign(raw)`: r || s hex by this
    node's signing key. Returns the state epoch the store holds when the daemon starts."""
    facts = {} if facts is None else facts
    clock = clock or (lambda: now)
    current = chain[-1]
    # 1. the statement
    require(membership.profile(current) == membership.SINGLE_NODE, "an etcd restore is refused under the %s profile (epoch %d): a "
            "multi-node cluster's etcd comes back by a take-over and a rejoin" % (membership.profile(current), current["epoch"]))
    statement = opstate.verify_restore(signed, chain, node_id)
    require(statement["manifest_epoch"] == current["epoch"], "the restore statement is for epoch %d; this node's manifest is epoch %d: "
            "a new epoch ends it" % (statement["manifest_epoch"], current["epoch"]))
    start = heartbeat.parse_time(statement["not_before"], "not_before")
    end = heartbeat.parse_time(statement["expires_at"], "expires_at")
    # exactly the window opstate.verify_state_epoch judges the entry by (not_before <= issued_at < expires_at), no skew: a
    # reading the entry check would refuse is refused here, before anything stops
    require(start <= now < end, "the restore statement is valid from %s to %s, not now" % (statement["not_before"], statement["expires_at"]))
    epoch = statement["state_epoch"]
    say("the owner's restore statement to state epoch %d (above the floor %d) holds" % (epoch, statement["floor"]))
    # 2. nothing left over, and the configuration
    require(not host.exists(DROPIN), "%s is still in place: an earlier restore stopped part way. Put etcd back on its live store "
            "first (remove it and %s, reload systemd, restart %s)" % (DROPIN, RESTORE_CONFIG, UNIT))
    config_text = host.read(etcdconf.CONFIG_PATH)
    config = etcdconf.check(config_text, membership.SINGLE_NODE)
    require(config["name"] == node_id, "etcd's configuration is %s's, not %s's" % (config["name"], node_id))
    staged = staged_config(config_text)
    for path in (STAGING, VERIFIED_SNAPSHOT):
        require(not host.exists(path), "%s exists, left by an earlier restore: look at it, move it away, then run again" % path)
    # 2b. the live store's state epoch: R must raise it too, not only the snapshot's. Read whenever the store exists, etcd
    # started on it for the read if it was stopped; only a store that is gone (the lost disk) is not read
    live_exists = host.exists(MEMBER)
    if live_exists:
        if not _active(host, UNIT):
            try:
                _start(host, UNIT)
            except (Refused, subprocess.SubprocessError, OSError) as error:
                raise Refused("the live store %s exists and etcd does not start on it (%s): its state epoch cannot be read, so the "
                              "statement cannot be shown to raise it. If that store is lost, move it away (the lost-disk case) "
                              "and run again" % (MEMBER, _reason(error))) from None
            say("etcd started on the live store to read its state epoch")
        live_cluster, _ = one_member(host, node_id)
        _, live = held_epoch(host, chain, live_cluster)
        live_held = live["state_epoch"] if live is not None else 0
        require(epoch > live_held, "REFUSED: the live store holds state epoch %d, and the statement's %d does not raise it: nothing "
                "is stopped (the owner issues a new statement)" % (live_held, epoch))
        say("the live store holds state epoch %d" % live_held)
    else:
        say("there is no live store (%s): the lost-disk case. The statement's floor (the collector's highest and the owner's "
            "ledger's) stands for its state epoch; the statement is single-use by procedure (module docstring)" % MEMBER)
        # before anything stops: from here until the exchange, a reboot starts neither etcd (it would form a new, empty
        # cluster) nor the daemon (regalia-kms-dx7.26)
        mark_pending(host, "restore run: no live store (the lost disk); removed once the restored store is exchanged in", now)
        say("%s written: etcd and the daemon stay stopped at every boot until the exchange" % PENDING)
    # 3. the daemon, then etcd; 4. the snapshot, verified as it is copied, restored into staging
    say("%s stopped (%s)" % (DAEMON, takeover._stop(host, DAEMON)))
    try:
        say("etcd stopped (%s)" % takeover._stop(host, UNIT))
        digest = host.copy_verified(snapshot, VERIFIED_SNAPSHOT)
        require(digest == statement["snapshot_sha256"], "the snapshot %s is not the one the statement names" % snapshot)
        url = config["initial-advertise-peer-urls"]
        done = host.run([ETCDUTL, "snapshot", "restore", VERIFIED_SNAPSHOT, "--data-dir", STAGING, "--name", node_id, "--initial-cluster",
                         config["initial-cluster"], "--initial-cluster-token", config["initial-cluster-token"], "--initial-advertise-peer-urls", url])
        require(done.returncode == 0, "etcdutl snapshot restore failed (%d): %s" % (done.returncode, (done.stderr or done.stdout or "").strip()[-300:]))
        host.remove(VERIFIED_SNAPSHOT)
        done = host.run(["chown", "-R", "--no-dereference", "%s:%s" % (ETCD_USER, ETCD_USER), STAGING])
        require(done.returncode == 0, "chown of %s failed (%d)" % (STAGING, done.returncode))
    except (Refused, subprocess.SubprocessError, OSError) as error:
        _first_steps_back(host, error, live=live_exists)
    say("the snapshot is restored into %s; the live store is untouched" % STAGING)
    facts.update(staged=True)
    # 5. etcd on the staging store; 6. the raise. A refusal from here puts etcd back on the live store, the daemon stopped
    try:
        host.write(RESTORE_CONFIG, staged, owner=ETCD_USER, mode=0o600)
        host.write(DROPIN, dropin())
        _start(host, UNIT)
        cluster_id, revision = one_member(host, node_id)
        facts.update(cluster_id=cluster_id, revision_before=revision)
        version, previous = held_epoch(host, chain, cluster_id)
        held = previous["state_epoch"] if previous is not None else 0
        require(epoch > held, "REFUSED: the restored store holds state epoch %d, and the statement's %d does not raise it: the daemon is "
                "not started (the owner issues a new statement)" % (held, epoch))
        issued = clock()
        require(start <= issued < end, "the restore statement's window (%s to %s) does not hold the entry's time %s: the owner "
                "issues a new statement" % (statement["not_before"], statement["expires_at"], stamp(issued)))
        entry = {"schema": opstate.STATE_EPOCH_SCHEMA, "state_epoch": epoch, "node_id": node_id, "authorization": signed,
                 "cluster_id": cluster_id, "revision_before": revision, "issued_at": stamp(issued)}
        value = {"entry": entry, "signature": sign(opstate.state_epoch_message(entry))}
        opstate.verify_state_epoch(opstate.STATE_EPOCH_KEY, value, chain, previous)
        require(takeover.put_state_epoch(host, value, version), "the state-epoch key changed while this ran: the daemon is not started")
        _, now_held = held_epoch(host, chain, cluster_id)
        require(now_held is not None and now_held["state_epoch"] == epoch, "the staging store does not hold state epoch %d after its write: "
                "the daemon is not started" % epoch)
        say("state epoch %d written over %d, the first write after revision %d" % (epoch, held, revision))
        # 7. the exchange: etcd stopped and the drop-in removed first
        takeover._stop(host, UNIT)
        host.remove(DROPIN)
        host.remove(RESTORE_CONFIG)
    except (Refused, subprocess.SubprocessError, OSError) as error:
        _off_staging(host, error, live=live_exists)
    try:
        how = host.exchange(STAGING + "/member", MEMBER)
    except NotDurable as error:
        raise Refused("the restored store is live (%s), but the fsync of its directory failed (%s): whether the rename survives a power "
                      "loss is not known. etcd and the daemon are stopped. Once the file system is sound: start %s on its normal "
                      "configuration, check that no restore or take-over drop-in is active (systemctl show -p DropInPaths %s), read "
                      "the state epoch from the live etcd (it must be %d), and only then start %s. If %s is there, it holds both "
                      "skipped: remove %s by hand only once the live etcd reads state epoch %d (start etcd for that read with "
                      "systemd-run or a /run drop-in like %s, never by removing it first)"
                      % (MEMBER, error, UNIT, UNIT, epoch, DAEMON, PENDING, PENDING, epoch, DROPIN)) from None
    except OSError as error:
        # the rename did not happen: the live store is as it was. etcd goes back on it (never onto a missing one), the
        # daemon stays stopped, and STAGING (holding the restored store at R) is kept
        _off_staging(host, Refused("the exchange of %s/member and %s failed (%s): the live store is as it was; the daemon is not "
                                   "started" % (STAGING, MEMBER, error)), live=live_exists)
    facts.update(exchanged=how)
    # the restored store holding R is live: the marker goes before etcd's restart, which it would skip; the daemon is still
    # started only on R read back from the live store (step 8)
    try:
        clear_pending(host)
    except OSError as error:
        raise Refused("the restored store is live (%s), but %s could not be removed (%s): etcd and the daemon stay stopped. Remove "
                      "it, start %s, read the state epoch from the live etcd (it must be %d), and only then start %s"
                      % (MEMBER, PENDING, error, UNIT, epoch, DAEMON)) from None
    if how == "exchanged":
        say("the restored store is live; the store it replaced is kept in %s/member" % STAGING)
    else:
        say("the restored store is live; there was no live store to replace (%s/member is gone)" % STAGING)
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


class exclusive:
    """An exclusive lock on `path` for one restore run, recovery included (CodeRabbit on #740): a second run while one holds
    it is refused at once, before it stops or copies anything."""

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd)
            raise Refused("another restore is running on this host (%s is held): one at a time" % self.path) from None
        return self

    def __exit__(self, *exc):
        os.close(self.fd)                       # the lock goes with the descriptor
        return False


RENAME_EXCHANGE = 2                     # linux/fs.h
AT_FDCWD = -100


class Host(takeover.Host):
    def exists(self, path):
        return os.path.lexists(path)

    def sync_dir(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def exchange(self, staged, live):
        """`staged` becomes `live` in one rename: the two exchanged (renameat2 RENAME_EXCHANGE) when `live` exists, else
        renamed into place; then their directories fsynced. Never a moment with no live directory. Returns "exchanged" or
        "renamed"; an OSError means the rename did not happen, NotDurable that it did and a directory fsync failed."""
        import ctypes
        if os.path.lexists(live):
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.renameat2(AT_FDCWD, os.fsencode(staged), AT_FDCWD, os.fsencode(live), RENAME_EXCHANGE) != 0:
                code = ctypes.get_errno()
                raise OSError(code, os.strerror(code), live)
            how = "exchanged"
        else:
            os.rename(staged, live)
            how = "renamed"
        try:
            for directory in sorted({os.path.dirname(staged), os.path.dirname(live)}):
                fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        except OSError as error:
            raise NotDurable(error.errno, error.strerror, live) from error
        return how

    def copy_verified(self, source, copy):
        """`source` copied to `copy` (new, 0600, fsynced) while its SHA-256 is computed: the digest of the very bytes the
        copy holds, which is then what is restored, whatever happens to `source` afterwards."""
        h = hashlib.sha256()
        size = 0
        fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with open(source, "rb") as f, os.fdopen(fd, "wb", closefd=False) as out:
                for block in iter(lambda: f.read(1024 * 1024), b""):
                    size += len(block)
                    require(size <= MAX_SNAPSHOT_BYTES, "the snapshot is over %d bytes" % MAX_SNAPSHOT_BYTES)
                    h.update(block)
                    out.write(block)
                out.flush()
                os.fsync(fd)
        except BaseException:
            os.close(fd)
            os.unlink(copy)
            raise
        os.close(fd)
        return h.hexdigest()



def main(argv=None, host=None, now=None, signer=None):
    parser = argparse.ArgumentParser(prog="restore", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    go = sub.add_parser("run", help="(root, at the node's console) restore etcd from a snapshot and raise the state epoch")
    go.add_argument("--config", required=True, help="the node's configuration (node.json)")
    go.add_argument("--statement", required=True, help="the owner's signed restore statement (JSON)")
    go.add_argument("--snapshot", required=True, help="the etcd snapshot the statement names")
    sub.add_parser("mark-pending", help="(root, at the node's console) hold etcd and the daemon stopped at every boot until a "
                   "restore exchanges a store with a raised state epoch: a replacement disk, before its first reboot")
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
        if args.command == "mark-pending":
            mark_pending(host or Host(), "restore mark-pending, at the console", now if now is not None else int(time.time()))
            print("WRITTEN: %s; %s and %s stay stopped at every boot until `restore run` exchanges a restored store"
                  % (PENDING, UNIT, DAEMON))
            return 0
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
        def authenticated():
            seconds, ok = node.clock()()
            require(ok, "the time is not authenticated (authtime): a restore is dated by authenticated time only")
            return int(seconds)
        with exclusive(RESTORE_LOCK):
            run(host, signed, chain, node.node_id, args.snapshot, now if now is not None else authenticated(), signer,
                clock=None if now is not None else authenticated)
    except (Refused, OSError, ValueError, KeyError) as refused:
        say("REFUSED: %s" % refused)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
