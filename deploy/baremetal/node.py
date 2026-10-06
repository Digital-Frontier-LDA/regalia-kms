#!/usr/bin/env python3
"""A KMS node's running services, assembled from one configuration file (#80, step 3b).

    python3 -Es -m deploy.baremetal.node --config /etc/regalia/node.json authtime | wg-apply | boot-session | admission | sync
    python3 -Es -m deploy.baremetal.node --config /etc/regalia/node.json esp-advance [--esp /efi]

Six processes, each the smallest one that can do its part. Four are root (authtime, wg-apply, esp-advance,
boot-session), and none of them parses what a peer sends; `sync` and `admission` do, and hold no capability
and are not root:

    authtime   root, CAP_DAC_OVERRIDE   asks chrony whether time is authenticated; writes
                                        /run/regalia/authtime.json (authtime.py)
    wg-apply   root, CAP_NET_ADMIN      makes wg-svc and wg-unlock what the CURRENT manifest says, and
                                        reads the result back (wgsvc.py, bootnet.py); a oneshot, run at
                                        boot and again whenever the published chain changes
    esp-advance   root, no capability, the TPM through its group
                                        a oneshot, whenever the published chain changes: writes it to
                                        the ESP (EFI/regalia/membership.json, the chain the initrd
                                        renders the next boot from, #66 B3), THEN moves the TPM anchor
                                        to it (esp_advance)
    boot-session  root, no capability   a oneshot: on a boot where the unlock client presented no
                                        session (the disk opened with the recovery key), makes one and
                                        leaves the pair in /run/regalia, as the client would have
    admission  its own user (regalia-admission, #191), no capability, the TPM through its group
                                        holds this node's runtime lease, asking peers through the
                                        service tunnel; writes /run/regalia/admission/admission.json
                                        for the KMS daemon (admission.py)
    sync       its own user, no capability, the TPM through its group
                                        answers peers on wg-svc (sync.py) and booting nodes on
                                        wg-unlock (unlock.py), pulls manifests and heartbeats from the
                                        peers, keeps the membership store, and runs the heartbeat watch
                                        (heartbeat_watch.py); under a v4 manifest it also proposes and
                                        co-signs the heartbeats with the
                                        TPM signing key and its signing counter (beat.py, #199)

ONE WRITER OF THE MEMBERSHIP CHAIN. `sync` owns the store (membership.Store: its files are its own, 0600).
After every change it PUBLISHES the verified chain, 0644, beside it (publish()). The other services read
that copy and verify it themselves (published()): every signature and transition from the root key, and
the TPM anchor, which only goes up. A `sync` that is compromised can therefore withhold a newer chain or
publish an older one, and either way the other services see a chain below the anchor and refuse it: the
node stops serving, it does not go on under an old manifest.

`sync` NEVER MOVES THE ANCHOR (#66 B3: membership.Store(anchors=False)). The initrd refuses an ESP chain below
the anchor (ROLLBACK), so the ESP must hold epoch N before the anchor reaches N: `esp-advance`, root, writes
the published chain to the ESP, durably, and only then anchors it. A crash between the two leaves the ESP
ahead of the anchor, which the initrd accepts (up to the jump bound) and the next run completes. Until it
runs, the published chain is ahead of the anchor: the root services act on it (it is verified from the root
key, and is not below the anchor), and sync refuses to run further ahead than the jump bound.

THE BOOT SESSION. A runtime lease is asked for with a quote over this boot's session, and a peer allows
one session per boot of a node's TPM. If the unlock client presented one in the initrd it left
/run/regalia/boot-session (64 hex) and boot-session.pub (hex of the key's DER); `boot-session` is written
last and is the marker. boot_session() uses that pair. With no `boot-session` at all (the disk opened with
the recovery key before any peer was asked) the root oneshot `boot-session` makes a session and writes the
pair, the same way, before `admission` starts; `admission` only reads it, since it is not root and
/run/regalia is root's, and the KMS daemon accepts the session only from root (#191). A `boot-session`
without its key, or either malformed, is a refusal: the right session cannot be guessed, and a wrong one
would be refused by the peer that holds the right one.

THE TRAIL. Each service appends its audit events to its own file (one JSON object per line, fsynced) in
its own state directory. Shipping them off the host is the audit pipeline's job, not this module's.

NOT HERE: the systemd units, the AppArmor profiles and the probes (#80 step 3b, next); enrolment, which
writes the trust anchors this configuration points at (#190).
"""
import argparse
import binascii
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

from deploy.baremetal import (admission, anchorpolicy, trails, attest, authtime, beat, bootnet, convergence, enrolpeer, heartbeat, heartbeat_watch, lease,
                              measurements, membership, metrics, signkey, sitecfg, sync, unlock, wgsvc)

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.node/v1"
KEYS = ("schema", "node_id", "site", "root_key", "tcti", "nv_epoch", "nv_heartbeat", "nv_signing", "state_dir", "admission_dir", "run_dir",
        "wg_service_key", "measurements", "pcrs", "time_servers", "pull_interval", "beat_interval_s")
PUBLISHED = "chain.json"        # in the state directory: the verified chain, for the root services
MAX_BYTES = 64 * 1024


# ---- the configuration ----

def _absolute(value, label):
    require(isinstance(value, str) and value.startswith("/") and "\0" not in value and os.path.normpath(value) == value,
            "%s must be an absolute, normalised path" % label)
    return value


def _index(value, label):
    require(isinstance(value, str) and re.fullmatch(r"0x01[0-9a-f]{6}", value) is not None, "%s must be an NV index, 0x01xxxxxx" % label)
    return value


def validate(doc):
    """The node configuration, checked. Every field is required and nothing else is allowed."""
    membership.exact(doc, KEYS, "node configuration")
    require(doc["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    require(isinstance(doc["node_id"], str) and re.fullmatch(sitecfg.NODE_ID, doc["node_id"]) is not None, "node_id is not a node ID")
    membership.root_entries(doc["root_key"], "root_key")
    require(doc["tcti"] is None or (isinstance(doc["tcti"], str) and re.fullmatch(r"[a-z]+(:[A-Za-z0-9/_.,=-]{1,200})?", doc["tcti"]) is not None),
            "tcti must be null (the kernel's resource manager) or a TCTI string")
    # what each really occupies, from the classes that define them (the anchor: counter, base and two record
    # slots; the heartbeat counter and the signing counter (#199): counter and base each), never retyped here
    taken = {"nv_epoch": membership.HighWater(_index(doc["nv_epoch"], "nv_epoch")).indices(),
             "nv_heartbeat": heartbeat.Counter(_index(doc["nv_heartbeat"], "nv_heartbeat")).indices(),
             "nv_signing": heartbeat.Counter(_index(doc["nv_signing"], "nv_signing")).indices(),
             # #361 C1: the rotation counter, at a fixed index on every node (enrol init defines it before node.json exists)
             "the rotation counter": {int(anchorpolicy.ROTATION_INDEX, 16)}}
    names = list(taken)
    for i, one in enumerate(names):
        for other in names[i + 1:]:
            overlap = taken[one] & taken[other]
            require(not overlap, "%s and %s must not overlap (both take %s): %s takes %s, %s takes %s" % (
                one, other, ", ".join("0x%x" % i for i in sorted(overlap)), one, ", ".join("0x%x" % i for i in sorted(taken[one])),
                other, ", ".join("0x%x" % i for i in sorted(taken[other]))))
    for key in ("site", "state_dir", "admission_dir", "run_dir", "wg_service_key", "measurements"):
        _absolute(doc[key], key)
    # each directory has ONE writer: sync's, admission's (regalia-admission, #191), and the run directory (root)
    require(len({doc["state_dir"], doc["admission_dir"], doc["run_dir"]}) == 3, "state_dir, admission_dir and run_dir must be three directories")
    pcrs = doc["pcrs"]
    require(isinstance(pcrs, list) and pcrs and all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i <= 23 for i in pcrs)
            and pcrs == sorted(set(pcrs)), "pcrs must be an ascending list of PCR indices 0-23")
    authtime.servers(doc["time_servers"])
    interval = doc["pull_interval"]
    require(isinstance(interval, int) and not isinstance(interval, bool) and 10 <= interval <= 3600, "pull_interval must be 10 to 3600 seconds")
    # #199: how often the nodes sign a heartbeat (beat.Proposer); 900 in production (#69). Never below
    # heartbeat.MIN_INTERVAL_S: a node's jump allowance grows by one per MIN_INTERVAL_S of issue time, so beating faster
    # would leave a node that was off for about a day refusing every heartbeat as an anomaly (regalia-kms-1e's read)
    beat_every = doc["beat_interval_s"]
    require(isinstance(beat_every, int) and not isinstance(beat_every, bool) and heartbeat.MIN_INTERVAL_S <= beat_every <= 3600,
            "beat_interval_s must be %d to 3600 seconds" % heartbeat.MIN_INTERVAL_S)
    return doc


def load(path):
    with open(path, "rb") as f:
        return validate(membership.load(f.read(MAX_BYTES + 1), MAX_BYTES))


# ---- the published chain ----

def publish(store, path):
    """Write the store's verified chain where the root services read it: complete or not at all, 0644. A file
    that already holds exactly these bytes, 0644, is left as it is: the path units that watch it fire on a
    change of the chain, not on every publication."""
    envelopes = store.envelopes(0)
    encoded = membership.canonical(envelopes)
    with contextlib.suppress(OSError):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644 and info.st_size == len(encoded) \
                    and os.read(fd, len(encoded) + 1) == encoded:
                return envelopes[-1]["manifest"] if envelopes else None
        finally:
            os.close(fd)
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".chain-")
    try:
        os.fchmod(fd, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return envelopes[-1]["manifest"] if envelopes else None


def published(path, root_key, anchor):
    """The current manifest by the published chain, verified here: every envelope from the root key, and the
    chain the TPM anchors (`anchor`, a membership.HighWater): not below its epoch (ROLLBACK), and at that
    epoch the very manifest its record names, so a fork the TPM never recorded is refused (CONFLICT). The
    read takes no lock (these services cannot write regalia-sync's lock directory); a CONFLICT can be a
    commit racing the read, so it is read once more before it stands."""
    envelopes = read_published(path)
    manifest = membership.accept_chain(None, envelopes, root_key)
    manifests = [e["manifest"] for e in envelopes]                       # verified, epoch 1 first

    def digest_of(epoch):
        require(epoch <= len(manifests), "ROLLBACK: the published chain ends at epoch %d, below the TPM anchor %d" % (len(manifests), epoch))
        return membership.digest(manifests[epoch - 1]) if epoch else membership.HighWater.ZERO
    try:
        anchor.verify(digest_of, lock=False)
    except Refused as refused:
        if str(refused).startswith("ROLLBACK"):
            raise
        anchor.verify(digest_of, lock=False)        # a commit may have been racing the read: it stands only if it stays
    return manifest


def read_published(path):
    """The published chain's envelopes, as written (NOT verified: published() and esp_advance verify them)."""
    # The file is written by a process that parses what other machines send, and read here by root: no
    # symlink is followed, and nothing but a regular file is read (a FIFO would hang the reader).
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as failure:
        raise Refused("the published membership chain cannot be read (%s)" % type(failure).__name__) from None
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "the published membership chain is not a regular file")
        chunks, size = [], 0
        while size <= membership.MAX_CHAIN_BYTES:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    envelopes = membership.load(raw, membership.MAX_CHAIN_BYTES)        # refuses a deeply nested document itself
    require(isinstance(envelopes, list) and envelopes, "the published membership chain is empty")
    return envelopes


# ---- the ESP advance (#66 B3) ----

ESP_LOCK = "/run/regalia-esp-advance/highwater.lock"     # its RuntimeDirectory: the anchor's one run-time writer
# the render is tried as a check (what the initrd will render); the device is only what the rendered unlock
# configuration names, and nothing rendered is written
ESP_RENDER_DEVICE = "/dev/disk/by-partlabel/regalia-root"


def esp_advance(node, esp, lock_path=ESP_LOCK):
    """Bring the boot chain on the ESP (`esp`, its mount point) up to the published chain, THEN move the TPM anchor
    to it: the order that never leaves the initrd an ESP chain below its anchor (a ROLLBACK, refused at boot).

    The chain is read from the published file and verified here as the initrd verifies it (bootcreds.anchored:
    from the root key and against the anchor, a chain ahead of the anchor accepted up to the jump bound). ONLY the
    chain is written (bootcreds.CHAIN_ON_ESP): the measured site credential is the site's, not the manifest's, and
    is left as enrolment wrote it. The render the initrd will do is tried too, and a chain it would refuse (this
    node no longer in the manifest, or left with no peer) is STILL written and anchored, with a warning returned:
    the next boot then goes to the recovery prompt, which is what that manifest means for this node, whereas
    refusing here would freeze the anchor, and rollback protection with it, at the older epoch. The write is enrolment's own (enrol._replace_esp, a
    temporary file fsynced and renamed, the directory fsynced, under a trusted path), and is read back before the
    anchor moves. A crash after the write and before the anchor leaves the ESP ahead, which the initrd accepts and
    the next run completes. Returns (epoch, the chain's SHA-256, whether the ESP was rewritten, the render's
    refusal or None).

    `lock_path`: the anchor's lock. regalia-sync's (the state directory's, 0600) cannot be opened by a root without
    CAP_DAC_OVERRIDE; sync no longer writes the anchor, and systemd runs one start of this unit at a time."""
    from deploy.baremetal import bootcreds, enrol
    envelopes = read_published(node.path(PUBLISHED))
    # judged by the chain it anchors (#242 B3, regalia-kms-ed): under a v4 tip an owner-written anchor is Unusable, refused
    # before the ESP is written (the unit's ok=0); a re-anchor repairs it
    require(isinstance(envelopes, list) and envelopes, "the membership chain must be a non-empty list of envelopes")
    tip = membership.accept_chain(None, envelopes, node.cfg["root_key"])
    anchor = node.anchor(lock_path=lock_path, schema=tip["schema"], anchor_key=tip.get("anchor_policy_key"))
    anchor.judge_by_tip(tip)          # #361 C4: its write presents K_A's approval from THIS tip's document, not the held chain's
    manifest = bootcreds.anchored(envelopes, node.cfg["root_key"], anchor)
    chain = membership.canonical(envelopes)
    require(len(chain) <= membership.MAX_CHAIN_BYTES, "the membership chain is over %d bytes" % membership.MAX_CHAIN_BYTES)
    try:
        bootcreds.render(manifest, node.site, ESP_RENDER_DEVICE)
        unrenderable = None
    except Refused as refused:
        unrenderable = str(refused)
    relative = enrol._rendered_path(bootcreds.CHAIN_ON_ESP)
    directory, filename = os.path.join(esp, os.path.dirname(relative)), os.path.basename(relative)
    target = os.path.join(directory, filename)
    try:
        enrol._ensure_trusted_dir(directory)
    except enrol.Refused as refused:
        raise Refused(str(refused)) from None
    rewritten = _read_regular(target, len(chain) + 1) != chain
    if rewritten:
        enrol._replace_esp(directory, filename, chain)
        require(_read_regular(target, len(chain) + 1) == chain, "the chain read back from %s is not the one written" % target)
    manifests = [e["manifest"] for e in envelopes]               # verified by bootcreds.anchored
    epoch = manifests[-1]["epoch"]
    anchor.anchor(epoch, membership.Store._digests(manifests))
    anchor.check(epoch)
    return epoch, hashlib.sha256(chain).hexdigest(), rewritten, unrenderable


ESP_SETTLE_RUNS = 5          # runs of esp_advance at most, while the published chain keeps changing under it


def esp_advance_settled(node, esp, lock_path=ESP_LOCK, advance=None):
    """esp_advance, run again while the published chain changed DURING the run, at most ESP_SETTLE_RUNS times.

    regalia-esp-advance.path's PathChanged= is edge-triggered: a publication that lands while a run is already active
    is folded into that run by systemd and starts nothing afterwards. If that run had read the chain before it changed,
    the ESP and the anchor would stay one epoch behind until the NEXT publication (regalia-kms-24 and 3e on main's
    three-node-recovery; on a host, the unit's boot run beside sync's first publication). So the published file is read
    before and after each run; a run that saw what is published now is the last one. Still changing after the bound (a
    sync publishing faster than a run, not something sync does), it is refused, and the unit's Restart= tries again.
    That cannot strand a node (24): every run that completes has written the ESP and moved the anchor to the chain it
    read, so each run makes progress and the anchor is never more than one publication behind; and the refusal is
    what guarantees ANOTHER run (Restart=on-failure, 15 s later, re-reading the newest), where a success after the
    bound could leave a lost trigger behind it."""
    advance = advance or esp_advance
    path = node.path(PUBLISHED)
    # the RUN holds `lock_path` (node.ESP_LOCK): the same file reanchor holds for its whole re-anchor (#391), so the unit,
    # a hand-run esp-advance and a re-anchor all serialize on one lock (regalia-kms-24). The anchor's own HighWater lock
    # inside each run is another file beside it: HighWater flocks its lock_path itself, and a second open of the held
    # file in this process would block on itself (regalia-kms-95)
    with _one_run(lock_path):
        for _ in range(ESP_SETTLE_RUNS):
            before = _read_regular(path, membership.MAX_CHAIN_BYTES + 1)
            result = advance(node, esp, lock_path=lock_path + ".anchor")
            if _read_regular(path, membership.MAX_CHAIN_BYTES + 1) == before:
                return result
    raise Refused("the published membership chain changed during each of %d runs: not settled; the unit tries again"
                  % ESP_SETTLE_RUNS)


@contextlib.contextmanager
def _one_run(path):
    """One ESP advance at a time, across the WHOLE run (every rerun: the ESP's write and the anchor's move), on
    node.ESP_LOCK, which reanchor also holds for its whole re-anchor (#391). Without it a hand-run `esp-advance` beside the
    unit could write an OLDER chain to the ESP after the other run anchored a newer one: an ESP below its anchor, a
    ROLLBACK at the next boot (regalia-kms-95 on #471). Its directory is the unit's RuntimeDirectory; a hand-run while the
    unit is stopped makes it (root's, 0700) rather than run unlocked. Opened as reanchor opens it: never through a link, a
    regular file with one name. Held by another run or a re-anchor, it is a refusal, not a wait: the unit's Restart=
    tries again, and an operator is told."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError as failure:
        if failure.errno == errno.ELOOP:
            raise Refused("the ESP advance's lock %s is a symbolic link: it is not taken through one" % path) from None
        raise
    try:
        held = os.fstat(fd)
        require(stat.S_ISREG(held.st_mode) and held.st_nlink == 1, "the ESP advance's lock %s is not a regular file with one name" % path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused("another regalia-esp-advance run, or a re-anchor, holds %s: one at a time (try again when it has "
                          "finished)" % path) from None
        yield
    finally:
        os.close(fd)


def esp_metrics(node, ok, renderable=None, publish=None):
    """regalia-esp-advance's own metrics (#66 B3), written at every run, success or not, by root: the anchor as IT reads
    it, so a sync that lies in membership.prom does not silence the alerts on these (regalia-kms-48), and whether the
    next boot can render. Never raises: a metric does not change the run's outcome."""
    publish = publish or (lambda samples: metrics.publish("esp-advance", samples))
    samples = [("regalia_esp_advance_ok", {}, 1 if ok else 0), ("regalia_esp_advance_run_timestamp_seconds", {}, int(time.time()))]
    if renderable is not None:
        samples.append(("regalia_esp_boot_renderable", {}, 1 if renderable else 0))
    try:
        samples.append(("regalia_esp_anchor_epoch", {}, node.anchor().value()))
    except Exception:                                   # noqa: BLE001 - a TPM that cannot be read: said by ok=0 already
        pass
    try:
        publish(samples)
    except Exception:                                   # noqa: BLE001 - see above
        pass


def _read_regular(path, limit):
    """The bytes of the regular file `path` (up to `limit`), never through a link; None if it is not there."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:                        # ELOOP: a link
        raise Refused("%s cannot be read as a regular file (%s): it is not followed" % (path, error.strerror)) from None
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "%s is not a regular file" % path)
        chunks, size = [], 0
        while size < limit:
            chunk = os.read(fd, min(1 << 20, limit - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


# ---- the boot session ----

def boot_session(run_dir, rand=os.urandom, make=False):
    """(session ID, the key's DER) of this boot: the unlock client's, or, with `make` (the root oneshot
    only), one made now. Without `make`, no session is a refusal. See the module."""
    marker, key = os.path.join(run_dir, "boot-session"), os.path.join(run_dir, "boot-session.pub")

    def read(path, label, pattern):
        with open(path, "rb") as f:
            text = f.read(2048).decode("ascii", "replace")
        require(re.fullmatch(pattern, text) is not None, "%s is malformed" % label)
        return text.strip()
    if os.path.exists(marker):
        session = read(marker, "boot-session", r"[0-9a-f]{64}\n")
        require(os.path.exists(key), "boot-session names a session whose key is missing: it cannot be presented again")
        public = bytes.fromhex(read(key, "boot-session.pub", r"([0-9a-f]{2}){1,512}\n"))
        return session, public
    require(make, "this boot has no session in %s: regalia-boot-session.service makes one before the lease service starts" % run_dir)
    session, public = rand(32).hex(), b"regalia-kms runtime session " + rand(32)
    for path, text in ((key, public.hex()), (marker, session)):      # the key first: the marker says both are there
        fd, tmp = tempfile.mkstemp(dir=run_dir, prefix=".boot-session-")
        try:
            os.fchmod(fd, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(text + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise
    return session, public


# ---- the trail ----

class Trail:
    """Audit events, one JSON object a line, hash-chained, appended and fsynced (trails.append, #278).
    Raises if it cannot write: callers that must not act unrecorded (sync.Server) refuse to answer then."""

    def __init__(self, path, trail=None):
        """`trail` names it in trails.TRAILS, so the file takes that trail's reader group (#286)."""
        self.path, self.lock = path, threading.Lock()
        self.group = trails.TRAILS[trail][3] if trail else None

    def __call__(self, event):
        with self.lock:
            trails.append(self.path, dict(event, at=int(time.time())), group=self.group)


def signing_counter(cfg, run=subprocess.run):
    """This node's signing counter (#199): the highest heartbeat sequence it has signed, as proposer or co-signer
    (beat.Signer). Its own index, never the heartbeat counter's: a node's co-signature must not make the heartbeat a
    replay to itself. Written by policy like the heartbeat counter (#242): the service advances it with no owner
    authorization; enrolment defines it."""
    return heartbeat.Counter(cfg["nv_signing"], cfg["tcti"], run, lock_path=os.path.join(cfg["state_dir"], "signing-counter.lock"),
                             policy=lambda: image_policy(cfg), image_key=lambda: image_key(cfg),
                             # #361 C3: under a v4 tip, the "signing-counter" class under K_A
                             schema=lambda: _tip_schema(cfg), anchor_key=lambda: _tip_anchor_key(cfg),
                             classes={"counter": "signing-counter"}, approvals=lambda cls, manifest=None: anchor_approval(cfg, cls, manifest=manifest))


def node_beat_signer(node, pem_path=None):
    """`node`'s beat.Signer (#199): its signing counter, and its TPM signing key under the running image's system-phase
    PCR key (systemd-stub's copy of the image's .pcrpkey, signkey.PCR_PUBLIC_KEY_PATH: a key the signing key's policy
    does not name signs nothing, and identity() says so before any number is reserved)."""
    path = pem_path or signkey.PCR_PUBLIC_KEY_PATH
    try:
        with open(path, "rb") as f:
            pem = f.read(65536)
    except FileNotFoundError:
        raise Refused("no system-phase PCR public key at %s: this boot is not a UKI with a signed PCR policy" % path) from None
    tcti, run = node.tcti, node.run
    k_a = _tip_anchor_key(node.cfg)                       # under a v4 tip the key was made under K_A's "signing" class (#361)
    point = signkey.identity(signkey.public(tcti, run), pem, k_a["key"] if k_a else None)[1]
    # #361 C3: under a v4 tip the signing key is used under K_A's approval of the "signing" class for this node
    approval = (lambda: anchor_approval(node.cfg, "signing", pem_path)) if _tip_schema(node.cfg) == membership.SCHEMA_V4 else (lambda: None)
    return beat.Signer(node.node_id, signing_counter(node.cfg, run), lambda message: signkey.sign(message, pem, tcti, run, anchor=approval()), point)


def image_policy(cfg, pem_path=None, manifest=None):
    """This node's approved-image write policy (#242), from root-signed sources only: the chain in the state
    directory (sync's store, else the chain it publishes for the other services), verified under the pinned
    root; the measurements document its newest manifest commits to, from the node's store by digest
    (measurements.held, #332: never the retired cfg["measurements"] file); and the running image's system-phase
    PCR key (signkey.PCR_PUBLIC_KEY_PATH), which that document must approve for this node
    (measurements.approved_image_policy). HighWater calls it only when it meets an index written by policy.
    Anything missing is a refusal, never a fallback to an unsigned value.
    The chain is NOT checked against the TPM here, and need not be: a restored older chain yields at most a key
    the root once approved for this node, and the anchor's own verify refuses the rollback itself. This names
    only the key the anchor's indices must have been defined under.
    `manifest`: an already verified manifest to judge by instead of the state directory's chain (enrolment, which
    defines the anchor before its first commit)."""
    return _image(cfg, pem_path, manifest)[0]


def define_policy(cfg, manifest=None, pem_path=None):
    """The policy a DEFINER (enrolment, a re-anchor, a recount) lays this node's anchor and heartbeat counter indices
    down under (#242): the node's approved-image write policy when the signed measurements its manifest commits to name
    a system-phase PCR key for it (its images are signed UKIs), and then the running image's key must be one of them
    (image_policy refuses otherwise); None when they name none: a node whose approved images are not signed has no
    policy to write by, and its indices are owner-written. The signed document decides, never a missing file."""
    if manifest is None:
        manifest = _chain_tip(cfg)
    document = measurements.held(os.path.join(cfg["state_dir"], measurements.STORE_DIR), manifest)
    if not measurements.system_keys(manifest, document, cfg["node_id"]):
        # Owner-written is for unsigned LAB images only. Production is a v4 manifest (#199): there a definer never lays
        # down the weaker layout; measurements that name no system key for the node fail loudly here (24, #242)
        require(manifest["schema"] != membership.SCHEMA_V4, "the measurements epoch %d commits to name no system-phase PCR key "
                "for %s: under %s the anchor is defined only in the policy-written layout, and the owner-written one is "
                "refused (a lab image under v1-v3 may have it)" % (manifest["epoch"], cfg["node_id"], membership.SCHEMA_V4))
        return None
    return image_policy(cfg, pem_path, manifest)


def image_key(cfg, pem_path=None, manifest=None):
    """The running image's system-phase PCR public key (PEM), once the same check as image_policy has approved it:
    the key the anchor's and the heartbeat counter's run-time writes open their policy sessions with (#242)."""
    return _image(cfg, pem_path, manifest)[1]


def _image(cfg, pem_path=None, manifest=None):
    """(policy hex, PEM): image_policy and image_key."""
    try:
        with open(pem_path or signkey.PCR_PUBLIC_KEY_PATH, "rb") as f:
            pem = f.read(65536)
    except OSError as error:
        raise Refused("this node's approved-image write policy cannot be established: %s" % error) from None
    if manifest is None:
        manifest = _chain_tip(cfg)
    document = measurements.held(os.path.join(cfg["state_dir"], measurements.STORE_DIR), manifest)
    switched = _switched(cfg, manifest, document, pem)
    if switched is not None:
        pem = switched["pem"]
    return measurements.approved_image_policy(manifest, document, cfg["node_id"], pem), pem


def _booted_set(document, node_id, pem):
    fingerprint = signkey.pcr_key_fingerprint(pem)
    sets = [e for e in document["nodes"].get(node_id, {}).get("accepted", []) if e.get("signing", {}).get("system") == fingerprint]
    require(sets, "no accepted set of %s is signed by the running image's key (%s...)" % (node_id, fingerprint[:16]))
    return sets[0]


def _resigned(cfg, document, pem, k_a, pcr11=None):
    """#361 C4b (regalia-kms-05's conditions on #361): the new system-phase key's re-sign of the image this node is booted
    on (its set's signing.resigned), checked here before it is used: refused by name unless
      * the entry names the key of one of this node's accepted sets (05's addition), and its PEM is that key;
      * its signature verifies under that key over its policy digest;
      * the digest is PolicyPCR(11 = the booted set's system-phase value), and THIS TPM's PCR 11, read now, is that value;
      * the new key's set carries K_A's approvals of the new key for THIS node, under the manifest's K_A (`k_a`), checked
        (anchorpolicy.check_approvals, regalia-kms-05 on #517): their generation is returned, and the catch-up requires it
        to be the published one, or R would move onto approvals the TPM refuses.
    None when the booted set carries no re-sign. Returns {"pem", "entry", "generation"}."""
    import base64
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from deploy.baremetal import uki
    node_id = cfg["node_id"]
    booted = _booted_set(document, node_id, pem)
    resigned = booted["signing"].get("resigned")
    if resigned is None:
        return None
    new = [e for e in document["nodes"][node_id]["accepted"] if e.get("signing", {}).get("system") == resigned["system"]]
    require(new, "the re-sign of %s's booted image names a key (%s...) no accepted set of %s is signed by" % (node_id, resigned["system"][:16], node_id))
    new_pem = resigned["pem"].encode()
    require(signkey.pcr_key_fingerprint(new_pem) == resigned["system"], "the re-sign's public key is not the key it names (%s...)"
            % resigned["system"][:16])
    try:
        serialization.load_pem_public_key(new_pem).verify(base64.b64decode(resigned["sig"]), bytes.fromhex(resigned["pol"]),
                                                          padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError):
        raise Refused("the re-sign of %s's booted image does not verify under the key it names" % node_id) from None
    want = booted["phases"]["system"]["11"]
    require(resigned["pol"] == uki.policy_digest(want), "the re-sign of %s's booted image is over another policy than PolicyPCR(11 = %s...)"
            % (node_id, want[:16]))
    measured = pcr11 if pcr11 is not None else _pcr11(cfg)
    require(measured == want, "this TPM's PCR 11 is %s..., not the %s... the re-sign is for: this boot is not that image's"
            % (measured[:16], want[:16]))
    require("anchor_approvals" in new[0]["signing"], "the new key's set for %s carries no K_A approvals" % node_id)
    generation = anchorpolicy.check_approvals(new[0]["signing"]["anchor_approvals"], new_pem, k_a, node_id)
    return {"pem": new_pem, "generation": generation,
            "entry": {"pcrs": [11], "pkfp": resigned["system"], "pol": resigned["pol"], "sig": resigned["sig"]}}


def _pcr11(cfg):
    """PCR 11 (SHA-256 bank) as THIS node's TPM reads it now, 64 hex."""
    with tempfile.TemporaryDirectory(prefix="regalia-pcr11-") as d:
        done = _tpm_run(cfg)(["tpm2_pcrread", "sha256:11", "-o", os.path.join(d, "pcr11")], capture_output=True)
        require(done.returncode == 0, "cannot read PCR 11: %s" % (done.stderr or b"").decode("utf-8", "replace").strip()[-200:])
        with open(os.path.join(d, "pcr11"), "rb") as f:
            return f.read(64).hex()


def _switched(cfg, manifest, document, pem):
    """After its bump (R above the booted set's own generation), a node booted on a re-signed image writes under the new
    key: its PEM, and the re-signed entry beside the boot's PCR signatures (signkey.RESIGNED_PATH). None otherwise."""
    if manifest.get("schema") != membership.SCHEMA_V4 or "anchor_policy_key" not in manifest:
        return None
    fingerprint = signkey.pcr_key_fingerprint(pem)
    booted = [e for e in document["nodes"].get(cfg["node_id"], {}).get("accepted", []) if e.get("signing", {}).get("system") == fingerprint]
    if not booted or "resigned" not in booted[0]["signing"] or "anchor_approvals" not in booted[0]["signing"]:
        return None                                  # nothing re-signed (approved_image_policy judges the key itself)
    booted = booted[0]
    if anchorpolicy.read_rotation(anchorpolicy.ROTATION_INDEX, _tpm_run(cfg)) <= booted["signing"]["anchor_approvals"]["generation"]:
        return None
    resigned = _resigned(cfg, document, pem, manifest["anchor_policy_key"]["key"])
    _keep_resigned(resigned["entry"])
    return resigned


def _keep_resigned(entry):
    """The re-signed entry where signkey.boot_signatures merges it (tmpfs, this boot only)."""
    os.makedirs(os.path.dirname(signkey.RESIGNED_PATH), mode=0o755, exist_ok=True)
    data = json.dumps({"sha256": [entry]}, sort_keys=True).encode()
    tmp = signkey.RESIGNED_PATH + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, signkey.RESIGNED_PATH)


def anchor_approval(cfg, cls, pem_path=None, manifest=None):
    """#361 C3: K_A's approval of class `cls` for this node, as signkey.policy_session's `anchor`, from root-signed
    sources only, as image_policy: the chain's tip (its K_A), the measurements document it commits to (the node's set
    for the running image's key, and that set's anchor_approvals), and the running image's key."""
    _, pem = _image(cfg, pem_path, manifest)
    if manifest is None:
        manifest = _chain_tip(cfg)
    document = measurements.held(os.path.join(cfg["state_dir"], measurements.STORE_DIR), manifest)
    approval = measurements.anchor_approval(manifest, document, cfg["node_id"], pem, cls)
    # #361 C4: every write and signature under K_A takes its approval here, so here a node behind on its rotation
    # counter writes and signs nothing until it has caught up (an approval the retire revoked may still open its objects)
    anchorpolicy.require_current(anchorpolicy.ROTATION_INDEX, cfg["node_id"], measurements.rotations(document, cfg["node_id"]), _tpm_run(cfg))
    return approval


def _tpm_run(cfg):
    """subprocess.run for tpm2-tools against this node's TPM (its node.json tcti, else the default)."""
    env = dict(os.environ, TPM2TOOLS_TCTI=cfg["tcti"]) if cfg.get("tcti") else None
    return lambda argv, **kw: subprocess.run(argv, env=env, **kw)


def catch_up_rotation(cfg, manifest=None, pem_path=None):
    """#361 C4: this node's rotation counter brought up to the generation the root published for it (the measurements
    document the tip commits to: its nodes.<id>.rotations), by K_A's single-use increments, in order. Refused, with R
    as it was, when an entry is missing or when the image this node is booted on carries approvals below the published
    generation and no checked re-sign (C4b): nothing is bumped, and the node is write-frozen under K_A until it boots an
    image approved at the published generation (`update apply` onto it; regalia-kms-62 on #517). Returns R."""
    _, pem = _image(cfg, pem_path, manifest)
    if manifest is None:
        manifest = _chain_tip(cfg)
    document = measurements.held(os.path.join(cfg["state_dir"], measurements.STORE_DIR), manifest)
    rotations = measurements.rotations(document, cfg["node_id"])
    booted = measurements.anchor_approval(manifest, document, cfg["node_id"], pem, "anchor")["generation"]
    target = anchorpolicy.published(rotations)
    if target is not None and booted < target:
        # #361 C4b: the booted image re-signed by the new key, its checks passed, moves this node to the new key's
        # approvals on the boot it is in (written where the writes find it BEFORE the bump, so none is stranded)
        resigned = _resigned(cfg, document, pem, manifest["anchor_policy_key"]["key"])
        if resigned is not None:
            require(resigned["generation"] == target, "the re-sign moves %s to approvals at generation %d, not the published %d: "
                    "nothing is bumped" % (cfg["node_id"], resigned["generation"], target))
            _keep_resigned(resigned["entry"])
            booted = resigned["generation"]
    return anchorpolicy.catch_up(anchorpolicy.ROTATION_INDEX, manifest["anchor_policy_key"]["key"], cfg["node_id"], rotations,
                                 booted, _tpm_run(cfg))


def _chain_tip(cfg):
    """The newest manifest of the chain in the state directory (sync's store, else the published chain), verified
    under the pinned root."""
    envelopes = None
    for name in ("membership.json", PUBLISHED):
        try:
            with open(os.path.join(cfg["state_dir"], name), "rb") as f:
                envelopes = membership.load(f.read(membership.MAX_CHAIN_BYTES + 1), limit=membership.MAX_CHAIN_BYTES)
            break
        except (FileNotFoundError, PermissionError):
            continue
    require(isinstance(envelopes, list) and envelopes, "this node's approved-image write policy cannot be established: no verified "
            "chain in %s" % cfg["state_dir"])
    return membership.accept_chain(None, envelopes, cfg["root_key"])


def _tip_schema(cfg):
    """The schema of the verified chain tip this node holds (_chain_tip), which its anchor and heartbeat counter are judged
    by (#242 B3); None before it holds any chain (an anchor defined at enrolment, before its first commit: the Store then
    judges by the chain it commits). A chain that is held but does not verify is refused, never None."""
    if not any(os.path.lexists(os.path.join(cfg["state_dir"], name)) for name in ("membership.json", PUBLISHED)):
        return None
    return _chain_tip(cfg)["schema"]


def _tip_anchor_key(cfg):
    """K_A, the anchor_policy_key of the verified chain tip this node holds (#361), which its anchor is judged and defined
    under under v4; None before it holds any chain, or under v1-v3 (no such field)."""
    if not any(os.path.lexists(os.path.join(cfg["state_dir"], name)) for name in ("membership.json", PUBLISHED)):
        return None
    return _chain_tip(cfg).get("anchor_policy_key")


def heartbeat_counter(cfg, run=subprocess.run, owner_auth=None):
    """This node's heartbeat sequence counter, with the lock its users take: the one construction the
    services and the recovery command (recount.py) share. Written by policy like the anchor (#242)."""
    return heartbeat.Counter(cfg["nv_heartbeat"], cfg["tcti"], run, lock_path=os.path.join(cfg["state_dir"], "heartbeat-counter.lock"),
                             policy=lambda: image_policy(cfg), image_key=lambda: image_key(cfg),
                             # its one definition, define_at (a first heartbeat, a replacement's, recount's floor), is
                             # laid down under the node's policy when its signed images name one (define_policy)
                             define_policy=lambda: define_policy(cfg), owner_auth=owner_auth,
                             schema=lambda: _tip_schema(cfg), anchor_key=lambda: _tip_anchor_key(cfg),
                             classes={"counter": "heartbeat"}, approvals=lambda cls, manifest=None: anchor_approval(cfg, cls, manifest=manifest))


# ---- the node ----

class Node:
    """The configured node's parts. `run` is subprocess.run (or a fake): every TPM, chrony, wg and ip call
    goes through it."""

    def __init__(self, cfg, run=subprocess.run):
        self.cfg, self.run, self.node_id = validate(cfg), run, cfg["node_id"]
        self.site = sitecfg.load(cfg["site"])
        require(self.site["boot_mesh"] is not None and self.site["service_mesh"] is not None,
                "the site configuration has no boot_mesh or no service_mesh: this is not a node of a three-site cluster")
        require(self.site["boot_mesh"]["node_id"] == self.node_id, "the site configuration is %s's, not %s's" % (self.site["boot_mesh"]["node_id"], self.node_id))
        self.state, self.runtime, self.tcti = cfg["state_dir"], cfg["run_dir"], cfg["tcti"]

    def path(self, name):
        """A file of `sync`'s state directory (the membership store, the published chain, freshness...)."""
        return os.path.join(self.state, name)

    def held(self, name):
        """A file of the admission service's own directory (its lease and its trail)."""
        return os.path.join(self.cfg["admission_dir"], name)

    # the shared view of time
    def clock(self):
        return authtime.clock(os.path.join(self.runtime, "authtime.json"))

    def tpm_clock(self):
        return heartbeat.TpmClock(self.tcti, self.run)

    def anchor(self, lock_path=None, schema=None, anchor_key=None):
        """The membership epoch anchor: membership.HighWater on its own index (and the pair and slots after it),
        with this node's approved-image write policy (image_policy) for an index written by policy (#242), judged by the
        schema of the chain tip this node holds (_tip_schema, #242 B3).
        `lock_path`: the writer's lock. The run-time writer is esp_advance: its run holds ESP_LOCK, and this lock is ESP_LOCK + ".anchor"; the default, in
        the state directory, is for the hand tools that build an anchoring store (enrolment). sync only reads.
        `schema`: the schema of the chain this anchor is judged by, for a caller holding another chain than the node's
        (esp_advance: the published one it anchors); default, the chain tip this node holds."""
        return membership.HighWater(self.cfg["nv_epoch"], self.tcti, self.run, lock_path=lock_path or self.path("highwater.lock"),
                                    policy=lambda: image_policy(self.cfg), image_key=lambda: image_key(self.cfg),
                                    schema=schema or (lambda: _tip_schema(self.cfg)),
                                    anchor_key=anchor_key or (lambda: _tip_anchor_key(self.cfg)),
                                    approvals=lambda cls, manifest=None: anchor_approval(self.cfg, cls, manifest=manifest))

    def manifest(self, patience=2.0, step=0.25):
        """The current manifest, by the published chain, verified (the root services' view).

        `sync` commits a manifest (the TPM anchor moves) and publishes it a moment later. A reader in
        between sees a chain below the anchor. It waits up to `patience` seconds for the publication
        before it refuses: long enough for an honest `sync`, far too short to matter if `sync` withholds."""
        anchor, deadline = self.anchor(), time.monotonic() + patience
        while True:
            try:
                return published(self.path(PUBLISHED), self.cfg["root_key"], anchor)
            except Refused as refused:
                if not str(refused).startswith("ROLLBACK") or time.monotonic() >= deadline:
                    raise
            time.sleep(step)

    # sync's parts
    def documents(self):
        """The measurement documents this node holds, by digest (#332), in its state directory."""
        return measurements.Documents(self.path(measurements.STORE_DIR))

    def store(self):
        # an epoch is committed only with the measurements it commits to held (#332). Sync never moves the TPM anchor
        # (#66 B3): the root ESP advance writes the boot chain to the ESP first, then anchors (esp_advance)
        return membership.Store(self.path("membership.json"), self.cfg["root_key"], self.anchor(), documents=self.documents().require_for,
                                anchors=False)

    def freshness(self, owner_auth=None):
        """`owner_auth`: for a definition of the counter (enrolment's first heartbeat); the services give none."""
        counter = heartbeat_counter(self.cfg, self.run, owner_auth)
        return heartbeat.Freshness(counter, self.clock(), self.tpm_clock(), self.path("freshness.json"))

    def attester_for(self, manifest):
        # the document THIS manifest commits to, by digest, and no other (#332): refused when it is not held
        document = measurements.held(self.documents(), manifest)
        policy = measurements.attest_policy(manifest, document, self.node_id)
        return attest.Verifier(policy, self.path("attest.json"), run=self.run)

    def peers(self, manifest):
        """{node ID: its service-tunnel address} for every other node this one may talk to."""
        return {n["node_id"]: wgsvc.address(n["wg_service_pub"]) for n in manifest["nodes"]
                if n["node_id"] != self.node_id and n["state"] not in membership.TERMINAL}

    def sources(self, manifest, timeout=sync.DEADLINE):
        """sync.Client transports: the peers (the nodes of the manifest; #199 retired the revocation authority)."""
        mine, port = self.own_address(manifest), self.site["service_mesh"]["sync_port"]
        return {node: sync.tcp_transport(where, port, mine, timeout) for node, where in self.peers(manifest).items()}

    def own_address(self, manifest):
        entries = {n["node_id"]: n for n in manifest["nodes"]}
        require(self.node_id in entries, "%s is not in the manifest" % self.node_id)
        return wgsvc.address(entries[self.node_id]["wg_service_pub"])

    def private_key(self):
        with open(self.cfg["wg_service_key"]) as f:
            return f.read(200).strip()

    def quote(self, session_id, ephemeral_public):
        """A `quote(nonce hex, manifest)` for sync.Client.renewer: this node's TPM quote over its boot
        session, the manifest's epoch and the peer's nonce."""
        def evidence(nonce, manifest):
            with tempfile.TemporaryDirectory(prefix="regalia-quote-") as d:
                paths = (os.path.join(d, "quote"), os.path.join(d, "signature"))
                old = os.environ.get("TPM2TOOLS_TCTI")
                if self.tcti:
                    os.environ["TPM2TOOLS_TCTI"] = self.tcti
                try:
                    attest.node_quote(self.node_id, manifest["epoch"], bytes.fromhex(session_id), ephemeral_public, bytes.fromhex(nonce),
                                      self.cfg["pcrs"], *paths, run=self.run)
                finally:
                    if self.tcti:
                        os.environ.pop("TPM2TOOLS_TCTI") if old is None else os.environ.__setitem__("TPM2TOOLS_TCTI", old)
                quote, signature = (open(p, "rb").read().hex() for p in paths)
            return {"ephemeral_public": ephemeral_public.hex(), "nonce": nonce, "quote": quote, "signature": signature}
        return evidence


# ---- the four services ----

def wg_apply(node):
    """Make wg-svc and wg-unlock what the current manifest says, and read both back. ANY refusal, the
    manifest's own included (a chain that does not verify, or is below the TPM anchor), leaves BOTH
    interfaces down: a peer list that is not the current manifest's is not one to answer on. An interrupt
    stays an interrupt, with an interface that could not be taken down noted on it."""
    mesh, svc = node.site["boot_mesh"], node.site["service_mesh"]
    names = (svc["interface"], mesh["interface"])
    try:
        manifest = node.manifest()
        underlays = {p["node_id"]: p["underlay"] for p in mesh["peers"]}
        key = node.private_key()
        wgsvc.reconcile(manifest, node.node_id, underlays, key, svc["listen_port"], svc["interface"], node.run)
        name, text = mesh["interface"], bootnet.peer_wg_conf(node.site, manifest)
        # as wgsvc.reconcile: nothing is carried until the peers are applied and read back
        present = node.run(["ip", "link", "show", "dev", name], capture_output=True, timeout=10).returncode == 0
        steps = ([] if present else [["ip", "link", "add", "dev", name, "type", "wireguard"]]) + [
            ["ip", "address", "replace", mesh["address"] + "/32", "dev", name]]
        for argv in steps:
            require(node.run(argv, capture_output=True, timeout=10).returncode == 0, "%s failed" % " ".join(argv[:4]))
        done = node.run(["wg", "syncconf", name, "/dev/stdin"], capture_output=True, timeout=10, input=bootnet.with_key(text, key).encode())
        require(done.returncode == 0, "the unlock tunnel's configuration could not be applied")
        wgsvc.verify(text, name, node.run)
        for argv in [["ip", "link", "set", "dev", name, "up"]] + [["ip", "route", "replace", p["address"] + "/32", "dev", name] for p in mesh["peers"]]:
            require(node.run(argv, capture_output=True, timeout=10).returncode == 0, "%s failed" % " ".join(argv[:4]))
    except BaseException as failure:
        stuck = []
        for name in names:
            try:
                wgsvc.down(name, node.run)
            except Refused as refused:
                stuck.append(str(refused))
        if stuck and not isinstance(failure, Exception):
            for note in stuck:
                failure.add_note(note)
            raise failure from None
        if stuck:
            raise Refused("%s; and %s" % (failure, "; ".join(stuck))) from None
        raise
    return manifest["epoch"]


def admission_file(run_dir):
    """Where the lease service writes and the daemon reads: a directory of the lease service's own user
    inside root's run directory (regalia.tmpfiles.conf), so it can replace the file and nothing else there."""
    return os.path.join(run_dir, "admission", "admission.json")


class QuietRefusals:
    """The admission trail's renewal refusals, bounded (48 on #347): the FIRST refusal of each kind (a peer, and its
    reason with the numbers and long hex taken out) is recorded whole; later ones of a kind already recorded are
    counted, and the counts written as one line at most once a PERIOD; a success first writes what is still counted,
    then itself, and makes the next failure news again. A node cut off from its peers then writes tens of lines a
    day, not thousands, and the trail still says what happened and how often. `trail(event)` raises if it cannot
    write: a refusal the trail did not take is the caller's to count again; a success it did not take is not used."""
    PERIOD = 60

    def __init__(self, trail, clock=time.monotonic):
        self.trail, self.clock, self.seen, self.pending, self.since = trail, clock, set(), {}, None

    @staticmethod
    def kind(reason):
        return re.sub(r"[0-9]+", "N", re.sub(r"[0-9a-fA-F]{8,}", "H", reason))[:160]

    def deny(self, event):
        key = (event["peer"], self.kind(event["reason"]))
        if key not in self.seen:
            self.trail(event)
            self.seen.add(key)
            return
        self.pending[key] = self.pending.get(key, 0) + 1
        self.since = self.clock() if self.since is None else self.since
        self.flush(event)

    def flush(self, template, now=False):
        if not self.pending or (not now and self.clock() - self.since < self.PERIOD):
            return
        total = sum(self.pending.values())
        parts = "; ".join("%s x%d: %s" % (peer or "no peer gave a lease", n, kind) for (peer, kind), n in sorted(self.pending.items()))
        self.trail(dict(template, peer="", outcome="DENY", repeated=total,
                        reason=convergence._printable("%d more refused renewal attempts, each of a kind already recorded: %s" % (total, parts),
                                                      membership.REASON_LIMIT)))
        self.pending, self.since = {}, None

    def allow(self, event):
        self.flush(event, now=True)
        self.trail(event)
        self.seen.clear()


def admission_service(node, daemon_started=None, rand=os.urandom):
    """The lease holder and the admission file, asking peers in turn for a lease over the service tunnel."""
    session, public = boot_session(node.runtime, rand)
    holder = lease.Holder(node.node_id, session, node.clock(), node.tpm_clock(), node.held("lease.json"), run=node.run)
    trail = Trail(node.held("audit.jsonl"), "admission")
    quiet = QuietRefusals(trail)

    class Manifest:
        load = staticmethod(node.manifest)
    order = []

    def renew(request):
        manifest = node.manifest()
        sources = node.sources(manifest, timeout=admission.RENEW_TIMEOUT)    # a silent peer costs seconds, not a lease
        peers = sorted(sources)
        require(peers, "no peer to ask for a lease")
        order[:] = order[1:] + order[:1] if order and set(order) == set(peers) else peers
        failures = []
        event = {"event": "admission-renew", "epoch": manifest["epoch"], "manifest_digest": membership.digest(manifest), "subject": node.node_id}
        for name in list(order):
            client = sync.Client(node.node_id, Manifest, None, sources, trail)
            try:
                got = client.renewer(name, node.quote(session, public))(request)
            except Refused as refused:
                failures.append("%s: %s" % (name, refused))
                quiet.deny(dict(event, peer=name, outcome="DENY", reason=convergence._printable(refused, membership.REASON_LIMIT)))
                continue
            # each attempt on the node's own trail (#340): ALLOW names the peer that issued the lease. A record that
            # cannot be written fails the attempt: a lease nobody recorded is not used.
            quiet.allow(dict(event, peer=name, outcome="ALLOW", reason=""))
            return got
        reason = "no peer gave a lease (%d asked: %s)" % (len(failures), "; ".join(sorted(failures)))     # by peer: one kind, whatever the rotation
        quiet.deny(dict(event, peer="", outcome="DENY", reason=convergence._printable(reason, membership.REASON_LIMIT)))
        raise Refused(reason)
    return admission.Service(holder, node.manifest, renew, admission_file(node.runtime),
                             daemon_started=daemon_started or admission.unit_started(),
                             metrics=lambda samples: metrics.publish("admission", samples),      # #305
                             record=trail)                                                     # #340: serving and not, on its trail


class RoundLog:
    """#470: one journal line per source per pull round, saying what happened: an epoch applied, nothing newer, a DENY
    with the reason the trail records, or a peer that did not answer. The trail (sync-audit.jsonl) stays the record;
    this is what an operator reads in `journalctl -u regalia-sync`. Rate-bounded per source: a line when the outcome
    changes, and the same outcome again at most once every REPEAT_S seconds. Nothing in it the trail does not hold
    already (source names, epochs, the bounded reason), so no secrets."""

    REPEAT_S = 900

    def __init__(self, clock=time.monotonic, out=None):
        self.clock = clock
        self.out = out or (lambda line: print("sync: " + line, file=sys.stderr, flush=True))
        self.last = {}                          # source -> (outcome key, when it was last said)

    def _say(self, source, key, line):
        now, prev = self.clock(), self.last.get(source)
        if prev is not None and prev[0] == key and now - prev[1] < self.REPEAT_S:
            return
        try:
            self.out(line)
        except OSError:                         # the journal is best-effort: a closed stderr never stops a round
            return
        self.last[source] = (key, now)

    def pulled(self, source, held, epoch):
        if held is None or epoch > held:
            self._say(source, ("applied", epoch), "applied epoch %d from %s (held %s before)" % (epoch, source, "none" if held is None else held))
        else:
            self._say(source, ("nothing", epoch), "nothing newer from %s: epoch %d held" % (source, epoch))

    def refused(self, source, refusal, event):
        text = convergence._printable(refusal, membership.REASON_LIMIT)
        if text.startswith("%s did not answer (" % source):            # the error class is the whole key
            self._say(source, ("silent", text), "peer " + text)
            return
        kind, reason = (event["event"], event["reason"]) if event is not None else ("pull", text)
        # printable again, though audited() made them so: a sink event written raw later must not reach the journal
        kind, reason = convergence._printable(kind, 64), convergence._printable(reason, membership.REASON_LIMIT)
        # keyed with digit runs collapsed: a reason that carries a count, a time or a sequence is the same outcome
        self._say(source, ("deny", kind, re.sub(r"[0-9]+", "#", reason)), "DENY %s from %s: %s" % (kind, source, reason))


class Sync:
    """The `sync` process: the two listeners, the pull loop and the heartbeat watch, on one store."""

    def __init__(self, node):
        # #332: the single document of before (node.json's `measurements`) goes into the store by digest, once
        measurements.migrate(node.documents(), node.cfg["measurements"], log=lambda line: print("sync: " + line, file=sys.stderr))
        self.node, self.store, self.freshness = node, node.store(), node.freshness()
        self.trail = Trail(node.path("sync-audit.jsonl"), "sync")
        self.signer = lease.TpmSigner(node.tcti, node.run)
        self._beat_signer = None        # beat.Signer, made at the first heartbeat signed (beat_signer())
        self.published = None
        self.rounds = RoundLog()                # #470: each pull round's outcome, in the journal
        # the unlock listener's refusals, by cause (#317), in regalia-sync's metrics directory
        self.refusals = metrics.Counter("sync", "regalia_unlock_refused_total", "unlock.prom", metrics.UNLOCK_CAUSES)

    def membership_metrics(self):
        """The held epoch and the TPM anchor's (#66 B3: sync never anchors; regalia-esp-advance does, after the ESP): a gap
        that lasts is an ESP advance that keeps failing, and rollback protection frozen at the anchor (regalia-kms-48's
        read; RegaliaMembershipAnchorBehind). Never raises: metrics do not stop sync; a file that stops moving alerts."""
        try:
            metrics.publish("sync", [("regalia_membership_epoch", {}, self.manifest()["epoch"]),
                                     ("regalia_membership_anchor_epoch", {}, self.node.anchor().value())],
                            metrics.path("sync", "membership.prom"))
        except Exception:                       # noqa: BLE001 - see above
            pass

    def manifest(self):
        return self.store.load()

    def server(self):
        # the enrolment operations (#190): the same contribution store the unlock peer serves paths from
        enrol = enrolpeer.Peer(unlock.Contributions(self.node.path("contributions.json")), enrolpeer.Wraps(self.node.path("enrol-wraps.json")),
                               enrolpeer.tpm_identity(self.node.tcti, self.node.run), enrolpeer.tpm_activate(self.node.tcti, self.node.run))
        # attester_for itself: each request is judged under the manifest held then, by that manifest's document (#332)
        return sync.Server(self.node.node_id, self.store, self.freshness, self.node.attester_for, self.signer,
                           wgsvc.key_at, self.trail, enrol=enrol, documents=self.node.documents(), cosigner=self.cosign)

    # ---- heartbeats signed by the nodes (#199, beat.py) ----

    def beat_signer(self):
        """This node's beat.Signer (node_beat_signer), made once."""
        if self._beat_signer is None:
            self._beat_signer = node_beat_signer(self.node)
        return self._beat_signer

    def cosign(self, manifest, caller, body, signature):
        """sync.Server's cosigner: beat.cosign with this node's parts."""
        return beat.cosign(manifest, self.node.node_id, caller, body, signature, self.freshness, self.node.clock(), self.beat_signer())

    def proposer(self):
        def ask(peer, body, signature):
            sources = self.node.sources(self.manifest())
            return sync.Client(self.node.node_id, self.store, self.freshness, sources, self.trail).beat_sign(peer, body, signature)
        sync_ = self

        class Lazy:
            """The Signer, made when a heartbeat is first signed: a node that is not under v4 (or not a UKI) still starts."""
            def signed(self):
                return sync_.beat_signer().signed()

            def __call__(self, body, manifest):
                return sync_.beat_signer()(body, manifest)
        return beat.Proposer(self.node.node_id, self.manifest, self.freshness, self.node.clock(), Lazy(), ask, self.trail,
                             interval=self.node.cfg["beat_interval_s"])

    def unlock_peer(self):
        return unlock.Peer(self.node.node_id, self.store, self.freshness, self.node.attester_for,
                           unlock.Contributions(self.node.path("contributions.json")), self.signer, self.trail, run=self.node.run,
                           refused=self.refusals)

    def caller(self, address):
        """unlock.serve's `caller`: the node a boot-tunnel address belongs to, by the manifest held NOW."""
        try:
            return bootnet.caller_of(self.node.site, self.manifest())(address)
        except Refused:
            return None

    def publish(self):
        """Publish the chain if it changed. Returns whether it did (wg-apply's path unit then runs)."""
        current = convergence.summary(self.store)
        if current == self.published:
            return False
        publish(self.store, self.node.path(PUBLISHED))
        self.published = current
        return True

    def pull_round(self):
        """Ask every source once. A source that refuses or does not answer is recorded and skipped. The
        chain is published after EACH source, not after all of them: a commit moves the TPM anchor, and
        the root services refuse the published chain until it catches up (Node.manifest)."""
        sources = self.node.sources(self.manifest())
        seen = []

        def sink(event):
            self.trail(event)                   # the trail first: it is the record, and a sink that fails still stops the round
            seen.append(event)
        client = sync.Client(self.node.node_id, self.store, self.freshness, sources, sink, documents=self.node.documents())
        changed = False
        for name in sorted(sources):
            del seen[:]
            try:
                now_at, _ = client.pull(name)
            except Refused as refused:
                denied = [e for e in seen if e.get("outcome") == "DENY"]
                self.rounds.refused(name, refused, denied[-1] if denied else None)
            else:
                # the epoch held when this source's pull began: its first sync-apply event was filed under it (no
                # second store load, and no TPM read, per round: 3e's read)
                applies = [e["epoch"] for e in seen if e.get("event") == "sync-apply"]
                self.rounds.pulled(name, applies[0] if applies and applies[0] else None, now_at["epoch"])
            changed = self.publish() or changed
        return changed

    def watch(self):
        return heartbeat_watch.Watch(self.freshness, self.manifest, self.trail, metrics.path("sync", "heartbeat.prom"),      # #305: node_exporter's
                                     self.node.path("heartbeat-watch.json"))

    def run(self, stop):
        """Until `stop()`: the listeners in threads, then the pull loop and the watch in this one."""
        self.publish()
        mesh, svc = self.node.site["boot_mesh"], self.node.site["service_mesh"]
        listeners = []
        service = bind_when_up((self.node.own_address(self.manifest()), svc["sync_port"]), stop, family=socket.AF_INET6)
        service.settimeout(1)
        listeners.append(service)
        unlocking = bind_when_up((mesh["address"], mesh["unlock_port"]), stop)
        listeners.append(unlocking)
        threads = [threading.Thread(target=sync.serve, args=(self.server(), service, stop), daemon=True),
                   threading.Thread(target=unlock.serve, args=(self.unlock_peer(), unlocking), kwargs={"caller": self.caller}, daemon=True)]
        for thread in threads:
            thread.start()
        watch, proposer = self.watch(), self.proposer()
        unable = None                           # the last refusal the proposer could not even start under
        self.refusals.flush()                   # its zeros from the start, then every round (refusals only count)
        try:
            behind = None                       # the last refusal the rotation catch-up met (#361 C4), written once
            while not stop():
                self.pull_round()
                # #361 C4: after each round, this node's rotation counter is brought to the generation the root published,
                # FIRST, before it proposes or signs: until it has, every write and signature under K_A is refused
                try:
                    if self.manifest()["schema"] == membership.SCHEMA_V4 and "anchor_policy_key" in self.manifest():
                        before = anchorpolicy.read_rotation(anchorpolicy.ROTATION_INDEX, _tpm_run(self.node.cfg))
                        after = catch_up_rotation(self.node.cfg)
                        if after != before:
                            self.trail({"event": "rotation-catch-up", "outcome": "ALLOW", "from": before, "to": after})
                        behind = None
                except (Refused, OSError) as refused:
                    if str(refused) != behind:
                        behind = str(refused)
                        with contextlib.suppress(Exception):
                            self.trail({"event": "rotation-catch-up", "outcome": "DENY", "reason": behind[:240]})
                # #199: under v4 the nodes sign the heartbeats; this node proposes when it is its turn (beat.Proposer).
                # A refusal before any proposal (no authenticated time, not a UKI boot: no PCR key to sign under) is
                # written once per cause, so a node that can never sign is not silent (regalia-kms-1e's read)
                try:
                    if self.manifest()["schema"] == membership.SCHEMA_V4:
                        proposer.step()
                except (Refused, OSError) as refused:
                    if str(refused) != unable:
                        unable = str(refused)
                        with contextlib.suppress(Exception):
                            self.trail({"event": "beat-propose", "outcome": "DENY", "reason": unable[:240]})
                else:
                    unable = None
                with contextlib.suppress(Refused, OSError):
                    watch.step()
                self.refusals.flush()
                self.membership_metrics()
                deadline = time.monotonic() + self.node.cfg["pull_interval"]
                while not stop() and time.monotonic() < deadline:
                    time.sleep(1)
        finally:
            for listener in listeners:
                listener.close()


def bind_when_up(where, stop, family=socket.AF_INET, create=socket.create_server, sleep=time.sleep):
    """A listener on a tunnel address, once the tunnel has it. On a host's first start the tunnels do not
    exist yet: regalia-wg-apply makes them from the chain this process has just published. Waiting here,
    rather than exiting, keeps the service from restarting in a loop until they appear."""
    while True:
        try:
            return create(where, family=family)
        except OSError as failure:
            if failure.errno != errno.EADDRNOTAVAIL or stop():
                raise
        sleep(1)


def authtime_service(cfg):
    """Takes the configuration only: it reads nothing else (not the site configuration, not a key), and
    its unit hides the rest of /etc and all of /var from it."""
    return authtime.service(cfg["run_dir"], cfg["time_servers"])     # the one entry point


# ---- command line ----

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", default="/etc/regalia/node.json")
    parser.add_argument("service", choices=("authtime", "wg-apply", "boot-session", "admission", "sync", "check", "time-clear", "esp-advance"))
    parser.add_argument("--esp", default="/efi", help="esp-advance only: the ESP's mount point")
    parser.add_argument("--esp-lock", default=ESP_LOCK, help="esp-advance only: the anchor's writer lock (default: the unit's "
                        "RuntimeDirectory; the three-node fixture gives each node its own)")
    parser.add_argument("--reason", help="time-clear only: why chronyd may run again. FIRST compare the declared NTS servers "
                        "with an independent clock (another site's, a GNSS receiver, a phone on the mobile network): chronyd "
                        "stopped because two of them agreed on a jump, and a restarted chronyd steps to what they agree on")
    args = parser.parse_args(argv)
    try:
        if args.service == "time-clear":
            # #303: the latch the chrony drop-in leaves when chronyd stops abnormally; root's, recorded first
            require(os.geteuid() == 0, "time-clear is root's: the latch is in root's %s" % authtime.LATCH_DIR)
            event = authtime.clear_latch(args.reason or "", Trail(trails.where(authtime.TRAIL), authtime.TRAIL))
            print("CLEARED the time latch (recorded in the time trail: %s). Start chronyd: systemctl start chrony" % event["chrony_said"][:120])
            return 0
        if args.service == "authtime":
            authtime_service(load(args.config)).run(lambda: False)
            return 0
        if args.service == "boot-session":
            # takes the configuration only, like authtime: it needs the run directory and nothing else
            run_dir = load(args.config)["run_dir"]
            had = os.path.exists(os.path.join(run_dir, "boot-session"))
            session, _ = boot_session(run_dir, make=True)
            print("boot session %s…, %s" % (session[:16], "the unlock client's" if had else "made now: the unlock client presented none"))
            return 0
        node = Node(load(args.config))
        if args.service == "check":
            # the anchor beside it (#66 B3): below the epoch while regalia-esp-advance has not yet run, or keeps failing
            print(json.dumps({"node_id": node.node_id, "epoch": node.manifest()["epoch"], "anchor": node.anchor().value()}))
        elif args.service == "wg-apply":
            print("wg-svc and %s applied under epoch %d" % (node.site["boot_mesh"]["interface"], wg_apply(node)))
        elif args.service == "esp-advance":
            try:
                epoch, sha, rewritten, unrenderable = esp_advance_settled(node, args.esp, lock_path=args.esp_lock)
            except BaseException:
                esp_metrics(node, ok=False)
                raise
            esp_metrics(node, ok=True, renderable=unrenderable is None)
            print("the ESP's membership chain is epoch %d (sha256 %s%s), and the TPM anchor with it"
                  % (epoch, sha, ", written now" if rewritten else ", already there"))
            if unrenderable:
                print("WARNING: the initrd cannot render a boot configuration under epoch %d (%s): the next boot asks for "
                      "the recovery key" % (epoch, unrenderable), file=sys.stderr)
        elif args.service == "admission":
            admission_service(node).run(lambda: False)
        else:
            Sync(node).run(lambda: False)
    except (OSError, Refused, sitecfg.InvalidSite, binascii.Error) as failure:
        print("REFUSED: %s" % failure, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
