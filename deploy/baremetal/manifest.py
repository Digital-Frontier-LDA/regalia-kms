"""regalia-manifest: propose, compare, sign and verify membership manifests (#156).

The membership root is an Ed25519 software key, Shamir-split and reconstructed only in the RAM of the air-gapped
ceremony laptop (ADR-0002 D28, the owner's decision of 2026-10-04, superseding the Nitrokey of #156), and handed to
this tool by regalia-ceremony's offline-keys.py on a file descriptor (--key-fd; deploy/baremetal/keyfd.py). A
PKCS#11 token (--key) remains the path for a P-256 key on a card. This is the tool the root's operator runs at a ceremony to sign the next manifest,
e.g. the two a kernel update needs (approve, then retire; KERNEL-UPDATE.md). It adds no cryptography and no
rule of its own: every rule is membership.py's, run BEFORE a signature exists and again on the finished
envelope, so nothing a node would refuse is ever signed.

    python3 -Es -m deploy.baremetal.manifest verify  --chain CHAIN.json --root-key ROOT
    python3 -Es -m deploy.baremetal.manifest propose --chain CHAIN.json --root-key ROOT (--from-rollout R.json | --set-state NODE=STATE ...)
                                                     [--issued-at YYYY-MM-DDTHH:MM:SSZ] --out PROPOSAL.json
                                                     [--old OLD.json --new NEW.json [--state NODE=STATE.json]...]
    python3 -Es -m deploy.baremetal.manifest propose --genesis --root-key ROOT --card-record CARDS.json --measurements DOC.json
                                                     --entry A.json --entry B.json --entry C.json --out EPOCH1.json
    python3 -Es -m deploy.baremetal.manifest diff    --chain CHAIN.json --root-key ROOT --proposal PROPOSAL.json
    python3 -Es -m deploy.baremetal.manifest sign    --chain CHAIN.json --root-key ROOT --expected-epoch N --proposal PROPOSAL.json
                                                     --signer root|revocation --key 'pkcs11:serial=…;token=…;id=%01;type=private'
                                                     --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so [--opensc-conf FILE]
                                                     [--pin-env NAME] --state-dir DIR --out ENVELOPE.json [--chain-out NEXT.json]
                                                     (or, the offline root: --signer root --key-fd N --offline-session ID, no --key/--module)
    python3 -Es -m deploy.baremetal.manifest sign --genesis --root-key ROOT --proposal EPOCH1.json --signer root --key-fd N
                                                     --offline-session ID --state-dir DIR --out E1.json [--chain-out CHAIN.json]
                                                     [--old OLD.json --new NEW.json [--state NODE=STATE.json]... [--emergency] [--locked-out NODE]...]
    python3 -Es -m deploy.baremetal.manifest clear-pin-latch --state-dir DIR

ROOT is the pinned root as rollout.py takes it: 64 hex (an Ed25519 root), or JSON (a typed entry
{"alg": "ecdsa-p256", "key": …} or a list of entries). CHAIN.json is a signed chain (a JSON list of
envelopes), verified from ROOT every time.

`sign` stops at the first refusal, and signs only at step 6:
  1. the chain verifies from ROOT and ends at --expected-epoch (the signing machine has no TPM anchor: the
     operator states which epoch the fleet is at, and a shorter or longer chain is refused);
  2. the proposal passes membership.transition() from the chain's last manifest, for --signer;
  2a. a proposal that changes the measurements is judged from --old, --new and --state, never from its own word:
     one step measurements.transition allows, and none that locks out a node still running the set that goes
     except an --emergency naming exactly the nodes it locks out with --locked-out (rollout.check_lockout, #75);
  3. --key is a PKCS#11 URI naming the card by serial= and token= and the key by object= or id=, with
     type=private and nothing else (p11uri.parse, the UKI build's rule); or --key-fd N, the offline root: an
     Ed25519 PKCS#8 key on a pipe or a sealed memfd (never a file on disk, keyfd.read), --signer root only, with
     --offline-session (the ID offline-keys.py records too). The key is read into a bytearray, loaded, and the
     buffer zeroed; the typed confirmation then comes from /dev/tty (offline-keys.py runs this with /dev/null
     on stdin), and the signing record names "offline-keys session <ID>" as its provenance;
  4. the token is opened in process (authority.Pkcs11Signer, #262): exactly one token attached, its serial
     and label read again in the session that logs in; its P-256 public key must be a pinned root key
     (--signer root) or a revocation key the current manifest names (--signer revocation);
  5. the diff, the epoch and the manifest digest are printed, and the operator types the epoch and the first
     eight hex digits of the digest;
  6. the token signs: CKM_ECDSA over SHA-256 of DOMAIN + canonical(manifest), r||s, low-S. The PIN is TYPED
     at the console with no echo, never an argument (regalia-kms-24's decision: at a ceremony the root PIN
     is never in an environment, a runbook or a shell history). --pin-env exists for tests and bench runs
     only: it is refused unless REGALIA_MANIFEST_TEST=1 is also set, and the signing record says which
     source gave the PIN. A PIN the token refuses latches (DIR/pin-latch.json) and is never presented
     again until `clear-pin-latch`;
  7. the signature is verified and membership.accept() takes the finished envelope; THEN, whatever that found, one
     line is appended to DIR/signing-record.jsonl for the signature the token made: the digest it was asked to
     sign, "verified" true or false, and the reason if false (every use of the root key is recorded, as an HSM's
     own audit records each sign operation). Only a verified signature whose line is on the record is written
     (--out, and with --chain-out the chain plus it, from which the next proposal of the session is made): a
     signature that does not verify, or a record that cannot be written, leaves nothing but the refusal.

GENESIS (`sign --genesis`, the first ceremony): there is no chain yet, so step 1 is replaced. The proposal must be
a fresh epoch-1 manifest of the current schema (v4) with no prev_digest, passing membership.validate and the
first-manifest rule; --chain and --expected-epoch are refused; only the offline root (--key-fd) signs it. At this
one moment the pin vouches for itself (nothing earlier names the root), so before the epoch and digest the operator
types the root key's FULL SHA-256 fingerprint, 64 hex, read from the ceremony's own record of the generated key and
never from this screen: the line `ROOT-FINGERPRINT <64 hex>  (sha256 of the raw 32-byte Ed25519 key, as enrol check and
manifest sign --genesis take it)` that offline-keys.py generate prints and records as `root_fingerprint`, which the
operator copied onto the ceremony sheet (regalia-ceremony#119; the format `enrol check` takes, #243). NOT its
`spki-sha256`, which is another hash of the same key. The key must be --root-key's and have that
fingerprint. The finished envelope must pass membership.accept(None, ...); the record line carries "genesis": true.

A key in a file is not a signing backend here: the root signs on its token, or from the offline session's
descriptor, and every step above runs either way.

CURRENT LIMITATIONS (stated, not hidden; the cross-cutting list is LIMITATIONS.md):
  * The node entries `propose --genesis` takes are UNSIGNED files (#399). It checks their shape, the bench serials and
    that no key is reused, but cannot tell an entry from the node from one edited on the way. Each node's `enrol check`
    compares its entry field by field with its own bundle and refuses a mismatch, but only AFTER the root signed: a
    tampered entry costs a redone genesis, not a silently accepted node. Until #399, the operator carries each entry
    from the node's console and reads every field of the printed proposal.
  * The owner's and the release card's keys come only from the card ceremony's record, verified under the pinned root
    (cardrecord.py); its attestation certificates are checked by digest only on this side (#400).
  * The bench tokens refused are a hand-kept list (membership.BENCH_TOKENS): a new bench token must be added there.
  * The genesis policy is GENESIS_POLICY's defaults plus two lifetime flags; the proposed D31 director party is not
    modelled.
  * Run only with software keys, software TPMs and CI: no ceremony has run, and nothing here has signed on the
    production hardware yet (#297)."""
import argparse
import datetime
import getpass
import hashlib
import hmac
import json
import os
import re
import sys
import time

from deploy.baremetal import attest, cardrecord, keyfd, measurements, membership, p11uri, rollout
from deploy.baremetal.membership import Refused, require

RECORD = "signing-record.jsonl"
LATCH = "pin-latch.json"


# ---- reading ----

def root_key(value):
    """--root-key: 64 hex, or a typed entry or list as JSON. Checked here, so a malformed pin fails at once."""
    if isinstance(value, str) and value.startswith(("{", "[")):
        value = json.loads(value)
    membership.root_entries(value, "--root-key")
    return value


def read_json(path, limit):
    with open(path, "rb") as f:
        return membership.load(f.read(limit + 1), limit)


def verify_chain(chain, root):
    """The last manifest of a signed chain, every envelope accepted in order from nothing. Returns it."""
    require(isinstance(chain, list) and chain, "the chain must be a non-empty list of signed manifests")
    return membership.accept_chain(None, chain, root)


# ---- proposing ----

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def propose_states(current, changes, issued_at):
    """The next manifest: `current` with the nodes' states changed ({node_id: state}), the epoch moved on and
    chained to it. Validated; whether a signer may make the change is transition()'s, at `sign`."""
    require(changes, "no change given")
    candidate = json.loads(json.dumps(current))
    nodes = {n["node_id"]: n for n in candidate["nodes"]}
    for nid, state in changes.items():
        require(nid in nodes, "%s is not a node of epoch %d" % (nid, current["epoch"]))
        require(state in membership.CAPABILITIES, "%r is not a state (%s)" % (state, ", ".join(membership.CAPABILITIES)))
        require(nodes[nid]["state"] != state, "%s is already %s" % (nid, state))
        nodes[nid]["state"] = state
    candidate.update(epoch=current["epoch"] + 1, prev_digest=membership.digest(current), issued_at=issued_at)
    membership.validate(candidate)
    return candidate


# ---- the genesis: epoch 1, built from recorded facts (the first ceremony) ----

# The policy of a genesis manifest (regalia-kms-24, 2026-10-04), printed in full in every proposal for the owner to
# review before `sign --genesis`. Overridden only by explicit flags (--heartbeat-max-lifetime-s,
# --owner-heartbeat-lifetime-s); membership.validate still refuses a value below its floors. The owner is ONE party,
# so "2 of {a, b, c, owner}" already means at least one node signs every heartbeat and activation lease. The proposed
# D31 director party (not decided) would make that floor explicit; there is deliberately no director field here.
GENESIS_POLICY = {"heartbeat_max_lifetime_s": 21600, "owner_heartbeat_lifetime_s": 3600}
OWNER_PARTY = membership.OWNER
# what `enrol entry` prints for a node (#358, #371 and its ssh_host_pub): the v4 entry is these and state ACTIVE
ENTRY_FIELDS = ("node_id", "ek_name", "ak_name", "wg_service_pub", "wg_boot_pub", "signing_key", "hsm_serials", "ssh_host_pub")
# the bench's tokens (membership.BENCH_TOKENS: its Nitrokeys and YubiKeys, in every form hsm_serials pins): never a
# production node's (ADR-0002 D28.5, D30). Genesis is where the root first vouches for a node's tokens, so refused here.
BENCH_SERIALS = membership.BENCH_TOKENS


def _raw_ed25519(value, what):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "%s is not a raw Ed25519 public key (64 lowercase hex)" % what)
    return value


def card_record_keys(envelope, root):
    """The owner's two keys and the release card's, from the card ceremony's record (regalia-ceremony#111, ADR-0002 D30)
    and nowhere else: verified by cardrecord.verify under the PINNED root first, so a key is never typed. The genesis
    root is one Ed25519 key (D28); a pin naming anything else is refused here. Returns cardrecord.verify's result."""
    entries = membership.root_entries(root)
    require(len(entries) == 1 and entries[0][0] == "ed25519",
            "the genesis root is one Ed25519 key (D28): a card record is verified under that key only, not %s"
            % ", ".join(alg for alg, _ in entries))
    return cardrecord.verify(envelope, entries[0][1])


def propose_genesis(entries, document, owners, release_key, root, issued_at, policy=None):
    """Epoch 1 (v4), unsigned: every node from its `enrol entry` output (state ACTIVE), the measurements `document` it
    commits to, the owner's two keys, and GENESIS_POLICY (with `policy` overrides). Refused unless it is a manifest a
    node would accept from the root at genesis (validate, transition(None, ..., "root"), measurements.bind), and unless
    the release card's key, the root's and every node's signing key are each other than the owner keys. `owners`
    ({card serial: key}) and `release_key` come from the card record (card_record_keys); checked here again, as a
    library caller may give them otherwise."""
    require(isinstance(owners, dict) and len(owners) == 2, "the owner's keys are exactly two cards' (D30), not %r" % (owners,))
    for serial, key in sorted(owners.items()):
        _raw_ed25519(key, "the owner card %s's key" % serial)
        require(isinstance(serial, str) and serial.upper() not in membership.BENCH_TOKENS,
                "the owner card %s is a bench token: the ceremony never uses a bench serial (D28.5, D30)" % serial)
    require(len(set(owners.values())) == 2, "the two owner cards have the same key: they are one card")
    require(isinstance(entries, list) and entries, "no node entry given (--entry, one per node, as `enrol entry` printed it)")
    nodes = []
    for i, entry in enumerate(entries):
        require(isinstance(entry, dict), "entry %d is not an object" % i)
        missing = [k for k in ENTRY_FIELDS if k not in entry]
        require(not missing, "the entry of %s lacks %s: re-run `enrol entry` on a bundle made by this release's enrol init"
                % (entry.get("node_id", "entry %d" % i), ", ".join(missing)))
        membership.exact(entry, ENTRY_FIELDS, "entry of %s" % entry["node_id"])
        require(isinstance(entry["hsm_serials"], list) and entry["hsm_serials"], "the entry of %s names no token serial" % entry["node_id"])
        bench = sorted(s for s in entry["hsm_serials"] if isinstance(s, str) and s.upper() in BENCH_SERIALS)
        require(not bench, "the entry of %s names a bench token (%s): never a production node's (D28.5)" % (entry["node_id"], ", ".join(bench)))
        nodes.append(dict(entry, state="ACTIVE"))
    nodes.sort(key=lambda n: n["node_id"])
    release_key = _raw_ed25519(release_key, "the release key")
    require(release_key not in owners.values(), "the release key is one of the owner keys: the release card is never an owner key")
    roots = {key for _, key in membership.root_entries(root)}
    for name, key in [("owner card %s" % s, k) for s, k in sorted(owners.items())] + [("release card", release_key)]:
        require(key not in roots, "the %s's key is the pinned root's" % name)
        for node in nodes:
            require(key != node["signing_key"].get("key"), "the %s's key is %s's signing key" % (name, node["node_id"]))
    ids = [n["node_id"] for n in nodes]
    candidate = dict(GENESIS_POLICY, **(policy or {}))
    candidate.update({
        "schema": membership.SCHEMA_V4, "epoch": 1, "prev_digest": "", "policy_version": measurements.version(document), "issued_at": issued_at,
        "owner_keys": [{"alg": "ed25519", "key": owners[serial]} for serial in sorted(owners)],
        "heartbeat_signers": {"threshold": 2, "parties": ids + [OWNER_PARTY]},
        "activation_signers": {"threshold": 2, "parties": ids + [OWNER_PARTY]},
        "revocation_signers": [{"threshold": 2, "parties": ids}, {"threshold": 1, "parties": [OWNER_PARTY]}],
        "nodes": nodes})
    membership.validate(candidate)
    membership.transition(None, candidate, "root")
    measurements.bind(candidate, document)
    return candidate


def measurement_step(current, candidate, step=None):
    """A proposal that changes the measurements (another policy_version) is judged HERE, from the documents
    and the peers' state files, never from what a proposal says of itself: `step` is {"old": the document
    `current` commits to, "new": the one `candidate` commits to, "states": {node: verifier state},
    "emergency": bool, "locked_out": [node, ...]}. The step must be one measurements.transition allows, and
    if it takes a set away, rollout.check_lockout's rule holds: no node that may still run the set that goes
    is locked out except in an emergency, and every node locked out is named. Returns {"transition",
    "locked_out"}, or None when the measurements do not change (and then `step` must be absent)."""
    if candidate.get("policy_version") == current.get("policy_version"):
        require(step is None, "the proposal keeps the measurements (policy_version unchanged): --old, --new, --state, "
                "--emergency and --locked-out are not read")
        return None
    require(step is not None and step.get("old") is not None and step.get("new") is not None,
            "the proposal changes the measurements (policy_version %s -> %s): give --old (the document the chain commits to), "
            "--new (the one the proposal commits to) and, if it takes a set away, --state for every authorizing node, so that "
            "this tool judges the step itself" % (current.get("policy_version"), candidate.get("policy_version")))
    old, new = step["old"], step["new"]
    measurements.bind(current, old)
    measurements.bind(candidate, new)
    gone = sorted(set(measurements.validate(old)) - set(measurements.validate(new)))
    kind = measurements.transition(old, new, emergency=bool(step.get("emergency")), dropped=gone)
    require(kind != "unchanged", "the two documents differ only in name: there is no step to sign")
    locked = rollout.check_lockout(current, old, new, kind, step.get("states") or {}, bool(step.get("emergency")),
                                   list(step.get("locked_out") or []))
    return {"transition": kind, "locked_out": locked}


def propose_from_rollout(current, output, step=None):
    """rollout.py `propose --json`'s unsigned manifest, if it follows `current` AND this tool, judging the
    step itself (measurement_step, with the output's own emergency and locked-out list as the operator's
    words), finds the same transition and the same nodes locked out. An edited output is refused."""
    require(isinstance(output, dict) and "unsigned_manifest" in output, "not the output of `rollout propose --json`")
    candidate = output["unsigned_manifest"]
    membership.validate(candidate)
    require(candidate["epoch"] == current["epoch"] + 1 and candidate["prev_digest"] == membership.digest(current),
            "the proposal does not follow epoch %d of this chain (it was made from another chain or epoch)" % current["epoch"])
    if candidate.get("policy_version") != current.get("policy_version"):
        require(step is not None, "the proposal changes the measurements: give --old, --new and --state so that this tool judges "
                "the step itself")
        step = dict(step, emergency=output.get("emergency") is True, locked_out=output.get("locked_out") or [])
    judged = measurement_step(current, candidate, step)
    if judged is not None:
        require(output.get("transition") == judged["transition"], "the proposal says %r, but the documents make it %r: it was "
                "edited, or made from other documents" % (output.get("transition"), judged["transition"]))
        require(output.get("locked_out") == judged["locked_out"], "the proposal says it locks out %s, but it locks out %s: it "
                "was edited, or made from other state files" % (output.get("locked_out"), judged["locked_out"]))
    return candidate


# ---- comparing ----

def _show(value):
    return json.dumps(value, sort_keys=True)


def diff(current, candidate):
    """Every difference, field by field, nothing summarised away. A list of lines."""
    lines = []
    for k in sorted(set(current) | set(candidate)):
        if k == "nodes":
            continue
        if current.get(k) != candidate.get(k):
            lines.append("%s: %s -> %s" % (k, _show(current.get(k)), _show(candidate.get(k))))
    old = {n["node_id"]: n for n in current["nodes"]}
    new = {n["node_id"]: n for n in candidate["nodes"]}
    for nid in sorted(set(old) | set(new)):
        if nid not in new:
            lines.append("node %s: REMOVED (was %s)" % (nid, old[nid]["state"]))
        elif nid not in old:
            lines.append("node %s: ADDED, %s" % (nid, _show(new[nid])))
        else:
            for k in sorted(set(old[nid]) | set(new[nid])):
                if old[nid].get(k) != new[nid].get(k):
                    lines.append("node %s: %s: %s -> %s" % (nid, k, _show(old[nid].get(k)), _show(new[nid].get(k))))
    return lines or ["no difference"]


# ---- signing ----

def _write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _write_new(path, data, mode=0o644):
    """A new file, never an existing one replaced, flushed to disk. A write that fails part way (a full disk)
    removes the file, so no truncated envelope is left that a later run could not replace (regalia-kms-48)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, mode)
    try:
        _write_all(fd, data)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        os.unlink(path)
        raise
    os.close(fd)


def _append_record(state_dir, line):
    fd = os.open(os.path.join(state_dir, RECORD), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        _write_all(fd, (json.dumps(line, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def state_dir(path):
    """The operator's directory for the signing record and the PIN latch: this user's, 0700."""
    info = os.stat(path)
    require(os.path.isdir(path) and info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
            "--state-dir %s must be a directory of this user's, mode 0700" % path)
    return path


def token_signer(uri, module, opensc_conf, pin, latch_path, pkcs11=None):
    """The token the URI names, opened through authority.Pkcs11Signer (#262) with the operator's opt-ins."""
    from deploy.baremetal import authority
    attributes = p11uri.parse(uri, "--key")
    require(module.startswith("/"), "--module must be an absolute path")
    return authority.Pkcs11Signer(module, attributes["serial"], p11uri.key_id(attributes), None, opensc_conf=opensc_conf,
                                  pkcs11=pkcs11, latch_path=latch_path, label=attributes["token"], only_token=True,
                                  key_label=attributes.get("object"), pin=pin)


class OfflineSigner:
    """The offline root (ADR-0002 D28): an Ed25519 key read from a descriptor (keyfd.read), the buffer zeroed once
    the key is loaded. `provenance` is what the signing record names: "offline-keys session <ID>". The bytes copy that
    loading makes, and the key object, cannot be cleared: they last until this process exits (keyfd.py says why that
    is the ceremony laptop's RAM, and what a pipe cannot prove)."""
    alg, serial, label = "ed25519", None, None

    def __init__(self, fd, provenance):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.provenance = provenance
        buffer = keyfd.read(fd, "--key-fd")
        try:
            try:
                key = serialization.load_pem_private_key(bytes(buffer), password=None)
            except (ValueError, TypeError) as error:
                raise Refused("--key-fd: not an unencrypted PKCS#8 PEM key (%s)" % type(error).__name__) from None
        finally:
            keyfd.zero(buffer)
        require(isinstance(key, Ed25519PrivateKey), "--key-fd: the offline root is an Ed25519 key")
        self._key = key

    def public(self):
        from cryptography.hazmat.primitives import serialization
        return self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def sign(self, message):
        signature = self._key.sign(message)
        self._key = None                        # one signature per session's key
        return signature


def check_signer_key(current, root, signer_role, public, alg="ecdsa-p256"):
    """The signer's key may sign as `signer_role`: a pinned root key of `alg` (the token's ecdsa-p256, or the offline
    root's ed25519), or a revocation key `current` names."""
    if signer_role == "root":
        algs = [a for a, key in membership.root_entries(root) if key == public]
        require(algs, "the signer's key %s… is not the pinned root" % public[:16])
        require(algs[0] == alg, "the pinned entry for the signer's key is not %s" % alg)
    else:
        require(membership.revocation_alg(current, public) == "ecdsa-p256",
                "the token's key %s… is not an ecdsa-p256 revocation key of epoch %d" % (public[:16], current["epoch"]))


def sign(chain, root, expected_epoch, candidate, signer_role, open_signer, confirm, out, state, chain_out=None, say=print,
         pin_source="terminal", step=None, offline=False, genesis=False):
    """Steps 1 to 7 of the module's docstring. `open_signer()` gives the token's signer (step 4's opening);
    `confirm(prompt)` returns what the operator typed. Returns the envelope written."""
    require(signer_role in ("root", "revocation"), "--signer must be root or revocation")
    if genesis:                                                                                # 1 and 2, the first ceremony
        require(offline and signer_role == "root", "the genesis is signed by the offline root only (--signer root --key-fd)")
        require(chain == [] and expected_epoch is None and step is None, "the genesis takes no chain, no expected epoch and no "
                "measurements step: nothing comes before it")
        membership.validate(candidate)
        require(candidate["schema"] == membership.SCHEMA_V4 and candidate["epoch"] == 1 and candidate["prev_digest"] == "",
                "the genesis is a fresh epoch-1 %s manifest with no prev_digest" % membership.SCHEMA_V4)
        current, judged = None, None
        membership.transition(None, candidate, "root")
    else:
        current = verify_chain(chain, root)                                                    # 1
        require(current["epoch"] == expected_epoch, "the chain ends at epoch %d, not the %d expected: fetch the fleet's chain"
                % (current["epoch"], expected_epoch))
        membership.validate(candidate)                                                         # 2
        require(offline or candidate["schema"] == membership.SCHEMA_V3, "the token's key is ecdsa-p256, which signs only schema %s"
                % membership.SCHEMA_V3)
        membership.transition(current, candidate, signer_role)
        require(candidate["epoch"] == current["epoch"] + 1, "the proposal is epoch %d, already in the chain" % candidate["epoch"])
        judged = measurement_step(current, candidate, step)                                     # 2a
    for path in (out,) + ((chain_out,) if chain_out else ()):
        require(not os.path.lexists(path), "%s exists: nothing is overwritten" % path)
    require(not offline or signer_role == "root", "--key-fd is the offline root's: a revocation key signs on its token")
    signer = open_signer()                                                                     # 3, 4
    public = signer.public()
    check_signer_key(current, root, signer_role, public, getattr(signer, "alg", "ecdsa-p256"))
    if genesis:
        # the pin vouches for itself here: the operator types the full fingerprint from the ceremony record, never shown
        fingerprint = hashlib.sha256(bytes.fromhex(public)).hexdigest()
        typed_fp = confirm("GENESIS: type the root key's ROOT-FINGERPRINT from the ceremony sheet (64 hex, not the spki-sha256): ").strip().lower()
        require(hmac.compare_digest(typed_fp.encode(), fingerprint.encode()), "the fingerprint typed is not this key's: nothing was signed")
    digest = membership.digest(candidate)                                                      # 5
    for line in diff(current or {"nodes": []}, candidate):
        say("  " + line)
    say("signer %s, key %s…, %s" % (signer_role, public[:16], getattr(signer, "provenance", None) or "token serial %s" % signer.serial))
    say("epoch %s -> %d, manifest digest %s" % (current["epoch"] if current else "none (genesis)", candidate["epoch"], digest))
    if judged is not None:
        say("measurements: %s%s" % (judged["transition"], "; LOCKS OUT %s (each refused its next unlock and lease until it boots an "
            "approved image)" % ", ".join(judged["locked_out"]) if judged["locked_out"] else ""))
    typed = confirm("type the new epoch and the first 8 hex digits of the digest (e.g. %d abcd1234): " % candidate["epoch"]).split()
    require(typed == [str(candidate["epoch"]), digest[:8]], "the confirmation does not match: nothing was signed")
    message = membership.DOMAIN + membership.canonical(candidate)                              # 6
    signature = signer.sign(message)
    envelope = {"manifest": candidate, "signature": {"signer": signer_role, "key": public, "sig": signature.hex()}}
    # 7. EVERY signature the token made is recorded, once, AFTER the software verification has run, whatever it
    # found: a signature that does not verify is still a use of the root key (as an HSM's own audit logs each sign
    # operation), and the line names the digest it was asked to sign. The envelope leaves this tool only when the
    # signature verified AND its line is on the record (regalia-kms-95 on #156).
    verified, reason, failed = False, "", None
    try:
        accepted = membership.accept(current, envelope, root)       # current None at genesis: the first-manifest rule
        require(membership.digest(accepted) == digest, "the accepted manifest is not the one signed")
        verified = True
    except Exception as failure:          # noqa: BLE001 - recorded as the reason; raised again below
        reason, failed = str(failure) or type(failure).__name__, failure
    try:
        line = {"epoch": candidate["epoch"], "digest": digest, "signer": signer_role, "key": public,
                "token_serial": signer.serial, "token_label": signer.label, "pin_source": pin_source,
                "verified": verified, "reason": reason, "at": int(time.time())}
        if getattr(signer, "provenance", None):
            line["provenance"] = signer.provenance                 # "offline-keys session <ID>": the ceremony's record names it too
        if genesis:
            line["genesis"] = True
        _append_record(state, line)
    except OSError as unrecorded:
        if failed is not None:            # both: say both (regalia-kms-95)
            raise Refused("the token's signature did not verify (%s) AND it could not be recorded (%s): nothing was written; "
                          "note this signature by hand in the ceremony log" % (reason, unrecorded)) from None
        raise
    if failed is not None:
        raise failed
    data = membership.canonical(envelope) + b"\n"
    _write_new(out, data)
    if chain_out:
        _write_new(chain_out, json.dumps(chain + [envelope], sort_keys=True).encode() + b"\n")
    say("signed epoch %d: %s" % (candidate["epoch"], out))
    return envelope


# ---- the command ----

def _propose_genesis(args, root, confirm=None, say=print):
    """`propose --genesis`: epoch 1 written after the operator types the two owner cards' serials, as printed on the
    cards, at the console (never on the command line), having read every field of it. Nothing is written otherwise.
    The owner's keys and the release card's come from the card ceremony's record (--card-record), verified under the
    pinned root before anything else is read: never typed, so there is no second way to give them."""
    require(args.chain is None and not args.from_rollout and not args.set_state and not (args.old or args.new or args.state),
            "--genesis takes no --chain, --from-rollout, --set-state or measurements step: nothing comes before it")
    require(args.measurements and args.card_record, "--genesis needs --measurements and --card-record")
    cards = card_record_keys(read_json(args.card_record, membership.MAX_BYTES), root)
    owners, release_key = cards["owners"], cards["release_key"]
    entries = [read_json(path, membership.MAX_BYTES) for path in args.entry]
    document = measurements.load(_raw(args.measurements, measurements.MAX_BYTES))
    policy = {k: v for k, v in (("heartbeat_max_lifetime_s", args.heartbeat_max_lifetime_s),
                                ("owner_heartbeat_lifetime_s", args.owner_heartbeat_lifetime_s)) if v is not None}
    candidate = propose_genesis(entries, document, owners, release_key, root, args.issued_at or utc_now(), policy)
    require(not os.path.lexists(args.out), "%s exists: nothing is overwritten" % args.out)
    for line in diff({"nodes": []}, candidate):
        say("  " + line)
    say("measurements: %s (%s)" % (candidate["policy_version"], document["name"]))
    say("card record: session %s, made %s, signed by the pinned root" % (cards["session"], cards["at"]))
    roles = {serial: role for role, serial in cards["roles"].items()}
    order = sorted(owners)
    for serial in order:
        say("owner card %s (%s): key %s, SHA-256 %s" % (serial, roles[serial], owners[serial],
                                                        hashlib.sha256(bytes.fromhex(owners[serial])).hexdigest()))
    say("release card key (not in the manifest; refused as an owner, root or node key): %s" % release_key)
    typed = (confirm or keyfd.tty_line)("type the two owner cards' serials, as printed ON THE CARDS, in the order above: ").split()
    require(typed == order, "the serials typed are not the owner cards above: nothing was written")
    _write_new(args.out, json.dumps(candidate, indent=2, sort_keys=True).encode() + b"\n")
    say("UNSIGNED genesis (epoch 1, %s) written to %s, digest %s: `sign --genesis` it on the offline laptop"
        % (membership.SCHEMA_V4, args.out, membership.digest(candidate)))
    return 0


def _step(args):
    """--old/--new/--state (and for sign --emergency/--locked-out) as measurement_step's `step`, or None if none was given."""
    given = args.old or args.new or args.state or getattr(args, "emergency", False) or getattr(args, "locked_out", [])
    if not given:
        return None
    states = {}
    for item in args.state:
        node_id, sep, path = item.partition("=")
        require(sep and node_id and path, "--state takes NODE=FILE, not %r" % item)
        require(node_id not in states, "--state names %s twice" % node_id)
        states[node_id] = read_json(path, 4 * 1024 * 1024)
    return {"old": measurements.load(_raw(args.old, measurements.MAX_BYTES)) if args.old else None,
            "new": measurements.load(_raw(args.new, measurements.MAX_BYTES)) if args.new else None,
            "states": states, "emergency": getattr(args, "emergency", False), "locked_out": getattr(args, "locked_out", [])}


def _raw(path, limit):
    with open(path, "rb") as f:
        return f.read(limit + 1)


def _states(pairs):
    changes = {}
    for pair in pairs:
        nid, sep, state = pair.partition("=")
        require(sep and nid and state and nid not in changes, "--set-state takes NODE=STATE, each node once")
        changes[nid] = state
    return changes


TEST_SWITCH = "REGALIA_MANIFEST_TEST"


def _pin_reader(name):
    """The PIN typed at the terminal; or, for a test or bench run only (TEST_SWITCH=1), from the variable
    `name`, read once and then removed from this process's environment."""
    if name:
        require(os.environ.get(TEST_SWITCH) == "1", "--pin-env is for tests and bench runs only (set %s=1): at a ceremony "
                "the root PIN is typed at the console" % TEST_SWITCH)
        require(re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", name) is not None, "--pin-env names an environment variable")
        require(name in os.environ, "--pin-env %s: the variable is not set" % name)
        pin = os.environ.pop(name)
        return lambda: pin
    return lambda: getpass.getpass("PIN of the token: ")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="regalia-manifest", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def chain(c):
        c.add_argument("--chain", required=True, metavar="CHAIN.json", help="the signed chain (a JSON list of envelopes)")
        c.add_argument("--root-key", required=True, metavar="ROOT", help="the pinned root: 64 hex, or a typed entry or list as JSON")

    def step_args(c, acknowledge):
        c.add_argument("--old", metavar="OLD.json", help="a measurements change: the document the chain's last manifest commits to")
        c.add_argument("--new", metavar="NEW.json", help="a measurements change: the document the proposal commits to")
        c.add_argument("--state", action="append", default=[], metavar="NODE=STATE.json",
                       help="a step that takes a set away: an authorizing node's attestation verifier state; one per node")
        if acknowledge:
            c.add_argument("--emergency", action="store_true", help="the step drops a set some node may still run (an emergency)")
            c.add_argument("--locked-out", action="append", default=[], metavar="NODE",
                           help="a node this step locks out; repeat, name each (as `rollout propose` listed them)")
    chain(sub.add_parser("verify", help="verify a chain from the pinned root"))
    c = sub.add_parser("propose", help="write the UNSIGNED next manifest (or, with --genesis, epoch 1)")
    c.add_argument("--chain", metavar="CHAIN.json", help="the signed chain (a JSON list of envelopes); not with --genesis")
    c.add_argument("--root-key", required=True, metavar="ROOT", help="the pinned root: 64 hex, or a typed entry or list as JSON")
    c.add_argument("--genesis", action="store_true", help="the first ceremony: epoch 1 from the nodes' entries, the measurements and the owner's two keys")
    c.add_argument("--entry", action="append", default=[], metavar="ENTRY.json", help="--genesis: a node's `enrol entry` output; one per node")
    c.add_argument("--measurements", metavar="DOC.json", help="--genesis: the measurements document epoch 1 commits to")
    c.add_argument("--card-record", metavar="CARDS.json",
                   help="--genesis: the card ceremony's record (regalia-ceremony#111, cards.record.json), signed by the pinned "
                        "root: the owner's two keys and the release card's, from it and never typed")
    c.add_argument("--heartbeat-max-lifetime-s", type=int, help="--genesis: override the default %d" % GENESIS_POLICY["heartbeat_max_lifetime_s"])
    c.add_argument("--owner-heartbeat-lifetime-s", type=int, help="--genesis: override the default %d" % GENESIS_POLICY["owner_heartbeat_lifetime_s"])
    c.add_argument("--from-rollout", metavar="R.json", help="the output of `rollout propose --json`")
    c.add_argument("--set-state", action="append", default=[], metavar="NODE=STATE", help="change a node's state; repeat")
    c.add_argument("--issued-at", metavar="YYYY-MM-DDTHH:MM:SSZ")
    c.add_argument("--out", required=True)
    step_args(c, acknowledge=False)
    c = sub.add_parser("diff", help="the proposal against the chain's last manifest, field by field")
    chain(c)
    c.add_argument("--proposal", required=True)
    c = sub.add_parser("sign", help="sign the proposal on the token (see the steps above)")
    c.add_argument("--chain", metavar="CHAIN.json", help="the signed chain (a JSON list of envelopes); not with --genesis")
    c.add_argument("--root-key", required=True, metavar="ROOT", help="the pinned root: 64 hex, or a typed entry or list as JSON")
    c.add_argument("--genesis", action="store_true", help="the first ceremony: sign epoch 1, with no chain (the offline root only)")
    c.add_argument("--expected-epoch", type=int, help="the epoch the fleet is at; the chain must end there (not with --genesis)")
    c.add_argument("--proposal", required=True)
    c.add_argument("--signer", required=True, choices=("root", "revocation"))
    c.add_argument("--key", metavar="PKCS11-URI", help="the key on a token (with --module)")
    c.add_argument("--module", help="the PKCS#11 module (OpenSC's opensc-pkcs11.so)")
    c.add_argument("--key-fd", type=int, metavar="N", help="the offline root (ADR-0002 D28): an Ed25519 PKCS#8 key on descriptor N, "
                   "a pipe or a sealed memfd from offline-keys.py, never a file; --signer root only")
    c.add_argument("--offline-session", metavar="ID", help="with --key-fd: the offline-keys session ID (32 hex), recorded")
    c.add_argument("--opensc-conf", help="an OpenSC configuration, e.g. one that ignores YubiKey readers")
    c.add_argument("--pin-env", metavar="NAME", help="TESTS AND BENCH RUNS ONLY (needs %s=1): read the PIN from this "
                   "environment variable instead of the terminal" % TEST_SWITCH)
    c.add_argument("--state-dir", required=True, help="this user's 0700 directory: the signing record and the PIN latch")
    c.add_argument("--out", required=True, help="the signed envelope (a new file)")
    c.add_argument("--chain-out", help="the chain with the new envelope appended (a new file), for the next proposal")
    step_args(c, acknowledge=True)
    c = sub.add_parser("clear-pin-latch", help="after fixing the PIN: allow the token to be tried again")
    c.add_argument("--state-dir", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "clear-pin-latch":
            path = os.path.join(state_dir(args.state_dir), LATCH)
            require(os.path.exists(path), "no PIN latch in %s" % args.state_dir)
            os.unlink(path)
            print("PIN latch cleared; the token's counter may still be low: one correct login resets it")
            return 0
        root = root_key(args.root_key)
        if args.command == "propose" and args.genesis:
            return _propose_genesis(args, root)
        if args.command == "propose":
            require(args.chain is not None, "give --chain (or --genesis)")
            require(not (args.entry or args.measurements or args.card_record or args.heartbeat_max_lifetime_s
                         or args.owner_heartbeat_lifetime_s), "--entry, --measurements, --card-record and the "
                    "lifetimes are for --genesis only")
        if args.command == "sign" and args.genesis:
            # the first ceremony: no chain at all, the offline root only (see GENESIS above)
            require(args.chain is None and args.expected_epoch is None, "--genesis takes no --chain and no --expected-epoch")
            require(args.key_fd is not None and args.key is None and args.module is None and args.pin_env is None
                    and args.opensc_conf is None, "--genesis is signed by the offline root: --key-fd and --offline-session only")
            require(not (args.old or args.new or args.state or args.emergency or args.locked_out), "--genesis takes no measurements step")
            provenance = keyfd.session(args.offline_session)
            sign([], root, None, read_json(args.proposal, membership.MAX_BYTES), args.signer, lambda: OfflineSigner(args.key_fd, provenance),
                 keyfd.tty_line, args.out, state_dir(args.state_dir), args.chain_out, pin_source="none (offline key)", offline=True,
                 genesis=True)
            return 0
        if args.command == "sign":
            require(args.chain is not None and args.expected_epoch is not None, "give --chain and --expected-epoch (or --genesis)")
        chain_doc = read_json(args.chain, membership.MAX_CHAIN_BYTES)
        current = verify_chain(chain_doc, root)
        if args.command == "verify":
            print("chain verified: %d envelopes, epoch %d, digest %s" % (len(chain_doc), current["epoch"], membership.digest(current)))
            return 0
        if args.command == "propose":
            require(bool(args.from_rollout) != bool(args.set_state), "give --from-rollout or --set-state, not both")
            if args.from_rollout:
                candidate = propose_from_rollout(current, read_json(args.from_rollout, membership.MAX_BYTES), _step(args))
            else:
                candidate = propose_states(current, _states(args.set_state), args.issued_at or utc_now())
            _write_new(args.out, json.dumps(candidate, indent=2, sort_keys=True).encode() + b"\n")
            print("\n".join(diff(current, candidate)))
            print("UNSIGNED epoch %d written to %s" % (candidate["epoch"], args.out))
            return 0
        candidate = read_json(args.proposal, membership.MAX_BYTES)
        if args.command == "diff":
            print("\n".join(diff(current, candidate)))
            return 0
        state = state_dir(args.state_dir)
        if args.key_fd is not None:                      # the offline root: no token, no PIN; the descriptor and the session
            require(args.key is None and args.module is None and args.pin_env is None and args.opensc_conf is None,
                    "--key-fd is not given with --key, --module, --pin-env or --opensc-conf")
            provenance = keyfd.session(args.offline_session)
            sign(chain_doc, root, args.expected_epoch, candidate, args.signer, lambda: OfflineSigner(args.key_fd, provenance),
                 keyfd.tty_line, args.out, state, args.chain_out, pin_source="none (offline key)", step=_step(args), offline=True)
            return 0
        require(args.key and args.module and args.offline_session is None, "give --key and --module (a token), or --key-fd and "
                "--offline-session (the offline root)")
        pin = _pin_reader(args.pin_env)                  # before any token is opened
        sign(chain_doc, root, args.expected_epoch, candidate, args.signer,
             lambda: token_signer(args.key, args.module, args.opensc_conf, pin, os.path.join(state, LATCH)),
             input, args.out, state, args.chain_out, pin_source="env (test)" if args.pin_env else "terminal", step=_step(args))
        return 0
    except (Refused, attest.Refused, OSError, ValueError) as error:
        print("regalia-manifest: refused: %s" % error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
