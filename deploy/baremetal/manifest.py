"""regalia-manifest: propose, compare, sign and verify membership manifests (#156).

The membership root is an ECDSA P-256 key generated on its own offline Nitrokey HSM 2 (the custody recorded
on #156, 2026-10-03). This is the tool the root's operator runs at a ceremony to sign the next manifest,
e.g. the two a kernel update needs (approve, then retire; KERNEL-UPDATE.md). It adds no cryptography and no
rule of its own: every rule is membership.py's, run BEFORE a signature exists and again on the finished
envelope, so nothing a node would refuse is ever signed.

    python3 -Es -m deploy.baremetal.manifest verify  --chain CHAIN.json --root-key ROOT
    python3 -Es -m deploy.baremetal.manifest propose --chain CHAIN.json --root-key ROOT (--from-rollout R.json | --set-state NODE=STATE ...)
                                                     [--issued-at YYYY-MM-DDTHH:MM:SSZ] --out PROPOSAL.json
                                                     [--old OLD.json --new NEW.json [--state NODE=STATE.json]...]
    python3 -Es -m deploy.baremetal.manifest diff    --chain CHAIN.json --root-key ROOT --proposal PROPOSAL.json
    python3 -Es -m deploy.baremetal.manifest sign    --chain CHAIN.json --root-key ROOT --expected-epoch N --proposal PROPOSAL.json
                                                     --signer root|revocation --key 'pkcs11:serial=…;token=…;id=%01;type=private'
                                                     --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so [--opensc-conf FILE]
                                                     [--pin-env NAME] --state-dir DIR --out ENVELOPE.json [--chain-out NEXT.json]
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
     type=private and nothing else (p11uri.parse, the UKI build's rule);
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

A key in a file is not a signing backend here: the root signs only on its token."""
import argparse
import datetime
import getpass
import json
import os
import re
import sys
import time

from deploy.baremetal import attest, measurements, membership, p11uri, rollout
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


def check_signer_key(current, root, signer_role, public):
    """The token's key may sign as `signer_role`: a pinned root key, or a revocation key `current` names."""
    if signer_role == "root":
        algs = [alg for alg, key in membership.root_entries(root) if key == public]
        require(algs, "the token's key %s… is not the pinned root" % public[:16])
        require(algs[0] == "ecdsa-p256", "the pinned entry for the token's key is not ecdsa-p256")
    else:
        require(membership.revocation_alg(current, public) == "ecdsa-p256",
                "the token's key %s… is not an ecdsa-p256 revocation key of epoch %d" % (public[:16], current["epoch"]))


def sign(chain, root, expected_epoch, candidate, signer_role, open_signer, confirm, out, state, chain_out=None, say=print,
         pin_source="terminal", step=None):
    """Steps 1 to 7 of the module's docstring. `open_signer()` gives the token's signer (step 4's opening);
    `confirm(prompt)` returns what the operator typed. Returns the envelope written."""
    require(signer_role in ("root", "revocation"), "--signer must be root or revocation")
    current = verify_chain(chain, root)                                                        # 1
    require(current["epoch"] == expected_epoch, "the chain ends at epoch %d, not the %d expected: fetch the fleet's chain"
            % (current["epoch"], expected_epoch))
    membership.validate(candidate)                                                             # 2
    require(candidate["schema"] == membership.SCHEMA_V3, "the token's key is ecdsa-p256, which signs only schema %s"
            % membership.SCHEMA_V3)
    membership.transition(current, candidate, signer_role)
    require(candidate["epoch"] == current["epoch"] + 1, "the proposal is epoch %d, already in the chain" % candidate["epoch"])
    judged = measurement_step(current, candidate, step)                                         # 2a
    for path in (out,) + ((chain_out,) if chain_out else ()):
        require(not os.path.lexists(path), "%s exists: nothing is overwritten" % path)
    signer = open_signer()                                                                     # 3, 4
    public = signer.public()
    check_signer_key(current, root, signer_role, public)
    digest = membership.digest(candidate)                                                      # 5
    for line in diff(current, candidate):
        say("  " + line)
    say("signer %s, key %s…, token serial %s" % (signer_role, public[:16], signer.serial))
    say("epoch %d -> %d, manifest digest %s" % (current["epoch"], candidate["epoch"], digest))
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
        accepted = membership.accept(current, envelope, root)
        require(membership.digest(accepted) == digest, "the accepted manifest is not the one signed")
        verified = True
    except Exception as failure:          # noqa: BLE001 - recorded as the reason; raised again below
        reason, failed = str(failure) or type(failure).__name__, failure
    try:
        _append_record(state, {"epoch": candidate["epoch"], "digest": digest, "signer": signer_role, "key": public,
                               "token_serial": signer.serial, "token_label": signer.label, "pin_source": pin_source,
                               "verified": verified, "reason": reason, "at": int(time.time())})
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
    c = sub.add_parser("propose", help="write the UNSIGNED next manifest")
    chain(c)
    c.add_argument("--from-rollout", metavar="R.json", help="the output of `rollout propose --json`")
    c.add_argument("--set-state", action="append", default=[], metavar="NODE=STATE", help="change a node's state; repeat")
    c.add_argument("--issued-at", metavar="YYYY-MM-DDTHH:MM:SSZ")
    c.add_argument("--out", required=True)
    step_args(c, acknowledge=False)
    c = sub.add_parser("diff", help="the proposal against the chain's last manifest, field by field")
    chain(c)
    c.add_argument("--proposal", required=True)
    c = sub.add_parser("sign", help="sign the proposal on the token (see the steps above)")
    chain(c)
    c.add_argument("--expected-epoch", required=True, type=int, help="the epoch the fleet is at; the chain must end there")
    c.add_argument("--proposal", required=True)
    c.add_argument("--signer", required=True, choices=("root", "revocation"))
    c.add_argument("--key", required=True, metavar="PKCS11-URI")
    c.add_argument("--module", required=True, help="the PKCS#11 module (OpenSC's opensc-pkcs11.so)")
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
