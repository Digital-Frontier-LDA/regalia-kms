#!/usr/bin/env python3
"""The TPM owner authorization (#242 step C): set from the ceremony's envelope, kept off the host, and given to every
owner-authorized TPM call through ONE channel, never on a command line.

The card ceremony (regalia-ceremony#111 step 3, rc#120) makes, per node, a random 32-byte owner authValue and
encrypts it twice: `ownerauth-<node>.yk.gpg` (to the developer cards' decryption keys) and `ownerauth-<node>.bg.age`
(break-glass). Its signed record, `ownerauth.record.json`, names each envelope's SHA-256 and a CHECK value:

    {"record": {..., "nodes": {"<node>": {"yk_sha256", "bg_sha256", "check"}}, ...}, "signature": "<128 hex>"}

    signature = Ed25519 by the membership root over RECORD_DOMAIN + canonical(record)
    check     = HMAC-SHA256(key = the 32 raw bytes, CHECK_DOMAIN + node_id), lowercase hex

An operator decrypts the envelope with the owner's card (`gpg --decrypt ownerauth-a.yk.gpg | ...`): the value
comes on STANDARD INPUT as 64 lowercase hex and one newline (read_value), is checked against the record verified
under the node's PINNED root (verify, check) BEFORE the TPM is touched, and lives only in the process that uses it.

THE CHANNEL. tpm2-tools takes an authorization as `-P <auth>`; on argv it would be in /proc for every local user.
Every owner call here passes `-P file:/dev/fd/N`, N an anonymous memory file (memfd: never on a disk, reachable only
through the descriptor the call inherits) holding "hex:<64 hex>" (owner_call). A memfd, not a pipe: tpm2-tools seeks
the file it reads an authorization from, and a pipe cannot seek. The hex form, because tpm2-tools cuts a raw value at
its first 0x00 byte (#242, both probed on swtpm). `-C o` appears in
this module only, and a test holds every other module to that (tests/test_baremetal_ownerauth.py).

THE POSTURE (posture): TPM_PT_PERMANENT's ownerAuthSet and lockoutAuthSet, read with tpm2_getcap, never by trying
an authorization. A production (v4) enrolment requires both set (#242; the lockout authorization is #57's
tpm-lockout.sh).

CURRENT LIMITATIONS (#242):
  * the break-glass envelope (.bg.age) is decrypted by the operator with age, and the value reaches these tools on
    standard input in the same form; nothing here reads either envelope file or checks its SHA-256 (the record's
    yk_sha256/bg_sha256 are for the ceremony's own proof);
  * set() takes the owner authorization from EMPTY only. A TPM whose owner authorization is already set is refused,
    with the way on (its value is this envelope's: nothing to do, `check` proves it; otherwise the TPM's owner
    hierarchy must be cleared by its owner first). Changing a set value to a new one (a rotation) is not built;
  * systemd's TPM credentials (systemd-creds, the unlock contribution's seal) use the storage root key at 0x81000001,
    which systemd-tpm2-setup persists at boot; creating it later needs the owner authorization, which systemd does
    not have. Nothing here checks that the SRK is persistent before the owner authorization is set (#242 C2);
  * enrolment, re-anchoring, recount and seal-hsm-pin.sh do not yet take the value from the envelope (#242 C2): on a
    TPM whose owner authorization is set, their owner-authorized steps fail closed until then.
"""
import contextlib
import hashlib
import hmac
import os
import re
import subprocess

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.ownerauth-record/v1"
EVENT = "ownerauth"
RECORD_DOMAIN = b"regalia-ceremony-record/v1\x00"
CHECK_DOMAIN = b"regalia-ownerauth/v1\x00"
FIELDS = {
    "record": ("at", "event", "master_id", "nodes", "root_entry", "root_fingerprint", "schema", "session", "share_indices",
               "slip39_identifier", "tool", "verify_keys", "yk_recipients"),
    "node": ("bg_sha256", "check", "yk_sha256"),
    "root_entry": ("alg", "key"),
    "recipient": ("primary", "subkey"),
}
HEX64 = re.compile(r"[0-9a-f]{64}")
OPENPGP_FPR = re.compile(r"[0-9A-F]{40}")
NODE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
OWNER = ("-C", "o")                    # the one place this argument pair is written (see the module text)


class Auth:
    """A node's owner authValue, 32 bytes, from its envelope. Never printed: repr and str say only that it is one."""

    def __init__(self, raw):
        require(isinstance(raw, bytes) and len(raw) == 32, "an owner authorization is 32 bytes")
        self._raw = raw

    def __repr__(self):
        return "<owner authorization>"

    __str__ = __repr__

    def check(self, node_id):
        """The record's check value for `node_id` (CHECK_DOMAIN): HMAC-SHA256 keyed by the value."""
        return hmac.new(self._raw, CHECK_DOMAIN + node_id.encode(), hashlib.sha256).hexdigest()

    def tool_form(self):
        """What tpm2-tools reads through the channel: "hex:<64 lowercase hex>" (a raw value stops at a 0x00 byte)."""
        return b"hex:" + self._raw.hex().encode()


def read_value(stream):
    """The value as `gpg --decrypt` (or `age --decrypt`) prints the envelope: exactly 64 lowercase hex and "\\n"."""
    raw = stream.read(66)
    if isinstance(raw, str):
        raw = raw.encode()
    require(len(raw) == 65 and raw[64:] == b"\n" and HEX64.fullmatch(raw[:64].decode("ascii", "replace")) is not None,
            "the owner authorization on standard input is not 64 lowercase hex and a newline: give it the decrypted "
            "envelope (gpg --decrypt ownerauth-<node>.yk.gpg | ...), nothing else")
    return Auth(bytes.fromhex(raw[:64].decode()))


def _ascii(value):
    """Every string ASCII: the producer signs json.dumps(ensure_ascii=False), which is membership.canonical's bytes
    exactly when nothing in it is non-ASCII."""
    if isinstance(value, str):
        require(value.isascii(), "the owner-authorization record holds a non-ASCII string")
    elif isinstance(value, dict):
        for k, v in value.items():
            _ascii(k)
            _ascii(v)
    elif isinstance(value, list):
        for v in value:
            _ascii(v)


def verify(envelope, root, node_id):
    """The record entry of `node_id` ({yk_sha256, bg_sha256, check}) from ownerauth.record.json, verified under the
    PINNED root (64 hex, the raw Ed25519 root key) before any field is used: exact fields at every level, the
    record's root the pin, its signature the pin's over RECORD_DOMAIN + canonical(record)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    require(isinstance(node_id, str) and NODE_ID.fullmatch(node_id) is not None, "%r is not a node id" % (node_id,))
    membership.hex_field(root, 64, "the pinned root")
    require(isinstance(envelope, dict), "the owner-authorization record is not an object")
    membership.exact(envelope, ("record", "signature"), "the owner-authorization record")
    _ascii(envelope)
    record, signature = envelope["record"], envelope["signature"]
    require(isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{128}", signature) is not None,
            "the owner-authorization record's signature is not 128 hex")
    membership.exact(record, FIELDS["record"], "the owner-authorization record")
    membership.exact(record["root_entry"], FIELDS["root_entry"], "root_entry")
    require(record["root_entry"] == {"alg": "ed25519", "key": root},
            "the owner-authorization record names another root than the pinned one: it is not this network's ceremony")
    require(record["root_fingerprint"] == hashlib.sha256(bytes.fromhex(root)).hexdigest(),
            "the owner-authorization record's root_fingerprint is not the root's")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(root)).verify(bytes.fromhex(signature), RECORD_DOMAIN + membership.canonical(record))
    except (InvalidSignature, ValueError):
        raise Refused("the owner-authorization record's signature is not the pinned root's") from None
    # signed: from here, what the ceremony recorded
    require(record["schema"] == SCHEMA and record["event"] == EVENT, "the record is not a %s (%s)" % (SCHEMA, EVENT))
    require(isinstance(record["nodes"], dict) and record["nodes"], "the owner-authorization record names no node")
    require(node_id in record["nodes"], "the owner-authorization record has no entry for %s: its envelope was made for "
            "other nodes (%s)" % (node_id, ", ".join(sorted(record["nodes"]))))
    entry = record["nodes"][node_id]
    membership.exact(entry, FIELDS["node"], "the record's entry for %s" % node_id)
    for field in FIELDS["node"]:
        membership.hex_field(entry[field], 64, "%s.%s" % (node_id, field))
    # the YubiKey envelope's recipients: the two developer cards' decryption subkeys (D30.3), and the ceremony's proof
    # that each card opened its own (verify_keys: {subkey: SHA-256}); not used here, held to their form
    recipients = record["yk_recipients"]
    require(isinstance(recipients, list) and len(recipients) == 2, "yk_recipients is not the two developer cards (D30.3)")
    for i, recipient in enumerate(recipients):
        membership.exact(recipient, FIELDS["recipient"], "yk_recipients[%d]" % i)
        for f in FIELDS["recipient"]:
            require(isinstance(recipient[f], str) and OPENPGP_FPR.fullmatch(recipient[f]) is not None, "yk_recipients[%d].%s is not 40 HEX" % (i, f))
    subkeys = [r["subkey"] for r in recipients]
    require(len(set(subkeys)) == 2 and len({r["primary"] for r in recipients}) == 2, "yk_recipients names one card twice")
    require(isinstance(record["verify_keys"], dict) and sorted(record["verify_keys"]) == sorted(subkeys),
            "verify_keys does not name exactly the recipients' subkeys")
    for subkey, sha in record["verify_keys"].items():
        membership.hex_field(sha, 64, "verify_keys[%s]" % subkey)
    return entry


def from_envelope(stream, envelope, root, node_id):
    """The node's Auth: the value on `stream` (read_value), refused unless the record verified under the pinned root
    names it for `node_id` (its check value). Nothing touches the TPM before this returns."""
    entry = verify(envelope, root, node_id)
    auth = read_value(stream)
    require(hmac.compare_digest(auth.check(node_id), entry["check"]),
            "the owner authorization given is not %s's (its check value is not the record's): the wrong envelope, or "
            "another node's" % node_id)
    return auth


def _value_fd(auth):
    """A new memfd holding the value (Auth.tool_form), at offset 0 and sealed against change: for one call."""
    import fcntl
    fd = os.memfd_create("regalia-ownerauth", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, auth.tool_form())
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    except BaseException:
        os.close(fd)
        raise
    return fd


@contextlib.contextmanager
def owner_call(auth):
    """(argv, kw) for ONE owner-authorized tpm2-tools call: argv `-C o` and, with an owner authorization set, `-P
    file:/dev/fd/N`, kw {"pass_fds": (N,)}, N a memfd that holds the value (_value_fd) and is closed after the call.
    `auth` None: the owner authorization is empty (a lab TPM), and none is passed."""
    if auth is None:
        yield list(OWNER), {}
        return
    require(isinstance(auth, Auth), "the owner authorization is not an ownerauth.Auth")
    fd = _value_fd(auth)
    try:
        yield list(OWNER) + ["-P", "file:/dev/fd/%d" % fd], {"pass_fds": (fd,)}
    finally:
        os.close(fd)


def resolve(auth):
    """`auth` (an Auth, None, or a function returning one of them), resolved: what an owner call is made with."""
    return auth() if callable(auth) else auth


def _env(tcti):
    return dict(os.environ, TPM2TOOLS_TCTI=tcti) if tcti else None


def posture(tcti=None, run=subprocess.run):
    """{"owner": bool, "lockout": bool}: TPM_PT_PERMANENT's ownerAuthSet and lockoutAuthSet, as the TPM reports them."""
    r = run(["tpm2_getcap", "properties-variable"], capture_output=True, env=_env(tcti))
    require(r.returncode == 0, "cannot read the TPM's properties (tpm2_getcap properties-variable)")
    text = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else r.stdout
    found = {}
    for name, key in (("ownerAuthSet", "owner"), ("lockoutAuthSet", "lockout")):
        m = re.search(r"(?m)^\s*%s:\s*([01])\s*$" % name, text)
        require(m is not None, "the TPM's properties do not say %s" % name)
        found[key] = m.group(1) == "1"
    return found


def require_production(tcti=None, run=subprocess.run):
    """A production (v4) node's TPM: its owner and lockout authorizations both SET. Refused, naming what to do, else."""
    held = posture(tcti, run)
    require(held["owner"], "the TPM's owner authorization is empty: a v4 node's is set from its envelope first "
            "(gpg --decrypt ownerauth-<node>.yk.gpg | enrol ownerauth ...), and kept off the host (#242)")
    require(held["lockout"], "the TPM's lockout authorization is empty: set it first (deploy/baremetal/tpm-lockout.sh --set, #57)")


def set_owner(auth, tcti=None, run=subprocess.run):
    """The TPM's owner authorization set to `auth`, from EMPTY only: one already set is refused, never overwritten
    and never guessed at (its way on is in the message). Then proven by an owner-authorized call with it."""
    require(isinstance(auth, Auth), "the owner authorization is not an ownerauth.Auth")
    require(not posture(tcti, run)["owner"],
            "the TPM's owner authorization is already set. If it is this envelope's value, there is nothing to do (`enrol "
            "ownerauth --check` proves it, in one try). If not, this TPM was provisioned by someone else: its owner "
            "hierarchy must be cleared by whoever holds its lockout authorization (tpm2_clear) or from the firmware's TPM "
            "menu, and this run again. Nothing was changed")
    fd = _value_fd(auth)
    try:
        done = run(["tpm2_changeauth", "-c", "o", "file:/dev/fd/%d" % fd], capture_output=True, env=_env(tcti), pass_fds=(fd,))
    finally:
        os.close(fd)
    require(done.returncode == 0, "the TPM did not set the owner authorization")
    require(holds(auth, tcti, run), "the TPM's owner authorization does not answer to the value just set: nothing more is done")


def holds(auth, tcti=None, run=subprocess.run):
    """Whether the TPM's owner authorization is `auth`: ONE owner-authorized call that changes nothing (changeauth to
    the same value). False when it is not (a hierarchy authorization is not subject to dictionary-attack lockout)."""
    require(isinstance(auth, Auth), "the owner authorization is not an ownerauth.Auth")
    fds = []
    try:
        for _ in range(2):
            fds.append(_value_fd(auth))
        done = run(["tpm2_changeauth", "-c", "o", "-p", "file:/dev/fd/%d" % fds[0], "file:/dev/fd/%d" % fds[1]],
                   capture_output=True, env=_env(tcti), pass_fds=tuple(fds))
    finally:
        for fd in fds:
            os.close(fd)
    return done.returncode == 0
