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

CUSTODY (owner, 2026-10-05, recorded on #242 by regalia-kms-24). Two independent paths, so neither strands a node:
  * day to day, the developer cards' envelope (.yk.gpg, rc#120/#130), as above;
  * BREAK-GLASS, a SOPS file per node encrypted to an age key that is never held whole: it is rebuilt k-of-n from the
    ADR-0002 D28 platform Shamir share set (`ssss-combine ... 2> key`, never typed), as the ceremony opens its own vault
    (regalia-ceremony qubes/recovery/RECOVERY-TECHNICAL.md), and it replaces the per-node .bg.age envelope
    (regalia-ceremony#111). A binary SOPS file (`--input-type binary`) holds "<64 hex>\n" and `sops decrypt` gives
    it back byte for byte, read_value's form; a YAML value given by `--extract` comes WITHOUT the newline (measured with
    the ceremony's sops 3.13.1), which read_value refuses: one binary file per node, not a map. Nothing on a server
    holds either the value or that key.
  * THE DRILL (the ceremony rehearsal): rebuild the key, decrypt one node's value, check it against the root-signed
    record WITHOUT a TPM (`python3 -Es -m deploy.baremetal.ownerauth check`, main), destroy the rebuilt key file.

THE CHANNEL. tpm2-tools takes an authorization as `-P <auth>`; on argv it would be in /proc for every local user.
Every owner call here passes `-P file:/dev/fd/N`, N an anonymous memory file (memfd) holding "hex:<64 hex>"
(owner_call): never on a disk nor on a command line; while the call runs it is readable through /proc/<pid>/fd by
the same user or root (ptrace rules permitting), an accepted residual on a node where these tools run as root. A memfd, not a pipe: tpm2-tools seeks
the file it reads an authorization from, and a pipe cannot seek. The hex form, because tpm2-tools cuts a raw value at
its first 0x00 byte (#242, both probed on swtpm). `-C o` appears in
this module only, and a test holds every other module to that (tests/test_baremetal_ownerauth.py).

THE POSTURE (posture): TPM_PT_PERMANENT's ownerAuthSet and lockoutAuthSet, read with tpm2_getcap, never by trying
an authorization. A production (v4) enrolment requires both set (#242; the lockout authorization is #57's
tpm-lockout.sh).

CURRENT LIMITATIONS (#242):
  * ON THE TPM BUS (#414, measured on swtpm with tpm2-tools 5.7): an owner call's `-P` is authorized in an HMAC
    session that tpm2-tools opens itself, so the value is never sent, only HMACs keyed by it; setting it (changeauth's
    new value, a parameter) goes in a session salted to the node's EK with parameter encryption (salted_session), the
    EK's Name checked against enrolment's first; the proof (holds) is an owner createprimary, which sends no value.
    That an owner call's -P goes in an HMAC session is tpm2-tools' own choice, measured for MEASURED_TOOLS only; the
    tools refuse another version (require_measured_tools), and CI's wire test measures the version it runs.
    The EK's Name is the one `enrol init` recorded, which the root's challenge/activate bound (its credential is made
    to that EK). Residual: the automatic HMAC sessions are unsalted and unbound. They expose nothing of a 256-bit random value, but
    they do not encrypt PARAMETERS: an owner call's own parameters (an NV index's attributes and policy, a record's
    epoch and digest) cross in clear, none of them secret;
  * the value is a Python object (bytes, and the 64-hex text it was read from): it cannot be zeroed, and lives in the
    process's memory until it exits, as the offline keys' do;
  * the break-glass path is decrypted by the operator (today's ceremony writes .bg.age, for age; the decided SOPS file
    replaces it with rc#111), and the value reaches these tools on standard input in the same form; nothing here reads
    any envelope file or checks its SHA-256 (the record's yk_sha256/bg_sha256 are for the ceremony's own proof). The
    record's field for the break-glass envelope follows rc#111 when it changes: bg_sha256 until then;
  * set() takes the owner authorization from EMPTY only. A TPM whose owner authorization is already set is refused,
    with the way on (its value is this envelope's: nothing to do, `check` proves it; otherwise the TPM's owner
    hierarchy must be cleared by its owner first). Changing a set value to a new one (a rotation) is not built;
  * a child process (enrolment's steps as regalia-sync) takes the value from its root parent through an inherited
    memfd (child_fd, --ownerauth-fd) and does not re-verify the record: the parent verified it. While that child runs,
    the OWNER authorization is held by a process of uid regalia-sync, the network-facing sync daemon's user: enrolment
    refuses to hand it over while any other process of that uid exists (enrol._no_sync_process), and moving the owner
    calls into the root parent is #419;
  * enrol commit reads the value (standard input) before the operator types the root's fingerprint (at the terminal),
    and checks it against the record (confirm) only once that fingerprint has confirmed the root key;
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
    return confirm(read_value(stream), envelope, root, node_id, entry)


def confirm(auth, envelope, root, node_id, entry=None):
    """`auth`, read before its record could be judged (a command that must read the value before the operator types
    the root's fingerprint), refused unless the record verified under the pinned root names it for `node_id`."""
    entry = entry or verify(envelope, root, node_id)
    require(hmac.compare_digest(auth.check(node_id), entry["check"]),
            "the owner authorization given is not %s's (its check value is not the record's): the wrong envelope, or "
            "another node's" % node_id)
    return auth


def read_fd(fd):
    """The value from the descriptor `fd` (read_value's form): the memfd a root parent hands its child process
    (child_fd, enrolment's steps as regalia-sync). Refused if `fd` is a terminal. The descriptor is closed once read."""
    require(isinstance(fd, int) and fd >= 0, "--ownerauth-fd takes a descriptor number")
    try:
        require(not os.isatty(fd), "descriptor %d is a terminal: the owner authorization comes from its envelope (e.g. "
                "on standard input), never typed" % fd)
        with os.fdopen(fd, "rb", closefd=True) as stream:
            return read_value(stream)
    except OSError as error:
        raise Refused("descriptor %d cannot be read: %s" % (fd, error.strerror)) from None


def child_fd(auth):
    """A sealed memfd holding the value in read_value's form, for ONE child process given `--ownerauth-fd N` (enrolment's
    steps run as regalia-sync): close-on-exec, so only the child the caller names in pass_fds inherits it (subprocess
    makes it inheritable there alone, regalia-kms-d9); the caller closes it after."""
    import fcntl
    fd = os.memfd_create("regalia-ownerauth", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, auth._raw.hex().encode() + b"\n")
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
    except BaseException:
        os.close(fd)
        raise
    return fd


def add_arguments(parser):
    """--ownerauth RECORD, the same on every tool that makes owner-authorized TPM calls (#242 C2): the value comes on
    STANDARD INPUT, `gpg --decrypt ownerauth-<node>.yk.gpg | sudo <tool> ... --ownerauth ownerauth.record.json`. Not
    on another descriptor: sudo closes every descriptor above 2 (sudoers' closefrom). What the operator types (a
    fingerprint, a confirmation phrase) is then read from the controlling terminal (console)."""
    parser.add_argument("--ownerauth", metavar="RECORD.json", help="the ceremony's ownerauth.record.json: the TPM's owner "
                        "authorization is set, and this node's comes from its envelope on standard input "
                        "(gpg --decrypt ownerauth-<node>.yk.gpg | ...), never typed and never an argument (#242)")


def read_arguments(args, stream=None):
    """(Auth, record) from --ownerauth and standard input, read but NOT yet judged (confirm), or None without
    --ownerauth: for a command that must read the value before the operator types (enrol commit)."""
    if getattr(args, "ownerauth", None) is None:
        return None
    import sys
    stream = stream or sys.stdin.buffer
    with open(args.ownerauth, "rb") as f:
        envelope = membership.load(f.read(membership.MAX_BYTES + 1), membership.MAX_BYTES)
    require(not (hasattr(stream, "isatty") and stream.isatty()), "standard input is a terminal: with --ownerauth it carries "
            "the decrypted envelope (gpg --decrypt ownerauth-<node>.yk.gpg | ...), which is never typed")
    return read_value(stream), envelope


def from_arguments(args, root, node_id, stream=None):
    """The node's Auth from --ownerauth and standard input, judged against the record under the pinned root; None
    without --ownerauth (the owner authorization is empty)."""
    pending = read_arguments(args, stream)
    return None if pending is None else confirm(pending[0], pending[1], root, node_id)


def console(prompt, tty="/dev/tty"):
    """A line typed at the controlling terminal, for a command whose standard input carries the owner authorization:
    what it asks (a fingerprint, a phrase) is still typed by a person, never piped. None at end of input."""
    try:
        fd = os.open(tty, os.O_RDWR | os.O_NOCTTY)
    except OSError as error:
        raise Refused("there is no terminal to type at (%s): this is typed at the host's console. Nothing was written"
                      % error.strerror) from None
    try:
        require(os.isatty(fd), "%s is not a terminal: this is typed at the host's console" % tty)
        os.write(fd, prompt.encode())
        with os.fdopen(os.dup(fd), "r", encoding="utf-8", errors="replace") as t:   # read-only: a tty does not seek
            line = t.readline(4096)                        # one line, bounded
    finally:
        os.close(fd)
    return line.rstrip("\n") if line else None


SRK = "0x81000001"                     # systemd's storage root key (systemd-tpm2-setup), persisted at boot


def srk_persistent(tcti=None, run=subprocess.run):
    """Whether systemd's SRK is persistent: its TPM credentials (systemd-creds, the unlock contribution's seal) use it,
    and once the owner authorization is set systemd can no longer create it (it does not hold the authorization)."""
    r = run(["tpm2_getcap", "handles-persistent"], capture_output=True, env=_env(tcti))
    require(r.returncode == 0, "cannot list the TPM's persistent handles")
    text = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else r.stdout
    return SRK in {h.lower() for h in re.findall(r"0x[0-9a-fA-F]{8}", text)}


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
    measured_once()
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


EK_HANDLE = "0x81010001"               # the node's EK, persistent since `enrol init` (attest.EK_HANDLE)
# tpm2-tools versions MEASURED to authorize an owner call's -P in an HMAC session they open themselves, so the value
# never crosses the TPM bus (#414; tests/test_baremetal_ownerauth.py OnSwtpm's wire test). A version that sent -P as
# a password session would put it back on the bus in clear, every test still green: the tools refuse another
# (require_measured_tools, regalia-kms-d9).
# 5.7: measured on the dev qube (Debian 13, as the production image); 5.6: CI's runner, by OnTheWire in job
# 111570576171 ("tpm2-tools 5.6: the owner authorization never crossed the bus (108 commands read)").
MEASURED_TOOLS = ("5.6", "5.7")


def tools_version(run=subprocess.run):
    """tpm2-tools' version, as `tpm2_createprimary --version` reports it (version="5.7")."""
    r = run(["tpm2_createprimary", "--version"], capture_output=True)
    text = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
    found = re.search(r'version="([^"]+)"', text)
    require(r.returncode == 0 and found is not None, "cannot tell tpm2-tools' version (tpm2_createprimary --version)")
    return found.group(1)


_tools_checked = False                 # once per process (measured_once): set by a test that measures or fakes the tools


def measured_once():
    """The channel's own gate (regalia-kms-d9 on #423): every owner call with a value, its set and its proof go through
    owner_call, set_owner or holds, which refuse unless tpm2-tools is measured (require_measured_tools), once per process.
    So a new owner-call tool cannot forget it, and enrolment's regalia-sync step checks for itself."""
    global _tools_checked
    if not _tools_checked:
        require_measured_tools(subprocess.run)
        _tools_checked = True


def require_measured_tools(run=subprocess.run):
    """Refused unless tpm2-tools is a version measured to keep the owner authorization off the TPM bus (MEASURED_TOOLS):
    the channel runs it before its first owner call with a value (measured_once); the tools run it up front as well."""
    version = tools_version(run)
    require(version in MEASURED_TOOLS, "tpm2-tools %s is not a version measured to keep the owner authorization off the "
            "TPM bus (%s): it might send it in clear. Measure it (tests/test_baremetal_ownerauth.py, OnSwtpm's wire test, on "
            "this version) and add it to ownerauth.MEASURED_TOOLS (#414). Nothing was done"
            % (version, ", ".join(MEASURED_TOOLS)))


@contextlib.contextmanager
def salted_session(ek_name, tcti=None, run=subprocess.run, handle=EK_HANDLE):
    """An HMAC session salted to this node's EK, with parameter encryption both ways (#414): for the one command that
    sends an owner authorization as a PARAMETER, changeauth's new value, which otherwise crosses the TPM bus in clear
    (measured on swtpm). The EK at `handle` is first required to be the one enrolment recorded (`ek_name`, the Name's
    hex), so a key substituted on the bus is refused, not only passive sniffing. Yields the session's context file,
    flushed after."""
    import tempfile
    require(isinstance(ek_name, str) and re.fullmatch(r"[0-9a-f]{68}", ek_name) is not None,
            "the EK's Name to salt with is not 68 hex (enrolment's record)")
    with tempfile.TemporaryDirectory(prefix="ownerauth-") as d:
        r = run(["tpm2_readpublic", "-c", handle, "-n", d + "/ek.name"], capture_output=True, env=_env(tcti))
        require(r.returncode == 0, "the TPM holds no EK at %s: `enrol init` makes it, and it salts this session. Nothing was "
                "sent" % handle)
        with open(d + "/ek.name", "rb") as f:
            held = f.read(35).hex()                        # a Name is 34 bytes (SHA-256); a longer file fails the match
        require(held == ek_name, "the EK at %s is not the one enrolment recorded (%s..., not %s...): no session is salted to "
                "it, and nothing was sent" % (handle, held[:16], ek_name[:16]))
        ctx = d + "/session.ctx"
        r = run(["tpm2_startauthsession", "--hmac-session", "-c", handle, "-S", ctx], capture_output=True, env=_env(tcti))
        require(r.returncode == 0, "the TPM did not start a session salted to its EK: %s. Nothing was sent" % _tail(r.stderr))
        try:
            r = run(["tpm2_sessionconfig", ctx, "--enable-encrypt", "--enable-decrypt"], capture_output=True, env=_env(tcti))
            require(r.returncode == 0, "the salted session's parameter encryption could not be set: %s. Nothing was sent"
                    % _tail(r.stderr))
            yield ctx
        finally:
            run(["tpm2_flushcontext", ctx], capture_output=True, env=_env(tcti))


def set_owner(auth, ek_name, tcti=None, run=subprocess.run):
    """The TPM's owner authorization set to `auth`, from EMPTY only: one already set is refused, never overwritten
    and never guessed at (its way on is in the message). The new value travels encrypted, in a session salted to
    the node's EK (salted_session, #414). Then proven by an owner-authorized call with it (holds)."""
    require(isinstance(auth, Auth), "the owner authorization is not an ownerauth.Auth")
    measured_once()
    require(srk_persistent(tcti, run), "systemd's storage root key (%s) is not persistent: systemd-tpm2-setup makes it at "
            "boot, and once the owner authorization is set systemd cannot. Boot the node once with systemd-tpm2-setup "
            "enabled (or run /usr/lib/systemd/systemd-tpm2-setup), then this again. Nothing was changed" % SRK)
    require(not posture(tcti, run)["owner"],
            "the TPM's owner authorization is already set. If it is this envelope's value, there is nothing to do (`enrol "
            "ownerauth --check` proves it, in one try). If not, this TPM was provisioned by someone else: its owner "
            "hierarchy must be cleared by whoever holds its lockout authorization (tpm2_clear) or from the firmware's TPM "
            "menu, and this run again. Nothing was changed")
    with salted_session(ek_name, tcti, run) as session:
        fd = _value_fd(auth)
        try:
            # -p session: the (empty) old authorization through the salted session; the new value its encrypted parameter
            done = run(["tpm2_changeauth", "-c", "o", "-p", "session:" + session, "file:/dev/fd/%d" % fd],
                       capture_output=True, env=_env(tcti), pass_fds=(fd,))
        finally:
            os.close(fd)
    require(done.returncode == 0, "the TPM did not set the owner authorization: %s. It should be unchanged; `enrol "
            "ownerauth --check` with this envelope tells" % _tail(done.stderr))
    try:
        proven, why = holds(auth, tcti, run), "it does not answer to it"
    except Refused as refused:
        proven, why = False, str(refused)
    # no-stranding: the TPM said it changed the authorization, and the change cannot be proven
    require(proven, "the TPM accepted the new owner authorization but the value just set could not be proven (%s): the "
            "owner authorization may now be UNKNOWN. Re-run `enrol ownerauth --check` with this envelope; if that fails, "
            "clear the owner hierarchy with the lockout authorization (tpm2_clear -c l, #57) or from the firmware's TPM "
            "menu, and set it again" % why)


AUTH_FAILURE = re.compile(r"\(0x0*9(?:a2|8e)\)", re.IGNORECASE)   # TPM_RC_BAD_AUTH / TPM_RC_AUTH_FAIL, session 1


def _tail(stderr):
    text = stderr.decode("utf-8", "replace") if isinstance(stderr, bytes) else (stderr or "")
    return text.strip()[-300:] or "(no message)"


def holds(auth, tcti=None, run=subprocess.run):
    """Whether the TPM's owner authorization is `auth`: ONE owner-authorized call that changes nothing, a primary key
    under the owner hierarchy created and flushed at once (regalia-kms-24 on #414). tpm2-tools authorizes it in an
    HMAC session, so the value is never sent, only HMACs keyed by it (measured on swtpm); a changeauth to the same
    value would send it as a parameter. False ONLY when the TPM answers with an authorization failure (0x9a2, or
    0x98e); anything else (a busy TPM, a TCTI error, a missing tool) is a refusal, never "not this value" (d9)."""
    import tempfile
    require(isinstance(auth, Auth), "the owner authorization is not an ownerauth.Auth")
    with tempfile.TemporaryDirectory(prefix="ownerauth-") as d:
        with owner_call(auth) as (owner, kw):
            done = run(["tpm2_createprimary", *owner, "-G", "ecc256", "-c", d + "/proof.ctx"], capture_output=True,
                       env=_env(tcti), **kw)
        # The proof's transient key: through the kernel's resource manager (/dev/tpmrm0, production) it is flushed when
        # the tool exits. Only a private simulator has no manager and keeps it (as attest.node_init says): there every
        # transient object is flushed, and a flush that fails is said (a slot stays taken until the TPM restarts).
        # (flushcontext takes no saved OBJECT context, only a session's or a handle.)
        if done.returncode == 0 and (tcti or os.environ.get("TPM2TOOLS_TCTI", "")).startswith(("swtpm", "mssim")):
            flushed = run(["tpm2_flushcontext", "-t"], capture_output=True, env=_env(tcti))
            require(flushed.returncode == 0, "the owner authorization answered, but the proof's transient key could not be "
                    "flushed (%s): a TPM object slot stays taken until the TPM restarts" % _tail(flushed.stderr))
    if done.returncode == 0:
        return True
    require(AUTH_FAILURE.search(_tail(done.stderr)) is not None,
            "could not ask the TPM whether its owner authorization is this value: %s" % _tail(done.stderr))
    return False


def main(argv=None, stdin=None):
    """`python3 -Es -m deploy.baremetal.ownerauth check --node-id X --root-key ROOT --record ownerauth.record.json`, the
    value on standard input: whether it is node X's, by the check value of the record verified under the pinned root.
    Touches no TPM and writes nothing: the break-glass drill's last step (the module text), and a way to tell which
    node a decrypted value is for before going to that node."""
    import argparse
    import sys
    parser = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.ownerauth",
                                     description="the TPM owner authorization, without a TPM (#242)")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check", help="is the value on standard input this node's? (the record's check value; no TPM)")
    c.add_argument("--node-id", required=True)
    c.add_argument("--root-key", required=True, help="the membership root's public key, 64 hex: the record is verified under it")
    c.add_argument("--record", required=True, help="the ceremony's ownerauth.record.json")
    args = parser.parse_args(argv)
    stream = stdin or sys.stdin.buffer
    try:
        require(not (hasattr(stream, "isatty") and stream.isatty()), "standard input is a terminal: it carries the decrypted "
                "value (sops decrypt ... | or gpg --decrypt ... |), which is never typed")
        with open(args.record, "rb") as f:
            envelope = membership.load(f.read(membership.MAX_BYTES + 1), membership.MAX_BYTES)
        from_envelope(stream, envelope, args.root_key, args.node_id)
    except (OSError, Refused) as failure:
        print("REFUSED: %s" % failure, file=sys.stderr)
        return 2
    print("the value is %s's: it matches the check value of the record signed by the pinned root (no TPM touched, "
          "nothing written)" % args.node_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
