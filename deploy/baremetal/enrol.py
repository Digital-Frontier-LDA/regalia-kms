"""regalia-node enrol, phase 1: `init` makes this host's keys, on this host, and prints what the
manifest ceremony needs to name it (#190).

    sudo python3 -Es -m deploy.baremetal.enrol init --node-id a

WHAT IT MAKES, each on the host and never imported (ADR-0002 D5's rule, applied to node keys):
  * the EK and a restricted signing AK, persistent in the TPM (attest.node_init, 0x81010001/0x81010002);
  * the WG-SERVICE key, /etc/regalia/wg-service.key, root 0600;
  * the WG-BOOT key, kept root 0600 in the enrolment directory until `commit` seals it to this TPM.
The local unlock contribution is NOT made here: `commit` makes it and seals it in one step, so it is never
on disk in the clear between the two phases. It then stays root 0600 in the enrolment directory (local.bin)
only until the peers' LUKS paths are enrolled, which need it; its sealed copy opens only in the initrd.

PHASE 2, `commit` (root, at the console): the manifest chain checked under the root fingerprint typed by
hand; the boot image checked (uki.verify on the image, its signed record, both PCR keys and the Secure Boot
certificate, and its PCR 11 among the sets the measurements accept for this node); the configuration; the
anchor, the store and the heartbeat counter as regalia-sync; then regalia.unlock-local and
regalia.wg-boot-key sealed to this TPM (PCR 7, and PCR 11 through the initrd key) onto the ESP's
loader/credentials, never replacing a file, with their SHA-256 and size journalled for PCR 12
(espcreds.record). The WG-BOOT private key file is removed once its sealed copy is published.

WHAT IT PRINTS: the identity bundle (bundle.json in the enrolment directory), public values only: the EK
and AK public areas and Names, the EK certificate when the TPM carries one (checked here to certify THIS
EK; the ceremony verifies it to the manufacturer's CA), both WireGuard public keys, and the TPM's
firmware version. Without an EK certificate, the EK Name and its SHA-256 are shown on screen, to be copied
by hand to the ceremony (the fallback the ceremony records).

WHAT IT REFUSES: a persistent object at the EK or AK handle, or a WG-SERVICE key, that this enrolment did
not make. A host that was enrolled is re-enrolled only as a new node, through replacement (#76).

BETWEEN THE PHASES the WG-BOOT private key is in the clear on the encrypted root, 0600 in a root-only
directory; `commit` seals it to the TPM and removes it. Host backups must exclude /var/lib/regalia-enrol
(the local contribution is there too, until the peers' paths are enrolled).

A CRASH AT ANY STEP: every step is recorded in the journal (journal.json, root, in a 0700 directory)
as started before it acts and as done, with what it produced, after. Run `init` again: a done step is
checked against what it recorded and skipped; a step that started and did not finish is done again, and
removes only what it can PROVE it made: an AK whose Name, or a key file whose public key, it journalled
before that object or file existed. Anything else at its handle or path is refused, never removed.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time

from deploy.baremetal import attest, espcreds, measurements, membership

SCHEMA_JOURNAL = "regalia.enrol-journal/v1"
SCHEMA_BUNDLE = "regalia.enrol-bundle/v1"
ENROL_DIR = "/var/lib/regalia-enrol"
WG_SERVICE_KEY = "/etc/regalia/wg-service.key"
EK_CERT_INDICES = ("0x01c00002", "0x01c0000a")       # TCG EK credential profile: RSA 2048, ECC P-256
NODE_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
WG_KEY = re.compile(r"[A-Za-z0-9+/]{43}=")


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


def _write_private(path, data, exclusive=True):
    """data to path, 0600, fsynced; with exclusive, a file already there is a refusal, not a replacement."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_json(path, value):
    directory = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".journal-")
    try:
        os.write(fd, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class Journal:
    def __init__(self, directory, node_id):
        self.path = os.path.join(directory, "journal.json")
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.doc = json.load(f)
            require(self.doc.get("schema") == SCHEMA_JOURNAL, "%s is not an enrolment journal" % self.path)
            require(self.doc.get("node_id") == node_id,
                    "this host's enrolment was started as node %r, not %r: one host is one node (replacement is #76)"
                    % (self.doc.get("node_id"), node_id))
        else:
            self.doc = {"schema": SCHEMA_JOURNAL, "node_id": node_id, "steps": {}}
            _atomic_json(self.path, self.doc)

    def state(self, step):
        return self.doc["steps"].get(step, {}).get("state")

    def get(self, step):
        return self.doc["steps"].get(step, {})

    def started(self, step):
        self.doc["steps"][step] = {"state": "started", "at": int(time.time())}
        _atomic_json(self.path, self.doc)

    def done(self, step, **facts):
        self.doc["steps"][step] = dict(facts, state="done", at=int(time.time()))
        _atomic_json(self.path, self.doc)


def _run(argv, run, check=True, **kwargs):
    done = run(argv, capture_output=True, **kwargs)
    if check:
        err = done.stderr if isinstance(done.stderr, str) else (done.stderr or b"").decode(errors="replace")
        require(done.returncode == 0, "%s failed: %s" % (argv[0], err.strip()[-300:]))
    return done


def persistent_handles(run):
    out = _run(["tpm2_getcap", "handles-persistent"], run, text=True).stdout
    return {h.lower() for h in re.findall(r"0x[0-9a-fA-F]{8}", out)}


def _evict(handle, run):
    _run(["tpm2_evictcontrol", "-C", "o", "-c", handle], run, text=True)


def _name_at(handle, directory, run):
    """The Name of the persistent object at `handle`, from its public area."""
    path = os.path.join(directory, ".probe.pub")
    _run(["tpm2_readpublic", "-c", handle, "-o", path], run, text=True)
    try:
        with open(path, "rb") as f:
            return attest.name_of(attest.public_area(f.read(), handle)).hex()
    finally:
        os.unlink(path)


def _this_tpms_ek(directory, run):
    """The EK this TPM derives from its endorsement seed, made transiently: (public area, Name). The same
    template gives the same key every time, so an EK at our handle with this Name is this TPM's own."""
    ctx, pub = os.path.join(directory, ".ek.ctx"), os.path.join(directory, ".ek.pub")
    try:
        _run(["tpm2_createek", "-c", ctx, "-G", "rsa", "-u", pub], run, text=True)
        with open(pub, "rb") as f:
            blob = f.read()
        _run(["tpm2_flushcontext", ctx], run, check=False, text=True)
        if os.environ.get("TPM2TOOLS_TCTI", "").startswith(("swtpm", "mssim")):
            _run(["tpm2_flushcontext", "-t"], run, check=False, text=True)   # no resource manager (see attest.node_init)
        return blob, attest.name_of(attest.public_area(blob, "the EK")).hex()
    finally:
        for p in (ctx, pub):
            if os.path.exists(p):
                os.unlink(p)


def identity(journal, directory, run):
    """The EK and AK, persistent; their public areas in the enrolment directory.

    RESUME EVICTS ONLY WHAT IT CAN PROVE IT MADE. The EK is derived from the TPM's seed: an object at the EK
    handle whose Name equals this TPM's own EK is that EK, whoever persisted it. The AK is random: its Name
    is recorded in the journal right after TPM2_Create and BEFORE it is made persistent, so any AK this
    enrolment persisted has a recorded Name, and an object at the AK handle with another Name is not ours
    and is refused, never evicted."""
    ek_h, ak_h = attest.EK_HANDLE.lower(), attest.AK_HANDLE.lower()
    if journal.state("identity") == "done":
        facts = journal.get("identity")
        for k in ("ek", "ak"):
            with open(os.path.join(directory, k + ".pub"), "rb") as f:
                require(attest.name_of(attest.public_area(f.read(), k)).hex() == facts[k + "_name"],
                        "%s.pub no longer matches the journal" % k)
        require({ek_h, ak_h} <= persistent_handles(run), "the EK or AK this enrolment made is no longer in the TPM")
        for handle, k in ((attest.EK_HANDLE, "ek"), (attest.AK_HANDLE, "ak")):
            require(_name_at(handle, directory, run) == facts[k + "_name"],
                    "the object at %s is not the %s this enrolment recorded" % (handle, k.upper()))
        return facts
    ek_blob, ek_name = _this_tpms_ek(directory, run)
    present = persistent_handles(run)
    started = journal.state("identity") == "started"
    if ek_h in present:
        require(_name_at(attest.EK_HANDLE, directory, run) == ek_name,
                "the TPM holds an object at %s that is not this TPM's EK. A host that was enrolled is re-enrolled "
                "only as a new node, through replacement (#76)" % attest.EK_HANDLE)
        # This TPM's own EK, persisted by whoever (some distributions provision it): the same key, so it is
        # used as it is. What marks a host as already enrolled is an AK at the AK handle (below).
    if ak_h in present:
        recorded = journal.get("identity").get("ak_name") if started else None
        require(recorded is not None and _name_at(attest.AK_HANDLE, directory, run) == recorded,
                "the TPM already holds a persistent object at %s, which this enrolment did not make. A host that "
                "was enrolled is re-enrolled only as a new node, through replacement (#76)" % attest.AK_HANDLE)
        _evict(attest.AK_HANDLE, run)            # recorded right after it was created: ours, unseen
    journal.started("identity")
    with tempfile.TemporaryDirectory(prefix="enrol-") as d:
        if ek_h not in persistent_handles(run):
            _run(["tpm2_createek", "-c", attest.EK_HANDLE, "-G", "rsa", "-u", os.path.join(d, "ek.pub")], run, text=True)
        ctx, ak_pub = os.path.join(d, "ak.ctx"), os.path.join(d, "ak.pub")
        _run(["tpm2_createak", "-C", attest.EK_HANDLE, "-c", ctx, "-G", "ecc", "-g", "sha256", "-s", "ecdsa", "-u", ak_pub],
             run, text=True)
        with open(ak_pub, "rb") as f:
            ak_blob = f.read()
        ak_name = attest.name_of(attest.public_area(ak_blob, "the AK")).hex()
        journal.doc["steps"]["identity"]["ak_name"] = ak_name       # recorded BEFORE it is made persistent
        _atomic_json(journal.path, journal.doc)
        _run(["tpm2_evictcontrol", "-C", "o", "-c", ctx, attest.AK_HANDLE], run, text=True)
        if os.environ.get("TPM2TOOLS_TCTI", "").startswith(("swtpm", "mssim")):
            _run(["tpm2_flushcontext", "-t"], run, check=False, text=True)   # no resource manager (see attest.node_init)
    for k, blob in (("ek", ek_blob), ("ak", ak_blob)):
        path = os.path.join(directory, k + ".pub")
        if os.path.exists(path):
            os.unlink(path)
        _write_private(path, blob)
        os.chmod(path, 0o644)
    facts = {"ek_public": ek_blob.hex(), "ek_name": ek_name, "ak_public": ak_blob.hex(), "ak_name": ak_name}
    journal.done("identity", **facts)
    return facts


def _der_exact(raw, index):
    """The certificate in an NV index, cut at the length its outer DER SEQUENCE gives. The rest of the index
    must be padding (0x00 or 0xFF). Anything else is a refusal: a certificate that is there but cannot be
    read is not "no certificate"."""
    require(len(raw) >= 4 and raw[0] == 0x30, "the EK certificate at %s is not DER (no outer SEQUENCE)" % index)
    if raw[1] < 0x80:
        size, head = raw[1], 2
    else:
        count = raw[1] & 0x7f
        require(1 <= count <= 3 and len(raw) >= 2 + count, "the EK certificate at %s has a malformed DER length" % index)
        size, head = int.from_bytes(raw[2:2 + count], "big"), 2 + count
    end = head + size
    require(end <= len(raw), "the EK certificate at %s is truncated (%d of %d bytes)" % (index, len(raw), end))
    rest = raw[end:]
    require(rest.strip(b"\x00") == b"" or rest.strip(b"\xff") == b"",
            "the EK certificate at %s is followed by data that is not padding" % index)
    return raw[:end]


def ek_certificate(journal, directory, run):
    """The TPM's EK certificate for the RSA EK this enrolment uses (TCG index 0x01c00002), checked to
    certify THAT key. Only a missing index means "no certificate"; one that is there and cannot be read
    (an index whose read is refused, for example locked by its authorisation, included), or certifies
    another key, is a refusal. An ECC EK certificate (0x01c0000a) certifies the ECC EK, which
    this enrolment does not use: its presence is recorded, nothing is decided on it. Not a trust decision
    either way: the ceremony verifies the issuer against the manufacturer's CA."""
    if journal.state("ek_certificate") == "done":
        return journal.get("ek_certificate")
    journal.started("ek_certificate")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    _run(["tpm2_readpublic", "-c", attest.EK_HANDLE, "-f", "pem", "-o", os.path.join(directory, "ek.pem")], run, text=True)
    with open(os.path.join(directory, "ek.pem"), "rb") as f:
        ek_spki = serialization.load_pem_public_key(f.read()).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    defined = _nv_indices(run)
    found = None
    rsa_index, ecc_index = EK_CERT_INDICES
    if rsa_index in defined:
        path = os.path.join(directory, "ek-cert.der")
        _run(["tpm2_nvread", rsa_index, "-o", path], run, text=True)
        with open(path, "rb") as f:
            der = _der_exact(f.read(), rsa_index)
        try:
            cert = x509.load_der_x509_certificate(der)
            spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        except ValueError as error:
            raise Refused("the EK certificate at %s cannot be read: %s" % (rsa_index, error))
        require(spki == ek_spki, "the EK certificate at %s certifies another key than this TPM's EK: refused, the "
                "ceremony could not tell this TPM from another" % rsa_index)
        found = {"index": rsa_index, "der": base64.b64encode(der).decode(),
                 "claimed_issuer": cert.issuer.rfc4514_string(), "certifies_this_ek": True}
    facts = {"certificate": found, "ecc_certificate_present": ecc_index in defined}
    journal.done("ek_certificate", **facts)
    return facts


def _nv_indices(run):
    out = _run(["tpm2_getcap", "handles-nv-index"], run, text=True).stdout
    return {h.lower() for h in re.findall(r"0x[0-9a-fA-F]{7,8}", out)} | {
        "0x%08x" % int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]{7,8}", out)}


def _wg_pair(run):
    private = _run(["wg", "genkey"], run, text=True).stdout.strip()
    require(WG_KEY.fullmatch(private), "wg genkey gave no key")
    public = _run(["wg", "pubkey"], run, text=True, input=private + "\n").stdout.strip()
    require(WG_KEY.fullmatch(public), "wg pubkey gave no key")
    return private, public


def _wg_public_of(path, run):
    with open(path) as f:
        private = f.read().strip()
    require(WG_KEY.fullmatch(private), "%s does not hold a WireGuard key" % path)
    return _run(["wg", "pubkey"], run, text=True, input=private + "\n").stdout.strip()


def wg_key(journal, step, path, run):
    """A WireGuard key made here. Its PUBLIC half is journalled before the private file is written, so on a
    resume a file at `path` is removed only if it holds that very key; anything else is refused and left."""
    if journal.state(step) == "done":
        recorded = journal.get(step)["public"]
        require(os.path.exists(path) and _wg_public_of(path, run) == recorded,
                "%s no longer holds the key this enrolment made" % path)
        return recorded
    if os.path.lexists(path):
        recorded = journal.get(step).get("public") if journal.state(step) == "started" else None
        mine = recorded is not None and os.path.isfile(path) and not os.path.islink(path)
        if mine and os.path.getsize(path) == 0:
            pass                         # created (O_EXCL) and killed before the one write: our empty file
        elif mine:
            try:
                mine = _wg_public_of(path, run) == recorded
            except Refused:
                mine = False
        require(mine, "%s already exists and this enrolment did not make it. A host that was enrolled is re-enrolled "
                "only as a new node, through replacement (#76); a stray file is removed by hand: rm %s" % (path, path))
        os.unlink(path)
    private, public = _wg_pair(run)
    journal.doc["steps"][step] = {"state": "started", "at": int(time.time()), "public": public}
    _atomic_json(journal.path, journal.doc)                     # one write: recorded BEFORE the private file exists
    _ensure_trusted_dir(os.path.dirname(path))
    _write_private(path, (private + "\n").encode())
    journal.done(step, public=public, path=path)
    return public


def firmware_version(run):
    out = _run(["tpm2_getcap", "properties-fixed"], run, text=True).stdout
    words = []
    for name in ("TPM2_PT_FIRMWARE_VERSION_1", "TPM2_PT_FIRMWARE_VERSION_2"):
        m = re.search(name + r":\s*\n?\s*raw:\s*(0x[0-9a-fA-F]+)", out)
        words.append(int(m.group(1), 16) if m else None)
    return "%08x%08x" % tuple(words) if None not in words else None


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _check_ancestor(name, st, child_uid):
    """One directory on the way down: owned by root (or this user) and closed to group and others, OR sticky
    (/tmp, 1777) with the entry below it owned by root or this user: in a sticky directory only an entry's owner
    can rename or remove it, so nobody else can swap what lies beneath. The SAME rule as admission.ancestorsTrusted
    (#233, Go); kept identical by hand until one shared helper exists."""
    me = os.geteuid()                    # root, in production: main() refuses anything else, and _hand_over requires it
    open_to_others = st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    require(stat.S_ISDIR(st.st_mode) and st.st_uid in (0, me)
            and (not open_to_others or (st.st_mode & stat.S_ISVTX and child_uid in (0, me))),
            "%s is not a root-owned directory closed to group and others (nor a sticky one): what enrolment puts "
            "under it could be replaced" % name)


def _open_trusted(path, create=None):
    """A descriptor on the directory `path`, reached from / one component at a time, each opened without
    following a link (O_NOFOLLOW at EVERY level, not only the last) and each checked by _check_ancestor before
    anything is made in it or below it. With `create`, a missing component is made with that mode, inside the
    descriptor of the one above (never os.makedirs, which follows links). The last directory is checked as an
    ancestor of what will be put in it, by this user."""
    path = os.path.abspath(path)
    fd, name, st = os.open("/", _DIR_FLAGS), "/", None
    try:
        st = os.fstat(fd)
        for part in [p for p in path.split("/") if p]:
            below = os.path.join(name, part)
            try:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                require(create is not None, "%s does not exist" % below)
                _check_ancestor(name, st, os.geteuid())        # before anything is made in it
                os.mkdir(part, create, dir_fd=fd)
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.fchmod(child, create)                        # the mode asked for, whatever the umask
            except OSError as error:                            # ELOOP: a link; ENOTDIR: not a directory
                raise Refused("%s is not a real directory (%s): enrolment does not follow it" % (below, error.strerror))
            child_st = os.fstat(child)
            _check_ancestor(name, st, child_st.st_uid)
            os.close(fd)
            fd, name, st = child, below, child_st
        _check_ancestor(name, st, os.geteuid())
        return fd
    except BaseException:
        os.close(fd)
        raise


def _ensure_trusted_dir(path, mode=0o755):
    """`path` and every directory above it trusted (see _open_trusted), missing ones made with `mode`. Only root
    can then change what lies there, so the path-based writes after it cannot be redirected."""
    os.close(_open_trusted(path, create=mode))


def _safe_directory(directory):
    """The enrolment directory holds the journal and, between the phases, the WG-BOOT private key: it must be a
    real directory (not a link), owned by root, 0700, and every directory above it trusted (_check_ancestor:
    otherwise someone could swap it). Created if absent; never trusted if it is not so."""
    directory = os.path.abspath(directory)
    parent = _open_trusted(os.path.dirname(directory))
    try:
        base = os.path.basename(directory)
        try:
            os.mkdir(base, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        try:
            fd = os.open(base, _DIR_FLAGS, dir_fd=parent)
        except OSError as error:
            raise Refused("%s is not a real directory (%s)" % (directory, error.strerror))
        try:
            st = os.fstat(fd)
            _check_ancestor(os.path.dirname(directory), os.fstat(parent), st.st_uid)
            require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid(),
                    "%s is not a real directory owned by this user (root)" % directory)
            os.fchmod(fd, 0o700)
            require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, "%s could not be made 0700" % directory)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def init(node_id, directory=ENROL_DIR, wg_service_key=WG_SERVICE_KEY, run=subprocess.run, out=sys.stdout):
    require(NODE_ID.fullmatch(node_id or ""), "a node ID is a lower-case name, such as a")
    _safe_directory(directory)
    journal = Journal(directory, node_id)
    ids = identity(journal, directory, run)
    cert = ek_certificate(journal, directory, run)
    service = wg_key(journal, "wg_service", wg_service_key, run)
    boot = wg_key(journal, "wg_boot", os.path.join(directory, "wg-boot.key"), run)
    bundle = {"schema": SCHEMA_BUNDLE, "node_id": node_id,
              "ek_public": ids["ek_public"], "ek_name": ids["ek_name"],
              "ak_public": ids["ak_public"], "ak_name": ids["ak_name"],
              "ek_certificate": cert["certificate"],
              "wg_service_pub": service, "wg_boot_pub": boot,
              "tpm_firmware_version": firmware_version(run)}
    _atomic_json(os.path.join(directory, "bundle.json"), bundle)
    os.chmod(os.path.join(directory, "bundle.json"), 0o644)
    print("ENROL INIT: node %s, identity bundle %s (public values only; take it to the manifest ceremony)"
          % (node_id, os.path.join(directory, "bundle.json")), file=out)
    if cert["certificate"] is None:
        print("NO EK CERTIFICATE in this TPM. Copy BY HAND to the ceremony:\n  EK Name   %s\n  sha256    %s"
              % (ids["ek_name"], hashlib.sha256(bytes.fromhex(ids["ek_name"])).hexdigest()), file=out)
    else:
        print("EK certificate from %s, which CLAIMS to be issued by %s. It certifies this TPM's EK; whether that issuer "
              "is the manufacturer is for the ceremony to verify" % (cert["certificate"]["index"], cert["certificate"]["claimed_issuer"]), file=out)
    return bundle


def fingerprint(root_key):
    """The root key's fingerprint as the ceremony prints it and the operator types it: SHA-256 of the raw
    Ed25519 public key, hex."""
    return hashlib.sha256(bytes.fromhex(root_key)).hexdigest()


def check_manifest(directory, chain, root_key, typed, document):
    """Phase 2's first step, and the only one before anything is written: `chain` (one envelope, or the list
    of envelopes from epoch 1 to N) verifies from the root-signed epoch 1 onwards under the root key whose
    fingerprint the operator typed by hand (a file alone never sets a trust anchor, ADR-0002 D21.2); its LAST
    manifest names THIS host exactly as its identity bundle says, and commits to the measurements document
    given. The first three hosts enrol on epoch 1; a host added later (a fourth node, or a replacement under
    #76) is named first at some epoch N and enrols on the whole chain to N. Returns the last manifest; writes
    nothing."""
    require(isinstance(root_key, str) and re.fullmatch(r"[0-9a-f]{64}", root_key), "the root key is 64 lower-case hex")
    typed = re.sub(r"[\s:]", "", (typed or "").lower())
    require(re.fullmatch(r"[0-9a-f]{64}", typed), "the fingerprint typed is not 64 hex digits")
    require(typed == fingerprint(root_key), "the root key's fingerprint is not the one typed: this is not the root "
            "key the ceremony made. Nothing was written")
    bundle = _bundle(directory)
    envelopes = chain if isinstance(chain, list) else [chain]
    require(envelopes, "the chain is empty")
    try:
        manifest = membership.accept_chain(None, envelopes, root_key)
    except membership.Refused as refusal:
        raise Refused("the manifest chain is refused: %s" % refusal)
    nodes = membership.validate(manifest)
    node_id = bundle["node_id"]
    require(node_id in nodes, "the manifest does not name this host (%s)" % node_id)
    node = nodes[node_id]
    require(membership.CAPABILITIES[node["state"]] & {"request", "serve"},
            "the manifest names %s %s: a node in that state is not enrolled" % (node_id, node["state"]))
    wg = {k: base64.b64decode(bundle[k]).hex() for k in ("wg_service_pub", "wg_boot_pub")}
    for field, mine in (("ek_name", bundle["ek_name"]), ("ak_name", bundle["ak_name"]),
                        ("wg_service_pub", wg["wg_service_pub"]), ("wg_boot_pub", wg["wg_boot_pub"])):
        require(node[field] == mine, "the manifest's %s for %s is not this host's: it was made from another bundle, or "
                "for another host. Nothing was written" % (field, node_id))
    try:
        measurements.bind(manifest, document)
    except membership.Refused as refusal:            # measurements raises the same class
        raise Refused("the measurements are refused: %s" % refusal)
    return manifest


NODE_JSON = "/etc/regalia/node.json"


def node_config(node_id, root_key, example):
    """The node configuration enrolment writes: the shipped example (deploy/baremetal/node.example.json) with
    this host's node ID and the root key whose fingerprint was typed. Checked by node.validate."""
    from deploy.baremetal import node as node_module           # imported here: node imports most of the package
    doc = dict(example, node_id=node_id, root_key=root_key)
    node_module.validate(doc)
    return doc


CONFIG_DIR = "/etc/regalia/"


def _same(target, digest):
    with open(target, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest() == digest


def _install(journal, step, path, data, prefix=""):
    """Write `data` to `path` (0644, root's), recording its SHA-256 in the journal, WITHOUT EVER REPLACING a file:
    the bytes go to a temporary file whose exact name is journalled first, and are published with link(2),
    which fails if the target exists (a rename would replace it silently). A file already there, or one that
    appears meanwhile, is accepted only if it is byte-for-byte what this step writes (a resumed run); anything
    else is refused and left. Enrolment never overwrites a node's configuration (re-enrolment is #76)."""
    require(path.startswith(CONFIG_DIR) and os.path.normpath(path) == path and "\0" not in path,
            "%s is not under %s: enrolment writes configuration only there" % (path, CONFIG_DIR))
    target = prefix + path
    digest = hashlib.sha256(data).hexdigest()
    facts = {k: v for k, v in journal.get(step).items() if k not in ("state", "at")}

    def existing():
        require(os.path.isfile(target) and not os.path.islink(target), "%s exists and is not a regular file" % path)
        require(_same(target, digest), "%s already exists with other content. Enrolment does not overwrite a node's "
                "configuration (re-enrolment is replacement, #76); remove it by hand if it is a leftover: rm %s" % (path, path))
        require(facts.get(path) in (None, digest), "%s changed since this enrolment wrote it" % path)

    tmp = target + ".enrol-new"
    if facts.get("tmp:" + path) and os.path.lexists(tmp):
        os.unlink(tmp)                   # this step's own temporary file, by the exact name it journalled
    if os.path.lexists(target):
        existing()
    else:
        directory = os.path.dirname(target)
        _ensure_trusted_dir(directory)
        facts["tmp:" + path] = os.path.basename(tmp)
        journal.done(step, **facts)       # the temporary name, recorded before the file exists
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        try:
            os.write(fd, data)
            os.fsync(fd)
            os.fchmod(fd, 0o644)
        finally:
            os.close(fd)
        try:
            os.link(tmp, target)          # no-clobber publish
        except FileExistsError:
            existing()
        finally:
            os.unlink(tmp)
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    facts.pop("tmp:" + path, None)
    facts[path] = digest
    journal.done(step, **facts)
    return digest


def install_config(journal, node_id, root_key, example, site, document, prefix=""):
    """Phase 2's configuration: node.json, the site configuration and the measurements document the manifest
    commits to, each where node.json says, each refused if something else is already there."""
    from deploy.baremetal import sitecfg
    sitecfg.validate(site)
    config = node_config(node_id, root_key, example)
    for key in ("site", "measurements"):
        require(config[key].startswith(CONFIG_DIR), "node.json puts %s at %s, outside %s" % (key, config[key], CONFIG_DIR))
    pretty = lambda doc: (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()        # noqa: E731
    _install(journal, "config", config["site"], pretty(site), prefix)
    _install(journal, "config", config["measurements"], pretty(document), prefix)
    _install(journal, "config", NODE_JSON, pretty(config), prefix)
    return config


SYNC_USER = "regalia-sync"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def anchor_and_store(config_path, chain, run=subprocess.run):
    """Phase 2's trust anchors, run AS regalia-sync (the user that owns them from then on, #214): the
    membership epoch anchor (membership.HighWater: the counter, its base and the two record slots, #68),
    the store committed with the whole chain, so the anchor stands at its last epoch N, and the heartbeat
    counter. Returns (epoch, digest of the last manifest).

    RESUMED, it never takes over indices it cannot prove are this chain's: a store that exists must load
    (Store checks it against the anchor) and be a PREFIX of `chain`, and the rest is committed; indices
    without a store are accepted only as `define` leaves them (epoch 0, the zero record), the state of an
    enrolment stopped before its first commit. Anything else is refused and left."""
    from deploy.baremetal import heartbeat, node as node_module
    with open(config_path, "rb") as f:
        cfg = node_module.validate(membership.load(f.read(node_module.MAX_BYTES + 1), node_module.MAX_BYTES))
    n = node_module.Node(cfg, run)
    hw, store = n.anchor(), n.store()
    counter = heartbeat.Counter(cfg["nv_heartbeat"], cfg["tcti"], run, lock_path=n.path("heartbeat-counter.lock"))
    envelopes = chain if isinstance(chain, list) else [chain]

    def defined(owner, indices):
        return [i for i in indices if owner._tpm("nvreadpublic", i).returncode == 0]
    anchor_indices = hw._indices()
    already = 0
    if os.path.exists(store.path):
        store.load()                                   # refuses a store the TPM anchor does not vouch for
        held = [membership.digest(m) for m in store.manifests]
        current, mine = None, []
        for envelope in envelopes:
            current = membership.accept(current, envelope, cfg["root_key"])
            mine.append(membership.digest(current))
        require(held == mine[:len(held)], "%s holds a chain that is not the beginning of this one: an enrolment of "
                "another manifest, or a node already in service. Enrolment does not touch it (re-enrolment is #76)" % store.path)
        already = len(held)
    else:
        present = defined(hw, anchor_indices)
        if present:
            require(len(present) == len(anchor_indices) and hw.value() == 0 and hw.record() == (0, membership.HighWater.ZERO),
                    "the TPM already holds the anchor's indices (%s) and no store goes with them: they are not an enrolment "
                    "stopped before its first commit. Enrolment does not take them over (re-enrolment is replacement, #76)"
                    % ", ".join(present))
        else:
            hw.define()
    for envelope in envelopes[already:]:            # what the store holds already is this chain's beginning (checked)
        store.commit(envelope)
    manifest = store.load()
    counter_indices = (counter.index, counter.base_index)
    present = defined(counter, counter_indices)
    if not present:
        counter.define()
    else:
        require(len(present) == 2 and counter.value() == 0, "the TPM already holds the heartbeat counter's indices (%s) at "
                "a value other than a fresh one: enrolment does not take them over" % ", ".join(present))
    return manifest["epoch"], membership.digest(manifest)


def run_as_sync(config_path, chain, run=subprocess.run):
    """anchor_and_store, in a process of regalia-sync with the tss group (the TPM), started from the package
    root so `-m` finds it. The chain goes on its standard input: the enrolment directory is root's (0700),
    and regalia-sync could not read a file there. The journal stays with the caller."""
    # env -i: nothing of root's environment reaches the step (the TCTI comes from node.json, not from here)
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.enrol", "_anchor", "--config", config_path, "--chain", "-"],
               cwd=PACKAGE_ROOT, capture_output=True, text=True, input=membership.canonical(chain).decode())
    require(done.returncode == 0, "the anchor step, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    m = re.search(r"^ANCHORED epoch (\d+) digest ([0-9a-f]{64})$", done.stdout, re.M)
    require(m is not None, "the anchor step did not report its result")
    return int(m.group(1)), m.group(2)


def _hand_over(state, chown=True):
    """The state directory, made regalia-sync's: every directory above it trusted and made one level at a time
    (_open_trusted), then the directory itself opened without following a link and judged by descriptor, so what
    is checked is what is changed. Taken over only when it is root's and empty; one that is regalia-sync's
    already (an enrolment resumed) only at 0755, the mode this step gives it. `chown` False (tests, which
    cannot change an owner): the user that owns it is taken to be regalia-sync."""
    if chown:
        # _check_ancestor trusts directories of this user as well as root's: right for root, which main()
        # requires, and for tests; a handover to regalia-sync is never done by anyone else
        require(os.geteuid() == 0, "the state directory is handed to %s by root only" % SYNC_USER)
        import pwd
        user = pwd.getpwnam(SYNC_USER)
        uid, gid = user.pw_uid, user.pw_gid
    else:
        uid, gid = os.geteuid(), os.getegid()
    parent = _open_trusted(os.path.dirname(os.path.abspath(state)), create=0o755)
    try:
        base, created = os.path.basename(state), False
        try:
            os.mkdir(base, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            pass
        try:
            fd = os.open(base, _DIR_FLAGS, dir_fd=parent)
        except OSError as error:
            raise Refused("%s is not a real directory (%s): enrolment does not follow it" % (state, error.strerror))
    finally:
        os.close(parent)
    try:
        st = os.fstat(fd)
        if created:                                      # ours, just made (root's on a host): handed over below
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o755)
        elif (st.st_uid, st.st_gid) == (uid, gid):
            require(stat.S_IMODE(st.st_mode) == 0o755, "%s is %s's but mode %o, not 0755: enrolment did not leave it so, "
                    "and does not take it over" % (state, SYNC_USER, stat.S_IMODE(st.st_mode)))
        else:
            require(st.st_uid == 0 and not os.listdir(fd), "%s is neither %s's nor an empty directory of root's: "
                    "enrolment does not take it over" % (state, SYNC_USER))
            os.fchown(fd, uid, gid)
            os.fchmod(fd, 0o755)
    finally:
        os.close(fd)


def _bundle(directory):
    with open(os.path.join(directory, "bundle.json"), "rb") as f:
        bundle = membership.load(f.read(membership.MAX_BYTES + 1))
    require(isinstance(bundle, dict) and bundle.get("schema") == SCHEMA_BUNDLE
            and all(isinstance(bundle.get(k), str) for k in ("node_id", "ek_name", "ak_name", "wg_service_pub", "wg_boot_pub")),
            "bundle.json is not a complete identity bundle")
    return bundle


def approved_image(image, record_path, initrd_pub, system_pub, secure_boot_cert, document, node_id, run=subprocess.run):
    """The boot image this host's sealed credentials will open in, and the key they are sealed to. The initrd-phase
    key is never taken as a bare file: uki.verify checks the image against its signed record, both PCR keys
    against the record and the image's own signatures, and the Secure Boot signature; then the record's PCR 11
    per phase must be a set the measurements document (which the manifest commits to) accepts for this node.
    Returns the initrd-phase public key (PEM bytes) to seal to."""
    from deploy.baremetal import uki
    with open(record_path, "rb") as f:
        record = membership.load(f.read(membership.MAX_BYTES + 1))
    keys = {}
    for phase, path in (("initrd", initrd_pub), ("system", system_pub)):
        with open(path, "rb") as f:
            keys[phase] = f.read(65537)
    try:
        pcr11 = uki.verify(image, record, keys, secure_boot_cert, run)
    except (uki.Refused, membership.Refused) as refusal:
        raise Refused("the boot image is refused: %s" % refusal)
    sets = measurements.validate(document).get(node_id, [])
    approved = [s for s in sets if {phase: values.get("11") for phase, values in (s.get("phases") or {}).items()} == pcr11]
    require(approved, "the measurements the manifest commits to accept no set with this image's PCR 11 (%s) for %s: "
            "the credentials would be sealed to an image this node may not run" % (
                ", ".join("%s %s" % (p, v[:16]) for p, v in sorted(pcr11.items())), node_id))
    return keys["initrd"]


LOCAL_FILE = "local.bin"
SEALED = (("regalia.unlock-local", "local"), ("regalia.wg-boot-key", "wg_boot"))


def local_contribution(journal, directory):
    """The local unlock contribution, 32 random bytes made here (unlock.SECRET_BYTES). Its SHA-256 is journalled
    BEFORE the file exists, so a resumed run removes only the file it made. It stays root 0600 in the enrolment
    directory until the LUKS paths with the peers are enrolled (they need it, and its sealed copy opens only in
    the initrd); then it is removed."""
    from deploy.baremetal import unlock
    path, step = os.path.join(directory, LOCAL_FILE), "local"
    digest = lambda data: hashlib.sha256(data).hexdigest()      # noqa: E731
    if journal.state(step) == "done":
        with open(path, "rb") as f:
            local = f.read(unlock.SECRET_BYTES + 1)
        require(digest(local) == journal.get(step)["sha256"], "%s no longer holds the contribution this enrolment made" % path)
        return local
    if os.path.lexists(path):
        recorded = journal.get(step).get("sha256") if journal.state(step) == "started" else None
        mine = recorded is not None and os.path.isfile(path) and not os.path.islink(path)
        if mine and os.path.getsize(path):
            with open(path, "rb") as f:
                mine = digest(f.read(unlock.SECRET_BYTES + 1)) == recorded
        require(mine, "%s already exists and this enrolment did not make it; a stray file is removed by hand: rm %s" % (path, path))
        os.unlink(path)
    local = os.urandom(unlock.SECRET_BYTES)
    journal.doc["steps"][step] = {"state": "started", "at": int(time.time()), "sha256": digest(local)}
    _atomic_json(journal.path, journal.doc)                     # recorded BEFORE the file exists
    _write_private(path, local)
    journal.done(step, sha256=digest(local))
    return local


def _seal(name, plaintext, initrd_pub, run):
    """`plaintext` as a systemd credential named `name`, bound to this TPM: PCR 7 directly, PCR 11 through the
    initrd-phase signature (e2e-enrol's binding). The bytes systemd-creds prints, exactly as the ESP gets them."""
    from deploy.baremetal import unlock
    with tempfile.NamedTemporaryFile(prefix="initrd-pub.", suffix=".pem") as key:
        key.write(initrd_pub)
        key.flush()
        done = run(["systemd-creds", "encrypt", "--name=" + name, "--with-key=tpm2-with-public-key", "--tpm2-pcrs=7",
                    "--tpm2-public-key=" + key.name, "--tpm2-public-key-pcrs=11", "-", "-"], input=plaintext, capture_output=True)
    require(done.returncode == 0, "systemd-creds could not seal %s to the TPM (exit %d)" % (name, done.returncode))
    try:
        kind = unlock.local_key_type(done.stdout.decode("ascii", "replace"))
    except unlock.Refused:
        kind = None
    require(kind == "tpm2-with-public-key", "systemd-creds did not seal %s to the TPM and the initrd key (it does that "
            "silently when it is not root): nothing was written" % name)
    return done.stdout


def _publish_esp(journal, step, directory, filename, data):
    """`data` to directory/filename on the ESP, never replacing a file. The ESP is FAT: no link(2), so the
    target's absence is checked and the temporary file renamed onto it (only root writes the ESP). Its digest
    is journalled as PENDING before the rename and as the file's after it, so a resumed run accepts exactly
    what this enrolment published, and refuses anything else there."""
    facts = {k: v for k, v in journal.get(step).items() if k not in ("state", "at")}
    target, tmp = os.path.join(directory, filename), os.path.join(os.path.dirname(directory), "." + filename + ".enrol-new")
    if facts.get("tmp:" + filename) and os.path.lexists(tmp):
        os.unlink(tmp)                   # this step's own temporary file, by the exact name it journalled
    if os.path.lexists(target):
        with open(target, "rb") as f:
            held = hashlib.sha256(f.read(1 << 20)).hexdigest()
        require(os.path.isfile(target) and not os.path.islink(target)
                and held in (facts.get(filename), facts.get("pending:" + filename)),
                "%s already exists and this enrolment did not write it. Enrolment does not replace a node's sealed "
                "credentials (re-enrolment is replacement, #76); a leftover is removed by hand: rm %s" % (target, target))
        facts[filename] = held
    else:
        facts["tmp:" + filename], facts["pending:" + filename] = os.path.basename(tmp), hashlib.sha256(data).hexdigest()
        _journal_facts(journal, step, facts)          # the temporary name and the digest, before the file exists
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        require(not os.path.lexists(target), "%s appeared while it was being written" % target)
        os.rename(tmp, target)
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        facts[filename] = facts["pending:" + filename]
    facts.pop("tmp:" + filename, None)
    facts.pop("pending:" + filename, None)
    _journal_facts(journal, step, facts)
    return facts[filename]


def _journal_facts(journal, step, facts):
    """`facts` for a step still under way: written at once, the state kept "started"."""
    journal.doc["steps"][step] = dict(facts, state="started", at=int(time.time()))
    _atomic_json(journal.path, journal.doc)


def seal_credentials(journal, directory, esp, initrd_pub, run=subprocess.run):
    """Design step 4 of #190: regalia.unlock-local (the local contribution, made here) and regalia.wg-boot-key (the
    WG-BOOT private key init made) sealed to this TPM and the initrd key (approved_image), on the ESP in
    loader/credentials. Returns {file: {"sha256", "size"}} of the two sealed files: the part of PCR 12 a peer
    cannot render from the manifest and the site (espcreds.record). The WG-BOOT private key file is removed once
    its sealed copy is published; the local contribution stays until the peers' paths are enrolled."""
    directory_esp = os.path.join(esp, "loader", "credentials")
    if journal.state("seal") == "done":
        files = journal.get("seal")["files"]
        for filename, fact in files.items():
            path = os.path.join(directory_esp, filename)
            with open(path, "rb") as f:
                require(hashlib.sha256(f.read(1 << 20)).hexdigest() == fact["sha256"], "%s changed since this enrolment sealed it" % path)
        boot_key = journal.get("wg_boot").get("path")
        if boot_key and os.path.lexists(boot_key):
            os.unlink(boot_key)          # sealed and published: the clear copy goes (a crash came between the two)
        return files
    _ensure_trusted_dir(directory_esp)
    plain = {"local": local_contribution(journal, directory)}
    boot_key = journal.get("wg_boot")["path"]
    with open(boot_key, "rb") as f:
        plain["wg_boot"] = f.read(4096)
    require(WG_KEY.fullmatch(plain["wg_boot"].decode("ascii", "replace").strip()), "%s does not hold a WireGuard key" % boot_key)
    if journal.state("seal") is None:
        _journal_facts(journal, "seal", {})
    for name, source in SEALED:
        filename = name + espcreds.SUFFIX
        if os.path.lexists(os.path.join(directory_esp, filename)):
            _publish_esp(journal, "seal", directory_esp, filename, None)        # ours (journalled) is kept; anything else refused
        else:
            _publish_esp(journal, "seal", directory_esp, filename, _seal(name, plain[source], initrd_pub, run))
    files = {}
    for name, _ in SEALED:
        filename = name + espcreds.SUFFIX
        with open(os.path.join(directory_esp, filename), "rb") as f:
            data = f.read(1 << 20)
        files[filename] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    journal.done("seal", files=files)
    os.unlink(boot_key)
    return files


def commit(directory, chain, root_key, typed, document, site, example, boot=None, run=subprocess.run, prefix="", as_sync=None,
           out=sys.stdout):
    """Phase 2 (#190): this host's TPM identity re-checked by Name, the manifest chain checked again (never trusted
    from an earlier `check`), the boot image checked (approved_image), the configuration installed, the state
    directory made regalia-sync's, the anchor, the store and the heartbeat counter set up AS regalia-sync, and the
    two boot credentials sealed onto the ESP. `boot` = {"image", "record", "initrd_pub", "system_pub",
    "secure_boot_cert", "esp"}; the CLI always gives it, and only tests of the earlier steps leave it out, which
    stops after the anchors. The peers' paths and the enrolment record follow in later steps."""
    journal = Journal(directory, _bundle(directory)["node_id"])
    require(journal.state("identity") == "done", "this host has no identity yet: run `enrol init` first")
    identity(journal, directory, run)                               # a done identity is re-checked by Name at both handles
    manifest = check_manifest(directory, chain, root_key, typed, document)
    initrd_pub = None
    if boot is not None:                                            # checked before anything is written
        initrd_pub = approved_image(boot["image"], boot["record"], boot["initrd_pub"], boot["system_pub"],
                                    boot["secure_boot_cert"], document, journal.doc["node_id"], run)
    config = install_config(journal, journal.doc["node_id"], root_key, example, site, document, prefix)
    _hand_over(prefix + config["state_dir"], as_sync is None)
    journal.started("anchor")
    epoch, digest = (as_sync or run_as_sync)(prefix + NODE_JSON, chain if isinstance(chain, list) else [chain])
    require(epoch == manifest["epoch"] and digest == membership.digest(manifest),
            "the anchor stands at epoch %d (%s), not at the manifest checked (%d)" % (epoch, digest[:16], manifest["epoch"]))
    journal.done("anchor", epoch=epoch, digest=digest)
    print("ENROLLED (trust anchors): node %s, membership epoch %d (%s) anchored in the TPM and committed as %s"
          % (journal.doc["node_id"], epoch, digest[:16], SYNC_USER), file=out)
    if boot is not None:
        files = seal_credentials(journal, directory, boot["esp"], initrd_pub, run)
        print("SEALED to this TPM and the initrd key, on the ESP: %s" % ", ".join(
            "%s (sha256 %s, %d bytes)" % (f, v["sha256"][:16], v["size"]) for f, v in sorted(files.items())), file=out)
    return epoch, digest


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.enrol", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="make this host's keys and print its identity bundle")
    p.add_argument("--node-id", required=True)
    p.add_argument("--enrol-dir", default=ENROL_DIR)
    p.add_argument("--wg-service-key", default=WG_SERVICE_KEY)
    c = sub.add_parser("check", help="check the root-signed manifest against this host, writing nothing")
    c.add_argument("--manifest", required=True, help="the root-signed epoch-1 envelope, or a JSON list of the "
                   "envelopes from epoch 1 to the one that first names this host")
    c.add_argument("--root-key", required=True, help="the membership root's public key, 64 hex")
    c.add_argument("--measurements", required=True, help="the measurements document the manifest commits to")
    c.add_argument("--enrol-dir", default=ENROL_DIR)
    k = sub.add_parser("commit", help="enrol this host's trust anchors from the checked manifest chain")
    k.add_argument("--manifest", required=True, help="the root-signed envelope, or the JSON list of envelopes from epoch 1")
    k.add_argument("--root-key", required=True, help="the membership root's public key, 64 hex")
    k.add_argument("--measurements", required=True, help="the measurements document the manifest commits to")
    k.add_argument("--site", required=True, help="this host's site configuration (with boot_mesh and service_mesh)")
    k.add_argument("--example", default=os.path.join(PACKAGE_ROOT, "deploy", "baremetal", "node.example.json"),
                   help="the node configuration this enrolment starts from (default: the shipped example)")
    k.add_argument("--image", required=True, help="the signed boot image (UKI) on the ESP")
    k.add_argument("--image-record", required=True, help="its signed record (uki.py sign)")
    k.add_argument("--initrd-pub", required=True, help="the initrd-phase PCR key's public half: the sealed credentials are bound to it")
    k.add_argument("--system-pub", required=True, help="the system-phase PCR key's public half")
    k.add_argument("--secure-boot-cert", required=True, help="the Secure Boot certificate the record names")
    k.add_argument("--esp", required=True, help="the ESP's mount point: the sealed credentials go to ESP/loader/credentials")
    k.add_argument("--enrol-dir", default=ENROL_DIR)
    a = sub.add_parser("_anchor", help=argparse.SUPPRESS)
    a.add_argument("--config", required=True)
    a.add_argument("--chain", required=True, choices=["-"], help="always -: the chain comes on standard input")
    args = ap.parse_args(argv)
    if args.command == "_anchor":                    # run by commit, as regalia-sync
        try:
            chain = membership.load(sys.stdin.buffer.read(membership.MAX_CHAIN_BYTES + 1), membership.MAX_CHAIN_BYTES)
            epoch, digest = anchor_and_store(args.config, chain)
        except (Refused, membership.Refused, OSError, ValueError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        print("ANCHORED epoch %d digest %s" % (epoch, digest))
        return 0
    if args.command == "commit":
        if os.geteuid() != 0:
            print("REFUSED: enrolment runs as root, at the host's console", file=sys.stderr)
            return 2
        try:
            with open(args.manifest, "rb") as f:
                chain = membership.load(f.read())
            loaded = {}
            for name in ("measurements", "site", "example"):
                with open(getattr(args, name)) as f:
                    loaded[name] = json.load(f)
            require(sys.stdin.isatty(), "the root key's fingerprint is typed at the console; standard input is not a terminal")
            typed = input("The root key's SHA-256 fingerprint, read from the ceremony record (typed by hand): ")
            boot = {"image": args.image, "record": args.image_record, "initrd_pub": args.initrd_pub, "system_pub": args.system_pub,
                    "secure_boot_cert": args.secure_boot_cert, "esp": args.esp}
            commit(args.enrol_dir, chain, args.root_key, typed, loaded["measurements"], loaded["site"], loaded["example"], boot)
        except (Refused, membership.Refused, attest.Refused, OSError, ValueError, EOFError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        return 0
    if args.command == "check":
        try:
            with open(args.manifest) as f:
                envelope = membership.load(f.read())
            with open(args.measurements) as f:
                document = json.load(f)
            # TYPED, from a terminal: piped from a file, the fingerprint would be a file again (D21.2)
            require(sys.stdin.isatty(), "the root key's fingerprint is typed at the console; standard input is not a terminal")
            typed = input("The root key's SHA-256 fingerprint, read from the ceremony record (typed by hand): ")
            manifest = check_manifest(args.enrol_dir, envelope, args.root_key, typed, document)
        except (Refused, membership.Refused, OSError, ValueError, EOFError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        print("OK: the manifest (epoch %d, %s) is root-signed by the key whose fingerprint was typed, names this host "
              "as its bundle says, and commits to these measurements. Nothing was written." % (manifest["epoch"],
              membership.digest(manifest)[:16]))
        return 0
    if os.geteuid() != 0:
        print("REFUSED: enrolment runs as root, at the host's console", file=sys.stderr)
        return 2
    try:
        init(args.node_id, args.enrol_dir, args.wg_service_key)
    except (Refused, attest.Refused, OSError, ValueError) as error:       # json.JSONDecodeError is a ValueError
        print("REFUSED: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
