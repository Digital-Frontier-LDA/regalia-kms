"""regalia-node enrol, phase 1: `init` makes this host's keys, on this host, and prints what the
manifest ceremony needs to name it (#190).

    sudo python3 -Es -m deploy.baremetal.enrol init --node-id a --system-pub SYSTEM-PCR-KEY.pem
    python3 -Es -m deploy.baremetal.enrol challenge --bundle bundle.json --out CRED.bin --keep KEEP.json   (the root's side, no TPM)
    sudo python3 -Es -m deploy.baremetal.enrol activate --credential CRED.bin                      (on the node: prints the answer)
    python3 -Es -m deploy.baremetal.enrol entry --bundle bundle.json --system-pub SYSTEM-PCR-KEY.pem --keep KEEP.json --answer HEX
    gpg --decrypt ownerauth-a.yk.gpg | sudo python3 -Es -m deploy.baremetal.enrol ownerauth --node-id a --root-key ROOT \
        --record ownerauth.record.json [--check]    (after `init`, before `commit`: the TPM owner authorization, #242)

WHAT IT MAKES, each on the host and never imported (ADR-0002 D5's rule, applied to node keys):
  * the EK and a restricted signing AK, persistent in the TPM (attest.node_init, 0x81010001/0x81010002);
  * the SIGNING KEY (#199, schema v4's signing_key: signkey.py), persistent at 0x81010003, usable only under
    PolicyAuthorize of the system-phase PCR key given with --system-pub, and certified by the AK;
  * the WG-SERVICE key, /etc/regalia/wg-service.key, root 0600;
  * the WG-BOOT key, kept root 0600 in the enrolment directory until `commit` seals it to this TPM.
It READS, and records in the bundle, the serial of every hardware token the node serves from (#363), in each form a
backend pins it: its SmartCard-HSM's PKCS#11 serial, and its YubiKey's decimal serial (PIV) and OpenPGP-applet PKCS#11
serial (yubikey-openpgp), for the manifest's hsm_serials. It reads the host's SSH host key the same way, from
/etc/ssh/ssh_host_ed25519_key.pub, for ssh_host_pub (refused when missing or not Ed25519).
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
EK; the ceremony verifies it to the manufacturer's CA), both WireGuard public keys, the signing key's public
area with the AK's certification of it, and the TPM's firmware version. `entry`, on the root's machine,
checks a bundle without a TPM (signkey.verify_certification against the root's own system-phase PCR key) and
prints the node's identity fields as a v4 manifest entry carries them. Without an EK certificate, the EK Name and its SHA-256 are shown on screen, to be copied
by hand to the ceremony (the fallback the ceremony records).

WHAT IT REFUSES: a persistent object at the EK, AK or signing key handle, or a WG-SERVICE key, that this
enrolment did not make. A host that was enrolled is re-enrolled only as a new node, through replacement (#76).

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
import contextlib
import glob
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

from deploy.baremetal import attest, espcreds, measurements, membership, ownerauth, signkey

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


def _evict(handle, run, owner_auth=None):
    with ownerauth.owner_call(owner_auth) as (owner, kw):
        _run(["tpm2_evictcontrol", *owner, "-c", handle], run, text=True, **kw)


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


def identity(journal, directory, run, owner_auth=None):
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
        _evict(attest.AK_HANDLE, run, owner_auth)  # recorded right after it was created: ours, unseen
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
        with ownerauth.owner_call(owner_auth) as (owner, kw):
            _run(["tpm2_evictcontrol", *owner, "-c", ctx, attest.AK_HANDLE], run, text=True, **kw)
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


def signing_key(journal, directory, system_pub, ids, run, owner_auth=None):
    """The signing key (signkey.py) at signkey.HANDLE, made once and certified by the AK. #234's rules: an object at
    the handle is removed only when the journal recorded its Name before it was made persistent (a crash between the
    two); anything else there is refused, never evicted."""
    handle = signkey.HANDLE.lower()
    if journal.state("signing_key") == "done":
        facts = journal.get("signing_key")
        require(handle in persistent_handles(run) and _name_at(signkey.HANDLE, directory, run) == facts["signing_name"],
                "the signing key this enrolment made is no longer at %s" % signkey.HANDLE)
        require(facts["system_pkfp"] == signkey.pcr_key_fingerprint(system_pub),
                "the signing key was made for another system-phase PCR key (%s...); a host's signing key is made once"
                % facts["system_pkfp"][:16])
        return facts
    if handle in persistent_handles(run):
        recorded = journal.get("signing_key").get("signing_name") if journal.state("signing_key") == "started" else None
        require(recorded is not None and _name_at(signkey.HANDLE, directory, run) == recorded,
                "the TPM already holds a persistent object at %s, which this enrolment did not make. A host that was "
                "enrolled is re-enrolled only as a new node, through replacement (#76)" % signkey.HANDLE)
        _evict(signkey.HANDLE, run, owner_auth)  # recorded right after it was created: ours, unseen

    def record(name):
        journal.doc["steps"]["signing_key"]["signing_name"] = name         # BEFORE it is made persistent
        _atomic_json(journal.path, journal.doc)

    journal.started("signing_key")
    blob = signkey.create(system_pub, run=run, record=record, owner_auth=owner_auth)
    info, sig = signkey.certify(run=run)
    entry = signkey.verify_certification(blob, info, sig, bytes.fromhex(ids["ak_public"]), ids["ek_name"], system_pub, run=run)
    facts = {"signing_public": blob.hex(), "signing_certify": info.hex(), "signing_sig": sig.hex(), "signing_key": entry["key"],
             "signing_name": signkey.identity(blob, system_pub)[0].hex(), "system_pkfp": signkey.pcr_key_fingerprint(system_pub)}
    journal.done("signing_key", **facts)
    return facts


TOKEN_SERIAL = re.compile(r"[A-Za-z0-9]{1,32}")     # membership's hsm_serials entry
CARDCONTACT = "CardContact"                       # the SmartCard-HSM's PKCS#11 manufacturer (Nitrokey HSM 2, Pico HSM)
YUBICO_VENDOR = "1050"
# OpenSC told to use its OpenPGP card driver only: how the yubikey-openpgp backend (D26, regalia#541) sees a YubiKey
OPENPGP_ONLY = "app default {\n  card_drivers = openpgp;\n}\n"


def _pkcs11_tokens(module, run, env=None):
    """pkcs11-tool's slot listing as one dict per slot, each field taken from its own slot's block (a slot with no
    token prints no serial)."""
    done = run(["pkcs11-tool", "--module", module, "--list-token-slots"], capture_output=True, text=True, env=env)
    require(done.returncode == 0, "pkcs11-tool could not list the token slots: %s" % (done.stderr or "").strip()[-200:])
    slots, slot = [], None
    for line in done.stdout.splitlines():
        if line.startswith("Slot "):
            slot = {}
            slots.append(slot)
        elif slot is not None and ":" in line:
            key, _, value = line.partition(":")
            slot[key.strip()] = value.strip()
    return [slot for slot in slots if slot.get("serial num")]


def token_serials(module, run=subprocess.run, usb_root="/sys/bus/usb/devices"):
    """The serials of the hardware tokens this host serves from, in every form a backend pins them (#363, #72 G1), all
    read from the devices, never typed:
      * the SmartCard-HSM's PKCS#11 token serial (TokenInfo.serialNumber, trimmed): nitrokey-pkcs11. Exactly one.
      * each YubiKey's decimal serial (ykman): yubikey-piv.
      * each YubiKey's OpenPGP-applet PKCS#11 serial, as OpenSC's openpgp driver presents it: yubikey-openpgp. Measured
        2026-10-04 on YubiKey 35718625 (OpenSC 0.26, ykman 5.6.1): 000635718625, Yubico's manufacturer 0006 then the
        decimal serial, on two tokens (User PIN, User PIN (sig)). Each must be an attached YubiKey's, or it is refused.
    A YubiKey attached with no ykman to read it, or whose serial ykman cannot read, is refused rather than left out."""
    hsm = [slot["serial num"] for slot in _pkcs11_tokens(module, run) if CARDCONTACT in slot.get("token manufacturer", "")]
    require(len(hsm) == 1, "%d SmartCard-HSM tokens are attached; a node serves from exactly one (attach only its own)" % len(hsm))
    attached = 0
    for vendor in glob.glob(os.path.join(usb_root, "*", "idVendor")):
        with open(vendor) as f:
            attached += f.read().strip() == YUBICO_VENDOR
    yubikeys = []
    if shutil.which("ykman"):
        done = run(["ykman", "list", "--serials"], capture_output=True, text=True)
        require(done.returncode == 0, "ykman could not list the YubiKeys")
        yubikeys = [line.strip() for line in done.stdout.splitlines() if line.strip()]
    else:
        require(not attached, "a YubiKey is attached and ykman is not installed to read its serial: install yubikey-manager")
    # a YubiKey whose serial is hidden from USB (serial-api-visible off) lists nothing: refused, never left out (ed)
    require(len(yubikeys) == attached, "%d YubiKeys are attached and ykman read %d serials: a YubiKey's serial is not readable "
            "over USB (serial-api-visible), and it is not left out" % (attached, len(yubikeys)))
    require(all(re.fullmatch(r"[0-9]{1,8}", s) for s in yubikeys), "ykman listed a serial that is not a YubiKey's: %s" % yubikeys)
    openpgp = []
    if yubikeys:
        with tempfile.TemporaryDirectory() as conf_dir:
            conf = os.path.join(conf_dir, "opensc.conf")
            with open(conf, "w") as f:
                f.write(OPENPGP_ONLY)
            env = dict(os.environ, OPENSC_CONF=conf)
            for slot in _pkcs11_tokens(module, run, env):
                if slot["serial num"] not in openpgp:
                    openpgp.append(slot["serial num"])
        expected = {"0006%08d" % int(s) for s in yubikeys}
        require(set(openpgp) <= expected, "an OpenPGP card is attached that is not one of this host's YubiKeys (%s): attach only "
                "the node's own tokens" % ", ".join(sorted(set(openpgp) - expected)))
    serials = hsm + yubikeys + openpgp
    require(all(TOKEN_SERIAL.fullmatch(s) for s in serials), "a token serial is not one the manifest can list: %s" % serials)
    require(len(set(serials)) == len(serials), "a token serial appears twice: %s" % serials)
    return serials


def tokens(journal, module, run):
    """The token serials, journalled: read once at init, and the same tokens required at every later init."""
    serials = token_serials(module, run)
    if journal.state("tokens") == "done":
        require(journal.get("tokens")["hsm_serials"] == serials, "the tokens attached (%s) are not the ones this enrolment recorded (%s)"
                % (", ".join(serials), ", ".join(journal.get("tokens")["hsm_serials"])))
        return serials
    journal.done("tokens", hsm_serials=serials)
    return serials


SSH_HOST_KEY = "/etc/ssh/ssh_host_ed25519_key.pub"


def ssh_host_pub(path=SSH_HOST_KEY):
    """This host's SSH host key, as the manifest's ssh_host_pub carries it (membership v2: the raw Ed25519 public key,
    64 lowercase hex), read from the host's own public key file. Missing, or not ssh-ed25519, is refused."""
    try:
        with open(path) as f:
            line = f.read(4096).strip()
    except FileNotFoundError:
        raise Refused("%s is missing: this host has no Ed25519 SSH host key (ssh-keygen -A makes one)" % path)
    fields = line.split()
    require(len(fields) >= 2 and fields[0] == "ssh-ed25519", "%s is not an ssh-ed25519 public key" % path)
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except ValueError:
        raise Refused("%s does not hold a base64 key" % path)
    parts, at = [], 0
    while at < len(blob) and len(parts) < 3:
        require(at + 4 <= len(blob), "%s holds a malformed key" % path)
        (size,) = struct.unpack(">I", blob[at:at + 4])
        parts.append(blob[at + 4:at + 4 + size])
        at += 4 + size
    require(at == len(blob) and len(parts) == 2 and parts[0] == b"ssh-ed25519" and len(parts[1]) == 32,
            "%s does not hold exactly one 32-byte Ed25519 key" % path)
    return parts[1].hex()


def ssh_host(journal, path):
    """The SSH host key, journalled as the tokens are: read at init, and the same key required at every later init."""
    key = ssh_host_pub(path)
    if journal.state("ssh_host") == "done":
        require(journal.get("ssh_host")["ssh_host_pub"] == key, "this host's SSH host key (%s) is not the one this enrolment "
                "recorded (%s)" % (key, journal.get("ssh_host")["ssh_host_pub"]))
        return key
    journal.done("ssh_host", ssh_host_pub=key)
    return key


def recheck_signing_key(journal, directory, run):
    """Before `commit` writes anything: the signing key this enrolment made is still the object at its handle (its Name
    the journal recorded), and it is the one the bundle names. A key removed or replaced after `init` would otherwise
    go into a v4 manifest this TPM cannot sign for. Nothing to check for an enrolment made before #199."""
    if journal.state("signing_key") != "done":
        return
    facts = journal.get("signing_key")
    require(signkey.HANDLE.lower() in persistent_handles(run) and _name_at(signkey.HANDLE, directory, run) == facts["signing_name"],
            "the signing key this enrolment made is no longer at %s: nothing was written" % signkey.HANDLE)
    require(_bundle(directory).get("signing_key") == facts["signing_key"], "bundle.json names another signing key than the one this "
            "enrolment made: nothing was written")


ENTRY_KEYS = ("node_id", "ek_name", "ak_name", "wg_service_pub", "wg_boot_pub", "signing_key", "hsm_serials", "ssh_host_pub")
CHALLENGE_SCHEMA = "regalia.enrol-challenge/v1"


def _bundle_identity(bundle):
    """The bundle's EK and AK public areas, with their Names recomputed and required to be the ones it states."""
    require(isinstance(bundle, dict) and bundle.get("schema") == SCHEMA_BUNDLE, "not an identity bundle")
    for k in ("node_id", "ek_public", "ek_name", "ak_public", "ak_name"):
        require(isinstance(bundle.get(k), str), "the bundle has no %s" % k)
    require(NODE_ID.fullmatch(bundle["node_id"]), "the bundle's node ID is not a node ID")
    ek_public, ak_public = bytes.fromhex(bundle["ek_public"]), bytes.fromhex(bundle["ak_public"])
    require(attest.name_of(attest.public_area(ek_public, "the EK public area")).hex() == bundle["ek_name"], "the bundle's EK Name is not its EK's")
    require(attest.ak_identity(ak_public)[0].hex() == bundle["ak_name"], "the bundle's AK Name is not its AK's")
    return ek_public, ak_public


def challenge(bundle, run=subprocess.run, rand=os.urandom):
    """The root's side, no TPM: a credential to the bundle's EK and AK Name (TPM2_MakeCredential in software) and what to
    KEEP to check the answer: only the SHA-256 of the secret, never the secret. Only the TPM that holds that EK and an
    object of that AK Name under it can release the secret (enrol activate), which is what proves the AK is in the TPM
    the EK names: the AK's certification of the signing key is worth nothing without it (a software "AK" could sign any
    TPMS_ATTEST; CodeRabbit's finding on #358). This is an AK enrolment challenge, carrying nothing else, as
    attest.make_credential's invariant requires. Returns (credential bytes, keep document)."""
    ek_public, _ = _bundle_identity(bundle)
    secret = bytearray(rand(32))
    try:
        credential = attest.make_credential(ek_public, bytes.fromhex(bundle["ak_name"]), bytes(secret), run)
        keep = {"schema": CHALLENGE_SCHEMA, "node_id": bundle["node_id"], "ek_name": bundle["ek_name"], "ak_name": bundle["ak_name"],
                "secret_sha256": hashlib.sha256(secret).hexdigest()}
    finally:
        secret[:] = bytes(len(secret))
    return credential, keep


def activate(credential, run=subprocess.run):
    """On the node (root): the secret its TPM releases for `credential` under its persistent EK and AK (attest.node_activate),
    as hex, for the operator to carry back to the root's machine."""
    with tempfile.TemporaryDirectory(prefix="enrol-activate-") as d:
        path, out = os.path.join(d, "credential"), os.path.join(d, "secret")
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(credential)
        attest.node_activate(path, out, run=run)
        with open(out, "rb") as f:
            return f.read().hex()


def entry(bundle, system_pub, keep, answer, run=subprocess.run):
    """The root's side, on its own machine and without a TPM: a node's identity fields as a v4 manifest entry carries
    them, from its bundle, once everything in it that can be checked is. The EK and AK Names are recomputed from their
    public areas, and the signing key is accepted only as signkey.verify_certification accepts it: certified by THIS
    AK under THIS EK, with the attributes and the PolicyAuthorize of `system_pub` (the root's own copy of the
    system-phase PCR key, never the node's word). The EK certificate is the ceremony's to verify, as before.

    `keep` and `answer` are the AK's proof (challenge, then activate on the node): the secret only the TPM holding this EK
    and this AK could release. Without it the AK's certification proves nothing, and nothing is printed."""
    for k in ("wg_service_pub", "wg_boot_pub", "signing_public", "signing_certify", "signing_sig"):
        require(isinstance(bundle.get(k), str), "the bundle has no %s%s" % (k, ": it was made before #199" if k.startswith("signing") else ""))
    _, ak_public = _bundle_identity(bundle)
    require(isinstance(keep, dict) and keep.get("schema") == CHALLENGE_SCHEMA, "the kept challenge is not one `enrol challenge` wrote")
    require((keep.get("node_id"), keep.get("ek_name"), keep.get("ak_name")) == (bundle["node_id"], bundle["ek_name"], bundle["ak_name"]),
            "the kept challenge was made for another bundle")
    require(isinstance(answer, str) and re.fullmatch(r"[0-9a-f]{64}", answer or "") is not None, "the answer is the 64 hex `enrol activate` printed")
    import hmac
    require(hmac.compare_digest(hashlib.sha256(bytes.fromhex(answer)).hexdigest(), keep.get("secret_sha256", "")),
            "the answer is not the challenge's secret: the AK is not proven to be in the TPM this EK names")
    signing = signkey.verify_certification(bytes.fromhex(bundle["signing_public"]), bytes.fromhex(bundle["signing_certify"]),
                                           bytes.fromhex(bundle["signing_sig"]), ak_public, bundle["ek_name"], system_pub, run=run)
    wg = {k: base64.b64decode(bundle[k], validate=True).hex() for k in ("wg_service_pub", "wg_boot_pub")}
    require(all(len(v) == 64 for v in wg.values()), "a WireGuard public key is 32 bytes")
    serials = bundle.get("hsm_serials")
    require(isinstance(serials, list) and serials and all(isinstance(x, str) and TOKEN_SERIAL.fullmatch(x) for x in serials)
            and len(set(serials)) == len(serials), "the bundle has no hsm_serials, or a malformed list: it was made before #363")
    require(isinstance(bundle.get("ssh_host_pub"), str) and re.fullmatch(r"[0-9a-f]{64}", bundle["ssh_host_pub"]) is not None,
            "the bundle has no ssh_host_pub (64 hex): it was made before #371")
    return dict(zip(ENTRY_KEYS, (bundle["node_id"], bundle["ek_name"], bundle["ak_name"], wg["wg_service_pub"], wg["wg_boot_pub"], signing,
                                 list(serials), bundle["ssh_host_pub"])))


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


OPENSC_MODULE = "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"


def init(node_id, system_pub, directory=ENROL_DIR, wg_service_key=WG_SERVICE_KEY, run=subprocess.run, out=sys.stdout, module=OPENSC_MODULE,
         ssh_host_key=SSH_HOST_KEY):
    """`system_pub`: the system-phase PCR public key (PEM bytes) the signing key's policy names."""
    require(NODE_ID.fullmatch(node_id or ""), "a node ID is a lower-case name, such as a")
    signkey.pcr_key_name(system_pub)                 # an RSA-2048 PEM, before anything is made
    _safe_directory(directory)
    journal = Journal(directory, node_id)
    ids = identity(journal, directory, run)
    cert = ek_certificate(journal, directory, run)
    signing = signing_key(journal, directory, system_pub, ids, run)     # after the EK checks: nothing more is made on a refusal
    hsm_serials = tokens(journal, module, run)
    ssh_key = ssh_host(journal, ssh_host_key)
    service = wg_key(journal, "wg_service", wg_service_key, run)
    boot = wg_key(journal, "wg_boot", os.path.join(directory, "wg-boot.key"), run)
    bundle = {"schema": SCHEMA_BUNDLE, "node_id": node_id,
              "ek_public": ids["ek_public"], "ek_name": ids["ek_name"],
              "ak_public": ids["ak_public"], "ak_name": ids["ak_name"],
              "ek_certificate": cert["certificate"],
              "wg_service_pub": service, "wg_boot_pub": boot,
              "signing_public": signing["signing_public"], "signing_certify": signing["signing_certify"],
              "signing_sig": signing["signing_sig"], "signing_key": signing["signing_key"],
              "hsm_serials": hsm_serials, "ssh_host_pub": ssh_key, "tpm_firmware_version": firmware_version(run)}
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


def _check_replacement_step(envelopes, root_key, node_id, replace):
    """The step of the chain that first names `node_id`: a replacement only with `replace`, and `replace` only for one."""
    from deploy.baremetal import replacement
    previous = None
    for envelope in envelopes:
        current = membership.accept(previous, envelope, root_key)
        if node_id in membership.validate(current):
            break
        previous = current
    else:
        return                                             # not named at all: check_manifest says so next
    before = membership.validate(previous) if previous is not None else {}
    after = membership.validate(current)
    retired = sorted(n for n, entry in after.items() if n in before and before[n]["state"] not in replacement.TERMINAL
                     and entry["state"] in replacement.TERMINAL)
    if replace is None:
        require(not retired, "the manifest that first names %s (epoch %d) retires %s: it is a replacement, enrolled only with "
                "`commit --replace %s`" % (node_id, current["epoch"], ", ".join(retired), retired[0] if retired else ""))
        return
    require(previous is not None, "%s is named from epoch 1: it replaces nobody" % node_id)
    require(replace in retired, "the manifest that first names %s (epoch %d) does not replace %s%s: not the replacement typed"
            % (node_id, current["epoch"], replace, " (it retires %s)" % ", ".join(retired) if retired else ""))
    try:
        # policy_version changes with a replacement whose measurements name the new node: the documents are the
        # root's to compare (measurements.check_replacement); here the identities are asserted
        replacement._check_replacement(previous, current, replace, node_id, policy_version_may_change=True)
    except membership.Refused as refusal:
        raise Refused("the replacement of %s by %s is refused: %s" % (replace, node_id, refusal))


def check_manifest(directory, chain, root_key, typed, document, replace=None):
    """Phase 2's first step, and the only one before anything is written: `chain` (one envelope, or the list
    of envelopes from epoch 1 to N) verifies from the root-signed epoch 1 onwards under the root key whose
    fingerprint the operator typed by hand (a file alone never sets a trust anchor, ADR-0002 D21.2); its LAST
    manifest names THIS host exactly as its identity bundle says, and commits to the measurements document
    given. The first three hosts enrol on epoch 1; a host added later (a fourth node, or a replacement under
    #76) is named first at some epoch N and enrols on the whole chain to N. Returns the last manifest; writes
    nothing.

    A REPLACEMENT (#76): when the manifest that first names this host also moves a node to RETIRED or
    REVOKED_STOLEN, it is a replacement, and it is enrolled only as one: with `replace` = the old node's ID, typed
    by the operator, and replacement.check_replacement's rules on that step (the old node terminal and kept, no
    identity of any node ever listed reused, nothing else changed). A replacement is never enrolled by accident as
    a plain addition, nor an addition as a replacement of a node the operator did not name. The measurement
    document of that step is the root's ceremony to compare (measurements.check_replacement); enrolment asserts the
    identities."""
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
    _check_replacement_step(envelopes, root_key, node_id, replace)
    require(node_id in nodes, "the manifest does not name this host (%s)" % node_id)
    node = nodes[node_id]
    require(membership.CAPABILITIES[node["state"]] & {"request", "serve"},
            "the manifest names %s %s: a node in that state is not enrolled" % (node_id, node["state"]))
    wg = {k: base64.b64decode(bundle[k]).hex() for k in ("wg_service_pub", "wg_boot_pub")}
    mine_all = [("ek_name", bundle["ek_name"]), ("ak_name", bundle["ak_name"]),
                ("wg_service_pub", wg["wg_service_pub"]), ("wg_boot_pub", wg["wg_boot_pub"])]
    if "signing_key" in node:                        # v4 (#199): the key this host made and its AK certified
        require(isinstance(bundle.get("signing_key"), str), "this host's bundle has no signing key: it was made before #199")
        mine_all.append(("signing_key", {"alg": "ecdsa-p256", "key": bundle["signing_key"]}))
    if "ssh_host_pub" in node:                       # v2 on: the host key init read from this host
        require(isinstance(bundle.get("ssh_host_pub"), str), "this host's bundle has no ssh_host_pub: it was made before #371")
        mine_all.append(("ssh_host_pub", bundle["ssh_host_pub"]))
    for field, mine in mine_all:
        require(node[field] == mine, "the manifest's %s for %s is not this host's: it was made from another bundle, or "
                "for another host. Nothing was written" % (field, node_id))
    # the tokens this host read at init (#363): the manifest lists exactly them, so the daemon serves from them and no other
    require(isinstance(bundle.get("hsm_serials"), list), "this host's bundle has no hsm_serials: it was made before #363")
    require(sorted(node["hsm_serials"]) == sorted(bundle["hsm_serials"]),
            "the manifest's hsm_serials for %s (%s) are not this host's tokens (%s): the daemon would refuse to serve. Nothing was written"
            % (node_id, ", ".join(node["hsm_serials"]), ", ".join(bundle["hsm_serials"])))
    try:
        measurements.bind(manifest, document)
    except membership.Refused as refusal:            # measurements raises the same class
        raise Refused("the measurements are refused: %s" % refusal)
    return manifest


def signing_note(directory, manifest):
    """What the operator is told when this host has a signing key (#199) that the manifest does not name (a manifest
    before v4): nothing is wrong, but the key waits, and heartbeats under v4 will need it. None otherwise."""
    bundle = _bundle(directory)
    entry = {n["node_id"]: n for n in manifest["nodes"]}.get(bundle["node_id"], {})
    if isinstance(bundle.get("signing_key"), str) and "signing_key" not in entry:
        return ("NOTE: the manifest (%s) names no signing key for %s; this host's key at %s (%s...) waits for a v4 manifest, "
                "under which the nodes sign the heartbeats (#199)" % (manifest["schema"], bundle["node_id"], signkey.HANDLE, bundle["signing_key"][:18]))
    return None


NODE_JSON = "/etc/regalia/node.json"


def node_config(node_id, root_key, example, site):
    """The node configuration enrolment writes: the shipped example (deploy/baremetal/node.example.json) with
    this host's node ID, the root key whose fingerprint was typed, and the NTS servers of the validated site
    config's time.nts (#303: chrony.conf and the firewall are rendered from the same list, so the names chrony
    uses and the names authtime judges cannot differ). Checked by node.validate."""
    from deploy.baremetal import node as node_module           # imported here: node imports most of the package
    doc = dict(example, node_id=node_id, root_key=root_key, time_servers=[server["name"] for server in site["time"]["nts"]])
    node_module.validate(doc)
    return doc


CONFIG_DIR = "/etc/regalia/"
# chronyd -f, by units/chrony.service.d/regalia.conf (#303). In /etc/chrony, not CONFIG_DIR: the distribution's AppArmor
# profile for chronyd reads /etc/chrony/** and nothing else of /etc. A file of its own: Debian's chrony.conf, a package
# conffile, is never touched.
CHRONY_CONF = "/etc/chrony/regalia.conf"   # the same as authtime.CHRONY_CONF (held equal by a test)


def _same(target, digest):
    with open(target, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest() == digest


def _install(journal, step, path, data, prefix=""):
    """Write `data` to `path` (0644, root's), recording its SHA-256 in the journal, WITHOUT EVER REPLACING a file:
    the bytes go to a temporary file whose exact name is journalled first, and are published with link(2),
    which fails if the target exists (a rename would replace it silently). A file already there, or one that
    appears meanwhile, is accepted only if it is byte-for-byte what this step writes (a resumed run); anything
    else is refused and left. Enrolment never overwrites a node's configuration (re-enrolment is #76)."""
    require((path.startswith(CONFIG_DIR) or path == CHRONY_CONF) and os.path.normpath(path) == path and "\0" not in path,
            "%s is not under %s: enrolment writes configuration only there (and %s)" % (path, CONFIG_DIR, CHRONY_CONF))
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


def install_config(journal, node_id, root_key, example, site, prefix=""):
    """Phase 2's configuration: node.json and the site configuration, each where node.json says, and chrony.conf
    (#303), rendered from the site's time.nts by authtime.conf, at CHRONY_CONF, where the shipped chrony drop-in points chronyd (Debian's own
    /etc/chrony/chrony.conf, a package conffile, is never touched). Each refused if something else is already
    there. The measurements document is not configuration: commit puts it into the node's store by digest (#332)."""
    from deploy.baremetal import authtime, sitecfg
    validated = sitecfg.validate(site)
    config = node_config(node_id, root_key, example, validated)
    for key in ("site", "measurements"):
        require(config[key].startswith(CONFIG_DIR), "node.json puts %s at %s, outside %s" % (key, config[key], CONFIG_DIR))
    pretty = lambda doc: (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()        # noqa: E731
    _install(journal, "config", config["site"], pretty(site), prefix)
    _install(journal, "config", CHRONY_CONF, authtime.conf(config["time_servers"]).encode(), prefix)
    _install(journal, "config", NODE_JSON, pretty(config), prefix)
    return config


SYNC_USER = "regalia-sync"
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def first_epoch(envelopes, root_key, node_id):
    """The epoch of the first manifest of the chain that names `node_id` (None if none does). A node first named
    above epoch 1 (a replacement, or a node added later) joins a network whose heartbeats have long been running."""
    current = None
    for envelope in envelopes:
        current = membership.accept(current, envelope, root_key)
        if node_id in membership.validate(current):
            return current["epoch"]
    return None


def anchor_and_store(config_path, chain, run=subprocess.run, owner_auth=None):
    """Phase 2's trust anchors, run AS regalia-sync (the user that owns them from then on, #214): the
    membership epoch anchor (membership.HighWater: the counter, its base and the two record slots, #68),
    the store committed with the whole chain, so the anchor stands at its last epoch N, the heartbeat counter
    checked, and the signing counter (#199) defined at 0. Returns (epoch, digest of the last manifest).

    RESUMED, it never takes over indices it cannot prove are this chain's: a store that exists must load
    (Store checks it against the anchor) and be a PREFIX of `chain`, and the rest is committed; indices
    without a store are accepted only as `define` leaves them (epoch 0, the zero record), the state of an
    enrolment stopped before its first commit. Anything else is refused and left."""
    from deploy.baremetal import heartbeat, node as node_module
    with open(config_path, "rb") as f:
        cfg = node_module.validate(membership.load(f.read(node_module.MAX_BYTES + 1), node_module.MAX_BYTES))
    n = node_module.Node(cfg, run)
    envelopes = chain if isinstance(chain, list) else [chain]
    # Enrolment DEFINES the anchor (#242): under the node's approved-image policy when the signed measurements the
    # chain's last manifest commits to name a system-phase key for this node (node.define_policy; its measurements are
    # in the store already, #332), from the chain it is given, since nothing is committed yet; and it reads and writes
    # by that same policy. Owner-written when they name none.
    tip = membership.accept_chain(None, envelopes, cfg["root_key"])
    policy = lambda: node_module.define_policy(cfg, manifest=tip)
    hw = membership.HighWater(cfg["nv_epoch"], cfg["tcti"], run, lock_path=n.path("highwater.lock"), define_policy=policy,
                              image_key=lambda: node_module.image_key(cfg, manifest=tip), owner_auth=owner_auth)
    store = membership.Store(n.path("membership.json"), cfg["root_key"], hw, documents=n.documents().require_for)
    counter = heartbeat.Counter(cfg["nv_heartbeat"], cfg["tcti"], run, lock_path=n.path("heartbeat-counter.lock"), policy=policy,
                                owner_auth=owner_auth)
    # the signing counter (#199: the highest heartbeat sequence this node has signed): defined HERE, at 0, under the same
    # policy as the anchor, since a node that has signed nothing starts there
    signing = heartbeat.Counter(cfg["nv_signing"], cfg["tcti"], run, lock_path=n.path("signing-counter.lock"), define_policy=policy,
                                image_key=lambda: node_module.image_key(cfg, manifest=tip), owner_auth=owner_auth)

    def defined(owner, indices):
        return [i for i in indices if owner._tpm("nvreadpublic", i).returncode == 0]
    anchor_indices = hw._indices()
    # Every refusal before the first write: the heartbeat counter is checked BEFORE the anchor is defined or the
    # store committed, so a counter someone else advanced leaves the TPM and the store as they were.
    counter_present = defined(counter, (counter.index, counter.base_index))
    require(not counter_present or (len(counter_present) == 2 and counter.value() == 0),
            "the TPM already holds the heartbeat counter's indices (%s) at a value other than a fresh one: enrolment "
            "does not take them over" % ", ".join(counter_present))
    # The heartbeat counter is NOT defined here: first_heartbeat defines it AT the network's current sequence (or at
    # 0, only at a network's bootstrap, by the operator's --bootstrap), whenever the node enrols (#190, d9's read).
    # The signing counter is: at 0, a node new to signing. Taken over only as this step leaves it (both indices, at 0).
    signing_present = defined(signing, (signing.index, signing.base_index))
    require(not signing_present or (len(signing_present) == 2 and signing.value() == 0),
            "the TPM already holds the signing counter's indices (%s), not as an enrolment leaves them (both, at 0): "
            "enrolment does not take them over" % ", ".join(signing_present))
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
    rest = envelopes[already:]                       # what the store holds already is this chain's beginning (checked)
    for index, envelope in enumerate(rest):
        # the chain's last epoch is the one the node is left at: its measurements are in the store already (#332)
        store.commit(envelope, final=index == len(rest) - 1)
    if not signing_present:
        signing.define()                              # at 0, under the anchor's policy; written by policy from then on
    manifest = store.load()
    return manifest["epoch"], membership.digest(manifest)


def first_heartbeat(config_path, run=subprocess.run, bootstrap=False, owner_auth=None):
    """As regalia-sync (it owns the heartbeat state and the counter's lock), for a node first named above epoch 1:
    the highest heartbeat any reachable peer holds, verified under this node's manifest, taken as
    its FIRST (heartbeat.Freshness.accept_first: same checks as accept, live by authenticated time with no
    system-clock fallback, its counter defined AT that sequence with no increment loop, and its issued_at the
    held time). A `heartbeat-first` event goes to the sync trail before (INCOMPLETE) and after (ALLOW). Returns
    (sequence, seconds left); (None, None) when a heartbeat is already held (done before)."""
    from deploy.baremetal import node as node_module
    with open(config_path, "rb") as f:
        cfg = node_module.validate(membership.load(f.read(node_module.MAX_BYTES + 1), node_module.MAX_BYTES))
    n = node_module.Node(cfg, run)
    store = n.store()
    manifest = store.load()             # the store the anchor step committed, checked against the TPM anchor (the
    #                                     published chain does not exist yet: the sync service writes it)
    return take_first_heartbeat(n.node_id, manifest, store, n.freshness(owner_auth), n.sources(manifest),
                                node_module.Trail(n.path("sync-audit.jsonl")), bootstrap, note=lambda text: print("NOTE " + " ".join(text.split())))


def take_first_heartbeat(node_id, manifest, store, freshness, sources, trail, bootstrap=False, note=lambda text: None):
    """first_heartbeat's decision, given the node's parts. WHENEVER the node enrols with no heartbeat counter yet (a
    founding node whose hardware came late, a re-imaged one, a replacement: the network's heartbeats may be far past
    the jump bound), its counter is defined at the highest heartbeat a source holds that verifies under its
    manifest. At 0 only at a network's BOOTSTRAP, when no heartbeat was ever issued: the operator says so
    (`bootstrap`), and no reachable source may hold one. Returns (sequence, seconds left); (None, None) when there is
    nothing to do (a heartbeat held, or the counter defined already)."""
    from deploy.baremetal import convergence, heartbeat, sync
    counter = freshness.counter
    present = [i for i in (counter.index, counter.base_index) if counter._tpm("nvreadpublic", i).returncode == 0]
    if freshness.held() is not None:
        return None, None
    require(len(present) != 1, "the heartbeat counter is half defined (%s): that is recount.py's case, not enrolment's" % ", ".join(present))
    client = sync.Client(node_id, store, None, sources, lambda event: None)
    found, failures = [], []
    for name in sorted(sources):
        try:
            answer = client._ask(name, "pull", summary=convergence.summary(store), sequence=0)
            envelope = answer["bundle"]["heartbeat"]
            if envelope is None:
                failures.append("%s: holds none newer" % name)
                continue
            found.append((heartbeat.verify(envelope, manifest)["sequence"], name, envelope))
        except (Refused, membership.Refused, KeyError, TypeError) as refusal:
            failures.append("%s: %s" % (name, refusal))
    if len(present) == 2:
        # a counter from an earlier life of this TPM (the same board re-enrolled, an earlier commit cut after the define),
        # with no heartbeat held: fine only if it is within the jump bound of the network (regalia-kms-d9 on #279)
        # Safe to keep only when a verified heartbeat is within the jump bound of it: accept() then takes that heartbeat
        # as it would any other, and the node becomes fresh. Otherwise refused, never "nothing to do".
        value = counter.value()
        if found:
            highest = max(f[0] for f in found)
            require(highest - value <= counter.MAX_JUMP, "the TPM holds a heartbeat counter at %d with no heartbeat held, %d "
                    "behind the network's %d (more than the jump bound %d): the node would never be fresh. recount.py sets its "
                    "floor" % (value, highest - value, highest, counter.MAX_JUMP))
            return None, None
        require(bootstrap and value == 0 and manifest["epoch"] == 1,
                "the TPM holds a heartbeat counter at %d with no heartbeat held, and no source gave one to check it against (%s): "
                "run commit again once one answers, or recount.py sets its floor" % (value, "; ".join(failures) or "none reachable"))
        return None, None                     # the bootstrap's own counter, before any heartbeat exists
    event = {"event": "heartbeat-first", "node": node_id, "epoch": manifest["epoch"]}
    if not found:
        require(bootstrap, "no peer gave a heartbeat that verifies under epoch %d (%s): the node cannot start "
                "its heartbeat counter yet; run commit again once one answers (or, at a network's bootstrap, before any "
                "heartbeat was ever issued, with --bootstrap)" % (manifest["epoch"], "; ".join(failures) or "none reachable"))
        require(manifest["epoch"] == 1, "--bootstrap is the first bring-up of a cluster, under epoch 1; this manifest is epoch %d: "
                "a heartbeat has been issued since, run commit again once a source answers" % manifest["epoch"])
        # an unreachable source and one that holds none look alike from here: the operator is shown which is which
        note("bootstrap: no source gave a heartbeat. %s" % ("; ".join(failures) or "no source is configured"))
        trail(dict(event, sequence=0, outcome="INCOMPLETE", reason="bootstrap (--bootstrap): no source holds a heartbeat (%s)"
                   % ("; ".join(failures) or "no source configured")))
        counter.define()
        trail(dict(event, sequence=0, outcome="ALLOW", reason="bootstrap: the counter starts at 0"))
        return 0, None
    sequence, source, envelope = max(found, key=lambda f: f[0])
    # who signed it: the revocation key (v1 to v3), or the quorum's parties (v4, #199)
    issuer = envelope["signature"]["key"] if "signature" in envelope else ",".join(sorted(s.get("party", "?") for s in envelope.get("signatures", [])))
    event.update(sequence=sequence, issuer=issuer, source=source)
    trail(dict(event, outcome="INCOMPLETE", reason="taking the first heartbeat"))
    try:
        left = freshness.accept_first(envelope, manifest)
    except (Refused, membership.Refused) as refusal:
        trail(dict(event, outcome="DENY", reason=str(refusal)))           # the trail never ends open
        raise Refused("the first heartbeat (sequence %d, from %s) is refused: %s. Run commit again" % (sequence, source, refusal))
    trail(dict(event, outcome="ALLOW", reason=""))
    return sequence, left


def define_anchors(config_path, chain, directory, owner_auth, run=subprocess.run):
    """#419, as ROOT (enrol commit's parent), under v4: every owner-authorized definition of enrolment, so the owner
    authorization never enters a process of regalia-sync. The membership anchor (at epoch 0, the zero record) and the
    signing counter (at 0), both under the node's define policy from the chain's tip (node.define_policy: the system key
    its measurements name). Then anchor_and_store, as regalia-sync, finds them "as define leaves them" (its resumable
    state) and commits the chain by policy sessions, with no owner authorization. Locks are root's, in the enrolment
    directory: nothing else writes these indices during enrolment, and a lock file root made in regalia-sync's state
    directory would be one regalia-sync could not open. Already defined (a resumed commit): left as it is; half defined:
    refused (that is recount's case, not enrolment's). Returns what was defined."""
    from deploy.baremetal import heartbeat, node as node_module
    with open(config_path, "rb") as f:
        cfg = node_module.validate(membership.load(f.read(node_module.MAX_BYTES + 1), node_module.MAX_BYTES))
    envelopes = chain if isinstance(chain, list) else [chain]
    tip = membership.accept_chain(None, envelopes, cfg["root_key"])
    policy = lambda: node_module.define_policy(cfg, manifest=tip)
    image_key = lambda: node_module.image_key(cfg, manifest=tip)
    hw = membership.HighWater(cfg["nv_epoch"], cfg["tcti"], run, lock_path=os.path.join(directory, "define-anchor.lock"),
                              define_policy=policy, image_key=image_key, owner_auth=owner_auth)
    signing = heartbeat.Counter(cfg["nv_signing"], cfg["tcti"], run, lock_path=os.path.join(directory, "define-signing.lock"),
                                define_policy=policy, image_key=image_key, owner_auth=owner_auth)
    defined = []
    for name, held, indices in (("anchor", hw, hw._indices()), ("signing counter", signing, (signing.index, signing.base_index))):
        present = [i for i in indices if held._tpm("nvreadpublic", i).returncode == 0]
        if len(present) == len(indices):
            # a resumed commit: adopted only as this definer lays it down (HighWater._as_defined: the attributes, and an
            # authPolicy that is the node's approved-image policy), never an index planted with another (regalia-kms-d9)
            held.value()
            continue
        require(not present, "the TPM holds part of the %s's indices (%s): not as an enrolment leaves them; enrolment does not "
                "take them over" % (name, ", ".join(present)))
        held.define()
        defined.append(name)
    return defined


def probe_heartbeats(config_path, run=subprocess.run):
    """#419, as regalia-sync (it holds the sources' tunnels and its store): the heartbeat envelopes the node's sources
    hold, as they gave them, and why a source gave none. Nothing is verified here and nothing is defined: the root parent
    verifies them itself (define_first_counter), so the counter's start never rests on this process's word."""
    from deploy.baremetal import convergence, node as node_module, sync
    with open(config_path, "rb") as f:
        cfg = node_module.validate(membership.load(f.read(node_module.MAX_BYTES + 1), node_module.MAX_BYTES))
    n = node_module.Node(cfg, run)
    store = n.store()
    manifest = store.load()
    sources = n.sources(manifest)
    client = sync.Client(n.node_id, store, None, sources, lambda event: None)
    envelopes, failures = [], []
    for name in sorted(sources):
        try:
            envelope = client._ask(name, "pull", summary=convergence.summary(store), sequence=0)["bundle"]["heartbeat"]
        except (Refused, membership.Refused, KeyError, TypeError) as refusal:
            failures.append("%s: %s" % (name, refusal))
            continue
        if envelope is None:
            failures.append("%s: holds none newer" % name)
        else:
            envelopes.append({"source": name, "envelope": envelope})
    return envelopes, failures


def define_first_counter(config_path, manifest, probed, directory, owner_auth, bootstrap=False, run=subprocess.run, now=None):
    """#419, as ROOT, under v4: the heartbeat counter's one definition, from heartbeats the root parent VERIFIES ITSELF
    (heartbeat.verify under `manifest`, pure: no network, no owner authorization; regalia-kms-24). `probed` is what
    probe_heartbeats fetched, as regalia-sync: (envelopes, failures). Defined at max(highest verified sequence - 1, 0), so
    the node's own sync takes that heartbeat at its first pull, as new (one above the counter, within the jump bound).
    With nothing verified: at 0 only at a network's BOOTSTRAP (`bootstrap`, epoch 1, no source holding one); otherwise
    refused, nothing defined (a counter at 0 on a running network would strand the node past the jump bound, #279).
    Only a LIVE heartbeat counts: issued and unexpired by authenticated time (`now`, default authtime's, the check sync
    applies, Freshness._live). So a probe that withholds the newest and returns an older valid one can lower the start
    by at most one heartbeat lifetime, within the jump bound by construction; one that returns nothing live makes it
    refuse (regalia-kms-d9). Already defined: adopted only as defined here. Returns the value it was defined at, or None
    when it was there already."""
    from deploy.baremetal import heartbeat, node as node_module
    with open(config_path, "rb") as f:
        cfg = node_module.validate(membership.load(f.read(node_module.MAX_BYTES + 1), node_module.MAX_BYTES))
    counter = heartbeat.Counter(cfg["nv_heartbeat"], cfg["tcti"], run, lock_path=os.path.join(directory, "define-heartbeat.lock"),
                                define_policy=lambda: node_module.define_policy(cfg, manifest=manifest),
                                image_key=lambda: node_module.image_key(cfg, manifest=manifest), owner_auth=owner_auth)
    present = [i for i in (counter.index, counter.base_index) if counter._tpm("nvreadpublic", i).returncode == 0]
    if len(present) == 2:
        counter.value()                                    # a resumed commit: adopted only as defined here (see define_anchors)
        return None
    require(not present, "the heartbeat counter is half defined (%s): that is recount.py's case, not enrolment's" % ", ".join(present))
    envelopes, failures = probed
    verified, seconds = [], None
    for item in envelopes:
        try:
            beat = heartbeat.verify(item["envelope"], manifest)
            if seconds is None:                            # authenticated time, as sync judges a heartbeat (fail closed)
                if now is not None:
                    seconds = now()
                else:
                    n = node_module.Node(cfg, run)
                    seconds, _ = heartbeat.authenticated_now(n.clock(), n.tpm_clock(), None)
            heartbeat.Freshness._live(beat, seconds)       # issued, and not expired: an old valid one does not count
            verified.append(beat["sequence"])
        except (Refused, membership.Refused, KeyError, TypeError) as refusal:
            failures = failures + ["%s: %s" % (item.get("source", "?"), refusal)]
    if verified:
        start = max(max(verified) - 1, 0)
        counter.define_at(start)
        return start
    require(bootstrap, "no source gave a heartbeat that verifies under epoch %d (%s): the node cannot start its heartbeat counter "
            "yet; run commit again once one answers (or, at a network's bootstrap, before any heartbeat was ever issued, "
            "with --bootstrap)" % (manifest["epoch"], "; ".join(failures) or "none reachable"))
    require(manifest["epoch"] == 1, "--bootstrap is the first bring-up of a cluster, under epoch 1; this manifest is epoch %d"
            % manifest["epoch"])
    counter.define_at(0)
    return 0


def _no_sync_process(run):
    """Refused while any process of uid regalia-sync exists (regalia-kms-d9 on #418): the owner authorization handed to
    enrolment's regalia-sync step is readable by every process of that uid (/proc/<pid>/fd) while the step runs, so
    none may be there. A residual race with a process starting meanwhile stays (stated; #419 removes the handoff)."""
    done = run(["pgrep", "-u", SYNC_USER], capture_output=True, text=True)
    if done.returncode == 2 and "invalid user name" in (done.stderr or ""):
        return                                          # no such user (yet): no process of it
    require(done.returncode == 1, "a process of %s is running (%s): the owner authorization is handed to enrolment's %s step "
            "only while none is (stop regalia-sync and its services first; pgrep -u %s)" % (
                SYNC_USER, (done.stdout or "pgrep failed").split()[:5], SYNC_USER, SYNC_USER) if done.returncode == 0 else
            "cannot tell whether a process of %s is running (pgrep exit %d): the owner authorization is not handed over" % (
                SYNC_USER, done.returncode))


@contextlib.contextmanager
def _owner_fd(owner_auth, run=subprocess.run):
    """(argv, kw) handing the owner authorization to a regalia-sync step: an inherited memfd (ownerauth.child_fd) named
    by --ownerauth-fd, closed here after the step; nothing when there is none (an empty owner authorization)."""
    if owner_auth is None:
        yield [], {}
        return
    _no_sync_process(run)
    fd = ownerauth.child_fd(owner_auth)
    try:
        yield ["--ownerauth-fd", str(fd)], {"pass_fds": (fd,)}
    finally:
        os.close(fd)


def run_first_heartbeat_as_sync(config_path, run=subprocess.run, bootstrap=False, owner_auth=None):
    with _owner_fd(owner_auth, run) as (extra, kw):
        done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                    "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.enrol", "_first-heartbeat", "--config", config_path]
                   + (["--bootstrap"] if bootstrap else []) + extra,
                   cwd=PACKAGE_ROOT, capture_output=True, text=True, stdin=subprocess.DEVNULL, **kw)
    require(done.returncode == 0, "the first-heartbeat step, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    m = re.search(r"^FIRST-HEARTBEAT (\S+) (\S+)$", done.stdout, re.M)
    require(m is not None, "the first-heartbeat step did not report its result")
    for line in re.findall(r"^NOTE (.*)$", done.stdout, re.M):
        print("  " + line)                                     # to the operator at the console
    if m.group(1) == "held":
        return None, None
    return int(m.group(1)), (None if m.group(2) == "-" else float(m.group(2)))


def run_probe_as_sync(config_path, run=subprocess.run):
    """probe_heartbeats, in a process of regalia-sync (#419): (envelopes, failures), as it fetched them, unverified."""
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.enrol", "_first-heartbeat", "--config", config_path, "--probe"],
               cwd=PACKAGE_ROOT, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    require(done.returncode == 0, "the heartbeat probe, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    m = re.search(r"^PROBE (.*)$", done.stdout, re.M)
    require(m is not None, "the heartbeat probe did not report what it fetched")
    probed = membership.load(m.group(1).encode(), membership.MAX_CHAIN_BYTES)
    require(isinstance(probed, dict) and isinstance(probed.get("envelopes"), list) and isinstance(probed.get("failures"), list),
            "the heartbeat probe's report is not {envelopes, failures}")
    return probed["envelopes"], probed["failures"]


def run_as_sync(config_path, chain, run=subprocess.run, owner_auth=None):
    """anchor_and_store, in a process of regalia-sync with the tss group (the TPM), started from the package
    root so `-m` finds it. The chain goes on its standard input: the enrolment directory is root's (0700),
    and regalia-sync could not read a file there. The journal stays with the caller."""
    # env -i: nothing of root's environment reaches the step (the TCTI comes from node.json, not from here)
    with _owner_fd(owner_auth, run) as (extra, kw):
        done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                    "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.enrol", "_anchor", "--config", config_path, "--chain", "-"]
                   + extra, cwd=PACKAGE_ROOT, capture_output=True, text=True, input=membership.canonical(chain).decode(), **kw)
    require(done.returncode == 0, "the anchor step, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    m = re.search(r"^ANCHORED epoch (\d+) digest ([0-9a-f]{64})$", done.stdout, re.M)
    require(m is not None, "the anchor step did not report its result")
    return int(m.group(1)), m.group(2)


def store_documents(state, document, chown=True):
    """`document` into the measurement store of the state directory `state` (measurements.Documents), owned like the
    state directory: regalia-sync's (`chown` False in tests: the caller's). Immutable by digest: a resumed run finds
    the same file and passes."""
    from deploy.baremetal import measurements
    st = os.stat(state)
    store = measurements.Documents(os.path.join(state, measurements.STORE_DIR), owner=(st.st_uid, st.st_gid) if chown else None)
    return store.put(document)


# ---- design steps 6 and 7: the peers' AKs, and this node's LUKS path from each peer (#190) ----

ROOT_DEVICE = "/dev/disk/by-partlabel/regalia-root"      # the root volume, as the image's crypttab names it


def _ask_for(node, manifest, peer):
    """`ask(op, **fields)` to `peer` over the service tunnel (sync's transport and answer rules)."""
    from deploy.baremetal import sync
    transports = node.sources(manifest)
    require(peer in transports, "%s is not reachable over the service tunnel by this node's manifest" % peer)
    client = sync.Client(node.node_id, None, None, transports, lambda event: None)
    return lambda op, **fields: client._ask(peer, op, **fields)


def peers_to_enrol(manifest, node_id):
    """Every other node that may authorize: each must give this node a path before local.bin goes."""
    return sorted(n["node_id"] for n in manifest["nodes"] if n["node_id"] != node_id and membership.may(manifest, n["node_id"], "authorize"))


def enrol_aks(config_path, run=subprocess.run):
    """As regalia-sync (it owns the verifier's state): this node's AK into every peer's verifier, and theirs into
    its own. Returns {peer: "ok" or the refusal}; a peer that is down is named, the others go on."""
    from deploy.baremetal import enrolpeer, node as node_module
    node = node_module.Node(node_module.load(config_path), run)
    manifest = node.manifest()
    verifier = node.attester_for(manifest)
    identity, activate = enrolpeer.tpm_identity(node.tcti, run), enrolpeer.tpm_activate(node.tcti, run)
    out = {}
    for peer in peers_to_enrol(manifest, node.node_id):
        try:
            enrolpeer.enrol_aks(manifest, node.node_id, peer, _ask_for(node, manifest, peer), identity, activate, verifier)
            out[peer] = "ok"
        except (Refused, membership.Refused, attest.Refused, OSError) as refusal:
            out[peer] = str(refusal)
    return out


def run_aks_as_sync(config_path, run=subprocess.run):
    done = run(["runuser", "-u", SYNC_USER, "-g", SYNC_USER, "-G", "tss", "--", "env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL=C", sys.executable, "-Es", "-m", "deploy.baremetal.enrol", "_aks", "--config", config_path],
               cwd=PACKAGE_ROOT, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    require(done.returncode == 0, "the AK step, as %s, did not finish: %s" % (SYNC_USER, (done.stderr or done.stdout).strip()[-400:]))
    found = re.findall(r"^AK (\S+) (.*)$", done.stdout, re.M)
    require(found, "the AK step did not report")
    return dict(found)


def _quote_with(node):
    """request_path's `quote`: this node's TPM quote over its boot session, binding the enrolment key."""
    def quote(epoch, session_id, session_key, nonce, binding):
        env = dict(os.environ, TPM2TOOLS_TCTI=node.tcti) if node.tcti else None
        with tempfile.TemporaryDirectory(prefix="enrol-quote-") as d:
            paths = (os.path.join(d, "quote"), os.path.join(d, "signature"))
            attest.node_quote(node.node_id, epoch, bytes.fromhex(session_id), session_key, nonce, node.cfg["pcrs"], *paths,
                              run=lambda argv, **kw: node.run(argv, **dict(kw, **({"env": env} if env else {}))), binding=binding)
            quote_bytes, signature = (open(p, "rb").read() for p in paths)
        return {"ephemeral_public": session_key.hex(), "nonce": nonce.hex(), "quote": quote_bytes.hex(), "signature": signature.hex()}
    return quote


def enrol_paths(directory, esp, recovery, device=ROOT_DEVICE, run=subprocess.run, aks=None, out=sys.stdout, config_path=None):
    """Design steps 6 and 7 of #190, after `commit` (resumable, run again until it finishes):
      1. the AKs both ways, as regalia-sync (`aks`, default run_aks_as_sync);
      2. as root, this node's LUKS path from every peer that may authorize (enrolpeer.request_path), each
         journalled ("path:<peer>") once its keyslot opens and its token is written;
      3. only when EVERY such peer has a path IN THE HEADER (read again, not the journal's word): "paths" done in
         the journal, then local.bin overwritten and unlinked, then "local_removed" journalled. Nothing else
         removes it.
    A path the journal holds but the header no longer has (a reseal, a killed keyslot) is asked for again.
    `recovery()` returns the recovery key (typed at the console) as a bytearray, zeroed here once used.
    Returns the peers still without a path."""
    from deploy.baremetal import enrolpeer, node as node_module, unlock
    node_id = _bundle(directory)["node_id"]
    journal = Journal(directory, node_id)
    require(journal.state("seal") == "done", "the boot credentials are not sealed yet: run `enrol commit` first")
    sealed_file = os.path.join(esp, "loader", "credentials", SEALED[0][0] + espcreds.SUFFIX)
    with open(sealed_file, "rb") as f:
        sealed = f.read(1 << 20)
    require(hashlib.sha256(sealed).hexdigest() == journal.get("seal")["files"][os.path.basename(sealed_file)]["sha256"],
            "%s is not the credential this enrolment sealed" % sealed_file)
    sealed_local = "".join(sealed.decode("ascii").split())

    def without_path(peers):
        return _without_path(unlock.luks_meta(device, run), node_id, peers, sealed_local)

    if journal.state("paths") == "done" and not without_path(journal.get("paths").get("peers") or []):
        if journal.state("record") != "done":            # a crash between the two: the record is written now
            node = node_module.Node(node_module.load(config_path or NODE_JSON), run)
            write_record(journal, directory, node, node.manifest(), journal.get("paths")["peers"], run)
        _remove_local(journal, directory, without_path)
        return []
    config_path = config_path or NODE_JSON
    node = node_module.Node(node_module.load(config_path), run)
    manifest = node.manifest()
    peers = peers_to_enrol(manifest, node.node_id)
    require(peers, "no other node may authorize under epoch %d: no path can be made" % manifest["epoch"])
    ak_results = (aks or run_aks_as_sync)(config_path)
    local = local_contribution(journal, directory)
    session = node_module.boot_session(node.runtime)      # (ID hex, key): the one this boot presents to everyone
    lost = set(without_path(peers))
    key, missing, made = None, [], []
    try:
        for peer in peers:
            if journal.state("path:" + peer) == "done":
                if peer not in lost:
                    continue
                print("PATH from %s: journalled, but no longer in the header: asked for again" % peer, file=out)
            if ak_results.get(peer) != "ok":
                missing.append("%s (AK step: %s)" % (peer, ak_results.get(peer, "not reached")))
                continue
            if key is None:
                key = recovery()
            try:
                result = enrolpeer.request_path(manifest, node.node_id, peer, _ask_for(node, manifest, peer), session, _quote_with(node),
                                                local, sealed_local, device, key, run)
            except (Refused, membership.Refused, attest.Refused, OSError) as refusal:
                missing.append("%s (%s)" % (peer, refusal))
                continue
            journal.done("path:" + peer, **{k: v for k, v in result.items() if v is not None})
            made.append(peer)
            print("PATH from %s: %s" % (peer, "already in the header" if result.get("existing") else
                                        "path epoch %d, keyslot %d" % (result["path_epoch"], result["keyslot"])), file=out)
    finally:
        _zero(key)
        del key, local
    if not missing:
        missing = ["%s (journalled, but the header has no path from it)" % peer for peer in without_path(peers)]
    if missing:
        print("NOT FINISHED: no path yet from %s. local.bin stays; run `enrol paths` again once they answer" % "; ".join(missing), file=out)
        return missing
    journal.done("paths", peers=peers)
    if journal.state("record") != "done" or made:      # a path made again (the header had lost it): the record follows
        write_record(journal, directory, node, manifest, peers, run)
    _remove_local(journal, directory, without_path)
    print("ENROLLED: a path from every peer (%s); the local contribution is only sealed now" % ", ".join(peers), file=out)
    return []


RECORD_SCHEMA = "regalia.enrolment-record/v1"
RECORD_FILE = "enrolment.json"
RECORD_KEYS = ("schema", "node_id", "epoch", "manifest_digest", "root_fingerprint", "ek_name", "ak_name", "ak_public",
               "wg_service_pub", "wg_boot_pub", "nv", "espcreds", "peers", "paths", "tool", "at")


VERSION_FILE = os.path.join(PACKAGE_ROOT, "deploy", "baremetal", "VERSION")


def _tool():
    """This tool's version, for the record: the one line the package build writes to deploy/baremetal/VERSION, or
    "unknown". Never by running git: enrolment runs as root, and git in a tree another user can write would run
    that tree's configured helpers as root (regalia-kms-3e on #277)."""
    try:
        with open(VERSION_FILE, "rb") as f:
            text = f.read(129).decode("ascii", "replace").strip()
    except OSError:
        return "unknown"
    return text if re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", text) else "unknown"


def write_record(journal, directory, node, manifest, peers, run=subprocess.run, now=time.time, tool=_tool):
    """Design step 8 of #190: the enrolment record, public values only, signed by this node's AK in a TPM quote over
    its system-phase PCRs (attest.quote_document: qualifying data = the record's digest under its own label), so it
    chains to what the ceremony saw: the root key, the manifest naming this AK, the quote, the record. The `enrol`
    event (with the record's SHA-256) goes to the enrolment trail BEFORE the file is written; the journal's "record"
    step comes last. Returns the record."""
    from deploy.baremetal import node as node_module
    bundle = _bundle(directory)
    with open(os.path.join(directory, "bundle.json"), "rb") as f:
        full = membership.load(f.read(membership.MAX_BYTES + 1))
    hw = node.anchor()
    from deploy.baremetal import heartbeat
    from deploy.baremetal.node import image_policy
    counter = heartbeat.Counter(node.cfg["nv_heartbeat"], node.tcti, run, lock_path=node.path("heartbeat-counter.lock"),
                                policy=lambda: image_policy(node.cfg))      # read with the node's policy (#242)
    paths = []
    for peer in peers:
        fact = journal.get("path:" + peer)
        paths.append({"peer": peer, "path_epoch": fact.get("path_epoch"), "keyslot": fact.get("keyslot")})
    nodes = membership.validate(manifest)
    record = {"schema": RECORD_SCHEMA, "node_id": bundle["node_id"], "epoch": manifest["epoch"],
              "manifest_digest": membership.digest(manifest), "root_fingerprint": fingerprint(node.cfg["root_key"]),
              "ek_name": bundle["ek_name"], "ak_name": bundle["ak_name"], "ak_public": full["ak_public"],
              "wg_service_pub": bundle["wg_service_pub"], "wg_boot_pub": bundle["wg_boot_pub"],
              "nv": {"anchor": {"indices": list(hw._indices()), "attributes": dict(membership.HighWater.ATTRIBUTES),
                                "epoch": hw.value(), "record": list(hw.record())},
                     "heartbeat": {"index": counter.index, "base": counter.base_index}},
              "espcreds": {k: v for k, v in journal.get("espcreds").items() if k not in ("state", "at")},
              "peers": [{"peer": p, "ak_name": nodes[p]["ak_name"]} for p in peers], "paths": paths,
              "tool": tool(), "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now()))}
    payload = membership.canonical(record)
    from deploy.baremetal import trails
    trail = node_module.Trail(trails.where("enrol"))     # the registry's one path for this trail (#278)
    # requested, then the outcome (reanchor's order): a crash before the file is in place leaves INCOMPLETE, and the
    # rerun's ALLOW names the one record that exists (regalia-kms-3e on #277)
    trail({"event": "enrol", "node": record["node_id"], "epoch": record["epoch"], "manifest_digest": record["manifest_digest"],
           "outcome": "INCOMPLETE", "reason": "writing the enrolment record"})
    env = dict(os.environ, TPM2TOOLS_TCTI=node.tcti) if node.tcti else None
    with tempfile.TemporaryDirectory(prefix="enrol-record-") as d:
        qpath, spath = os.path.join(d, "quote"), os.path.join(d, "signature")
        attest.quote_document(payload, node.cfg["pcrs"], qpath, spath,
                              run=lambda argv, **kw: run(argv, **dict(kw, **({"env": env} if env else {}))))
        with open(qpath, "rb") as f:
            quote = f.read(1025)
        with open(spath, "rb") as f:
            signature = f.read(257)
    attest.verify_document(payload, bytes.fromhex(record["ak_public"]), record["ek_name"], quote, signature)
    document = {"record": record, "quote": quote.hex(), "signature": signature.hex()}
    digest = hashlib.sha256(membership.canonical(document)).hexdigest()
    _atomic_json(os.path.join(directory, RECORD_FILE), document)        # written, fsynced, renamed, directory fsynced
    os.chmod(os.path.join(directory, RECORD_FILE), 0o644)
    with open(os.path.join(directory, RECORD_FILE), "rb") as f:
        read_back = membership.load(f.read(membership.MAX_BYTES + 1))
    require(hashlib.sha256(membership.canonical(read_back)).hexdigest() == digest, "the record read back is not the one written")
    trail({"event": "enrol", "node": record["node_id"], "epoch": record["epoch"], "manifest_digest": record["manifest_digest"],
           "record_sha256": digest, "outcome": "ALLOW", "reason": ""})
    journal.done("record", sha256=digest)
    return record


def verify_record(document, chain, root_key):
    """`enrol verify-record`: the record (as written) against a root-signed manifest chain, with no TPM. The root key
    is the record's fingerprint's; the manifest at the record's epoch is in the chain with the record's digest and
    names this node with the record's EK, AK and WireGuard keys; and the quote is by that AK under that EK over
    exactly this record. Returns the quote's facts."""
    membership.exact(document, ("record", "quote", "signature"), "enrolment record")
    record = document["record"]
    membership.exact(record, RECORD_KEYS, "record")
    require(record["schema"] == RECORD_SCHEMA, "schema must be %s" % RECORD_SCHEMA)
    require(fingerprint(root_key) == record["root_fingerprint"], "the root key given is not the one the record names")
    envelopes = chain if isinstance(chain, list) else [chain]
    manifests, current = [], None
    for envelope in envelopes:
        current = membership.accept(current, envelope, root_key)
        manifests.append(current)
    at = [m for m in manifests if m["epoch"] == record["epoch"]]
    require(at and membership.digest(at[0]) == record["manifest_digest"], "the chain has no manifest at epoch %d with the record's digest" % record["epoch"])
    node = membership.validate(at[0]).get(record["node_id"])
    require(node is not None, "the manifest does not name %s" % record["node_id"])
    wg = {k: base64.b64decode(record[k]).hex() for k in ("wg_service_pub", "wg_boot_pub")}
    for field, mine in (("ek_name", record["ek_name"]), ("ak_name", record["ak_name"]), ("wg_service_pub", wg["wg_service_pub"]),
                        ("wg_boot_pub", wg["wg_boot_pub"])):
        require(node[field] == mine, "the record's %s is not the manifest's" % field)
    # the peers too: each AK the record names is the one that manifest gives that peer, so nothing in the record
    # is only its own claim (regalia-kms-1e on #277)
    every = membership.validate(at[0])
    for entry in record["peers"]:
        require(isinstance(entry, dict) and entry.get("peer") in every and entry.get("ak_name") == every[entry["peer"]]["ak_name"],
                "the record's AK for peer %r is not the manifest's" % (entry.get("peer") if isinstance(entry, dict) else entry,))
    facts = attest.verify_document(membership.canonical(record), bytes.fromhex(record["ak_public"]), record["ek_name"],
                                   bytes.fromhex(document["quote"]), bytes.fromhex(document["signature"]))
    require(facts["ak_name"] == node["ak_name"], "the record's AK public area is not the manifest's AK")
    return facts


def _without_path(meta, node_id, peers, sealed_local):
    """The peers of `peers` the LUKS2 header `meta` holds no live path from: a well-formed token for this node
    from that peer, naming a keyslot that exists, over the local half this enrolment sealed."""
    from deploy.baremetal import unlock
    keyslots = set(meta.get("keyslots") or {})
    live = set()
    for _, token in unlock.path_tokens(meta):
        try:
            unlock.validate_token(token)
        except (Refused, membership.Refused):
            continue
        if token["target"] == node_id and token["keyslots"][0] in keyslots and token["local"] == sealed_local:
            live.add(token["peer"])
    return [peer for peer in peers if peer not in live]


def _zero(buffer):
    """Overwrite a bytearray in place. Python may have copied it before (a slice, a subprocess pipe): this
    clears the one buffer this module holds, no more."""
    if isinstance(buffer, bytearray):
        buffer[:] = bytes(len(buffer))


def _remove_local(journal, directory, without_path):
    """The last step: local.bin goes only after "paths" and the record are journalled done AND the header, read again now, holds
    a path from every journalled peer (`without_path(peers)` is empty). It is overwritten with zeros, synced,
    unlinked, and the directory synced; then that is journalled. On an SSD the overwrite is best effort (the
    flash translation layer may keep the old blocks); what protects them is that the root volume is encrypted."""
    require(journal.state("paths") == "done", "local.bin is removed only once every peer's path is journalled")
    require(journal.state("record") == "done", "local.bin is removed only once the enrolment record is written")
    gone = without_path(journal.get("paths").get("peers") or [])
    require(not gone, "local.bin stays: the header has no path from %s" % ", ".join(gone))
    path = os.path.join(directory, LOCAL_FILE)
    if os.path.lexists(path):
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            size = os.fstat(fd).st_size
            os.pwrite(fd, bytes(size), 0)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.unlink(path)
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    if journal.state("local_removed") != "done":
        journal.done("local_removed")


def console_key(prompt, tty="/dev/tty"):
    """A secret typed at the console, as a bytearray: only when standard input is a terminal AND this process
    has a controlling terminal it reads from directly, with echo off. Never a pipe, a here-string or a script
    (getpass would fall back to standard input when /dev/tty cannot be opened)."""
    import termios
    require(sys.stdin.isatty(), "the recovery key is typed at the console: standard input is not a terminal")
    try:
        fd = os.open(tty, os.O_RDWR | os.O_NOCTTY)
    except OSError as error:
        raise Refused("the recovery key is typed at the console: no controlling terminal (%s)" % error.strerror) from None
    typed = bytearray()
    try:
        require(os.isatty(fd), "the recovery key is typed at the console: %s is not a terminal" % tty)
        old = termios.tcgetattr(fd)
        new = list(old)
        new[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)      # echo off and typeahead dropped, THEN the prompt
        try:
            os.write(fd, prompt.encode())
            while len(typed) <= 1024:
                chunk = os.read(fd, 1)
                if not chunk or chunk in (b"\n", b"\r"):
                    break
                typed += chunk
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
            os.write(fd, b"\n")
        require(len(typed) <= 1024, "the recovery key is longer than 1024 bytes")
        require(typed, "no recovery key was typed")
        return typed
    except BaseException:
        _zero(typed)
        raise
    finally:
        os.close(fd)


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
    """The boot image this host's sealed credentials will open in, and the key they are sealed to, taken ONLY
    from the root's chain. uki.verify checks the image against its record, both PCR keys and the Secure Boot
    certificate against the record and the image's own signatures. That proves the files given are consistent,
    not that anyone approved them: PCR 11 does not cover .pcrsig, so a re-signed copy of an approved image,
    with its own key and record, measures the same (regalia-kms-d9 on #265). So the set the measurements
    document accepts for this node (the document the root-signed manifest commits to, measurements.bind) must
    match the image's PCR 11 per phase AND name, under "signing", the very keys verified here: both PCR keys'
    pkfp and the Secure Boot certificate's SHA-256 (#267). A set without "signing" is refused: there is no
    second, typed path to trust a key. Returns the initrd-phase public key (PEM bytes) to seal to."""
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
    # what uki.verify has just proven the given files to be: the keys' pkfp and the certificate's SHA-256
    verified = {"initrd": record["signed"]["pcr_signatures"]["initrd"]["pkfp"], "system": record["signed"]["pcr_signatures"]["system"]["pkfp"],
                "secure_boot_cert": record["signed"]["secure_boot_cert_sha256"]}
    sets = measurements.validate(document).get(node_id, [])
    matched = [s for s in sets if {phase: values.get("11") for phase, values in (s.get("phases") or {}).items()} == pcr11]
    require(matched, "the measurements the manifest commits to accept no set with this image's PCR 11 (%s) for %s: "
            "the credentials would be sealed to an image this node may not run" % (
                ", ".join("%s %s" % (p, v[:16]) for p, v in sorted(pcr11.items())), node_id))
    require(any("signing" in s for s in matched), "the set the measurements accept for this image names no signing keys: the "
            "initrd key cannot be taken from the root's chain. Regenerate the set from the SIGNED record (uki.py set, #267)")
    require(any(s.get("signing") == verified for s in matched),
            "the image is signed with keys the approved set does not name (initrd %s, system %s, Secure Boot %s): a re-signed "
            "copy of an approved image is not an approved image. Nothing was sealed" % (
                verified["initrd"][:16], verified["system"][:16], verified["secure_boot_cert"][:16]))
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
    loader/credentials. Returns {file: {"sha256", "size"}} of the two sealed files as read back off the ESP: the
    part of PCR 12 a peer cannot render from the manifest and the site (espcreds.record).

    THE CLEAR COPIES. The WG-BOOT private key file is removed once its sealed copy is published (or, after a
    crash between the two, on the next run). The local contribution (local.bin) stays until the peers' LUKS
    paths are enrolled (step "paths", which removes it): they need it, and its sealed copy opens only in the
    initrd. If local.bin is gone before then, the sealed copy could never be paired with a path, so it is made
    again and resealed: this enrolment's unlock-local.cred (by its journalled digest) is replaced, and the
    returned record changes with it (no stranding)."""
    directory_esp = os.path.join(esp, "loader", "credentials")
    local_path = os.path.join(directory, LOCAL_FILE)
    unlock_file = SEALED[0][0] + espcreds.SUFFIX
    if journal.state("local") == "done" and not os.path.lexists(local_path) and journal.state("paths") != "done":
        # ORDER: a reseal changes PCR 12, so it is possible only before the enrolment record publishes the sealed
        # files' digests to the peers (the record comes after "paths"; regalia-kms-d9 on #265)
        require(journal.state("record") is None, "local.bin is gone after the enrolment record was written: resealing now would "
                "change the PCR 12 the peers expect. This is a re-enrolment (#76)")
        target = os.path.join(directory_esp, unlock_file)
        facts = {k: v for k, v in journal.get("seal").items() if k not in ("state", "at")}
        recorded = ((facts.get("files") or {}).get(unlock_file, {}).get("sha256") or facts.get(unlock_file)
                    or facts.get("pending:" + unlock_file))     # published, then a crash before the digest moved
        if os.path.lexists(target):
            with open(target, "rb") as f:
                require(recorded is not None and hashlib.sha256(f.read(1 << 20)).hexdigest() == recorded,
                        "%s is not the one this enrolment sealed, and local.bin is gone: remove it by hand" % target)
            os.unlink(target)
        journal.doc["steps"].pop("local")
        kept = {k: v for k, v in facts.items() if k != "files" and not k.endswith(unlock_file)}
        kept.update({f: v["sha256"] for f, v in (facts.get("files") or {}).items() if f != unlock_file})
        _journal_facts(journal, "seal", kept)    # sealed again below, from a new contribution
    if journal.state("seal") == "done":
        files = journal.get("seal")["files"]
        for filename, fact in files.items():
            path = os.path.join(directory_esp, filename)
            with open(path, "rb") as f:
                require(hashlib.sha256(f.read(1 << 20)).hexdigest() == fact["sha256"], "%s changed since this enrolment sealed it" % path)
    else:
        _ensure_trusted_dir(directory_esp)
        if journal.state("seal") is None:
            _journal_facts(journal, "seal", {})
        boot_key = journal.get("wg_boot")["path"]
        for name, source in SEALED:
            filename = name + espcreds.SUFFIX
            if os.path.lexists(os.path.join(directory_esp, filename)):
                _publish_esp(journal, "seal", directory_esp, filename, None)    # ours (journalled) is kept; anything else refused
                continue
            if source == "local":
                plain = local_contribution(journal, directory)
            else:
                with open(boot_key, "rb") as f:
                    plain = f.read(4096)
                require(WG_KEY.fullmatch(plain.decode("ascii", "replace").strip()), "%s does not hold a WireGuard key" % boot_key)
            _publish_esp(journal, "seal", directory_esp, filename, _seal(name, plain, initrd_pub, run))
        files = {}
        for name, _ in SEALED:
            filename = name + espcreds.SUFFIX
            with open(os.path.join(directory_esp, filename), "rb") as f:
                data = f.read(1 << 20)
            files[filename] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        journal.done("seal", files=files)
    boot_key = journal.get("wg_boot").get("path")
    if boot_key and os.path.lexists(boot_key):
        os.unlink(boot_key)              # sealed and published: the clear copy goes
    return files


RENDERED_DIRS = ("loader/credentials/", "EFI/regalia/")   # where bootcreds.esp_files may write or remove, at any B3 stage


def _rendered_path(path):
    """`path` from esp_files, normalized and confined: under loader/credentials/ or EFI/regalia/ (FAT compares names
    without case), never absolute, never climbing out."""
    require(isinstance(path, str) and path and "\0" not in path, "bootcreds named %r" % (path,))
    relative = os.path.normpath(path.lstrip("/"))
    require(not os.path.isabs(relative) and relative != ".." and not relative.startswith("../")
            and any((os.path.dirname(relative) + "/").lower() == d.lower() for d in RENDERED_DIRS),   # one level, no deeper
            "bootcreds named %r, outside %s" % (path, " and ".join(RENDERED_DIRS)))
    return relative


def _replace_esp(directory, filename, data):
    """A RENDERED file (public, re-derivable from the anchored chain) written over whatever is there: a temporary
    file in the same directory, fsynced, renamed onto the name, the directory fsynced. The sealed files are never
    replaced (_publish_esp); a rendered one must be, after every manifest change (regalia-kms-ed on #276)."""
    target, tmp = os.path.join(directory, filename), os.path.join(directory, "." + filename + ".enrol-new")
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, target)
    dfd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def render_credentials(journal, esp, site, chain, root_key, anchor, device=None):
    """The ESP files rendered from the anchored chain and the site (bootcreds.esp_files, #271: the ONE call enrol and
    the update path make; what it returns depends on #66's B3 stage, so its paths are taken as they come, confined
    to RENDERED_DIRS). {path: bytes} is written, replacing what is there (public, re-derivable: a resumed enrolment
    whose manifest moved on is not stranded); {path: None} is removed if present (the B3 switch retires files the
    peers no longer expect). Each is journalled. Then the record of EVERY credential the stub will measure
    (espcreds.record over loader/credentials as uki reads it): the PCR 12 the peers must expect, journalled as
    "espcreds". A chain the TPM did not anchor is refused by esp_files before anything is written."""
    from deploy.baremetal import bootcreds, uki
    envelopes = chain if isinstance(chain, list) else [chain]
    files = bootcreds.esp_files(site, envelopes, root_key, device or "/dev/disk/by-partlabel/regalia-root", anchor)
    planned = sorted((_rendered_path(path), data) for path, data in files.items())
    require(all(data is None or isinstance(data, bytes) for _, data in planned), "bootcreds gave something that is neither bytes nor None")
    journal.started("render")
    done = {}
    for relative, data in planned:
        directory, filename = os.path.join(esp, os.path.dirname(relative)), os.path.basename(relative)
        _ensure_trusted_dir(directory)
        target = os.path.join(directory, filename)
        if data is None:
            removed = False
            for name in (target, os.path.join(directory, "." + filename + ".enrol-new")):    # and a crash's leftover
                if os.path.lexists(name):
                    require(not os.path.islink(name) and os.path.isfile(name), "%s is not a regular file" % name)
                    os.unlink(name)
                    removed = True
            if removed:                                 # durable: a retired credential must not come back after a power cut
                dfd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            done[relative] = None
        else:
            _replace_esp(directory, filename, data)
            done[relative] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    journal.done("render", files=done)
    record = espcreds.record(uki.credential_files(esp))
    journal.done("espcreds", **record)
    return record


def commit_owner_auth(manifest, given, root_key, node_id, run=subprocess.run):
    """The owner authorization enrolment commits with (#242): `given` (Auth, record), read from standard input before
    the fingerprint was typed, judged against the record under `root_key` (the typed fingerprint's by now). Under v4
    (production) the TPM's owner and lockout authorizations must both be SET, and the value given: refused otherwise,
    before anything is written. None: an empty owner authorization (a v1-v3 lab chain without --ownerauth)."""
    owner_auth = None if given is None else ownerauth.confirm(given[0], given[1], root_key, node_id)
    if manifest["schema"] == membership.SCHEMA_V4:
        ownerauth.require_production(run=run)
        require(owner_auth is not None, "under %s the TPM's owner authorization is set and enrolment takes it from this "
                "node's envelope: gpg --decrypt ownerauth-%s.yk.gpg | enrol commit ... --ownerauth ownerauth.record.json"
                % (membership.SCHEMA_V4, node_id))
    return owner_auth


def commit(directory, chain, root_key, typed, document, site, example, boot=None, run=subprocess.run, prefix="", as_sync=None,
           out=sys.stdout, replace=None, first_beat=None, bootstrap=False, ownerauth_given=None, probe=None):
    """Phase 2 (#190): this host's TPM identity re-checked by Name, the manifest chain checked again (never trusted
    from an earlier `check`), the boot image checked (approved_image), the configuration installed, the state
    directory made regalia-sync's, the anchor, the store and the heartbeat counter set up AS regalia-sync, and the
    two boot credentials sealed onto the ESP. `boot` = {"image", "record", "initrd_pub", "system_pub",
    "secure_boot_cert", "esp"}; the CLI always gives it, and only tests of the earlier steps leave it out, which
    stops after the anchors. The peers' paths and the enrolment record follow in later steps.
    `ownerauth_given`: (ownerauth.Auth, ownerauth.record.json) as read from standard input before the operator typed the
    root's fingerprint; judged here once that fingerprint has confirmed the root key, before anything is written. Under
    v4 the TPM's owner and lockout authorizations must both be set (#242: ownerauth.require_production).
    Under v4 every owner-authorized step is THIS process's (#419): define_anchors before the regalia-sync step, which
    then commits by policy with no owner authorization, and define_first_counter after the sync step's heartbeat probe
    (`probe`, default run_probe_as_sync), from heartbeats this process verifies itself. v1-v3 (a lab chain): as before."""
    journal = Journal(directory, _bundle(directory)["node_id"])
    require(journal.state("identity") == "done", "this host has no identity yet: run `enrol init` first")
    identity(journal, directory, run)                               # a done identity is re-checked by Name at both handles
    recheck_signing_key(journal, directory, run)                    # and the signing key at its own (#199; CodeRabbit on #358)
    manifest = check_manifest(directory, chain, root_key, typed, document, replace)
    owner_auth = commit_owner_auth(manifest, ownerauth_given, root_key, journal.doc["node_id"], run)
    note = signing_note(directory, manifest)
    if note:
        print(note, file=out)
    initrd_pub = None
    if boot is not None:                                            # checked before anything is written
        initrd_pub = approved_image(boot["image"], boot["record"], boot["initrd_pub"], boot["system_pub"],
                                    boot["secure_boot_cert"], document, journal.doc["node_id"], run)
    config = install_config(journal, journal.doc["node_id"], root_key, example, site, prefix)
    _hand_over(prefix + config["state_dir"], as_sync is None)
    # the measurements document the manifest commits to, into the node's store by digest (#332), regalia-sync's,
    # before the anchor: the store commits no epoch whose document it does not hold
    store_documents(prefix + config["state_dir"], document, as_sync is None)
    journal.started("anchor")
    production = manifest["schema"] == membership.SCHEMA_V4
    if production:                                  # #419: the owner's definitions here, as root; the sync step gets none
        # no regalia-sync process meanwhile: its service's locks are not these, so only that keeps its writers out
        # while root defines (regalia-kms-d9); it was also the handoff's guard
        _no_sync_process(run)
        defined = define_anchors(prefix + NODE_JSON, chain, directory, owner_auth, run)
        if defined:
            print("DEFINED as root, under the node's policy: %s" % ", ".join(defined), file=out)
    owner = {} if owner_auth is None or production else {"owner_auth": owner_auth}   # a lab chain's owner-written writes
    epoch, digest = (as_sync or run_as_sync)(prefix + NODE_JSON, chain if isinstance(chain, list) else [chain], **owner)
    require(epoch == manifest["epoch"] and digest == membership.digest(manifest),
            "the anchor stands at epoch %d (%s), not at the manifest checked (%d)" % (epoch, digest[:16], manifest["epoch"]))
    journal.done("anchor", epoch=epoch, digest=digest)
    if journal.state("heartbeat_first") != "done":
        # the heartbeat counter starts AT the network's current sequence whenever the node enrols (#190), at 0 only at
        # the network's bootstrap (--bootstrap)
        journal.started("heartbeat_first")
        if production:                              # #419: fetched as regalia-sync, verified and defined here
            probed = (probe or run_probe_as_sync)(prefix + NODE_JSON)
            start = define_first_counter(prefix + NODE_JSON, manifest, probed, directory, owner_auth, bootstrap, run)
            sequence, left = start, None
            print("FIRST HEARTBEAT: %s" % ("the counter was defined already" if start is None else
                                          "the counter defined at %d, by this process from heartbeats it verified; the node's "
                                          "sync takes the next at its first pull" % start), file=out)
        else:
            sequence, left = (first_beat or run_first_heartbeat_as_sync)(prefix + NODE_JSON, bootstrap=bootstrap, **owner)
        journal.done("heartbeat_first", sequence=sequence, bootstrap=bool(bootstrap and sequence == 0 and left is None))
        if not production:
            print("FIRST HEARTBEAT: %s" % ("nothing to do (a heartbeat held, or the counter defined)" if sequence is None else
                                          "network bootstrap: the counter starts at 0" if left is None else
                                          "sequence %d, the counter defined at it; live for %.0f s more" % (sequence, left)), file=out)
    print("ENROLLED (trust anchors): node %s, membership epoch %d (%s) anchored in the TPM and committed as %s"
          % (journal.doc["node_id"], epoch, digest[:16], SYNC_USER), file=out)
    if boot is not None:
        files = seal_credentials(journal, directory, boot["esp"], initrd_pub, run)
        print("SEALED to this TPM and the initrd key, on the ESP: %s" % ", ".join(
            "%s (sha256 %s, %d bytes)" % (f, v["sha256"][:16], v["size"]) for f, v in sorted(files.items())), file=out)
        from deploy.baremetal import node as node_module
        anchor = node_module.Node(node_module.load(prefix + NODE_JSON), run).anchor()
        record = render_credentials(journal, boot["esp"], site, chain, root_key, anchor)
        print("RENDERED the boot credentials onto the ESP; PCR 12 the peers must expect: %s (from %s)" % (
            record["pcr12"], ", ".join(c["file"] for c in record["credentials"])), file=out)
        print("NOT FINISHED: the local contribution stays in %s until the peers' LUKS paths are enrolled: run "
              "`enrol paths` next; the host cannot unlock unattended before then" % os.path.join(directory, LOCAL_FILE), file=out)
    return epoch, digest


def enrolled_ek_name(directory, node_id):
    """The Name (hex) of the EK `enrol init` recorded for this host: what the owner authorization's salted session is
    salted to (#414). Refused before init has run (or finished)."""
    journal = Journal(directory, node_id)
    require(journal.state("identity") == "done", "%s has no finished identity step: run `enrol init` first (its EK salts "
            "the session the owner authorization is set in)" % directory)
    return journal.get("identity")["ek_name"]


def set_ownerauth(node_id, root_key, record_path, stream, check=False, tcti=None, run=subprocess.run, directory=ENROL_DIR,
                  ek_name=None):
    """`enrol ownerauth` (#242 step C): this TPM's owner authorization from the node's envelope, the value on `stream`
    (gpg --decrypt ownerauth-<node>.yk.gpg | ...), checked against ownerauth.record.json verified under the pinned
    root BEFORE the TPM is touched. Sets it from EMPTY only (ownerauth.set_owner refuses one already set, never
    overwriting it). `check`: changes nothing, and proves in ONE owner-authorized call that the TPM's owner
    authorization is this node's envelope value. The value is set in a session salted to the EK `enrol init` recorded
    (`ek_name`, else read from `directory`'s journal; #414). Returns what to print."""
    with open(record_path, "rb") as f:
        envelope = membership.load(f.read(membership.MAX_BYTES + 1), membership.MAX_BYTES)
    auth = ownerauth.from_envelope(stream, envelope, root_key, node_id)
    if check:
        require(ownerauth.posture(tcti, run)["owner"], "the TPM's owner authorization is empty: nothing to check; set it "
                "(this command without --check)")
        require(ownerauth.holds(auth, tcti, run), "the TPM's owner authorization is NOT %s's envelope value: this TPM was "
                "provisioned otherwise, or the envelope is another node's. Nothing was changed" % node_id)
        return "the TPM's owner authorization is %s's envelope value" % node_id
    ownerauth.set_owner(auth, ek_name or enrolled_ek_name(directory, node_id), tcti, run)
    return "the TPM's owner authorization is set to %s's envelope value, and answers to it; keep the envelope, never the value" % node_id


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.enrol", description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="make this host's keys and print its identity bundle")
    p.add_argument("--node-id", required=True)
    p.add_argument("--enrol-dir", default=ENROL_DIR)
    p.add_argument("--wg-service-key", default=WG_SERVICE_KEY)
    p.add_argument("--pkcs11-module", default=OPENSC_MODULE, help="the PKCS#11 module that reads the SmartCard-HSM's serial")
    p.add_argument("--system-pub", required=True, help="the system-phase PCR key's public half (PEM): the signing key is usable "
                   "only under PCR 11 policies it signed")
    o = sub.add_parser("ownerauth", help="set this TPM's owner authorization from the node's envelope, on standard input (#242)")
    o.add_argument("--node-id", required=True)
    o.add_argument("--root-key", required=True, help="the membership root's public key, 64 hex: the record is verified under it")
    o.add_argument("--record", required=True, help="the ceremony's ownerauth.record.json")
    o.add_argument("--check", action="store_true", help="change nothing: prove the TPM's owner authorization is this envelope's")
    o.add_argument("--enrol-dir", default=ENROL_DIR, help="the enrolment directory: the EK `init` recorded salts the session")
    g = sub.add_parser("challenge", help="(the root's side, no TPM) a credential to the bundle's EK and AK, for `activate`")
    g.add_argument("--bundle", required=True)
    g.add_argument("--out", required=True, help="the credential, to carry to the node")
    g.add_argument("--keep", required=True, help="what the root's machine keeps: the secret's SHA-256, never the secret")
    a = sub.add_parser("activate", help="(on the node, root) the secret its TPM releases for the root's credential")
    a.add_argument("--credential", required=True)
    e = sub.add_parser("entry", help="(the root's side, no TPM) check a bundle and print the node's v4 identity fields")
    e.add_argument("--bundle", required=True)
    e.add_argument("--system-pub", required=True, help="the root's own copy of the system-phase PCR key's public half (PEM)")
    e.add_argument("--keep", required=True, help="the file `challenge` kept")
    e.add_argument("--answer", required=True, help="the 64 hex `activate` printed on the node")
    c = sub.add_parser("check", help="check the root-signed manifest against this host, writing nothing")
    c.add_argument("--manifest", required=True, help="the root-signed epoch-1 envelope, or a JSON list of the "
                   "envelopes from epoch 1 to the one that first names this host")
    c.add_argument("--root-key", required=True, help="the membership root's public key, 64 hex")
    c.add_argument("--measurements", required=True, help="the measurements document the manifest commits to")
    c.add_argument("--enrol-dir", default=ENROL_DIR)
    c.add_argument("--replace", metavar="OLD_NODE_ID", help="this host replaces that node (#76): the manifest must say so")
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
    k.add_argument("--replace", metavar="OLD_NODE_ID", help="this host replaces that node (#76): the manifest must say so")
    ownerauth.add_arguments(k)
    k.add_argument("--bootstrap", action="store_true", help="the network has issued no heartbeat yet: start the counter at 0 "
                   "if no reachable peer holds one")
    h = sub.add_parser("_first-heartbeat", help=argparse.SUPPRESS)
    h.add_argument("--config", required=True)
    h.add_argument("--bootstrap", action="store_true")
    h.add_argument("--ownerauth-fd", type=int, help=argparse.SUPPRESS)     # commit's memfd (_owner_fd): commit verified it
    h.add_argument("--probe", action="store_true", help=argparse.SUPPRESS)  # #419: fetch only; commit verifies and defines
    q = sub.add_parser("paths", help="the peers' AKs and this node's LUKS path from each peer; then local.bin goes")
    q.add_argument("--esp", required=True, help="the ESP's mount point (the sealed unlock-local credential is read from it)")
    q.add_argument("--device", default=ROOT_DEVICE)
    q.add_argument("--enrol-dir", default=ENROL_DIR)
    v = sub.add_parser("verify-record", help="check an enrolment record against the root-signed chain (no TPM needed)")
    v.add_argument("--record", required=True)
    v.add_argument("--manifest", required=True, help="the root-signed envelope, or the JSON list of envelopes from epoch 1")
    v.add_argument("--root-key", required=True, help="the membership root's public key, 64 hex")
    x = sub.add_parser("_aks", help=argparse.SUPPRESS)
    x.add_argument("--config", required=True)
    a = sub.add_parser("_anchor", help=argparse.SUPPRESS)
    a.add_argument("--config", required=True)
    a.add_argument("--chain", required=True, choices=["-"], help="always -: the chain comes on standard input")
    a.add_argument("--ownerauth-fd", type=int, help=argparse.SUPPRESS)     # commit's memfd (_owner_fd): commit verified it
    args = ap.parse_args(argv)
    if args.command == "ownerauth":
        try:
            ownerauth.measured_once()             # the value stays off the TPM bus only on measured tools (#414)
            print(set_ownerauth(args.node_id, args.root_key, args.record, sys.stdin.buffer, check=args.check, directory=args.enrol_dir))
        except (Refused, membership.Refused, OSError, ValueError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        return 0
    if args.command == "verify-record":
        try:
            with open(args.record, "rb") as f:
                document = membership.load(f.read(membership.MAX_BYTES + 1))
            with open(args.manifest, "rb") as f:
                chain = membership.load(f.read(membership.MAX_CHAIN_BYTES + 1), membership.MAX_CHAIN_BYTES)
            facts = verify_record(document, chain, args.root_key)
        except (Refused, membership.Refused, attest.Refused, OSError, ValueError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        record = document["record"]
        # only what was checked: the quote's PCR VALUES are not in it (only their digest), so the record's expected PCR 12
        # is the record's claim, not something this verification shows
        print("VERIFIED: node %s enrolled on epoch %d (manifest %s); the record is signed by its AK %s, the manifest's, under its "
              "EK, in a quote over PCRs %s (TPM reset count %d)"
              % (record["node_id"], record["epoch"], record["manifest_digest"][:16], facts["ak_name"][:20],
                 ",".join(str(p) for p in facts["pcrs"]), facts["reset_count"]))
        return 0
    if args.command == "_aks":                       # run by paths, as regalia-sync
        try:
            results = enrol_aks(args.config)
        except (Refused, membership.Refused, attest.Refused, OSError, ValueError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        for peer, result in sorted(results.items()):
            print("AK %s %s" % (peer, " ".join(str(result).split())))
        return 0
    if args.command == "paths":
        if os.geteuid() != 0:
            print("REFUSED: enrolment runs as root, at the host's console", file=sys.stderr)
            return 2

        def recovery():
            # the recovery key from the console only: never argv, the environment, a pipe, a file or the journal
            return console_key("The recovery key of this host's root volume (from its card; not shown): ")
        try:
            missing = enrol_paths(args.enrol_dir, args.esp, recovery, args.device)
        except (Refused, membership.Refused, attest.Refused, OSError, ValueError, EOFError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        return 3 if missing else 0
    if args.command == "_first-heartbeat" and args.probe:   # run by commit, as regalia-sync (#419): fetch, never define
        try:
            envelopes, failures = probe_heartbeats(args.config)
        except (Refused, membership.Refused, OSError, ValueError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        print("PROBE %s" % membership.canonical({"envelopes": envelopes, "failures": failures}).decode())
        return 0
    if args.command == "_first-heartbeat":           # run by commit, as regalia-sync
        try:
            owner_auth = None if args.ownerauth_fd is None else ownerauth.read_fd(args.ownerauth_fd)
            sequence, left = first_heartbeat(args.config, bootstrap=args.bootstrap, owner_auth=owner_auth)
        except (Refused, membership.Refused, OSError, ValueError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        print("FIRST-HEARTBEAT held -" if sequence is None else "FIRST-HEARTBEAT %d %s" % (sequence, "-" if left is None else "%.0f" % left))
        return 0
    if args.command == "_anchor":                    # run by commit, as regalia-sync
        try:
            chain = membership.load(sys.stdin.buffer.read(membership.MAX_CHAIN_BYTES + 1), membership.MAX_CHAIN_BYTES)
            owner_auth = None if args.ownerauth_fd is None else ownerauth.read_fd(args.ownerauth_fd)
            epoch, digest = anchor_and_store(args.config, chain, owner_auth=owner_auth)
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
            # the envelope's value FIRST, on standard input (gpg asks for the card's PIN on the console and exits), judged
            # once the fingerprint is typed; then the fingerprint, at the terminal
            given = ownerauth.read_arguments(args)
            if given is not None:
                ownerauth.measured_once()         # the value stays off the TPM bus only on measured tools (#414)
            prompt = "The root key's SHA-256 fingerprint, read from the ceremony record (typed by hand): "
            if given is not None:
                typed = ownerauth.console(prompt)
                require(typed is not None, "no fingerprint was typed")
            else:
                require(sys.stdin.isatty(), "the root key's fingerprint is typed at the console; standard input is not a terminal")
                typed = input(prompt)
            boot = {"image": args.image, "record": args.image_record, "initrd_pub": args.initrd_pub, "system_pub": args.system_pub,
                    "secure_boot_cert": args.secure_boot_cert, "esp": args.esp}
            commit(args.enrol_dir, chain, args.root_key, typed, loaded["measurements"], loaded["site"], loaded["example"], boot,
                   replace=args.replace, bootstrap=args.bootstrap, ownerauth_given=given)
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
            manifest = check_manifest(args.enrol_dir, envelope, args.root_key, typed, document, args.replace)
        except (Refused, membership.Refused, OSError, ValueError, EOFError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        print("OK: the manifest (epoch %d, %s) is root-signed by the key whose fingerprint was typed, names this host "
              "as its bundle says, and commits to these measurements. Nothing was written." % (manifest["epoch"],
              membership.digest(manifest)[:16]))
        note = signing_note(args.enrol_dir, manifest)
        if note:
            print(note)
        return 0
    if args.command == "challenge":
        try:
            with open(args.bundle, "rb") as f:
                credential, keep = challenge(membership.load(f.read(membership.MAX_BYTES + 1)))
            for path, data in ((args.out, credential), (args.keep, json.dumps(keep, sort_keys=True).encode())):
                with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                    f.write(data)
        except (Refused, membership.Refused, attest.Refused, OSError, ValueError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        print("WRITTEN: the credential %s (to the node: enrol activate) and the kept hash %s" % (args.out, args.keep))
        return 0
    if args.command == "activate":
        try:
            with open(args.credential, "rb") as f:
                print("ANSWER %s" % activate(f.read(4096)))
        except (Refused, attest.Refused, OSError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        return 0
    if args.command == "entry":
        try:
            with open(args.bundle, "rb") as f:
                document = membership.load(f.read(membership.MAX_BYTES + 1))
            with open(args.keep, "rb") as f:
                keep = membership.load(f.read(4096))
            with open(args.system_pub, "rb") as f:
                print(json.dumps(entry(document, f.read(65536), keep, args.answer), indent=1, sort_keys=True))
        except (Refused, membership.Refused, attest.Refused, OSError, ValueError, KeyError, TypeError) as error:
            print("REFUSED: %s" % error, file=sys.stderr)
            return 1
        return 0
    if os.geteuid() != 0:
        print("REFUSED: enrolment runs as root, at the host's console", file=sys.stderr)
        return 2
    try:
        with open(args.system_pub, "rb") as f:
            init(args.node_id, f.read(65536), args.enrol_dir, args.wg_service_key, module=args.pkcs11_module)
    except (Refused, attest.Refused, OSError, ValueError) as error:       # json.JSONDecodeError is a ValueError
        print("REFUSED: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
