"""testgenesis: ALL the staging TEST genesis material of a single-node genesis, from a named TEST membership root
(regalia-kms-223; the GA's ruling of 2026-11-25 for regalia-kms-dx7.14's staging run). TEST ONLY.

    python3 -Es -m deploy.baremetal.testgenesis --root-key HEX --root-pk8 TEST-root.pk8.pem --out DIR \\
        --node-id NODE --host-ipv4 A.B.C.D --prefix N --gateway A.B.C.D --nic-mac aa:bb:cc:dd:ee:ff \\
        --boot-address 10.89.0.1 --owner-underlay A.B.C.D --owner-address 10.89.0.9 \\
        --client-cidr CIDR --monitoring-cidr CIDR --admin-cidr CIDR --audit CIDR:tcp:PORT [--outbound NAME=CIDR:PROTO:PORT]... \\
        --nts NAME=CIDR[,CIDR...] --nts ... --site SITE \\
        --build-record SIGNED-RECORD.json --pcrs PCRS.json --tpm-firmware-version HEX16 --device /dev/... \\
        [--owner-recipient PRIMARY:SUBKEY --owner-recipient PRIMARY:SUBKEY]

deploy.baremetal only VERIFIES the genesis records (manifest.card_record_keys, manifest.offline_keys_record,
ownerauth.verify, cardrecord.verify); their writers are regalia-ceremony's offline-keys.py, which signs with the
sealed offline root. A staging box under a TEST root needs the same records signed by THAT root, and this is the
one reviewed writer of them. Every record is in the exact form its verifier reads, and every output is verified
by the existing verifier, from disk, before the tool says it is done.

WHAT IT WRITES, into DIR (created 0700, or an existing EMPTY directory of this user's, made 0700; a non-empty one, a
link or another user's is refused). Every file is 0600 and every name says TEST (the signing state's two files keep
the names manifest.py and cardrecord.py read; their directory says TEST):
  TM-3  TEST-cards.record.json            the card ceremony record (regalia.card-ceremony-record/v1), signed by the root:
                                          the two owner "cards'" Ed25519 keys, the release card's, ownerauth_recipients,
                                          ssh_signers; sequence 1, supersedes ""
        TEST-signing-state/               the laptop state directory (0700) manifest sign --state-dir and
                                          manifest.card_record_keys read: regalia-signing-state.json (the marker naming
                                          the root) and signing-record.jsonl (the card-record line 1, its digest)
  TM-4  TEST-offline-keys.record.json     the offline-keys generation record (regalia.offline-keys-record/v1, event
                                          generate), signed by the root, naming K_A; TEST-anchor-policy.p256.pk8.pem (K_A)
  TM-5  TEST-ownerauth.record.json        the owner-authorization record (regalia.ownerauth-record/v1), and
        TEST-ownerauth-NODE.value         the node's value: 64 lowercase hex and a newline (ownerauth.read_value's form)
  TM-6  TEST-owner-main.ed25519.pk8.pem, TEST-owner-backup.ed25519.pk8.pem    the owner "cards'" keys as plain files
        TEST-release.ed25519.pk8.pem, TEST-ssh-owner-{main,backup}.key/.pub   the release and SSH signer keys
        TEST-owner-recipients.txt         the two --recipient values owner.py contribute takes (the decryption subkeys)
  TM-7  TEST-owner-wg.key, .pub, .pub.hex the owner's WireGuard pair (X25519, `wg genkey` form, base64), the public key
                                          also as 64 hex: propose --genesis --owner-wg-pub
  TM-8  TEST-site.json                    regalia.baremetal-site/v1 of a single-node host (boot_mesh.owner), loaded back
                                          by sitecfg.load
        TEST-regalia.site.cred            the ESP credential PCR 12 is computed from (bootcreds.site_document)
  TM-9  TEST-measurements.json            regalia.measurements/v1: one set, uki.measurement_set over the signed build
                                          record, the operator's PCR 0-7 values and PCR 12 from TEST-regalia.site.cred
  TM-10 TEST-lockout.value                a TPM lockout authorization: 32 printable characters and a newline
                                          (tpm-lockout.sh --set reads one line on stdin)
        TEST-genesis.json                 what was made (public values only), "TEST": true
        TEST-README.txt                   how each output is used, the stand-ins, how the owner keys are loaded
        TEST-SHA256SUMS                   SHA-256 of every other file (sha256sum -c form)

THE ROOT. --root-key names it (64 hex, the raw Ed25519 public key: root-key.json's value); --root-pk8 is its private
key (unencrypted PKCS#8 PEM, a regular file of this user's, mode 0600, never a link), whose public key must be the
named one. It is read into a bytearray, loaded and zeroed, and never printed or written.

THE GUARD. Refused, before the private key is read, unless the named root is TEST:
  (a) DENY: a real or ceremony root (REAL_ROOTS, with where each id comes from) is refused FIRST, whatever the allow-list
      says: putting one on TEST_ROOTS changes nothing;
  (b) ALLOW: only a root on the explicit allow-list TEST_ROOTS is accepted (the staging TEST root of dx7.14). Anything
      else, an unknown root included, is refused. `generate(..., allow=...)` is the tests' hook for a throwaway root;
      the command line has no way to extend the list.
  (c) the image: a signed build record whose initrd review names the root its image pins (initrd_review.root_key, the
      SHA-256 of root-key.json) must name THIS root: TEST material for an image that trusts another root, or pins none, is refused.
No production root exists yet (no ceremony has run, manifest.py's limitations): when one does, its id goes on
REAL_ROOTS in the same change that records it.

NOT DONE HERE: no SoftHSM, HSM, TPM or gpg call, no network, no `wg` binary. The PCR values are the operator's (read
from a file, never from a TPM). The OpenPGP fingerprints (ownerauth recipients, the release key's) and the envelope
digests of the ownerauth record are STAND-INS unless --owner-recipient gives real ones: no envelope is made, so the
record's yk_sha256/bg_sha256 are digests of a named stand-in text (nothing in deploy.baremetal reads an envelope or
checks those, ownerauth.py's limitations). TEST-README.txt says how the key files are loaded where a token is needed.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys

from deploy.baremetal import (bootcreds, cardrecord, espcreds, manifest, measurements, membership, ownerauth, sitecfg,
                              uki)

Refused, require = membership.Refused, membership.require

TOOL = "regalia-kms testgenesis/1 (TEST)"
MARK = "TEST"
SCHEMA = "regalia.testgenesis/v1"

# (b) the explicit allow-list: the TEST roots this tool signs for, by key id (the raw Ed25519 public key, 64 hex)
TEST_ROOTS = frozenset({
    # the dx7-14 staging TEST root: ~/.config/regalia-staging/dx7-14/test-root/root-key.json (regalia-kms-dx7.14)
    "6df81ed70ee55731c409a4c8c676203f69c55bb8c2d0b394f76919d77bb88c30",
})

# (a) the deny-list: real or ceremony roots, refused even if one is put on TEST_ROOTS. No production root is pinned
# anywhere yet (no ceremony has run); these are the roots regalia-ceremony's REAL writers produced, kept in this
# repository as vectors (their records are public: a root whose signed records are published is never a staging root)
REAL_ROOTS = {
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c": "tests/vectors/card-ceremony-record/root.hex",
    "8e119683841b2edd12a3f01c1a1985b49a373f782ce4c0bb0ed90e182dd8346f": "tests/vectors/card-ceremony-record/writer-run/root.hex",
    "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394":
        "tests/vectors/card-ceremony-record/other-root.json (freshness/marker-other-root)",
    "c62f5b68e34b9abd5c417cdc610eb544b6b7d141d7e8cf7fd4b6a367c029b5ad": "tests/vectors/offline-keys-record/root.hex",
    "d253f87454a3717ca6d4aa59b0a64db1e1e0a1a0d6c577d701f02580fd62cb95": "tests/vectors/offline-keys-record/root-fd8df0a.hex",
    "5a91603f023794dd2c8acc92fd470da260bbf06a4d08e2b916dca643c9b605a9": "tests/vectors/offline-keys-record/root-rc133.hex",
    "becd9865eb9eef864694071aa83d221a85edc9f137ddae0224a9c0d0a2b53b76": "tests/vectors/ownerauth-v1.json (root)",
}

# the TEST card serials (decimal, no leading zero: cardrecord.SERIAL), none a bench YubiKey's
OWNER_SERIALS = ("91000001", "91000002")
RELEASE_SERIALS = ("91000003", "91000004")
PCR_INDICES = tuple(str(i) for i in range(8))      # the host's own PCRs 0-7 (11 is the record's, 12 the credentials')
LOCKOUT_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"   # printable, no space, none easily misread
LOCKOUT_LENGTH = 32
MAX_KEY_FILE = 16 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def check_root(root, allow=None, deny=None):
    """The guard (module text): `root` (64 hex) refused if it is a real or ceremony root (`deny`, default REAL_ROOTS),
    whatever `allow` says, and unless it is on `allow` (default TEST_ROOTS). Returns it."""
    allow = TEST_ROOTS if allow is None else allow
    deny = REAL_ROOTS if deny is None else deny
    require(isinstance(root, str) and re.fullmatch(r"[0-9a-f]{64}", root) is not None,
            "--root-key is not a raw Ed25519 public key (64 lowercase hex, root-key.json's value)")
    require(root not in deny, "the root %s is a real or ceremony root (%s): TEST material is never made for it, whatever the "
            "allow-list says" % (root, deny.get(root, "the deny-list")))
    require(root in allow, "the root %s is not on the TEST allow-list (testgenesis.TEST_ROOTS): only a named TEST root is "
            "accepted, never an unknown one" % root)
    return root


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stand_in(*parts):
    """A named stand-in SHA-256: what a TEST record holds where a ceremony would name a real artifact."""
    return hashlib.sha256(b"\0".join([b"regalia testgenesis stand-in (TEST)"] + [p.encode() for p in parts])).hexdigest()


def _fingerprint_stand_in(*parts):
    """A stand-in OpenPGP fingerprint (40 upper-case hex), named as one in TEST-genesis.json."""
    return hashlib.sha1(b"\0".join([b"regalia testgenesis OpenPGP stand-in (TEST)"] + [p.encode() for p in parts])).hexdigest().upper()


# ---- the root's private key ----

def read_root_private(path, root):
    """The root's private key from `path` (module text): a regular file of this user's, mode 0600, not a link; one
    unencrypted PKCS#8 PEM Ed25519 key whose public key is `root`. The buffer is zeroed once the key is loaded."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise Refused("--root-pk8 %s cannot be opened (%s): it is never read through a link" % (path, error.strerror)) from None
    buffer = bytearray()
    try:
        held = os.fstat(fd)
        require(stat.S_ISREG(held.st_mode) and held.st_uid == os.geteuid() and held.st_mode & 0o077 == 0,
                "--root-pk8 %s is not a regular file of this user's, mode 0600" % path)
        while len(buffer) <= MAX_KEY_FILE:
            chunk = os.read(fd, MAX_KEY_FILE + 1 - len(buffer))
            if not chunk:
                break
            buffer += chunk
        require(len(buffer) <= MAX_KEY_FILE, "--root-pk8 %s is larger than %d bytes" % (path, MAX_KEY_FILE))
        try:
            key = serialization.load_pem_private_key(bytes(buffer), password=None)
        except (ValueError, TypeError):
            raise Refused("--root-pk8 %s is not one unencrypted PKCS#8 PEM private key" % path) from None
    finally:
        os.close(fd)
        for i in range(len(buffer)):
            buffer[i] = 0
    require(isinstance(key, Ed25519PrivateKey), "--root-pk8 %s is not an Ed25519 key: the membership root is one (D28)" % path)
    require(hmac.compare_digest(_raw_public(key), root), "--root-pk8 %s is not the private key of --root-key %s" % (path, root))
    return key


def _raw_public(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _pk8(key):
    from cryptography.hazmat.primitives import serialization
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def _spki_b64(key):
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()


def _signed(root_key, domain, record):
    """{record, signature}: the root's Ed25519 signature over `domain` + canonical(record), as each verifier checks it."""
    return {"record": record, "signature": root_key.sign(domain + membership.canonical(record)).hex()}


def _proven(key, sign_verify):
    """A key's operation proof, as the generation record's operation_proof says "verified": it signed a fresh challenge
    that verified under its own public key."""
    challenge = secrets.token_bytes(32)
    sign_verify(key, challenge)
    return "verified"


# ---- the output directory ----

class Output:
    """The caller's directory, and nothing outside it: every write is a plain name (or one TEST sub-directory) under the
    directory's own descriptor, O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600."""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        require(self.path not in ("/", os.path.abspath(os.path.expanduser("~"))), "--out %s is / or the home directory itself: name a "
                "directory of its own" % self.path)
        try:
            info = os.lstat(self.path)
        except FileNotFoundError:
            parent = os.path.dirname(self.path)
            require(os.path.isdir(parent), "--out %s: its parent directory does not exist" % self.path)
            os.mkdir(self.path, 0o700)
            info = os.lstat(self.path)
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid(),
                "--out %s is not a directory of this user's (a link is refused)" % self.path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        require(not os.listdir(self.fd), "--out %s is not empty: TEST material is written only into an empty directory" % self.path)
        os.fchmod(self.fd, 0o700)
        self.files = []

    def _parts(self, name):
        parts = name.split("/")
        require(1 <= len(parts) <= 2 and all(NAME.fullmatch(p) for p in parts) and all(p not in (".", "..") for p in parts),
                "%r is not a plain name inside --out" % name)
        require(parts[0].startswith(MARK + "-"), "%r is not marked TEST" % name)
        return parts

    def mkdir(self, name):
        self._parts(name)
        os.mkdir(name, 0o700, dir_fd=self.fd)
        dfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            os.fchmod(dfd, 0o700)
        finally:
            os.close(dfd)

    def write(self, name, data):
        parts = self._parts(name)
        where = self.fd
        if len(parts) == 2:
            where = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=where)
            try:
                os.fchmod(fd, 0o600)
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            if where != self.fd:
                os.close(where)
        self.files.append(name)
        return os.path.join(self.path, *parts)

    def json(self, name, obj):
        return self.write(name, json.dumps(obj, indent=1, sort_keys=True).encode() + b"\n")

    def join(self, name):
        return os.path.join(self.path, *self._parts(name))

    def close(self):
        os.close(self.fd)


# ---- the inputs ----

def _load_json(path, limit, what):
    try:
        with open(path, "rb") as f:
            return membership.load(f.read(limit + 1), limit)
    except OSError as error:
        raise Refused("%s %s cannot be read (%s)" % (what, path, error.strerror)) from None


def read_pcrs(path):
    """The host's own PCR 0-7 values, from the operator's file ({"0": "<64 hex>", ..., "7": ...}): exactly those eight.
    Read from the file, never from a TPM."""
    pcrs = _load_json(path, 65536, "--pcrs")
    require(isinstance(pcrs, dict) and sorted(pcrs) == sorted(PCR_INDICES),
            "--pcrs is not exactly PCRs 0-7 ({\"0\": \"<64 hex>\", ..., \"7\": ...}): 11 comes from the build record, 12 from the "
            "site credential")
    for index, value in pcrs.items():
        membership.hex_field(value, 64, "--pcrs PCR %s" % index)
    return pcrs


def _endpoint(text, what):
    parts = text.split(":")
    require(len(parts) == 3 and parts[1] in ("tcp", "udp") and parts[2].isdigit(), "%s %r is not CIDR:PROTO:PORT" % (what, text))
    return {"cidr": parts[0], "proto": parts[1], "port": int(parts[2])}


def site_document(args):
    """regalia.baremetal-site/v1 of a single-node host, from the command line (sitecfg validates it)."""
    outbound = [dict(_endpoint(args.audit, "--audit"), name="audit")]
    for item in args.outbound:
        name, _, rest = item.partition("=")
        outbound.append(dict(_endpoint(rest, "--outbound"), name=name))
    nts = []
    for item in args.nts:
        name, _, cidrs = item.partition("=")
        nts.append({"name": name, "cidrs": [c for c in cidrs.split(",") if c]})
    return {"schema": sitecfg.SCHEMA, "site": args.site, "host_ipv4": args.host_ipv4, "kms_port": args.kms_port,
            "ssh_port": args.ssh_port, "client_cidrs": args.client_cidr, "monitoring_cidrs": args.monitoring_cidr,
            "admin_cidrs": args.admin_cidr, "outbound": outbound, "time": {"nts": nts},
            "boot_mesh": {"node_id": args.node_id, "interface": args.boot_interface, "listen_port": args.listen_port,
                          "address": args.boot_address, "unlock_port": args.unlock_port, "nic_mac": args.nic_mac,
                          "prefix": args.prefix, "gateway": args.gateway, "peers": [],
                          "owner": {"underlay": args.owner_underlay, "address": args.owner_address}},
            "service_mesh": None}


def _recipients(given):
    """The two owner cards' ownerauth recipients, [(primary, subkey)] from --owner-recipient PRIMARY:SUBKEY, or None."""
    if not given:
        return None
    require(len(given) == 2, "--owner-recipient is given for both owner cards (owner-main, then owner-backup), or not at all")
    out = []
    for item in given:
        primary, _, subkey = item.partition(":")
        for fpr in (primary, subkey):
            require(re.fullmatch(r"[0-9A-F]{40}", fpr) is not None, "--owner-recipient %r is not PRIMARY:SUBKEY, 40 upper-case hex each" % item)
        out.append((primary, subkey))
    return out


# ---- the material ----

def generate(root, root_pk8, out, node_id, site, build_record, pcrs, tpm_firmware_version, device, label=None,
             recipients=None, allow=None, deny=None, say=print):
    """Everything the module text lists, written into `out` and verified from disk by the existing verifiers. `site` is
    the site document (dict), `build_record` the signed record (dict), `pcrs` {"0".."7": hex}. `allow` is the tests'
    hook (a throwaway root); `deny` is always checked first. Returns TEST-genesis.json's content."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
    from cryptography.hazmat.primitives import hashes
    check_root(root, allow, deny)
    require(isinstance(node_id, str) and re.fullmatch(sitecfg.NODE_ID, node_id) is not None, "--node-id %r is not a node ID" % (node_id,))
    # the inputs judged before any key is read or any file written
    try:
        cfg = sitecfg.validate(site)
    except sitecfg.InvalidSite as invalid:
        raise Refused("the site: %s" % invalid) from None
    require(sitecfg.profile(cfg) == sitecfg.SINGLE_NODE and cfg["boot_mesh"]["node_id"] == node_id,
            "the site is not a single-node host's (boot_mesh.owner) for %s" % node_id)
    record = uki.load_record(membership.canonical(build_record), signed=True)
    pinned = record["initrd_review"]["root_key"]
    # council on #787: an image that pins NO root is refused too (staging images always pin the TEST root they trust)
    require(pinned is not None, "the build record's image pins no membership root (initrd_review.root_key is null): TEST "
            "material is made only for an image that trusts this TEST root")
    require(pinned == hashlib.sha256(membership.canonical(root)).hexdigest(),
            "the build record's image pins another membership root (initrd_review.root_key %s, not the SHA-256 of root-key.json "
            "for %s): TEST material is made only for an image that trusts this TEST root" % (pinned, root))
    require(isinstance(pcrs, dict) and sorted(pcrs) == sorted(PCR_INDICES), "the PCR values are exactly PCRs 0-7")
    site_cred = bootcreds.site_document(cfg, device)
    entry = uki.measurement_set(record, label or record["name"], tpm_firmware_version, pcrs, {"regalia.site.cred": site_cred})
    root_key = read_root_private(root_pk8, root)

    output = Output(out)
    try:
        return _write_all(output, root, root_key, node_id, site, cfg, site_cred, entry, record, recipients, say,
                          serialization, ec, ed25519, x25519, hashes)
    except (Refused, OSError) as failure:
        raise Refused("%s; %s is INCOMPLETE and holds TEST secrets: delete it, nothing in it is to be used" % (failure, output.path)) from None
    finally:
        output.close()


def _write_all(output, root, root_key, node_id, site, cfg, site_cred, entry, record, recipients, say, serialization, ec, ed25519,
               x25519, hashes):
    at, session = _now(), secrets.token_hex(16)
    fingerprint = hashlib.sha256(bytes.fromhex(root)).hexdigest()
    root_entry = {"alg": "ed25519", "key": root}
    stand_ins = []

    # TM-6: the owner "cards'", the release card's and the SSH signers' keys, plain TEST Ed25519 keys
    owners = {role: ed25519.Ed25519PrivateKey.generate() for role in cardrecord.ROLES}
    release = ed25519.Ed25519PrivateKey.generate()
    ssh = {role: ed25519.Ed25519PrivateKey.generate() for role in cardrecord.ROLES}
    serial = dict(zip(cardrecord.ROLES, OWNER_SERIALS))
    if recipients is None:
        recipients = [(_fingerprint_stand_in(role, "primary", _raw_public(owners[role])),
                       _fingerprint_stand_in(role, "subkey", _raw_public(owners[role]))) for role in cardrecord.ROLES]
        stand_ins.append("ownerauth recipients (OpenPGP primary and subkey fingerprints of the owner cards): stand-ins, no gpg "
                         "key exists for them; give --owner-recipient to name real TEST keys")
    release_fpr = _fingerprint_stand_in("release", _raw_public(release))
    stand_ins.append("release_key.fingerprint (the release card's OpenPGP fingerprint): a stand-in")
    stand_ins.append("owner_keys[].attestation_sha256: stand-ins, as for every record today (cardrecord.py's limitations, #400)")
    recipient_of = dict(zip(cardrecord.ROLES, recipients))

    # TM-3: the card ceremony record, signed by the root
    card = {"schema": cardrecord.SCHEMA, "event": cardrecord.EVENT, "session": session, "tool": TOOL, "at": at, "sequence": 1,
            "supersedes": "", "root_entry": root_entry, "root_fingerprint": fingerprint,
            "owner_keys": [{"role": role, "serial": serial[role], "alg": "ed25519", "key": _raw_public(owners[role]), "attested": True,
                            "attestation_sha256": {k: _stand_in("attestation", role, k, _raw_public(owners[role])) for k in ("sig", "dec", "aut")}}
                           for role in cardrecord.ROLES],
            "release_key": {"alg": "ed25519", "key": _raw_public(release), "fingerprint": release_fpr, "cards": list(RELEASE_SERIALS),
                            "imported": True, "attested": False},
            "ownerauth_recipients": [{"serial": serial[role], "primary": recipient_of[role][0], "subkey": recipient_of[role][1]}
                                     for role in cardrecord.ROLES],
            "ssh_signers": [{"serial": serial[role], "key": ssh[role].public_key().public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()} for role in cardrecord.ROLES]}
    card_envelope = _signed(root_key, cardrecord.RECORD_DOMAIN, card)
    output.json("TEST-cards.record.json", card_envelope)
    output.mkdir("TEST-signing-state")
    output.write("TEST-signing-state/" + cardrecord.SIGNING_STATE,
                 membership.canonical({"root": root, "schema": cardrecord.SIGNING_STATE_SCHEMA}))
    output.write("TEST-signing-state/" + cardrecord.SIGNING_RECORD, json.dumps(
        {"at": at, "digest": cardrecord.digest(card), "key": root, "kind": "card-record", "sequence": 1}, sort_keys=True).encode() + b"\n")

    # TM-4: the offline-keys generation record, K_A beside it
    anchor = ec.generate_private_key(ec.SECP256R1())
    anchor_point = anchor.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    proof = {"root": _proven(root_key, lambda k, c: k.public_key().verify(k.sign(c), c)),
             "anchor-policy": _proven(anchor, lambda k, c: k.public_key().verify(k.sign(c, ec.ECDSA(hashes.SHA256())), c,
                                                                                    ec.ECDSA(hashes.SHA256())))}
    offline = {"schema": manifest.OFFLINE_KEYS_SCHEMA, "event": "generate", "threshold": 1, "shares": 1,
               "slip39_identifier": secrets.randbelow(32768), "master_id": secrets.token_hex(16),
               "publics": {"root": {"alg": "ed25519", "spki": _spki_b64(root_key)},
                           "anchor-policy": {"alg": "ecdsa-p256", "spki": _spki_b64(anchor)}},
               "root_entry": root_entry, "anchor_policy_entry": {"alg": "ecdsa-p256", "key": anchor_point},
               "root_fingerprint": fingerprint, "files": {}, "operation_proof": proof, "tool": TOOL, "at": at}
    output.json("TEST-offline-keys.record.json", _signed(root_key, manifest.OFFLINE_KEYS_DOMAIN, offline))
    output.write("TEST-anchor-policy.p256.pk8.pem", _pk8(anchor))
    stand_ins.append("offline-keys record: threshold 1 of 1, no Shamir shares and no sealed files (files {}): a TEST root is a "
                     "plain key file, not a sealed set")

    # TM-5: the owner-authorization record and the node's value
    value = secrets.token_bytes(32)
    oa = {"schema": ownerauth.SCHEMA, "event": ownerauth.EVENT, "at": at, "session": session, "master_id": offline["master_id"],
          "share_indices": [1], "slip39_identifier": offline["slip39_identifier"], "tool": TOOL,
          "root_entry": root_entry, "root_fingerprint": fingerprint,
          "nodes": {node_id: {"yk_sha256": _stand_in("ownerauth", node_id, "yk.gpg"), "bg_sha256": _stand_in("ownerauth", node_id, "bg"),
                              "check": ownerauth.Auth(value).check(node_id)}},
          "yk_recipients": [{"primary": p, "subkey": s} for p, s in recipients],
          "verify_keys": {s: _stand_in("verify", s) for _, s in recipients}}
    output.json("TEST-ownerauth.record.json", _signed(root_key, ownerauth.RECORD_DOMAIN, oa))
    output.write("TEST-ownerauth-%s.value" % node_id, value.hex().encode() + b"\n")
    stand_ins.append("ownerauth record: yk_sha256, bg_sha256 and verify_keys are stand-in digests (no envelope is made; the value "
                     "is TEST-ownerauth-%s.value)" % node_id)

    # TM-6, the key files
    for role in cardrecord.ROLES:
        output.write("TEST-%s.ed25519.pk8.pem" % role, _pk8(owners[role]))
        output.write("TEST-ssh-%s.key" % role, ssh[role].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                                                         serialization.NoEncryption()))
        output.write("TEST-ssh-%s.pub" % role, card["ssh_signers"][cardrecord.ROLES.index(role)]["key"].encode() + b"\n")
    output.write("TEST-release.ed25519.pk8.pem", _pk8(release))
    output.write("TEST-owner-recipients.txt", "".join("%s\n" % s for _, s in recipients).encode())

    # TM-7: the owner's WireGuard pair, `wg genkey` form (a clamped X25519 private key, base64)
    raw = bytearray(secrets.token_bytes(32))
    raw[0] &= 248
    raw[31] = (raw[31] & 127) | 64
    wg = x25519.X25519PrivateKey.from_private_bytes(bytes(raw))
    wg_pub = wg.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    output.write("TEST-owner-wg.key", base64.b64encode(bytes(raw)) + b"\n")
    output.write("TEST-owner-wg.pub", base64.b64encode(wg_pub) + b"\n")
    output.write("TEST-owner-wg.pub.hex", wg_pub.hex().encode() + b"\n")

    # TM-8: the site, and the credential PCR 12 is computed from
    output.json("TEST-site.json", site)
    output.write("TEST-regalia.site.cred", site_cred)

    # TM-9: the measurements document
    name = ("TEST-" + entry["label"])[:64]
    document = {"schema": measurements.SCHEMA, "name": name, "nodes": {node_id: {"accepted": [entry]}}}
    output.json("TEST-measurements.json", document)

    # TM-10: the lockout authorization
    output.write("TEST-lockout.value", "".join(secrets.choice(LOCKOUT_ALPHABET) for _ in range(LOCKOUT_LENGTH)).encode() + b"\n")

    summary = {MARK: True, "schema": SCHEMA, "tool": TOOL, "at": at, "session": session, "root": root, "root_fingerprint": fingerprint,
               "node_id": node_id, "site": cfg["site"], "topology": membership.SINGLE_NODE,
               "owner_keys": {role: {"serial": serial[role], "key": _raw_public(owners[role])} for role in cardrecord.ROLES},
               "release_key": _raw_public(release), "card_record": {"sequence": 1, "digest": cardrecord.digest(card)},
               "anchor_policy_key": {"alg": "ecdsa-p256", "key": anchor_point}, "owner_wg_pub": wg_pub.hex(),
               "measurements": {"name": name, "policy_version": measurements.version(document), "label": entry["label"],
                                "build_record": record["name"], "pcr12": entry["pcrs"]["12"]},
               "ownerauth_recipients": [s for _, s in recipients], "stand_ins": stand_ins}
    output.json("TEST-genesis.json", summary)
    output.write("TEST-README.txt", _readme(summary).encode())

    verify_outputs(output.path, root, node_id)
    sums = []
    for name in sorted(output.files):
        with open(output.join(name), "rb") as f:
            sums.append("%s  %s\n" % (hashlib.sha256(f.read()).hexdigest(), name))
    output.write("TEST-SHA256SUMS", "".join(sums).encode())
    say("TEST genesis material for %s under the TEST root %s... written to %s and verified by the existing verifiers "
        "(card_record_keys, cardrecord.verify, offline_keys_record, ownerauth.verify, sitecfg.load, measurements.load)"
        % (node_id, root[:16], output.path))
    return summary


def verify_outputs(directory, root, node_id):
    """Every record in `directory`, read back from disk and verified by the existing verifiers. Raises Refused."""
    def load(name):
        return _load_json(os.path.join(directory, name), membership.MAX_BYTES, name)
    state = os.path.join(directory, "TEST-signing-state")
    cards = manifest.card_record_keys(load("TEST-cards.record.json"), root, state)
    require(cards["sequence"] == 1 and cards["of"] == 1, "the card record is not the newest (1 of 1)")
    cardrecord.verify(load("TEST-cards.record.json"), root, cardrecord.read_signing_state(state, root))
    manifest.offline_keys_record(load("TEST-offline-keys.record.json"), root)
    envelope = load("TEST-ownerauth.record.json")
    with open(os.path.join(directory, "TEST-ownerauth-%s.value" % node_id), "rb") as f:
        ownerauth.from_envelope(f, envelope, root, node_id)
    try:
        sitecfg.load(os.path.join(directory, "TEST-site.json"))
    except sitecfg.InvalidSite as invalid:
        raise Refused("TEST-site.json: %s" % invalid) from None
    with open(os.path.join(directory, "TEST-measurements.json"), "rb") as f:
        document = measurements.load(f.read(measurements.MAX_BYTES + 1))
    with open(os.path.join(directory, "TEST-regalia.site.cred"), "rb") as f:
        require(document["nodes"][node_id]["accepted"][0]["pcrs"]["12"] == espcreds.pcr12({"regalia.site.cred": f.read()}),
                "the measurements' PCR 12 is not TEST-regalia.site.cred's")
    with open(os.path.join(directory, "TEST-lockout.value"), "rb") as f:
        require(re.fullmatch(rb"[!-~]{16,32}\n", f.read(64)) is not None, "TEST-lockout.value is not 16-32 printable characters and a newline")


def _readme(summary):
    return """TEST GENESIS MATERIAL -- TEST ONLY, NEVER A PRODUCTION GENESIS (regalia-kms-223)

Made by %(tool)s at %(at)s for node %(node_id)s (site %(site)s, single-node) under the TEST
membership root %(root)s. Every record here verifies under that root only.

Using it (manifest.py's genesis; see deploy/baremetal/README.md, "Staging TEST genesis material"):
  manifest propose --genesis --topology single-node --root-key %(root)s
      --card-record TEST-cards.record.json --measurements TEST-measurements.json
      --owner-wg-pub $(cat TEST-owner-wg.pub.hex) ...
  manifest sign --genesis ... --state-dir TEST-signing-state   (the root signs from its descriptor, --key-fd)
  ownerauth check --node-id %(node_id)s --root-key %(root)s --record TEST-ownerauth.record.json < TEST-ownerauth-%(node_id)s.value
  tpm-lockout.sh --set < TEST-lockout.value

The owner "cards" are plain key files (TEST-owner-main.ed25519.pk8.pem, TEST-owner-backup.ed25519.pk8.pem: unencrypted
PKCS#8 PEM, Ed25519). owner.py opens the owner's key through PKCS#11 by --serial and --key-id (p11sign.Pkcs11Signer); to
use one there, import it onto a TEST SoftHSM token OUTSIDE this tool, on the machine that runs owner.py, e.g.
  softhsm2-util --init-token --free --label owner-test --so-pin ... --pin ...
  softhsm2-util --import TEST-owner-main.ed25519.pk8.pem --token owner-test --label owner-main --id 01 --pin ...
(that softhsm2-util imports an Ed25519 PKCS#8 key is NOT verified by this tool; e2e/lib/threenode.py generates its owner
keys on the token with pkcs11-tool --keypairgen instead). The card serials in the record (%(serials)s) are TEST
stand-ins: owner.py's --serial is the TEST token's own serial.

owner.py contribute's --recipient values are in TEST-owner-recipients.txt.

Stand-ins (nothing in deploy.baremetal checks them beyond their form):
%(stand_ins)s

TEST-SHA256SUMS: sha256sum -c TEST-SHA256SUMS
""" % dict(summary, serials=", ".join(v["serial"] for v in summary["owner_keys"].values()),
           stand_ins="".join("  * %s\n" % s for s in summary["stand_ins"]))


# ---- the command ----

def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.testgenesis", description=__doc__.split("\n\n")[0])
    parser.add_argument("--root-key", required=True, help="the TEST membership root: 64 hex, root-key.json's value")
    parser.add_argument("--root-pk8", required=True, help="its private key: unencrypted PKCS#8 PEM, a file of this user's, mode 0600")
    parser.add_argument("--out", required=True, help="the output directory: created 0700, or an existing empty one")
    parser.add_argument("--node-id", required=True)
    # TM-8: the site
    parser.add_argument("--site", required=True, help="the site's short name")
    parser.add_argument("--host-ipv4", required=True)
    parser.add_argument("--prefix", type=int, required=True, help="host_ipv4's prefix length on the initrd's card")
    parser.add_argument("--gateway", required=True, help="the initrd's gateway to the owner's underlay, or 'none' (on the link)")
    parser.add_argument("--nic-mac", required=True, help="the initrd's network card, by MAC address (lower case)")
    parser.add_argument("--boot-address", required=True, help="this node's address inside the boot tunnel")
    parser.add_argument("--owner-underlay", required=True, help="the owner's unlock endpoint, outside the tunnel")
    parser.add_argument("--owner-address", required=True, help="the owner's unlock endpoint, inside the tunnel")
    parser.add_argument("--boot-interface", default="wg-unlock")
    parser.add_argument("--listen-port", type=int, default=51820)
    parser.add_argument("--unlock-port", type=int, default=7443)
    parser.add_argument("--kms-port", type=int, default=8443)
    parser.add_argument("--ssh-port", type=int, default=22)
    parser.add_argument("--client-cidr", action="append", required=True)
    parser.add_argument("--monitoring-cidr", action="append", required=True)
    parser.add_argument("--admin-cidr", action="append", required=True)
    parser.add_argument("--audit", required=True, metavar="CIDR:PROTO:PORT", help="the audit sink")
    parser.add_argument("--outbound", action="append", default=[], metavar="NAME=CIDR:PROTO:PORT")
    parser.add_argument("--nts", action="append", required=True, metavar="NAME=CIDR[,CIDR]", help="an NTS server (two at least)")
    # TM-9: the measurements
    parser.add_argument("--build-record", required=True, help="the image's SIGNED build record (uki.py sign)")
    parser.add_argument("--pcrs", required=True, help="a JSON file of the host's own PCR 0-7 values, as the operator read them")
    parser.add_argument("--tpm-firmware-version", required=True, help="16 hex")
    parser.add_argument("--device", required=True, help="the node's root volume (regalia.site's device): PCR 12 is computed with it")
    parser.add_argument("--label", help="the measurement set's label (default: the build record's name)")
    parser.add_argument("--owner-recipient", action="append", default=[], metavar="PRIMARY:SUBKEY",
                        help="the owner cards' OpenPGP keys (owner-main, then owner-backup); stand-ins without it")
    args = parser.parse_args(argv)
    if args.gateway == "none":
        args.gateway = None
    try:
        check_root(args.root_key)
        record = _load_json(args.build_record, 1024 * 1024, "--build-record")
        generate(args.root_key, args.root_pk8, args.out, args.node_id, site_document(args), record, read_pcrs(args.pcrs),
                 args.tpm_firmware_version, args.device, label=args.label, recipients=_recipients(args.owner_recipient))
    except (Refused, OSError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
