"""The card-ceremony record, verified by the side that consumes it (regalia-ceremony#111 step 2; ADR-0002 D30).

The card ceremony writes `cards.record.json`: which cards hold the owner's two keys (the developer pair's OpenPGP SIG
keys) and which hold the release key, signed by the membership root in the offline session that made them. The
genesis proposal takes owner_keys and the release key from it (manifest propose --genesis --card-record) instead of
having them typed. This module is that consumer's own check: it imports nothing of regalia-ceremony, and it PINS the
root (regalia-ceremony's own verify_record checks only that a record is consistent with itself).

    {"record": {...}, "signature": "<128 hex: Ed25519 over RECORD_DOMAIN + canonical(record)>"}

Refused, by name, unless:
  * the envelope is exactly those two keys, every string in it is ASCII (the producer refuses anything else, so
    membership.canonical gives the producer's bytes), and the signature is 128 lowercase hex;
  * the record's root_entry is the PINNED root (Ed25519) and root_fingerprint is the SHA-256 of its raw key, and the
    signature verifies under that pinned key over RECORD_DOMAIN + canonical(record);
  * every field is as the producer writes it, none missing and none unknown, at every level (FIELDS);
  * owner_keys are exactly two, the roles dev-main and dev-backup, with distinct serials and keys, Ed25519, and each
    attested on its card (D5), naming the SHA-256 of its SIG and DEC keys' attestation certificates, all four distinct;
  * the release key is Ed25519, imported, not attested, on two distinct cards, its key no owner key and its cards no
    owner card (D30.3);
  * no card is a bench YubiKey (membership.BENCH_YUBIKEYS; D28.5, D30);
  * ownerauth_recipients and ssh_signers name exactly the owner cards, and no OpenPGP fingerprint twice;
  * every Ed25519 key in it (the two owner keys, the release key, the two SSH keys, the root) is distinct;
  * it is the NEWEST card record the root signed (#403): the laptop's root signing record (signing_lines, read by
    read_signing_state) has card-record lines 1..M without a gap, all under the pinned root, this record is line M
    (its `sequence` and digest), and its `supersedes` is line M-1's digest ("" at sequence 1). An older record, which
    still verifies, is refused: after a card replacement it would give the retired cards' keys.
Returns {"owners": {serial: key}, "roles": {role: serial}, "release_key": key, "session": ..., "at": ..., "sequence": N,
"of": M, "digest": ..., "supersedes": ...}.

No node ever reads a card record: a node has no laptop signing record to judge it by.
"""
import base64
import hashlib
import json
import os
import re
import stat
import struct

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

RECORD_DOMAIN = b"regalia-ceremony-record/v1\x00"
SCHEMA = "regalia.card-ceremony-record/v1"
EVENT = "card-ceremony"
ROLES = ("dev-main", "dev-backup")
FIELDS = {
    "record": ("schema", "event", "owner_keys", "ownerauth_recipients", "ssh_signers", "release_key", "session", "root_entry",
               "root_fingerprint", "tool", "at", "sequence", "supersedes"),
    "card_record_line": ("kind", "sequence", "digest", "key", "at"),
    "signing_state": ("schema", "root"),
    "owner_key": ("role", "serial", "alg", "key", "attested", "attestation_sha256"),
    "attestation_sha256": ("sig", "dec"),
    "release_key": ("alg", "key", "fingerprint", "cards", "imported", "attested"),
    "ownerauth_recipient": ("serial", "primary", "subkey"),
    "ssh_signer": ("serial", "key"),
    "root_entry": ("alg", "key"),
}
# the laptop's ceremony state directory (manifest sign --state-dir, and regalia-ceremony's card ceremony): one ordered
# record of the root's uses, and the marker saying whose root that record is (agreed with regalia-kms-51 on #403)
SIGNING_RECORD = "signing-record.jsonl"
SIGNING_STATE = "regalia-signing-state.json"
SIGNING_STATE_SCHEMA = "regalia.signing-state/v1"
MAX_SIGNING_RECORD = 4 * 1024 * 1024        # read whole or refused whole: a cut at a line boundary would make an older record line M
SERIAL = re.compile(r"[1-9][0-9]{0,9}")
HEX64 = re.compile(r"[0-9a-f]{64}")
OPENPGP_FPR = re.compile(r"[0-9A-F]{40}")


def _ascii(value, where="the record"):
    """Every string, key and value, ASCII: the producer refuses anything else, so the canonical bytes are its own."""
    if isinstance(value, str):
        require(value.isascii(), "%s holds a non-ASCII string" % where)
    elif isinstance(value, dict):
        for k, v in value.items():
            _ascii(k, where)
            _ascii(v, where)
    elif isinstance(value, list):
        for v in value:
            _ascii(v, where)


def _exact(obj, kind, where):
    require(isinstance(obj, dict), "%s is not an object" % where)
    membership.exact(obj, FIELDS[kind], where)


def _serial(value, where):
    require(isinstance(value, str) and SERIAL.fullmatch(value) is not None, "%s is not a card serial (decimal, no leading zero)" % where)
    return value


def _key(value, where):
    require(isinstance(value, str) and HEX64.fullmatch(value) is not None, "%s is not a raw Ed25519 key (64 lowercase hex)" % where)
    return value


def _ssh_ed25519(value, where):
    """The raw 32-byte key of an "ssh-ed25519 <base64>" public key (the SSH wire format: two length-prefixed strings)."""
    require(isinstance(value, str) and value.startswith("ssh-ed25519 ") and len(value.split(" ")) == 2, "%s is not an ssh-ed25519 key" % where)
    try:
        blob = base64.b64decode(value.split(" ")[1], validate=True)
    except ValueError:
        raise Refused("%s is not base64" % where) from None
    parts, at = [], 0
    while at < len(blob):
        require(at + 4 <= len(blob), "%s is not an SSH key blob" % where)
        (n,) = struct.unpack(">I", blob[at:at + 4])
        parts.append(blob[at + 4:at + 4 + n])
        at += 4 + n
    require(at == len(blob) and len(parts) == 2 and parts[0] == b"ssh-ed25519" and len(parts[1]) == 32, "%s is not an ssh-ed25519 key" % where)
    return parts[1].hex()


def digest(record):
    """A card record's digest, as `supersedes` and the signing record name it: SHA-256 of its canonical bytes (the form
    the signature covers, without RECORD_DOMAIN), 64 hex; regalia-ceremony's card_record_digest."""
    return hashlib.sha256(membership.canonical(record)).hexdigest()


def _read_own(directory, name, limit, what):
    """`name` in `directory`, never through a link: a regular file of this user's, 0600, read whole (at most `limit`
    bytes, else refused whole: never a silent truncation)."""
    try:
        fd = os.open(os.path.join(directory, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise Refused("%s cannot be opened (%s): it is not read through a link" % (what, error.strerror)) from None
    try:
        held = os.fstat(fd)
        require(stat.S_ISREG(held.st_mode) and held.st_uid == os.geteuid() and held.st_mode & 0o077 == 0,
                "%s is not a regular file of this user's, mode 0600 (a link to an older copy is never read)" % what)
        data = b""
        while len(data) <= limit:
            chunk = os.read(fd, limit + 1 - len(data))
            if not chunk:
                break
            data += chunk
        require(len(data) <= limit, "%s is larger than %d bytes" % (what, limit))
        return data
    finally:
        os.close(fd)


def read_signing_state(state_dir, root):
    """The laptop's root signing record, every line parsed, after its marker says it is the pinned `root`'s. Refused,
    by name, unless: the directory is a real directory of this user's, mode 0700; the marker regalia-signing-state.json
    is there, exactly {schema, root} with root the PINNED root (a missing marker, or another root's, would let a second
    "gapless" record be judged); the signing record is there; and the WHOLE file parses, each line a JSON object
    ending in a newline (a torn last line is refused, never skipped). Returns the lines in file order."""
    _key(root, "the pinned root")
    try:
        info = os.lstat(state_dir)
    except OSError as error:
        raise Refused("the state directory %s cannot be read (%s)" % (state_dir, error.strerror)) from None
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
            "the state directory %s must be a directory of this user's, mode 0700, not a link" % state_dir)
    marker = _read_own(state_dir, SIGNING_STATE, 4096, "the state directory's marker %s" % SIGNING_STATE)
    require(marker is not None, "the state directory %s has no %s: it is not the root's signing state (wrong --state-dir?)"
            % (state_dir, SIGNING_STATE))
    try:
        state = json.loads(marker.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("the state directory's marker %s is not JSON" % SIGNING_STATE) from None
    _exact(state, "signing_state", "the state directory's marker")
    require(state["schema"] == SIGNING_STATE_SCHEMA, "the state directory's marker is not a %s" % SIGNING_STATE_SCHEMA)
    require(state["root"] == root, "the state directory is another root's signing state: it is not this network's laptop")
    data = _read_own(state_dir, SIGNING_RECORD, MAX_SIGNING_RECORD, "the signing record %s" % SIGNING_RECORD)
    require(data, "the state directory %s holds no signing record: no card record can be shown to be the newest" % state_dir)
    require(data.endswith(b"\n"), "the signing record's last line is torn (no newline at its end): it is not read")
    lines = []
    for number, raw in enumerate(data.split(b"\n")[:-1], 1):
        try:
            line = json.loads(raw.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            raise Refused("the signing record's line %d is not JSON: the record is not read" % number) from None
        require(isinstance(line, dict) and isinstance(line.get("kind"), str),
                "the signing record's line %d is not an object with a kind (\"manifest\", \"card-record\")" % number)
        lines.append(line)
    return lines


def _newest(record, root, signing_lines):
    """`record` is line M of the card-record lines, and supersedes line M-1 (see the module text). Returns M."""
    cards = []
    for number, line in enumerate(signing_lines, 1):
        require(isinstance(line, dict) and isinstance(line.get("kind"), str),
                "the signing record's line %d is not an object with a kind (\"manifest\", \"card-record\")" % number)
        if line["kind"] == "card-record":
            _exact(line, "card_record_line", "the signing record's card-record line %d" % number)
            require(line["key"] == root, "the signing record's card-record line %d names another root than the pinned one" % number)
            _key(line["digest"], "the signing record's card-record line %d's digest" % number)
            cards.append(line)
    require(cards, "the signing record holds no card-record line: this card record cannot be shown to be the newest (wrong --state-dir?)")
    sequences = [line["sequence"] for line in cards]
    require(all(type(s) is int for s in sequences) and sequences == list(range(1, len(cards) + 1)),
            "the signing record's card-record lines are not 1..%d without a gap or a repeat (%s)" % (len(cards), sequences))
    newest = cards[-1]
    require(record["sequence"] == newest["sequence"] and digest(record) == newest["digest"],
            "this card record (sequence %d) is not the newest the root signed (sequence %d, digest %s): an older one is superseded"
            % (record["sequence"], newest["sequence"], newest["digest"][:16]))
    require(record["supersedes"] == (cards[-2]["digest"] if len(cards) > 1 else ""),
            "this card record does not supersede the one before it in the signing record")
    return len(cards)


def verify(envelope, root, signing_lines):
    """The card-ceremony record in `envelope`, checked against the pinned `root` (64 hex, the raw Ed25519 root key) and
    the laptop's root signing record (`signing_lines`, from read_signing_state: REQUIRED, there is no unjudged path):
    see the module text. Returns its owner and release keys, and where it stands among the root's card records."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    require(isinstance(envelope, dict), "the card record is not an object")
    membership.exact(envelope, ("record", "signature"), "the card record")
    _ascii(envelope)
    record, signature = envelope["record"], envelope["signature"]
    require(isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{128}", signature) is not None, "the card record's signature is not 128 hex")
    _exact(record, "record", "the card record")
    _exact(record["root_entry"], "root_entry", "root_entry")
    _key(root, "the pinned root")
    require(record["root_entry"]["alg"] == "ed25519" and record["root_entry"]["key"] == root,
            "the card record names another root than the pinned one: it is not this network's ceremony")
    require(record["root_fingerprint"] == hashlib.sha256(bytes.fromhex(root)).hexdigest(), "the card record's root_fingerprint is not the root's")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(root)).verify(bytes.fromhex(signature), RECORD_DOMAIN + membership.canonical(record))
    except (InvalidSignature, ValueError):
        raise Refused("the card record's signature is not the pinned root's over %r and the record" % RECORD_DOMAIN.decode().rstrip("\x00")) from None
    # signed: from here, what the ceremony recorded, checked as the producer checks it
    require(record["schema"] == SCHEMA and record["event"] == EVENT, "the card record is not a %s (%s)" % (SCHEMA, EVENT))
    require(isinstance(record["session"], str) and re.fullmatch(r"[0-9a-f]{32}", record["session"]) is not None, "session is not 32 hex")
    require(isinstance(record["tool"], str) and 0 < len(record["tool"]) <= 200, "tool is not a short name")
    require(isinstance(record["at"], str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", record["at"]) is not None,
            "at is not YYYY-MM-DDTHH:MM:SSZ")
    require(type(record["sequence"]) is int and record["sequence"] >= 1, "sequence is not a count from 1")
    require(record["supersedes"] == "" if record["sequence"] == 1 else
            isinstance(record["supersedes"], str) and HEX64.fullmatch(record["supersedes"]) is not None,
            "supersedes is not \"\" at sequence 1, or the previous record's digest (64 hex) after it")
    owners, roles, certificates = {}, {}, []
    require(isinstance(record["owner_keys"], list) and len(record["owner_keys"]) == 2, "owner_keys is not exactly two keys (D30)")
    for i, entry in enumerate(record["owner_keys"]):
        where = "owner_keys[%d]" % i
        _exact(entry, "owner_key", where)
        require(entry["role"] in ROLES and entry["role"] not in roles, "%s: the role %r is not one of %s, once each" % (where, entry["role"], ", ".join(ROLES)))
        serial = _serial(entry["serial"], where + ".serial")
        require(serial not in owners, "%s: the card %s holds two owner keys" % (where, serial))
        require(entry["alg"] == "ed25519", "%s is not an Ed25519 key" % where)
        require(entry["attested"] is True, "%s: the key is not attested as made on its card (D5)" % where)
        _exact(entry["attestation_sha256"], "attestation_sha256", where + ".attestation_sha256")
        for f in ("sig", "dec"):
            certificates.append(_key(entry["attestation_sha256"][f], "%s.attestation_sha256.%s (a certificate's SHA-256, 64 hex)" % (where, f)))
        owners[serial], roles[entry["role"]] = _key(entry["key"], where + ".key"), serial
    require(sorted(roles) == sorted(ROLES), "owner_keys lacks a role: %s" % ", ".join(sorted(set(ROLES) - set(roles))))
    require(len(set(owners.values())) == 2, "the two owner cards hold the same key")
    require(len(set(certificates)) == len(certificates), "an attestation certificate is named twice: each key has its own")
    release = record["release_key"]
    _exact(release, "release_key", "release_key")
    require(release["alg"] == "ed25519", "release_key is not an Ed25519 key")
    key = _key(release["key"], "release_key.key")
    require(isinstance(release["fingerprint"], str) and OPENPGP_FPR.fullmatch(release["fingerprint"]) is not None, "release_key.fingerprint is not 40 HEX")
    require(isinstance(release["cards"], list), "release_key.cards is not a list")
    cards = [_serial(c, "release_key.cards[%d]" % i) for i, c in enumerate(release["cards"])]       # each a serial, before any set
    require(len(cards) == 2 and len(set(cards)) == 2, "release_key.cards is not two distinct cards")
    require(release["imported"] is True and release["attested"] is False, "release_key is not an imported (unattested) key, as the ceremony makes it")
    require(key not in owners.values(), "the release key is an owner key: the release card is never an owner key (D30.3)")
    require(not set(cards) & set(owners), "a release card is an owner card (D30.3): %s" % ", ".join(sorted(set(cards) & set(owners))))
    bench = sorted(s for s in set(owners) | set(cards) if s in membership.BENCH_YUBIKEYS)
    require(not bench, "a bench YubiKey is named (%s): the ceremony never uses a bench serial (D28.5, D30)" % ", ".join(bench))
    fingerprints = []                     # every OpenPGP key an ownerauth recipient names: one card's, never two cards'
    for kind, field in (("ownerauth_recipient", "ownerauth_recipients"), ("ssh_signer", "ssh_signers")):
        listed = record[field]
        require(isinstance(listed, list), "%s is not a list" % field)
        serials = []
        for i, entry in enumerate(listed):
            _exact(entry, kind, "%s[%d]" % (field, i))
            serials.append(_serial(entry["serial"], "%s[%d].serial" % (field, i)))
            if kind == "ownerauth_recipient":
                for f in ("primary", "subkey"):
                    require(isinstance(entry[f], str) and OPENPGP_FPR.fullmatch(entry[f]) is not None, "%s[%d].%s is not 40 HEX" % (field, i, f))
                    fingerprints.append(entry[f])
        require(sorted(serials) == sorted(owners), "%s names other cards than the owner cards" % field)
    require(len(set(fingerprints)) == len(fingerprints), "an OpenPGP key is named twice among the ownerauth recipients: each owner card "
            "decrypts with its own")
    ssh = [_ssh_ed25519(e["key"], "ssh_signers[%d].key" % i) for i, e in enumerate(record["ssh_signers"])]
    every = list(owners.values()) + [key] + ssh + [root]
    require(len(set(every)) == len(every), "a key appears twice among the owner, release, SSH and root keys")
    of = _newest(record, root, signing_lines)                   # #403: the newest the root signed, by the laptop's record
    return {"owners": owners, "roles": roles, "release_key": key, "session": record["session"], "at": record["at"],
            "sequence": record["sequence"], "of": of, "digest": digest(record), "supersedes": record["supersedes"]}
