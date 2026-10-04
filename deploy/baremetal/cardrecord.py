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
    attested on its card (D5);
  * the release key is Ed25519, imported, not attested, on two distinct cards, its key no owner key and its cards no
    owner card (D30.3);
  * ownerauth_recipients and ssh_signers name exactly the owner cards;
  * every Ed25519 key in it (the two owner keys, the release key, the two SSH keys, the root) is distinct.
Returns {"owners": {serial: key}, "roles": {role: serial}, "release_key": key, "session": ..., "at": ...}.
"""
import base64
import hashlib
import re
import struct

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

RECORD_DOMAIN = b"regalia-ceremony-record/v1\x00"
SCHEMA = "regalia.card-ceremony-record/v1"
EVENT = "card-ceremony"
ROLES = ("dev-main", "dev-backup")
FIELDS = {
    "record": ("schema", "event", "owner_keys", "ownerauth_recipients", "ssh_signers", "release_key", "session", "root_entry",
               "root_fingerprint", "tool", "at"),
    "owner_key": ("role", "serial", "alg", "key", "attested"),
    "release_key": ("alg", "key", "fingerprint", "cards", "imported", "attested"),
    "ownerauth_recipient": ("serial", "primary", "subkey"),
    "ssh_signer": ("serial", "key"),
    "root_entry": ("alg", "key"),
}
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


def verify(envelope, root):
    """The card-ceremony record in `envelope`, checked against the pinned `root` (64 hex, the raw Ed25519 root key):
    see the module text. Returns its owner and release keys."""
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
    owners, roles = {}, {}
    require(isinstance(record["owner_keys"], list) and len(record["owner_keys"]) == 2, "owner_keys is not exactly two keys (D30)")
    for i, entry in enumerate(record["owner_keys"]):
        where = "owner_keys[%d]" % i
        _exact(entry, "owner_key", where)
        require(entry["role"] in ROLES and entry["role"] not in roles, "%s: the role %r is not one of %s, once each" % (where, entry["role"], ", ".join(ROLES)))
        serial = _serial(entry["serial"], where + ".serial")
        require(serial not in owners, "%s: the card %s holds two owner keys" % (where, serial))
        require(entry["alg"] == "ed25519", "%s is not an Ed25519 key" % where)
        require(entry["attested"] is True, "%s: the key is not attested as made on its card (D5)" % where)
        owners[serial], roles[entry["role"]] = _key(entry["key"], where + ".key"), serial
    require(sorted(roles) == sorted(ROLES), "owner_keys lacks a role: %s" % ", ".join(sorted(set(ROLES) - set(roles))))
    require(len(set(owners.values())) == 2, "the two owner cards hold the same key")
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
    return {"owners": owners, "roles": roles, "release_key": key, "session": record["session"], "at": record["at"]}
