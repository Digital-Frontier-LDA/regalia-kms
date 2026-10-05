"""The card-ceremony record, verified by the side that consumes it (regalia-ceremony#111 step 2; ADR-0002 D30).

The card ceremony writes `cards.record.json`: which cards hold the owner's two keys (the OWNER pair's OpenPGP SIG
keys, ADR-0002 D30.7: never the developer cards, which hold no KMS key) and which hold the release key, signed by the membership root in the offline session that made them. The
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
  * owner_keys are exactly two, the roles owner-main and owner-backup (D30.7), with distinct serials and keys, Ed25519,
    and each attested on its card (D5), naming the SHA-256 of its SIG, DEC and AUT keys' attestation certificates (their
    DER), all six distinct; given the certificates (`attestations`, #400), each is verified as made on that card (attested());
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

CURRENT LIMITATIONS (stated, not hidden; the cross-cutting list is LIMITATIONS.md):
  * "attested" is verified only when the certificates are given (`attestations`; `propose --genesis` requires them):
    without them, verify() checks the digests' form and distinctness only, and says so ("attestations": "not given").
    The trust and its limits are opgpattest's (one card measured, no revocation, vendored intermediates).
  * "Newest" is by THIS laptop's signing record, not by every use of the root: the root is a Shamir software key
    (D28), and one reconstructed elsewhere with a fresh state directory signs a valid "sequence 1" (the card
    ceremony's --first-card-record makes that visible, regalia-ceremony#111).
  * The signing record is not hash-chained (plain fsync'd 0600 lines, as manifest signing's): a deleted line, a cut
    tail or a state directory restored from an older backup is not seen here. The backstop is the ceremony sheet
    (`card record N of M, digest ...`, printed by propose --genesis); #405 would anchor the newest digest in the
    root-signed manifest. A lost state directory is rebuilt (#406) from ONE baseline line standing for 1..N, which
    is only as true as its source: the ceremony sheet before genesis, the chain's card_record pin after it.
  * The release key's OpenPGP fingerprint is checked for form and distinctness, not tied to its cards (the producer
    reads it from them; the release key is imported, so there is no attestation to tie it to). The SSH signers' keys
    are tied to their owner cards only through the AUT attestations, so only when they are given.
  * The bench YubiKeys refused are a hand-kept list (membership.BENCH_YUBIKEYS).
  * Verified against the producer's signed vectors and records made in tests; no ceremony has produced a real one yet.
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
ROLES = ("owner-main", "owner-backup")      # the OWNER pair (D30.7): the developer cards are in no KMS record
ATTESTED_SLOTS = ("sig", "dec", "aut")      # each owner card's three OpenPGP keys, each attested (D5, D30.7; regalia-kms-51)
TOUCH_FIXED = 2                             # the attested touch policy (5.8) every owner key must have: on, and fixed (D30.7)
FIELDS = {
    "record": ("schema", "event", "owner_keys", "ownerauth_recipients", "ssh_signers", "release_key", "session", "root_entry",
               "root_fingerprint", "tool", "at", "sequence", "supersedes"),
    "card_record_line": ("kind", "sequence", "digest", "key", "at"),
    "baseline_line": ("kind", "sequence", "digest", "key", "at", "source"),
    "rebuild": ("schema", "event", "baseline", "disc_record_sha256", "rebuilt", "root_entry", "root_fingerprint", "session", "tool", "at"),
    "rebuild_baseline": ("sequence", "digest", "source"),
    "rebuild_rebuilt": ("sequence", "digest"),
    "signing_state": ("schema", "root"),
    "owner_key": ("role", "serial", "alg", "key", "attested", "attestation_sha256"),
    "attestation_sha256": ("sig", "dec", "aut"),
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
# a REBUILT state directory (#406, regalia-ceremony#131): the signing record's first card line is ONE card-record-baseline
# line standing for the lost history 1..N, and the root-signed record of that rebuild is beside it, under its OWN domain
# (a signature over one can never be presented as a card record's)
BASELINE_KIND = "card-record-baseline"
BASELINE_SOURCES = ("chain", "sheet")
REBUILD_RECORD = "card-record-rebuild.record.json"
REBUILD_SCHEMA = "regalia.card-record-rebuild/v1"
REBUILD_EVENT = "card-record-rebuild"
REBUILD_DOMAIN = b"regalia-card-record-rebuild/v1\x00"
MAX_REBUILD_RECORD = 64 * 1024
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
    baselines = [line for line in lines if line["kind"] == BASELINE_KIND]
    if baselines:                       # a rebuilt record carries the root-signed record of its rebuild (d9 on #406)
        held = _read_own(state_dir, REBUILD_RECORD, MAX_REBUILD_RECORD, "the rebuild record %s" % REBUILD_RECORD)
        require(held is not None, "the signing record has a baseline but %s holds no %s as a regular file" % (state_dir, REBUILD_RECORD))
        try:
            rebuild = verify_rebuild(json.loads(held.decode("ascii")), root)
        except (UnicodeDecodeError, ValueError):
            raise Refused("the rebuild record %s is not JSON" % REBUILD_RECORD) from None
        base = baselines[0]
        require(rebuild["baseline"] == {"sequence": base.get("sequence"), "digest": base.get("digest"), "source": base.get("source")},
                "the rebuild record does not name the signing record's baseline")
        # the record it re-signed as N+1 is the signing record's line N+1, once that line is written (a crash between the
        # baseline line and it leaves none: the baseline is then the newest)
        following = [line for line in lines if line["kind"] == "card-record" and line.get("sequence") == rebuild["rebuilt"]["sequence"]]
        require(all(line.get("digest") == rebuild["rebuilt"]["digest"] for line in following),
                "the signing record's card record %d is not the one its rebuild record re-signed" % rebuild["rebuilt"]["sequence"])
    return lines


def verify_rebuild(envelope, root):
    """The root-signed record of a state directory's rebuild (#406, regalia-ceremony#131's writer): exactly {record,
    signature}, every field by name, signed by the PINNED root over REBUILD_DOMAIN and the canonical record. Returns the
    record. Read for its baseline (which the signing record's baseline line must equal), and printed, never trusted further."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    require(isinstance(envelope, dict), "the rebuild record is not an object")
    membership.exact(envelope, ("record", "signature"), "the rebuild record")
    _ascii(envelope, "the rebuild record")
    record, signature = envelope["record"], envelope["signature"]
    require(isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{128}", signature) is not None, "the rebuild record's signature is not 128 hex")
    _exact(record, "rebuild", "the rebuild record")
    _exact(record["root_entry"], "root_entry", "the rebuild record's root_entry")
    require(record["root_entry"] == {"alg": "ed25519", "key": root}, "the rebuild record names another root than the pinned one")
    require(record["root_fingerprint"] == hashlib.sha256(bytes.fromhex(root)).hexdigest(), "the rebuild record's root_fingerprint is not the root's")
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(root)).verify(bytes.fromhex(signature), REBUILD_DOMAIN + membership.canonical(record))
    except (InvalidSignature, ValueError):
        raise Refused("the rebuild record's signature does not verify under the pinned root") from None
    require(record["schema"] == REBUILD_SCHEMA and record["event"] == REBUILD_EVENT, "the rebuild record is not a %s (%s)" % (REBUILD_SCHEMA, REBUILD_EVENT))
    _exact(record["baseline"], "rebuild_baseline", "the rebuild record's baseline")
    _exact(record["rebuilt"], "rebuild_rebuilt", "the rebuild record's rebuilt")
    for what, entry in (("baseline", record["baseline"]), ("rebuilt", record["rebuilt"])):
        require(type(entry["sequence"]) is int and entry["sequence"] >= 1, "the rebuild record's %s.sequence is not a count from 1" % what)
        require(isinstance(entry["digest"], str) and HEX64.fullmatch(entry["digest"]) is not None,
                "the rebuild record's %s.digest is not a SHA-256 (64 lowercase hex)" % what)
    require(record["baseline"]["source"] in BASELINE_SOURCES, "the rebuild record's baseline.source is not one of %s" % ", ".join(BASELINE_SOURCES))
    require(record["rebuilt"]["sequence"] == record["baseline"]["sequence"] + 1,
            "the rebuild record's rebuilt record is not the one after its baseline")
    require(isinstance(record["disc_record_sha256"], str) and HEX64.fullmatch(record["disc_record_sha256"]) is not None,
            "the rebuild record's disc_record_sha256 is not a SHA-256 (64 lowercase hex)")
    return record


def _newest(record, root, signing_lines, pin=None):
    """`record` is the newest card line M (or, with `pin`, the chain's pinned record), and supersedes line M-1. A rebuilt
    record (#406) starts with ONE card-record-baseline line N standing for the lost history 1..N; card lines then run
    N+1..M. Returns (M, the baseline line or None, whether supersedes was checked: None under a pin, which decides alone)."""
    cards = []
    for number, line in enumerate(signing_lines, 1):
        require(isinstance(line, dict) and isinstance(line.get("kind"), str),
                "the signing record's line %d is not an object with a kind (\"manifest\", \"card-record\")" % number)
        if line["kind"] in ("card-record", BASELINE_KIND):
            cards.append(line)
    baselines = [i for i, line in enumerate(cards) if line["kind"] == BASELINE_KIND]
    # 51's texts on #406 (regalia-ceremony's reader refuses the same things with the same words)
    require(len(baselines) <= 1, "the signing record holds more than one card-record-baseline line")
    require(baselines in ([], [0]), "a card-record-baseline line is not the first card line of the signing record")
    base = cards[0] if baselines else None
    if base is not None:
        _exact(base, "baseline_line", "the card-record-baseline line")
        require(type(base["sequence"]) is int and base["sequence"] >= 1 and isinstance(base["digest"], str)
                and HEX64.fullmatch(base["digest"]) is not None and base["source"] in BASELINE_SOURCES,
                "the card-record-baseline line is malformed (sequence an integer from 1, digest 64 hex, source chain or sheet)")
        require(base["key"] == root, "the card-record-baseline line names another root than the pinned one")
    for number, line in enumerate(cards[1:] if base else cards, 1):
        _exact(line, "card_record_line", "the signing record's card-record line %d" % number)
        require(line["key"] == root, "the signing record's card-record line %d names another root than the pinned one" % number)
        _key(line["digest"], "the signing record's card-record line %d's digest" % number)
    require(cards, "the signing record holds no card-record line: this card record cannot be shown to be the newest (wrong --state-dir?)")
    sequences = [line["sequence"] for line in (cards[1:] if base else cards)]
    start = base["sequence"] + 1 if base else 1
    require(all(type(s) is int for s in sequences) and sequences == list(range(start, start + len(sequences))),
            ("the signing record's card-record lines are not %d..%d without a gap after its baseline" % (start, start + len(sequences) - 1))
            if base else "the signing record's card-record lines are not 1..%d without a gap or a repeat (%s)" % (len(cards), sequences))
    if pin is not None:
        # after genesis the verified chain's card_record pin decides, not the laptop's record (d9 on #406): the record must be
        # the pinned one, and the record must hold it (its line, or the baseline standing for it)
        require(isinstance(pin, (tuple, list)) and len(pin) == 2 and type(pin[0]) is int and isinstance(pin[1], str),
                "the pin is (sequence, digest)")
        require((record["sequence"], digest(record)) == (pin[0], pin[1]),
                "this card record is not the one the chain pins (sequence %s): only the pinned record counts after genesis" % pin[0])
        require(any((line["sequence"], line["digest"]) == (pin[0], pin[1]) for line in cards),
                "the chain's pinned card record is not in this signing record")
        return cards[-1]["sequence"], base, None                     # the pin decides: supersedes is not this path's question
    newest = cards[-1]
    require(record["sequence"] == newest["sequence"] and digest(record) == newest["digest"],
            "this card record (sequence %d) is not the newest the root signed (sequence %d, digest %s): an older one is superseded"
            % (record["sequence"], newest["sequence"], newest["digest"][:16]))
    if len(cards) > 1:
        require(record["supersedes"] == cards[-2]["digest"], "this card record does not supersede the one before it in the signing record")
        return newest["sequence"], base, True
    if base is not None:
        return newest["sequence"], base, False                     # the baseline itself: what came before it is lost
    require(record["supersedes"] == "", "this card record does not supersede the one before it in the signing record")
    return newest["sequence"], None, True


def attested(record, directory, anchors=None):
    """#400: each owner key's three attestation certificates (attestation_sha256.{sig, dec, aut}), found in `directory` by
    the SHA-256 of their DER (the producer writes DER files, regalia-kms-51), verified as made ON THAT CARD:
      * each chains, through a card's "YubiKey OPGP Attestation" certificate in `directory`, to the pinned Yubico root
        (opgpattest.verify), and is the attestation of its own slot (SIG, DEC, AUT);
      * each names the card's serial (5.7), says the key was generated on the card (5.2, D5) and that its touch policy is
        fixed (5.8, D30.7);
      * SIG's key is the recorded owner key; SIG's and DEC's OpenPGP fingerprints (5.4) are the card's ownerauth
        recipient's primary and subkey; AUT's key is the card's SSH signing key (ssh_signers).
    `record` is verify()'s, already checked; the first failure refuses, by name."""
    from deploy.baremetal import opgpattest
    try:
        certs = opgpattest.certificates(directory)
    except OSError as error:
        raise Refused("the attestation certificates cannot be read from %s: %s" % (directory, error.strerror or error)) from None
    cards = opgpattest.devices(certs)
    recipients = {e["serial"]: e for e in record["ownerauth_recipients"]}
    ssh = {e["serial"]: _ssh_ed25519(e["key"], "ssh_signers") for e in record["ssh_signers"]}
    for entry in record["owner_keys"]:
        serial, where = entry["serial"], "owner card %s (%s)" % (entry["serial"], entry["role"])
        for f in ATTESTED_SLOTS:
            digest_ = entry["attestation_sha256"][f]
            cert = certs.get(digest_)
            require(cert is not None, "%s: no certificate in %s has the %s attestation's SHA-256 %s…" % (where, directory, f.upper(), digest_[:16]))
            got = opgpattest.verify(cert, cards, f.upper(), anchors=anchors)
            what = "%s: its %s attestation" % (where, f.upper())
            require(got["serial"] == serial, "%s names the card %s, not %s" % (what, got["serial"], serial))
            require(got["source"] == opgpattest.GENERATED, "%s says the key was imported, not generated on the card (D5)" % what)
            require(got["touch"] == TOUCH_FIXED, "%s gives the touch policy %d, not fixed (%d, D30.7)" % (what, got["touch"], TOUCH_FIXED))
            if f == "sig":
                require(got["key_type"] == "ed25519" and got["key"].hex() == entry["key"], "%s is of another key than the recorded owner key" % what)
                require(got["fingerprint"] == recipients[serial]["primary"], "%s's fingerprint %s is not the card's ownerauth recipient's primary %s"
                        % (what, got["fingerprint"], recipients[serial]["primary"]))
            elif f == "dec":
                require(got["fingerprint"] == recipients[serial]["subkey"], "%s's fingerprint %s is not the card's ownerauth recipient's subkey %s"
                        % (what, got["fingerprint"], recipients[serial]["subkey"]))
            else:
                require(got["key_type"] == "ed25519" and got["key"].hex() == ssh[serial], "%s is of another key than the card's SSH signing key" % what)


def verify(envelope, root, signing_lines, pin=None, attestations=None, anchors=None):
    """The card-ceremony record in `envelope`, checked against the pinned `root` (64 hex, the raw Ed25519 root key) and
    the laptop's root signing record (`signing_lines`, from read_signing_state: REQUIRED, there is no unjudged path):
    see the module text. Returns its owner and release keys, and where it stands among the root's card records. `pin`,
    (sequence, digest) from the verified chain's card_record (#405, `manifest verify`'s CARD-RECORD-PIN), is given after
    genesis: then only the pinned record counts, whatever the laptop's record says is newest (#406).
    `attestations`: the directory of the owner cards' attestation certificates (the ceremony disc's cards/, #400),
    each owner key's three then verified (attested()); `anchors` the Yubico trust for a test (opgpattest.verify)."""
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
    require(isinstance(record["owner_keys"], list) and len(record["owner_keys"]) == 2, "owner_keys is not exactly two keys: the two owner cards' (D30.7)")
    for i, entry in enumerate(record["owner_keys"]):
        where = "owner_keys[%d]" % i
        _exact(entry, "owner_key", where)
        require(entry["role"] in ROLES and entry["role"] not in roles, "%s: the role %r is not one of %s, once each" % (where, entry["role"], ", ".join(ROLES)))
        serial = _serial(entry["serial"], where + ".serial")
        require(serial not in owners, "%s: the card %s holds two owner keys" % (where, serial))
        require(entry["alg"] == "ed25519", "%s is not an Ed25519 key" % where)
        require(entry["attested"] is True, "%s: the key is not attested as made on its card (D5)" % where)
        _exact(entry["attestation_sha256"], "attestation_sha256", where + ".attestation_sha256")
        for f in ATTESTED_SLOTS:
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
    require(key not in owners.values(), "the release key is an owner key: the release cards hold no owner key (D30.3, D30.7)")
    require(not set(cards) & set(owners), "a release card is an owner card (D30.3, D30.7): %s" % ", ".join(sorted(set(cards) & set(owners))))
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
    of, base, checked = _newest(record, root, signing_lines, pin)   # #403: the newest the root signed, by the laptop's record
    if attestations is not None:
        attested(record, attestations, anchors)
    return {"attestations": "verified" if attestations is not None else "not given",
            "owners": owners, "roles": roles, "release_key": key, "session": record["session"], "at": record["at"],
            "sequence": record["sequence"], "of": of, "digest": digest(record), "supersedes": record["supersedes"],
            "baseline": None if base is None else {k: base[k] for k in ("sequence", "digest", "source")}, "supersedes_checked": checked,
            "pinned": pin is not None}
