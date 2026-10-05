"""A YubiKey's OpenPGP key attestation, verified offline (#400; ADR-0002 D5: an owner key is generated on its card).

`ykman openpgp keys attest SIG|DEC|AUT` gives a certificate for the key in that slot, signed by the card's
"YubiKey OPGP Attestation" certificate (`ykman openpgp certificates export ATT`), which Yubico issued:

    "YubiKey OPGP Attestation SIG"  <- "YubiKey OPGP Attestation"  <- "Yubico OPGP Attestation {A,B,B2} 1"
        <- "Yubico Attestation Intermediate {A,B} 1"  <- "Yubico Attestation Root 1"

Measured on YubiKey 35718625 (firmware 5.7.4, regalia-kms-24, 2026-10-05): the fixtures in
tests/vectors/opgp-attestation-35718625. The card's attestation key, like PIV's f9 (regalia-ceremony's
yubikey-attestation-verify.py), signs for its batch, so a verified chain says "a genuine YubiKey made this key" and
the SERIAL Yubico's extension carries says which one: it is always compared.

The leaf's Yubico extensions (1.3.6.1.4.1.41482.5.N), each a DER value, signed by the card:
    5.2 the key's source, INTEGER: 1 generated on the card, 0 imported (D5 requires generated)
    5.3 the firmware version, OCTET STRING of 3 bytes
    5.4 the key's OpenPGP fingerprint, OCTET STRING of 20 bytes (v4)
    5.7 the card's serial, INTEGER
    5.8 the slot's touch policy, OCTET STRING of 1 byte (0 off, 1 on, 2 fixed, 3 cached, 4 cached-fixed)
    5.1 the cardholder name, 5.5 the key's generation date, 5.6 the signature counter (SIG only), 5.9 the form factor

TRUST. Yubico Attestation Root 1 is PINNED by the SHA-256 of its DER below; the vendored copy
(vendor/yubico-attestation, the same files regalia-ceremony vendors from developers.yubico.com/PKI) must match the
pin, so replacing it changes nothing trusted. The intermediates come from the vendored bundle. Every link is checked:
the issuer's name and its signature over the certificate (cryptography's verify_directly_issued_by), each issuer a
CA, and each certificate within its validity period.

CURRENT LIMITATIONS: the vendored intermediates are taken as they are (each is checked by its signature up to the
pinned root, so a substituted one fails, but a NEW Yubico intermediate needs the bundle updated); revocation is not
checked (Yubico publishes no CRL for these); measured on one card and firmware (5.7.4) only.
"""
import datetime
import hashlib
import os
import stat

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require

VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor", "yubico-attestation")
ROOT_FILE, INTERMEDIATES_FILE = "yubico-attestation-root-1.pem", "yubico-intermediates.pem"
# SHA-256 of Yubico Attestation Root 1's DER: pinned here, not read from the vendored file (regalia-ceremony pins the same)
PINNED_ROOT = "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8"
DEVICE_CN = "YubiKey OPGP Attestation"
SLOTS = ("SIG", "DEC", "AUT")
OID = "1.3.6.1.4.1.41482.5.%d"
GENERATED = 1
MAX_DEPTH = 6
MAX_FILES, MAX_FILE_BYTES = 64, 64 * 1024


def _der(value, tag, where):
    """A short DER value of `tag` (0x02 INTEGER, 0x04 OCTET STRING): its content bytes. Yubico's are a few bytes, so only
    the short length form is taken; anything else is refused by name."""
    require(isinstance(value, bytes) and len(value) >= 2 and value[0] == tag and value[1] < 0x80 and len(value) == 2 + value[1],
            "%s is not a short DER %s" % (where, {0x02: "INTEGER", 0x04: "OCTET STRING"}[tag]))
    return value[2:]


def _integer(value, where):
    content = _der(value, 0x02, where)
    require(content and (content[0] & 0x80) == 0, "%s is not a non-negative INTEGER" % where)
    return int.from_bytes(content, "big")


def extensions(cert):
    """The leaf's Yubico values: {"source", "firmware", "fingerprint", "serial", "touch"}, each required and decoded."""
    from cryptography import x509
    raw = {}
    for ext in cert.extensions:
        if isinstance(ext.value, x509.UnrecognizedExtension):
            raw[ext.oid.dotted_string] = ext.value.value
    for n in (2, 3, 4, 7, 8):
        require(OID % n in raw, "the attestation has no Yubico extension %s" % (OID % n))
    firmware = _der(raw[OID % 3], 0x04, "the firmware extension (5.3)")
    fingerprint = _der(raw[OID % 4], 0x04, "the fingerprint extension (5.4)")
    touch = _der(raw[OID % 8], 0x04, "the touch policy extension (5.8)")
    require(len(firmware) == 3, "the firmware extension (5.3) is not 3 bytes")
    require(len(fingerprint) == 20, "the fingerprint extension (5.4) is not a 20-byte OpenPGP v4 fingerprint")
    require(len(touch) == 1, "the touch policy extension (5.8) is not 1 byte")
    return {"source": _integer(raw[OID % 2], "the key source extension (5.2)"), "firmware": "%d.%d.%d" % tuple(firmware),
            "fingerprint": fingerprint.hex().upper(), "serial": str(_integer(raw[OID % 7], "the serial extension (5.7)")),
            "touch": touch[0]}


def _cn(name):
    from cryptography.x509.oid import NameOID
    values = [a.value for a in name.get_attributes_for_oid(NameOID.COMMON_NAME)]
    return values[0] if len(values) == 1 else None


def _within(cert, now, where):
    require(cert.not_valid_before_utc <= now <= cert.not_valid_after_utc, "%s (%s) is outside its validity period" % (where, _cn(cert.subject)))


def _is_ca(cert):
    from cryptography import x509
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    except x509.ExtensionNotFound:
        return False


def _issued_by(cert, issuer):
    from cryptography.exceptions import InvalidSignature
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def trust(vendor=VENDOR, pinned=PINNED_ROOT):
    """(root, intermediates) from the vendored files, the root refused unless its DER's SHA-256 is `pinned`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    with open(os.path.join(vendor, ROOT_FILE), "rb") as f:
        roots = x509.load_pem_x509_certificates(f.read())
    require(len(roots) == 1, "the vendored Yubico root file holds %d certificates, not one" % len(roots))
    require(hashlib.sha256(roots[0].public_bytes(serialization.Encoding.DER)).hexdigest() == pinned,
            "the vendored Yubico Attestation Root is not the pinned one (%s…)" % pinned[:16])
    with open(os.path.join(vendor, INTERMEDIATES_FILE), "rb") as f:
        return roots[0], x509.load_pem_x509_certificates(f.read())


def verify(leaf, devices, slot, now=None, anchors=None):
    """The attestation `leaf` (an x509 certificate) of the key in `slot` (SIG, DEC or AUT), chained through one of
    `devices` (the cards' "YubiKey OPGP Attestation" certificates) and the vendored intermediates to the pinned root.
    `anchors`: (root, intermediates), for a test; default trust(). Returns extensions(leaf) plus "key", the attested
    public key (raw bytes, Ed25519 or X25519 or another type as the card made it), and "key_type"."""
    from cryptography.hazmat.primitives import serialization
    require(slot in SLOTS, "the slot %r is not one of %s" % (slot, ", ".join(SLOTS)))
    root, intermediates = anchors or trust()
    now = now or datetime.datetime.now(datetime.timezone.utc)
    require(_cn(leaf.subject) == "%s %s" % (DEVICE_CN, slot), "the certificate is %r, not the %s slot's attestation (%s %s)"
            % (_cn(leaf.subject), slot, DEVICE_CN, slot))
    _within(leaf, now, "the attestation")
    device = [d for d in devices if _cn(d.subject) == DEVICE_CN and d.subject == leaf.issuer and _issued_by(leaf, d)]
    require(device, "no card attestation certificate (%s) given signs the %s attestation" % (DEVICE_CN, slot))
    chain, cert = [leaf, device[0]], device[0]
    while cert.subject != root.subject:
        require(len(chain) <= MAX_DEPTH, "the attestation chain is longer than %d" % MAX_DEPTH)
        above = [i for i in intermediates if i.subject == cert.issuer and _issued_by(cert, i)]
        if not above and cert.issuer == root.subject and _issued_by(cert, root):
            above = [root]
        require(above, "%r is issued by %r, which no vendored Yubico certificate is (or its signature does not verify)"
                % (_cn(cert.subject), _cn(cert.issuer)))
        cert = above[0]
        chain.append(cert)
    require(chain[-1].public_bytes(serialization.Encoding.DER) == root.public_bytes(serialization.Encoding.DER),
            "the attestation does not chain to the pinned Yubico root")
    for where, c in zip(["the attestation"] + ["%r" % _cn(c.subject) for c in chain[1:]], chain):
        _within(c, now, where)
    require(all(_is_ca(c) for c in chain[1:]), "an issuer in the attestation chain is not a CA")
    values = extensions(leaf)
    key = leaf.public_key()
    values["key"] = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) \
        if type(key).__name__ in ("Ed25519PublicKey", "X25519PublicKey", "_Ed25519PublicKey", "_X25519PublicKey") else \
        key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    values["key_type"] = type(key).__name__.lstrip("_").replace("PublicKey", "").lower()
    return values


def certificates(directory):
    """Every certificate in `directory`'s regular files (PEM, one or more; or one DER), as {SHA-256 of its DER: cert}.
    At most MAX_FILES files of MAX_FILE_BYTES each; a symbolic link, a non-regular file or an unreadable certificate
    is refused by name, so a disc that holds something else is noticed, not skipped."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    names = sorted(os.listdir(directory))
    require(0 < len(names) <= MAX_FILES, "%s holds %d files: the attestations are 1 to %d certificate files" % (directory, len(names), MAX_FILES))
    out = {}
    for name in names:
        path = os.path.join(directory, name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode), "%s is not a regular file" % path)
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read(MAX_FILE_BYTES + 1)
        finally:
            os.close(fd)
        require(len(data) <= MAX_FILE_BYTES, "%s is over %d bytes" % (path, MAX_FILE_BYTES))
        try:
            certs = x509.load_pem_x509_certificates(data) if data.lstrip().startswith(b"-----BEGIN") else [x509.load_der_x509_certificate(data)]
        except ValueError:
            raise Refused("%s is not a certificate (PEM or DER)" % path) from None
        for cert in certs:
            out[hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()] = cert
    return out


def devices(certs):
    """The cards' attestation certificates among `certs` (what certificates() returned)."""
    return [c for c in certs.values() if _cn(c.subject) == DEVICE_CN]
