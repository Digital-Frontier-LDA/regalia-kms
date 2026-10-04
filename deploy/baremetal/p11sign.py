#!/usr/bin/env python3
"""A key on a PKCS#11 token, used in process (#262; moved here from the retired authority.py, #199): chosen by
serial in the very session that logs in, its PIN never in an argv or a child's environment, a refused PIN latched
and never presented again, and every signature verified before it is returned. Used by manifest.py (the membership
root, ECDSA P-256) and owner.py (the owner's approval YubiKeys, Ed25519)."""
import hashlib
import json
import os
import re
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from deploy.baremetal import membership

Refused, require = membership.Refused, membership.require


class Pkcs11Signer:
    """A key on a token, in process: the membership root on its Nitrokey (manifest.py, #156: ECDSA P-256, the
    token's PKCS#11 offers no EdDSA) and the owner's approval YubiKeys (owner.py, #199: Ed25519 through OpenSC).
    First written for the revocation authority (#262), retired with it (#199); its rules are unchanged.

    IN PROCESS, ONE SESSION (regalia-kms-d9's read of #262, decided by regalia-kms-24). The token is
    chosen by SERIAL, never by label or slot number, and the serial is read in the very session that
    logs in: the one slot whose token has it is found, a session opened on it, the serial read again
    from that session's slot, and only then C_Login and C_Sign. A token removed or swapped after that
    read ends the session (CKR_DEVICE_REMOVED, CKR_SESSION_HANDLE_INVALID), so the PIN can reach only
    the token whose serial was read: a slot renumbered by a hot-plugged reader, or another card in the
    same reader, never receives it. (Two pkcs11-tool runs, one to find the slot and one to log in, could
    not promise that.) The serial is read once more after signing, and a difference is refused.
      * The PIN comes from a systemd credential ($CREDENTIALS_DIRECTORY/<pin_credential>), alphanumeric,
        4 to 64 characters (what the ceremony issues). It stays in this process: no argv, no child's
        environment.
      * `opensc_conf` (e.g. deploy/opensc/ignore-yubikey.conf) keeps OpenSC off every other reader; set
        before the module is loaded.
      * The signature is CKM_ECDSA over SHA-256 of the message, r || s, normalised to low-S (the
        verifiers refuse high-S), and verified against the token's public key before it is returned.

    THE PIN IS NEVER SPENT BY RETRYING (regalia-kms-d9, decided by regalia-kms-24; the Go daemon's PIN
    latch, request-context-is-not-token-evidence). The beat loop retries a failed signature, and a
    restart retries too, so a wrong PIN credential would lock the token within three tries, and the
    revocation key with it until an SO-PIN ceremony.
      * The token refuses the PIN (CKR_PIN_INCORRECT, CKR_PIN_INVALID, CKR_PIN_LEN_RANGE,
        CKR_PIN_LOCKED from C_Login): the signer LATCHES. It never calls C_Login again, writes
        <state_dir>/pin-latch.json (0600, read at every start), and the event goes to the trail once.
        Only `authority.py clear-pin-latch`, run as root, removes it. Fix the credential first.
      * Before every C_Login the token's flags are read, and a token with CKF_USER_PIN_COUNT_LOW,
        FINAL_TRY or LOCKED set is refused with no login: its last tries are kept for a human.
      * Nothing else latches. A token pulled out, a session ended, or any other error refuses that
        signature and the next one tries again.
    `pkcs11` is the PyKCS11 module (Debian: python3-pykcs11); a test passes a stand-in.

    FOR AN OPERATOR'S TOOL (manifest.py, #156: the membership root on its offline Nitrokey), each opt-in, the
    authority's behaviour unchanged without them:
      * `label`: the token's label is asserted beside its serial, in the same places: in the listing, and
        again from the session's own slot before C_Login.
      * `only_token`: exactly one initialised token is attached (CKF_TOKEN_INITIALIZED: a module's spare
        empty slot or a blank card can take no PIN), counted in the same listing that finds the serial.
      * `key_label`: the key is found by CKA_LABEL as well as (or instead of) CKA_ID; still exactly one
        object of the class must match, so a label two keys share is refused rather than one picked.
      * `pin`: a callable returning the PIN (the tool reads an environment variable or the terminal, no
        echo). The latch and the low-tries refusal apply to it exactly as to the credential.
      * `alg="ed25519"` (#199: the owner's approval YubiKeys, Ed25519 on the OpenPGP applet through OpenSC, #126):
        the key must be an Ed25519 key (CKA_EC_PARAMS the curve's OID or its name), the token signs the MESSAGE
        itself with CKM_EDDSA (EdDSA hashes internally), and the 64-byte signature is verified the same way."""
    kind = "pkcs11"
    ALGS = ("ecdsa-p256", "ed25519")
    P256_PARAMS = bytes.fromhex("06082a8648ce3d030107")   # DER OID prime256v1
    # DER OID 1.3.101.112, or the PrintableString "edwards25519" that OpenSC and SoftHSM also write
    ED25519_PARAMS = (bytes.fromhex("06032b6570"), bytes.fromhex("130c") + b"edwards25519")
    PIN_REFUSALS = ("CKR_PIN_INCORRECT", "CKR_PIN_INVALID", "CKR_PIN_LEN_RANGE", "CKR_PIN_LOCKED")
    PIN_LOW = ("CKF_USER_PIN_COUNT_LOW", "CKF_USER_PIN_FINAL_TRY", "CKF_USER_PIN_LOCKED")

    def __init__(self, module, serial, key_id, pin_credential, opensc_conf=None, credentials=None, pkcs11=None, latch_path=None,
                 label=None, only_token=False, key_label=None, pin=None, alg="ecdsa-p256"):
        if pkcs11 is None:
            import PyKCS11 as pkcs11
        require(alg in self.ALGS, "the key's algorithm is one of %s" % ", ".join(self.ALGS))
        self.alg = alg
        require(key_id is not None or key_label is not None, "the key is named by its id, its label, or both")
        require((pin_credential is None) != (pin is None), "the PIN comes from one source: a credential or the caller")
        self.pkcs11, self.serial, self.key_id = pkcs11, serial, bytes.fromhex(key_id) if key_id is not None else None
        self.label, self.only_token, self.key_label, self.pin_source = label, only_token, key_label, pin
        self.credentials = credentials or os.environ.get("CREDENTIALS_DIRECTORY")
        self.pin_credential = pin_credential
        self.latch_path, self.on_latch = latch_path, None
        self.latched = _read_latch(latch_path)
        if opensc_conf:
            os.environ["OPENSC_CONF"] = opensc_conf         # read by OpenSC when the module loads, below
        self.lib = pkcs11.PyKCS11Lib()
        self.lib.load(module)
        session, _ = self._session()
        try:
            self._public = self._read_public(session)
        finally:
            session.closeSession()

    def _serial_of(self, slot):
        return str(self.lib.getTokenInfo(slot).serialNumber).strip()

    def _is_ours(self, slot):
        """The token in `slot` has our serial, and our label when one is asserted."""
        info = self.lib.getTokenInfo(slot)
        return str(info.serialNumber).strip() == self.serial and (self.label is None or str(info.label).strip() == self.label)

    def _named(self):
        return "serial %s" % self.serial + ("" if self.label is None else " and label %r" % self.label)

    def _session(self):
        """A session on the one token with this serial (and label), both read again from the session's slot."""
        present = self.lib.getSlotList(tokenPresent=True)
        if self.only_token:
            # initialised tokens: a module's spare empty slot (SoftHSM always lists one) or a blank card can take no PIN
            initialised = [slot for slot in present if int(self.lib.getTokenInfo(slot).flags) & self.pkcs11.CKF_TOKEN_INITIALIZED]
            require(len(initialised) == 1, "%d initialised tokens are attached: attach only the one with %s"
                    % (len(initialised), self._named()))
        slots = [slot for slot in present if self._is_ours(slot)]
        require(len(slots) == 1, "%s token with %s is present" % ("no" if not slots else "more than one", self._named()))
        session = self.lib.openSession(slots[0])
        try:
            slot = session.getSessionInfo().slotID
            require(slot == slots[0] and self._is_ours(slot),
                    "the token in the session's slot is not %s: refused before the PIN" % self._named())
        except BaseException:
            session.closeSession()
            raise
        return session, slot

    def _object(self, session, cls):
        template = [(self.pkcs11.CKA_CLASS, cls)]
        if self.key_id is not None:
            template.append((self.pkcs11.CKA_ID, self.key_id))
        if self.key_label is not None:
            template.append((self.pkcs11.CKA_LABEL, self.key_label))
        found = session.findObjects(template)
        require(len(found) == 1, "the token holds %d objects of that class with %s, not one" % (len(found), self._key_named()))
        return found[0]

    def _key_named(self):
        return " and ".join(([] if self.key_id is None else ["id %s" % self.key_id.hex()]) +
                            ([] if self.key_label is None else ["label %r" % self.key_label]))

    def _read_public(self, session):
        point, params = session.getAttributeValue(self._object(session, self.pkcs11.CKO_PUBLIC_KEY),
                                                  [self.pkcs11.CKA_EC_POINT, self.pkcs11.CKA_EC_PARAMS])
        point, params = bytes(point), bytes(params)
        if self.alg == "ed25519":
            if len(point) == 34 and point[:2] == b"\x04\x20":     # DER OCTET STRING around the 32-byte key
                point = point[2:]
            require(params in self.ED25519_PARAMS and len(point) == 32, "the token's key %s is not an Ed25519 key" % self._key_named())
            Ed25519PublicKey.from_public_bytes(point)
            return point.hex()
        if len(point) == 67 and point[:2] == b"\x04\x41":     # DER OCTET STRING around the point
            point = point[2:]
        require(params == self.P256_PARAMS and len(point) == 65 and point[0] == 4, "the token's key %s is not a P-256 key" % self._key_named())
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)   # on the curve
        return point.hex()

    def _pin(self):
        if self.pin_source is not None:
            pin = self.pin_source()
            require(isinstance(pin, str) and re.fullmatch(r"[0-9A-Za-z]{4,64}", pin) is not None, "the PIN given is not a PIN (alphanumeric, 4 to 64)")
            return pin
        require(self.credentials, "no systemd credentials directory: the PIN comes from LoadCredentialEncrypted=")
        path = os.path.join(self.credentials, self.pin_credential)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            pin = os.read(fd, 256).decode().strip()
        finally:
            os.close(fd)
        require(re.fullmatch(r"[0-9A-Za-z]{4,64}", pin) is not None, "the PIN credential is not a PIN (alphanumeric, 4 to 64)")
        return pin

    def public(self):
        return self._public

    def _latch(self, reason):
        self.latched = {"reason": reason, "serial": self.serial, "at": int(time.time())}
        if self.latch_path:
            _write_latch(self.latch_path, self.latched)
        if self.on_latch:
            self.on_latch(self.latched)

    def _login(self, session, slot, pin):
        flags = int(self.lib.getTokenInfo(slot).flags)
        low = [name for name in self.PIN_LOW if flags & getattr(self.pkcs11, name)]
        require(not low, "the token reports %s: no login is tried, its last tries are kept for a human. One correct login "
                "(`pkcs11-tool --login --test` with the right PIN) resets the counter; then restart" % ", ".join(low))
        try:
            session.login(pin)
        except self.pkcs11.PyKCS11Error as error:
            refused = [name for name in self.PIN_REFUSALS if getattr(error, "value", None) == getattr(self.pkcs11, name)]
            if refused:
                self._latch(refused[0])
                raise Refused("the token refused the PIN (%s): latched, no further attempt is made; %s" % (refused[0], WAY_OUT)) from error
            raise

    def sign(self, message):
        require(not self.latched, "the token refused the PIN (%s) and the signer is latched, no further attempt is made: %s"
                % ((self.latched or {}).get("reason"), WAY_OUT))
        pin = self._pin()                                # before any session: a missing PIN touches no token
        session, slot = self._session()
        try:
            self._login(session, slot, pin)
            try:
                if self.alg == "ed25519":           # EdDSA signs the message itself
                    data, mechanism = message, self.pkcs11.Mechanism(self.pkcs11.CKM_EDDSA)
                else:
                    data, mechanism = hashlib.sha256(message).digest(), self.pkcs11.Mechanism(self.pkcs11.CKM_ECDSA)
                raw = bytes(session.sign(self._object(session, self.pkcs11.CKO_PRIVATE_KEY), data, mechanism))
                require(self._serial_of(slot) == self.serial, "the token's serial changed while it signed: refused")
            finally:
                session.logout()
        finally:
            session.closeSession()
        require(len(raw) == 64, "the token returned a %d-byte signature, not 64" % len(raw))
        if self.alg == "ed25519":
            membership.verify_revocation(self.alg, self._public, message, raw.hex(), "token")
            return raw
        r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        s = min(s, membership.P256_ORDER - s)            # low-S: the verifiers refuse the other form
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        membership.verify_revocation(self.alg, self._public, message, signature.hex(), "token")
        return signature


PIN_LATCH = "pin-latch.json"
# The way out of a PIN latch. The refusal left the token's counter low (CKF_USER_PIN_COUNT_LOW), which
# the signer also refuses, and only a correct login resets it (regalia-kms-d9).
WAY_OUT = ("fix the credential, reset the token's counter with one correct login (`pkcs11-tool --login --test` with the "
           "right PIN), then the tool's `clear-pin-latch` as root, and try again")


def _read_latch(path):
    """The persisted PIN latch, or None. One that cannot be read as a latch is treated as one: a damaged
    file never re-opens the way to the PIN."""
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            latch = json.loads(f.read(4096))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return {"reason": "an unreadable pin-latch.json"}
    return latch if isinstance(latch, dict) else {"reason": "an unreadable pin-latch.json"}


def _write_latch(path, latch):
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".pin-latch-")
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, json.dumps(latch, sort_keys=True).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(tmp, path)
    dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
