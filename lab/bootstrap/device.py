"""Disposable real PKCS#11 sessions; software token state is not hardware custody."""

import hashlib
import os

import PyKCS11 as p11
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from peer import Refusal


class Device:
    def __init__(self, root):
        self.root = root / "device"
        self.root.mkdir(mode=0o700)
        self.store = self.root / "tokens"
        self.store.mkdir(mode=0o700)
        self.config = self.root / "softhsm.conf"
        self.config.write_text(f"directories.tokendir = {self.store}\nobjectstore.backend = file\nlog.level = ERROR\n")
        self.pin = os.urandom(16).hex()
        self.label = "regalia-lab"
        self.session = None
        self.present = True
        self.load()
        so_pin = os.urandom(16).hex()
        self.lib.initToken(self.lib.getSlotList()[0], so_pin, self.label)
        session = self.lib.openSession(self.slot(), p11.CKF_SERIAL_SESSION | p11.CKF_RW_SESSION)
        session.login(so_pin, p11.CKU_SO)
        session.initPin(self.pin)
        session.logout()
        session.login(self.pin)
        pub, private = session.generateKeyPair([
            (p11.CKA_TOKEN, True), (p11.CKA_PRIVATE, False), (p11.CKA_MODULUS_BITS, 2048),
            (p11.CKA_PUBLIC_EXPONENT, (1, 0, 1)), (p11.CKA_VERIFY, True), (p11.CKA_ID, (1,))], [
            (p11.CKA_TOKEN, True), (p11.CKA_PRIVATE, True), (p11.CKA_SENSITIVE, True),
            (p11.CKA_EXTRACTABLE, False), (p11.CKA_SIGN, True), (p11.CKA_ID, (1,))])
        modulus, exponent = session.getAttributeValue(pub, [p11.CKA_MODULUS, p11.CKA_PUBLIC_EXPONENT])
        self.public = rsa.RSAPublicNumbers(int.from_bytes(bytes(exponent), "big"),
                                          int.from_bytes(bytes(modulus), "big")).public_key()
        self.der = self.public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.fingerprint = hashlib.sha256(self.der).hexdigest()
        local, sensitive, extractable = session.getAttributeValue(private, [p11.CKA_LOCAL, p11.CKA_SENSITIVE, p11.CKA_EXTRACTABLE])
        self.attributes = {"local": local, "sensitive": sensitive, "extractable": extractable}
        self.private_unreadable = session.getAttributeValue(private, [p11.CKA_PRIVATE_EXPONENT]) == [None]
        session.logout()
        session.closeSession()

    def load(self):
        os.environ["SOFTHSM2_CONF"] = str(self.config)
        self.lib = p11.PyKCS11Lib()
        self.lib.load("/usr/lib/softhsm/libsofthsm2.so")

    def slot(self):
        for slot in self.lib.getSlotList(tokenPresent=True):
            if self.lib.getTokenInfo(slot).label.rstrip(" \0") == self.label:
                return slot
        raise Refusal()

    def authenticate(self):
        if not self.present:
            raise Refusal()
        if self.session is None:
            self.session = self.lib.openSession(self.slot(), p11.CKF_SERIAL_SESSION)
            self.session.login(self.pin)
            matches = self.session.findObjects([(p11.CKA_CLASS, p11.CKO_PRIVATE_KEY), (p11.CKA_ID, (1,))])
            if len(matches) != 1:
                raise RuntimeError("test private key unavailable")
            self.private = matches[0]

    def sign(self, message):
        if not self.present or self.session is None:
            raise Refusal()
        return bytes(self.session.sign(self.private, message, p11.Mechanism(p11.CKM_SHA256_RSA_PKCS, None)))

    def logout(self):
        if self.session is not None:
            self.session.logout()
            self.session.closeSession()
            self.session = None

    def logout_probe(self):
        if self.session is None:
            raise RuntimeError("probe needs an authenticated positive control")
        session, key = self.session, self.private
        session.logout()
        self.session = None
        try:
            session.sign(key, b"logout-probe", p11.Mechanism(p11.CKM_SHA256_RSA_PKCS, None))
            return False
        except p11.PyKCS11Error as error:
            if error.value not in [p11.CKR_USER_NOT_LOGGED_IN, p11.CKR_OBJECT_HANDLE_INVALID]:
                raise
            return True
        finally:
            session.closeSession()

    def wrong_pin_probe(self):
        self.logout()
        session = self.lib.openSession(self.slot(), p11.CKF_SERIAL_SESSION)
        try:
            session.login(("0" if self.pin[0] != "0" else "1") + self.pin[1:])
            session.logout()
            return False
        except p11.PyKCS11Error as error:
            if error.value != p11.CKR_PIN_INCORRECT:
                raise
            return True
        finally:
            session.closeSession()

    def remove(self):
        if self.present:
            self.logout()
            self.lib.unload()
            self.store.rename(self.root / "offline-tokens")
            self.store.mkdir(mode=0o700)
            self.present = False
            self.load()

    def insert(self):
        if not self.present:
            self.lib.unload()
            self.store.rmdir()
            (self.root / "offline-tokens").rename(self.store)
            self.load()
            self.present = True
