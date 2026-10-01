#!/usr/bin/env python3
"""Ask the TOKEN for a private key's secret attributes through raw PKCS#11 (#62, PoC 2.1).

pkcs11-tool refuses `--read-object --type privkey` by itself ("reading private keys not (yet)
supported"), so it cannot show what the token would do. This calls C_GetAttributeValue directly,
through the module's exported C_* functions, for CKA_VALUE (EC) and CKA_PRIVATE_EXPONENT / CKA_PRIME_1
(RSA), and reports the token's answer. The verdict is per key type (CKA_KEY_TYPE): each secret
attribute that APPLIES to the key (EC: CKA_VALUE; RSA: CKA_PRIVATE_EXPONENT and CKA_PRIME_1) must be
answered with no bytes and either CKR_ATTRIBUTE_SENSITIVE (0x11), the standard refusal, or
CKR_ATTRIBUTE_TYPE_INVALID (0x12), meaning the token does not expose that attribute at all (OpenSC's
SmartCard-HSM emulation answers 0x12 for an EC key's CKA_VALUE: measured on a Nitrokey HSM 2, #62).
CKA_SENSITIVE must be true and CKA_EXTRACTABLE false. Any other answer is INCONCLUSIVE, not a pass.

    REGALIA_Q_PIN=... p11_extract_probe.py <module.so> <token serial> <hex key id>

The PIN is read from the environment, never argv. Output: one JSON line, with a "verdict". Exit 0
(REFUSED): every applicable secret attribute refused, the key sensitive and not extractable. Exit 1
(LEAK or EXPOSABLE): a secret byte returned, or the key is not sensitive / is extractable. Exit 2: a
usage or PKCS#11 error, or an INCONCLUSIVE answer (e.g. CKR_GENERAL_ERROR, or CKR_OK with no length).
Linux/x86-64 PKCS#11 ABI (CK_ULONG = unsigned long).
"""
import ctypes
import json
import os
import sys

CKR_OK, CKR_ATTRIBUTE_SENSITIVE, CKR_USER_ALREADY_LOGGED_IN = 0x0, 0x11, 0x100
CKF_SERIAL_SESSION, CKU_USER = 0x4, 1
CKO_PRIVATE_KEY = 3
CKA_CLASS, CKA_ID, CKA_KEY_TYPE, CKA_VALUE = 0x0, 0x102, 0x100, 0x11
CKA_PRIVATE_EXPONENT, CKA_PRIME_1 = 0x123, 0x124
CKA_SENSITIVE, CKA_EXTRACTABLE, CKA_LOCAL = 0x103, 0x162, 0x163
CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE = 0x165, 0x164
CK_UNAVAILABLE = ctypes.c_ulong(-1).value
U = ctypes.c_ulong


class Attr(ctypes.Structure):
    _fields_ = [("type", U), ("pValue", ctypes.c_void_p), ("ulValueLen", U)]


class TokenInfo(ctypes.Structure):
    _fields_ = [("label", ctypes.c_char * 32), ("manufacturerID", ctypes.c_char * 32),
                ("model", ctypes.c_char * 16), ("serialNumber", ctypes.c_char * 16), ("flags", U)] + \
               [(n, U) for n in ("a", "b", "c", "d", "e", "f", "g", "h", "i", "j")] + \
               [("hw", ctypes.c_ubyte * 2), ("fw", ctypes.c_ubyte * 2), ("utcTime", ctypes.c_char * 16)]


def main(argv):
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    lib, serial, key_id = ctypes.CDLL(argv[1]), argv[2], bytes.fromhex(argv[3])
    pin = os.environ.get("REGALIA_Q_PIN", "").encode()
    if not pin:
        print("REGALIA_Q_PIN is not set", file=sys.stderr)
        return 2

    def call(name, *args):
        rv = getattr(lib, name)(*args)
        return rv & 0xFFFFFFFF

    if call("C_Initialize", None) not in (CKR_OK, 0x191):
        return 2
    try:
        n = U(0)
        call("C_GetSlotList", ctypes.c_ubyte(1), None, ctypes.byref(n))
        slots = (U * n.value)()
        call("C_GetSlotList", ctypes.c_ubyte(1), slots, ctypes.byref(n))
        slot = None
        for s in slots[:n.value]:
            ti = TokenInfo()
            if call("C_GetTokenInfo", U(s), ctypes.byref(ti)) == CKR_OK and ti.serialNumber.decode(errors="replace").strip() == serial:
                slot = s
        if slot is None:
            print("no token with serial %s" % serial, file=sys.stderr)
            return 2
        h = U(0)
        if call("C_OpenSession", U(slot), U(CKF_SERIAL_SESSION), None, None, ctypes.byref(h)) != CKR_OK:
            return 2
        rv = call("C_Login", h, U(CKU_USER), ctypes.c_char_p(pin), U(len(pin)))
        if rv not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
            print("login failed: 0x%x" % rv, file=sys.stderr)
            return 2
        cls, idbuf = U(CKO_PRIVATE_KEY), ctypes.create_string_buffer(key_id, len(key_id))
        tmpl = (Attr * 2)(Attr(CKA_CLASS, ctypes.cast(ctypes.byref(cls), ctypes.c_void_p), ctypes.sizeof(cls)),
                          Attr(CKA_ID, ctypes.cast(idbuf, ctypes.c_void_p), len(key_id)))
        call("C_FindObjectsInit", h, tmpl, U(2))
        objs, found = (U * 2)(), U(0)
        call("C_FindObjects", h, objs, U(2), ctypes.byref(found))
        call("C_FindObjectsFinal", h)
        if found.value != 1:
            print("expected one private key with id %s, found %d" % (argv[3], found.value), file=sys.stderr)
            return 2
        obj = objs[0]
        report, leaked = {"serial": serial, "id": argv[3]}, False
        for name, t in (("CKA_SENSITIVE", CKA_SENSITIVE), ("CKA_EXTRACTABLE", CKA_EXTRACTABLE),
                        ("CKA_ALWAYS_SENSITIVE", CKA_ALWAYS_SENSITIVE), ("CKA_NEVER_EXTRACTABLE", CKA_NEVER_EXTRACTABLE),
                        ("CKA_LOCAL", CKA_LOCAL)):
            b = ctypes.c_ubyte(0)
            a = Attr(t, ctypes.cast(ctypes.byref(b), ctypes.c_void_p), 1)
            rv = call("C_GetAttributeValue", h, U(obj), ctypes.byref(a), U(1))
            report[name] = bool(b.value) if rv == CKR_OK else "rv=0x%x" % rv
        for name, t in (("CKA_VALUE", CKA_VALUE), ("CKA_PRIVATE_EXPONENT", CKA_PRIVATE_EXPONENT), ("CKA_PRIME_1", CKA_PRIME_1)):
            a = Attr(t, None, 0)                       # first ask the length, then the bytes
            rv = call("C_GetAttributeValue", h, U(obj), ctypes.byref(a), U(1))
            got = 0
            if rv == CKR_OK and a.ulValueLen not in (0, CK_UNAVAILABLE):
                buf = ctypes.create_string_buffer(a.ulValueLen)
                a.pValue = ctypes.cast(buf, ctypes.c_void_p)
                rv = call("C_GetAttributeValue", h, U(obj), ctypes.byref(a), U(1))
                got = a.ulValueLen if rv == CKR_OK else 0
            report[name] = {"rv": "0x%x" % rv, "bytes_returned": got}
            # Not applicable to this key type (0x12 CKR_ATTRIBUTE_TYPE_INVALID) is fine; any returned
            # byte, or an OK answer with a length, is a leak.
            if got or (rv == CKR_OK and a.ulValueLen not in (0, CK_UNAVAILABLE)):
                leaked = True
        report["secret_bytes_returned"] = leaked
        kt = U(CK_UNAVAILABLE)
        a = Attr(CKA_KEY_TYPE, ctypes.cast(ctypes.byref(kt), ctypes.c_void_p), ctypes.sizeof(kt))
        rv = call("C_GetAttributeValue", h, U(obj), ctypes.byref(a), U(1))
        key_type = {0x0: "RSA", 0x3: "EC"}.get(kt.value) if rv == CKR_OK else None
        report["key_type"] = key_type or "unknown"
        applicable = {"EC": ("CKA_VALUE",), "RSA": ("CKA_PRIVATE_EXPONENT", "CKA_PRIME_1")}.get(key_type, ())
        refused = all(report[n]["rv"] in ("0x11", "0x12") and report[n]["bytes_returned"] == 0 for n in applicable)
        exposed = report["CKA_SENSITIVE"] is not True or report["CKA_EXTRACTABLE"] is not False
        verdict = "LEAK" if leaked else ("EXPOSABLE" if exposed else ("REFUSED" if applicable and refused else "INCONCLUSIVE"))
        report["verdict"] = verdict
        print(json.dumps(report, sort_keys=True))
        call("C_Logout", h)
        call("C_CloseSession", h)
        return {"REFUSED": 0, "LEAK": 1, "EXPOSABLE": 1}.get(verdict, 2)
    finally:
        call("C_Finalize", None)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
