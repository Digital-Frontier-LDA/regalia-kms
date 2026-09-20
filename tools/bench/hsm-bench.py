#!/usr/bin/env python3
"""hsm-bench.py — throughput per KEY TYPE on a PKCS#11 token, one persistent session.

Why persistent: spawning `pkcs11-tool` per operation costs ~298 ms of process start, PKCS#11
init and C_Login, which swamps the card. Measuring that and calling it card throughput is how a
5x-wrong number ends up in a design document. Open one session, log in once, then loop.

Reports median and p90 as well as mean: a smartcard's variance matters when the number is used
as a capacity ceiling.

    HSM_PIN=… ./hsm-bench.py                      # needs PyKCS11; `cryptography` enables decrypt
    HSM_PIN=… BENCH_N=50 PKCS11_MODULE=… ./hsm-bench.py

Labels are derived from the KEY, never assumed: an RSA key is reported at its real modulus size
and an EC key at its real curve. A benchmark that hardcodes "RSA-2048" silently mislabels a 4096
key, which is worse than not measuring it at all.
"""
import math
import os
import statistics
import sys
import time

import PyKCS11

MODULE = os.environ.get("PKCS11_MODULE", "/opt/homebrew/lib/opensc-pkcs11.so")
PIN = os.environ["HSM_PIN"]


def _samples(raw):
    """BENCH_N, or a refusal. Zero or a negative count makes `measure()` return an empty list and
    `statistics.mean([])` raise StatisticsError — the run dies after spending PIN logins and card
    operations, with a traceback that names statistics rather than the environment variable that
    caused it. A number the tool cannot measure with is a refusal, stated before the card is
    touched."""
    try:
        n = int(raw)
    except ValueError:
        sys.exit(f"BENCH_N={raw!r} is not an integer; give a sample count of 1 or more")
    if n < 1:
        sys.exit(f"BENCH_N={n} would take no samples; give a sample count of 1 or more")
    return n


N = _samples(os.environ.get("BENCH_N", "25"))

CURVE_OID = {
    "06082a8648ce3d030107": "prime256v1 (P-256)",
    "06052b8104000a": "secp256k1",
    "06052b81040022": "secp384r1 (P-384)",
    "06052b81040023": "secp521r1 (P-521)",
}


def p90(times):
    """Nearest-rank p90. `int(n*0.9)-1` is an off-by-one that reports ~p88 for n=25 — it was in
    an earlier revision of this file and the wrong figure reached a design doc."""
    return sorted(times)[math.ceil(0.9 * len(times)) - 1]


def key_desc(sess, obj, ktype):
    if ktype == PyKCS11.CKK_EC:
        try:
            raw = sess.getAttributeValue(obj, [PyKCS11.CKA_EC_PARAMS])[0]
            if raw is None:
                # A key whose PKCS#15 description carries no domain parameters (an unwrapped key
                # described by buildPrkDforECC, measured on a Nitrokey HSM 2 2026-09-17) returns
                # None here, not an error. bytes(None) crashed the whole run.
                return "EC (curve unreadable)"
            h = bytes(raw).hex()
            return CURVE_OID.get(h, f"EC unknown ({h[:20]})")
        except PyKCS11.PyKCS11Error:
            return "EC (curve unreadable)"
    if ktype == PyKCS11.CKK_RSA:
        try:
            return f"RSA-{sess.getAttributeValue(obj, [PyKCS11.CKA_MODULUS_BITS])[0]}"
        except PyKCS11.PyKCS11Error:
            return "RSA (size unreadable)"
    return f"key type {ktype}"


def rsa_ciphertext(sess, obj):
    """Encrypt host-side with the public half, as SOPS/GPG do. The card refuses C_Encrypt on a
    public object (CKR_KEY_TYPE_INCONSISTENT) — correct, public ops do not belong on it."""
    try:
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        return None, "install `cryptography` to measure decrypt"
    kid = sess.getAttributeValue(obj, [PyKCS11.CKA_ID])[0]
    pubs = sess.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, kid)])
    if not pubs:
        return None, "no public half on token"
    n = int.from_bytes(bytes(sess.getAttributeValue(pubs[0], [PyKCS11.CKA_MODULUS])[0]), "big")
    e = int.from_bytes(bytes(sess.getAttributeValue(pubs[0], [PyKCS11.CKA_PUBLIC_EXPONENT])[0]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key().encrypt(b"A" * 32, padding.PKCS1v15()), None


def measure(fn):
    times = []
    for _ in range(N):
        t0 = time.perf_counter()
        try:
            fn()
        except PyKCS11.PyKCS11Error as exc:
            return None, str(exc)
        times.append((time.perf_counter() - t0) * 1000)
    return times, None


def main():
    lib = PyKCS11.PyKCS11Lib()
    lib.load(MODULE)
    slot = lib.getSlotList(tokenPresent=True)[0]
    info = lib.getTokenInfo(slot)
    sess = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    # try/finally, not a trailing logout: on a smartcard a leaked session can leave the token
    # logged in and block the next process that opens it. An exception mid-benchmark must not
    # cost you the card.
    holder = [sess]

    def reopen():
        """A failed C_Sign can leave the operation ACTIVE (CKR_BUFFER_TOO_SMALL does not end it,
        per PKCS#11), and every later operation on that session then fails with
        CKR_OPERATION_ACTIVE — measured 2026-09-17: one bad key blanked every EC row after it.
        Closing the session terminates the operation; the replacement is again ONE session,
        logged in once, for everything that follows."""
        try:
            holder[0].logout()
        except PyKCS11.PyKCS11Error:
            pass
        holder[0].closeSession()
        holder[0] = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        holder[0].login(PIN)

    try:
        sess.login(PIN)
        _run(holder, info, reopen)
    finally:
        try:
            holder[0].logout()
        except PyKCS11.PyKCS11Error:
            pass
        holder[0].closeSession()


def _run(holder, info, reopen):
    print(f"token   : {info.label.strip()}  fw {info.firmwareVersion}")
    print(f"module  : {MODULE}")
    print(f"samples : {N} per measurement, ONE session, logged in ONCE")
    print("p90     : nearest-rank\n")

    # ENUMERATE BY CKA_ID, NOT BY HANDLE. PKCS#11 guarantees an object handle only for the life of
    # the session that produced it, and `reopen()` below replaces the session after a failed
    # operation — so every handle taken from the old session may be invalid on the new one, and a
    # module is free to number them differently. Keeping them meant the recovery path measured
    # nothing: each later key failed with CKR_OBJECT_HANDLE_INVALID, which reads in the output as
    # a card that cannot sign. Identity is the CKA_ID; the handle is re-resolved from it whenever
    # the session changes.
    keys = []
    for obj in holder[0].findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)]):
        try:
            kid_raw = bytes(holder[0].getAttributeValue(obj, [PyKCS11.CKA_ID])[0])
            ktype = holder[0].getAttributeValue(obj, [PyKCS11.CKA_KEY_TYPE])[0]
            label = holder[0].getAttributeValue(obj, [PyKCS11.CKA_LABEL])[0] or "(no label)"
        except PyKCS11.PyKCS11Error as exc:
            print(f"  !! skipping a key, attributes unreadable: {exc}")
            continue
        keys.append((kid_raw, kid_raw.hex(), ktype, label))

    def resolve(kid_raw):
        """The current handle for this key on the CURRENT session, or None if it is gone."""
        found = holder[0].findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                                       (PyKCS11.CKA_ID, kid_raw)])
        return found[0] if found else None

    rows = []
    for kid_raw, kid, ktype, label in keys:
        # Resolved ONCE per key, outside the measured operations: a C_FindObjects inside the timed
        # loop would be measuring the search, not the signature.
        cell = [resolve(kid_raw)]
        if cell[0] is None:
            rows.append((label, kid, "?", "key lookup", None, "key not found on this session"))
            continue
        obj = cell[0]
        desc = key_desc(holder[0], obj, ktype)

        ops = []
        if ktype == PyKCS11.CKK_RSA:
            ms = PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None)
            ops.append(("sign (PKCS#1 v1.5, SHA-256)",
                        lambda c=cell, m=ms: holder[0].sign(c[0], os.urandom(32), m)))
            ct, why = rsa_ciphertext(holder[0], obj)
            md = PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)
            if ct is None:
                rows.append((label, kid, desc, "decrypt (PKCS#1 v1.5)", None, why))
            else:
                ops.append(("decrypt (PKCS#1 v1.5)",
                            lambda k=cell, c=ct, m=md: holder[0].decrypt(k[0], c, m)))
        elif ktype == PyKCS11.CKK_EC:
            for nm, mech in (("ECDSA sign (raw, pre-hashed)", PyKCS11.CKM_ECDSA),
                             ("ECDSA sign (SHA-256 on card)", PyKCS11.CKM_ECDSA_SHA256)):
                m = PyKCS11.Mechanism(mech, None)
                ops.append((nm, lambda c=cell, m=m: holder[0].sign(c[0], os.urandom(32), m)))

        for name, fn in ops:
            if cell[0] is None:
                rows.append((label, kid, desc, name, None,
                             "key not found after the session was replaced"))
                continue
            times, err = measure(fn)
            rows.append((label, kid, desc, name, times, err))
            if err:
                reopen()
                # The replacement session's handles are its own. Re-resolve before the next
                # operation; if the key cannot be found there, say so instead of timing a stale
                # handle and reporting the resulting error as a property of the card.
                cell[0] = resolve(kid_raw)

    hdr = (f"{'label':14} {'id':4} {'key':20} {'operation':30} "
           f"{'mean ms':>9} {'med ms':>8} {'p90 ms':>8} {'ops/s':>7}")
    print(hdr)
    print("-" * len(hdr))
    for label, kid, desc, name, times, err in rows:
        if err:
            print(f"{label[:14]:14} {kid:4} {desc[:20]:20} {name[:30]:30} "
                  f"{'—':>9} {'—':>8} {'—':>8} {'—':>7}   {err[:30]}")
        else:
            mean = statistics.mean(times)
            print(f"{label[:14]:14} {kid:4} {desc[:20]:20} {name[:30]:30} "
                  f"{mean:9.1f} {statistics.median(times):8.1f} {p90(times):8.1f} {1000 / mean:7.2f}")


if __name__ == "__main__":
    sys.exit(main())
