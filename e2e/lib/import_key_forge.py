"""import_key_forge.py — the attacker's documents for e2e/import-key-certify-swtpm.sh (#702). Run with python3 -I.

    python3 -I import_key_forge.py ROOT software REAL.cert.json OUT.cert.json OUT.import.pub
        A SOFTWARE P-256 key with exactly the import key's template (fixedTPM and the rest only CLAIMED: a public
        area is bytes anyone can write), and a certification of it forged in software: a software "AK" with the AK's
        template signs a TPMS_ATTEST whose qualifiedSigner names that AK under the REAL EK (taken from REAL). Every
        check passes but the AK's binding to the EK, which needs the TPM. Prints the software key's fingerprint (what
        a compromised host would show at the console).
    python3 -I import_key_forge.py ROOT swap REAL.cert.json CERTIFY SIG OUT.cert.json [IMPORT.pub]
        REAL with its certify and signature replaced by CERTIFY and SIG (a real certification of another object), and
        with IMPORT.pub as its import key's public area when given.
"""
import hashlib
import json
import os
import struct
import sys

sys.path.append(sys.argv[1])
from cryptography.hazmat.primitives import hashes                           # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec                    # noqa: E402

from deploy.baremetal import attest, importkey, signkey                    # noqa: E402


def point(key):
    n = key.public_key().public_numbers()
    return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")


def tpm2b(data):
    return struct.pack(">H", len(data)) + data


def import_area(x, y):
    # the template of seal-hsm-pin.sh --init-import-key (#671), as importkey.identity reads it
    return (struct.pack(">HHI", attest.ALG_ECC, attest.ALG_SHA256, importkey.ATTRIBUTES) + tpm2b(b"")
            + struct.pack(">HHH", importkey.ALG_AES, importkey.AES_BITS, importkey.ALG_CFB)
            + struct.pack(">HHH", attest.ALG_NULL, attest.CURVE_P256, attest.ALG_NULL) + tpm2b(x) + tpm2b(y))


def ak_area(x, y):
    # attest.ak_identity's AK: restricted ECDSA P-256 signing key
    return (struct.pack(">HHI", attest.ALG_ECC, attest.ALG_SHA256, attest.AK_ATTRIBUTES) + tpm2b(b"")
            + struct.pack(">HHHHH", attest.ALG_NULL, attest.ALG_ECDSA, attest.ALG_SHA256, attest.CURVE_P256, attest.ALG_NULL)
            + tpm2b(x) + tpm2b(y))


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main():
    mode, real = sys.argv[2], json.load(open(sys.argv[3]))
    if mode == "software":
        out, out_pub = sys.argv[4], sys.argv[5]
        key = ec.generate_private_key(ec.SECP256R1())
        area = import_area(*point(key))
        public = tpm2b(area)
        name = attest.name_of(area)
        fake = ec.generate_private_key(ec.SECP256R1())
        fake_public = tpm2b(ak_area(*point(fake)))
        fake_name, _ = attest.ak_identity(fake_public)
        ek_name = attest.name_of(attest.public_area(bytes.fromhex(real["ek_public"]), "the EK"))
        # a child's qualifiedName (under some storage key): the parent check passes
        qualified = struct.pack(">H", attest.ALG_SHA256) + hashlib.sha256(os.urandom(34) + name).digest()
        certify = (struct.pack(">IH", attest.TPM_GENERATED, signkey.ST_ATTEST_CERTIFY)
                   + tpm2b(attest.qualified_name(ek_name, fake_name)) + tpm2b(signkey.TOOLS_QUALIFYING)
                   + struct.pack(">QIIBQ", 1000, 1, 0, 1, 0) + tpm2b(name) + tpm2b(qualified))
        signature = fake.sign(certify, ec.ECDSA(hashes.SHA256()))
        doc = dict(real, import_public=public.hex(), ak_public=fake_public.hex(), certify=certify.hex(),
                   signature=signature.hex(), answer=os.urandom(32).hex())
        write(out_pub, public)
        write(out, json.dumps(doc, sort_keys=True).encode())
        print(importkey.fingerprint(public))
    elif mode == "swap":
        certify, signature, out = open(sys.argv[4], "rb").read(), open(sys.argv[5], "rb").read(), sys.argv[6]
        doc = dict(real, certify=certify.hex(), signature=signature.hex())
        if len(sys.argv) > 7:
            doc["import_public"] = open(sys.argv[7], "rb").read().hex()
        write(out, json.dumps(doc, sort_keys=True).encode())
    else:
        sys.exit("import_key_forge: unknown mode %s" % mode)


main()
