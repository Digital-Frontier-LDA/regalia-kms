#!/usr/bin/env python3
"""The anchor-policy authority's arithmetic (#361): every TPM Name and policy digest the anchor, its counters and the
node signing key are defined and used under, computed without a TPM. Held to the TPM's own values by
tests/vectors/anchor-policy-v1.json, measured on swtpm (tests/vectors/make-anchor-policy-v1.py), which the Go reader
takes too.

THE DESIGN (#361, decided by regalia-kms-24 with d9 and 95; measured by 95 and 1e):
  * Each TPM object a node keeps across key rotations (the anchor counter and record slots, the heartbeat and signing
    counters, the rotation counter R, and the node signing key) is defined ONCE, at enrolment, under
        authPolicy = PolicyAuthorize(Name(K_A), policyRef = its class)
    K_A is the anchor-policy authority: an offline P-256 Shamir software key (ADR-0002 D28), pinned in the v4 manifest
    and never changed. Its Name is computed as `tpm2_loadexternal -G ecc` loads it (k_a_name).
  * One policyRef per CLASS (REFS): K_A's approval for one class never satisfies another's authPolicy (measured: the
    "rotation" approval on the anchor, and the "anchor" one on the signing key, are refused).
  * K_A approves, per class, P(K_sys, G) = PolicyAuthorize(Name(K_sys)) followed by PolicyNV(R <= G) (approved). A
    writer's session: PolicyPCR(11), PolicyAuthorize(K_sys) with K_sys's signature over that PCR policy, PolicyNV(R <= G),
    then PolicyAuthorize(K_A, class) with K_A's signature over authorize_message(P, class).
  * A K_sys rotation is K_A approving P(K_new, G+1): nothing is redefined. REVOCATION: once a node's R passes G, P(K, G)
    no longer satisfies PolicyNV in its TPM.
  * R itself is incremented only under K_A's single-use approvals (increment_first, increment_from): PolicyCommandCode
    (NV_Increment) with PolicyNvWritten(clear) for its first increment, or with PolicyNV(R == n) for the one after n, so
    an approval to increment cannot be replayed to bump R at will. R is defined with policywrite only (not even the
    owner increments it) and is publicly readable (authread, empty authValue) for PolicyNV.
  * R's Name includes TPMA_NV_WRITTEN, so every approval naming R is computed AFTER its first increment (at enrolment):
    rotation_name(written=True).
"""
import hashlib
import struct

from deploy.baremetal import attest, membership

Refused, require = membership.Refused, membership.require

CC_NV_INCREMENT = 0x00000134
CC_POLICY_NV = 0x00000149
CC_POLICY_AUTHORIZE = 0x0000016A
CC_POLICY_COMMAND_CODE = 0x0000016C
CC_POLICY_NV_WRITTEN = 0x0000018F
EO_EQ, EO_UNSIGNED_LE = 0x0000, 0x0009            # TPM_EO

# how K_A's public point is loaded to check its signatures: tpm2_loadexternal's default for an ECC public key
# (decrypt | sign | userWithAuth, SHA-256 Name, no scheme, no symmetric, no KDF), the same template as the PCR key's
K_A_ATTRIBUTES = 0x00060040
# the rotation counter R: nt=counter | policywrite | authread | no_da, and WRITTEN once incremented
NV_COUNTER, NV_POLICYWRITE, NV_AUTHREAD, NV_NO_DA, NV_WRITTEN = 0x00000010, 0x00000008, 0x00040000, 0x02000000, 0x20000000
ROTATION_ATTRIBUTES = NV_COUNTER | NV_POLICYWRITE | NV_AUTHREAD | NV_NO_DA
ROTATION_SIZE = 8
# one policyRef per class of object (#361, 95's measurement): the bytes K_A's approval names
REFS = {"anchor": b"anchor", "slots": b"slots", "heartbeat": b"heartbeat", "signing-counter": b"signing-counter",
        "rotation": b"rotation", "signing": b"signing"}


def _h(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def k_a_name(point):
    """The TPM Name of K_A's P-256 public point (65 bytes, uncompressed, or its hex)."""
    point = bytes.fromhex(point) if isinstance(point, str) else point
    require(isinstance(point, bytes) and len(point) == 65 and point[0] == 4, "K_A is an uncompressed P-256 point (65 bytes)")
    area = struct.pack(">HHI", attest.ALG_ECC, attest.ALG_SHA256, K_A_ATTRIBUTES) + struct.pack(">H", 0) + \
        struct.pack(">HHHH", attest.ALG_NULL, attest.ALG_NULL, attest.CURVE_P256, attest.ALG_NULL) + \
        struct.pack(">H", 32) + point[1:33] + struct.pack(">H", 32) + point[33:]
    return attest.name_of(area)


def nv_name(index, attributes, auth_policy, size):
    """The TPM Name of an NV index: nameAlg SHA-256 || SHA-256(TPMS_NV_PUBLIC)."""
    return attest.name_of(struct.pack(">IHI", index, attest.ALG_SHA256, attributes) + struct.pack(">H", len(auth_policy)) + auth_policy
                          + struct.pack(">H", size))


def policy_authorize(key_name, policy_ref):
    """The digest after PolicyAuthorize(key_name, policy_ref): it starts from zeros, whatever came before."""
    return _h(_h(bytes(32), struct.pack(">I", CC_POLICY_AUTHORIZE), key_name), policy_ref)


def policy_nv(previous, index_name, operand, offset, operation):
    return _h(previous, struct.pack(">I", CC_POLICY_NV), _h(operand, struct.pack(">HH", offset, operation)), index_name)


def policy_command_code(previous, code):
    return _h(previous, struct.pack(">I", CC_POLICY_COMMAND_CODE), struct.pack(">I", code))


def policy_nv_written(previous, written):
    return _h(previous, struct.pack(">I", CC_POLICY_NV_WRITTEN), b"\x01" if written else b"\x00")


def class_policy(k_a_point, cls):
    """The authPolicy an object of class `cls` is defined under: PolicyAuthorize(Name(K_A), REFS[cls])."""
    require(cls in REFS, "no policy class %r" % (cls,))
    return policy_authorize(k_a_name(k_a_point), REFS[cls])


def rotation_name(index, k_a_point, written=True):
    """R's Name, as defined (policywrite only, under the "rotation" class) and, once incremented, WRITTEN."""
    return nv_name(index, ROTATION_ATTRIBUTES | (NV_WRITTEN if written else 0), class_policy(k_a_point, "rotation"), ROTATION_SIZE)


def _count(value, what):
    require(type(value) is int and 0 <= value < 2 ** 64, "%s is a 64-bit count" % what)
    return value.to_bytes(8, "big")


def approved(k_sys_name, rotation, generation):
    """P(K_sys, G): PolicyAuthorize(Name(K_sys)) (systemd's empty policyRef) then PolicyNV(R <= G) on the rotation
    counter of Name `rotation` (written). K_A approves this, per class."""
    return policy_nv(policy_authorize(k_sys_name, b""), rotation, _count(generation, "the generation"), 0, EO_UNSIGNED_LE)


def increment_first():
    """K_A's approval for R's FIRST increment: NV_Increment, and only while R has never been written."""
    return policy_nv_written(policy_command_code(bytes(32), CC_NV_INCREMENT), False)


def increment_from(rotation, n):
    """K_A's approval for the increment that takes R from n: NV_Increment, and only while R == n."""
    return policy_nv(policy_command_code(bytes(32), CC_NV_INCREMENT), rotation, _count(n, "n"), 0, EO_EQ)


def authorize_message(policy, cls):
    """What K_A signs (ECDSA P-256 over SHA-256) to approve `policy` for class `cls`: aHash = H(policy || policyRef)."""
    require(cls in REFS, "no policy class %r" % (cls,))
    return policy + REFS[cls]
