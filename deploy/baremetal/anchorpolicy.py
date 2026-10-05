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
    owner increments it) and is publicly readable (authread, empty authValue) for PolicyNV. The owner can still UNDEFINE
    it, which only denies: every class write fails until R is redefined and K_A's first-increment approval reused, and the
    redefined R starts ABOVE its old value (the TPM's saved highest count), never below (measured, #361 case 6).
  * G AND n ARE PER NODE (regalia-kms-95 on #437). A counter's first increment starts at the TPM's saved highest count,
    which deleting any counter raises, so each node's R starts somewhere of its own. Enrolment records R's value after
    its first increment; K_A approves P(K_sys, G_node) per node and per class, and increment_from(R, n_node) per node.
    A single fleet-wide G could not both work on every node and revoke on every node.
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


# A node's OWN rotation counter (#361, regalia-kms-1e and d9): R is defined under a policyRef that names the node, so its
# Name differs per node and every approval naming R opens that node's objects only. With one Name for R on every node, an
# approval at G_y (public, in the measurements document) would open node x's objects whenever R_x <= G_y, and a retire
# would not revoke an old key on a node whose G is lower. A policyRef is a TPM2B_NONCE, at most the TPM's largest digest
# (32 bytes on a SHA-256-only TPM: d9), so the node's ref is a digest: SHA-256("regalia-rotation/v1\0" || node_id).
ROTATION_DOMAIN = b"regalia-rotation/v1\x00"
NODE_ID = __import__("re").compile(r"[a-z0-9][a-z0-9-]{0,31}")         # membership's node_id


def rotation_class(node_id):
    """The class (and policyRef) of `node_id`'s rotation counter: "rotation/<node_id>"."""
    require(isinstance(node_id, str) and NODE_ID.fullmatch(node_id) is not None, "%r is not a node ID" % (node_id,))
    return "rotation/" + node_id


# The shared "rotation" class is #437's VECTORS' only (measured on swtpm before R was per node): no production path takes it
# (regalia-kms-95 on #462). class_policy and authorize_message refuse it; _shared_* below give it to the vector tests.
SHARED_ROTATION = "rotation"


def _ref(cls, shared=False):
    """The policyRef of a class: REFS for the object classes; a node's rotation counter's, a 32-byte digest of its ID. The
    shared "rotation" class is refused unless `shared` (the vectors)."""
    if isinstance(cls, str) and cls.startswith("rotation/"):
        node_id = cls[len("rotation/"):]
        require(NODE_ID.fullmatch(node_id) is not None, "no policy class %r" % (cls,))
        return hashlib.sha256(ROTATION_DOMAIN + node_id.encode()).digest()
    require(cls in REFS and (shared or cls != SHARED_ROTATION),
            "no policy class %r%s" % (cls, " (the shared rotation class is the vectors' only: a node's is rotation/<node_id>)"
                                      if cls == SHARED_ROTATION else ""))
    return REFS[cls]


def class_policy(k_a_point, cls, shared=False):
    """The authPolicy an object of class `cls` is defined under: PolicyAuthorize(Name(K_A), its policyRef)."""
    return policy_authorize(k_a_name(k_a_point), _ref(cls, shared))


def rotation_name(index, k_a_point, node_id, written=True):
    """`node_id`'s R's Name, as defined (policywrite only, under its own class rotation/<node_id>) and, once incremented,
    WRITTEN. The node is required: there is no shared form on a production path (regalia-kms-95)."""
    return nv_name(index, ROTATION_ATTRIBUTES | (NV_WRITTEN if written else 0), class_policy(k_a_point, rotation_class(node_id)), ROTATION_SIZE)


def _shared_rotation_name(index, k_a_point, written=True):
    """R's Name under the shared "rotation" class: #437's vectors only (anchor-policy-v1.json, measured on swtpm)."""
    return nv_name(index, ROTATION_ATTRIBUTES | (NV_WRITTEN if written else 0), class_policy(k_a_point, SHARED_ROTATION, shared=True),
                   ROTATION_SIZE)


def _count(value, what):
    require(type(value) is int and 0 <= value < 2 ** 64, "%s is a 64-bit count" % what)
    return value.to_bytes(8, "big")


def approved(k_sys_name, rotation, generation):
    """P(K_sys, G): PolicyAuthorize(Name(K_sys)) (systemd's empty policyRef) then PolicyNV(R <= G) on the rotation
    counter of Name `rotation` (written). G is THIS NODE's: its R's value (from its enrolment, then its rotations).
    K_A approves this per node and per class."""
    return policy_nv(policy_authorize(k_sys_name, b""), rotation, _count(generation, "the generation"), 0, EO_UNSIGNED_LE)


def increment_first():
    """K_A's approval for R's FIRST increment: NV_Increment, and only while R has never been written."""
    return policy_nv_written(policy_command_code(bytes(32), CC_NV_INCREMENT), False)


def increment_from(rotation, n):
    """K_A's approval for the increment that takes R from n: NV_Increment, and only while R == n."""
    return policy_nv(policy_command_code(bytes(32), CC_NV_INCREMENT), rotation, _count(n, "n"), 0, EO_EQ)


def authorize_message(policy, cls):
    """What K_A signs (ECDSA P-256 over SHA-256) to approve `policy` for class `cls`: aHash = H(policy || policyRef)."""
    return policy + _ref(cls)


# ---- the TPM side of the rotation counter R (#361 C1): defined and first incremented at `enrol init` ----
#
# R is defined before the anchor and the counters (regalia-kms-95: every class approval names R's WRITTEN Name, so it is
# written first) and before `enrol ownerauth` (the owner authorization is still empty, as the define needs), under the
# node's OWN class rotation/<node_id> (rotation_class: its Name names the node). Its first increment is made under K_A's
# approval increment_first for that class (valid only while R is unwritten: a replay is refused by the TPM). Its value after that is this node's G start; its Name and value go into the identity the
# AK quotes, and the genesis requires that Name to be rotation_name(index, the genesis manifest's K_A).

ROTATION_INDEX = "0x01500020"           # R's NV index on every node: apart from the anchor's, the counters' (node.validate)
ROTATION_WORDS = "nt=counter|policywrite|authread|no_da"        # ROTATION_ATTRIBUTES, as tpm2_nvdefine spells them
FIRST_SCHEMA = "regalia.anchor-policy-first/v1"                # the file `enrol init --anchor-policy` takes


def _point(point):
    return bytes.fromhex(point) if isinstance(point, str) else point


def k_a_pem(point):
    """K_A's public key as PEM (SubjectPublicKeyInfo), for tpm2_loadexternal."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    k_a_name(point)                                             # the form checked by name first
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _point(point)).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_approval(point, policy, cls, signature, what):
    """K_A's signature (r||s, 128 hex, low-S) over authorize_message(policy, cls), checked here before any TPM is asked: a
    signature by another key is refused by name. Returns it as DER, the form tpm2_verifysignature takes."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    require(isinstance(signature, str) and len(signature) == 128 and all(c in "0123456789abcdef" for c in signature),
            "%s is not a P-256 signature (128 lowercase hex, r||s)" % what)
    r, s = int(signature[:64], 16), int(signature[64:], 16)
    require(0 < r < membership.P256_ORDER and 0 < s <= membership.P256_ORDER // 2, "%s is not a low-S P-256 signature" % what)
    der = encode_dss_signature(r, s)
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _point(point)).verify(
            der, authorize_message(policy, cls), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        raise Refused("%s does not verify under the K_A it names" % what) from None
    return der


def read_first(doc, node_id=None):
    """The `--anchor-policy` file: exactly {schema, node_id, anchor_policy_key, increment_first}, K_A a typed P-256 entry
    and its approval of THIS node's R's first increment (class rotation/<node_id>) verified under it; the node the file
    is for must be `node_id` when given. Unauthenticated here by design: the genesis checks R's quoted Name against the
    manifest's K_A (regalia-kms-95). Returns (node_id, K_A's point hex, the approval's DER)."""
    require(isinstance(doc, dict), "the anchor-policy file is not an object")
    membership.exact(doc, ("schema", "node_id", "anchor_policy_key", "increment_first"), "the anchor-policy file")
    require(doc["schema"] == FIRST_SCHEMA, "the anchor-policy file is not a %s" % FIRST_SCHEMA)
    cls = rotation_class(doc["node_id"])
    require(node_id is None or doc["node_id"] == node_id, "the anchor-policy file is for node %s, not %s" % (doc["node_id"], node_id))
    point = membership.typed_key(doc["anchor_policy_key"], "the anchor-policy file's anchor_policy_key", membership.ANCHOR_POLICY_KEY_ALGS)[1]
    der = verify_approval(point, increment_first(), cls, doc["increment_first"], "the anchor-policy file's increment_first")
    return doc["node_id"], point, der


def _tpm(run, *argv):
    import subprocess
    done = (run or subprocess.run)(["tpm2_" + argv[0], *argv[1:]], capture_output=True)
    return done


def _must(done, what):
    err = done.stderr.decode(errors="replace") if isinstance(done.stderr, bytes) else (done.stderr or "")
    require(done.returncode == 0, "%s failed: %s" % (what, err.strip()[-300:]))
    return done


def nv_name_of(index, run=None):
    """The Name tpm2_nvreadpublic reports for `index` (hex), or None when the TPM does not hold it. A failed read is not
    taken for absence (regalia-kms-95, as HighWater._public): None only when the TPM's own list lacks the index; a TPM
    that does not answer, or lists the index and does not give it, is a refusal."""
    import re
    done = _tpm(run, "nvreadpublic", index)
    if done.returncode != 0:
        listed = _must(_tpm(run, "getcap", "handles-nv-index"), "listing the TPM's NV indices (the TPM does not answer)")
        out = listed.stdout.decode() if isinstance(listed.stdout, bytes) else listed.stdout
        require(int(index, 16) not in {int(h, 16) for h in re.findall(r"0x[0-9A-Fa-f]+", out)},
                "the TPM lists NV index %s and did not give its public area" % index)
        return None
    out = done.stdout.decode() if isinstance(done.stdout, bytes) else done.stdout
    found = re.search(r"(?m)^\s*name:\s*([0-9a-fA-F]+)\s*$", out)
    require(found is not None, "unparseable nvreadpublic output for %s" % index)
    return found.group(1).lower()


def read_rotation(index, run=None):
    """R's value (its 8 bytes, big-endian): readable by its own empty authorization (authread)."""
    import os
    import tempfile
    with tempfile.TemporaryDirectory(prefix="regalia-rotation-") as d:
        out = os.path.join(d, "r")
        _must(_tpm(run, "nvread", index, "-C", index, "-s", "8", "-o", out), "reading the rotation counter %s" % index)
        with open(out, "rb") as f:
            raw = f.read()
    require(len(raw) == 8, "the rotation counter %s gave %d bytes, not 8" % (index, len(raw)))
    return int.from_bytes(raw, "big")


def start_rotation(index, point, approval_der, node_id, run=None):
    """Define R at `index` under PolicyAuthorize(Name(K_A), rotation/<node_id>) and make its first increment under K_A's approval,
    finishing what an interrupted run left (regalia-kms-95's cases):
      * R absent: K_A's approval is checked by the TPM first (loadexternal, verifysignature: no R is defined for a wrong
        one), then R is defined, then incremented;
      * R present and unwritten, under this K_A: the increment is finished;
      * R present and written, under this K_A: nothing to do;
      * anything else at `index`: refused, never undefined.
    Needs the TPM's owner authorization to be empty (a define before `enrol ownerauth`). R is `node_id`'s own: under
    the class rotation/<node_id>, so its Name names the node. Returns {index, name, value}."""
    import os
    import tempfile
    cls = rotation_class(node_id)
    unwritten = rotation_name(int(index, 16), point, node_id, written=False).hex()
    written = rotation_name(int(index, 16), point, node_id).hex()
    held = nv_name_of(index, run)
    require(held in (None, unwritten, written), "NV index %s holds an index that is not this enrolment's rotation counter under the "
            "K_A given (Name %s): it is refused and left as it is" % (index, held))
    if held != written:
        with tempfile.TemporaryDirectory(prefix="regalia-rotation-") as d:
            path = lambda n: os.path.join(d, n)                                  # noqa: E731
            with open(path("ka.pem"), "wb") as f:
                f.write(k_a_pem(point))
            with open(path("sig.der"), "wb") as f:
                f.write(approval_der)
            with open(path("approved"), "wb") as f:
                f.write(increment_first())
            with open(path("message"), "wb") as f:
                f.write(authorize_message(increment_first(), cls))
            _tpm(run, "flushcontext", "-t")
            _must(_tpm(run, "loadexternal", "-C", "o", "-G", "ecc", "-u", path("ka.pem"), "-c", path("ka.ctx"), "-n", path("ka.name")),
                  "loading K_A")
            with open(path("ka.name"), "rb") as f:                # the template checked before the TPM is asked anything else
                require(f.read() == k_a_name(point), "the TPM's Name of K_A is not the one computed for it")
            _must(_tpm(run, "verifysignature", "-c", path("ka.ctx"), "-g", "sha256", "-m", path("message"), "-s", path("sig.der"),
                       "-f", "ecdsa", "-t", path("ticket")), "the TPM's check of K_A's approval of the rotation counter's first increment")
            if held is None:
                with open(path("policy"), "wb") as f:
                    f.write(class_policy(point, cls))
                _must(_tpm(run, "nvdefine", index, "-C", "o", "-s", "8", "-a", ROTATION_WORDS, "-L", path("policy")),
                      "defining the rotation counter %s (the TPM's owner authorization must still be empty: `enrol init` comes "
                      "before `enrol ownerauth`)" % index)
            _tpm(run, "flushcontext", "-t")                       # the ticket outlives K_A's context
            _must(_tpm(run, "startauthsession", "--policy-session", "-S", path("s.ctx")), "a policy session")
            try:
                _must(_tpm(run, "policycommandcode", "-S", path("s.ctx"), "TPM2_CC_NV_Increment"), "PolicyCommandCode")
                _must(_tpm(run, "policynvwritten", "-S", path("s.ctx"), "c"), "PolicyNvWritten")
                _must(_tpm(run, "policyauthorize", "-S", path("s.ctx"), "-i", path("approved"), "-n", path("ka.name"),
                           "-q", _ref(cls).hex(), "-t", path("ticket")), "PolicyAuthorize(K_A, %s)" % cls)
                _must(_tpm(run, "nvincrement", index, "-C", index, "-P", "session:" + path("s.ctx")),
                      "the rotation counter's first increment")
            finally:
                _tpm(run, "flushcontext", path("s.ctx"))
    name = nv_name_of(index, run)
    require(name == written, "the rotation counter %s is not written under this K_A after its first increment (Name %s, not %s)"
            % (index, name, written))
    return {"index": index, "name": name, "value": read_rotation(index, run)}


# ---- K_A's approvals (#361 C2): one per node, per class, per approved system-phase key, in the measurements set ----
#
# A signed set (one naming signing.system) carries, inside its `signing`, "anchor_approvals": {"generation": G,
# "classes": {class: r||s}} (attest.validate_approvals: the form). Each signature is K_A's over
# authorize_message(approved(Name(K_sys), Name(R), G), class): K_sys the set's own system-phase key, R THIS node's rotation
# counter (at ROTATION_INDEX, under K_A), G this node's generation. G is never typed: at the genesis it is the node's
# AK-quoted first value of R; at a rotation it is the current set's G + 1 (R moves only at a retire, by exactly 1).

APPROVAL_CLASSES = attest.APPROVAL_CLASSES


def sign(key, policy, cls):
    """K_A's approval of `policy` for class `cls`, with K_A's private key (cryptography's), as r||s low-S hex."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(key.sign(authorize_message(policy, cls), ec.ECDSA(hashes.SHA256())))
    return "%064x%064x" % (r, min(s, membership.P256_ORDER - s))


def approved_for(k_sys_pem, k_a_point, generation, node_id):
    """P(K_sys, G) for `node_id`'s rotation counter under this K_A: what each class's approval for that node signs."""
    from deploy.baremetal import signkey
    return approved(signkey.pcr_key_name(k_sys_pem), rotation_name(int(ROTATION_INDEX, 16), k_a_point, node_id=node_id), generation)


def approvals_for(key, k_sys_pem, k_a_point, generation, node_id):
    """`node_id`'s set's anchor_approvals block, signed with K_A's private `key` (the signer's)."""
    policy = approved_for(k_sys_pem, k_a_point, generation, node_id)
    return {"generation": generation, "classes": {cls: sign(key, policy, cls) for cls in APPROVAL_CLASSES}}


def check_approvals(approvals, k_sys_pem, k_a_point, node_id, label="anchor_approvals"):
    """Every class's approval in `approvals` (attest.validate_approvals' form) is K_A's, over THIS key and `node_id`'s
    rotation counter at its G: refused by name otherwise (another node's approvals among them). Returns G."""
    attest.validate_approvals(approvals, label)
    policy = approved_for(k_sys_pem, k_a_point, approvals["generation"], node_id)
    for cls in APPROVAL_CLASSES:
        verify_approval(k_a_point, policy, cls, approvals["classes"][cls], "%s.classes.%s" % (label, cls))
    return approvals["generation"]


# ---- the K_A signer (#361 C2): run by regalia-ceremony's offline-keys with K_A in a sealed memfd (51's TOOLS entries) ----
#
#   python3 -Es -m deploy.baremetal.anchorpolicy approve-first --root-key ROOT --offline-keys-record REC --node-id X --key-fd N --offline-session ID
#   python3 -Es -m deploy.baremetal.anchorpolicy approve --document DOC --system-pub PEM --root-key ROOT --key-fd N --offline-session ID
#       (--offline-keys-record REC --node BUNDLE KEEP ACTIVATION ...   at the genesis)
#       (--chain CHAIN --current CURRENT_DOC                            at a rotation)
#   python3 -Es -m deploy.baremetal.anchorpolicy approve-increment --chain CHAIN --root-key ROOT --node-id X --from N --key-fd N --offline-session ID
#
# The K_A source is always explicit (regalia-kms-51: offline-keys records the argv): the root-verified offline-keys record
# at the genesis, else the chain tip's anchor_policy_key. A key on the fd that is not that K_A is refused, and every
# signature is verified, low-S, before anything is printed. Output goes to stdout only (offline-keys hashes it into its
# root-signed session record).

INCREMENT_SCHEMA = "regalia.anchor-increment/v1"


def _key_from_fd(fd, k_a_point):
    """K_A's private key from `fd` (keyfd's rules: a pipe or a sealed memfd, unencrypted PKCS#8 PEM, read to EOF), refused
    unless it is THE pinned K_A."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from deploy.baremetal import keyfd
    buffer = keyfd.read(fd, "--key-fd")
    try:
        try:
            key = serialization.load_pem_private_key(bytes(buffer), password=None)
        except (ValueError, TypeError):
            raise Refused("--key-fd: not an unencrypted PKCS#8 PEM private key") from None
    finally:
        keyfd.zero(buffer)
    require(isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1), "--key-fd: not a P-256 key (K_A is ECDSA P-256)")
    point = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    require(point == k_a_point, "--key-fd: this key is not the pinned K_A (%s…): nothing is signed" % k_a_point[:16])
    return key


def _pinned_at_genesis(root, record_path):
    from deploy.baremetal import manifest
    entry, _ = manifest.offline_keys_record(manifest.read_json(record_path, membership.MAX_BYTES), root)
    return entry["key"]


def _pinned_by_chain(root, chain_path):
    from deploy.baremetal import manifest
    tip = manifest.verify_chain(manifest.read_json(chain_path, membership.MAX_CHAIN_BYTES), root)
    require(tip["schema"] == membership.SCHEMA_V4, "the chain's tip is %s: K_A is pinned only under %s" % (tip["schema"], membership.SCHEMA_V4))
    return tip["anchor_policy_key"]["key"], tip


def first_document(key, k_a_point, node_id):
    """`node_id`'s `enrol init --anchor-policy` file: K_A and its approval of that node's rotation counter's first increment."""
    doc = {"schema": FIRST_SCHEMA, "node_id": node_id, "anchor_policy_key": {"alg": "ecdsa-p256", "key": k_a_point},
           "increment_first": sign(key, increment_first(), rotation_class(node_id))}
    read_first(doc, node_id)                                    # verified before it is printed
    return doc


def fill(document, k_sys_pem, k_a_point, key, generations):
    """`document` (a measurements document) with every set whose signing.system is K_sys's fingerprint given its node's
    anchor_approvals at `generations[node_id]`. A node with such a set and no generation is refused. Each block is
    checked (check_approvals) before the document is returned."""
    import copy
    from deploy.baremetal import measurements, signkey
    out = copy.deepcopy(document)
    measurements.validate(out)
    fingerprint = signkey.pcr_key_fingerprint(k_sys_pem)
    filled = []
    for node_id, node in sorted(out["nodes"].items()):
        node["accepted"] = list(node["accepted"])
        for i, entry in enumerate(node["accepted"]):
            if entry.get("signing", {}).get("system") != fingerprint:
                continue
            require(node_id in generations, "%s has a set signed by this system-phase key and no generation to approve it at" % node_id)
            # each node's set its own object: deepcopy keeps the sharing of a document built in memory with one set for
            # several nodes, and filling one node would then overwrite another's approvals
            entry = node["accepted"][i] = copy.deepcopy(entry)
            entry["signing"]["anchor_approvals"] = approvals_for(key, k_sys_pem, k_a_point, generations[node_id], node_id)
            check_approvals(entry["signing"]["anchor_approvals"], k_sys_pem, k_a_point, node_id,
                            "nodes.%s.accepted[%d].signing.anchor_approvals" % (node_id, i))
            filled.append(node_id)
    require(filled, "no set in the document is signed by this system-phase key (%s): nothing to approve" % fingerprint)
    for node_id in filled:                                      # each block checked again, once every node is filled
        for i, entry in enumerate(out["nodes"][node_id]["accepted"]):
            if entry.get("signing", {}).get("system") == fingerprint:
                check_approvals(entry["signing"]["anchor_approvals"], k_sys_pem, k_a_point, node_id,
                                "nodes.%s.accepted[%d].signing.anchor_approvals" % (node_id, i))
    measurements.validate(out)
    return out


def genesis_generations(document, k_sys_pem, k_a_point, nodes):
    """At the genesis: each node's G is its AK-quoted first value of R, proven here as `manifest propose --genesis` proves
    it (enrol.proven_entry, then enrol.rotation_of under THIS K_A). `nodes`: [(bundle, keep, activation)]."""
    from deploy.baremetal import enrol
    generations = {}
    for bundle, keep, activation in nodes:
        entry, _ = enrol.proven_entry(bundle, k_sys_pem, keep, activation, k_a=k_a_point)
        require(entry["node_id"] not in generations, "--node names %s twice" % entry["node_id"])
        generations[entry["node_id"]] = enrol.rotation_of(bundle, k_a_point)["value"]
    return generations


def rotation_generations(current, k_sys_pem, k_a_point):
    """At a rotation: each node's G for K_sys is the one the CURRENT document (the chain tip's, bound) already gives that
    key, or else one above the highest G any of the node's current sets carries (R moves only at a retire, by one)."""
    from deploy.baremetal import signkey
    fingerprint = signkey.pcr_key_fingerprint(k_sys_pem)
    generations = {}
    for node_id, node in current["nodes"].items():
        own = [e["signing"]["anchor_approvals"]["generation"] for e in node["accepted"]
               if e.get("signing", {}).get("system") == fingerprint and "anchor_approvals" in e["signing"]]
        known = sorted({e["signing"]["anchor_approvals"]["generation"] for e in node["accepted"] if "anchor_approvals" in e.get("signing", {})})
        if own:
            generations[node_id] = own[0]
        elif known:
            # regalia-kms-d9: keys die oldest-first, one per retire bump; a node running CURRENT and NEXT under two live
            # approvals takes no third (it would outlive its set, and a set dropped without a bump is still live)
            require(len(known) < 2, "keys at G %s are live on node %s; retire the older (the rollout's retire bumps its "
                    "rotation counter) before approving a third" % (" and ".join(str(g) for g in known), node_id))
            generations[node_id] = max(known) + 1
    return generations


def increment_document(key, k_a_point, node_id, n):
    """K_A's single-use approval of the increment that takes `node_id`'s R from `n` (C4's retire)."""
    _count(n, "--from")
    rotation = rotation_name(int(ROTATION_INDEX, 16), k_a_point, node_id=node_id)
    sig = sign(key, increment_from(rotation, n), rotation_class(node_id))
    verify_approval(k_a_point, increment_from(rotation, n), rotation_class(node_id), sig, "the increment approval")
    return {"schema": INCREMENT_SCHEMA, "node_id": node_id, "from": n, "signature": sig}


# ---- C4: a node's catch-up (the retire bump, applied on the node; regalia-kms-1e's shape, agreed by d9 on #361) ----
#
# The measurements document carries, per node, `rotations`: a list of {"from": n, "signature": r||s}, one per retire
# this node has been through, each K_A's single-use increment_from(Name(R_node), n) (increment_document). G_pub, the
# generation the root has published for the node, is the last entry's from + 1. A node whose R is below it bumps FIRST
# (catch_up) and refuses every write under K_A and every signature until it has (require_current).


def published(rotations, label="rotations"):
    """G_pub from `rotations` (their form: each {"from", "signature"}, `from` a count rising by exactly 1), or None when
    the node has been through no retire."""
    require(isinstance(rotations, list), "%s is not a list" % label)
    previous = None
    for i, entry in enumerate(rotations):
        require(isinstance(entry, dict) and sorted(entry) == ["from", "signature"], "%s[%d] is not {from, signature}" % (label, i))
        _count(entry["from"], "%s[%d].from" % (label, i))
        require(previous is None or entry["from"] == previous + 1, "%s[%d].from is %d, not %d: a retire moves R by exactly 1"
                % (label, i, entry["from"], (previous or 0) + 1))
        previous = entry["from"]
    return None if previous is None else previous + 1


def bump(index, point, node_id, n, signature, run=None):
    """K_A's single-use approval `signature` of R's increment from `n`, checked in software, then applied in the TPM:
    PolicyCommandCode(NV_Increment), PolicyNV(R == n), PolicyAuthorize(K_A, rotation/<node_id>). R is read back at n + 1."""
    import os
    import tempfile
    cls = rotation_class(node_id)
    rotation = rotation_name(int(index, 16), point, node_id)
    approved_ = increment_from(rotation, n)
    der = verify_approval(point, approved_, cls, signature, "K_A's approval of %s's rotation counter from %d" % (node_id, n))
    with tempfile.TemporaryDirectory(prefix="regalia-rotation-") as d:
        path = lambda name: os.path.join(d, name)                             # noqa: E731
        for name, data in (("ka.pem", k_a_pem(point)), ("sig.der", der), ("approved", approved_),
                           ("message", authorize_message(approved_, cls)), ("n", n.to_bytes(8, "big"))):
            with open(path(name), "wb") as f:
                f.write(data)
        _tpm(run, "flushcontext", "-t")
        _must(_tpm(run, "loadexternal", "-C", "o", "-G", "ecc", "-u", path("ka.pem"), "-c", path("ka.ctx"), "-n", path("ka.name")), "loading K_A")
        with open(path("ka.name"), "rb") as f:
            require(f.read() == k_a_name(point), "the TPM's Name of K_A is not the one computed for it")
        _must(_tpm(run, "verifysignature", "-c", path("ka.ctx"), "-g", "sha256", "-m", path("message"), "-s", path("sig.der"),
                   "-f", "ecdsa", "-t", path("ticket")), "the TPM's check of K_A's approval of the bump from %d" % n)
        _tpm(run, "flushcontext", "-t")
        _must(_tpm(run, "startauthsession", "--policy-session", "-S", path("s.ctx")), "a policy session")
        try:
            _must(_tpm(run, "policycommandcode", "-S", path("s.ctx"), "TPM2_CC_NV_Increment"), "PolicyCommandCode")
            _must(_tpm(run, "policynv", "-S", path("s.ctx"), "-i", path("n"), index, "eq"),
                  "PolicyNV(R == %d): the rotation counter is not at the value this approval bumps from" % n)
            _must(_tpm(run, "policyauthorize", "-S", path("s.ctx"), "-i", path("approved"), "-n", path("ka.name"),
                       "-q", _ref(cls).hex(), "-t", path("ticket")), "PolicyAuthorize(K_A, %s)" % cls)
            _must(_tpm(run, "nvincrement", index, "-C", index, "-P", "session:" + path("s.ctx")), "the rotation counter's bump from %d" % n)
        finally:
            _tpm(run, "flushcontext", path("s.ctx"))
    now = read_rotation(index, run)
    require(now == n + 1, "the rotation counter %s reads %d after the bump from %d, not %d" % (index, now, n, n + 1))
    return now


def catch_up(index, point, node_id, rotations, booted_generation, run=None):
    """Bring this node's R up to G_pub (published(rotations)) by applying, in order, each entry from R on. Refused, with R
    as it was, when an entry at R is missing, or when the set the node is BOOTED on carries approvals below G_pub
    (`booted_generation`, its anchor_approvals.generation): a bump would leave it no approval to write with, so it keeps
    the old one, still valid, until it boots an image approved at G_pub (local no-stranding). Returns R."""
    target, r = published(rotations), read_rotation(index, run)
    if target is None or r >= target:
        return r
    by_from = {e["from"]: e for e in rotations}
    require(r in by_from, "%s's rotation counter is %d and the document's rotations start at %d: an entry is missing, nothing "
            "is bumped" % (node_id, r, rotations[0]["from"]))
    require(isinstance(booted_generation, int) and booted_generation >= target,
            "%s is booted on an image whose approvals are at generation %s, below the published %d: bumping would leave it no "
            "approval to write with, so it keeps its current one until it boots an image approved at %d"
            % (node_id, booted_generation, target, target))
    while r < target:
        r = bump(index, point, node_id, r, by_from[r]["signature"], run)
    return r


def require_current(index, node_id, rotations, run=None):
    """Refused unless this node's R has reached G_pub: a node behind on R writes nothing under K_A and signs nothing
    (heartbeats, activations), since an approval the retire meant to revoke may still open its objects."""
    target = published(rotations)
    if target is None:
        return
    r = read_rotation(index, run)
    require(r >= target, "%s's rotation counter is %d, below the published %d: it bumps first (catch-up), and writes or signs "
            "nothing under the anchor-policy authority until it has" % (node_id, r, target))


# ---- C4: R in a D32 lease request (regalia-kms-24, 48 and 95 on #361): a peer co-signs no lease while R < G_pub ----
#
# The requester certifies its R with its AK (TPM2_NV_Certify, R's own empty authorization: authread), qualified by
# what the request binds (48: the SHA-256 of the canonical lease it proposes; a peer's nonce works the same). Measured
# on swtpm by 1e and 95: TPM_ST_ATTEST_NV, extraData = the qualifying data, the certified Name = R's, the 8-byte value.

ST_ATTEST_NV = 0x8014
ROTATION_REQUEST_KEYS = ("value", "certify", "signature")


def certify_rotation(qualifying, index=ROTATION_INDEX, run=None):
    """This node's R, certified by its AK (attest.AK_HANDLE) over `qualifying` (bytes, at most 64): the request's
    `rotation` field, {"value", "certify", "signature"} (base64 for the TPMS_ATTEST and the AK's DER signature)."""
    import base64
    import os
    import tempfile
    require(isinstance(qualifying, bytes) and 0 < len(qualifying) <= 64, "the qualifying data is 1 to 64 bytes")
    with tempfile.TemporaryDirectory(prefix="regalia-rotation-") as d:
        attest_path, sig_path = os.path.join(d, "attest"), os.path.join(d, "sig")
        _must(_tpm(run, "nvcertify", "-C", attest.AK_HANDLE, "-c", index, "-g", "sha256", "-s", "ecdsa", "-f", "plain",
                   "-q", qualifying.hex(), "--size", "8", "--offset", "0", "-o", sig_path, "--attestation", attest_path, index),
              "certifying the rotation counter %s with the AK" % index)
        with open(attest_path, "rb") as f:
            blob = f.read(1025)
        with open(sig_path, "rb") as f:
            sig = f.read(257)
    value = parse_nv_certify(blob)["contents"]
    require(len(value) == 8, "the certified rotation counter is not 8 bytes")
    return {"value": int.from_bytes(value, "big"), "certify": base64.b64encode(blob).decode(), "signature": base64.b64encode(sig).decode()}


def parse_nv_certify(blob):
    """TPMS_ATTEST for an NV_Certify: its signer, extra data, the certified index's Name, offset and contents."""
    r = attest.Reader(blob, "the NV certification")
    require(r.u("I") == attest.TPM_GENERATED, "the NV certification was not generated by a TPM (magic)")
    require(r.u("H") == ST_ATTEST_NV, "the attestation is not an NV certification")
    out = {"qualified_signer": r.sized(), "extra_data": r.sized()}
    r.take(8 + 4 + 4 + 1 + 8)                       # clockInfo and firmwareVersion
    out["name"], out["offset"], out["contents"] = r.sized(), r.u("H"), r.sized()
    r.end()
    return out


def check_rotation(rotation, qualifying, ak_public, ek_name, ak_name, k_a_point, node_id, rotations, run=None):
    """A lease request's `rotation` (certify_rotation's), checked by the peer asked to co-sign: certified by the AK the
    manifest names for `node_id` (its `ak_name`, the AK's public area `ak_public` from enrolment, under its `ek_name`),
    over THIS request's `qualifying`, of that node's R under the tip's K_A (`k_a_point`), and at least G_pub from the
    node's `rotations` in the measurements document. Refused, by name, otherwise: a node behind on R gets no lease."""
    import base64
    import hmac
    require(isinstance(rotation, dict) and sorted(rotation) == sorted(ROTATION_REQUEST_KEYS),
            "the request's rotation is not {%s}" % ", ".join(ROTATION_REQUEST_KEYS))
    try:
        blob = base64.b64decode(rotation["certify"], validate=True)
        sig = base64.b64decode(rotation["signature"], validate=True)
    except (TypeError, ValueError):
        raise Refused("the request's rotation certification is not base64") from None
    require(len(blob) <= 1024 and len(sig) <= 256, "the request's rotation certification is oversized")
    _count(rotation["value"], "the request's rotation value")
    try:
        name, spki = attest.ak_identity(ak_public)
    except attest.Refused as refused:
        raise Refused("%s's AK: %s" % (node_id, refused)) from None
    require(name.hex() == ak_name, "the AK given is not the one the manifest names for %s" % node_id)
    try:
        attest.verify_signature(spki, blob, sig, run or __import__("subprocess").run)
    except (Refused, attest.Refused):
        raise Refused("%s's rotation certification does not verify under its AK" % node_id) from None
    c = parse_nv_certify(blob)
    require(c["qualified_signer"] == attest.qualified_name(bytes.fromhex(ek_name), name),
            "%s's rotation certification is not by its AK under its EK" % node_id)
    require(hmac.compare_digest(c["extra_data"], qualifying), "%s's rotation certification is not for this request" % node_id)
    require(c["name"] == rotation_name(int(ROTATION_INDEX, 16), k_a_point, node_id) and c["offset"] == 0 and len(c["contents"]) == 8,
            "%s's rotation certification is not of its rotation counter under the anchor-policy authority" % node_id)
    value = int.from_bytes(c["contents"], "big")
    require(value == rotation["value"], "%s's rotation value %d is not the certified %d" % (node_id, rotation["value"], value))
    target = published(rotations)
    if target is not None:
        require(value >= target, "%s's rotation counter is %d, below the published %d: no lease is co-signed until it has caught up"
                % (node_id, value, target))
    return value


def main(argv=None, out=None):
    import argparse
    import json
    import os
    import sys
    from deploy.baremetal import enrol, keyfd, manifest, measurements
    out = out or sys.stdout
    # allow_abbrev=False (regalia-kms-51): offline-keys' allow-list checks the exact flags; an abbreviation (--key-f) given
    # after the allowed one would otherwise be taken, the last one winning
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.anchorpolicy", description="K_A's approvals (#361), on the offline laptop",
                                 allow_abbrev=False)
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("approve-first", "approve", "approve-increment"):
        c = sub.add_parser(name, allow_abbrev=False)
        c.add_argument("--root-key", required=True, help="the pinned membership root (64 hex)")
        c.add_argument("--key-fd", type=int, required=True, help="K_A's private key: a sealed memfd or a pipe (offline-keys' {keyfd:anchor-policy})")
        c.add_argument("--offline-session", required=True, help="the offline-keys session ID (32 hex)")
        c.add_argument("--state-dir", required=True, help="the laptop's state directory (the root's signing record): what is "
                       "signed is appended there before it is printed (regalia-kms-d9: which approvals are live)")
        if name == "approve-first":
            c.add_argument("--offline-keys-record", required=True, help="offline-keys.record.json: K_A, verified under the root")
            c.add_argument("--node-id", required=True, help="the node whose rotation counter this starts (one file per node)")
        elif name == "approve":
            c.add_argument("--document", required=True, help="the measurements document to fill")
            c.add_argument("--system-pub", required=True, help="the system-phase PCR key whose sets are approved (PEM)")
            c.add_argument("--offline-keys-record", help="at the genesis: K_A, verified under the root")
            c.add_argument("--node", action="append", default=[], nargs=3, metavar=("BUNDLE", "KEEP", "ACTIVATION"),
                           help="at the genesis, once per node: its proof, as `manifest propose --genesis` takes it")
            c.add_argument("--chain", help="at a rotation: the signed chain; K_A is its tip's")
            c.add_argument("--current", help="at a rotation: the measurements document the chain's tip commits to")
        else:
            c.add_argument("--chain", required=True, help="the signed chain; K_A is its tip's")
            c.add_argument("--node-id", required=True)
            c.add_argument("--from", dest="from_n", type=int, required=True, help="the node's rotation counter's value before the increment")
    args = ap.parse_args(argv)
    try:
        # every path absolute (51): offline-keys runs this from inside its digest-checked tool tree, where a relative path
        # would name a file of the tree
        for flag in ("document", "system_pub", "offline_keys_record", "chain", "current", "state_dir"):
            value = getattr(args, flag, None)
            require(value is None or os.path.isabs(value), "--%s %s is not an absolute path" % (flag.replace("_", "-"), value))
        for triple in getattr(args, "node", None) or []:
            for value in triple:
                require(os.path.isabs(value), "--node %s is not an absolute path" % value)
        provenance = keyfd.session(args.offline_session)
        root = manifest.root_key(args.root_key)
        manifest.signing_state(args.state_dir, root)           # this root's laptop record, checked before anything is read
        if args.command == "approve-first":
            point = _pinned_at_genesis(root, args.offline_keys_record)
            result = first_document(_key_from_fd(args.key_fd, point), point, args.node_id)
            issued = [{"kind": "anchor-first", "node_id": args.node_id}]
        elif args.command == "approve-increment":
            point, tip = _pinned_by_chain(root, args.chain)
            require(args.node_id in membership.validate(tip), "%s is not a node of the chain's tip" % args.node_id)
            result = increment_document(_key_from_fd(args.key_fd, point), point, args.node_id, args.from_n)
            issued = [{"kind": "anchor-increment", "node_id": args.node_id, "from": args.from_n}]
        else:
            genesis = bool(args.offline_keys_record or args.node)
            require(genesis != bool(args.chain or args.current), "give --offline-keys-record and --node (the genesis), or --chain and "
                    "--current (a rotation), not both")
            with open(args.system_pub, "rb") as f:
                pem = f.read(65536)
            document = measurements.load(manifest._raw(args.document, measurements.MAX_BYTES))
            if genesis:
                require(args.offline_keys_record and args.node, "the genesis needs --offline-keys-record and --node for each node")
                point = _pinned_at_genesis(root, args.offline_keys_record)
                generations = genesis_generations(document, pem, point, [
                    (manifest.read_json(b, membership.MAX_BYTES), manifest.read_json(k, 4096), manifest.read_json(a, 65536)) for b, k, a in args.node])
            else:
                require(args.chain and args.current, "a rotation needs --chain and --current")
                point, tip = _pinned_by_chain(root, args.chain)
                current = measurements.load(manifest._raw(args.current, measurements.MAX_BYTES))
                measurements.bind(tip, current)               # the document the tip commits to, and no other
                generations = rotation_generations(current, pem, point)
            result = fill(document, pem, point, _key_from_fd(args.key_fd, point), generations)
            from deploy.baremetal import signkey
            fingerprint = signkey.pcr_key_fingerprint(pem)
            issued = [{"kind": "anchor-approval", "node_id": node_id, "k_sys": fingerprint, "generation": e["signing"]["anchor_approvals"]["generation"],
                       "classes": sorted(e["signing"]["anchor_approvals"]["classes"])}
                      for node_id, node in sorted(result["nodes"].items()) for e in node["accepted"]
                      if e.get("signing", {}).get("system") == fingerprint and "anchor_approvals" in e["signing"]]
        # the issuance record (regalia-kms-d9): appended, synced, BEFORE anything is printed, in the laptop's one ordered
        # record of the offline keys' uses (its readers skip kinds they do not know)
        import time
        for line in issued:
            manifest._append_record(args.state_dir, dict(line, at=int(time.time()), provenance=provenance))
    except (Refused, enrol.Refused, OSError, ValueError) as error:          # enrol's: the genesis proof and rotation_of
        print("anchorpolicy: refused: %s" % error, file=sys.stderr)
        return 2
    out.write(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
