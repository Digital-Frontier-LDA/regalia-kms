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
    require(cls in REFS, "no policy class %r" % (cls,))
    return policy + REFS[cls]


# ---- the TPM side of the rotation counter R (#361 C1): defined and first incremented at `enrol init` ----
#
# R is defined before the anchor and the counters (regalia-kms-95: every class approval names R's WRITTEN Name, so it is
# written first) and before `enrol ownerauth` (the owner authorization is still empty, as the define needs). Its first
# increment is made under K_A's public, node-independent approval increment_first (valid only while R is unwritten: a
# replay is refused by the TPM). Its value after that is this node's G start; its Name and value go into the identity the
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


def read_first(doc):
    """The `--anchor-policy` file: exactly {schema, anchor_policy_key, increment_first}, K_A a typed P-256 entry and its
    approval of R's first increment verified under it. Unauthenticated here by design: the genesis checks R's quoted Name
    against the manifest's K_A (regalia-kms-95). Returns (K_A's point hex, the approval's DER)."""
    require(isinstance(doc, dict), "the anchor-policy file is not an object")
    membership.exact(doc, ("schema", "anchor_policy_key", "increment_first"), "the anchor-policy file")
    require(doc["schema"] == FIRST_SCHEMA, "the anchor-policy file is not a %s" % FIRST_SCHEMA)
    point = membership.typed_key(doc["anchor_policy_key"], "the anchor-policy file's anchor_policy_key", membership.ANCHOR_POLICY_KEY_ALGS)[1]
    der = verify_approval(point, increment_first(), "rotation", doc["increment_first"], "the anchor-policy file's increment_first")
    return point, der


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


def start_rotation(index, point, approval_der, run=None):
    """Define R at `index` under PolicyAuthorize(Name(K_A), "rotation") and make its first increment under K_A's approval,
    finishing what an interrupted run left (regalia-kms-95's cases):
      * R absent: K_A's approval is checked by the TPM first (loadexternal, verifysignature: no R is defined for a wrong
        one), then R is defined, then incremented;
      * R present and unwritten, under this K_A: the increment is finished;
      * R present and written, under this K_A: nothing to do;
      * anything else at `index`: refused, never undefined.
    Needs the TPM's owner authorization to be empty (a define before `enrol ownerauth`). Returns {index, name, value}."""
    import os
    import tempfile
    unwritten, written = rotation_name(int(index, 16), point, written=False).hex(), rotation_name(int(index, 16), point).hex()
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
                f.write(authorize_message(increment_first(), "rotation"))
            _tpm(run, "flushcontext", "-t")
            _must(_tpm(run, "loadexternal", "-C", "o", "-G", "ecc", "-u", path("ka.pem"), "-c", path("ka.ctx"), "-n", path("ka.name")),
                  "loading K_A")
            with open(path("ka.name"), "rb") as f:                # the template checked before the TPM is asked anything else
                require(f.read() == k_a_name(point), "the TPM's Name of K_A is not the one computed for it")
            _must(_tpm(run, "verifysignature", "-c", path("ka.ctx"), "-g", "sha256", "-m", path("message"), "-s", path("sig.der"),
                       "-f", "ecdsa", "-t", path("ticket")), "the TPM's check of K_A's approval of the rotation counter's first increment")
            if held is None:
                with open(path("policy"), "wb") as f:
                    f.write(class_policy(point, "rotation"))
                _must(_tpm(run, "nvdefine", index, "-C", "o", "-s", "8", "-a", ROTATION_WORDS, "-L", path("policy")),
                      "defining the rotation counter %s (the TPM's owner authorization must still be empty: `enrol init` comes "
                      "before `enrol ownerauth`)" % index)
            _tpm(run, "flushcontext", "-t")                       # the ticket outlives K_A's context
            _must(_tpm(run, "startauthsession", "--policy-session", "-S", path("s.ctx")), "a policy session")
            try:
                _must(_tpm(run, "policycommandcode", "-S", path("s.ctx"), "TPM2_CC_NV_Increment"), "PolicyCommandCode")
                _must(_tpm(run, "policynvwritten", "-S", path("s.ctx"), "c"), "PolicyNvWritten")
                _must(_tpm(run, "policyauthorize", "-S", path("s.ctx"), "-i", path("approved"), "-n", path("ka.name"),
                           "-q", REFS["rotation"].hex(), "-t", path("ticket")), "PolicyAuthorize(K_A, \"rotation\")")
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


def approved_for(k_sys_pem, k_a_point, generation):
    """P(K_sys, G) for this K_A's rotation counter: what each class's approval signs."""
    from deploy.baremetal import signkey
    return approved(signkey.pcr_key_name(k_sys_pem), rotation_name(int(ROTATION_INDEX, 16), k_a_point), generation)


def approvals_for(key, k_sys_pem, k_a_point, generation):
    """A set's anchor_approvals block, signed with K_A's private `key` (the signer's)."""
    policy = approved_for(k_sys_pem, k_a_point, generation)
    return {"generation": generation, "classes": {cls: sign(key, policy, cls) for cls in APPROVAL_CLASSES}}


def check_approvals(approvals, k_sys_pem, k_a_point, label="anchor_approvals"):
    """Every class's approval in `approvals` (attest.validate_approvals' form) is K_A's, over THIS key and THIS node's
    rotation counter at its G: refused by name otherwise. Returns G."""
    attest.validate_approvals(approvals, label)
    policy = approved_for(k_sys_pem, k_a_point, approvals["generation"])
    for cls in APPROVAL_CLASSES:
        verify_approval(k_a_point, policy, cls, approvals["classes"][cls], "%s.classes.%s" % (label, cls))
    return approvals["generation"]


# ---- the K_A signer (#361 C2): run by regalia-ceremony's offline-keys with K_A in a sealed memfd (51's TOOLS entries) ----
#
#   python3 -Es -m deploy.baremetal.anchorpolicy approve-first --root-key ROOT --offline-keys-record REC --key-fd N --offline-session ID
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


def first_document(key, k_a_point):
    """The `enrol init --anchor-policy` file: K_A and its approval of the rotation counter's first increment."""
    doc = {"schema": FIRST_SCHEMA, "anchor_policy_key": {"alg": "ecdsa-p256", "key": k_a_point},
           "increment_first": sign(key, increment_first(), "rotation")}
    read_first(doc)                                             # verified before it is printed
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
        for i, entry in enumerate(node["accepted"]):
            if entry.get("signing", {}).get("system") != fingerprint:
                continue
            require(node_id in generations, "%s has a set signed by this system-phase key and no generation to approve it at" % node_id)
            entry["signing"]["anchor_approvals"] = approvals_for(key, k_sys_pem, k_a_point, generations[node_id])
            check_approvals(entry["signing"]["anchor_approvals"], k_sys_pem, k_a_point, "nodes.%s.accepted[%d].signing.anchor_approvals" % (node_id, i))
            filled.append(node_id)
    require(filled, "no set in the document is signed by this system-phase key (%s): nothing to approve" % fingerprint)
    measurements.validate(out)
    return out


def genesis_generations(document, k_sys_pem, k_a_point, nodes):
    """At the genesis: each node's G is its AK-quoted first value of R, proven here as `manifest propose --genesis` proves
    it (enrol.proven_entry, then enrol.rotation_of under THIS K_A). `nodes`: [(bundle, keep, activation)]."""
    from deploy.baremetal import enrol
    generations = {}
    for bundle, keep, activation in nodes:
        entry, _ = enrol.proven_entry(bundle, k_sys_pem, keep, activation)
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
        known = [e["signing"]["anchor_approvals"]["generation"] for e in node["accepted"] if "anchor_approvals" in e.get("signing", {})]
        if own:
            generations[node_id] = own[0]
        elif known:
            generations[node_id] = max(known) + 1
    return generations


def increment_document(key, k_a_point, node_id, n):
    """K_A's single-use approval of the increment that takes `node_id`'s R from `n` (C4's retire)."""
    _count(n, "--from")
    rotation = rotation_name(int(ROTATION_INDEX, 16), k_a_point)
    sig = sign(key, increment_from(rotation, n), "rotation")
    verify_approval(k_a_point, increment_from(rotation, n), "rotation", sig, "the increment approval")
    return {"schema": INCREMENT_SCHEMA, "node_id": node_id, "from": n, "signature": sig}


def main(argv=None, out=None):
    import argparse
    import json
    import sys
    from deploy.baremetal import keyfd, manifest, measurements
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="python3 -Es -m deploy.baremetal.anchorpolicy", description="K_A's approvals (#361), on the offline laptop")
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("approve-first", "approve", "approve-increment"):
        c = sub.add_parser(name)
        c.add_argument("--root-key", required=True, help="the pinned membership root (64 hex)")
        c.add_argument("--key-fd", type=int, required=True, help="K_A's private key: a sealed memfd or a pipe (offline-keys' {keyfd:anchor-policy})")
        c.add_argument("--offline-session", required=True, help="the offline-keys session ID (32 hex)")
        if name == "approve-first":
            c.add_argument("--offline-keys-record", required=True, help="offline-keys.record.json: K_A, verified under the root")
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
        keyfd.session(args.offline_session)
        root = manifest.root_key(args.root_key)
        if args.command == "approve-first":
            point = _pinned_at_genesis(root, args.offline_keys_record)
            result = first_document(_key_from_fd(args.key_fd, point), point)
        elif args.command == "approve-increment":
            point, tip = _pinned_by_chain(root, args.chain)
            require(args.node_id in membership.validate(tip), "%s is not a node of the chain's tip" % args.node_id)
            result = increment_document(_key_from_fd(args.key_fd, point), point, args.node_id, args.from_n)
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
    except (Refused, OSError, ValueError) as error:
        print("anchorpolicy: refused: %s" % error, file=sys.stderr)
        return 2
    out.write(json.dumps(result, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
