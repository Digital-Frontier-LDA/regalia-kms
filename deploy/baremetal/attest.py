"""Fresh TPM attestation of a bare-metal KMS node, verified by a peer (regalia-kms#65, PoC 5.1/5.4/5.5;
THREE-SITE-THREAT-MODEL.md S3).

A peer decides whether to help a node boot from a TPM quote. Three things make the quote mean something:

  1  THE KEY IS IN THE KNOWN TPM. The node's Attestation Key (AK) is a restricted ECDSA P-256 signing
     key: the TPM signs with it only structures it built itself, so a quote cannot be forged by handing
     the AK a digest. The verifier binds it to the Endorsement Key (EK) recorded at intake with
     TPM2_MakeCredential / TPM2_ActivateCredential: a secret wrapped to that EK and to the AK's Name
     comes back only from the TPM that holds both.
  2  THE QUOTE IS ABOUT THIS BOOT SESSION. Its qualifying data is the SHA-256 of a canonical transcript:
     node ID, manifest epoch, boot session ID, the boot session's ephemeral public key and the nonce the
     peer issued. Replaying a quote, or substituting any one field, fails.
  3  THE TPM'S OWN COUNTERS AGREE. The quote carries TPMS_CLOCK_INFO (resetCount, restartCount, clock)
     and the firmware version. The counters never go backwards, one boot carries one boot session (it
     may be verified again in that boot, with a fresh nonce each time), and a boot session never
     outlives a reboot. The clock and its `safe` flag are INFORMATIONAL: they are reported in the
     verdict and never refuse a quote. `safe` is NO after a power loss, which is exactly when a node
     needs its peers, and two quotes of one boot may arrive in either order.

The verifier needs no TPM: tpm2_makecredential runs with no TCTI, the signature is checked by OpenSSL,
and the structures are parsed here from the exact bytes that were signed. Nothing below implements a
cryptographic primitive.

    policy (the verifier's reference values, written at intake):
      {"schema": "regalia-kms/attest-policy/v1",
       "nodes": {"site-a": {"ek_name": "000b<64 hex>",            # the Name of the EK's public area
                            "tpm_firmware_version": "<16 hex>",    # TPMS_ATTEST.firmwareVersion
                            "pcrs": {"0": "<64 hex>", "7": "<64 hex>"}}}}   # SHA-256 bank, expected values

    ONE OR TWO ACCEPTED MEASUREMENT SETS (#75). A node entry may instead carry
      {"ek_name": ..., "accepted": [{"label": "<name>", "tpm_firmware_version": ..., "pcrs": {...}}, ...]}
    with one or two sets: CURRENT, and NEXT while an update rolls through the nodes (measurements.py
    builds these from the document the membership manifest commits to). A quote is accepted when it
    matches one set whole, its PCR values and its firmware version together; the verdict names the
    set, and the verifier's state remembers the set, the epoch and the boot phase of each node's last
    accepted quote (rollout.py reads that). Never more than two: a list that only grows is how a retired image
    stays accepted. All sets of a node select the same PCRs, since the node quotes one selection.

    PCR VALUES PER BOOT PHASE (#57, #156). On a host that boots a unified kernel image, systemd extends
    PCR 11 as the boot passes its phases, so ONE image has two PCR 11 values at the two moments a peer
    judges it: in the initrd, when the node asks for its disk to be unlocked, and once booted, when it
    asks for a runtime lease. A set may therefore give some PCRs per phase, beside the ones that hold
    one value throughout:
      {"label": ..., "tpm_firmware_version": ..., "pcrs": {"7": ...},
       "phases": {"initrd": {"11": "<64 hex>"}, "system": {"11": "<64 hex>"}}}
    and verify() is told which phase the request must come from (PHASES). A quote that is the image's
    OTHER phase is refused, and the refusal says so: a booted system does not get a disk key, and an
    initrd does not get a lease. A set with no "phases" has one value per PCR, whatever the phase (a
    host that does not boot a UKI, whose PCR 11 never moves). A policy with per-phase sets refuses a
    verification that names no phase.

    state (what the verifier has learned; 0600, updated under a lock):
      enrolled AKs, outstanding nonces (single use, 120 s), each node's last accepted counters and
      the hash of every boot session and ephemeral key it ever accepted.

NOT covered here: the EK certificate chain to the TPM manufacturer (the swtpm EK has none; the DL360's
is checked at intake, #65 PoC 5.2), and which PCRs to expect (PoC 5.2/5.3 on the real hardware).
"""
import argparse
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time

POLICY_SCHEMA = "regalia-kms/attest-policy/v1"
MAX_SETS = 2          # CURRENT and NEXT; see the module text
SET_KEYS = ("label", "tpm_firmware_version", "pcrs")
# The phases a node is judged in, and what it may ask for there: "initrd" an unlock (replacement.may_unlock),
# "system" a runtime lease (lease.issue). Which systemd phase path each one is belongs to the image's build
# record (#57): enter-initrd, and enter-initrd:leave-initrd:sysinit:ready.
PHASES = ("initrd", "system")
STATE_SCHEMA = "regalia-kms/attest-state/v1"
TRANSCRIPT_LABEL = b"regalia-kms/attest/v1"
# A quote that also binds one more value (a path enrolment key, #190): its own label and a sixth field, so it
# can never encode to a lease's or an unlock's transcript, nor the reverse
BINDING_LABEL = b"regalia-enrol/v1/path"
MAX_BYTES = 128 * 1024
# The state keeps two hashes for every boot it ever accepted, per node, and never forgets one (about
# 140 bytes a boot: 4 MiB is some 10,000 boots a node across three nodes). When it is full the verifier
# refuses rather than forget: an operator archives the state deliberately.
STATE_MAX_BYTES = 4 * 1024 * 1024
NONCE_TTL = 120
MAX_OUTSTANDING = 8   # nonces per node; the oldest gives way, so asking for nonces cannot fill the state

TPM_GENERATED = 0xFF544347
ST_ATTEST_QUOTE = 0x8018
ALG_SHA256, ALG_NULL, ALG_ECDSA, ALG_ECC, CURVE_P256 = 0x000B, 0x0010, 0x0018, 0x0023, 0x0003
RH_ENDORSEMENT = 0x4000000B
# fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | sign, and nothing else:
# no decrypt (a key that also decrypts is not an attestation key), not duplicable, made in the TPM
AK_ATTRIBUTES = 0x00050072
P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
EK_HANDLE, AK_HANDLE = "0x81010001", "0x81010002"


class Refused(Exception):
    pass


def require(cond, message):
    if not cond:
        raise Refused(message)


# ---- TPM structures, parsed from the signed bytes ----

class Reader:
    def __init__(self, data, label):
        self.data, self.at, self.label = data, 0, label

    def take(self, n):
        require(self.at + n <= len(self.data), "%s is truncated" % self.label)
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def u(self, fmt):
        return struct.unpack(">" + fmt, self.take(struct.calcsize(fmt)))[0]

    def sized(self):
        return self.take(self.u("H"))

    def end(self):
        require(self.at == len(self.data), "%s has trailing bytes" % self.label)


def name_of(public_area):
    return struct.pack(">H", ALG_SHA256) + hashlib.sha256(public_area).digest()


def public_area(blob, label):
    """The TPMT_PUBLIC inside a TPM2B_PUBLIC (tpm2-tools' -u output)."""
    r = Reader(blob, label)
    area = r.sized()
    r.end()
    return area


def ak_identity(ak_public):
    """An AK's Name and PEM public key, both computed from its public area and never taken on the node's
    word. Refuses anything that is not a restricted, TPM-made, sign-only ECDSA P-256/SHA-256 key."""
    area = public_area(ak_public, "the AK public area")
    r = Reader(area, "the AK public area")
    require(r.u("H") == ALG_ECC, "the AK must be an ECC key")
    require(r.u("H") == ALG_SHA256, "the AK's name algorithm must be SHA-256")
    attributes = r.u("I")
    require(attributes == AK_ATTRIBUTES, "the AK must be a restricted, sign-only, fixedTPM key made in the TPM "
            "(attributes 0x%08x, not 0x%08x)" % (attributes, AK_ATTRIBUTES))
    require(r.sized() == b"", "the AK must not carry an auth policy")
    require(r.u("H") == ALG_NULL, "a restricted signing key has no symmetric algorithm")
    require((r.u("H"), r.u("H")) == (ALG_ECDSA, ALG_SHA256), "the AK's scheme must be ECDSA with SHA-256")
    require(r.u("H") == CURVE_P256, "the AK's curve must be NIST P-256")
    require(r.u("H") == ALG_NULL, "the AK must not carry a KDF")
    x, y = r.sized(), r.sized()
    r.end()
    require(len(x) == 32 and len(y) == 32, "the AK's public point is not a P-256 point")
    return name_of(area), P256_SPKI_PREFIX + b"\x04" + x + y


def qualified_name(ek_name, ak_name):
    """The AK's Qualified Name under the EK in the endorsement hierarchy: what TPMS_ATTEST.qualifiedSigner
    must be if the signing key is this AK under this EK."""
    def h(data):
        return struct.pack(">H", ALG_SHA256) + hashlib.sha256(data).digest()
    return h(h(struct.pack(">I", RH_ENDORSEMENT) + ek_name) + ak_name)


def parse_quote(blob):
    """TPMS_ATTEST for a quote over one SHA-256 PCR selection."""
    r = Reader(blob, "the quote")
    require(r.u("I") == TPM_GENERATED, "the quote was not generated by a TPM (magic)")
    require(r.u("H") == ST_ATTEST_QUOTE, "the attestation is not a quote")
    out = {"qualified_signer": r.sized(), "extra_data": r.sized(), "clock": r.u("Q"), "reset_count": r.u("I"),
           "restart_count": r.u("I"), "safe": r.u("B"), "firmware_version": "%016x" % r.u("Q")}
    require(r.u("I") == 1, "the quote must select exactly one PCR bank")
    require(r.u("H") == ALG_SHA256, "the quote must select the SHA-256 PCR bank")
    bitmap = r.take(r.u("B"))
    out["pcrs"] = [i for i in range(len(bitmap) * 8) if bitmap[i // 8] >> (i % 8) & 1]
    out["pcr_digest"] = r.sized()
    r.end()
    return out


def transcript(node_id, epoch, session_id, ephemeral_public, nonce, binding=None):
    """The canonical transcript the quote is bound to. Every field is length-prefixed under a fixed
    label, so no two different field tuples encode to the same bytes. With `binding` (bytes), the label is
    BINDING_LABEL and the binding is a sixth field: the quote then also vouches for that value, in the same
    boot session (a path enrolment key, #190)."""
    if binding is None:
        fields = (TRANSCRIPT_LABEL, node_id.encode(), struct.pack(">Q", epoch), session_id, ephemeral_public, nonce)
    else:
        require(isinstance(binding, bytes) and 1 <= len(binding) <= 1024, "the binding must be 1-1024 bytes")
        fields = (BINDING_LABEL, node_id.encode(), struct.pack(">Q", epoch), session_id, ephemeral_public, nonce, binding)
    return b"".join(struct.pack(">I", len(f)) + f for f in fields)


def qualifying_data(*fields, binding=None):
    return hashlib.sha256(transcript(*fields, binding=binding)).digest()


def check_session(node_id, epoch, session_id, ephemeral_public, nonce):
    require(isinstance(node_id, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", node_id), "the node ID is not a plain name")
    require(isinstance(epoch, int) and not isinstance(epoch, bool) and 0 <= epoch < 2 ** 64, "the manifest epoch must be a uint64")
    require(len(session_id) == 32, "the boot session ID must be 32 bytes")
    require(1 <= len(ephemeral_public) <= 512, "the ephemeral public key must be 1-512 bytes")
    require(len(nonce) == 32, "the nonce must be 32 bytes")


# ---- policy and state ----

def load_json(raw, label, limit=MAX_BYTES):
    require(len(raw) <= limit, "%s exceeds %d KiB" % (label, limit // 1024))

    def unique(pairs):
        out = {}
        for k, v in pairs:
            require(k not in out, "duplicate %s field: %s" % (label, k))
            out[k] = v
        return out
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except ValueError as error:
        raise Refused("%s is not valid JSON" % label) from error


def exact_keys(value, keys, label):
    require(isinstance(value, dict), "%s must be an object" % label)
    missing, unknown = set(keys) - set(value), set(value) - set(keys)
    require(not missing and not unknown, "%s fields mismatch: missing=%s unknown=%s" % (label, sorted(missing), sorted(unknown)))
    return value


def is_hex(value, n):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % n, value) is not None


def _validate_pcrs(pcrs, label):
    require(isinstance(pcrs, dict) and pcrs, "%s must expect at least one PCR" % label)
    for index, value in pcrs.items():
        # [0-9], not \d: \d also matches the digits of other scripts, and int() reads them ("1" + ARABIC-INDIC ONE is 11)
        require(isinstance(index, str) and re.fullmatch(r"0|[1-9][0-9]?", index) and int(index) <= 23, "%s: %r is not a PCR 0-23" % (label, index))
        require(is_hex(value, 64), "%s.%s must be 64 lowercase hex" % (label, index))


def validate_set(entry, label):
    """One measurement set: a TPM firmware version and the expected value of each selected PCR, some of
    them per boot phase (the module text)."""
    require(is_hex(entry["tpm_firmware_version"], 16), "%s.tpm_firmware_version must be 16 hex" % label)
    _validate_pcrs(entry["pcrs"], "%s.pcrs" % label)
    if "phases" not in entry:
        return
    phases = exact_keys(entry["phases"], PHASES, "%s.phases" % label)
    for phase in PHASES:
        _validate_pcrs(phases[phase], "%s.phases.%s" % (label, phase))
    require(set(phases[PHASES[0]]) == set(phases[PHASES[1]]), "%s.phases: the two phases give different PCRs; a node quotes one selection" % label)
    both = sorted(set(entry["pcrs"]) & set(phases[PHASES[0]]), key=int)
    require(not both, "%s: PCR %s is given once for every phase and again per phase" % (label, ", ".join(both)))
    # the same values in both phases would let the request of one phase pass as the other's
    require(phases[PHASES[0]] != phases[PHASES[1]], "%s.phases: the two phases hold the same values; a PCR that does not move "
            "between them belongs in pcrs" % label)


def selection(entry):
    """The PCRs a node on this set quotes: the ones with one value, and the ones given per phase."""
    return sorted(int(i) for i in set(entry["pcrs"]) | set(entry.get("phases", {}).get(PHASES[0], {})))


def values(entry, phase):
    """The expected value of every selected PCR in `phase` (None: the set must have no per-phase PCR)."""
    return dict(entry["pcrs"], **entry["phases"][phase]) if "phases" in entry else dict(entry["pcrs"])


def _measurements(entry):
    return (entry["tpm_firmware_version"], entry["pcrs"], entry.get("phases"))


def validate_sets(sets, label):
    """The `accepted` list of a node: one or two distinct sets, named apart, over one PCR selection."""
    require(isinstance(sets, list) and 1 <= len(sets) <= MAX_SETS,
            "%s.accepted must hold one or two measurement sets (CURRENT, and NEXT during an update)" % label)
    for i, entry in enumerate(sets):
        here = "%s.accepted[%d]" % (label, i)
        require(isinstance(entry, dict), "%s must be an object" % here)
        exact_keys(entry, SET_KEYS + (("phases",) if "phases" in entry else ()), here)
        require(isinstance(entry["label"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,48}", entry["label"]), "%s.label must be a short plain name" % here)
        validate_set(entry, here)
    if len(sets) == 2:
        require(sets[0]["label"] != sets[1]["label"], "%s.accepted: two sets share the label %r" % (label, sets[0]["label"]))
        # compared as selections: during the move to a UKI, CURRENT gives PCR 11 once and NEXT gives it per phase
        require(selection(sets[0]) == selection(sets[1]), "%s.accepted: the two sets select different PCRs; a node quotes one selection" % label)
        require(_measurements(sets[0]) != _measurements(sets[1]), "%s.accepted: the two sets are the same measurements under two labels" % label)
        # ... and no phase of one may read as a phase of the other: the label a quote is given would be a guess
        seen = {}
        for entry in sets:
            for phase in (PHASES if "phases" in entry else (None,)):
                key = (entry["tpm_firmware_version"], tuple(sorted(values(entry, phase).items())))
                require(seen.setdefault(key, entry["label"]) == entry["label"], "%s.accepted: %r and %r hold the same PCR values "
                        "in one of their phases" % (label, seen[key], entry["label"]))


def validate_policy(doc):
    """The policy's nodes, each as {"ek_name": ..., "accepted": [set, ...]}. The one-set form (the
    firmware version and the PCRs beside the EK) is read as one set with an empty label."""
    root = exact_keys(doc, ("schema", "nodes"), "policy")
    require(root["schema"] == POLICY_SCHEMA, "policy schema must be %s" % POLICY_SCHEMA)
    require(isinstance(root["nodes"], dict) and root["nodes"], "policy.nodes must name at least one node")
    nodes = {}
    for node_id, node in root["nodes"].items():
        label = "policy.nodes.%s" % node_id
        require(re.fullmatch(r"[A-Za-z0-9._-]{1,64}", node_id), "%s is not a plain name" % label)
        if isinstance(node, dict) and "accepted" in node:
            exact_keys(node, ("ek_name", "accepted"), label)
            validate_sets(node["accepted"], label)
            sets = node["accepted"]
        else:
            exact_keys(node, ("ek_name", "tpm_firmware_version", "pcrs"), label)
            validate_set(node, label)
            sets = [{"label": "", "tpm_firmware_version": node["tpm_firmware_version"], "pcrs": node["pcrs"]}]
        require(is_hex(node["ek_name"], 68) and node["ek_name"].startswith("000b"), "%s.ek_name must be a SHA-256 Name (000b + 64 hex)" % label)
        nodes[node_id] = {"ek_name": node["ek_name"], "accepted": sets}
    return nodes


def check_reported_values(pcr_values, selected, quoted_digest):
    """The node's reported PCR values, or None when it sent none (protocol v1). They must give exactly the
    verifier's selection, each as 64 lowercase hex, and hash to the quoted digest: only then are they as good
    as quoted. Anything else is refused, and never used."""
    if pcr_values is None:
        return None
    require(isinstance(pcr_values, dict) and all(isinstance(k, str) and is_hex(v, 64) for k, v in pcr_values.items()),
            "the reported PCR values must map PCR indices to 64 lowercase hex")
    given = sorted(int(k) for k in pcr_values if re.fullmatch(r"0|[1-9][0-9]?", k))
    require(len(given) == len(pcr_values) and given == selected,
            "the reported PCR values cover PCRs %s, not the quoted selection %s" % (sorted(pcr_values, key=lambda k: (len(k), k)), selected))
    require(hmac.compare_digest(quoted_digest, expected_pcr_digest(pcr_values)), "the reported PCR values do not match the quote")
    return pcr_values


def differences(reported, sets, phase):
    """With reported values that match the quote: every PCR that differs from each accepted set, in index
    order, with both values in hex. Without them: nothing to add (a v1 node)."""
    if reported is None:
        return ""
    parts = []
    for entry in sets:
        want = values(entry, phase)
        # never empty: this is called only when the quoted digest matches no set's values
        diff = ["PCR %s is %s, expected %s" % (i, reported[i], want[i]) for i in sorted(want, key=int) if reported[i] != want[i]]
        where = entry["label"] + (" (%s phase)" % phase if "phases" in entry and phase else "")
        parts.append("%s: %s" % (where or "the set", "; ".join(diff)))
    return ". " + " | ".join(parts)


def expected_pcr_digest(pcrs):
    """What TPMS_QUOTE_INFO.pcrDigest is when the selected PCRs hold the expected values."""
    return hashlib.sha256(b"".join(bytes.fromhex(pcrs[i]) for i in sorted(pcrs, key=int))).digest()


@contextlib.contextmanager
def locked_state(path):
    """The verifier's state, read and rewritten under an exclusive lock: two verifications of the same
    nonce cannot both find it outstanding."""
    lock = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(path, "rb") as f:
                state = load_json(f.read(STATE_MAX_BYTES + 1), "state", STATE_MAX_BYTES)
            require(isinstance(state, dict) and state.get("schema") == STATE_SCHEMA, "state schema must be %s" % STATE_SCHEMA)
        except FileNotFoundError:
            state = {"schema": STATE_SCHEMA, "nodes": {}, "nonces": {}}
        def save():
            """Durable before it returns: the file, then the directory entry that names it. A state too
            large to be read back is refused and the file on disk is left as it was."""
            data = json.dumps(state, indent=1, sort_keys=True).encode()
            require(len(data) <= STATE_MAX_BYTES, "the verifier state is full (%d KiB): archive it deliberately; "
                    "nothing was recorded" % (STATE_MAX_BYTES // 1024))
            directory = os.path.dirname(os.path.abspath(path))
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".attest-state-")
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            entry = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(entry)
            finally:
                os.close(entry)
        yield state, save
    finally:
        os.close(lock)


# ---- the verifier ----

def make_credential(ek_public, ak_name, secret, run=subprocess.run):
    """TPM2_MakeCredential in software (no TPM): the secret, wrapped to the EK and to the AK's Name. The
    secret goes to the tool on stdin and is never written to disk."""
    with tempfile.TemporaryDirectory(prefix="attest-") as d:
        ek, credential = os.path.join(d, "ek.pub"), os.path.join(d, "credential")
        with open(os.open(ek, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(ek_public)
        made = run(["tpm2_makecredential", "--tcti", "none", "-u", ek, "-s", "-", "-n", ak_name.hex(), "-o", credential],
                   input=secret, capture_output=True)
        require(made.returncode == 0, "tpm2_makecredential failed: %s" % made.stderr.decode(errors="replace").strip()[-200:])
        with open(credential, "rb") as f:
            return f.read()


def verify_signature(spki_der, message, signature, run=subprocess.run):
    with tempfile.TemporaryDirectory(prefix="attest-") as d:
        paths = {n: os.path.join(d, n) for n in ("ak.der", "quote", "signature")}
        for name, data in (("ak.der", spki_der), ("quote", message), ("signature", signature)):
            with open(os.open(paths[name], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                f.write(data)
        checked = run(["openssl", "dgst", "-sha256", "-verify", paths["ak.der"], "-keyform", "DER",
                       "-signature", paths["signature"], paths["quote"]], capture_output=True, text=True)
        require(checked.returncode == 0, "the quote's signature does not verify under the enrolled AK")


class Verifier:
    """One peer's view: its policy, and the state it keeps between calls."""

    def __init__(self, policy, state_path, now=time.time, rand=os.urandom, run=subprocess.run):
        self.nodes, self.state_path, self.now, self.rand, self.run = validate_policy(policy), state_path, now, rand, run

    def node(self, node_id):
        require(isinstance(node_id, str) and node_id in self.nodes, "unknown node: not in the policy")
        return self.nodes[node_id]

    def challenge(self, node_id, ek_public, ak_public, replace=False, ak_name=None):
        """Step 1 of enrollment: a credential only the TPM holding this EK and this AK can open. With `ak_name`
        (the AK Name the root-signed manifest gives this node, #190), the AK offered must be exactly that one:
        the challenge then proves the manifest's AK sits in the TPM with the manifest's EK."""
        expected = self.node(node_id)
        require(len(ek_public) <= 1024 and len(ak_public) <= 1024, "a public area exceeds 1 KiB")
        ek_name = name_of(public_area(ek_public, "the EK public area"))
        require(hmac.compare_digest(ek_name.hex(), expected["ek_name"]), "the EK is not the one recorded for this node at intake")
        ak_name_offered, _ = ak_identity(ak_public)
        if ak_name is not None:
            # the manifest's one spelling (68 lowercase hex, as membership and lease.py hold it), checked before comparing
            require(is_hex(ak_name, 68), "the manifest's ak_name must be 68 lowercase hex")
            require(hmac.compare_digest(ak_name_offered.hex(), ak_name), "the AK offered is not the one the manifest names for this node")
        ak_name = ak_name_offered
        secret = self.rand(32)
        credential = make_credential(ek_public, ak_name, secret, self.run)
        with locked_state(self.state_path) as (state, save):
            record = state["nodes"].setdefault(node_id, {})
            require(replace or "ak_public" not in record, "the node already has an enrolled AK: enrolling another "
                    "replaces its attestation identity (pass replace to do that deliberately)")
            record["pending"] = {"ak_public": ak_public.hex(), "secret_sha256": hashlib.sha256(secret).hexdigest(),
                                 "expires": self.now() + NONCE_TTL}
            save()
        return credential

    def enroll(self, node_id, secret):
        """Step 2: the node returned the secret, so the AK lives in the TPM with the recorded EK."""
        self.node(node_id)
        with locked_state(self.state_path) as (state, save):
            record = state["nodes"].get(node_id, {})
            pending = record.pop("pending", None)
            save()   # one attempt per challenge, right or wrong
            require(pending is not None, "no enrollment challenge is outstanding for this node")
            require(self.now() <= pending["expires"], "the enrollment challenge expired")
            require(hmac.compare_digest(hashlib.sha256(secret).hexdigest(), pending["secret_sha256"]),
                    "the activated credential is not the secret that was wrapped: the AK is not in the TPM with this EK")
            # the counters and the session history are kept: a new AK must not rewind the node's boot history
            record["ak_public"] = pending["ak_public"]
            save()
        return ak_identity(bytes.fromhex(pending["ak_public"]))[0]

    def enrolled(self, node_id):
        """The Name (hex) of the AK enrolled for `node_id`, or None. Read only."""
        self.node(node_id)
        with locked_state(self.state_path) as (state, _):
            record = state["nodes"].get(node_id, {})
            return ak_identity(bytes.fromhex(record["ak_public"]))[0].hex() if "ak_public" in record else None

    def nonce(self, node_id):
        self.node(node_id)
        nonce = self.rand(32)
        with locked_state(self.state_path) as (state, save):
            require("ak_public" in state["nodes"].get(node_id, {}), "the node has no enrolled AK")
            now = self.now()
            state["nonces"] = {n: v for n, v in state["nonces"].items() if v["expires"] >= now}
            mine = sorted((n for n, v in state["nonces"].items() if v["node"] == node_id), key=lambda n: state["nonces"][n]["issued"])
            for old in mine[:max(0, len(mine) - MAX_OUTSTANDING + 1)]:
                del state["nonces"][old]
            state["issued"] = state.get("issued", 0) + 1   # issue order, whatever the clock says
            state["nonces"][nonce.hex()] = {"node": node_id, "expires": now + NONCE_TTL, "issued": state["issued"]}
            save()
        return nonce

    def verify(self, node_id, epoch, session_id, ephemeral_public, nonce, quote, signature, phase=None, pcr_values=None, binding=None):
        """A quote for one boot session. `node_id`, `epoch` and `nonce` are what THIS verifier holds (the
        node it is talking to, its manifest epoch, the nonce it issued); the session ID and the ephemeral
        key are what the node sent. `phase` is the boot phase the request must come from (PHASES): what
        the CALLER is deciding, never something the node said. `pcr_values` ({"<index>": "<64 hex>"},
        protocol v2) are the values the node read beside its quote: unauthenticated, so used only once they
        hash to the quoted digest under THIS verifier's selection, and then only to say which PCR differs
        when the quote matches no accepted set. Such a reason carries the expected PCR values in hex: it goes to
        the caller's audit trail (the operator's), never to the node, which is answered only DENIED. Returns the
        verdict, or raises Refused with the reason."""
        expected = self.node(node_id)
        require(phase is None or (isinstance(phase, str) and phase in PHASES), "the phase must be one of %s" % ", ".join(PHASES))
        phased = [s["label"] for s in expected["accepted"] if "phases" in s]
        require(phase is not None or not phased, "the accepted measurements of %s are per boot phase (%s): the verification must "
                "name the phase the request comes from" % (node_id, ", ".join(phased)))
        check_session(node_id, epoch, session_id, ephemeral_public, nonce)
        require(len(quote) <= 1024 and len(signature) <= 256, "the quote or its signature is oversized")
        with locked_state(self.state_path) as (state, save):
            issued = state["nonces"].pop(nonce.hex(), None)
            save()   # consumed by the first attempt, whatever its outcome
            require(issued is not None, "the nonce is not outstanding (never issued, or already used)")
            require(issued["node"] == node_id, "the nonce was issued to another node")
            require(self.now() <= issued["expires"], "the nonce expired")
            record = state["nodes"].get(node_id, {})
            require("ak_public" in record, "the node has no enrolled AK")
            ak_name, spki = ak_identity(bytes.fromhex(record["ak_public"]))
            verify_signature(spki, quote, signature, self.run)
            q = parse_quote(quote)
            require(q["qualified_signer"] == qualified_name(bytes.fromhex(expected["ek_name"]), ak_name),
                    "the quote's signer is not the enrolled AK under the recorded EK")
            require(hmac.compare_digest(q["extra_data"], qualifying_data(node_id, epoch, session_id, ephemeral_public, nonce, binding=binding)),
                    "the quote is not bound to this transcript (node ID, manifest epoch, boot session ID, ephemeral key, nonce%s)"
                    % (", the value it must bind" if binding is not None else ""))
            sets = expected["accepted"]
            selected = selection(sets[0])                              # the same for every set of a node
            require(q["pcrs"] == selected, "the quote covers PCRs %s, not the expected %s" % (q["pcrs"], selected))
            reported = check_reported_values(pcr_values, selected, q["pcr_digest"])
            # One set must match WHOLE: its PCR values and its firmware version together. A new image
            # under the old TPM firmware's set, or the reverse, is a combination nobody approved.
            on_pcrs = [s for s in sets if hmac.compare_digest(q["pcr_digest"], expected_pcr_digest(values(s, phase)))]
            matched = [s for s in on_pcrs if q["firmware_version"] == s["tpm_firmware_version"]]
            if not matched and phase is not None:
                # an accepted image, whole, in its other phase: say so, since "not the expected values" or "not
                # the recorded firmware" would send an operator looking for a wrong image or a wrong TPM
                other = PHASES[1 - PHASES.index(phase)]
                elsewhere = [s["label"] for s in sets if "phases" in s and q["firmware_version"] == s["tpm_firmware_version"]
                             and hmac.compare_digest(q["pcr_digest"], expected_pcr_digest(values(s, other)))]
                require(not elsewhere, "the node is in the %s phase of %s; this request is accepted only from the %s phase"
                        % (other, elsewhere[0] if elsewhere else "", phase))
            require(on_pcrs, ("the quoted PCR digest is not the expected PCR values" if len(sets) == 1 else
                              "the quoted PCR digest is none of the accepted measurement sets (%s)" % ", ".join(s["label"] for s in sets))
                    + differences(reported, sets, phase))
            require(matched, "the TPM firmware version %s is not the recorded %s" % (
                q["firmware_version"], " or ".join(s["tpm_firmware_version"] for s in on_pcrs)))
            self.check_counters(record, q, session_id, ephemeral_public)
            # Which set, under which manifest epoch, and in which phase: what a rollout asks before the next
            # node reboots and before it retires CURRENT. A node verified in its initrd has asked for its disk;
            # it is not yet a node that came up (rollout.py counts only "system" where the set is per phase).
            seen_phase = phase if "phases" in matched[0] else None
            record["measurement"] = {"label": matched[0]["label"], "epoch": epoch, "phase": seen_phase}
            save()
        # ak_name: the AK this quote was verified under, read inside the same lock as the verification, so
        # a caller that requires a particular AK (a runtime lease, lease.py) compares what was actually used
        return {"node": node_id, "epoch": epoch, "session_id": session_id.hex(), "ak_name": ak_name.hex(), "reset_count": q["reset_count"],
                "restart_count": q["restart_count"], "clock": q["clock"], "clock_safe": bool(q["safe"]), "pcrs": q["pcrs"],
                "measurement": matched[0]["label"], "phase": seen_phase}

    @staticmethod
    def check_counters(record, q, session_id, ephemeral_public):
        """TPMS_CLOCK_INFO against the node's last accepted quote. One boot (resetCount, restartCount)
        carries one boot session; a session, or its ephemeral key, never appears in a later boot.

        Within its boot a session may be verified any number of times, each with its own nonce: the
        initramfs retries its peers with the one session it holds. The clock (and its `safe` flag, which
        is NO after a power loss, exactly when a node needs its peers) is reported and decides nothing:
        two quotes of one boot can arrive in either order, and each already needs its own unused nonce.
        resetCount and restartCount are what the decision rests on."""
        boot = [q["reset_count"], q["restart_count"]]
        session = hashlib.sha256(session_id).hexdigest()
        key = hashlib.sha256(ephemeral_public).hexdigest()
        last = record.get("boot")
        history = record.setdefault("sessions", [])
        if last is not None:
            require(boot >= last["counters"], "the TPM's reset/restart counters went backwards (%s after %s): "
                    "rolled-back TPM state" % (boot, last["counters"]))
            if boot == last["counters"]:
                require(session == last["session"] and key == last["key"],
                        "a second boot session in the same boot: one boot carries one session and one ephemeral key")
            else:
                require(session not in history and key not in history,
                        "a boot session or ephemeral key from an earlier boot was presented after a reboot")
        if last is None or boot != last["counters"]:
            history.extend((session, key))   # never evicted: see STATE_MAX_BYTES
        record["boot"] = {"counters": boot, "session": session, "key": key}


# ---- the node (tpm2-tools against the TPM named by TPM2TOOLS_TCTI) ----

def tpm2(*args, run=subprocess.run):
    done = run(["tpm2_" + args[0], *args[1:]], capture_output=True, text=True)
    require(done.returncode == 0, "tpm2_%s failed: %s" % (args[0], done.stderr.strip()[-300:]))


def node_init(out_dir, run=subprocess.run):
    """Create the EK and a restricted ECDSA P-256 AK under it, both persistent; export their public areas."""
    ek, ak = os.path.join(out_dir, "ek.pub"), os.path.join(out_dir, "ak.pub")
    with tempfile.TemporaryDirectory(prefix="attest-") as d:
        ctx = os.path.join(d, "ak.ctx")
        tpm2("createek", "-c", EK_HANDLE, "-G", "rsa", "-u", ek, run=run)
        tpm2("createak", "-C", EK_HANDLE, "-c", ctx, "-G", "ecc", "-g", "sha256", "-s", "ecdsa", "-u", ak, run=run)
        tpm2("evictcontrol", "-C", "o", "-c", ctx, AK_HANDLE, run=run)
        # Production goes through the kernel resource manager (/dev/tpmrm0), which cleans up after each
        # connection; flushing every transient object (-t) there would break the TPM's other users. Only a
        # private simulator has no manager and keeps what each tool call loaded (deploy/seal-hsm-pin.sh).
        if os.environ.get("TPM2TOOLS_TCTI", "").startswith(("swtpm", "mssim")):
            tpm2("flushcontext", "-t", run=run)


def node_activate(credential_path, secret_path, run=subprocess.run):
    """TPM2_ActivateCredential under the EK's policy (endorsement auth). The secret goes to a 0600 file;
    tpm2_activatecredential also prints it, so its output is never passed on.

    Three processes share one policy session through the -S file: each tpm2-tools call saves the
    session's context when it ends and loads it in the next. Behind the kernel's resource manager
    (/dev/tpmrm0, a host's TCTI) that holds: tests/test_baremetal_attest_kernel_rm.py activates through
    it (measured 2026-10-03, Linux 6.18, tpm2-tools 5.7). tpm2-abrmd would pass for another reason."""
    with tempfile.TemporaryDirectory(prefix="attest-") as d:
        session = os.path.join(d, "session.ctx")
        tpm2("startauthsession", "--policy-session", "-S", session, run=run)
        try:
            tpm2("policysecret", "-S", session, "-c", "e", run=run)
            fd = os.open(secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            activated = False
            try:
                done = run(["tpm2_activatecredential", "-c", AK_HANDLE, "-C", EK_HANDLE, "-i", credential_path,
                            "-o", secret_path, "-P", "session:" + session], capture_output=True, text=True)
                activated = done.returncode == 0
            finally:
                if not activated:
                    os.unlink(secret_path)   # the file this attempt made, so the same path can be retried
            require(activated, "tpm2_activatecredential failed: this TPM does not hold the EK and AK "
                    "the credential was made for")
        finally:
            run(["tpm2_flushcontext", session], capture_output=True)


def node_quote(node_id, epoch, session_id, ephemeral_public, nonce, pcrs, quote_path, signature_path, run=subprocess.run, binding=None):
    check_session(node_id, epoch, session_id, ephemeral_public, nonce)
    require(pcrs and all(isinstance(i, int) and 0 <= i <= 23 for i in pcrs), "PCRs must be 0-23")
    tpm2("quote", "-c", AK_HANDLE, "-g", "sha256", "-l", "sha256:" + ",".join(str(i) for i in sorted(set(pcrs))),
         "-q", qualifying_data(node_id, epoch, session_id, ephemeral_public, nonce, binding=binding).hex(),
         "-m", quote_path, "-s", signature_path, "-f", "plain", run=run)


# ---- command line ----

def read(path, limit=MAX_BYTES):
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    require(len(data) <= limit, "%s is oversized" % path)
    return data


def unhex(value, label):
    require(re.fullmatch(r"([0-9a-f]{2})+", value or "") is not None, "%s must be lowercase hex" % label)
    return bytes.fromhex(value)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="command", required=True)

    def session_args(c):
        c.add_argument("--node-id", required=True)
        c.add_argument("--epoch", required=True, type=int)
        c.add_argument("--session-id", required=True, help="32 bytes, hex")
        c.add_argument("--ephemeral-public", required=True, help="file: the boot session's public key (DER)")
        c.add_argument("--nonce", required=True, help="32 bytes, hex")
        c.add_argument("--quote", required=True)
        c.add_argument("--signature", required=True)

    def verifier_args(c, node=True):
        c.add_argument("--policy", required=True)
        c.add_argument("--state", required=True)
        if node:
            c.add_argument("--node-id", required=True)

    c = sub.add_parser("node-init", help="node: create the EK and AK, export ek.pub and ak.pub")
    c.add_argument("--out", required=True)
    c = sub.add_parser("node-activate", help="node: open an enrollment credential")
    c.add_argument("--credential", required=True)
    c.add_argument("--secret", required=True)
    c = sub.add_parser("node-quote", help="node: quote the PCRs, bound to the boot-session transcript")
    session_args(c)
    c.add_argument("--pcrs", required=True, help="comma-separated, SHA-256 bank")
    c = sub.add_parser("challenge", help="verifier: wrap an enrollment secret to the node's EK and AK")
    verifier_args(c)
    c.add_argument("--ek-public", required=True)
    c.add_argument("--ak-public", required=True)
    c.add_argument("--credential", required=True)
    c.add_argument("--replace", action="store_true")
    c = sub.add_parser("enroll", help="verifier: accept the AK if the node returned the secret")
    verifier_args(c)
    c.add_argument("--secret", required=True)
    c = sub.add_parser("nonce", help="verifier: issue a single-use nonce")
    verifier_args(c)
    c = sub.add_parser("verify", help="verifier: decide on a quote")
    verifier_args(c, node=False)
    session_args(c)
    c.add_argument("--phase", choices=PHASES, help="the boot phase the request must come from; required when the node's sets are per phase")
    a = p.parse_args(argv)

    try:
        if a.command == "node-init":
            node_init(a.out)
            return 0
        if a.command == "node-activate":
            node_activate(a.credential, a.secret)
            return 0
        if a.command == "node-quote":
            require(re.fullmatch(r"\d{1,2}(,\d{1,2})*", a.pcrs) is not None, "--pcrs must be a list such as 0,7")
            node_quote(a.node_id, a.epoch, unhex(a.session_id, "--session-id"), read(a.ephemeral_public, 512),
                       unhex(a.nonce, "--nonce"), [int(i) for i in a.pcrs.split(",")], a.quote, a.signature)
            return 0
        v = Verifier(load_json(read(a.policy), "policy"), a.state)
        if a.command == "challenge":
            credential = v.challenge(a.node_id, read(a.ek_public, 1024), read(a.ak_public, 1024), a.replace)
            with open(a.credential, "wb") as f:
                f.write(credential)
            print("challenge issued to %s" % a.node_id)
        elif a.command == "enroll":
            print("ENROLLED %s AK %s" % (a.node_id, v.enroll(a.node_id, read(a.secret, 64)).hex()))
        elif a.command == "nonce":
            print(v.nonce(a.node_id).hex())
        else:
            verdict = v.verify(a.node_id, a.epoch, unhex(a.session_id, "--session-id"), read(a.ephemeral_public, 512),
                               unhex(a.nonce, "--nonce"), read(a.quote, 1024), read(a.signature, 256), phase=a.phase)
            print("ACCEPTED " + json.dumps(verdict, sort_keys=True))
        return 0
    except (Refused, OSError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
