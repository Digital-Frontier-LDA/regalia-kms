#!/usr/bin/env python3
"""The TPM high-water anchor as the initrd reads it, decided by the Python: each case is the NV indices a
TPM holds (as membership.HighWater laid them out, driven through tests.test_baremetal_heartbeat.FakeTpm),
each with its authPolicy ("policy", null for none), the node's configured approved-image policy (the case's
"policy", null for none; #242), a chain from the ESP, and what Store.load decides before it writes anything.

    python3 -Es tests/vectors/make-highwater-v1.py > tests/vectors/highwater-v1.json

The decision is Store._load without its writes, from HighWater's public methods: value(); a chain below the
high-water is a ROLLBACK; verify(digest_of, lock=False), which accepts the crash window (a record one epoch
behind the counter); and the jump bound advance() applies. cmd/regalia-unlock/membership decides every case
alike (TestEveryAnchorIsReadAlike). The chains are signed with a fixed test key (bytes 0..31): not a secret.
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from deploy.baremetal import membership as m  # noqa: E402
from tests.test_baremetal_heartbeat import FakeTpm  # noqa: E402

root = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
root_pub = root.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
INDEX, SLOTS = "0x1500016", ("0x150001a", "0x150001b")


def envelope(manifest):
    return {"manifest": manifest, "signature": {"signer": "root", "key": root_pub,
                                                "sig": root.sign(m.DOMAIN + m.canonical(manifest)).hex()}}


def node(i, state="ACTIVE"):
    return {"node_id": "n%d" % i, "state": state, "ek_name": "000b" + "%02x" % i * 32, "ak_name": "000b" + "%02x" % (i + 100) * 32,
            "wg_boot_pub": "%02x" % (i + 30) * 32, "wg_service_pub": "%02x" % (i + 60) * 32, "hsm_serials": ["DENK%07d" % i]}


def chain(length, fork_at=None):
    """A chain of `length` epochs; from `fork_at` on, another one (n3 DRAINING instead of ACTIVE)."""
    envelopes, prev = [], ""
    for epoch in range(1, length + 1):
        state = "DRAINING" if fork_at and epoch >= fork_at else "ACTIVE"
        manifest = {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": "p1", "issued_at": "2026-10-03T12:00:00Z",
                    "revocation_keys": [], "nodes": [node(1), node(2), node(3, state)]}
        envelopes.append(envelope(manifest))
        prev = m.digest(manifest)
    return envelopes


def v4_chain(length):
    """A v4 chain (#242 B3: under it the anchor is written by policy only): the same nodes with SSH host keys and fixed
    P-256 signing keys, one Ed25519 owner key, and the format's signer rules."""
    from cryptography.hazmat.primitives.asymmetric import ec

    def p256(n):
        return ec.derive_private_key(0x5EED4000 + n, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint).hex()
    owner = Ed25519PrivateKey.from_private_bytes(bytes([0x42]) * 32).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    nodes = [dict(node(i), ssh_host_pub="%02x" % (i + 90) * 32, signing_key={"alg": "ecdsa-p256", "key": p256(i)}) for i in (1, 2, 3)]
    envelopes, prev = [], ""
    for epoch in range(1, length + 1):
        manifest = {"schema": m.SCHEMA_V4, "epoch": epoch, "prev_digest": prev, "policy_version": "p1", "issued_at": "2026-10-04T12:00:00Z",
                    "heartbeat_max_lifetime_s": 21600, "owner_heartbeat_lifetime_s": 3600,
                    "owner_keys": [{"alg": "ed25519", "key": owner}],
                    "heartbeat_signers": {"threshold": 2, "parties": ["n1", "n2", "n3", "owner"]},
                    "activation_signers": {"threshold": 2, "parties": ["n1", "n2", "n3"]},
                    "revocation_signers": [{"threshold": 2, "parties": ["n1", "n2", "n3"]}, {"threshold": 1, "parties": ["owner"]}],
                    # #361/#405: K_A (a fixed public test point) and the card record's pin
                    "anchor_policy_key": {"alg": "ecdsa-p256", "key": p256(60)}, "card_record": {"sequence": 1, "digest": "ca" * 32},
                    "nodes": nodes}
        envelopes.append(envelope(manifest))
        prev = m.digest(manifest)
    return envelopes


CHAINS = {"main": chain(6), "fork at 3": chain(6, fork_at=3), "fork at 4": chain(6, fork_at=4), "v4": v4_chain(6)}


def composed(document):
    """A document for the file: every "key" written "public" (the v4 chain's typed keys), as make-membership-v4.py writes
    them, so the secret scanner's generic rule does not read a public key under the name "key" as a credential. Readers
    undo it (cmd/regalia-unlock: restoreTyped, vectorManifest; the nv test's restore)."""
    if isinstance(document, dict):
        return {("public" if k == "key" else k): composed(v) for k, v in document.items()}
    if isinstance(document, list):
        return [composed(v) for v in document]
    return document


def manifests_of(envelopes):
    """Store._load's reading loop."""
    current, manifests = None, []
    for env in envelopes:
        nxt = m.accept(current, env, root_pub)
        assert nxt is not current
        manifests.append(nxt)
        current = nxt
    return manifests


class Tpm:
    """FakeTpm with the faults a real TPM can show: an index it lists and does not describe, an index it
    describes and does not read."""

    def __init__(self, highest):
        self.tpm, self.public_fails, self.unreadable, self.cut = FakeTpm(highest), set(), set(), None

    def __call__(self, argv, input=None, **kw):
        tool, index = argv[0][len("tpm2_"):], argv[1]
        no = subprocess.CompletedProcess(argv, 1, b"", b"the TPM said no")
        if tool == "nvreadpublic" and index in self.public_fails or tool == "nvread" and index in self.unreadable:
            return no
        if tool == "nvwrite" and index in SLOTS and self.cut is not None:
            kept, self.cut = self.cut, None
            if kept:
                self.tpm(argv, input=input[:kept], **kw)            # FakeTpm keeps the old bytes after a short write
            return subprocess.CompletedProcess(argv, 1, b"", b"power lost")
        return self.tpm(argv, input=input, **kw)

    def state(self):
        nv = {}
        for index, (bits, data, size) in sorted(self.tpm.nv.items()):
            if isinstance(data, int):
                data = data.to_bytes(8, "big")
            nv[index] = {"attributes": bits, "size": size, "data": None if data is None else data.hex(), "policy": self.tpm.policies.get(index)}
        return {"nv": nv, "broken": self.tpm.broken, "public_fails": sorted(self.public_fails), "unreadable": sorted(self.unreadable)}


def decide(hw, manifests):
    """Store._load before its writes, judged by the tip as the Store judges it (#242 B3, Store._judge_by): its schema, and
    under v4 its anchor_policy_key (#361)."""
    hw.judge_by_tip(manifests[-1])
    try:
        high = hw.value()
        epoch = manifests[-1]["epoch"]
        m.require(epoch >= high, "ROLLBACK: the membership on disk is epoch %d but the TPM high-water is %d; "
                  "fetch the chain from a peer" % (epoch, high))
        high = hw.verify(m.Store._digests(manifests), lock=False)
        m.require(epoch - high <= hw.MAX_JUMP, "epoch jump %d exceeds the bound %d: anomaly" % (epoch - high, hw.MAX_JUMP))
        return {"high_water": high}
    except m.Unusable as reason:
        return {"unusable": str(reason)}
    except m.Refused as reason:
        return {"refused": str(reason)}


cases = []
scratch = tempfile.mkdtemp()


def case(name, anchored, chain_name, length, change=None, highest=41, then=None, policy=None, anchored_on="main"):
    """A TPM anchored through `anchored` epochs of the chain `anchored_on` (define, then anchor() each), changed by
    `change(tpm, hw)`, read against the first `length` epochs of `chain_name` by a node whose approved-image
    policy is `policy`."""
    lock = os.path.join(scratch, "%d.lock" % len(cases))
    tpm = Tpm(highest)
    hw = m.HighWater(INDEX, run=tpm, lock_path=lock, policy=policy)
    hw.define()
    digests = m.Store._digests(manifests_of(CHAINS[anchored_on]))
    for epoch in range(1, anchored + 1):
        hw.anchor(epoch, digests)
    if change:
        change(tpm, hw)
    envelopes = CHAINS[chain_name][:length]
    outcome = decide(hw, manifests_of(envelopes))
    if then:
        assert then in json.dumps(outcome), (name, outcome)
    cases.append({"name": name, "tpm": tpm.state(), "chain": chain_name, "length": length, "policy": policy, **outcome})


def nv(tpm, index):
    return tpm.tpm.nv[index]


def set_bits(index, add=0, remove=0):
    def change(tpm, hw):
        nv(tpm, index)[0] = (nv(tpm, index)[0] | add) & ~remove
    return change


def redefine(index, size=48, words="ownerread|ownerwrite|authread", data=None):
    def change(tpm, hw):
        tpm.tpm(["tpm2_nvundefine", index, "-C", "o"])
        tpm.tpm(["tpm2_nvdefine", index, "-C", "o", "-s", str(size), "-a", words])
        if data is not None:
            tpm.tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=data)
    return change


def torn_advance(kept, epoch):
    """The counter moves to `epoch`, and the record write for it is cut after `kept` bytes."""
    def change(tpm, hw):
        tpm.cut = kept
        try:
            hw.anchor(epoch, m.Store._digests(manifests_of(CHAINS["main"])))
        except m.Refused:
            pass
        assert tpm.cut is None
    return change


def both(*changes):
    def change(tpm, hw):
        for c in changes:
            c(tpm, hw)
    return change


case("anchored at 3, the chain at 3", 3, "main", 3, then="high_water")
case("anchored at 3, the chain ahead at 6", 3, "main", 6, then="high_water")
case("a TPM that never held a counter", 3, "main", 3, highest=0, then="high_water")
case("defined only (epoch 0, a zero digest), the chain at 1", 0, "main", 1, then="high_water")
case("anchored at 5, the chain at 3: a restored disk", 5, "main", 3, then="ROLLBACK")
case("anchored at 3, another chain at 3", 3, "fork at 3", 3, then="CONFLICT")
case("anchored at 3, another chain from epoch 4", 3, "fork at 4", 5, then="high_water")
case("the crash window: counter at 4, record at 3, the chain at 4", 3, "main", 4, lambda t, hw: hw.advance(4), then="high_water")
case("the crash window, another manifest at 4 (only 3 is pinned)", 3, "fork at 4", 4, lambda t, hw: hw.advance(4), then="high_water")
case("the crash window, another chain from 3", 3, "fork at 3", 4, lambda t, hw: hw.advance(4), then="CONFLICT")
case("the record two epochs behind the counter", 3, "main", 5, lambda t, hw: hw.advance(5), then="inconsistent")
for kept in (0, 1, 7, 8, 20, 39, 40, 47):
    case("a record write cut after %d bytes" % kept, 3, "main", 4, torn_advance(kept, 4), then="high_water")
case("both slots holding no valid record", 3, "main", 3, lambda t, hw: (nv(t, SLOTS[0]).__setitem__(1, b"\x00" * 48),
                                                                       nv(t, SLOTS[1]).__setitem__(1, b"\x00" * 48)), then="NO RECORD")
case("one slot never written", 3, "main", 3, redefine(SLOTS[0]), then="high_water")
case("both slots never written", 3, "main", 3, both(redefine(SLOTS[0]), redefine(SLOTS[1])), then="NO RECORD")
case("one slot holding garbage", 3, "main", 3, redefine(SLOTS[1], data=bytes(range(48))), then="high_water")
case("a record slot that is gone", 3, "main", 3, lambda t, hw: t.tpm(["tpm2_nvundefine", SLOTS[1], "-C", "o"]), then="not defined")
case("the counter is gone", 3, "main", 3, lambda t, hw: t.tpm(["tpm2_nvundefine", INDEX, "-C", "o"]), then="not defined")
case("the base is gone", 3, "main", 3, lambda t, hw: t.tpm(["tpm2_nvundefine", "0x1500017", "-C", "o"]), then="not defined")
case("a slot others may write (authwrite)", 3, "main", 3, set_bits(SLOTS[0], add=FakeTpm.BITS["authwrite"]), then="attributes")
case("a slot under a policy (policywrite) with no authPolicy, on a node with none", 3, "main", 3,
     set_bits(SLOTS[1], add=FakeTpm.BITS["policywrite"]), then="approved-image policy")
case("a slot the owner cannot read", 3, "main", 3, set_bits(SLOTS[0], remove=FakeTpm.BITS["ownerread"]), then="attributes")
case("a write-locked slot", 3, "main", 3, set_bits(SLOTS[0], add=FakeTpm.LOCKED), then="write-locked")
case("a slot of 40 bytes", 3, "main", 3, redefine(SLOTS[0], size=40), then="40 bytes")
case("a slot that is a counter", 3, "main", 3, redefine(SLOTS[0], size=8, words="nt=counter|ownerread|ownerwrite|authread"), then="not an ordinary")
case("a counter others may write", 3, "main", 3, set_bits(INDEX, add=FakeTpm.BITS["authwrite"]), then="attributes")
case("a counter that clears at startup", 3, "main", 3, set_bits(INDEX, add=FakeTpm.BITS["clear_stclear"]), then="attributes")
case("a counter never incremented", 3, "main", 3, redefine(INDEX, size=8, words="nt=counter|ownerread|ownerwrite|authread"), then="not a written counter")
case("a base that is not write-locked", 3, "main", 3, set_bits("0x1500017", remove=FakeTpm.LOCKED), then="write-locked")
case("a base others may write", 3, "main", 3, set_bits("0x1500017", add=FakeTpm.BITS["authwrite"]), then="attributes")
# a counter or base of another size than 8 is not this anchor's: Unusable, which a re-anchor repairs (#336)
for label, index, size, words in (("a base of 4 bytes", "0x1500017", 4, "ownerread|ownerwrite|authread|writedefine"),
                                  ("a base of 16 bytes", "0x1500017", 16, "ownerread|ownerwrite|authread|writedefine")):
    case(label, 3, "main", 3, both(redefine(index, size=size, words=words, data=b"\0" * size), set_bits(index, add=FakeTpm.LOCKED)),
         then="is %d bytes, not 8" % size)


def counter_of(size):
    def change(tpm, hw):
        tpm.tpm(["tpm2_nvundefine", INDEX, "-C", "o"])
        tpm.tpm(["tpm2_nvdefine", INDEX, "-C", "o", "-s", str(size), "-a", "nt=counter|ownerread|ownerwrite|authread"])
        tpm.tpm(["tpm2_nvincrement", INDEX, "-C", "o"])
    return change


case("a counter of 16 bytes (FakeTpm only: a TPM refuses it)", 3, "main", 3, counter_of(16), then="is 16 bytes, not 8")
case("the counter below its base", 3, "main", 3, lambda t, hw: nv(t, "0x1500017").__setitem__(1, (10 ** 6).to_bytes(8, "big")), then="below its base")
case("two slots at one epoch naming different manifests", 3, "main", 3,
     lambda t, hw: (nv(t, SLOTS[0]).__setitem__(1, m.HighWater.slot_bytes(3, "aa" * 32)),
                    nv(t, SLOTS[1]).__setitem__(1, m.HighWater.slot_bytes(3, "bb" * 32))), then="different manifests")
# the tag is unkeyed: anyone who can write the TPM can plant a valid record; at 2^64-1 a Go "epoch + 1" wraps to 0
case("a planted record at the highest epoch beside a high-water of 0", 0, "main", 1,
     lambda t, hw: nv(t, SLOTS[0]).__setitem__(1, m.HighWater.slot_bytes(2 ** 64 - 1, m.HighWater.ZERO)), then="high-water is 0")
case("a planted record at the highest epoch beside a high-water of 3", 3, "main", 3,
     lambda t, hw: nv(t, SLOTS[0]).__setitem__(1, m.HighWater.slot_bytes(2 ** 64 - 1, m.HighWater.ZERO)), then="high-water is 3")
case("a slot the TPM describes and does not read", 3, "main", 3, lambda t, hw: t.unreadable.add(SLOTS[1]), then="cannot read 48 bytes")
case("a base the TPM does not read", 3, "main", 3, lambda t, hw: t.unreadable.add("0x1500017"), then="cannot read 8 bytes")
case("an index the TPM lists and does not describe", 3, "main", 3, lambda t, hw: t.public_fails.add(SLOTS[0]), then="did not give it")
case("a TPM that does not answer", 3, "main", 3, lambda t, hw: setattr(t.tpm, "broken", True), then="does not answer")

# #242: the policy-written layout, index by index (B2's definers lay it out; here it is set by hand)
POLICY, OTHER = "a7" * 32, "b8" * 32


def by_policy(*indices, policy=POLICY):
    def change(tpm, hw):
        for index in indices:
            nv(tpm, index)[0] |= FakeTpm.BITS["policywrite"]
            tpm.tpm.policies[index] = policy
    return change


ALL = (INDEX,) + SLOTS
case("a policy-written anchor, this node's policy", 3, "main", 3, by_policy(*ALL), policy=POLICY, then="high_water")
case("a policy-written anchor, the chain ahead", 3, "main", 5, by_policy(*ALL), policy=POLICY, then="high_water")
case("a policy-written anchor, a restored disk", 3, "main", 2, by_policy(*ALL), policy=POLICY, then="ROLLBACK")
case("a policy-written anchor read by a node of another policy", 3, "main", 3, by_policy(*ALL), policy=OTHER, then="approved-image policy")
case("a policy-written anchor read by a node with no policy", 3, "main", 3, by_policy(*ALL), then="none configured")
case("a policy-written slot beside an owner-written one", 3, "main", 3, by_policy(SLOTS[0]), policy=POLICY, then="high_water")
case("a policy-written counter, owner-written slots", 3, "main", 3, by_policy(INDEX), policy=POLICY, then="high_water")
case("a policy-written slot of another policy", 3, "main", 3, both(by_policy(*ALL), by_policy(SLOTS[1], policy=OTHER)), policy=POLICY,
     then="0x150001b is written by policy")
case("a policy-written slot with an empty authPolicy", 3, "main", 3, both(by_policy(*ALL), by_policy(SLOTS[1], policy="")), policy=POLICY,
     then="(none)")
case("a policy-written base", 3, "main", 3, by_policy("0x1500017"), policy=POLICY, then="attributes")
case("an owner-written anchor read by a node with a policy", 3, "main", 3, policy=POLICY, then="high_water")
# #242 B3: under a v4 chain tip the anchor is written by policy only; v1-v3 keep both layouts (the cases above).
# #361 C: and by the anchor-policy authority only: the counter under PolicyAuthorize(Name(K_A), "anchor"), the slots under
# PolicyAuthorize(Name(K_A), "slots"), K_A the tip's anchor_policy_key. The image key's policy is refused (no fallback).
from deploy.baremetal import anchorpolicy  # noqa: E402

K_A = CHAINS["v4"][0]["manifest"]["anchor_policy_key"]["key"]
UNDER_K_A = {INDEX: anchorpolicy.class_policy(K_A, "anchor").hex(), **{s_: anchorpolicy.class_policy(K_A, "slots").hex() for s_ in SLOTS}}


def by_k_a(*indices, wrong_class=()):
    """Each index policy-written under K_A's policy for its class, or for the OTHER class when named in `wrong_class`."""
    swapped = {INDEX: UNDER_K_A[SLOTS[0]], SLOTS[0]: UNDER_K_A[INDEX], SLOTS[1]: UNDER_K_A[INDEX]}

    def change(tpm, hw):
        for index in indices:
            nv(tpm, index)[0] |= FakeTpm.BITS["policywrite"]
            tpm.tpm.policies[index] = swapped[index] if index in wrong_class else UNDER_K_A[index]
    return change


case("a v4 chain, an owner-written anchor", 3, "v4", 3, anchored_on="v4", policy=POLICY, then="is owner-written: under regalia.membership/v4")
case("a v4 chain, an anchor under K_A's classes", 3, "v4", 3, by_k_a(*ALL), anchored_on="v4", then="high_water")
case("a v4 chain ahead of an anchor under K_A's classes", 3, "v4", 5, by_k_a(*ALL), anchored_on="v4", then="high_water")
case("a v4 chain, a restored disk under K_A's classes", 3, "v4", 2, by_k_a(*ALL), anchored_on="v4", then="ROLLBACK")
case("a v4 chain, an anchor under the image key's policy (no fallback)", 3, "v4", 3, by_policy(*ALL), anchored_on="v4", policy=POLICY,
     then="0x1500016 (the anchor class) is not defined under the anchor-policy authority")
case("a v4 chain, a slot under K_A's anchor class", 3, "v4", 3, by_k_a(*ALL, wrong_class=(SLOTS[1],)), anchored_on="v4",
     then="0x150001b (the slots class) is not defined under the anchor-policy authority")
case("a v4 chain, a slot with an empty authPolicy", 3, "v4", 3, both(by_k_a(*ALL), by_policy(SLOTS[0], policy="")), anchored_on="v4",
     then="its authPolicy is (none)")
case("a v4 chain, owner-written slots beside a counter under K_A", 3, "v4", 3, by_k_a(INDEX), anchored_on="v4",
     then="0x150001a is owner-written")

shutil.rmtree(scratch)
print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "root_public": root_pub,
                  "chains": {name: [{"manifest": composed(e["manifest"]), "sig": e["signature"]["sig"]} for e in envs] for name, envs in CHAINS.items()},
                  "cases": cases}, indent=1, sort_keys=True))
