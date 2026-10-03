#!/usr/bin/env python3
"""The TPM high-water anchor as the initrd reads it, decided by the Python: each case is the NV indices a
TPM holds (as membership.HighWater laid them out, driven through tests.test_baremetal_heartbeat.FakeTpm),
a chain from the ESP, and what Store.load decides before it writes anything.

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


CHAINS = {"main": chain(6), "fork at 3": chain(6, fork_at=3), "fork at 4": chain(6, fork_at=4)}


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
            nv[index] = {"attributes": bits, "size": size, "data": None if data is None else data.hex()}
        return {"nv": nv, "broken": self.tpm.broken, "public_fails": sorted(self.public_fails), "unreadable": sorted(self.unreadable)}


def decide(hw, manifests):
    """Store._load before its writes."""
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


def case(name, anchored, chain_name, length, change=None, highest=41, then=None):
    """A TPM anchored through `anchored` epochs of the main chain (define, then anchor() each), changed by
    `change(tpm, hw)`, read against the first `length` epochs of `chain_name`."""
    lock = os.path.join(scratch, "%d.lock" % len(cases))
    tpm = Tpm(highest)
    hw = m.HighWater(INDEX, run=tpm, lock_path=lock)
    hw.define()
    digests = m.Store._digests(manifests_of(CHAINS["main"]))
    for epoch in range(1, anchored + 1):
        hw.anchor(epoch, digests)
    if change:
        change(tpm, hw)
    envelopes = CHAINS[chain_name][:length]
    outcome = decide(hw, manifests_of(envelopes))
    if then:
        assert then in json.dumps(outcome), (name, outcome)
    cases.append({"name": name, "tpm": tpm.state(), "chain": chain_name, "length": length, **outcome})


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
case("a slot under a policy (policywrite)", 3, "main", 3, set_bits(SLOTS[1], add=FakeTpm.BITS["policywrite"]), then="attributes")
case("a slot the owner cannot read", 3, "main", 3, set_bits(SLOTS[0], remove=FakeTpm.BITS["ownerread"]), then="attributes")
case("a write-locked slot", 3, "main", 3, set_bits(SLOTS[0], add=FakeTpm.LOCKED), then="write-locked")
case("a slot of 40 bytes", 3, "main", 3, redefine(SLOTS[0], size=40), then="40 bytes")
case("a slot that is a counter", 3, "main", 3, redefine(SLOTS[0], size=8, words="nt=counter|ownerread|ownerwrite|authread"), then="not an ordinary")
case("a counter others may write", 3, "main", 3, set_bits(INDEX, add=FakeTpm.BITS["authwrite"]), then="attributes")
case("a counter that clears at startup", 3, "main", 3, set_bits(INDEX, add=FakeTpm.BITS["clear_stclear"]), then="attributes")
case("a counter never incremented", 3, "main", 3, redefine(INDEX, size=8, words="nt=counter|ownerread|ownerwrite|authread"), then="not a written counter")
case("a base that is not write-locked", 3, "main", 3, set_bits("0x1500017", remove=FakeTpm.LOCKED), then="write-locked")
case("a base others may write", 3, "main", 3, set_bits("0x1500017", add=FakeTpm.BITS["authwrite"]), then="attributes")
case("a base of 4 bytes", 3, "main", 3, both(redefine("0x1500017", size=4, words="ownerread|ownerwrite|authread|writedefine", data=b"\0" * 4),
                                              set_bits("0x1500017", add=FakeTpm.LOCKED)), then="cannot read 8 bytes")
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

shutil.rmtree(scratch)
print(json.dumps({"about": __doc__.strip().split("\n\n")[0], "root_public": root_pub,
                  "chains": {name: [{"manifest": e["manifest"], "sig": e["signature"]["sig"]} for e in envs] for name, envs in CHAINS.items()},
                  "cases": cases}, indent=1, sort_keys=True))
