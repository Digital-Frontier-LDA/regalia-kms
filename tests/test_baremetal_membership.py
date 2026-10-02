"""deploy/baremetal/membership.py (#68, Phase 8): signed manifests, the capability matrix, root versus
revocation authority, the epoch chain, and the TPM-backed high-water mark (PoC 8.3 runs on swtpm)."""
import copy
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import membership as m


def raw_pub(priv):
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def node(nid, state="ACTIVE", n=0):
    h = lambda tag, size: (("%02x" % (n + 1)) * size)[:size] if tag == "x" else (tag * size)[:size]
    return {"node_id": nid, "state": state, "ek_name": "000b" + ("%02x" % (0x10 + n)) * 32,
            "ak_name": "000b" + ("%02x" % (0x40 + n)) * 32, "wg_boot_pub": ("%02x" % (0x70 + n)) * 32,
            "wg_service_pub": ("%02x" % (0xa0 + n)) * 32, "hsm_serials": ["DENK04041%02d" % n]}


ROOT = Ed25519PrivateKey.generate()
REVOKE = Ed25519PrivateKey.generate()
STRANGER = Ed25519PrivateKey.generate()
ROOT_PUB, REVOKE_PUB = raw_pub(ROOT), raw_pub(REVOKE)


def manifest(epoch, prev, nodes, policy="p1", keys=None):
    return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": policy,
            "issued_at": "2026-10-02T09:00:00Z", "revocation_keys": [REVOKE_PUB] if keys is None else keys,
            "nodes": nodes}


def sign(man, key, signer="root"):
    return {"manifest": man, "signature": {"signer": signer, "key": raw_pub(key),
                                           "sig": key.sign(m.DOMAIN + m.canonical(man)).hex()}}


def three(**states):
    return [node(n, states.get(n, "ACTIVE"), i) for i, n in enumerate(("a", "b", "c"))]


class Manifests(unittest.TestCase):
    def setUp(self):
        self.m1 = m.accept(None, sign(manifest(1, "", three()), ROOT), ROOT_PUB)

    def test_poc_8_1_a_signed_manifest_is_accepted(self):
        self.assertEqual(self.m1["epoch"], 1)
        self.assertTrue(m.may(self.m1, "a", "serve"))

    def test_poc_8_2_refusals(self):
        good = sign(manifest(2, m.digest(self.m1), three()), ROOT)
        cases = {
            "corrupted signature": lambda e: e["signature"].__setitem__("sig", "00" * 64),
            "unknown signer key": lambda e: e.update(sign(e["manifest"], STRANGER)),
            "malformed state": lambda e: e["manifest"]["nodes"][0].__setitem__("state", "ACTIV"),
            "duplicate node id": lambda e: e["manifest"]["nodes"][1].__setitem__("node_id", "a"),
            "shared identity": lambda e: e["manifest"]["nodes"][1].__setitem__("ak_name", e["manifest"]["nodes"][0]["ak_name"]),
            "unknown field": lambda e: e["manifest"].__setitem__("extra", 1),
        }
        for label, breakit in cases.items():
            with self.subTest(label):
                env = copy.deepcopy(good)
                breakit(env)
                with self.assertRaises(m.Refused):
                    m.accept(self.m1, env, ROOT_PUB)

    def test_ambiguous_encodings_are_refused_at_parse(self):
        for raw in ('{"a": 1, "a": 2}', '{"epoch": 1.0}', '{"epoch": NaN}'):
            with self.subTest(raw=raw), self.assertRaises(m.Refused):
                m.load(raw)

    def test_poc_8_4_maintenance_requests_only(self):
        m2 = m.accept(self.m1, sign(manifest(2, m.digest(self.m1), three(a="MAINTENANCE")), REVOKE, "revocation"), ROOT_PUB)
        self.assertEqual((m.may(m2, "a", "request"), m.may(m2, "a", "authorize"), m.may(m2, "a", "serve")), (True, False, False))

    def test_poc_8_5_retired_gets_nothing(self):
        m2 = m.accept(self.m1, sign(manifest(2, m.digest(self.m1), three(c="RETIRED")), REVOKE, "revocation"), ROOT_PUB)
        self.assertFalse(any(m.may(m2, "c", a) for a in ("serve", "request", "authorize")))

    def test_the_state_matrix(self):
        expect = {"ACTIVE": (True, True, True), "MAINTENANCE": (False, True, False), "DRAINING": (True, False, False),
                  "QUARANTINED": (False, False, False), "RETIRED": (False, False, False), "REVOKED_STOLEN": (False, False, False)}
        for state, caps in expect.items():
            with self.subTest(state):
                man = manifest(1, "", three(a=state))
                self.assertEqual(tuple(m.may(man, "a", x) for x in ("serve", "request", "authorize")), caps)

    def test_revocation_authority_is_restrictive_only(self):
        m2 = m.accept(self.m1, sign(manifest(2, m.digest(self.m1), three(b="QUARANTINED")), REVOKE, "revocation"), ROOT_PUB)
        widen = sign(manifest(3, m.digest(m2), three()), REVOKE, "revocation")              # QUARANTINED -> ACTIVE
        with self.assertRaises(m.Refused):
            m.accept(m2, widen, ROOT_PUB)
        self.assertEqual(m.accept(m2, sign(manifest(3, m.digest(m2), three()), ROOT), ROOT_PUB)["epoch"], 3)  # root may
        for label, man in (("add a node", manifest(3, m.digest(m2), three(b="QUARANTINED") + [node("d", n=3)])),
                           ("change an identity", manifest(3, m.digest(m2), [dict(three(b="QUARANTINED")[0], ak_name="000b" + "ee" * 32)] + three(b="QUARANTINED")[1:])),
                           ("change the keys", manifest(3, m.digest(m2), three(b="QUARANTINED"), keys=[raw_pub(STRANGER)]))):
            with self.subTest(label), self.assertRaises(m.Refused):
                m.accept(m2, sign(man, REVOKE, "revocation"), ROOT_PUB)

    def test_a_revocation_key_must_be_named_by_the_current_manifest(self):
        m2 = m.accept(self.m1, sign(manifest(2, m.digest(self.m1), three(), keys=[]), ROOT), ROOT_PUB)   # root drops it
        with self.assertRaises(m.Refused):
            m.accept(m2, sign(manifest(3, m.digest(m2), three(a="RETIRED"), keys=[]), REVOKE, "revocation"), ROOT_PUB)

    def test_chain_conflict_and_catch_up(self):
        e2 = sign(manifest(2, m.digest(self.m1), three(a="DRAINING")), ROOT)
        m2 = m.accept(self.m1, e2, ROOT_PUB)
        self.assertIs(m.accept(m2, e2, ROOT_PUB), m2)                                   # re-delivery: no change
        other = sign(manifest(2, m.digest(self.m1), three(b="DRAINING")), ROOT)
        with self.assertRaisesRegex(m.Refused, "CONFLICT"):
            m.accept(m2, other, ROOT_PUB)
        e3 = sign(manifest(3, m.digest(m2), three()), ROOT)
        with self.assertRaisesRegex(m.Refused, "does not follow"):
            m.accept(self.m1, e3, ROOT_PUB)                                               # missed epoch 2
        self.assertEqual(m.accept_chain(self.m1, [e2, e3], ROOT_PUB)["epoch"], 3)         # catches up in order
        with self.assertRaises(m.Refused):
            m.accept(m2, sign(manifest(3, "00" * 32, three()), ROOT), ROOT_PUB)            # broken prev_digest

    def test_first_manifest_must_be_root_epoch_1(self):
        with self.assertRaises(m.Refused):
            m.accept(None, sign(manifest(1, "", three()), REVOKE, "revocation"), ROOT_PUB)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_nvdefine"), "needs swtpm and tpm2-tools")
class HighWaterOnSwtpm(unittest.TestCase):
    """PoC 8.3: accept 50, advance to 51, restore a disk at 50: refused by the TPM high-water mark."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        port = free_port()
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d, "--server", "type=tcp,port=%d" % port,
                        "--ctrl", "type=tcp,port=%d" % (port + 1), "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=%s/pid" % self.d], check=True, capture_output=True)
        self.addCleanup(lambda: os.kill(int(open(self.d + "/pid").read()), 15))
        time.sleep(0.5)
        self.tcti = "swtpm:port=%d" % port
        self.env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        self.hw = m.HighWater("0x1500016", tcti=self.tcti)
        self.hw.define()

    def test_rollback_of_the_disk_is_refused(self):
        self.assertEqual(self.hw.advance(50), 50)
        self.assertEqual(self.hw.check(50), 50)
        self.assertEqual(self.hw.advance(51), 51)
        with self.assertRaisesRegex(m.Refused, "ROLLBACK"):
            self.hw.check(50)                         # the disk restored to the epoch-50 manifest
        with self.assertRaises(m.Refused):
            self.hw.advance(50)                       # and the TPM will not accept going back
        self.assertEqual(self.hw.check(51), 51)

    def test_a_crash_between_advance_and_disk_write_is_caught(self):
        self.hw.advance(7)                            # the counter moved; the disk still holds epoch 6
        with self.assertRaisesRegex(m.Refused, "ROLLBACK"):
            self.hw.check(6)

    def test_a_tpm_that_already_had_counters_starts_at_epoch_0(self):
        # 48's finding: a new counter's first increment lands above any deleted counter's value.
        other = m.HighWater("0x1500030", tcti=self.tcti)
        other.define()
        other.advance(5)
        for idx in ("0x1500030", "0x1500031", "0x1500016", "0x1500017"):
            subprocess.run(["tpm2_nvundefine", idx, "-C", "o"], env=self.env, check=True, capture_output=True)
        fresh = m.HighWater("0x1500016", tcti=self.tcti)
        self.assertGreater(fresh.define(), 5)
        self.assertEqual((fresh.value(), fresh.advance(1), fresh.advance(2)), (0, 1, 2))

    def test_a_missing_counter_or_tpm_fails_closed(self):
        # 48's finding: value() used to read 0 on any failure, so check() passed every epoch.
        self.hw.advance(3)
        subprocess.run(["tpm2_nvundefine", "0x1500016", "-C", "o"], env=self.env, check=True, capture_output=True)
        with self.assertRaisesRegex(m.Refused, "fail closed"):
            self.hw.check(1)
        with self.assertRaisesRegex(m.Refused, "fail closed"):
            m.HighWater("0x1500016", tcti="device:/nonexistent/tpmrm0").check(1)       # no TPM there

    def test_the_base_is_write_once(self):
        r = subprocess.run(["tpm2_nvwrite", "0x1500017", "-C", "o", "-i", "-"], input=b"\0" * 8, env=self.env, capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        with self.assertRaisesRegex(m.Refused, "already exists"):
            self.hw.define()

    def test_an_anomalous_jump_is_refused(self):
        with self.assertRaisesRegex(m.Refused, "anomaly"):
            self.hw.advance(m.HighWater.MAX_JUMP + 5)


if __name__ == "__main__":
    unittest.main()
