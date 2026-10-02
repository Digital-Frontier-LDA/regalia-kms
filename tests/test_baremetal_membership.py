"""deploy/baremetal/membership.py (#68, Phase 8): signed manifests, the capability matrix, root versus
revocation authority, the epoch chain, and the TPM-backed high-water mark with its manifest-digest record
(PoC 8.3 runs on swtpm)."""
import copy
import fcntl
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
from tests.test_baremetal_heartbeat import FakeTpm


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
            "one WG key in two roles, two nodes": lambda e: e["manifest"]["nodes"][1].__setitem__("wg_service_pub", e["manifest"]["nodes"][0]["wg_boot_pub"]),
            "one WG key in two roles, one node": lambda e: e["manifest"]["nodes"][0].__setitem__("wg_service_pub", e["manifest"]["nodes"][0]["wg_boot_pub"]),
            "a malformed revocation key": lambda e: e["manifest"].__setitem__("revocation_keys", [[]]),
            "a duplicated revocation key": lambda e: e["manifest"].__setitem__("revocation_keys", [REVOKE_PUB, REVOKE_PUB]),
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
class _Swtpm(unittest.TestCase):
    """A fresh swtpm per test, with the HighWater defined on it."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        for _ in range(5):                                   # a port taken between free_port() and bind: retry
            port = free_port()
            r = subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d, "--server", "type=tcp,port=%d" % port,
                                "--ctrl", "type=tcp,port=%d" % (port + 1), "--flags", "not-need-init,startup-clear", "--daemon",
                                "--pid", "file=%s/pid" % self.d], capture_output=True)
            if r.returncode == 0:
                break
        else:
            self.fail("swtpm did not start: %s" % r.stderr.decode(errors="replace"))
        with open(self.d + "/pid") as f:
            pid = int(f.read())
        self.addCleanup(os.kill, pid, 15)
        time.sleep(0.5)
        self.tcti = "swtpm:port=%d" % port
        self.env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        self.hw = m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock")
        self.hw.define()


class HighWaterOnSwtpm(_Swtpm):
    """PoC 8.3: accept 50, advance to 51, restore a disk at 50: refused by the TPM high-water mark."""

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
        other = m.HighWater("0x1500030", tcti=self.tcti, lock_path=self.d + "/other.lock")
        other.define()
        other.advance(5)
        for idx in ("0x1500030", "0x1500031", "0x1500034", "0x1500016", "0x1500017", "0x150001a"):
            subprocess.run(["tpm2_nvundefine", idx, "-C", "o"], env=self.env, check=True, capture_output=True)
        fresh = m.HighWater("0x1500016", tcti=self.tcti, lock_path=self.d + "/hw.lock")
        self.assertGreater(fresh.define(), 5)
        self.assertEqual((fresh.value(), fresh.advance(1), fresh.advance(2)), (0, 1, 2))

    def test_a_missing_counter_or_tpm_fails_closed(self):
        # 48's finding: value() used to read 0 on any failure, so check() passed every epoch.
        self.hw.advance(3)
        subprocess.run(["tpm2_nvundefine", "0x1500016", "-C", "o"], env=self.env, check=True, capture_output=True)
        with self.assertRaisesRegex(m.Refused, "fail closed"):
            self.hw.check(1)
        with self.assertRaisesRegex(m.Refused, "fail closed"):
            m.HighWater("0x1500016", tcti="device:/nonexistent/tpmrm0", lock_path=self.d + "/x.lock").check(1)       # no TPM there

    def test_the_base_is_write_once(self):
        r = subprocess.run(["tpm2_nvwrite", "0x1500017", "-C", "o", "-i", "-"], input=b"\0" * 8, env=self.env, capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        with self.assertRaisesRegex(m.Refused, "already exists"):
            self.hw.define()

    def test_a_disk_epoch_ahead_of_the_tpm_is_not_anchored(self):
        self.hw.advance(50)
        with self.assertRaisesRegex(m.Refused, "not anchored"):
            self.hw.check(51)

    def test_advance_waits_for_the_lock(self):
        # Copilot's finding on #93: two unserialized advances could both increment and overshoot. Hold
        # the lock as another process would; the advance must not touch the TPM until it is released.
        import threading
        lock = os.open(self.d + "/hw.lock", os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = []
        worker = threading.Thread(target=lambda: result.append(self.hw.advance(2)))
        worker.start()
        worker.join(3)
        self.assertTrue(worker.is_alive(), "advance did not wait for the lock")
        self.assertEqual(self.hw.value(), 0)
        fcntl.flock(lock, fcntl.LOCK_UN)
        worker.join(60)
        self.assertEqual((result, self.hw.value()), ([2], 2))

    def test_an_anomalous_jump_is_refused(self):
        with self.assertRaisesRegex(m.Refused, "anomaly"):
            self.hw.advance(m.HighWater.MAX_JUMP + 5)

    def nv(self, *argv, **kw):
        return subprocess.run(["tpm2_" + argv[0], *argv[1:]], env=self.env, capture_output=True, **kw)

    def test_define_creates_the_record_at_epoch_0_with_a_zero_digest(self):
        self.assertEqual((self.hw.record_index, self.hw.record(), self.hw.pinned()), ("0x150001a", (0, "00" * 32), True))
        public = self.nv("nvreadpublic", "0x150001a").stdout.decode()
        self.assertRegex(public, r"size: 40\b")
        self.assertRegex(public, r"value: 0x20060006\b")                 # ordinary, owner/auth read and write, written
        self.assertEqual(self.hw.verify(lambda epoch: "00" * 32), 0)
        # a counter without a record (the heartbeat's) defines no third index, and has none to read
        class Plain(m.HighWater):
            RECORD = False
        plain = Plain("0x1500030", tcti=self.tcti, lock_path=self.d + "/plain.lock")
        plain.define()
        self.assertEqual((plain.record_index, plain.advance(2)), (None, 2))
        self.assertNotEqual(self.nv("nvreadpublic", "0x1500034").returncode, 0)
        with self.assertRaisesRegex(m.Refused, "this counter keeps no record"):
            plain.record()

    def test_define_refuses_a_record_index_that_exists(self):
        self.assertEqual(self.nv("nvdefine", "0x1500034", "-C", "o", "-s", "40").returncode, 0)
        other = m.HighWater("0x1500030", tcti=self.tcti, lock_path=self.d + "/other.lock")
        with self.assertRaisesRegex(m.Refused, "NV index 0x1500034 already exists"):
            other.define()
        self.assertNotEqual(self.nv("nvreadpublic", "0x1500030").returncode, 0)     # refused before anything was defined

    def test_a_record_that_cannot_be_read_fails_closed(self):
        zero = lambda epoch: "00" * 32
        cases = (
            ("missing", (), "cannot read NV index 0x150001a: the high-water anchor is unavailable \\(fail closed\\)"),
            ("defined and never written", (("nvdefine", "0x150001a", "-C", "o", "-s", "40", "-a", "ownerread|ownerwrite|authread|authwrite"),),
             "record index 0x150001a is not a written ordinary index"),
            ("a counter", (("nvdefine", "0x150001a", "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread|authwrite"),
                           ("nvincrement", "0x150001a", "-C", "o")), "record index 0x150001a is not a written ordinary index"),
            ("too short", (("nvdefine", "0x150001a", "-C", "o", "-s", "8", "-a", "ownerread|ownerwrite|authread|authwrite"),
                           ("nvwrite", "0x150001a", "-C", "o", "-i", "-")), "cannot read 40 bytes from the record index 0x150001a"),
        )
        for label, commands, reason in cases:
            with self.subTest(label):
                self.nv("nvundefine", "0x150001a", "-C", "o")
                self.assertNotEqual(self.nv("nvreadpublic", "0x150001a").returncode, 0)
                for argv in commands:
                    self.assertEqual(self.nv(*argv, input=b"\0" * 8 if argv[0] == "nvwrite" else None).returncode, 0, argv)
                for call in (self.hw.record, self.hw.pinned, lambda: self.hw.verify(zero), lambda: self.hw.anchor(1, zero)):
                    with self.assertRaisesRegex(m.Refused, reason):
                        call()
                self.assertEqual(self.hw.value(), 0)                     # and the counter did not move


class RecordWrites(unittest.TestCase):
    """What the TPM can refuse or get wrong when the record is written (a TPM that says no cannot be had
    from swtpm on demand: FakeTpm)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.calls = []

    def run_tpm(self, argv, **kw):
        self.calls.append(argv[0])
        verdict = self.fault(argv)
        if isinstance(verdict, bytes):                       # the tool succeeds and prints this
            return subprocess.CompletedProcess(argv, 0, verdict, b"")
        if verdict is not None:
            return subprocess.CompletedProcess(argv, verdict, b"", b"")
        return self.tpm(argv, **kw)

    def anchor(self):
        return m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.run_tpm)

    def test_a_record_index_that_cannot_be_defined(self):
        self.fault = lambda argv: 1 if argv[:2] == ["tpm2_nvdefine", "0x150001a"] else None
        with self.assertRaisesRegex(m.Refused, "cannot define the record index 0x150001a"):
            self.anchor().define()

    def test_a_record_write_the_tpm_refuses(self):
        self.fault = lambda argv: None
        hw = self.anchor()
        hw.define()
        self.fault = lambda argv: 1 if argv[:2] == ["tpm2_nvwrite", "0x150001a"] else None
        with self.assertRaisesRegex(m.Refused, "cannot write the record index 0x150001a"):
            hw.anchor(1, lambda epoch: "ab" * 32 if epoch else "00" * 32)
        self.assertEqual((hw.value(), hw.record(), hw.pinned()), (1, (0, "00" * 32), False))     # the crash window, as left

    def test_a_record_write_that_does_not_take(self):
        self.fault = lambda argv: None
        hw = self.anchor()
        hw.define()
        self.fault = lambda argv: 0 if argv[:2] == ["tpm2_nvwrite", "0x150001a"] else None      # says yes, stores nothing
        with self.assertRaisesRegex(m.Refused, "the record index 0x150001a did not take the write"):
            hw.anchor(1, lambda epoch: "ab" * 32 if epoch else "00" * 32)

    def test_a_record_read_of_another_length_is_refused(self):
        # tpm2_nvread -s 40 gives 40 bytes or fails; a tool that gave fewer or more must not be parsed as a record
        self.fault = lambda argv: None
        hw = self.anchor()
        hw.define()
        for out in (b"", b"\0" * 39, b"\0" * 41):
            self.fault = lambda argv: out if argv[:2] == ["tpm2_nvread", "0x150001a"] else None
            for call in (hw.record, hw.pinned, lambda: hw.verify(lambda epoch: "00" * 32), lambda: hw.anchor(1, lambda epoch: "00" * 32)):
                with self.subTest(length=len(out)), self.assertRaisesRegex(m.Refused, "cannot read 40 bytes from the record index 0x150001a"):
                    call()
        self.fault = lambda argv: None
        self.assertEqual((hw.value(), hw.record()), (0, (0, "00" * 32)))

    def test_a_digest_that_is_not_one_is_never_written(self):
        self.fault = lambda argv: None
        hw = self.anchor()
        hw.define()
        del self.calls[:]
        for bad in ("AB" * 32, "ab" * 31, None, b"\0" * 32):
            with self.subTest(bad=bad), self.assertRaisesRegex(m.Refused, "a manifest digest must be 64 lowercase hex"):
                hw._write_record(1, bad)
        self.assertNotIn("tpm2_nvwrite", self.calls)

    def test_the_order_is_counter_then_record_for_every_epoch(self):
        self.fault = lambda argv: None
        hw = self.anchor()
        hw.define()
        del self.calls[:]
        self.assertEqual(hw.anchor(3, lambda epoch: "%02x" % epoch * 32), 3)
        self.assertEqual([c[len("tpm2_"):] for c in self.calls if c in ("tpm2_nvincrement", "tpm2_nvwrite")], ["nvincrement", "nvwrite"] * 3)
        self.assertEqual((hw.record(), hw.pinned()), ((3, "03" * 32), True))


class StoreOnSwtpm(_Swtpm):
    """The persisted-state API: the chain on disk anchored to the TPM (PoC 8.3 through Store)."""

    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.d, "membership.json")
        self.store = m.Store(self.path, ROOT_PUB, self.hw)
        self.envs, cur = [], None
        for e in range(1, 5):
            env = sign(manifest(e, m.digest(cur) if cur else "", three(a="DRAINING" if e % 2 else "ACTIVE")), ROOT)
            cur = m.accept(cur, env, ROOT_PUB)
            self.envs.append(env)

    def test_commit_load_and_a_restored_file_is_refused(self):
        self.assertIsNone(self.store.load())
        for env in self.envs[:2]:
            self.store.commit(env)
        snapshot = open(self.path, "rb").read()                  # the disk at epoch 2
        self.store.commit(self.envs[2])
        self.assertEqual((m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], self.hw.value()), (3, 3))
        self.assertIs(self.store.commit(self.envs[2])["epoch"], 3)   # re-delivery: nothing changes
        with open(self.path, "wb") as f:
            f.write(snapshot)
        with self.assertRaisesRegex(m.Refused, "ROLLBACK"):
            m.Store(self.path, ROOT_PUB, self.hw).load()
        os.unlink(self.path)                                      # a deleted file is a rollback to nothing
        with self.assertRaisesRegex(m.Refused, "ROLLBACK"):
            m.Store(self.path, ROOT_PUB, self.hw).load()

    def test_a_second_writer_at_the_same_epoch_gets_a_conflict(self):
        self.store.commit(self.envs[0])
        self.store.commit(self.envs[1])
        rival = sign(manifest(2, m.digest(self.envs[0]["manifest"]), three(c="RETIRED")), ROOT)
        with self.assertRaisesRegex(m.Refused, "CONFLICT"):
            m.Store(self.path, ROOT_PUB, self.hw).commit(rival)       # another process, after the lock
        self.assertEqual((m.Store(self.path, ROOT_PUB, self.hw).load(), self.hw.value()), (self.envs[1]["manifest"], 2))

    def test_a_crash_after_the_disk_write_is_completed_by_load(self):
        for env in self.envs[:2]:
            self.store.commit(env)
        self.store._write(self.envs[:3])                          # written, then the TPM never advanced
        self.assertEqual((self.hw.value(), self.hw.record()), (2, (2, self.digest(2))))
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], 3)
        self.assertEqual((self.hw.value(), self.hw.record()), (3, (3, self.digest(3))))     # the counter, then the record

    def digest(self, epoch):
        return m.digest(self.envs[epoch - 1]["manifest"])

    def rivals(self, upto):
        """A second validly signed chain that leaves the real one after epoch 1: what a key that signed twice
        for one epoch makes possible. Same length, same signer, every link verifies."""
        chain, cur = [self.envs[0]], self.envs[0]["manifest"]
        for e in range(2, upto + 1):
            env = sign(manifest(e, m.digest(cur), three(c="QUARANTINED")), ROOT)
            cur = m.accept(cur, env, ROOT_PUB)
            chain.append(env)
        return chain

    def put(self, chain):
        with open(self.path, "wb") as f:
            f.write(m.canonical(chain))

    def test_every_commit_records_the_manifest_it_anchored(self):
        self.assertEqual(self.hw.record(), (0, "00" * 32))
        for epoch, env in enumerate(self.envs, 1):
            self.store.commit(env)
            self.assertEqual((self.hw.value(), self.hw.record(), self.store.pinned()), (epoch, (epoch, self.digest(epoch)), True))

    def test_a_same_length_substituted_chain_is_refused_by_load(self):
        for env in self.envs[:3]:
            self.store.commit(env)
        rival = self.rivals(3)
        self.assertEqual(m.accept_chain(None, rival, ROOT_PUB)["epoch"], 3)       # valid by itself, and as long as the real one
        self.put(rival)
        fresh = m.Store(self.path, ROOT_PUB, self.hw)
        for call in (fresh.load, fresh.envelopes):
            with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 3 is not the one this node's TPM recorded"):
                call()
        with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 3"):
            fresh.commit(sign(manifest(4, m.digest(rival[-1]["manifest"]), three()), ROOT))     # nothing is built on it either
        # nor a LONGER substituted chain: it is the anchored epoch that is compared, and nothing above it is anchored
        self.put(self.rivals(4))
        with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 3"):
            fresh.load()
        self.assertEqual((self.hw.value(), self.hw.record()), (3, (3, self.digest(3))))
        self.put(self.envs[:3])                                                  # the real chain is still accepted
        self.assertEqual(fresh.load()["epoch"], 3)

    def test_a_crash_after_the_counter_and_before_the_record_is_repaired(self):
        for env in self.envs[:2]:
            self.store.commit(env)
        self.store._write(self.envs[:3])
        self.hw.advance(3)                                                       # the counter moved; the record was never written
        self.assertEqual((self.hw.value(), self.hw.record(), self.store.pinned()), (3, (2, self.digest(2)), False))
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], 3)
        self.assertEqual((self.hw.value(), self.hw.record(), self.store.pinned()), (3, (3, self.digest(3)), True))

    def test_in_the_crash_window_a_substituted_chain_is_still_refused(self):
        for env in self.envs[:2]:
            self.store.commit(env)
        self.store._write(self.envs[:3])
        self.hw.advance(3)
        self.put(self.rivals(3))                                                 # differs at epoch 2, which the record names
        with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 2 is not the one this node's TPM recorded"):
            m.Store(self.path, ROOT_PUB, self.hw).load()
        self.assertEqual(self.hw.record(), (2, self.digest(2)))                  # and the record was not repaired onto it
        self.put(self.envs[:2])                                                  # the disk from before the write: a rollback
        with self.assertRaisesRegex(m.Refused, "ROLLBACK: the membership on disk is epoch 2 but the TPM high-water is 3"):
            m.Store(self.path, ROOT_PUB, self.hw).load()
        self.assertEqual(self.hw.record(), (2, self.digest(2)))

    def test_a_record_for_any_other_epoch_fails_closed(self):
        self.store.commit(self.envs[0])
        self.store._write(self.envs[:3])
        self.hw.advance(3)                                                       # two epochs past the record: no crash leaves this
        for call in (m.Store(self.path, ROOT_PUB, self.hw).load, lambda: self.store.restore(self.envs[:3])):
            with self.assertRaisesRegex(m.Refused, "the TPM record is for epoch 1 but the TPM high-water is 3: the anchor is inconsistent"):
                call()
        self.assertEqual(self.hw.record(), (1, self.digest(1)))
        # and a record AHEAD of the counter: written with owner authorization, by something that is not Store
        ahead = (9).to_bytes(8, "big") + bytes.fromhex(self.digest(3))
        subprocess.run(["tpm2_nvwrite", "0x150001a", "-C", "o", "-i", "-"], input=ahead, env=self.env, check=True, capture_output=True)
        with self.assertRaisesRegex(m.Refused, "the TPM record is for epoch 9 but the TPM high-water is 3"):
            m.Store(self.path, ROOT_PUB, self.hw).load()

    def test_restore_from_one_source_is_accepted_when_it_matches_the_record(self):
        for env in self.envs[:3]:
            self.store.commit(env)
        for label, lose in (("the file is lost", lambda: os.unlink(self.path)), ("the disk is rolled back", lambda: self.put(self.envs[:1]))):
            with self.subTest(label):
                lose()
                fresh = m.Store(self.path, ROOT_PUB, self.hw)
                with self.assertRaisesRegex(m.Refused, "ROLLBACK"):
                    fresh.load()
                self.assertEqual(fresh.restore(self.envs[:3])["epoch"], 3)
                self.assertEqual((fresh.load()["epoch"], self.hw.value(), self.hw.record()), (3, 3, (3, self.digest(3))))
        os.unlink(self.path)                                                     # and a longer one that passes through the record
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).restore(self.envs)["epoch"], 4)
        self.assertEqual((self.hw.value(), self.hw.record()), (4, (4, self.digest(4))))

    def test_restore_from_one_source_is_refused_when_it_diverges_from_the_record(self):
        for env in self.envs[:3]:
            self.store.commit(env)
        os.unlink(self.path)
        fresh = m.Store(self.path, ROOT_PUB, self.hw)
        for label, chain in (("the same length", self.rivals(3)), ("longer", self.rivals(4))):
            with self.subTest(label):
                with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 3 is not the one this node's TPM recorded"):
                    fresh.restore(chain)
                self.assertFalse(os.path.exists(self.path))                      # refused before anything was written
                self.assertEqual((self.hw.value(), self.hw.record()), (3, (3, self.digest(3))))

    def test_restore_in_the_crash_window_matches_the_epoch_below_and_repairs(self):
        for env in self.envs[:2]:
            self.store.commit(env)
        self.hw.advance(3)                                                       # counter at 3, record at 2
        fresh = m.Store(self.path, ROOT_PUB, self.hw)
        os.unlink(self.path)
        with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 2 is not the one this node's TPM recorded"):
            fresh.restore(self.rivals(3))
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual((self.hw.record(), fresh.pinned()), ((2, self.digest(2)), False))      # a refusal repairs nothing
        self.assertEqual(fresh.restore(self.envs[:3])["epoch"], 3)
        self.assertEqual((self.hw.value(), self.hw.record(), fresh.pinned()), (3, (3, self.digest(3)), True))

    def test_a_restore_refused_after_the_record_check_repairs_nothing(self):
        """The crash window, with the disk intact through epoch 3. A fetched chain that matches the record
        at epoch 2 and forks at epoch 3 passes the record check and is refused by the disk. The check must
        not have written the fork's epoch 3 into the record on the way."""
        for env in self.envs[:2]:
            self.store.commit(env)
        self.store._write(self.envs[:3])
        self.hw.advance(3)
        fork3 = sign(manifest(3, self.digest(2), three(c="QUARANTINED")), ROOT)
        with self.assertRaisesRegex(m.Refused, "CONFLICT: the fetched chain differs from the stored one at epoch 3"):
            m.Store(self.path, ROOT_PUB, self.hw).restore(self.envs[:2] + [fork3])
        self.assertEqual(self.hw.record(), (2, self.digest(2)))
        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), m.canonical(self.envs[:3]))
        self.assertEqual((self.hw.verify(self.digest), self.hw.record()), (3, (2, self.digest(2))))     # verify() changes nothing
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], 3)
        self.assertEqual(self.hw.record(), (3, self.digest(3)))                  # the disk's epoch 3, by load()

    def interrupted_restore(self, counter_too):
        """restore() wrote epochs 1-4 over a node at epoch 1 and stopped part-way through anchoring them:
        after the record for epoch 2, or after the counter for epoch 3 as well."""
        self.store.commit(self.envs[0])
        self.store._write(self.envs)
        self.hw.anchor(2, self.digest)
        if counter_too:
            self.hw.advance(3)
        self.assertEqual((self.hw.value(), self.hw.record()), (3 if counter_too else 2, (2, self.digest(2))))
        self.assertEqual(m.Store(self.path, ROOT_PUB, self.hw).load()["epoch"], 4)
        self.assertEqual((self.hw.value(), self.hw.record()), (4, (4, self.digest(4))))

    def test_a_restore_interrupted_after_a_record_is_completed_by_load(self):
        self.interrupted_restore(counter_too=False)

    def test_a_restore_interrupted_after_a_counter_is_completed_by_load(self):
        self.interrupted_restore(counter_too=True)

    def test_a_tampered_or_unsigned_chain_is_refused_and_does_not_move_the_tpm(self):
        self.store.commit(self.envs[0])
        forged = copy.deepcopy(self.envs[:2])
        forged[1]["manifest"]["nodes"][0]["state"] = "QUARANTINED"
        stranger = sign(manifest(2, m.digest(self.envs[0]["manifest"]), three()), STRANGER)
        for label, chain in (("altered", forged), ("stranger-signed", [self.envs[0], stranger]),
                             ("repeated", [self.envs[0], self.envs[0]]), ("not a list", {"a": 1})):
            with self.subTest(label):
                with open(self.path, "wb") as f:
                    f.write(m.canonical(chain))
                with self.assertRaises(m.Refused):
                    m.Store(self.path, ROOT_PUB, self.hw).load()
                self.assertEqual(self.hw.value(), 1)


if __name__ == "__main__":
    unittest.main()
