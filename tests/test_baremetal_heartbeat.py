"""deploy/baremetal/heartbeat.py (#69, Phase 9): a peer authorizes only while it holds a live heartbeat for
its current manifest, judged against authenticated time, with the sequence in a TPM NV counter.

The first classes run with the TPM faked at the tpm2-tools boundary (so Counter's own code runs); the last
runs the same rollback and replay cases on swtpm."""
import contextlib
import copy
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m

T0 = 1790000000   # 2026-09-21T13:33:20Z
ROOT, REVOKE, OTHER = (Ed25519PrivateKey.generate() for _ in range(3))


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def stamp(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def node(nid, state, n):
    return {"node_id": nid, "state": state, "ek_name": "000b" + ("%02x" % (0x10 + n)) * 32,
            "ak_name": "000b" + ("%02x" % (0x40 + n)) * 32, "wg_boot_pub": ("%02x" % (0x70 + n)) * 32,
            "wg_service_pub": ("%02x" % (0xa0 + n)) * 32, "hsm_serials": ["DENK04041%02d" % n]}


def manifest(epoch=1, prev="", keys=None, **states):
    return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": "p1",
            "issued_at": "2026-09-21T09:00:00Z", "revocation_keys": [pub(REVOKE)] if keys is None else keys,
            "nodes": [node(n, states.get(n, "ACTIVE"), i) for i, n in enumerate(("a", "b", "c"))]}


def beat(man, sequence, issued=T0, lifetime=hb.MAX_LIFETIME, key=REVOKE, domain=hb.DOMAIN, **override):
    body = {"schema": hb.SCHEMA, "epoch": man["epoch"], "sequence": sequence, "issued_at": stamp(issued),
            "expires_at": stamp(issued + lifetime), "manifest_digest": m.digest(man)}
    body.update(override)
    return {"heartbeat": body, "signature": {"key": pub(key), "sig": key.sign(domain + m.canonical(body)).hex()}}


def simulated_ticks(test, tcti):
    """The TPM clock for a swtpm test whose wall clock (`test.now`) is simulated. The real TPM is read on
    every call, so TpmClock runs against swtpm; the value handed on is the test's own time in milliseconds.
    Feeding the real TPM's elapsed time to a clock that stands still makes the time floor depend on how
    long the test took: past about six seconds it refuses "the clock went backwards"."""
    real = hb.TpmClock(tcti=tcti)
    return lambda: (real(), int((test.now - T0 + 10 ** 6) * 1000))[1]


class FakeTpm:
    """tpm2-tools as HighWater calls them: NV indices with the real rules. A counter's first increment
    lands above the highest value any counter on this TPM ever held; a write-locked index refuses writes.
    A counter's value is an integer; an ordinary index holds bytes, at most the size it was defined with."""
    COUNTER, WRITTEN, LOCKED = 0x10, 0x20000000, 0x800
    BITS = {"ownerwrite": 0x2, "authwrite": 0x4, "policywrite": 0x8, "ppwrite": 0x1, "writedefine": 0x2000, "ownerread": 0x20000, "authread": 0x40000,
            "no_da": 0x2000000, "orderly": 0x4000000, "clear_stclear": 0x8000000}

    def __init__(self, highest=0, owner_auth=None):
        self.nv, self.highest, self.broken = {}, highest, False
        self.policies = {}                                   # index -> authPolicy (hex), for an index defined with one (-L)
        # the owner authorization (32 bytes, #242 C), None while it is empty. Set, an owner call (-C o) must give it as
        # the real channel does (-P file:/dev/fd/N, the pipe holding "hex:<64 hex>"), else the TPM says no
        self.owner_auth, self.lockout_set = owner_auth, False
        self.da = [0, 3, 1000]                               # counter, max, recovery s (swtpm's defaults)
        self.persistent = {"0x81000001"}                     # systemd's SRK, as systemd-tpm2-setup leaves it at boot
        # the node's EK at 0x81010001 (enrol init), by its Name; sessions salted to it (#414), and the changeauth calls
        # made through one (salted_with: the EK each changeauth's session was salted to, None for none)
        self.ek_name, self.sessions, self.salted_with = bytes.fromhex("000b" + "e5" * 32), {}, []

    @staticmethod
    def _from_fd(where, kw):
        """What an auth argument names through the channel (a passed pipe fd), or None for anything else (a value on argv)."""
        if not isinstance(where, str) or not where.startswith("file:/dev/fd/"):
            return None
        fd = int(where[len("file:/dev/fd/"):])
        return os.read(fd, 200) if fd in kw.get("pass_fds", ()) else None

    def _held(self):
        return None if self.owner_auth is None else b"hex:" + self.owner_auth.hex().encode()

    def _owner_ok(self, argv, kw):
        """An owner-authorized call carries the authorization the TPM holds, through the channel (none while it is empty)."""
        if "-P" not in argv:
            return self.owner_auth is None
        return self._held() is not None and self._from_fd(argv[argv.index("-P") + 1], kw) == self._held()

    def __call__(self, argv, input=None, **kw):
        tool, index = argv[0][len("tpm2_"):], argv[1]
        ok = lambda out=b"": subprocess.CompletedProcess(argv, 0, out, b"")
        no = subprocess.CompletedProcess(argv, 1, b"", b"the TPM said no")
        # what tpm2-tools prints for a wrong authorization (TPM_RC_BAD_AUTH, session 1), as on swtpm
        bad_auth = subprocess.CompletedProcess(argv, 1, b"", b"ERROR: Esys_HierarchyChangeAuth(0x9A2) - tpm:session(1):"
                                               b"authorization failure without DA implications")
        if self.broken:
            return no
        if tool == "getcap" and index == "properties-variable":
            # the dictionary-attack state as swtpm prints it (#456): TPM2_PT_LOCKOUT_COUNTER, _MAX_AUTH_FAIL, _RECOVERY
            return ok(("TPM2_PT_LOCKOUT_COUNTER: 0x%x\nTPM2_PT_MAX_AUTH_FAIL: 0x%x\nTPM2_PT_LOCKOUT_RECOVERY: 0x%x\n" % tuple(self.da)
                       + "TPM2_PT_PERMANENT:\n  ownerAuthSet:              %d\n  endorsementAuthSet:        0\n  lockoutAuthSet:            %d\n"
                       % (self.owner_auth is not None, self.lockout_set)).encode())
        if tool == "readpublic" and index == "-c" and argv[2] == "0x81010001" and "-n" in argv:
            if self.ek_name is None:
                return no
            with open(argv[argv.index("-n") + 1], "wb") as f:
                f.write(self.ek_name)
            return ok()
        if tool == "startauthsession":                       # --hmac-session -c <salt key> -S <ctx>
            if argv[argv.index("-c") + 1] != "0x81010001" or self.ek_name is None:
                return no
            self.sessions[argv[argv.index("-S") + 1]] = {"salt": self.ek_name, "encrypt": False}
            return ok()
        if tool == "sessionconfig":
            if index not in self.sessions:
                return no
            self.sessions[index]["encrypt"] = "--enable-encrypt" in argv and "--enable-decrypt" in argv
            return ok()
        if tool == "flushcontext":
            self.sessions.pop(index, None)
            return ok()
        if tool == "changeauth" and argv[1:3] == ["-c", "o"]:   # [-p OLD] NEW, both through the channel
            rest, old, session = argv[3:], None, None
            if rest[:1] == ["-p"]:
                given = rest[1]
                if given.startswith("session:"):             # session:<ctx>[+file:/dev/fd/N]
                    session, _, given = given[len("session:"):].partition("+")
                    if session not in self.sessions:
                        return no
                old = self._from_fd(given, kw) if given else None
                rest = rest[2:]
                if given and old is None:
                    return no
            new = self._from_fd(rest[0], kw) if len(rest) == 1 else None
            if new is None or not new.startswith(b"hex:") or len(new) != 68:
                return no
            if old != self._held():
                return bad_auth
            encrypted = session is not None and self.sessions[session]["encrypt"]
            self.salted_with.append(self.sessions[session]["salt"] if encrypted else None)
            self.owner_auth = bytes.fromhex(new[4:].decode())
            return ok()
        if "-C" in argv and argv[argv.index("-C") + 1] == "o" and tool != "loadexternal" and not self._owner_ok(argv, kw):
            return bad_auth                                  # the owner authorization not given, or not the one held
        if tool == "createprimary":                          # owner-authorized above; a transient primary, nothing kept
            return ok()
        if tool == "getcap" and index == "handles-persistent":
            return ok("".join("- %s\n" % h for h in sorted(self.persistent)).encode())
        if tool == "getcap":                                 # tpm2_getcap handles-nv-index: what the TPM says it holds
            return ok("".join("- %s\n" % name for name in sorted(self.nv)).encode()) if index == "handles-nv-index" else no
        if tool == "nvdefine":
            if index in self.nv:
                return no
            words = argv[argv.index("-a") + 1].split("|") if "-a" in argv else ["ownerread", "ownerwrite", "authread", "authwrite"]
            bits = sum(self.BITS.get(word, 0) for word in words) | (self.COUNTER if "nt=counter" in words else 0)
            self.nv[index] = [bits, None, int(argv[argv.index("-s") + 1])]
            if "-L" in argv:
                with open(argv[argv.index("-L") + 1], "rb") as f:
                    self.policies[index] = f.read().hex()
            return ok()
        if index not in self.nv:
            return no
        entry = self.nv[index]
        if tool == "nvreadpublic":
            policy = "  authorization policy: %s\n" % self.policies[index].upper() if index in self.policies else ""
            return ok(("%s:\n  attributes:\n    friendly: (not parsed)\n    value: 0x%X\n  size: %d\n%s" % (index, entry[0], entry[2], policy)).encode())
        if tool == "nvread":
            size = int(argv[argv.index("-s") + 1])
            # a read is authorized by the owner (ownerread) or by the index itself (authread), as the TPM checks
            auth = argv[argv.index("-C") + 1] if "-C" in argv else index
            if not entry[0] & (self.BITS["ownerread"] if auth == "o" else self.BITS["authread"] if auth == index else 0):
                return no
            if entry[1] is None or size > entry[2]:
                return no
            return ok((entry[1].to_bytes(8, "big") if entry[0] & self.COUNTER else entry[1])[:size])
        if tool == "nvincrement" and entry[0] & self.COUNTER:
            entry[1] = self.highest + 1 if entry[1] is None else entry[1] + 1
            self.highest, entry[0] = max(self.highest, entry[1]), entry[0] | self.WRITTEN
            return ok()
        if tool == "nvwrite" and not entry[0] & (self.COUNTER | self.LOCKED) and len(input) <= entry[2]:
            entry[1], entry[0] = input + (entry[1] or b"\xff" * entry[2])[len(input):], entry[0] | self.WRITTEN
            return ok()
        if tool == "nvwritelock":
            entry[0] |= self.LOCKED
            return ok()
        if tool == "nvundefine":
            del self.nv[index]
            self.policies.pop(index, None)
            return ok()
        return no


def hbt_killing(after):
    """A FakeTpm whose `after`-th counter increment, once armed, kills the caller (raises)."""
    tpm = FakeTpm()
    tpm.armed, tpm.count = False, 0
    real = tpm.__call__

    class Killing(FakeTpm):
        pass

    def call(argv, input=None, **kw):
        if tpm.armed and argv[0] == "tpm2_nvincrement":
            tpm.count += 1
            if tpm.count == after:
                raise OSError("killed at increment %d" % after)
        return real(argv, input=input, **kw)
    tpm.call = call
    return _Callable(tpm)


class _Callable:
    def __init__(self, tpm):
        self.tpm = tpm

    def __call__(self, argv, input=None, **kw):
        return self.tpm.call(argv, input=input, **kw)

    def __getattr__(self, name):
        return getattr(self.tpm, name)

    def __setattr__(self, name, value):
        if name == "tpm":
            object.__setattr__(self, name, value)
        else:
            setattr(self.tpm, name, value)


class FakeTpmReads(unittest.TestCase):
    def test_a_read_needs_the_attribute_of_whoever_authorizes_it(self):
        """The fake checks a read's authorization as the TPM does: the owner needs ownerread, the index itself
        authread. Without that, a reader that read as the owner would pass every fake test (#242)."""
        tpm = FakeTpm()
        for index, words in (("0x1500040", "ownerread|ownerwrite"), ("0x1500041", "authread|ownerwrite"), ("0x1500042", "ownerread|authread|ownerwrite")):
            tpm(["tpm2_nvdefine", index, "-C", "o", "-s", "8", "-a", words])
            tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=bytes(8))
        reads = {(index, auth): tpm(["tpm2_nvread", index, "-C", auth, "-s", "8"]).returncode == 0
                 for index in ("0x1500040", "0x1500041", "0x1500042") for auth in ("o", index, "0x1500043")}
        self.assertEqual(reads, {("0x1500040", "o"): True, ("0x1500040", "0x1500040"): False, ("0x1500040", "0x1500043"): False,
                                 ("0x1500041", "o"): False, ("0x1500041", "0x1500041"): True, ("0x1500041", "0x1500043"): False,
                                 ("0x1500042", "o"): True, ("0x1500042", "0x1500042"): True, ("0x1500042", "0x1500043"): False})


class DefineAt(unittest.TestCase):
    """heartbeat.Counter.define_at (#190 --replace, decided by regalia-kms-24 with regalia-kms-d9): a fresh
    counter that reads a verified sequence at once, by its write-once base, with no increment loop."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def counter(self, tpm):
        return hb.Counter("0x1500018", lock_path=self.d + "/lock", run=tpm)

    def test_it_reads_the_sequence_at_once_whether_the_counter_lands_below_or_above(self):
        for highest, sequence in ((0, 52000), (10 ** 6, 10), (2 ** 63, 7)):
            with self.subTest(highest=highest, sequence=sequence):
                tpm = FakeTpm(highest=highest)
                increments = []
                counter = self.counter(lambda argv, **kw: (increments.append(argv) if argv[0] == "tpm2_nvincrement" else None, tpm(argv, **kw))[1])
                self.assertEqual(counter.define_at(sequence), sequence)
                self.assertEqual(len(increments), 1)                            # one write, not one per heartbeat
                self.assertEqual(counter.value(), sequence)
                self.assertEqual(counter.advance(sequence + 1), sequence + 1)  # and it counts on from there
                self.assertEqual(counter.remains()[0], sequence + 1)            # recount's floor reads it the same way

    def test_a_complete_counter_is_never_redefined(self):
        tpm = FakeTpm()
        counter = self.counter(tpm)
        counter.define_at(100)
        with self.assertRaises(m.Refused) as caught:
            counter.define_at(5)
        self.assertIn("already defined", str(caught.exception))
        self.assertEqual(counter.value(), 100)

    def test_a_kill_before_or_after_the_base_write_is_done_again(self):
        for stop in ("tpm2_nvwrite", "tpm2_nvwritelock"):
            with self.subTest(killed_at=stop):
                tpm = FakeTpm()
                armed = {"on": True}

                def killing(argv, **kw):
                    if armed["on"] and argv[0] == stop:
                        raise OSError("power cut at %s" % stop)
                    return tpm(argv, **kw)
                counter = self.counter(killing)
                with self.assertRaises(OSError):
                    counter.define_at(4000)
                armed["on"] = False
                self.assertEqual(counter.define_at(4000), 4000)
                self.assertEqual(counter.value(), 4000)

    def test_a_replacement_takes_its_first_heartbeat_at_the_network_s_sequence(self):
        tpm = FakeTpm()
        counter = self.counter(tpm)                                     # not defined yet: a node being replaced
        man = manifest()
        fresh = hb.Freshness(counter, lambda: (T0 + 60, True), lambda: 5000, self.d + "/f.json")
        self.assertEqual(fresh.accept_first(beat(man, 52000, issued=T0), man), hb.MAX_LIFETIME - 60)
        self.assertEqual(counter.value(), 52000)
        fresh.accept(beat(man, 52001, issued=T0 + 30), man)           # then the ordinary rule
        self.assertEqual(counter.value(), 52001)
        with self.assertRaises(m.Refused) as caught:
            fresh.accept_first(beat(man, 60000, issued=T0 + 40), man)
        self.assertIn("already held", str(caught.exception))

    def test_a_damaged_counter_is_recount_s_case_not_a_first_heartbeat_s(self):
        """#261 (regalia-kms-3e): a counter whose base is gone, on a node whose disk state is lost, is not
        redefined by a first heartbeat: that would skip recount's floor, phrase, audit and proofs."""
        man = manifest()
        for damage in ("base gone", "complete"):
            with self.subTest(damage):
                tpm = FakeTpm()
                counter = hb.Counter("0x1500018", lock_path=self.d + "/" + damage + ".lock", run=tpm)
                counter.define_at(5000)
                if damage == "base gone":
                    tpm.nv.pop(counter.base_index)
                before = {k: list(v) for k, v in tpm.nv.items()}
                fresh = hb.Freshness(counter, lambda: (T0 + 60, True), lambda: 5000, self.d + "/" + damage + ".json")
                with self.assertRaises(m.Refused) as caught:
                    fresh.accept_first(beat(man, 70000, issued=T0), man)
                self.assertIn("use recount", str(caught.exception))
                self.assertEqual({k: list(v) for k, v in tpm.nv.items()}, before)      # nothing touched
                self.assertFalse(os.path.exists(self.d + "/" + damage + ".json"))       # nothing held

    def test_a_first_heartbeat_is_checked_like_any_other(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        man = manifest()
        for label, envelope, clock in (("a stranger's", beat(man, 50000, issued=T0, key=Ed25519PrivateKey.generate()), (T0 + 60, True)),
                                       ("expired", beat(man, 50000, issued=T0), (T0 + hb.MAX_LIFETIME + 1, True)),
                                       ("from the future", beat(man, 50000, issued=T0 + 3600), (T0 + 60, True)),
                                       ("time not authenticated", beat(man, 50000, issued=T0), (T0 + 60, False))):
            with self.subTest(label):
                tpm = FakeTpm()
                counter = hb.Counter("0x1500018", lock_path=self.d + "/" + label + ".lock", run=tpm)
                fresh = hb.Freshness(counter, lambda clock=clock: clock, lambda: 5000, self.d + "/" + label + ".json")
                with self.assertRaises(m.Refused):
                    fresh.accept_first(envelope, man)
                self.assertNotIn(counter.index, tpm.nv)                    # nothing defined

    def test_a_sequence_out_of_range_is_refused(self):
        for bad in (-1, 1 << 63, True, 1.5):
            with self.subTest(bad=bad), self.assertRaises(m.Refused):
                self.counter(FakeTpm()).define_at(bad)


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.counter = hb.Counter("0x1500018", lock_path=self.d + "/lock", run=self.tpm)
        self.counter.define()
        self.now, self.authenticated, self.ticks = T0 + 60, True, 5000
        self.state = os.path.join(self.d, "freshness.json")
        self.f = hb.Freshness(self.counter, lambda: (self.now, self.authenticated), lambda: self.ticks, self.state)
        self.m1 = manifest()

    def later(self, seconds):
        """Real time and the TPM clock both move on."""
        self.now += seconds
        self.ticks += seconds * 1000

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))


class Heartbeats(Case):
    def test_a_live_heartbeat_for_the_current_manifest_lets_the_peer_authorize(self):
        self.refused("no heartbeat is held", self.f.check, self.m1)
        self.assertEqual(self.f.accept(beat(self.m1, 1), self.m1), hb.MAX_LIFETIME - 60)
        self.assertEqual(self.counter.value(), 1)
        self.later(3600)
        self.assertEqual(self.f.check(self.m1), hb.MAX_LIFETIME - 3660)
        self.assertEqual(hb.authorize(self.m1, "b", "a", self.f), hb.MAX_LIFETIME - 3660)

    def test_it_expires(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(hb.MAX_LIFETIME - 61)
        self.assertEqual(self.f.check(self.m1), 1)
        self.later(1)
        self.refused("EXPIRED", self.f.check, self.m1)
        self.refused("EXPIRED", hb.authorize, self.m1, "b", "a", self.f)
        self.refused("EXPIRED", self.f.accept, beat(self.m1, 2), self.m1)                  # an old one, never seen: still expired
        self.assertEqual(self.counter.value(), 1)
        self.f.accept(beat(self.m1, 2, issued=self.now - 10), self.m1)                      # the next one restores it
        self.assertEqual(self.f.check(self.m1), hb.MAX_LIFETIME - 10)

    def test_a_heartbeat_lives_at_most_24_hours_under_a_v1_manifest_whatever_the_signer_wrote(self):
        self.refused("at most 86400 s under the current manifest", self.f.accept, beat(self.m1, 1, lifetime=hb.MAX_LIFETIME + 1), self.m1)
        self.refused("expires_at must be after issued_at", self.f.accept, beat(self.m1, 1, lifetime=0), self.m1)
        self.refused("issued in the future", self.f.accept, beat(self.m1, 1, issued=self.now + hb.FUTURE_SKEW + 1), self.m1)
        self.f.accept(beat(self.m1, 1, issued=self.now + hb.FUTURE_SKEW), self.m1)

    def test_a_heartbeat_for_another_manifest_is_refused(self):
        m2 = manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        other_same_epoch = manifest(c="DRAINING")
        self.refused("for epoch 2, the current manifest is epoch 1", self.f.accept, beat(m2, 1), self.m1)
        self.refused("another manifest (digest mismatch)", self.f.accept, beat(other_same_epoch, 1), self.m1)
        self.refused("another manifest (digest mismatch)", self.f.accept, beat(self.m1, 1, manifest_digest="00" * 32), self.m1)
        self.assertEqual(self.counter.value(), 0)
        self.assertFalse(os.path.exists(self.state))

    def test_poc_9_4_a_peer_that_moved_to_a_new_epoch_needs_a_heartbeat_for_it(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        m2 = manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        self.refused("for epoch 1, the current manifest is epoch 2", self.f.check, m2)
        self.refused("for epoch 1", hb.authorize, m2, "b", "c", self.f)
        self.f.accept(beat(m2, 2), m2)
        self.assertGreater(hb.authorize(m2, "b", "c", self.f), 0)
        self.refused("for epoch 2, the current manifest is epoch 1", self.f.check, self.m1)   # and the old manifest is not served by it

    def test_only_a_revocation_key_named_by_the_current_manifest_signs_heartbeats(self):
        self.refused("not a revocation key named by the current manifest", self.f.accept, beat(self.m1, 1, key=OTHER), self.m1)
        self.refused("not a revocation key named by the current manifest", self.f.accept, beat(self.m1, 1, key=ROOT), self.m1)
        # the root replaced the revocation key: the old key's heartbeats stop counting, held or new
        self.f.accept(beat(self.m1, 1), self.m1)
        m2 = manifest(2, m.digest(self.m1), keys=[pub(OTHER)])
        self.refused("not a revocation key named by the current manifest", self.f.accept, beat(m2, 2), m2)
        self.f.accept(beat(m2, 2, key=OTHER), m2)
        dropped = manifest(3, m.digest(m2), keys=[])
        self.refused("not a revocation key named by the current manifest", self.f.check, dropped)

    def test_a_signature_must_be_over_this_heartbeat_under_the_heartbeat_domain(self):
        good = beat(self.m1, 1)
        altered = copy.deepcopy(good)
        altered["heartbeat"]["expires_at"] = stamp(T0 + hb.MAX_LIFETIME - 1)
        self.refused("signature does not verify", self.f.accept, altered, self.m1)
        self.refused("signature does not verify", self.f.accept, beat(self.m1, 1, domain=m.DOMAIN), self.m1)
        self.refused("signature does not verify", self.f.accept, beat(self.m1, 1, domain=b""), self.m1)
        self.assertNotEqual(hb.DOMAIN, m.DOMAIN)

    def test_malformed_heartbeats_are_refused(self):
        good = beat(self.m1, 1)
        for label, reason, change in (
                ("unknown field", "fields mismatch", lambda e: e["heartbeat"].update(note="x")),
                ("missing field", "fields mismatch", lambda e: e["heartbeat"].pop("sequence")),
                ("schema", "schema must be", lambda e: e["heartbeat"].update(schema="regalia.heartbeat/v0")),
                ("sequence 0", "sequence must be an integer >= 1", lambda e: e["heartbeat"].update(sequence=0)),
                ("sequence true", "sequence must be an integer >= 1", lambda e: e["heartbeat"].update(sequence=True)),
                ("epoch text", "epoch must be an integer >= 1", lambda e: e["heartbeat"].update(epoch="1")),
                ("local time", "issued_at must be UTC", lambda e: e["heartbeat"].update(issued_at="2026-09-21T13:33:20+02:00")),
                ("Arabic-Indic digits", "issued_at must be UTC", lambda e: e["heartbeat"].update(issued_at="٢٠٢٦-٠٩-٢١T١١:٣٣:٢٠Z")),
                ("a fullwidth year", "expires_at must be UTC", lambda e: e["heartbeat"].update(expires_at="２０２６-09-21T11:33:20Z")),
                ("unpadded fields", "issued_at must be UTC", lambda e: e["heartbeat"].update(issued_at="2026-9-21T1:3:2Z")),
                ("no such date", "expires_at is not a real date", lambda e: e["heartbeat"].update(expires_at="2026-02-30T00:00:00Z")),
                ("digest", "manifest_digest must be 64 lowercase hex", lambda e: e["heartbeat"].update(manifest_digest="AB" * 32)),
                ("signer field", "signature fields mismatch", lambda e: e["signature"].update(signer="revocation")),
                ("short signature", "signature.sig must be 128 lowercase hex", lambda e: e["signature"].update(sig="00")),
                ("envelope", "envelope fields mismatch", lambda e: e.update(manifest={}))):
            with self.subTest(label):
                envelope = copy.deepcopy(good)
                change(envelope)
                self.refused(reason, self.f.accept, envelope, self.m1)
        self.refused("envelope must be an object", self.f.accept, [good], self.m1)


class Time(Case):
    def test_unauthenticated_time_fails_closed(self):
        self.authenticated = False
        self.refused("time is not authenticated", self.f.accept, beat(self.m1, 1), self.m1)
        self.assertEqual(self.counter.value(), 0)
        self.authenticated = True
        self.f.accept(beat(self.m1, 1), self.m1)
        self.authenticated = False
        self.refused("time is not authenticated", self.f.check, self.m1)
        self.refused("time is not authenticated", hb.authorize, self.m1, "b", "a", self.f)
        for not_true in (1, "yes", None):   # only the value True authenticates
            self.authenticated = not_true
            self.refused("time is not authenticated", self.f.check, self.m1)
        self.authenticated = True
        self.assertGreater(self.f.check(self.m1), 0)

    def test_the_clock_going_backwards_is_refused(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(7200)
        self.f.check(self.m1)
        self.now -= 3600                         # the time source now says an hour earlier; the TPM clock did not move
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.refused("the clock went backwards", self.f.accept, beat(self.m1, 2), self.m1)
        self.now += 3600
        self.assertGreater(self.f.check(self.m1), 0)

    def test_an_expired_heartbeat_cannot_be_revived_by_setting_the_clock_back(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(hb.MAX_LIFETIME)
        self.refused("EXPIRED", self.f.check, self.m1)
        self.now = T0 + 120                      # back to when the heartbeat was live
        self.refused("the clock went backwards", self.f.check, self.m1)

    def test_the_tpm_clock_raises_the_floor_between_checks(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.ticks += 1000 * 1000                # the TPM counted 1000 s; the time source claims only 100 s passed
        self.now += 100
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.now += 750 - 100                    # 85% of the TPM's 1000 s is the floor; 5 s of step-back are allowed
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.now += 100
        self.assertGreater(self.f.check(self.m1), 0)

    def test_a_small_correction_and_a_tpm_clock_reset_are_tolerated(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.now -= hb.STEP_BACK                 # an NTP correction
        self.assertGreater(self.f.check(self.m1), 0)
        self.now -= 1                            # the floor did not follow the correction down
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.now += hb.STEP_BACK + 1
        self.ticks = 3                           # the TPM clock restarted low (a power loss, a cleared TPM)
        self.later(600)
        self.assertGreater(self.f.check(self.m1), 0)
        self.now -= 300                          # and the floor still holds from the last reading
        self.refused("the clock went backwards", self.f.check, self.m1)

    def test_a_clock_that_returns_no_time_is_refused(self):
        for bad in (None, "1790000000", -1, True):
            with self.subTest(bad=bad):
                self.now = bad
                self.refused("the clock returned no time", self.f.check, self.m1)


class Sequence(Case):
    def test_a_sequence_at_or_below_the_counter_is_refused(self):
        self.f.accept(beat(self.m1, 5), self.m1)
        self.assertEqual(self.counter.value(), 5)
        with open(self.state, "rb") as f:
            before = f.read()
        self.refused("REPLAY: sequence 5 is not above the TPM counter 5", self.f.accept, beat(self.m1, 5, issued=T0 + 30), self.m1)
        self.refused("REPLAY: sequence 4 is not above the TPM counter 5", self.f.accept, beat(self.m1, 4), self.m1)
        with open(self.state, "rb") as f:
            self.assertEqual(f.read(), before)   # a refused heartbeat never reaches the disk
        # and the counter itself refuses, whoever calls it
        self.refused("REPLAY: sequence 5 is not above the TPM counter 5", self.counter.advance, 5)
        self.refused("REPLAY: sequence 1 is not above the TPM counter 5", self.counter.advance, 1)
        self.refused("jump 1001 exceeds the bound 1000: anomaly", self.counter.advance, 1006)
        self.assertEqual(self.counter.value(), 5)
        self.assertEqual(self.f.accept(beat(self.m1, 6), self.m1), hb.MAX_LIFETIME - 60)
        self.assertEqual(self.counter.value(), 6)

    def test_a_disk_rolled_back_to_an_older_heartbeat_is_refused_by_the_counter(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state, "rb") as f:
            snapshot = f.read()
        self.later(600)
        self.f.accept(beat(self.m1, 2, issued=self.now), self.m1)
        with open(self.state, "wb") as f:
            f.write(snapshot)                    # the disk restored; heartbeat 1 is still signed and unexpired
        self.refused("ROLLBACK: the heartbeat on disk is sequence 1 but the TPM counter is 2", self.f.check, self.m1)
        self.refused("ROLLBACK", hb.authorize, self.m1, "b", "a", self.f)
        self.refused("REPLAY", self.f.accept, beat(self.m1, 1), self.m1)                    # nor can it be fed in again
        self.refused("REPLAY", self.f.accept, beat(self.m1, 2, issued=self.now), self.m1)   # the lost one is gone too
        self.f.accept(beat(self.m1, 3, issued=self.now), self.m1)                           # recovery: the next heartbeat
        self.assertGreater(self.f.check(self.m1), 0)

    def test_a_crash_between_the_disk_and_the_counter_is_finished_by_the_next_check(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        real = self.counter.advance
        self.counter.advance = lambda sequence, allowance=None: (_ for _ in ()).throw(OSError("power lost"))
        with self.assertRaises(OSError):
            self.f.accept(beat(self.m1, 2), self.m1)
        self.counter.advance = real
        self.assertEqual(self.counter.value(), 1)          # the disk holds 2, the counter 1
        self.assertGreater(self.f.check(self.m1), 0)
        self.assertEqual(self.counter.value(), 2)          # finished
        self.refused("REPLAY", self.f.accept, beat(self.m1, 2), self.m1)

    def test_the_replay_check_runs_under_the_counter_s_lock(self):
        """Two processes handed the same sequence must not both pass: the comparison and the increments
        are one step under HighWater's lock."""
        events = []
        real_lock, real_value = m._exclusive, self.counter.value

        @contextlib.contextmanager
        def lock(path):
            events.append("lock " + path)
            with real_lock(path):
                yield
            events.append("unlock")
        self.counter.value = lambda: (events.append("compare"), real_value())[1]
        with unittest.mock.patch.object(m, "_exclusive", lock):
            self.counter.advance(1)
        self.assertEqual(events, ["lock " + self.d + "/lock", "compare", "unlock"])
        self.assertTrue(os.path.exists(self.d + "/lock"))

    def test_an_anomalous_jump_is_refused_and_nothing_is_written(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state, "rb") as f:
            before = f.read()
        self.refused("exceeds the bound 1000: anomaly", self.f.accept, beat(self.m1, 1002), self.m1)
        self.assertEqual(self.counter.value(), 1)
        with open(self.state, "rb") as f:
            self.assertEqual(f.read(), before)
        self.f.accept(beat(self.m1, 1001), self.m1)
        self.assertEqual(self.counter.value(), 1001)

    def test_a_node_back_from_a_month_away_catches_up(self):
        """#199: nodes signing every 900 s have moved 2880 sequences in 30 days. The bound grows by one
        per MIN_INTERVAL_S since the last accepted heartbeat, so the node accepts, and the counter steps the
        whole distance (what it would have stepped had it stayed online)."""
        self.f.accept(beat(self.m1, 1, issued=T0), self.m1)
        self.later(30 * 86400)
        sequence = 1 + 30 * 86400 // 900
        self.assertEqual(self.f.accept(beat(self.m1, sequence, issued=T0 + 30 * 86400), self.m1), hb.MAX_LIFETIME - 60)
        self.assertEqual(self.counter.value(), sequence)

    def test_a_sequence_that_runs_faster_than_time_is_still_an_anomaly(self):
        self.f.accept(beat(self.m1, 1, issued=T0), self.m1)
        self.later(3600)                                   # one hour: 1000 + 6 allowed
        self.refused("exceeds the bound 1006: anomaly", self.f.accept, beat(self.m1, 1 + 1007, issued=T0 + 3600), self.m1)
        self.assertEqual(self.counter.value(), 1)
        self.f.accept(beat(self.m1, 1 + 1006, issued=T0 + 3600), self.m1)
        self.assertEqual(self.counter.value(), 1007)

    def test_a_forged_future_issue_time_buys_no_bigger_jump(self):
        """#199 (regalia-kms-24): the issue time the allowance uses has already passed the authenticated-time
        check, so a signer claiming a later time is refused before the bound is computed; inside the
        FUTURE_SKEW it gains at most one step."""
        self.f.accept(beat(self.m1, 1, issued=T0), self.m1)
        self.later(60)                                     # now = T0 + 120
        self.refused("issued in the future", self.f.accept, beat(self.m1, 1 + 1000 + 4320, issued=T0 + 30 * 86400), self.m1)
        self.assertEqual(self.counter.value(), 1)
        skew = self.now + hb.FUTURE_SKEW                   # the latest issue time accepted now
        allowed = 1000 + -(-(skew - T0) // hb.MIN_INTERVAL_S)
        self.assertLessEqual(allowed, 1000 + 1)
        self.refused("exceeds the bound %d" % allowed, self.f.accept, beat(self.m1, 1 + allowed + 1, issued=skew), self.m1)
        self.f.accept(beat(self.m1, 1 + allowed, issued=skew), self.m1)
        self.assertEqual(self.counter.value(), 1 + allowed)

    def test_a_node_killed_at_any_increment_of_a_catch_up_is_not_stranded(self):
        """#199 (regalia-kms-51, decided by regalia-kms-24): the long advance is killed at EVERY increment; the
        node must finish on the same heartbeat (check), or on the next one (accept)."""
        days, interval = 12, 900
        target = 1 + days * 86400 // interval                       # 1153: more than MAX_JUMP away
        for kill in range(1, target):
            for finish in ("check", "next"):
                with self.subTest(kill=kill, finish=finish):
                    tpm = hbt_killing(kill)
                    counter = hb.Counter("0x1500018", lock_path=self.d + "/k.lock", run=tpm)
                    counter.define()
                    state = os.path.join(self.d, "k-%d-%s.json" % (kill, finish))
                    clock = {"now": T0 + 60, "ticks": 5000}
                    fresh = hb.Freshness(counter, lambda: (clock["now"], True), lambda: clock["ticks"], state)
                    fresh.accept(beat(self.m1, 1, issued=T0), self.m1)
                    clock["now"] += days * 86400
                    clock["ticks"] += days * 86400 * 1000
                    tpm.armed = True
                    with self.assertRaises(OSError):
                        fresh.accept(beat(self.m1, target, issued=T0 + days * 86400), self.m1)
                    tpm.armed = False
                    self.assertLess(counter.value(), target)
                    if finish == "check":
                        self.assertGreater(fresh.check(self.m1), 0)
                        self.assertEqual(counter.value(), target)
                    else:
                        clock["now"] += interval
                        clock["ticks"] += interval * 1000
                        fresh.accept(beat(self.m1, target + 1, issued=T0 + days * 86400 + interval), self.m1)
                        self.assertEqual(counter.value(), target + 1)
                    os.unlink(state)

    def test_a_node_killed_early_in_a_huge_catch_up_still_takes_a_later_heartbeat(self):
        """#230 second read (regalia-kms-51): after 50,000 steps owed and a crash at increment 10, a heartbeat
        13,000 further must be taken: the owed advance is finished first, and the new one measured from it."""
        tpm = hbt_killing(10)
        counter = hb.Counter("0x1500018", lock_path=self.d + "/k.lock", run=tpm)
        counter.define()
        clock = {"now": T0 + 60, "ticks": 5000}
        fresh = hb.Freshness(counter, lambda: (clock["now"], True), lambda: clock["ticks"], self.d + "/huge.json")
        fresh.accept(beat(self.m1, 1, issued=T0), self.m1)
        away = 50000 * hb.MIN_INTERVAL_S
        clock["now"] += away
        clock["ticks"] += away * 1000
        tpm.armed = True
        with self.assertRaises(OSError):
            fresh.accept(beat(self.m1, 50001, issued=T0 + away), self.m1)
        tpm.armed = False
        later = 13000 * hb.MIN_INTERVAL_S
        clock["now"] += later
        clock["ticks"] += later * 1000
        fresh.accept(beat(self.m1, 63001, issued=T0 + away + later), self.m1)
        self.assertEqual(counter.value(), 63001)

    def test_a_planted_state_owes_nothing_and_moves_nothing(self):
        """#230 third read (regalia-kms-51): finishing an owed advance must not trust the state file. A held
        heartbeat that is not signed by a key the manifest names owes nothing: the genuine next one is taken
        and the counter lands exactly on it."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        stranger = Ed25519PrivateKey.generate()
        for label, planted, allowance in (("unsigned, huge", {"heartbeat": {"sequence": 10 ** 9}}, None),
                                          ("signed by a stranger", beat(self.m1, 53705, issued=T0, key=stranger), hb.MAX_ALLOWANCE),
                                          ("over its stored allowance", {"heartbeat": {"sequence": 5000}}, 1000)):
            with self.subTest(label):
                tpm = FakeTpm()
                counter = hb.Counter("0x1500018", lock_path=self.d + "/p.lock", run=tpm)
                counter.define()
                path = os.path.join(self.d, "planted.json")
                fresh = hb.Freshness(counter, lambda: (self.now, True), lambda: self.ticks, path)
                fresh.accept(beat(self.m1, 1, issued=T0), self.m1)
                with open(path) as f:
                    state = json.load(f)
                state["envelope"], state["allowance"] = planted, allowance
                with open(path, "w") as f:
                    json.dump(state, f)
                fresh.accept(beat(self.m1, 2, issued=T0 + 60), self.m1)
                self.assertEqual(counter.value(), 2)
                os.unlink(path)

    def test_a_key_rotation_mid_catch_up_does_not_strand_the_node(self):
        """#230 fourth read (regalia-kms-51): killed early in a 50,000-step catch-up, then the manifest names only
        a NEW revocation key. The held heartbeat (old key) is not finished on its word, but its gap widens the
        bound for the new, verified heartbeat."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        tpm = hbt_killing(10)
        counter = hb.Counter("0x1500018", lock_path=self.d + "/r.lock", run=tpm)
        counter.define()
        clock = {"now": T0 + 60, "ticks": 5000}
        fresh = hb.Freshness(counter, lambda: (clock["now"], True), lambda: clock["ticks"], self.d + "/rot.json")
        fresh.accept(beat(self.m1, 1, issued=T0), self.m1)
        away = 50000 * hb.MIN_INTERVAL_S
        clock["now"] += away
        clock["ticks"] += away * 1000
        tpm.armed = True
        with self.assertRaises(OSError):
            fresh.accept(beat(self.m1, 50001, issued=T0 + away), self.m1)
        tpm.armed = False
        newer = Ed25519PrivateKey.generate()
        m2 = manifest(epoch=2, prev=m.digest(self.m1), keys=[pub(newer)])
        clock["now"] += 3600
        clock["ticks"] += 3600 * 1000
        fresh.accept(beat(m2, 50007, issued=T0 + away + 3600, key=newer), m2)
        self.assertEqual(counter.value(), 50007)

    def test_a_genuine_held_heartbeat_beyond_its_stored_allowance_is_finished_only_that_far(self):
        self.f.accept(beat(self.m1, 1, issued=T0), self.m1)
        with open(self.state) as f:
            state = json.load(f)
        state["envelope"], state["allowance"] = beat(self.m1, 3000, issued=T0 + 60), 1000    # genuine, but over its allowance
        with open(self.state, "w") as f:
            json.dump(state, f)
        self.f.accept(beat(self.m1, 1500, issued=T0 + 120), self.m1)
        self.assertEqual(self.counter.value(), 1500)

    def test_the_widened_bound_is_capped_too(self):
        """A gap planted at the largest stored allowance, across a rotation, still loosens the bound to at
        most MAX_ALLOWANCE in all."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.f.accept(beat(self.m1, 1, issued=T0), self.m1)
        with open(self.state) as f:
            state = json.load(f)
        state["envelope"], state["allowance"] = beat(self.m1, 1 + hb.MAX_ALLOWANCE, issued=T0 + 60), hb.MAX_ALLOWANCE
        with open(self.state, "w") as f:
            json.dump(state, f)
        newer = Ed25519PrivateKey.generate()
        m2 = manifest(epoch=2, prev=m.digest(self.m1), keys=[pub(newer)])
        self.later(3600)
        self.refused("exceeds the bound %d" % hb.MAX_ALLOWANCE, self.f.accept, beat(m2, 2 + hb.MAX_ALLOWANCE, issued=T0 + 3600, key=newer), m2)
        self.f.accept(beat(m2, 1 + hb.MAX_ALLOWANCE, issued=T0 + 3600, key=newer), m2)
        self.assertEqual(self.counter.value(), 1 + hb.MAX_ALLOWANCE)

    def test_the_stored_allowance_never_exceeds_the_cap(self):
        self.f.accept(beat(self.m1, 1, issued=T0), self.m1)
        self.later(2 * 366 * 86400)
        self.f.accept(beat(self.m1, 2, issued=T0 + 2 * 366 * 86400), self.m1)
        with open(self.state) as f:
            self.assertEqual(json.load(f)["allowance"], hb.MAX_ALLOWANCE)

    def test_an_issue_time_before_the_held_one_buys_nothing(self):
        held = beat(self.m1, 1, issued=T0 + 86400)
        self.assertEqual(hb.allowed_jump(beat(self.m1, 2, issued=T0)["heartbeat"], held, 1000), 1000)

    def test_the_allowance_is_capped_however_long_the_node_was_away(self):
        held = beat(self.m1, 1, issued=T0)
        self.assertEqual(hb.allowed_jump(beat(self.m1, 2, issued=T0 + 10 * 366 * 86400)["heartbeat"], held, 1000), hb.MAX_ALLOWANCE)
        self.refused("exceeds the bound", self.counter.advance, hb.MAX_ALLOWANCE + 2, hb.MAX_ALLOWANCE)

    def test_a_state_written_before_the_allowance_is_still_read(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state) as f:
            state = json.load(f)
        del state["allowance"]
        with open(self.state, "w") as f:
            json.dump(state, f)
        self.assertGreater(self.f.check(self.m1), 0)

    def test_without_the_held_heartbeat_the_bound_is_the_fixed_one(self):
        self.f.accept(beat(self.m1, 1, issued=T0), self.m1)
        os.unlink(self.state)                              # the state is lost; the TPM counter is not
        self.later(30 * 86400)
        self.refused("exceeds the bound 1000: anomaly", self.f.accept, beat(self.m1, 2881, issued=T0 + 30 * 86400), self.m1)
        self.assertEqual(self.counter.value(), 1)

    def test_the_counter_alone_keeps_the_fixed_bound(self):
        self.refused("exceeds the bound 1000: anomaly", self.counter.advance, 1001)
        self.assertEqual(self.counter.advance(1500, allowance=1500), 1500)

    def test_a_tpm_failure_is_never_read_as_zero(self):
        self.f.accept(beat(self.m1, 3), self.m1)
        self.tpm.broken = True
        self.refused("fail closed", self.counter.value)
        self.refused("fail closed", self.f.check, self.m1)
        self.refused("fail closed", self.f.accept, beat(self.m1, 4), self.m1)
        self.tpm.broken = False
        self.refused("fail closed", hb.Counter("0x1500099", lock_path=self.d + "/lock", run=self.tpm).value)   # an index nobody defined
        self.assertEqual(self.f.check(self.m1), hb.MAX_LIFETIME - 60)

    def test_a_tpm_that_held_counters_before_still_starts_at_zero(self):
        used = FakeTpm(highest=40)
        counter = hb.Counter("0x1500018", lock_path=self.d + "/lock", run=used)
        self.assertEqual(counter.define(), 41)             # where the counter landed: its base
        self.assertEqual(counter.value(), 0)
        f = hb.Freshness(counter, lambda: (self.now, True), lambda: self.ticks, os.path.join(self.d, "used.json"))
        f.accept(beat(self.m1, 1), self.m1)
        self.assertEqual(counter.value(), 1)

    def test_a_deleted_counter_refuses_and_a_recreated_one_does_not_count_from_below(self):
        self.f.accept(beat(self.m1, 7), self.m1)
        self.tpm(["tpm2_nvundefine", "0x1500018", "-C", "o"])
        self.refused("fail closed", self.f.check, self.m1)                  # no counter: no decision
        self.refused("already exists", self.counter.define)                 # its base is still there
        self.tpm(["tpm2_nvdefine", "0x1500018", "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread"])
        self.refused("is not a written counter", self.f.check, self.m1)
        self.tpm(["tpm2_nvincrement", "0x1500018", "-C", "o"])
        self.assertGreaterEqual(self.counter.value(), 7)                    # above every value it ever held
        self.refused("REPLAY", self.f.accept, beat(self.m1, 3), self.m1)
        self.refused("REPLAY", self.f.accept, beat(self.m1, 7), self.m1)

    def test_the_sequence_counter_does_not_share_membership_s_indices(self):
        epochs = m.HighWater("0x1500016", lock_path=self.d + "/lock", run=self.tpm)
        epochs.define()
        epochs.advance(3)
        self.assertEqual(self.counter.value(), 0)
        self.f.accept(beat(self.m1, 2), self.m1)
        self.assertEqual((epochs.value(), self.counter.value()), (3, 2))
        self.assertEqual(len({epochs.index, epochs.base_index, self.counter.index, self.counter.base_index}), 4)
        self.refused("already exists", hb.Counter("0x1500017", lock_path=self.d + "/lock", run=self.tpm).define)   # membership's base index

    def test_a_counter_that_does_not_move_or_cannot_be_incremented_is_refused(self):
        def stuck(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, b"", b"") if argv[0] == "tpm2_nvincrement" else self.tpm(argv, **kw)

        def failing(argv, **kw):
            return subprocess.CompletedProcess(argv, 1, b"", b"no") if argv[0] == "tpm2_nvincrement" else self.tpm(argv, **kw)
        self.refused("did not advance by one", hb.Counter("0x1500018", lock_path=self.d + "/lock", run=stuck).advance, 1)
        self.refused("cannot increment the NV counter", hb.Counter("0x1500018", lock_path=self.d + "/lock", run=failing).advance, 1)
        self.assertEqual(self.counter.value(), 0)

    def test_a_planted_heartbeat_cannot_push_the_counter_forward(self):
        """check() finishes an interrupted accept, so what is on disk must pass every check before the
        counter moves: otherwise a planted file strands the node above the network's sequence."""
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state) as f:
            state = json.load(f)
        for label, reason, envelope in (
                ("a stranger's signature", "not a revocation key named by the current manifest", beat(self.m1, 900, key=OTHER)),
                ("an altered sequence", "signature does not verify", dict(beat(self.m1, 2), heartbeat=dict(beat(self.m1, 2)["heartbeat"], sequence=900))),
                ("another manifest", "digest mismatch", beat(manifest(c="DRAINING"), 900)),
                ("too long a life", "at most 604800 s under any manifest", beat(self.m1, 900, lifetime=hb.MAX_LIFETIME * 30)),
                ("too long a life for this manifest", "at most 86400 s under the current manifest", beat(self.m1, 900, lifetime=hb.MAX_LIFETIME * 2)),
                ("expired", "EXPIRED", beat(self.m1, 900, issued=T0 - 2 * hb.MAX_LIFETIME)),
                ("from the future", "issued in the future", beat(self.m1, 900, issued=self.now + 3600)),
                ("a jump", "exceeds the bound 1000: anomaly", beat(self.m1, 5000))):
            with self.subTest(label):
                with open(self.state, "w") as f:
                    json.dump(dict(state, envelope=envelope), f)
                self.refused(reason, self.f.check, self.m1)
                self.assertEqual(self.counter.value(), 1)
        with open(self.state, "w") as f:
            json.dump(state, f)
        self.assertGreater(self.f.check(self.m1), 0)


class State(Case):
    def test_the_state_file_is_strict_and_small(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state) as f:
            good = json.load(f)
        self.assertEqual(sorted(good), ["allowance", "envelope", "floor"])
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)
        for label, reason, doc in (("unknown field", "freshness state fields mismatch", dict(good, extra=1)),
                                   ("floor field", "floor fields mismatch", dict(good, floor={"time": 1})),
                                   ("negative floor", "floor must be integers", dict(good, floor={"time": -1, "tpm_clock": 0})),
                                   ("allowance too large", "allowance is out of range", dict(good, allowance=hb.MAX_ALLOWANCE + 1)),
                                   ("a list", "must be an object", [good]),
                                   ("allowance zero", "allowance is out of range", dict(good, allowance=0)),
                                   ("float floor", "floats are not allowed", None)):
            with self.subTest(label):
                with open(self.state, "w") as f:
                    f.write(json.dumps(doc) if doc else '{"envelope": null, "floor": {"time": 1.5, "tpm_clock": 0}}')
                self.refused(reason, self.f.check, self.m1)
        with open(self.state, "w") as f:
            f.write(" " * (hb.MAX_BYTES + 1))
        self.refused("oversized", self.f.check, self.m1)

    def test_a_floor_lowered_on_disk_only_weakens_the_floor_never_the_expiry(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(hb.MAX_LIFETIME)
        with open(self.state) as f:
            state = json.load(f)
        state["floor"] = None
        with open(self.state, "w") as f:
            json.dump(state, f)
        self.refused("EXPIRED", self.f.check, self.m1)

    def test_accept_and_check_wait_for_the_state_lock(self):
        """Each reads, decides and rewrites the state file; held from outside, the lock makes both wait."""
        import fcntl
        import threading
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state, "rb") as f:
            before = f.read()
        lock = os.open(self.f.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, lock)
        fcntl.flock(lock, fcntl.LOCK_EX)
        results = {}
        calls = {"accept": lambda: self.f.accept(beat(self.m1, 2), self.m1), "check": lambda: self.f.check(self.m1)}
        workers = {name: threading.Thread(target=lambda name=name, fn=fn: results.update({name: fn()})) for name, fn in calls.items()}
        for worker in workers.values():
            worker.start()
        for name, worker in workers.items():
            worker.join(1)
            self.assertTrue(worker.is_alive(), "%s did not wait for the lock" % name)
        with open(self.state, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self.counter.value(), 1)
        fcntl.flock(lock, fcntl.LOCK_UN)
        for worker in workers.values():
            worker.join(30)
        self.assertEqual(sorted(results), ["accept", "check"])
        self.assertEqual(self.counter.value(), 2)
        with open(self.state) as f:
            self.assertEqual(json.load(f)["envelope"]["heartbeat"]["sequence"], 2)

    def test_live_until_gives_the_reading_and_the_absolute_expiry(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        self.later(600)
        self.assertEqual(self.f.live_until(self.m1), (self.now, T0 + hb.MAX_LIFETIME))
        self.assertEqual(self.f.check(self.m1), T0 + hb.MAX_LIFETIME - self.now)
        self.authenticated = False
        self.refused("time is not authenticated", self.f.live_until, self.m1)

    def test_a_failed_write_leaves_no_temporary_file_and_the_state_as_it_was(self):
        self.f.accept(beat(self.m1, 1), self.m1)
        with open(self.state, "rb") as f:
            before = f.read()
        with unittest.mock.patch.object(hb.os, "fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.f.accept(beat(self.m1, 2), self.m1)
        self.assertEqual([n for n in os.listdir(self.d) if n.startswith(".freshness-")], [])
        with open(self.state, "rb") as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(self.counter.value(), 1)

    def test_the_state_is_durable_before_the_counter_moves(self):
        order = []
        real_fsync, real_advance = os.fsync, self.counter.advance
        self.counter.advance = lambda sequence, allowance=None: (order.append("counter"), real_advance(sequence, allowance))[1]
        with unittest.mock.patch.object(hb.os, "fsync", side_effect=lambda fd: (order.append("dir" if os.path.isdir("/proc/self/fd/%d" % fd) else "file"), real_fsync(fd))[1]):
            self.f.accept(beat(self.m1, 1), self.m1)
        self.assertEqual(order, ["file", "dir", "counter"])


class Decision(Case):
    """hb.authorize: the membership matrix and the freshness, together (PoC 9.1 and 9.3, in software)."""

    def test_poc_9_1_a_revoked_node_is_not_unlocked_by_a_current_peer(self):
        revoked = manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        self.f.accept(beat(revoked, 1), revoked)
        self.refused("a may not be unlocked under epoch 2", hb.authorize, revoked, "b", "a", self.f)
        self.assertGreater(hb.authorize(revoked, "b", "c", self.f), 0)

    def test_poc_9_3_a_revoked_or_non_active_peer_authorizes_nobody(self):
        for state in ("REVOKED_STOLEN", "RETIRED", "QUARANTINED", "MAINTENANCE", "DRAINING"):
            with self.subTest(state=state):
                man = manifest(2, m.digest(self.m1), a=state)
                self.refused("a may not authorize under epoch 2", hb.authorize, man, "a", "b", self.f)
        self.refused("z may not authorize", hb.authorize, self.m1, "z", "a", self.f)
        self.refused("z may not be unlocked", hb.authorize, self.m1, "b", "z", self.f)

    def test_a_node_does_not_authorize_itself_and_an_eligible_pair_still_needs_freshness(self):
        self.refused("no heartbeat is held", hb.authorize, self.m1, "b", "a", self.f)
        self.f.accept(beat(self.m1, 1), self.m1)
        self.refused("a node does not authorize itself", hb.authorize, self.m1, "b", "b", self.f)
        maintenance = manifest(c="MAINTENANCE")
        self.f2 = hb.Freshness(self.counter, lambda: (self.now, True), lambda: self.ticks, self.state)
        self.f2.accept(beat(maintenance, 2), maintenance)
        self.assertGreater(hb.authorize(maintenance, "b", "c", self.f2), 0)   # a node in MAINTENANCE may be unlocked


class OnSwtpm(unittest.TestCase):
    """The real Counter and TpmClock on a software TPM, on a private unix socket. Where the TPM tools are
    provisioned (REGALIA_EXPECT_SWTPM=1: e2e/heartbeat-swtpm.sh, CI) a missing one is a failure, not a skip."""

    def setUp(self):
        if not (shutil.which("swtpm") and shutil.which("tpm2_nvdefine") and shutil.which("tpm2_readclock")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm and tpm2-tools are expected here and were not found")
            self.skipTest("needs swtpm and tpm2-tools")
        self.d = tempfile.mkdtemp(dir="/tmp")   # short: a unix socket path is at most 107 bytes
        self.addCleanup(shutil.rmtree, self.d, True)
        os.mkdir(self.d + "/tpm")
        sock = self.d + "/s"
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d + "/tpm", "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=" + self.d + "/pid"], check=True, capture_output=True)
        time.sleep(0.5)
        with open(self.d + "/pid") as f:
            self.addCleanup(os.kill, int(f.read()), 15)
        self.tcti = "swtpm:path=" + sock
        self.epochs = m.HighWater("0x1500016", lock_path=self.d + "/lock", tcti=self.tcti)    # with its base at 0x1500017
        self.epochs.define()
        self.counter = hb.Counter("0x1500018", lock_path=self.d + "/lock", tcti=self.tcti)    # with its base at 0x1500019
        self.counter.define()
        self.now = T0 + 60
        self.state = self.d + "/freshness.json"
        self.f = hb.Freshness(self.counter, lambda: (self.now, True), simulated_ticks(self, self.tcti), self.state)
        self.m1 = manifest()

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_the_sequence_counter_is_its_own_index_and_refuses_replay_and_rollback(self):
        self.assertEqual(self.counter.value(), 0)
        self.epochs.advance(3)                                  # the epoch counter moves on its own
        self.assertEqual(self.counter.value(), 0)
        self.assertEqual(self.f.accept(beat(self.m1, 1), self.m1), hb.MAX_LIFETIME - 60)
        with open(self.state, "rb") as f:
            snapshot = f.read()
        self.f.accept(beat(self.m1, 4), self.m1)                # a missed heartbeat or two: the counter is raised to 4
        self.assertEqual(self.counter.value(), 4)
        self.assertEqual(self.epochs.value(), 3)
        self.refused("REPLAY: sequence 4 is not above the TPM counter 4", self.f.accept, beat(self.m1, 4), self.m1)
        self.refused("REPLAY", self.f.accept, beat(self.m1, 2), self.m1)
        with open(self.state, "wb") as f:
            f.write(snapshot)                                   # the disk rolled back to heartbeat 1
        self.refused("ROLLBACK: the heartbeat on disk is sequence 1 but the TPM counter is 4", self.f.check, self.m1)
        self.f.accept(beat(self.m1, 5), self.m1)
        self.assertGreater(hb.authorize(self.m1, "b", "a", self.f), 0)

    def test_the_counter_survives_a_tpm_restart_and_cannot_be_rewound_by_deleting_it(self):
        self.f.accept(beat(self.m1, 7), self.m1)
        env = dict(os.environ, TPM2TOOLS_TCTI=self.tcti)
        tpm = lambda *argv: subprocess.run(argv, check=True, capture_output=True, env=env)
        tpm("tpm2_shutdown", "-c")
        tpm("tpm2_startup", "-c")
        self.assertEqual(self.counter.value(), 7)
        tpm("tpm2_nvundefine", "0x1500018", "-C", "o")
        self.refused("fail closed", self.f.check, self.m1)      # no counter: no decision
        self.refused("already exists", self.counter.define)     # the write-once base is still there
        tpm("tpm2_nvdefine", "0x1500018", "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread")
        tpm("tpm2_nvincrement", "0x1500018", "-C", "o")
        self.assertGreaterEqual(self.counter.value(), 7)        # a re-created counter starts above what it held
        self.refused("REPLAY", self.f.accept, beat(self.m1, 3), self.m1)
        self.refused("REPLAY", self.f.accept, beat(self.m1, 7), self.m1)

    def test_the_tpm_clock_runs_forward_and_an_unreachable_tpm_is_a_refusal(self):
        clock = hb.TpmClock(tcti=self.tcti)
        first = clock()
        time.sleep(0.3)
        self.assertGreater(clock(), first)
        self.f.accept(beat(self.m1, 1), self.m1)
        # the real TPM clock behind the floor (the other tests simulate it: see simulated_ticks)
        real = hb.Freshness(self.counter, lambda: (self.now, True), clock, self.d + "/real-clock.json")
        real.accept(beat(self.m1, 2), self.m1)
        self.assertGreater(real.check(self.m1), 0)
        self.now -= 3600
        self.refused("the clock went backwards", real.check, self.m1)
        self.refused("the clock went backwards", self.f.check, self.m1)
        self.refused("the TPM clock cannot be read", hb.TpmClock(tcti="swtpm:path=" + self.d + "/absent"))
        self.refused("fail closed", hb.Counter("0x1500018", lock_path=self.d + "/lock", tcti="swtpm:path=" + self.d + "/absent").value)


if __name__ == "__main__":
    unittest.main()
