"""deploy/baremetal/authority.py: the revocation authority's rules, on the fake TPM (#199)."""
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.baremetal import authority, heartbeat as hb, membership as m
import tests.test_baremetal_heartbeat as hbt

T0 = hbt.T0


def config(d, **override):
    cfg = {"schema": authority.SCHEMA, "root_key": hbt.pub(hbt.ROOT), "tcti": None, "nv_epoch": "0x01500016", "nv_sequence": "0x01500020",
           "state_dir": d, "run_dir": d, "signer": {"kind": "file", "path": d + "/revocation.pem"}, "interval_s": 900, "lifetime_s": None,
           "sequence_offset": 0, "sequence_stride": 1, "revoke_requesters": ["local-root"], "wg_service_key": d + "/wg.key",
           "underlays": {"a": "192.0.2.11", "b": "192.0.2.12", "c": "192.0.2.13"}, "listen_port": 51821, "sync_port": 7444,
           "control_socket": d + "/control.sock"}
    cfg.update(override)
    return cfg


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        key = Ed25519PrivateKey.generate()
        with open(self.d + "/revocation.pem", "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(self.d + "/revocation.pem", 0o600)
        self.key = key
        self.tpm = hbt.FakeTpm()
        self.now, self.authenticated = T0, True
        self.events = []
        self.a = self.authority()
        self.m1 = self.manifest()
        self.a.init([m_sign(self.m1)])

    def authority(self, **override):
        return authority.Authority(authority.validate(config(self.d, **override)), clock=lambda: (self.now, self.authenticated),
                                   run=self.tpm, trail=self.events.append)

    def manifest(self):
        man = hbt.manifest()
        man["revocation_keys"] = [self.a.signer.public()]
        return man

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


def m_sign(man, key=None, signer="root"):
    key = key or hbt.ROOT
    return {"manifest": man, "signature": {"signer": signer, "key": hbt.pub(key), "sig": key.sign(m.DOMAIN + m.canonical(man)).hex()}}


class Configuration(unittest.TestCase):
    def test_the_interval_has_a_floor(self):
        d = "/nonexistent"
        authority.validate(config(d, interval_s=600))
        with self.assertRaises(m.Refused):
            authority.validate(config(d, interval_s=599))

    def test_the_anchor_and_the_sequence_counter_take_disjoint_indices(self):
        """#244: the anchor at C takes C, C+1, C+4, C+5; the sequence counter at S takes S, S+1."""
        base = int(config("/x")["nv_epoch"], 16)
        for offset in (-1, 0, 1, 3, 4, 5):
            with self.subTest(offset=offset), self.assertRaises(m.Refused) as caught:
                authority.validate(config("/x", nv_sequence="0x%08x" % (base + offset)))
            self.assertIn("must not overlap", str(caught.exception))
        for offset in (2, 6, 10):
            authority.validate(config("/x", nv_sequence="0x%08x" % (base + offset)))

    def test_one_authority_until_takeover_exists(self):
        with self.assertRaises(m.Refused) as caught:
            authority.validate(config("/x", interval_s=1200, sequence_stride=2, sequence_offset=1))
        self.assertIn("#231", str(caught.exception))

    def test_only_local_root_may_request_and_only_known_signers(self):
        for bad in ({"revoke_requesters": ["anyone"]}, {"revoke_requesters": []}, {"signer": {"kind": "vault"}},
                    {"sequence_offset": 1, "sequence_stride": 1}):
            with self.subTest(bad), self.assertRaises(m.Refused):
                authority.validate(config("/x", **bad))

    def test_a_pkcs11_signer_is_named_and_refused_until_built(self):
        cfg = authority.validate(config("/x", signer={"kind": "pkcs11"}))
        with self.assertRaises(m.Refused) as caught:
            authority.signer_for(cfg)
        self.assertIn("not built yet", str(caught.exception))

    def test_the_key_file_must_be_this_user_s_and_private(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(d + "/k.pem", "wb") as f:
            f.write(Ed25519PrivateKey.generate().private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        os.chmod(d + "/k.pem", 0o644)
        with self.assertRaises(m.Refused):
            authority.FileSigner(d + "/k.pem")
        os.chmod(d + "/k.pem", 0o600)
        os.symlink(d + "/k.pem", d + "/link.pem")
        with self.assertRaises(OSError):
            authority.FileSigner(d + "/link.pem")
        self.assertEqual(authority.FileSigner(d + "/k.pem").kind, "file")


class Heartbeats(Case):
    def test_a_heartbeat_a_node_accepts_with_the_counter_moved_first(self):
        envelope = self.a.beat()
        self.assertEqual((envelope["heartbeat"]["sequence"], self.a.counter.value()), (1, 1))
        self.assertEqual(hb.verify(envelope, self.m1)["epoch"], 1)
        self.assertEqual(self.a.held(), envelope)
        self.assertEqual(os.stat(self.d + "/heartbeat.json").st_mode & 0o777, 0o644)
        # a node takes it
        node_tpm = hbt.FakeTpm()
        counter = hb.Counter("0x1500018", lock_path=self.d + "/node.lock", run=node_tpm)
        counter.define()
        fresh = hb.Freshness(counter, lambda: (self.now + 1, True), lambda: 5000, self.d + "/node-freshness.json")
        self.assertEqual(fresh.accept(envelope, self.m1), hb.MAX_LIFETIME - 1)
        last = self.events[-1]
        self.assertEqual((last["event"], last["sequence"], last["signer"]), ("authority-heartbeat", 1, "file"))
        self.assertEqual(self.a.beat()["heartbeat"]["sequence"], 2)

    def test_unauthenticated_time_signs_nothing_and_moves_nothing(self):
        self.authenticated = False
        self.refused("time is not authenticated", self.a.beat)
        self.assertEqual((self.a.counter.value(), self.a.held()), (0, None))

    def test_a_failure_in_the_signer_spends_its_number_never_signs_it_twice(self):
        """#230 fourth read (regalia-kms-51, the reviewer, and 24's rule): sign() may fail after the token
        signed, so the number is spent the moment it is handed over. One number, at most one signature."""
        with unittest.mock.patch.object(self.a.signer, "sign", side_effect=OSError("token busy")):
            for _ in range(3):
                with self.assertRaises(OSError):
                    self.a.beat()
        self.assertEqual((self.a.counter.value(), self.a.held()), (3, None))
        self.assertEqual(self.a.beat()["heartbeat"]["sequence"], 4)

    def test_a_failure_before_the_signer_reserves_nothing(self):
        self.authenticated = False
        for _ in range(3):
            self.refused("not authenticated", self.a.beat)
        self.assertEqual(self.a.counter.value(), 0)

    def test_a_failure_after_signing_republishes_the_same_bytes(self):
        with unittest.mock.patch.object(authority.Authority, "_publish", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.a.beat()
        with open(self.d + "/pending-heartbeat.json", "rb") as f:
            signed = f.read()
        self.assertEqual(self.a.counter.value(), 1)
        restarted = self.authority()                       # across a restart too
        restarted.beat()
        with open(self.d + "/heartbeat.json", "rb") as f:
            self.assertEqual(f.read(), signed)             # byte for byte: one signature under number 1
        self.assertFalse(os.path.exists(self.d + "/pending-heartbeat.json"))
        self.assertEqual(restarted.counter.value(), 1)

    def test_signed_bytes_that_expire_unpublished_are_dropped_and_the_number_is_lost(self):
        with unittest.mock.patch.object(authority.Authority, "_publish", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.a.beat()
        self.now += hb.MAX_LIFETIME + 1
        self.assertEqual(self.a.beat()["heartbeat"]["sequence"], 2)
        self.assertIn(("authority-heartbeat", "DROPPED"), [(e["event"], e["outcome"]) for e in self.events])

    def test_a_pending_file_that_cannot_be_used_is_dropped_and_serving_goes_on(self):
        """#230 second read (regalia-kms-51): a valid-JSON pending file without its fields crashed every beat."""
        for label, raw in (("fields missing", b'{"heartbeat": {}}'), ("not JSON", b"{"), ("a list", b"[]"), ("another key", None),
                           ("inside the margin", "margin")):
            with self.subTest(label):
                if raw == "margin":                        # genuinely signed, but with less than MIN_INTERVAL_S to live
                    self.a.beat()
                    with open(self.d + "/heartbeat.json", "rb") as f:
                        raw = f.read()
                    self.now += hb.MAX_LIFETIME - hb.MIN_INTERVAL_S + 1
                elif raw is None:
                    stranger = Ed25519PrivateKey.generate()
                    body = {"schema": hb.SCHEMA, "epoch": 1, "sequence": 99, "issued_at": authority.stamp(self.now), "expires_at": authority.stamp(self.now + 3600),
                            "manifest_digest": m.digest(self.m1)}
                    raw = json.dumps(hbt.beat(self.m1, 99, issued=self.now, key=stranger)).encode()
                with open(self.d + "/pending-heartbeat.json", "wb") as f:
                    f.write(raw)
                before = self.a.counter.value()
                envelope = self.a.catch_up()                       # the path serve takes first
                self.assertEqual(envelope["heartbeat"]["sequence"], before + 1)
                self.assertFalse(os.path.exists(self.d + "/pending-heartbeat.json"))
                self.assertEqual(self.events[-2]["outcome"], "DROPPED")

    def test_a_failed_pending_write_never_signs_the_number_again(self):
        real = authority.Authority._write
        calls = {"n": 0}

        def write(this, name, raw, mode):
            if name == authority.PENDING and calls["n"] == 0:
                calls["n"] += 1
                raise OSError("no space left")
            return real(this, name, raw, mode)
        signed = []
        real_sign = self.a.signer.sign
        self.a.signer.sign = lambda message: (signed.append(json.loads(message[len(hb.DOMAIN):])["sequence"]), real_sign(message))[1]
        with unittest.mock.patch.object(authority.Authority, "_write", write):
            with self.assertRaises(OSError):
                self.a.beat()
            self.a.beat()
        self.assertEqual(signed, [1, 2])                   # number 1 lost, never signed twice

    def test_a_signer_failing_for_a_day_reserves_one_number(self):
        clock = {"t": 0.0}
        failing = unittest.mock.patch.object(self.a.signer, "sign", side_effect=OSError("token gone"))
        with failing:
            self.a.run_loop(lambda: clock["t"] > 86400, sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"])
        attempts = sum(1 for e in self.events if e.get("outcome") == "FAILED")
        self.assertEqual(self.a.counter.value(), attempts)                 # one number per handed-over signature
        self.assertLessEqual(attempts, 86400 // 900 + 6)   # backed off to the interval: the nodes' own rate
        self.assertEqual([authority.retry_delay(n, 900) for n in range(6)], [60, 120, 240, 480, 900, 900])

    def test_a_pending_file_that_cannot_be_removed_is_said(self):
        real = os.unlink

        def unlink(path, *a, **k):
            if path.endswith("pending-heartbeat.json"):
                raise PermissionError("read-only")
            return real(path, *a, **k)
        with unittest.mock.patch.object(authority.os, "unlink", unlink):
            self.a.beat()
        self.assertEqual(self.events[-1]["outcome"], "STUCK")

    def test_a_pending_path_that_cannot_be_cleared_stops_signing_before_a_number_is_spent(self):
        os.mkdir(self.d + "/pending-heartbeat.json")          # a directory: unreadable, and not removable by unlink
        for _ in range(3):
            self.refused("cannot be cleared", self.a.beat)
        self.assertEqual(self.a.counter.value(), 0)
        os.rmdir(self.d + "/pending-heartbeat.json")
        self.assertEqual(self.a.beat()["heartbeat"]["sequence"], 1)

    def test_a_pending_file_that_cannot_be_read_is_dropped(self):
        with open(self.d + "/pending-heartbeat.json", "w") as f:
            f.write("{}")
        real = authority.Authority._read

        def read(this, name):
            if name == authority.PENDING:
                raise PermissionError("unreadable")
            return real(this, name)
        with unittest.mock.patch.object(authority.Authority, "_read", read):
            self.assertEqual(self.a.beat()["heartbeat"]["sequence"], 1)
        self.assertIn("DROPPED", [e["outcome"] for e in self.events if e.get("event") == "authority-heartbeat"])

    def test_wake_runs_the_next_beat_at_once(self):
        clock, beats = {"t": 0.0}, []
        self.a.beat = lambda reason="interval": beats.append(clock["t"])
        self.a.catch_up = lambda: None

        def sleep(seconds):
            clock["t"] += seconds
            if clock["t"] == 5:
                self.a.wake.set()                          # a revocation's heartbeat failed: try again now
        self.a.run_loop(lambda: clock["t"] >= 10, sleep=sleep, clock=lambda: clock["t"])
        self.assertEqual(beats, [0.0, 5.0])

    def test_a_key_the_manifest_does_not_name_reserves_nothing(self):
        stranger = authority.FileSigner(self.d + "/revocation.pem")
        stranger._key = Ed25519PrivateKey.generate()
        a = authority.Authority(authority.validate(config(self.d)), signer=stranger, clock=lambda: (self.now, True), run=self.tpm, trail=self.events.append)
        for _ in range(5):
            self.refused("is not named by the manifest", a.beat)
        self.assertEqual(a.counter.value(), 0)

    def test_the_interval_is_at_most_a_quarter_of_the_lifetime(self):
        short = self.authority(lifetime_s=3600, interval_s=1200)
        self.refused("more than a quarter of the heartbeat lifetime", short.beat)
        self.assertEqual(short.counter.value(), 0)
        self.assertEqual(self.authority(lifetime_s=3600, interval_s=900).beat()["heartbeat"]["expires_at"], authority.stamp(T0 + 3600))

    def test_status_names_the_signer_kind(self):
        self.a.beat()
        status = self.a.status()
        self.assertEqual((status["signer"], status["epoch"], status["sequence"], status["heartbeat"]["sequence"]), ("file", 1, 1, 1))


class Revocation(Case):
    def test_a_revocation_is_signed_committed_and_followed_at_once_by_its_heartbeat(self):
        self.a.beat()
        envelope, beat = self.a.revoke("c", "REVOKED_STOLEN", "stolen from site c", "local-root")
        manifest = envelope["manifest"]
        self.assertEqual((manifest["epoch"], envelope["signature"]["signer"]), (2, "revocation"))
        self.assertEqual([n["state"] for n in manifest["nodes"]], ["ACTIVE", "ACTIVE", "REVOKED_STOLEN"])
        self.assertEqual((beat["heartbeat"]["epoch"], beat["heartbeat"]["sequence"]), (2, 2))
        # a peer's store takes the chain as it would from the authority
        anchor = m.HighWater("0x1500016", lock_path=self.d + "/peer.lock", run=hbt.FakeTpm())
        anchor.define()
        peer = m.Store(self.d + "/peer.json", hbt.pub(hbt.ROOT), anchor)
        for e in self.a.store.envelopes(0):
            peer.commit(e)
        self.assertEqual(peer.load()["epoch"], 2)
        kinds = [(e["event"], e.get("node"), e.get("signer")) for e in self.events[-2:]]
        self.assertEqual(kinds, [("authority-revoke", "c", "file"), ("authority-heartbeat", None, "file")])

    def test_only_restrictive_changes_by_a_permitted_requester(self):
        self.refused("anything else is the root's", self.a.revoke, "c", "ACTIVE", "reinstating", "local-root")
        self.refused("may not request a revocation", self.a.revoke, "c", "QUARANTINED", "by mail", "someone")
        self.refused("is not in the manifest", self.a.revoke, "z", "QUARANTINED", "unknown", "local-root")
        self.a.revoke("c", "REVOKED_STOLEN", "stolen", "local-root")
        self.refused("already REVOKED_STOLEN", self.a.revoke, "c", "QUARANTINED", "again", "local-root")
        self.assertEqual(self.a.store.load()["epoch"], 2)

    def test_a_crash_between_the_revocation_and_its_heartbeat_is_finished_at_the_next_start(self):
        """#199 (regalia-kms-24): the manifest is committed, the process stops before the heartbeat. On
        restart the authority still publishes the new epoch, with a higher sequence."""
        self.a.beat()
        with unittest.mock.patch.object(authority.Authority, "beat", side_effect=OSError("power lost")):
            with self.assertRaises(authority.Committed) as caught:          # committed, heartbeat not yet out
                self.a.revoke("b", "QUARANTINED", "suspected tampering", "local-root")
        self.assertEqual(caught.exception.epoch, 2)
        self.assertEqual((self.a.store.load()["epoch"], self.a.held()["heartbeat"]["epoch"]), (2, 1))
        restarted = self.authority()
        beat = restarted.catch_up()
        self.assertEqual((beat["heartbeat"]["epoch"], beat["heartbeat"]["sequence"]), (2, 2))
        self.assertIsNone(restarted.catch_up())                          # nothing more to do

    def test_a_revocation_drops_pending_bytes_for_the_old_epoch(self):
        with unittest.mock.patch.object(authority.Authority, "_publish", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.a.beat()                              # epoch 1, number 1: signed, not published
        _, beat = self.a.revoke("c", "REVOKED_STOLEN", "stolen", "local-root")
        self.assertEqual((beat["heartbeat"]["epoch"], beat["heartbeat"]["sequence"]), (2, 2))
        self.assertEqual(self.a.held()["heartbeat"]["epoch"], 2)
        self.a.beat()
        self.assertEqual(self.a.held()["heartbeat"]["epoch"], 2)          # the old bytes never go out

    def test_a_beat_in_flight_cannot_publish_after_the_revocation(self):
        import threading
        signing, release, published = threading.Event(), threading.Event(), []
        real_sign, real_publish = self.a.signer.sign, self.a._publish

        def slow_sign(message):
            if not signing.is_set():
                signing.set()
                release.wait(10)
            return real_sign(message)
        self.a.signer.sign = slow_sign
        self.a._publish = lambda raw: (published.append((json.loads(raw)["heartbeat"]["epoch"], json.loads(raw)["heartbeat"]["sequence"])), real_publish(raw))
        first = threading.Thread(target=self.a.beat)
        first.start()
        signing.wait(10)
        second = threading.Thread(target=self.a.revoke, args=("c", "REVOKED_STOLEN", "stolen", "local-root"))
        second.start()
        second.join(1)                                     # the revocation finishes, or (correctly) waits for the beat
        release.set()
        first.join(10)
        second.join(10)
        self.assertEqual([epoch for epoch, _ in published], [1, 2])
        self.assertEqual([sequence for _, sequence in published], [1, 2])          # never two signatures under one number
        self.assertEqual(self.a.held()["heartbeat"]["epoch"], 2)

    def test_a_revocation_committed_but_not_published_says_so(self):
        with unittest.mock.patch.object(authority.Authority, "_publish", side_effect=KeyError("anything at all")):
            answer = self.a.control(json.dumps({"op": "revoke", "node": "c", "state": "QUARANTINED", "reason": "half done"}).encode(), 0)
        self.assertEqual((answer["ok"], answer["epoch"], answer["published"]), (True, 2, False))
        self.assertTrue(self.a.wake.is_set())                  # serve tries again at once
        self.assertIn("the next beat will", answer["reason"])
        self.assertEqual(self.a.catch_up()["heartbeat"]["epoch"], 2)

    def test_a_trail_that_fails_after_the_commit_still_reports_committed(self):
        calls = {"n": 0}
        real = self.a.trail

        def trail(event):
            if event.get("event") == "authority-revoke":
                raise OSError("disk full")
            return real(event)
        self.a.trail = trail
        with self.assertRaises(authority.Committed):
            self.a.revoke("c", "QUARANTINED", "trail full", "local-root")
        self.assertEqual(self.a.store.load()["epoch"], 2)
        self.assertTrue(self.a.wake.is_set())

    def test_unauthenticated_time_signs_no_revocation(self):
        self.authenticated = False
        self.refused("time is not authenticated", self.a.revoke, "c", "QUARANTINED", "x-ray", "local-root")
        self.assertEqual(self.a.store.load()["epoch"], 1)


class TunnelApply(Case):
    """wg-apply runs as root with CAP_NET_ADMIN (CodeRabbit on #230): it must not load the revocation key
    (whose owner check refuses root) nor create anything in the service's state directory."""

    def test_it_reads_the_chain_as_a_reader_and_never_builds_the_authority(self):
        before = set(os.listdir(self.d))
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            if argv[0].startswith("tpm2_"):
                return self.tpm(argv, **kw)
            if argv[:2] == ["wg", "pubkey"]:
                return unittest.mock.Mock(returncode=0, stdout=b"AAAA" * 10 + b"AAA=\n")
            return unittest.mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with unittest.mock.patch.object(authority, "Authority", side_effect=AssertionError("wg-apply built the Authority")), \
                unittest.mock.patch.object(authority, "signer_for", side_effect=AssertionError("wg-apply loaded the key")), \
                unittest.mock.patch.object(authority.wgsvc, "reconcile", return_value="fd72::1") as reconcile:
            with open(self.d + "/wg.key", "w") as f:
                f.write("x\n")
            self.assertEqual(authority.wg_apply(authority.validate(config(self.d)), run), "fd72::1")
        self.assertEqual(reconcile.call_args.args[0]["epoch"], 1)
        self.assertEqual(set(os.listdir(self.d)) - before, {"wg.key"})       # no lock file, nothing else

    def test_a_fork_the_tpm_never_recorded_is_refused(self):
        fork = dict(self.m1, issued_at="2026-09-30T00:00:00Z")
        with open(self.d + "/membership.json", "wb") as f:
            f.write(m.canonical([m_sign(fork)]))
        self.refused("CONFLICT", authority.held_chain, authority.validate(config(self.d)), self.tpm)


class Control(Case):
    def test_root_only_and_the_requests_it_answers(self):
        refused = self.a.control(b'{"op":"status"}', peer_uid=1000)
        self.assertEqual(refused, {"ok": False, "refused": "only root on this host may ask"})
        self.assertEqual(self.a.control(b'{"op":"status"}', peer_uid=0)["status"]["signer"], "file")
        answer = self.a.control(json.dumps({"op": "revoke", "node": "c", "state": "QUARANTINED", "reason": "over the socket"}).encode(), 0)
        self.assertEqual((answer["ok"], answer["epoch"]), (True, 2))
        self.assertFalse(self.a.control(b'{"op":"revoke","node":"c","state":"ACTIVE","reason":"no"}', 0)["ok"])
        self.assertFalse(self.a.control(b'{"op":"rotate"}', 0)["ok"])

    def test_a_request_that_breaks_the_handler_does_not_take_the_socket_down(self):
        stop = []
        thread = self.a.control_listener(lambda: bool(stop), allowed_uid=os.getuid())
        self.addCleanup(lambda: (stop.append(True), thread.join(5)))
        answer = authority.ask(self.d + "/control.sock", {"op": "revoke", "node": ["c"], "state": "QUARANTINED", "reason": "list"})
        self.assertEqual((answer["ok"], answer["refused"]), (False, "node, state and reason must be strings"))
        with unittest.mock.patch.object(authority.Authority, "status", side_effect=TypeError("unexpected")):
            self.assertIn("internal error (TypeError)", authority.ask(self.d + "/control.sock", {"op": "status"})["refused"])
        self.assertTrue(authority.ask(self.d + "/control.sock", {"op": "status"})["ok"])       # still answering

    def test_over_a_real_socket_with_the_peer_s_credentials(self):
        stop = []
        thread = self.a.control_listener(lambda: bool(stop), allowed_uid=os.getuid())
        self.addCleanup(lambda: (stop.append(True), thread.join(5)))
        self.assertEqual(os.stat(self.d + "/control.sock").st_mode & 0o777, 0o600)
        self.assertEqual(authority.ask(self.d + "/control.sock", {"op": "status"})["status"]["epoch"], 1)
        answer = authority.ask(self.d + "/control.sock", {"op": "revoke", "node": "b", "state": "QUARANTINED", "reason": "socket"})
        self.assertEqual((answer["ok"], answer["sequence"]), (True, 1))
        stop.append(True)
        thread.join(5)
        other = self.a.control_listener(lambda: False, allowed_uid=os.getuid() + 1)
        self.assertFalse(authority.ask(self.d + "/control.sock", {"op": "status"})["ok"])


class CommandLine(Case):
    def path(self):
        path = self.d + "/authority.json"
        with open(path, "w") as f:
            json.dump(config(self.d), f)
        return path

    def run_main(self, *argv):
        with unittest.mock.patch("sys.stdout") as out, unittest.mock.patch("sys.stderr") as err:
            code = authority.main(["--config", self.path()] + list(argv))
        return code, "".join(c.args[0] for c in out.write.call_args_list), "".join(c.args[0] for c in err.write.call_args_list)

    def test_revoke_and_status_are_root_only_clients_of_serve(self):
        with unittest.mock.patch.object(authority.os, "geteuid", return_value=1000):
            code, _, err = self.run_main("revoke", "--node", "c", "--state", "QUARANTINED", "--reason", "test")
        self.assertEqual(code, 2)
        self.assertIn("as root", err)
        with unittest.mock.patch.object(authority.os, "geteuid", return_value=0), \
                unittest.mock.patch.object(authority, "ask", return_value={"ok": True, "status": {"signer": "file"}}) as asked:
            code, out, _ = self.run_main("status")
        self.assertEqual((code, asked.call_args.args[1]), (0, {"op": "status"}))
        self.assertIn('"signer": "file"', out)

    def test_one_writer_init_and_accept_are_refused_while_serve_holds_the_lock(self):
        with open(self.d + "/chain.json", "w") as f:
            json.dump([m_sign(self.m1)], f)
        held = authority.one_writer(self.d)                    # what serve holds while it runs
        self.addCleanup(os.close, held)
        code, _, err = self.run_main("accept", "--chain", self.d + "/chain.json")
        self.assertEqual(code, 2)
        self.assertIn("another writer holds", err)
        self.refused("another writer holds", authority.one_writer, self.d)

    def test_the_writer_lock_must_be_this_user_s_regular_file(self):
        os.mkfifo(self.d + "/writer.lock")
        self.refused("not this user's regular file", authority.one_writer, self.d)
        os.unlink(self.d + "/writer.lock")
        open(self.d + "/writer.lock", "w").close()
        with unittest.mock.patch.object(authority.os, "geteuid", return_value=os.getuid() + 1):
            self.refused("not this user's regular file", authority.one_writer, self.d)        # e.g. root's, from an older run

    def test_the_writer_lock_follows_no_link_and_serve_holds_it(self):
        os.symlink(self.d + "/elsewhere", self.d + "/writer.lock")
        with self.assertRaises(OSError):
            authority.one_writer(self.d)
        self.assertFalse(os.path.exists(self.d + "/elsewhere"))           # nothing created through the link
        os.unlink(self.d + "/writer.lock")
        seen = {}

        class Serving:
            def __init__(self, cfg):
                pass

            def serve(self, stop):
                try:
                    authority.one_writer(seen.setdefault("dir", self_dir))
                    seen["second"] = "got the lock"
                except m.Refused:
                    seen["second"] = "refused"
        self_dir = self.d
        with unittest.mock.patch.object(authority, "Authority", Serving):
            code, _, _ = self.run_main("serve")
        self.assertEqual((code, seen["second"]), (0, "refused"))

    def test_init_and_accept_only_as_the_service_s_own_user(self):
        with open(self.d + "/chain.json", "w") as f:
            json.dump([m_sign(self.m1)], f)
        with unittest.mock.patch.object(authority.os, "geteuid", return_value=os.getuid() + 1):
            code, _, err = self.run_main("accept", "--chain", self.d + "/chain.json")
        self.assertEqual(code, 2)
        self.assertIn("run as the authority's own user", err)


if __name__ == "__main__":
    unittest.main()
