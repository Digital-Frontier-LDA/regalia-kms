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
           "underlays": {"a": "192.0.2.11", "b": "192.0.2.12", "c": "192.0.2.13"}, "listen_port": 51821, "sync_port": 7444}
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
    def test_the_interval_has_a_floor_times_the_number_of_authorities(self):
        d = "/nonexistent"
        authority.validate(config(d, interval_s=600))
        with self.assertRaises(m.Refused) as caught:
            authority.validate(config(d, interval_s=900, sequence_stride=2, sequence_offset=1))
        self.assertIn("at least 1200 s", str(caught.exception))
        with self.assertRaises(m.Refused):
            authority.validate(config(d, interval_s=599))

    def test_only_local_root_may_request_and_only_known_signers(self):
        for bad in ({"revoke_requesters": ["anyone"]}, {"revoke_requesters": []}, {"signer": {"kind": "vault"}},
                    {"sequence_offset": 2, "sequence_stride": 2}):
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

    def test_a_crash_after_the_counter_moved_loses_a_number_and_never_reuses_it(self):
        with unittest.mock.patch.object(self.a.signer, "sign", side_effect=OSError("power lost")):
            with self.assertRaises(OSError):
                self.a.beat()
        self.assertEqual((self.a.counter.value(), self.a.held()), (1, None))
        self.assertEqual(self.a.beat()["heartbeat"]["sequence"], 2)

    def test_several_authorities_share_the_sequence_by_offset_and_stride(self):
        second = self.authority(interval_s=1200, sequence_offset=1, sequence_stride=2)
        self.assertEqual([second.beat()["heartbeat"]["sequence"] for _ in range(3)], [1, 3, 5])
        first = self.authority(interval_s=1200, sequence_offset=0, sequence_stride=2)
        self.assertEqual(first.beat()["heartbeat"]["sequence"], 6)

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
            with self.assertRaises(OSError):
                self.a.revoke("b", "QUARANTINED", "suspected tampering", "local-root")
        self.assertEqual((self.a.store.load()["epoch"], self.a.held()["heartbeat"]["epoch"]), (2, 1))
        restarted = self.authority()
        beat = restarted.catch_up()
        self.assertEqual((beat["heartbeat"]["epoch"], beat["heartbeat"]["sequence"]), (2, 2))
        self.assertIsNone(restarted.catch_up())                          # nothing more to do

    def test_unauthenticated_time_signs_no_revocation(self):
        self.authenticated = False
        self.refused("time is not authenticated", self.a.revoke, "c", "QUARANTINED", "x-ray", "local-root")
        self.assertEqual(self.a.store.load()["epoch"], 1)


class CommandLine(Case):
    def test_status_and_revoke(self):
        path = self.d + "/authority.json"
        with open(path, "w") as f:
            json.dump(config(self.d), f)
        with unittest.mock.patch.object(authority, "Authority", lambda cfg: self.a), \
                unittest.mock.patch("sys.stdout") as out:
            self.assertEqual(authority.main(["--config", path, "status"]), 0)
        printed = "".join(c.args[0] for c in out.write.call_args_list)
        self.assertIn('"signer": "file"', printed)
        with unittest.mock.patch.object(authority, "Authority", lambda cfg: self.a), unittest.mock.patch.object(authority.os, "geteuid", return_value=1000), \
                unittest.mock.patch("sys.stderr") as err:
            self.assertEqual(authority.main(["--config", path, "revoke", "--node", "c", "--state", "QUARANTINED", "--reason", "test"]), 2)
        self.assertIn("as root", "".join(c.args[0] for c in err.write.call_args_list))


if __name__ == "__main__":
    unittest.main()
