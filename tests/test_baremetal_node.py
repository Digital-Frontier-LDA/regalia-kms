"""deploy/baremetal/node.py (#80, step 3b): the node's four services assembled from one configuration.

The TPM, wg and ip are fakes here (hbt.FakeTpm and a recorder). The units that run these under a real
systemd, and the end-to-end run, are the next step."""
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import unittest.mock

from deploy.baremetal import membership as m
from deploy.baremetal import node, sitecfg, wgsvc
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_replacement as rt

ROOT = hbt.pub(hbt.ROOT)
SITE = {"schema": sitecfg.SCHEMA, "site": "site-a", "host_ipv4": "192.0.2.10", "kms_port": 8443, "ssh_port": 22,
        "client_cidrs": ["198.51.100.0/24"], "monitoring_cidrs": ["203.0.113.128/32"], "admin_cidrs": ["203.0.113.0/28"],
        "outbound": [{"name": "audit", "cidr": "203.0.113.192/32", "proto": "tcp", "port": 6514},
                     {"name": "ntp", "cidr": "203.0.113.193/32", "proto": "udp", "port": 123}],
        "boot_mesh": {"node_id": "a", "interface": "wg-unlock", "listen_port": 51820, "address": "10.89.0.1", "unlock_port": 7443,
                      "peers": [{"node_id": "b", "underlay": "192.0.2.20", "address": "10.89.0.2"},
                                {"node_id": "c", "underlay": "192.0.2.30", "address": "10.89.0.3"}]},
        "service_mesh": {"interface": "wg-svc", "listen_port": 51821, "sync_port": 7444,
                         "authority": {"key": "5e" * 32, "underlay": "192.0.2.50", "port": 51821}}}
PRIVATE = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        for sub in ("state", "admission", "run", "etc"):
            os.mkdir(os.path.join(self.d, sub), 0o755)
        with open(os.path.join(self.d, "etc", "site.json"), "w") as f:
            json.dump(SITE, f)
        with open(os.path.join(self.d, "etc", "wg-service.key"), "w") as f:
            f.write(PRIVATE + "\n")
        self.cfg = {"schema": node.SCHEMA, "node_id": "a", "site": self.d + "/etc/site.json", "root_key": ROOT, "tcti": None,
                    "nv_epoch": "0x01500016", "nv_heartbeat": "0x01500018", "state_dir": self.d + "/state", "admission_dir": self.d + "/admission", "run_dir": self.d + "/run",
                    "wg_service_key": self.d + "/etc/wg-service.key", "measurements": self.d + "/etc/measurements.json",
                    "pcrs": [7, 11], "time_servers": ["nts.netnod.se", "ptbtime1.ptb.de", "time.cloudflare.com"], "pull_interval": 60}
        self.tpm = hbt.FakeTpm()
        self.m1 = hbt.manifest()
        self.e1 = rt.sign(self.m1)

    def node(self, run=None, **change):
        return node.Node(dict(self.cfg, **change), run=run or self.tpm)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Configuration(Case):
    def test_the_configuration_is_exact(self):
        self.assertEqual(node.validate(dict(self.cfg)), self.cfg)
        path = os.path.join(self.d, "etc", "node.json")
        with open(path, "w") as f:
            json.dump(self.cfg, f)
        self.assertEqual(node.load(path)["node_id"], "a")
        for label, change, reason in (
                ("an unknown field", {"more": 1}, "node configuration fields mismatch"),
                ("another schema", {"schema": "regalia.node/v2"}, "schema must be regalia.node/v1"),
                ("a node ID in capitals", {"node_id": "A"}, "node_id is not a node ID"),
                ("a root key in capitals", {"root_key": ROOT.upper()}, "root_key"),
                ("a TCTI with a space", {"tcti": "swtpm:path=/x y"}, "tcti must be null"),
                ("an NV index of the wrong range", {"nv_epoch": "0x81000001"}, "nv_epoch must be an NV index"),
                ("an NV index in capitals", {"nv_heartbeat": "0x0150001A"}, "nv_heartbeat must be an NV index"),
                ("overlapping indices", {"nv_heartbeat": "0x01500017"}, "must not overlap"),
                ("a relative path", {"state_dir": "state"}, "state_dir must be an absolute, normalised path"),
                ("one directory for two writers", {"admission_dir": "/x", "state_dir": "/x"}, "must be three directories"),
                ("a path with ..", {"site": "/etc/regalia/../shadow"}, "site must be an absolute, normalised path"),
                ("no PCRs", {"pcrs": []}, "pcrs must be"), ("PCRs out of order", {"pcrs": [11, 7]}, "pcrs must be"),
                ("a PCR as true", {"pcrs": [True]}, "pcrs must be"), ("PCR 24", {"pcrs": [24]}, "pcrs must be"),
                ("one time server", {"time_servers": ["nts.netnod.se"]}, "at least 2 NTS servers"),
                ("a pull every second", {"pull_interval": 1}, "pull_interval must be 10 to 3600"),
                ("a pull interval as text", {"pull_interval": "60"}, "pull_interval must be 10 to 3600")):
            with self.subTest(label):
                self.refused(reason, node.validate, dict(self.cfg, **change))

    def test_the_node_needs_both_meshes_and_its_own_site_configuration(self):
        self.assertEqual(self.node().site["service_mesh"]["sync_port"], 7444)
        for label, site, reason in (("no service mesh", dict(SITE, service_mesh=None), "no boot_mesh or no service_mesh"),
                                    ("another node's site", dict(SITE, boot_mesh=dict(SITE["boot_mesh"], node_id="z")), "the site configuration is z's")):
            with self.subTest(label):
                with open(self.cfg["site"], "w") as f:
                    json.dump(site, f)
                self.refused(reason, self.node)

    def test_the_sources_are_the_peers_and_the_authority_at_their_tunnel_addresses(self):
        n = self.node()
        peers = n.peers(self.m1)
        self.assertEqual(peers, {"b": wgsvc.address(self.m1["nodes"][1]["wg_service_pub"]), "c": wgsvc.address(self.m1["nodes"][2]["wg_service_pub"])})
        self.assertEqual(sorted(n.sources(self.m1)), ["@authority", "b", "c"])
        self.assertEqual(sorted(n.peers(hbt.manifest(c="REVOKED_STOLEN"))), ["b"])          # a terminal node is nobody's source
        self.refused("is not in the manifest", n.own_address, dict(self.m1, nodes=self.m1["nodes"][1:]))


class Publishing(Case):
    """sync owns the store; the root services read a published copy and verify it themselves."""

    def store(self, n):
        anchor = n.anchor()
        anchor.define()
        return m.Store(n.path("membership.json"), ROOT, anchor)

    def test_the_published_chain_is_verified_by_its_reader(self):
        n = self.node()
        store = self.store(n)
        store.commit(self.e1)
        self.assertEqual(node.publish(store, n.path(node.PUBLISHED)), self.m1)
        self.assertEqual(stat.S_IMODE(os.stat(n.path(node.PUBLISHED)).st_mode), 0o644)
        self.assertEqual(n.manifest(), self.m1)
        e2 = rt.sign(hbt.manifest(2, m.digest(self.m1), a="REVOKED_STOLEN"))
        store.commit(e2)                                                           # the anchor moves to 2 before it is published:
        self.refused("ROLLBACK", n.manifest, patience=0)                           # a reader in between refuses, rather than read the old one
        import threading
        late = threading.Timer(0.3, node.publish, (store, n.path(node.PUBLISHED)))
        late.start()                                                               # published a moment later, as sync does
        self.assertEqual(n.manifest(patience=5, step=0.05)["epoch"], 2)            # and the reader waited for it
        late.join()

    def test_a_sync_that_withholds_or_rolls_back_stops_the_node_rather_than_misleading_it(self):
        n = self.node()
        store = self.store(n)
        store.commit(self.e1)
        node.publish(store, n.path(node.PUBLISHED))
        old = open(n.path(node.PUBLISHED), "rb").read()
        store.commit(rt.sign(hbt.manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")))   # the anchor moves to 2
        self.refused("ROLLBACK: the published chain ends at epoch 1, below the TPM anchor 2", n.manifest, patience=0.2, step=0.05)   # withheld
        node.publish(store, n.path(node.PUBLISHED))
        with open(n.path(node.PUBLISHED), "wb") as f:
            f.write(old)                                                           # rolled back
        self.refused("ROLLBACK", n.manifest, patience=0.2, step=0.05)

    def test_a_published_chain_that_is_not_the_root_s_is_refused(self):
        n = self.node()
        self.store(n)
        path = n.path(node.PUBLISHED)
        for label, raw, reason in (("absent", None, "cannot be read (FileNotFoundError)"), ("empty", b"[]", "is empty"),
                                   ("not a list", b"{}", "is empty"), ("not JSON", b"chain", "not valid JSON"),
                                   ("signed by a stranger", m.canonical([rt.sign(self.m1, hbt.OTHER)]), "signature"),
                                   ("a chain that starts at epoch 2", m.canonical([rt.sign(hbt.manifest(2, m.digest(self.m1)))]), "")):
            with self.subTest(label):
                if raw is None:
                    with __import__("contextlib").suppress(FileNotFoundError):
                        os.unlink(path)
                else:
                    with open(path, "wb") as f:
                        f.write(raw)
                with self.assertRaises(m.Refused) as caught:
                    n.manifest()
                self.assertIn(reason, str(caught.exception))

    def test_publishing_is_complete_or_not_at_all(self):
        n = self.node()
        store = self.store(n)
        store.commit(self.e1)
        node.publish(store, n.path(node.PUBLISHED))
        before = open(n.path(node.PUBLISHED), "rb").read()
        with unittest.mock.patch.object(node.os, "replace", side_effect=OSError("no rename")):
            with self.assertRaises(OSError):
                node.publish(store, n.path(node.PUBLISHED))
        self.assertEqual((open(n.path(node.PUBLISHED), "rb").read(), [f for f in os.listdir(n.state) if f.startswith(".chain-")]), (before, []))


class BootSession(Case):
    def run_dir(self):
        return self.cfg["run_dir"]

    def test_the_unlock_client_s_session_is_used_as_it_left_it(self):
        with open(self.run_dir() + "/boot-session.pub", "w") as f:
            f.write("30" * 300 + "\n")
        with open(self.run_dir() + "/boot-session", "w") as f:
            f.write("ab" * 32 + "\n")
        self.assertEqual(node.boot_session(self.run_dir()), ("ab" * 32, bytes.fromhex("30" * 300)))

    def test_with_no_session_this_boot_one_is_made_and_written_as_the_unlock_client_would(self):
        session, public = node.boot_session(self.run_dir(), rand=lambda n: b"\x07" * n)
        self.assertEqual(session, "07" * 32)
        self.assertTrue(public.startswith(b"regalia-kms runtime session "))
        self.assertEqual(node.boot_session(self.run_dir()), (session, public))      # the next start finds it
        for name in ("boot-session", "boot-session.pub"):
            self.assertEqual(stat.S_IMODE(os.stat(self.run_dir() + "/" + name).st_mode), 0o644)
        # a lone key (the unlock client died between its two writes) means nothing was presented: a session is made
        os.unlink(self.run_dir() + "/boot-session")
        self.assertEqual(node.boot_session(self.run_dir(), rand=lambda n: b"\x09" * n)[0], "09" * 32)

    def test_a_session_whose_key_is_missing_or_malformed_is_refused_not_guessed(self):
        node.boot_session(self.run_dir())
        os.unlink(self.run_dir() + "/boot-session.pub")
        self.refused("whose key is missing", node.boot_session, self.run_dir())
        for marker, key, reason in (("AB" * 32 + "\n", "30\n", "boot-session is malformed"), ("ab" * 32, "30\n", "boot-session is malformed"),
                                    ("ab" * 31 + "\n", "30\n", "boot-session is malformed"), ("ab" * 32 + "\n", "\n", "boot-session.pub is malformed"),
                                    ("ab" * 32 + "\n", "3\n", "boot-session.pub is malformed"), ("ab" * 32 + "\n", "30" * 513 + "\n", "boot-session.pub is malformed")):
            with self.subTest(marker=marker[:6], key=key[:6]):
                with open(self.run_dir() + "/boot-session", "w") as f:
                    f.write(marker)
                with open(self.run_dir() + "/boot-session.pub", "w") as f:
                    f.write(key)
                self.refused(reason, node.boot_session, self.run_dir())


class Applying(Case):
    def test_both_tunnels_are_made_what_the_manifest_says(self):
        class Host:
            def __init__(self, tpm):
                self.tpm, self.calls, self.inputs = tpm, [], []

            def __call__(self, argv, **kw):
                if argv[0].startswith("tpm2_"):
                    return self.tpm(argv, **kw)
                self.calls.append(argv)
                self.inputs.append(kw.get("input"))
                if argv[:3] == ["wg", "show", "wg-svc"]:
                    peers = [n["wg_service_pub"] for n in hbt.manifest()["nodes"] if n["node_id"] != "a"] + ["5e" * 32]
                    return subprocess.CompletedProcess(argv, 0, "".join("%s\t%s/128\n" % (wgsvc.wg_key(k), wgsvc.address(k)) for k in peers).encode(), b"")
                if argv[:3] == ["ip", "link", "show"]:
                    return subprocess.CompletedProcess(argv, 1, b"", b"")
                return subprocess.CompletedProcess(argv, 0, b"", b"")
        host = Host(self.tpm)
        n = self.node(run=host)
        anchor = n.anchor()
        anchor.define()
        store = m.Store(n.path("membership.json"), ROOT, anchor)
        store.commit(self.e1)
        node.publish(store, n.path(node.PUBLISHED))
        self.assertEqual(node.wg_apply(n), 1)
        unlock_calls = [c for c in host.calls if "wg-unlock" in c]
        self.assertIn(["ip", "link", "add", "dev", "wg-unlock", "type", "wireguard"], unlock_calls)
        self.assertIn(["ip", "route", "replace", "10.89.0.2/32", "dev", "wg-unlock"], unlock_calls)
        syncconf = host.calls.index(["wg", "syncconf", "wg-unlock", "/dev/stdin"])
        self.assertTrue(host.inputs[syncconf].decode().startswith("[Interface]\nPrivateKey = %s\n" % PRIVATE))
        self.assertNotIn(["ip", "link", "set", "dev", "wg-unlock", "down"], host.calls)
        # wg-unlock is brought up only after its peers are applied
        self.assertLess(unlock_calls.index(["wg", "syncconf", "wg-unlock", "/dev/stdin"]), unlock_calls.index(["ip", "link", "set", "dev", "wg-unlock", "up"]))


class Trail(Case):
    def test_events_are_appended_one_a_line_and_the_file_is_the_owner_s(self):
        trail = node.Trail(self.cfg["state_dir"] + "/audit.jsonl")
        trail({"event": "sync-pull", "outcome": "ALLOW"})
        trail({"event": "sync-pull", "outcome": "DENY"})
        lines = [json.loads(line) for line in open(self.cfg["state_dir"] + "/audit.jsonl")]
        self.assertEqual([(e["event"], e["outcome"]) for e in lines], [("sync-pull", "ALLOW"), ("sync-pull", "DENY")])
        self.assertTrue(all(isinstance(e["at"], int) for e in lines))
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg["state_dir"] + "/audit.jsonl").st_mode), 0o600)
        with self.assertRaises(OSError):
            node.Trail(self.d + "/nowhere/audit.jsonl")({"event": "x"})              # a trail that cannot be written raises


if __name__ == "__main__":
    unittest.main()
