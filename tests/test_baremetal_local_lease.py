"""regalia-kms-41n: under single-node the node's own lease is issued by its regalia-sync (sync.LocalServer: lease.issue_self
with sync's own heartbeat state, TPM signer, RevisionFloor and self-attest verifier, as a peer's sync issues one under
multi-node), and its regalia-admission asks for it over sync's local lease listener (sync.LEASE_SOCKET) the way it asks
a peer. dx7.3 had admission issue it, and admission cannot write sync's state (EACCES on attest-self.json.lock, then on
freshness.json.lock: the one-node scenario's first CI runs, dx7.10). Held here:

  * the listener answers only regalia-admission's uid and root's (SO_PEERCRED; root: the operator's update quote-for-owner
    and promote, dx7.10.2), only lease-nonce and lease, only under single-node;
  * the lease is lease.issue_self with sync's OWN freshness, signer and floor (fed at the request);
  * the socket is bound under umask 0177, then 0666, in a directory only regalia-sync can write, or not at all;
  * admission builds no issuer part of its own under single-node, and asks its own sync;
  * the shipped units are unchanged in what admission may write, and no AppArmor profile confines either service."""
import configparser
import json
import os
import pathlib
import shutil
import socket
import stat
import tempfile
import threading
import unittest
from unittest import mock

from deploy.baremetal import membership as m
from deploy.baremetal import sync
from tests.test_baremetal_membership_v4 import manifest4
from tests.test_baremetal_membership_v5 import one, single5

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNITS = ROOT / "deploy" / "baremetal" / "units"
ADMISSION_UID = 1234
EVIDENCE = {field: "ee" for field in sync.EVIDENCE_FIELDS}
REQUEST = {"node_id": "a", "nonce": "11" * 32}


def three():
    return manifest4(1, "", [one("a", i=0), one("b", i=1), one("c", i=2)])


def ask(op, **fields):
    return m.canonical(dict({"v": sync.VERSION, "op": op}, **fields))


class Local(unittest.TestCase):
    def setUp(self):
        self.manifest, self.trail, self.issued, self.fed = single5(1, ""), [], [], []
        self.verifier = mock.Mock()
        self.verifier.nonce.return_value = b"\x22" * 32
        self.attested = []
        # the store as a request's view reads it (sync._View: the chain, once)
        store = mock.Mock(envelopes=lambda after=0: [{"manifest": self.manifest}], load=lambda: self.manifest)
        self.server = sync.LocalServer("a", store, mock.Mock(name="sync's freshness"),
                                       lambda manifest: self.attested.append(manifest["epoch"]) or self.verifier,
                                       mock.Mock(name="sync's signer"), self.trail.append, admission_uid=ADMISSION_UID,
                                       floor=mock.Mock(applied=lambda *a: self.fed.append(a)), applied=lambda: ("c1" * 8, 1, 7))

        def issue_self(manifest, node_id, request, attester, evidence, freshness, signer, floor):
            self.issued.append((manifest["epoch"], node_id, request, attester, evidence, freshness, signer, floor))
            return "its own lease"
        for patcher in (mock.patch.object(sync.lease, "issue_self", issue_self), mock.patch.object(sync.lease, "validate_request"),
                        mock.patch.object(sync.lease, "issue", side_effect=AssertionError("a peer's lease was issued"))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def answer(self, raw, uid=ADMISSION_UID):
        return json.loads(self.server.handle(raw, sync.local_source(uid)))


class TheLease(Local):
    def test_its_own_admission_gets_a_nonce_then_its_own_lease_from_sync_s_own_parts(self):
        self.assertEqual(self.answer(ask("lease-nonce", node_id="a")), {"v": 1, "ok": True, "nonce": "22" * 32})
        self.assertEqual(self.answer(ask("lease", request=REQUEST, evidence=EVIDENCE)), {"v": 1, "ok": True, "lease": "its own lease"})
        (epoch, node_id, request, attester, evidence, freshness, signer, floor), = self.issued
        self.assertEqual((epoch, node_id, request, evidence), (1, "a", REQUEST, EVIDENCE))
        self.assertIs(attester, self.verifier)                 # the self-attest verifier, by the manifest held then
        self.assertIs(freshness, self.server.freshness)        # sync's OWN heartbeat state: the freshness check is not dropped
        self.assertIs(signer, self.server.signer)
        self.assertIs(floor, self.server.floor)
        self.assertEqual(self.fed, [("c1" * 8, 1, 7)])         # the floor fed at the request (D32), as for a peer's lease
        self.assertEqual([(e["event"], e["subject"], e["outcome"]) for e in self.trail], [("sync-lease-nonce", "a", "ALLOW"),
                                                                                        ("sync-lease", "a", "ALLOW")])

    def test_another_uid_is_told_refused_and_nothing_is_read_or_issued(self):
        for op, fields in (("lease-nonce", {"node_id": "a"}), ("lease", {"request": REQUEST, "evidence": EVIDENCE})):
            with self.subTest(op=op):
                self.assertEqual(self.answer(ask(op, **fields), uid=ADMISSION_UID + 1), {"v": 1, "ok": False, "refused": "refused"})
        self.assertEqual((self.issued, self.attested), ([], []))
        self.assertIn("uid:%d is not regalia-admission" % (ADMISSION_UID + 1), self.trail[-1]["reason"])

    def test_root_the_operator_s_update_gets_the_node_s_own_lease_too(self):
        """regalia-kms-dx7.10.2: update quote-for-owner and promote run as root and prove the serving path up by the
        node's own lease for this boot (update.Host.lease_from); the listener answered regalia-admission only, so both were
        refused on every host. Root is answered, through the same issuance; any other uid still is not."""
        self.assertEqual(self.answer(ask("lease-nonce", node_id="a"), uid=sync.OPERATOR_UID), {"v": 1, "ok": True, "nonce": "22" * 32})
        self.assertEqual(self.answer(ask("lease", request=REQUEST, evidence=EVIDENCE), uid=sync.OPERATOR_UID),
                         {"v": 1, "ok": True, "lease": "its own lease"})
        self.assertEqual([(epoch, node_id) for epoch, node_id, *_ in self.issued], [(1, "a")])
        self.assertEqual([(e["event"], e["outcome"]) for e in self.trail], [("sync-lease-nonce", "ALLOW"), ("sync-lease", "ALLOW")])
        self.assertEqual(sync.OPERATOR_UID, 0)

    def test_the_allow_events_carry_the_caller_s_uid_admission_s_or_root_s(self):
        """dx7.10.2 review: the subject of every event is this node, whoever asked; the caller's uid on each event, ALLOW
        included, is what tells a lease root asked for (the operator's update) apart from one admission asked for."""
        for uid in (ADMISSION_UID, sync.OPERATOR_UID):
            with self.subTest(uid=uid):
                del self.trail[:]
                self.answer(ask("lease-nonce", node_id="a"), uid=uid)
                self.answer(ask("lease", request=REQUEST, evidence=EVIDENCE), uid=uid)
                self.assertEqual([(e["event"], e["outcome"], e["subject"], e["uid"]) for e in self.trail],
                                 [("sync-lease-nonce", "ALLOW", "a", uid), ("sync-lease", "ALLOW", "a", uid)])
        self.assertEqual(len(self.issued), 2)

    def test_a_refused_uid_is_on_the_trail_by_its_uid_too(self):
        self.answer(ask("lease-nonce", node_id="a"), uid=ADMISSION_UID + 1)
        self.assertEqual((self.trail[-1]["outcome"], self.trail[-1]["uid"]), ("DENY", ADMISSION_UID + 1))

    def test_the_uid_is_read_from_the_local_source_only(self):
        self.assertEqual([sync.local_uid(s) for s in (sync.local_source(0), sync.local_source(ADMISSION_UID), "uid:", "uid:01",
                                                       "uid:-1", "10.0.0.2", None, ("uid:0",))],
                         [0, ADMISSION_UID, None, None, None, None, None, None])

    def test_the_network_listener_s_events_carry_no_uid(self):
        """Server (the tunnel's listener) is unchanged: its caller is a node, by its tunnel key, and no uid is recorded."""
        trail = []
        server = sync.Server("b", mock.Mock(envelopes=lambda after=0: [], load=lambda: None), None, None, None, lambda m, s: None,
                             trail.append)
        server.handle(ask("lease-nonce", node_id="a"), "10.0.0.1")
        self.assertTrue(trail)
        self.assertTrue(all("uid" not in e for e in trail))

    def test_root_is_refused_under_multi_node_too(self):
        """dx7.10.2 review: root is answered under the single-node profile only, as admission is. Under multi-node the
        listener issues nothing to root either, says why, and the DENY is on the trail under uid 0."""
        self.manifest = three()
        for op, fields in (("lease-nonce", {"node_id": "a"}), ("lease", {"request": REQUEST, "evidence": EVIDENCE})):
            with self.subTest(op=op):
                answered = self.answer(ask(op, **fields), uid=sync.OPERATOR_UID)
                self.assertIs(answered["ok"], False)
                self.assertIn("the local lease listener answers only under the single-node profile; epoch 1 is multi-node",
                              answered["refused"])
                self.assertEqual((self.trail[-1]["event"], self.trail[-1]["outcome"], self.trail[-1]["uid"]),
                                 ("sync-" + op, "DENY", sync.OPERATOR_UID))
        self.assertEqual((self.issued, self.attested), ([], []))
        self.verifier.nonce.assert_not_called()

    def test_an_operation_other_than_the_lease_s_is_refused_by_name(self):
        for op, fields in (("pull", {"summary": {}, "sequence": 0}), ("measurements", {"version": "p1"})):
            with self.subTest(op=op):
                self.assertEqual(self.answer(ask(op, **fields)),
                                 {"v": 1, "ok": False, "refused": "the local lease listener answers lease-nonce and lease only"})
        self.assertEqual(self.issued, [])

    def test_under_multi_node_it_issues_nothing_and_says_why(self):
        self.manifest = three()
        for op, fields in (("lease-nonce", {"node_id": "a"}), ("lease", {"request": REQUEST, "evidence": EVIDENCE})):
            with self.subTest(op=op):
                refused = self.answer(ask(op, **fields))["refused"]
                self.assertIn("the local lease listener answers only under the single-node profile; epoch 1 is multi-node", refused)
        self.assertEqual((self.issued, self.attested), ([], []))

    def test_a_request_over_the_network_listener_s_limit_is_refused(self):
        raw = ask("lease-nonce", node_id="a" * (sync.MAX_REQUEST + 1))
        self.assertIn("a request is at most %d bytes" % sync.MAX_REQUEST, self.answer(raw)["refused"])

    def test_a_peer_s_server_still_issues_a_peer_s_lease(self):
        """The multi-node issuance path is unchanged: Server._issued is lease.issue, never issue_self."""
        server = sync.Server("b", None, "freshness", lambda manifest: "verifier", "signer", None, None, floor=mock.Mock(),
                             applied=lambda: ("c1" * 8, 1, 7))
        with mock.patch.object(sync.lease, "issue", return_value="a peer's lease") as issue:
            self.assertEqual(server._issued(three(), REQUEST, EVIDENCE), "a peer's lease")
        self.assertEqual(issue.call_args.args[:7], (three(), "b", REQUEST, "verifier", EVIDENCE, "freshness", "signer"))
        self.assertEqual(self.issued, [])


class TheSocket(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="ll-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, self.dir, True)          # its own mkdtemp directory
        os.chmod(self.dir, 0o755)
        self.path = str(self.dir / sync.LEASE_SOCKET)

    def bound(self, owner=None):
        listener = sync.bind_local(self.path, os.getuid() if owner is None else owner)
        self.addCleanup(listener.close)
        return listener

    def refused(self, reason, **kw):
        with self.assertRaises(m.Refused) as caught:
            self.bound(**kw)
        self.assertIn(reason, str(caught.exception))

    def test_it_is_bound_under_umask_0177_then_opened_to_0666(self):
        umasks = []

        class Recording(socket.socket):
            def bind(inner, address):
                umasks.append(os.umask(0o022))
                os.umask(umasks[-1])
                return super().bind(address)
        before = os.umask(0o022)
        os.umask(before)
        listener = sync.bind_local(self.path, os.getuid(), create=Recording)
        self.addCleanup(listener.close)
        self.assertEqual(umasks, [0o177])
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o666)
        self.assertTrue(stat.S_ISSOCK(os.stat(self.path).st_mode))
        self.assertEqual(os.umask(before), before)              # the process's umask is given back

    def test_a_directory_that_is_not_regalia_sync_s_is_refused(self):
        self.refused("is not regalia-sync's", owner=os.getuid() + 1)
        self.assertFalse(os.path.exists(self.path))

    def test_a_directory_its_group_or_others_can_write_is_refused(self):
        for mode in (0o775, 0o757, 0o777):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.dir, mode)
                self.refused("is writable by its group or by others")
                self.assertFalse(os.path.exists(self.path))

    def test_a_stale_socket_is_replaced_and_anything_else_is_left_and_refused(self):
        self.bound().close()
        self.bound()                                             # the leftover socket: removed, bound again
        os.unlink(self.path)
        pathlib.Path(self.path).write_text("not a socket")
        self.refused("is there and is not a socket")
        self.assertEqual(pathlib.Path(self.path).read_text(), "not a socket")


@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "SO_PEERCRED: Linux")
class OverTheSocket(Local):
    """End to end on a real AF_UNIX socket: serve() with peer_source, a Client over unix_transport."""

    def served(self, admission_uid):
        directory = tempfile.mkdtemp(prefix="ll-", dir="/tmp")
        os.chmod(directory, 0o755)
        path = os.path.join(directory, sync.LEASE_SOCKET)
        listener = sync.bind_local(path, os.getuid())
        self.server.admission_uid = admission_uid
        stop = threading.Event()
        thread = threading.Thread(target=sync.serve, args=(self.server, listener, stop.is_set), kwargs={"source_of": sync.peer_source},
                                  daemon=True)
        thread.start()

        def cleanup():
            stop.set()
            thread.join(5)
            listener.close()
            os.unlink(path)
            os.rmdir(directory)
        self.addCleanup(cleanup)
        return sync.Client("a", mock.Mock(load=lambda: self.manifest), None, {"a": sync.unix_transport(path, timeout=5)}, self.trail.append)

    def test_its_own_admission_gets_its_lease_through_the_renewer_a_peer_is_asked_with(self):
        quotes = []
        client = self.served(admission_uid=os.getuid())
        with mock.patch.object(sync.lease, "request_binding", return_value=b"binding"):
            got = client.renewer("a", lambda nonce, manifest, binding: quotes.append(nonce) or EVIDENCE)(REQUEST)
        self.assertEqual((got, quotes), ("its own lease", ["22" * 32]))
        self.assertEqual(len(self.issued), 1)

    @unittest.skipIf(os.getuid() == sync.OPERATOR_UID, "as root the client is the operator, whom the listener answers")
    def test_any_other_uid_is_refused_on_the_wire(self):
        client = self.served(admission_uid=os.getuid() + 1)
        with self.assertRaises(m.Refused) as caught:
            client.renewer("a", lambda nonce, manifest, binding: EVIDENCE)(REQUEST)
        self.assertIn("refused", str(caught.exception))
        self.assertEqual(self.issued, [])
        self.assertIn("uid:%d is not regalia-admission" % os.getuid(), self.trail[-1]["reason"])


class Admission(unittest.TestCase):
    """node.admission_service under single-node asks its own sync (Node.self_source) through sync.Client, as a peer, and
    builds no issuer part of its own (no Freshness, TpmSigner, RevisionFloor or self-attester in admission)."""

    def test_it_asks_its_own_sync_and_makes_no_issuer_part(self):
        from deploy.baremetal import node
        trail, asked = [], []

        class Trail:
            def __init__(inner, path, name):
                pass

            def __call__(inner, event):
                trail.append(event)

        class Client:
            def __init__(inner, node_id, manifest, freshness, sources, sink):
                inner.sources = sources

            def renewer(inner, name, quote):
                def renew(request):
                    asked.append((name, sorted(inner.sources)))
                    if answer[0] is None:
                        raise m.Refused("the manifest leaves no node this peer could attest")
                    return answer[0]
                return renew
        answer = [{"lease": "its own"}]
        fake = mock.Mock(node_id="a", runtime="/run/regalia", run=None)
        fake.manifest.return_value = single5(3, "")
        fake.self_source.return_value = {"a": "the local lease listener"}
        fake.sources.side_effect = AssertionError("a peer was looked for")
        fake.freshness.side_effect = fake.self_attester.side_effect = AssertionError("admission made an issuer part")
        never = mock.Mock(side_effect=AssertionError("admission made an issuer part"))
        with mock.patch.object(node, "boot_session", return_value=("ab" * 32, b"pub")), mock.patch.object(node, "Trail", Trail), \
                mock.patch.object(sync, "Client", Client), mock.patch.object(node.lease, "Holder"), \
                mock.patch.object(node.lease, "TpmSigner", never), mock.patch.object(node.lease, "RevisionFloor", never), \
                mock.patch.object(node.lease, "issue_self", never):
            service = node.admission_service(fake, daemon_started=lambda: None)
            self.assertEqual(service.renew({"nonce": "n"}), {"lease": "its own"})
            answer[0] = None
            with self.assertRaises(m.Refused):
                service.renew({"nonce": "n2"})
        fake.self_source.assert_called_with(timeout=node.admission.RENEW_TIMEOUT)
        self.assertEqual(asked, [("a", ["a"])] * 2)
        self.assertEqual([(e["peer"], e["outcome"]) for e in trail], [("a", "ALLOW"), ("a", "DENY"), ("", "DENY")])
        self.assertIn("the manifest leaves no node this peer could attest", trail[1]["reason"])

    def test_self_source_is_sync_s_lease_socket_in_sync_s_state_directory(self):
        from deploy.baremetal import node
        host = object.__new__(node.Node)
        host.node_id, host.state = "a", "/var/lib/regalia-sync"
        with mock.patch.object(node.sync, "unix_transport", side_effect=lambda path, timeout: (path, timeout)):
            self.assertEqual(host.self_source(timeout=7), {"a": ("/var/lib/regalia-sync/lease.sock", 7)})

    def test_sync_s_local_server_is_built_from_sync_s_own_parts(self):
        from deploy.baremetal import node
        service = object.__new__(node.Sync)
        service.node = mock.Mock(node_id="a")
        service.store, service.freshness, service.signer, service.floor, service.trail = "store", "freshness", "signer", "floor", "trail"
        with mock.patch.object(node.pwd, "getpwnam", return_value=mock.Mock(pw_uid=ADMISSION_UID)) as getpwnam:
            local = service.local_server()
        getpwnam.assert_called_once_with("regalia-admission")
        self.assertIsInstance(local, sync.LocalServer)
        self.assertEqual((local.node_id, local.store, local.freshness, local.attester, local.signer, local.floor, local.admission_uid),
                         ("a", "store", "freshness", service.node.self_attester, "signer", "floor", ADMISSION_UID))
        self.assertIs(local.applied, node.lease.read_applied)


def unit(name):
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    parser.optionxform = str
    parser.read(UNITS / name)
    return parser["Service"]


class ShippedSandbox(unittest.TestCase):
    """What the local lease listener relies on, read from what is shipped: admission's sandbox is what it was (no write
    path into sync's state), it may open AF_UNIX sockets, sync's state directory is traversable, and no AppArmor profile
    confines either python service (a unix connect or bind would then need a rule)."""

    def test_admission_s_sandbox_is_unchanged(self):
        admission = unit("regalia-admission.service")
        self.assertEqual((admission["User"], admission["ProtectSystem"], admission["ReadWritePaths"]),
                         (sync.ADMISSION_USER, "strict", "/run/regalia/admission /var/log/regalia-admission -/run/regalia-metrics/admission"))
        self.assertIn("AF_UNIX", admission["RestrictAddressFamilies"].split())

    def test_sync_runs_as_regalia_sync_with_a_traversable_state_directory(self):
        service = unit("regalia-sync.service")
        self.assertEqual((service["User"], service["StateDirectory"], service["StateDirectoryMode"]), (sync.SYNC_USER, "regalia-sync", "0755"))
        self.assertIn("AF_UNIX", service["RestrictAddressFamilies"].split())

    def test_no_apparmor_profile_confines_either_service(self):
        for name in ("regalia-admission.service", "regalia-sync.service"):
            self.assertNotIn("AppArmorProfile", unit(name), name)
        profiles = [p for p in (ROOT / "deploy" / "baremetal" / "apparmor").rglob("*") if p.is_file()]
        self.assertTrue(profiles)
        for profile in profiles:
            # the rules and attachments only: a comment may name a command an operator runs
            rules = "\n".join(line for line in profile.read_text().splitlines() if not line.lstrip().startswith("#"))
            self.assertTrue(rules.strip(), profile)
            for word in ("python", "deploy/baremetal", "deploy.baremetal", "regalia-sync", "regalia-admission"):
                self.assertNotIn(word, rules.replace("/var/lib/regalia-sync/", ""), (profile, word))


if __name__ == "__main__":
    unittest.main()
