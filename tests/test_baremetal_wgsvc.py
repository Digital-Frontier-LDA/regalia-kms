"""deploy/baremetal/wgsvc.py (#80, step 2): the service tunnel's peers and addresses come from the manifest
alone; the root side applies them and reads them back; the caller of a connection is the node whose key
derives its address. `wg` and `ip` are a fake here;
e2e/regalia-sync-netns.py runs the same code on real WireGuard."""
import base64
import ipaddress
import subprocess
import unittest

from deploy.baremetal import membership as m
from deploy.baremetal import wgsvc
import tests.test_baremetal_heartbeat as hbt

KEY = {name: ("%02x" % (0xa0 + i)) * 32 for i, name in enumerate(("a", "b", "c"))}      # hbt.manifest's wg_service_pub
STRANGER = "5e" * 32               # a key no node of the manifest holds
PRIVATE = base64.b64encode(bytes(range(32))).decode()


def done(code=0, out=b""):
    return subprocess.CompletedProcess([], code, out, b"")


class Wg:
    """`wg show <interface> allowed-ips` over a table {key (hex): [allowed networks]}; everything else succeeds."""

    def __init__(self, table=None, code=0):
        self.table, self.code, self.calls, self.inputs = table or {}, code, [], []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        self.inputs.append(kw.get("input"))
        if argv[:2] == ["wg", "show"]:
            lines = ["%s\t%s" % (wgsvc.wg_key(key), " ".join(nets) or "(none)") for key, nets in self.table.items()]
            return done(self.code, ("\n".join(lines) + "\n").encode())
        return done(self.code)


class Case(unittest.TestCase):
    def setUp(self):
        self.m1 = hbt.manifest()

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Addresses(Case):
    def test_an_address_is_the_prefix_and_80_bits_of_the_key_s_hash(self):
        import hashlib
        for key in KEY.values():
            address = ipaddress.IPv6Address(wgsvc.address(key))
            self.assertIn(address, wgsvc.PREFIX)
            self.assertEqual(address.packed, bytes.fromhex("fd7265676c61") + hashlib.sha256(bytes.fromhex(key)).digest()[:10])
        self.assertEqual(len({wgsvc.address(key) for key in KEY.values()}), 3)
        self.assertEqual(wgsvc.address(KEY["a"]), wgsvc.address(KEY["a"]))
        self.assertEqual(str(wgsvc.PREFIX), "fd72:6567:6c61::/48")
        for bad in ("", "a0" * 31, "A0" * 32, "zz" * 32, None, 5, wgsvc.wg_key(KEY["a"])):
            with self.subTest(bad=bad):
                self.refused("a WireGuard public key", wgsvc.address, bad)

    def test_keys_go_between_the_manifest_s_hex_and_wireguard_s_base64(self):
        self.assertEqual(wgsvc.wg_key("00" * 32), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        for key in list(KEY.values()) + [STRANGER]:
            self.assertEqual(wgsvc.hex_key(wgsvc.wg_key(key)), key)
        for bad in ("", "AAAA", "not base64!", wgsvc.wg_key("00" * 32)[:-1], base64.b64encode(bytes(33)).decode(), None, b"AAAA", KEY["a"]):
            with self.subTest(bad=bad):
                self.refused("not a WireGuard public key", wgsvc.hex_key, bad)


class Rendering(Case):
    def peers(self, text):
        """[(comment, key hex, allowed, endpoint or None)] of a rendered configuration."""
        out = []
        for block in text.split("\n[Peer]\n")[1:]:
            fields = dict(line.split(" = ", 1) for line in block.splitlines() if " = " in line)
            self.assertEqual(set(fields) - {"PublicKey", "AllowedIPs", "Endpoint"}, set())
            out.append((block.splitlines()[0], wgsvc.hex_key(fields["PublicKey"]), fields["AllowedIPs"], fields.get("Endpoint")))
        return out

    def test_every_other_node_is_a_peer_by_its_service_key_at_its_derived_address(self):
        text = wgsvc.conf(self.m1, "a", {"b": "198.51.100.7", "c": "198.51.100.9"})
        self.assertTrue(text.startswith("[Interface]\nListenPort = 51821\n"))
        self.assertNotIn("PrivateKey", text)
        self.assertEqual(self.peers(text), [("# b", KEY["b"], wgsvc.address(KEY["b"]) + "/128", "198.51.100.7:51821"),
                                            ("# c", KEY["c"], wgsvc.address(KEY["c"]) + "/128", "198.51.100.9:51821")])
        boot = {n["wg_boot_pub"] for n in self.m1["nodes"]}
        self.assertEqual(boot & {p[1] for p in self.peers(text)}, set())          # never the boot keys

    def test_a_peer_with_no_known_underlay_is_still_a_peer(self):
        self.assertEqual(self.peers(wgsvc.conf(self.m1, "a", {"b": "198.51.100.7"}))[1],
                         ("# c", KEY["c"], wgsvc.address(KEY["c"]) + "/128", None))

    def test_a_node_in_a_terminal_state_is_nobody_s_peer_and_knows_nobody(self):
        for state in m.TERMINAL:
            with self.subTest(state=state):
                gone = hbt.manifest(c=state)
                self.assertEqual([p[0] for p in self.peers(wgsvc.conf(gone, "a", {}))], ["# b"])
                self.assertEqual(wgsvc.conf(gone, "c", {}), "[Interface]\nListenPort = 51821\n")
        for state in ("QUARANTINED", "DRAINING"):
            with self.subTest(state=state):
                still = hbt.manifest(c=state)                                       # it must go on learning what was decided
                self.assertEqual([p[0] for p in self.peers(wgsvc.conf(still, "a", {}))], ["# b", "# c"])
                self.assertEqual(len(self.peers(wgsvc.conf(still, "c", {}))), 2)

    def test_two_keys_that_derive_one_address_are_refused(self):
        from unittest import mock
        real = wgsvc.address
        collide = lambda key: real(KEY["b"]) if key in (KEY["b"], KEY["c"]) else real(key)        # noqa: E731
        with mock.patch.object(wgsvc, "address", collide):
            self.refused("two keys derive the same tunnel address", wgsvc.conf, self.m1, "a", {})
            self.refused("two keys derive the same tunnel address", wgsvc.conf, hbt.manifest(c="REVOKED_STOLEN"), "a", {})   # a terminal node's too

    def test_what_cannot_be_rendered_is_refused(self):
        self.refused("x is not in the manifest", wgsvc.conf, self.m1, "x", {})
        self.refused("underlays maps node IDs to addresses", wgsvc.conf, self.m1, "a", None)
        self.refused("the underlay of b is not an IPv4 address", wgsvc.conf, self.m1, "a", {"b": "198.51.100.7:51821"})
        self.refused("the underlay of b is not an IPv4 address", wgsvc.conf, self.m1, "a", {"b": "1.2.3.4\nEndpoint = 6.6.6.6:1"})
        self.refused("listen_port must be a port number", wgsvc.conf, self.m1, "a", {}, 70000)
        self.assertIn("ListenPort = 51999\n", wgsvc.conf(self.m1, "a", {"b": "198.51.100.7"}, 51999))
        self.assertIn("Endpoint = 198.51.100.7:51999\n", wgsvc.conf(self.m1, "a", {"b": "198.51.100.7"}, 51999))


class Applying(Case):
    def test_the_configuration_goes_to_syncconf_on_standard_input_with_the_key(self):
        wg, text = Wg(), wgsvc.conf(self.m1, "a", {"b": "198.51.100.7"})
        wgsvc.apply(text, PRIVATE, run=wg)
        self.assertEqual(wg.calls, [["wg", "syncconf", "wg-svc", "/dev/stdin"]])
        self.assertEqual(wg.inputs[0].decode(), "[Interface]\nPrivateKey = %s\n%s" % (PRIVATE, text[len("[Interface]\n"):]))
        self.refused("the private key is not a WireGuard key", wgsvc.apply, text, "")               # never applied without it
        self.refused("this is not a configuration rendered here", wgsvc.apply, "[Peer]\n", PRIVATE)
        self.refused("the tunnel's configuration could not be applied", wgsvc.apply, text, PRIVATE, run=Wg(code=1))

        def missing(argv, **kw):
            raise FileNotFoundError("wg")

        def slow(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 10)
        self.refused("could not be applied (FileNotFoundError)", wgsvc.apply, text, PRIVATE, run=missing)
        self.refused("could not be applied (TimeoutExpired)", wgsvc.apply, text, PRIVATE, run=slow)

    def test_the_interface_is_one_of_its_own(self):
        for bad in ("wg-boot", "eth0", "wg0", "wg-", "wg-svc; reboot", "wg-" + "x" * 13, None, "WG-SVC"):
            with self.subTest(bad=bad):
                self.refused("named wg-...", wgsvc.apply, "[Interface]\n", PRIVATE, interface=bad, run=Wg())
                self.refused("named wg-...", wgsvc.verify, "[Interface]\n", interface=bad, run=Wg())
                self.refused("named wg-...", wgsvc.prepare, KEY["a"], interface=bad, run=Wg())
                self.refused("named wg-...", wgsvc.up, interface=bad, run=Wg())
                self.refused("named wg-...", wgsvc.down, interface=bad, run=Wg())
        wgsvc.apply("[Interface]\nListenPort = 1\n", PRIVATE, interface="wg-other", run=Wg())

    def test_prepare_creates_the_interface_once_and_leaves_it_down_up_brings_it_up_with_the_route(self):
        own = wgsvc.address(KEY["a"])

        class Ip(Wg):
            present = False

            def __call__(self, argv, **kw):
                self.calls.append(argv)
                return done(0 if self.present else 1) if argv[:3] == ["ip", "link", "show"] else done(self.code)
        fresh = Ip()
        self.assertEqual(wgsvc.prepare(KEY["a"], run=fresh), own)
        self.assertEqual(fresh.calls, [["ip", "link", "show", "dev", "wg-svc"], ["ip", "link", "add", "dev", "wg-svc", "type", "wireguard"],
                                       ["ip", "-6", "address", "replace", own + "/128", "dev", "wg-svc", "nodad"]])   # not up
        wgsvc.up(run=fresh)
        self.assertEqual(fresh.calls[-2:], [["ip", "link", "set", "dev", "wg-svc", "up"], ["ip", "-6", "route", "replace", "fd72:6567:6c61::/48", "dev", "wg-svc"]])
        again = Ip()
        again.present = True
        wgsvc.prepare(KEY["a"], run=again)
        self.assertNotIn(["ip", "link", "add", "dev", "wg-svc", "type", "wireguard"], again.calls)   # it is there: not added twice
        failing = Ip(code=1)
        self.refused("the tunnel interface could not be created", wgsvc.prepare, KEY["a"], run=failing)
        failing.present = True
        self.refused("the tunnel address could not be set", wgsvc.prepare, KEY["a"], run=failing)
        self.refused("could not be brought up", wgsvc.up, run=failing)

    def test_down_is_down_or_deleted_or_a_refusal_that_says_so(self):
        class Ip(Wg):
            def __init__(self, codes):
                super().__init__()
                self.codes = codes

            def __call__(self, argv, **kw):
                self.calls.append(argv)
                code = self.codes.pop(0)
                if isinstance(code, Exception):
                    raise code
                return done(code)
        quiet = Ip([0])
        wgsvc.down(run=quiet)
        self.assertEqual(quiet.calls, [["ip", "link", "set", "dev", "wg-svc", "down"]])
        stubborn = Ip([1, 0])
        wgsvc.down(run=stubborn)
        self.assertEqual(stubborn.calls[-1], ["ip", "link", "del", "dev", "wg-svc"])
        for codes in ([1, 1], [OSError("ip"), subprocess.TimeoutExpired("ip", 10)]):
            self.refused("could not be taken down or deleted: it may still carry its old peers", wgsvc.down, run=Ip(codes))


class Verifying(Case):
    """The root side reads back what it applied: the kernel's peers must be exactly the manifest's."""

    def setUp(self):
        super().setUp()
        self.text = wgsvc.conf(self.m1, "a", {"b": "198.51.100.7"})

    def table(self, **override):
        table = {key: [wgsvc.address(key) + "/128"] for key in (KEY["b"], KEY["c"])}
        table.update(override)
        return {k: v for k, v in table.items() if v is not None}

    def test_exactly_the_rendered_peers_each_at_its_one_address_passes(self):
        wg = Wg(self.table())
        wgsvc.verify(self.text, run=wg)
        self.assertEqual(wg.calls, [["wg", "show", "wg-svc", "allowed-ips"]])
        self.assertEqual(wgsvc.expected(self.text), {ipaddress.ip_network(wgsvc.address(k) + "/128"): [k] for k in (KEY["b"], KEY["c"])})
        wgsvc.verify("[Interface]\nListenPort = 51821\n", run=Wg({}))             # a node that knows nobody: no peers

    def test_anything_else_is_refused_and_named(self):
        b, c = wgsvc.address(KEY["b"]), wgsvc.address(KEY["c"])
        stranger = "77" * 32
        for label, named, table in (
                ("a wider range for a peer", "fd72:6567:6c61::/48", self.table(**{KEY["c"]: ["fd72:6567:6c61::/48"]})),
                ("a second range for a peer", "10.0.0.0/8", self.table(**{KEY["c"]: [c + "/128", "10.0.0.0/8"]})),
                ("everything", "::/0", self.table(**{KEY["c"]: [c + "/128", "::/0"]})),
                ("another peer's address", c + "/128", self.table(**{KEY["b"]: [c + "/128"], KEY["c"]: [b + "/128"]})),
                ("an address owned twice", b + "/128", self.table(**{KEY["c"]: [c + "/128", b + "/128"]})),
                ("a peer the manifest does not have", wgsvc.wg_key(stranger), self.table(**{stranger: [wgsvc.address(stranger) + "/128"]})),
                ("a stranger with no address", wgsvc.wg_key(stranger), self.table(**{stranger: []})),
                ("a peer that is missing", wgsvc.wg_key(KEY["c"]), self.table(**{KEY["c"]: None})),
                ("a peer with no address", c + "/128", self.table(**{KEY["c"]: []})),
                ("a revoked node still configured", wgsvc.wg_key(KEY["c"]), None)):
            with self.subTest(label):
                text = self.text if table is not None else wgsvc.conf(hbt.manifest(c="REVOKED_STOLEN"), "a", {})
                with self.assertRaises(m.Refused) as caught:
                    wgsvc.verify(text, run=Wg(table if table is not None else self.table()))
                self.assertIn("the tunnel's peers are not the manifest's", str(caught.exception))
                self.assertIn(named, str(caught.exception))

    def test_a_peer_list_that_is_not_understood_or_cannot_be_read_is_a_refusal(self):
        self.refused("the tunnel's peers cannot be read back", wgsvc.verify, self.text, run=Wg(self.table(), code=1))

        def missing(argv, **kw):
            raise FileNotFoundError("wg")
        self.refused("cannot be read back (FileNotFoundError)", wgsvc.verify, self.text, run=missing)
        for label, text in (("no tab", "garbage"), ("a bad key", "notakey\tfd72:6567:6c61::1/128"), ("three fields", "a\tb\tc"),
                            ("a bad network", "%s\tfd72::zz/128" % wgsvc.wg_key(KEY["b"])),
                            ("host bits set", "%s\tfd72:6567:6c61::1/64" % wgsvc.wg_key(KEY["b"]))):
            with self.subTest(label):
                self.refused("not", wgsvc.verify, self.text, run=lambda argv, **kw: done(0, text.encode()))
        b = wgsvc.wg_key(KEY["b"])
        for label, text in (("a key and nothing else", b), ("a third field", "%s\t%s/128\tmore" % (b, wgsvc.address(KEY["b"])))):
            with self.subTest(label):
                self.refused("the tunnel's peer list is not understood", wgsvc.owners, text)
        self.assertEqual(wgsvc.owners("\n%s\t(none)\n\n" % wgsvc.wg_key(KEY["b"])), {})


class Reconciling(Case):
    class Host(Wg):
        """ip and wg: the interface exists; `wg show` answers from the table."""

        def __call__(self, argv, **kw):
            if argv[:3] == ["ip", "link", "show"]:
                self.calls.append(argv)
                return done(0)
            return super().__call__(argv, **kw)

    def table(self, manifest, node="a"):
        return {n["wg_service_pub"]: [wgsvc.address(n["wg_service_pub"]) + "/128"] for n in manifest["nodes"]
                if n["node_id"] != node and n["state"] not in m.TERMINAL}

    def test_apply_read_back_and_only_then_up(self):
        host = self.Host(self.table(self.m1))
        self.assertEqual(wgsvc.reconcile(self.m1, "a", {"b": "198.51.100.7"}, PRIVATE, run=host), wgsvc.address(KEY["a"]))
        self.assertEqual([c[:4] for c in host.calls], [["ip", "link", "show", "dev"], ["ip", "-6", "address", "replace"], ["wg", "syncconf", "wg-svc", "/dev/stdin"],
                                                       ["wg", "show", "wg-svc", "allowed-ips"], ["ip", "link", "set", "dev"], ["ip", "-6", "route", "replace"]])
        self.assertEqual(host.calls[4], ["ip", "link", "set", "dev", "wg-svc", "up"])     # after the read-back, not before
        self.assertNotIn(["ip", "link", "set", "dev", "wg-svc", "down"], host.calls)

    def test_a_failure_anywhere_takes_the_interface_down_and_a_failed_take_down_is_said(self):
        """Found by an independent read: a failure inside the old up() was outside the try, and a take-down
        that failed was ignored, so a refusal could leave the interface up with stale or widened peers."""
        for label, step in (("the address", ["ip", "-6", "address"]), ("the link up", ["ip", "link", "set", "dev", "wg-svc", "up"]),
                            ("the route", ["ip", "-6", "route"])):
            with self.subTest(label):
                class Failing(self.Host):
                    def __call__(self, argv, **kw):
                        if argv[:len(step)] == step:
                            self.calls.append(argv)
                            return done(1)
                        return super().__call__(argv, **kw)
                host = Failing(self.table(self.m1))
                with self.assertRaises(m.Refused):
                    wgsvc.reconcile(self.m1, "a", {}, PRIVATE, run=host)
                self.assertEqual(host.calls[-1], ["ip", "link", "set", "dev", "wg-svc", "down"])

        class Stuck(self.Host):
            def __call__(self, argv, **kw):
                if argv[:3] == ["ip", "link", "set"] or argv[:3] == ["ip", "link", "del"]:
                    self.calls.append(argv)
                    return done(1)
                return super().__call__(argv, **kw)
        wide = Stuck(dict(self.table(self.m1), **{KEY["c"]: ["fd72:6567:6c61::/48"]}))
        self.refused("the tunnel's peers are not the manifest's", wgsvc.reconcile, self.m1, "a", {}, PRIVATE, run=wide)
        self.refused("could not be taken down or deleted", wgsvc.reconcile, self.m1, "a", {}, PRIVATE, run=Stuck(dict(self.table(self.m1), **{KEY["c"]: ["fd72:6567:6c61::/48"]})))
        self.assertEqual(wide.calls[-2:], [["ip", "link", "set", "dev", "wg-svc", "down"], ["ip", "link", "del", "dev", "wg-svc"]])

        class Interrupted(Stuck):
            def __call__(self, argv, **kw):
                if argv[:2] == ["wg", "syncconf"]:
                    raise KeyboardInterrupt()
                return super().__call__(argv, **kw)
        with self.assertRaises(KeyboardInterrupt) as caught:                   # not turned into a refusal
            wgsvc.reconcile(self.m1, "a", {}, PRIVATE, run=Interrupted(self.table(self.m1)))
        self.assertIn("could not be taken down or deleted", " ".join(getattr(caught.exception, "__notes__", [])))

    def test_a_result_that_is_not_the_manifest_s_takes_the_interface_down(self):
        revoked = hbt.manifest(c="REVOKED_STOLEN")
        host = self.Host(self.table(self.m1))                                      # the kernel still has c, whatever was applied
        self.refused("the tunnel's peers are not the manifest's", wgsvc.reconcile, revoked, "a", {}, PRIVATE, run=host)
        self.assertEqual(host.calls[-1], ["ip", "link", "set", "dev", "wg-svc", "down"])
        wide = self.Host(dict(self.table(self.m1), **{KEY["c"]: ["fd72:6567:6c61::/48"]}))
        self.refused("fd72:6567:6c61::/48", wgsvc.reconcile, self.m1, "a", {}, PRIVATE, run=wide)
        self.assertEqual(wide.calls[-1], ["ip", "link", "set", "dev", "wg-svc", "down"])

    def test_a_failed_apply_takes_the_interface_down_and_a_bad_request_touches_nothing(self):
        class Failing(self.Host):
            def __call__(self, argv, **kw):
                if argv[:2] == ["wg", "syncconf"]:
                    self.calls.append(argv)
                    return done(1)
                return super().__call__(argv, **kw)
        host = Failing(self.table(self.m1))
        self.refused("the tunnel's configuration could not be applied", wgsvc.reconcile, self.m1, "a", {}, PRIVATE, run=host)
        self.assertEqual(host.calls[-1], ["ip", "link", "set", "dev", "wg-svc", "down"])
        for label, reason, args in (("a node the manifest does not have", "x is not in the manifest", (self.m1, "x", {}, PRIVATE)),
                                    ("a manifest that does not validate", "schema", (dict(self.m1, schema="other"), "a", {}, PRIVATE)),
                                    ("a bad underlay", "is not an IPv4 address", (self.m1, "a", {"b": "nowhere"}, PRIVATE))):
            with self.subTest(label):
                untouched = self.Host()
                self.refused(reason, wgsvc.reconcile, *args, run=untouched)
                self.assertEqual(untouched.calls, [])
        keyless = self.Host(self.table(self.m1))
        self.refused("the private key is not a WireGuard key", wgsvc.reconcile, self.m1, "a", {}, "", run=keyless)
        self.assertEqual(keyless.calls[-1], ["ip", "link", "set", "dev", "wg-svc", "down"])


class Caller(Case):
    """regalia-sync's side: the caller is the node of the current manifest whose key derives the address."""

    def test_the_address_names_the_key_of_one_node_of_the_manifest(self):
        for name, key in KEY.items():
            self.assertEqual(wgsvc.key_at(self.m1, wgsvc.address(key)), key)
        revoked = hbt.manifest(c="REVOKED_STOLEN")
        self.assertEqual(wgsvc.key_at(revoked, wgsvc.address(KEY["c"])), KEY["c"])   # found, to be refused by name (sync.peer_of)

    def test_an_address_no_node_s_key_derives_is_refused(self):
        self.refused("no node of the current manifest (epoch 1) has the address", wgsvc.key_at, self.m1, wgsvc.address(STRANGER))
        self.refused("no node of the current manifest", wgsvc.key_at, self.m1, "fd72:6567:6c61::1")
        replaced = dict(self.m1, nodes=[n for n in self.m1["nodes"] if n["node_id"] != "c"])
        self.refused("no node of the current manifest", wgsvc.key_at, replaced, wgsvc.address(KEY["c"]))   # the manifest held NOW
        boot = self.m1["nodes"][1]["wg_boot_pub"]
        self.refused("no node of the current manifest", wgsvc.key_at, self.m1, wgsvc.address(boot))          # the boot key is another identity

    def test_what_is_not_an_address_of_the_tunnel_is_refused(self):
        for outside in ("2001:db8::1", "fd72:6567:6c62::1", "::1", "10.89.0.2", "::ffff:10.89.0.2", "", None, 5, b"fd72:6567:6c61::1",
                        wgsvc.address(KEY["b"]) + "%eth0", "\x1b[2J", wgsvc.address(KEY["b"]) + "/128"):
            with self.subTest(outside=outside):
                self.refused("is not an address of the service tunnel", wgsvc.key_at, self.m1, outside)

    def test_two_nodes_at_one_address_are_refused_not_chosen_between(self):
        twice = dict(self.m1, nodes=self.m1["nodes"] + [dict(self.m1["nodes"][0], node_id="z")])
        self.refused("no node of the current manifest", wgsvc.key_at, twice, wgsvc.address(KEY["a"]))


if __name__ == "__main__":
    unittest.main()
