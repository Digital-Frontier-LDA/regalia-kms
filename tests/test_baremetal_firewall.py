"""deploy/baremetal/sitecfg.py and firewall.py: a strict site config, and a deterministic default-deny
nftables ruleset rendered from it. Behaviour is proven separately in network namespaces
(e2e/baremetal-firewall-netns.sh); these pin the config contract and the rendered text."""
import copy
import json
import shutil
import subprocess
import unittest
from pathlib import Path

from deploy.baremetal import firewall, sitecfg

EXAMPLE = Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "site.example.json"


class SiteConfig(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(EXAMPLE.read_text())

    def test_the_example_is_valid(self):
        self.assertEqual(sitecfg.validate(self.doc)["site"], "site-a")

    def test_refusals(self):
        cases = {
            "unknown field": (lambda d: d.__setitem__("extra", 1), "fields mismatch"),
            "missing field": (lambda d: d.pop("admin_cidrs"), "fields mismatch"),
            "wide-open network": (lambda d: d.__setitem__("client_cidrs", ["0.0.0.0/0"]), "every address"),
            "host bits set": (lambda d: d.__setitem__("admin_cidrs", ["203.0.113.4/28"]), "not an IPv4 network"),
            "IPv6": (lambda d: d.__setitem__("client_cidrs", ["2001:db8::/64"]), "not IPv4"),
            "same ports": (lambda d: d.__setitem__("ssh_port", 8443), "must differ"),
            "bool port": (lambda d: d.__setitem__("kms_port", True), "port number"),
            "no ntp sink": (lambda d: d.__setitem__("outbound", d["outbound"][:1]), "'audit' and 'ntp'"),
            "bad proto": (lambda d: d["outbound"][0].__setitem__("proto", "icmp"), "tcp or udp"),
            "loopback host": (lambda d: d.__setitem__("host_ipv4", "127.0.0.1"), "host address"),
            "duplicate net": (lambda d: d.__setitem__("client_cidrs", ["198.51.100.0/24", "198.51.100.0/24"]), "twice"),
            "admin overlaps clients": (lambda d: d.__setitem__("admin_cidrs", ["198.51.100.16/28"]), "must be disjoint"),
            "admin overlaps monitoring": (lambda d: d.__setitem__("admin_cidrs", ["203.0.113.128/25"]), "must be disjoint"),
        }
        for label, (breakit, why) in cases.items():
            with self.subTest(label):
                d = copy.deepcopy(self.doc)
                breakit(d)
                with self.assertRaises(sitecfg.InvalidSite) as ctx:
                    sitecfg.validate(d)
                self.assertIn(why, str(ctx.exception))


class DuplicateKeys(unittest.TestCase):
    def test_a_repeated_key_is_refused_at_every_level(self):
        import tempfile
        text = EXAMPLE.read_text()
        cases = (text.replace('"admin_cidrs":', '"admin_cidrs": ["0.0.0.1/32"], "admin_cidrs":', 1),
                 text.replace('"proto": "tcp",', '"proto": "tcp", "proto": "udp",', 1))
        for bad in cases:
            with self.subTest(), tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                f.write(bad)
            with self.assertRaises(sitecfg.InvalidSite) as ctx:
                sitecfg.load(f.name)
            self.assertIn("duplicate field", str(ctx.exception))
            Path(f.name).unlink()


class ProbeErrors(unittest.TestCase):
    """A probe-host failure must never read as 'the port is closed'."""

    def test_no_route_is_a_refusal_not_a_closed_port(self):
        import errno
        from unittest import mock
        from deploy.baremetal import network_probe
        err = OSError(errno.ENETUNREACH, "Network is unreachable")
        with mock.patch.object(network_probe.socket, "create_connection", side_effect=err):
            with self.assertRaises(network_probe.ProbeFailure):
                network_probe.connect("203.0.113.66", "192.0.2.10", 8443, 1)
        for e in (OSError(errno.ECONNREFUSED, "refused"), OSError(errno.EHOSTUNREACH, "unreachable"),
                  network_probe.socket.timeout()):
            with self.subTest(e=e), mock.patch.object(network_probe.socket, "create_connection", side_effect=e):
                self.assertEqual(network_probe.connect("203.0.113.66", "192.0.2.10", 8443, 1)[0], False)

    def test_main_exits_2_when_the_probe_host_has_no_route(self):
        import errno
        import io
        from contextlib import redirect_stderr, redirect_stdout
        from unittest import mock
        from deploy.baremetal import network_probe
        err = OSError(errno.ENETUNREACH, "Network is unreachable")
        with mock.patch.object(network_probe.socket, "create_connection", side_effect=err), \
                mock.patch.object(network_probe.socket.socket, "bind", return_value=None), \
                redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as e:
            rc = network_probe.main([str(EXAMPLE), "--role", "unauthorized", "--source-ip", "203.0.113.66"])
        self.assertEqual(rc, 2, out.getvalue() + e.getvalue())
        self.assertIn("not a firewall answer", e.getvalue())


class Render(unittest.TestCase):
    def setUp(self):
        self.cfg = sitecfg.validate(json.loads(EXAMPLE.read_text()))
        self.text = firewall.render(self.cfg)

    def test_deterministic(self):
        self.assertEqual(self.text, firewall.render(sitecfg.validate(json.loads(EXAMPLE.read_text()))))

    def test_every_chain_defaults_to_drop(self):
        for hook in ("input", "forward", "output"):
            self.assertIn("type filter hook %s priority filter; policy drop;" % hook, self.text)

    def test_each_port_only_from_its_zones(self):
        self.assertIn("tcp dport 8443 ip saddr { 198.51.100.0/24, 203.0.113.128/32 } accept", self.text)
        self.assertIn("tcp dport 22 ip saddr { 203.0.113.0/28 } accept", self.text)

    def test_outbound_only_to_declared_sinks(self):
        self.assertIn('ip daddr 203.0.113.192/32 tcp dport 6514 accept comment "audit"', self.text)
        self.assertIn('ip daddr 203.0.113.193/32 udp dport 123 accept comment "ntp"', self.text)
        self.assertEqual(self.text.count(" dport "), 4)    # kms, ssh, audit, ntp: nothing else opens

    @unittest.skipUnless(shutil.which("nft"), "nft not installed")
    def test_nft_accepts_the_syntax(self):
        r = subprocess.run(["nft", "-c", "-f", "-"], input=self.text, capture_output=True, text=True)
        if "Operation not permitted" in r.stderr:
            self.skipTest("nft -c needs CAP_NET_ADMIN here")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
