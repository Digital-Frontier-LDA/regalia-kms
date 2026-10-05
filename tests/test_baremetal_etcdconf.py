"""deploy/baremetal/etcdconf.py (ADR-0002 D32, #432): etcd's members, trust and timings from the root-signed manifest;
each member's certificate bound once by the signing key the manifest pins for it; the rendered configuration's safety
settings."""
import datetime
import json
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from deploy.baremetal import etcdconf, membership as m
from tests.test_baremetal_membership_v4 import NODE_KEYS, STRANGER, manifest4, nodes4, p256, p256_sig, typed

GENESIS = "ab" * 32
NOW = "2026-10-05T12:00:00Z"


def certificate(name, seed):
    """A self-signed etcd certificate, as a member makes at enrolment."""
    key = p256(500 + seed)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    start = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(1000 + seed).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


CERTS = {n: certificate("etcd-" + n, i) for i, n in enumerate("abc")}


def bound(node_id, pem=None, issued_at=NOW, key=None):
    pem = pem or CERTS[node_id]
    body = etcdconf.binding(node_id, pem, issued_at)
    return {"cert": pem, "binding": etcdconf.sign(body, lambda raw: p256_sig(key or NODE_KEYS[node_id], raw))}


class Case(unittest.TestCase):
    def setUp(self):
        self.m1 = manifest4(1, "", nodes4())
        self.offered = {n: [bound(n)] for n in "abc"}

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Bindings(Case):
    def test_each_member_s_certificate_bound_by_its_own_signing_key(self):
        self.assertEqual(etcdconf.choose(self.m1, self.offered), CERTS)

    def test_a_binding_by_another_key_or_for_another_certificate_is_not_counted(self):
        for label, item in (("signed by b's key", bound("a", key=NODE_KEYS["b"])),
                            ("signed by a stranger", bound("a", key=STRANGER)),
                            ("b's binding on a's entry", bound("b")),
                            ("another certificate than the bound one", dict(bound("a"), cert=certificate("etcd-a", 7)))):
            with self.subTest(label):
                self.refused("no certificate of a is bound", etcdconf.choose, self.m1, dict(self.offered, a=[item]))

    def test_the_latest_binding_wins_and_a_rendered_one_is_never_gone_back_on(self):
        newer = certificate("etcd-a", 9)
        offered = dict(self.offered, a=[bound("a"), bound("a", pem=newer, issued_at="2026-10-06T12:00:00Z")])
        self.assertEqual(etcdconf.choose(self.m1, offered)["a"], newer)
        self.refused("older than the one rendered before", etcdconf.choose, self.m1, self.offered, {"a": "2026-10-06T12:00:00Z"})

    def test_a_node_re_enrolled_on_a_new_tpm_has_its_old_bindings_stop_verifying(self):
        nodes = nodes4()
        nodes[0]["signing_key"] = typed(p256(77))                # a's new TPM's key, in a root-signed epoch
        m2 = manifest4(2, m.digest(self.m1), nodes)
        self.refused("no certificate of a is bound", etcdconf.choose, m2, self.offered)
        fresh = dict(self.offered, a=[bound("a", issued_at="2026-10-06T12:00:00Z", key=p256(77))])
        self.assertEqual(sorted(etcdconf.choose(m2, fresh)), ["a", "b", "c"])

    def test_only_the_members_the_manifest_keeps_are_in_the_cluster(self):
        m2 = manifest4(2, m.digest(self.m1), nodes4(c="QUARANTINED"))
        self.assertEqual(sorted(etcdconf.choose(m2, self.offered)), ["a", "b"])
        config, bundle = etcdconf.render(m2, "a", GENESIS, etcdconf.choose(m2, self.offered), 20)
        self.assertNotIn("c=", json.loads(config)["initial-cluster"])
        self.assertNotIn(CERTS["c"].strip(), bundle)
        self.refused("c is not an etcd member under epoch 2 (QUARANTINED)", etcdconf.render, m2, "c", GENESIS, etcdconf.choose(m2, self.offered), 20)
        m3 = manifest4(2, m.digest(self.m1), nodes4(c="MAINTENANCE"))
        self.assertEqual(sorted(etcdconf.choose(m3, self.offered)), ["a", "b", "c"])     # a node rebooting stays a member


class Rendered(Case):
    def test_the_configuration_s_safety_settings(self):
        config, bundle = etcdconf.render(self.m1, "b", GENESIS, etcdconf.choose(self.m1, self.offered), 20)
        doc = etcdconf.check(config)
        self.assertEqual(doc["name"], "b")
        self.assertEqual(doc["listen-client-urls"], "unix://client.sock:0")
        self.assertEqual(doc["initial-cluster"].count("https://[fd72:6567:6c61:"), 3)
        self.assertEqual((doc["heartbeat-interval"], doc["election-timeout"]), (100, 1000))
        self.assertEqual(doc["peer-transport-security"]["key-file"], "/run/credentials/regalia-etcd.service/etcd-peer.key")
        self.assertEqual(doc["initial-cluster-token"], "regalia-" + "ab" * 16)
        self.assertEqual(bundle.count("-----BEGIN CERTIFICATE-----"), 3)

    def test_check_refuses_each_unsafe_setting_on_its_own(self):
        good = json.loads(etcdconf.render(self.m1, "a", GENESIS, etcdconf.choose(self.m1, self.offered), 20)[0])
        cases = [("only over the unix socket", ["listen-client-urls"], "http://127.0.0.1:2379"),
                 ("not on the service mesh", ["listen-peer-urls"], "https://[2001:db8::1]:2380"),
                 ("not on the service mesh", ["initial-advertise-peer-urls"], "http://[fd72:6567:6c61::1]:2380"),
                 ("must require certificates", ["peer-transport-security", "client-cert-auth"], False),
                 ("must require certificates", ["client-transport-security", "auto-tls"], True),
                 ("from the unit's credentials", ["peer-transport-security", "key-file"], "/etc/regalia/etcd/peer.key"),
                 ("TLS 1.3", ["tls-min-version"], "TLS1.2"),
                 ("ten heartbeats", ["election-timeout"], 500)]
        for reason, path, value in cases:
            with self.subTest(path):
                doc = json.loads(json.dumps(good))
                target = doc
                for k in path[:-1]:
                    target = target[k]
                target[path[-1]] = value
                self.refused(reason, etcdconf.check, json.dumps(doc))

    def test_timings_come_from_the_measured_round_trip_and_out_of_bounds_is_refused(self):
        self.assertEqual(etcdconf.timings(20), (100, 1000))           # 500 km: etcd's defaults hold
        self.assertEqual(etcdconf.timings(143.2), (150, 1500))        # a 100 ms WAN with jitter
        for bad in (0, -1, 501, "20", True):
            with self.subTest(bad):
                self.refused("the measured p99 round trip", etcdconf.timings, bad)

    def test_render_refuses_certificates_that_do_not_match_the_members(self):
        certs = etcdconf.choose(self.m1, self.offered)
        self.refused("the certificates are for", etcdconf.render, self.m1, "a", GENESIS, {k: v for k, v in certs.items() if k != "c"}, 20)
        self.refused("initial-cluster-state is new or existing", etcdconf.render, self.m1, "a", GENESIS, certs, 20, state="join")


class Format(unittest.TestCase):
    def test_its_own_domain(self):
        from deploy.baremetal import heartbeat, lease
        for other in (m.DOMAIN, heartbeat.DOMAIN, lease.DOMAIN):
            self.assertFalse(etcdconf.DOMAIN.startswith(other) or other.startswith(etcdconf.DOMAIN))

    def test_a_pem_with_two_certificates_or_none_is_refused(self):
        with self.assertRaises(m.Refused):
            etcdconf.cert_der(CERTS["a"] + CERTS["b"])
        with self.assertRaises(m.Refused):
            etcdconf.cert_der("not a certificate")


if __name__ == "__main__":
    unittest.main()
