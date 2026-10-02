"""deploy/baremetal/lease.py (#74, Phase 14): a running node serves only while an ACTIVE peer with fresh
membership keeps vouching for it. PoC 14.1-14.4 as decisions, each binding of the signed lease with its own
refusal, and the time rules.

The issuers' TPM quotes are built here and signed with OpenSSL P-256 keys (as tests/test_baremetal_attest.py
does); the last class runs issue, install, revocation and a subject reboot on software TPMs."""
import copy
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from deploy.baremetal import attest, lease
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt   # FakeTpm, beat, pub, REVOKE: the heartbeat fixtures

T0 = hbt.T0
SESSION, OTHER_SESSION = "5e" * 32, "0b" * 32
NAMES = ("a", "b", "c")


def slurp(path):
    with open(path, "rb") as f:
        return f.read()


def b2(data):
    return struct.pack(">H", len(data)) + data


class Key:
    """One node's TPM identity: an EK Name, and an AK whose private half OpenSSL holds."""

    def __init__(self, directory, name, n):
        self.pem = os.path.join(directory, name + ".pem")
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", self.pem],
                       check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", self.pem, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
        area = struct.pack(">HHI", attest.ALG_ECC, attest.ALG_SHA256, attest.AK_ATTRIBUTES) + b2(b"") + struct.pack(
            ">HHHHH", attest.ALG_NULL, attest.ALG_ECDSA, attest.ALG_SHA256, attest.CURVE_P256, attest.ALG_NULL) + b2(der[-64:-32]) + b2(der[-32:])
        self.ak_public = b2(area)
        self.ak_name = attest.ak_identity(self.ak_public)[0].hex()
        self.ek_name = "000b" + ("%02x" % (0x10 + n)) * 32

    def signer(self, ek_name=None, domain=True, ak_public=None):
        """What TpmSigner returns: a quote over the digest, by this AK under this EK."""
        def sign(digest):
            signer = attest.qualified_name(bytes.fromhex(ek_name or self.ek_name), bytes.fromhex(self.ak_name))
            quote = (struct.pack(">IH", attest.TPM_GENERATED, attest.ST_ATTEST_QUOTE) + b2(signer) + b2(digest)
                     + struct.pack(">QIIB", 1000, 1, 0, 1) + bytes(8) + struct.pack(">IHB", 1, attest.ALG_SHA256, 3)
                     + bytes([0x80, 0, 0]) + b2(hashlib.sha256(bytes(32)).digest()))
            with tempfile.NamedTemporaryFile() as f:
                f.write(quote)
                f.flush()
                sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", self.pem, f.name], check=True, capture_output=True).stdout
            return {"ak_public": (ak_public or self.ak_public).hex(), "quote": quote.hex(), "sig": sig.hex()}
        return sign


def sign(body, key, **kw):
    """An envelope for an arbitrary lease body: what a peer that signs anything would produce."""
    return {"lease": body, "signature": key.signer(**kw)(lease.signed_digest(body))}


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keydir = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, cls.keydir)
        cls.keys = {name: Key(cls.keydir, name, i) for i, name in enumerate(NAMES)}

    def manifest(self, epoch=1, prev="", **states):
        return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": "p1",
                "issued_at": "2026-09-21T09:00:00Z", "revocation_keys": [hbt.pub(hbt.REVOKE)],
                "nodes": [{"node_id": n, "state": states.get(n, "ACTIVE"), "ek_name": self.keys[n].ek_name,
                           "ak_name": self.keys[n].ak_name, "wg_boot_pub": ("%02x" % (0x70 + i)) * 32,
                           "wg_service_pub": ("%02x" % (0xa0 + i)) * 32, "hsm_serials": ["DENK04041%02d" % i]}
                          for i, n in enumerate(NAMES)]}

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.now, self.authenticated, self.ticks = T0 + 60, True, 5000
        self.clock = lambda: (self.now, self.authenticated)
        self.m1 = self.manifest()
        self.sequence = 0
        self.peers = {name: self.peer(name) for name in ("b", "c")}
        self.beat(self.m1)
        self.holder = lease.Holder("a", SESSION, self.clock, lambda: self.ticks, os.path.join(self.d, "lease.json"),
                                   rand=lambda n: os.urandom(n))

    def peer(self, name, tag=""):
        """A peer's own state: its heartbeat counter and freshness, and its attestation verifier for node a."""
        tpm = hbt.FakeTpm()
        counter = hb.Counter("0x1500018", lock_path=os.path.join(self.d, name + tag + ".lock"), run=tpm)
        counter.define()
        freshness = hb.Freshness(counter, self.clock, lambda: self.ticks, os.path.join(self.d, name + tag + "-freshness.json"))
        policy = {"schema": attest.POLICY_SCHEMA, "nodes": {"a": {"ek_name": self.keys["a"].ek_name,
                                                                  "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}}}}
        attester = attest.Verifier(policy, os.path.join(self.d, name + tag + "-attest.json"))
        self.enroll(attester, self.keys["a"].ak_public)
        return {"freshness": freshness, "attester": attester, "signer": self.keys[name].signer()}

    @staticmethod
    def enroll(attester, ak_public):
        with open(attester.state_path, "w") as f:
            json.dump({"schema": attest.STATE_SCHEMA, "nodes": {"a": {"ak_public": ak_public.hex()}}, "nonces": {}}, f)

    def beat(self, manifest, peers=("b", "c"), **kw):
        self.sequence += 1
        for name in peers:
            self.peers[name]["freshness"].accept(hbt.beat(manifest, self.sequence, **kw), manifest)

    def later(self, seconds):
        self.now += seconds
        self.ticks += seconds * 1000

    def verdict(self, manifest, **override):
        """What attest.Verifier.verify returns once node a has re-attested."""
        return dict({"node": "a", "epoch": manifest["epoch"], "session_id": SESSION, "reset_count": 1, "restart_count": 0,
                     "clock": 1, "clock_safe": True, "pcrs": [7]}, **override)

    def issue(self, issuer="b", manifest=None, request=None, attested="default", **kw):
        manifest = manifest or self.m1
        peer = self.peers.get(issuer, self.peers["b"])
        args = dict(attester=peer["attester"], freshness=peer["freshness"], clock=self.clock, signer=peer["signer"])
        args.update(kw)
        return lease.issue(manifest, issuer, request or self.holder.request(),
                           attested=self.verdict(manifest) if attested == "default" else attested, **args)

    def body(self, manifest=None, **override):
        """A well-formed lease body for node a from peer b."""
        manifest = manifest or self.m1
        return dict({"schema": lease.SCHEMA, "node_id": "a", "ak_name": self.keys["a"].ak_name, "issuer": "b",
                     "epoch": manifest["epoch"], "manifest_digest": m.digest(manifest), "session_id": SESSION, "nonce": "11" * 32,
                     "issued_at": hbt.stamp(self.now), "expires_at": hbt.stamp(self.now + lease.MAX_LIFETIME)}, **override)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))


class Verify(Case):
    """What every verifier requires, whoever it is."""

    def test_a_lease_from_an_active_peer_is_good_for_five_minutes(self):
        envelope = self.issue()
        self.assertEqual(lease.verify(envelope, self.m1, self.now), 300)
        self.assertEqual(sorted(envelope["lease"]), sorted(lease.LEASE_KEYS))
        self.later(299)
        self.assertEqual(lease.verify(envelope, self.m1, self.now), 1)
        self.later(1)
        self.refused("EXPIRED", lease.verify, envelope, self.m1, self.now)

    def test_every_field_is_under_the_signature(self):
        envelope = self.issue()
        for field, other in (("node_id", "c"), ("ak_name", self.keys["c"].ak_name), ("issuer", "c"), ("epoch", 2),
                             ("manifest_digest", "00" * 32), ("session_id", OTHER_SESSION), ("nonce", "22" * 32),
                             ("issued_at", hbt.stamp(self.now + 1)), ("expires_at", hbt.stamp(self.now + 299)), ("schema", "x")):
            with self.subTest(field=field):
                altered = copy.deepcopy(envelope)
                altered["lease"][field] = other
                with self.assertRaises(m.Refused):
                    lease.verify(altered, self.manifest(2, m.digest(self.m1)) if field == "epoch" else self.m1, self.now)
        self.assertEqual(sorted(envelope["lease"]), sorted(lease.LEASE_KEYS))   # and there is no field outside it

    def test_each_binding_is_refused_on_its_own_even_when_validly_signed(self):
        b, c, a = self.keys["b"], self.keys["c"], self.keys["a"]
        for label, reason, envelope in (
                ("another subject AK", "names another AK than the manifest's for a", sign(self.body(ak_name=c.ak_name), b)),
                ("a subject not in the manifest", "z is not in the manifest", sign(self.body(node_id="z"), b)),
                ("an issuer not in the manifest", "z may not authorize", sign(self.body(issuer="z"), b)),
                ("self-issued", "a node does not vouch for itself", sign(self.body(issuer="a"), a)),
                ("signed by another node's AK", "not signed by the AK the manifest names for b", sign(self.body(), c)),
                ("b's AK under another EK", "not signed by b's AK under the EK the manifest names", sign(self.body(), b, ek_name=c.ek_name)),
                ("another manifest at this epoch", "another manifest at epoch 1 (digest mismatch)", sign(self.body(manifest_digest="00" * 32), b)),
                ("a newer epoch than the verifier's", "newer than this verifier's 1: fetch the chain", sign(self.body(epoch=2), b)),
                ("too long a life", "lives at most 300 seconds", sign(self.body(expires_at=hbt.stamp(self.now + 301)), b)),
                ("no life", "expires_at must be after issued_at", sign(self.body(expires_at=hbt.stamp(self.now)), b)),
                ("issued in the future", "issued in the future", sign(self.body(issued_at=hbt.stamp(self.now + 31), expires_at=hbt.stamp(self.now + 300)), b)),
                ("expired", "EXPIRED", sign(self.body(issued_at=hbt.stamp(self.now - 400), expires_at=hbt.stamp(self.now - 100)), b))):
            with self.subTest(label):
                self.refused(reason, lease.verify, envelope, self.m1, self.now)
        ahead = sign(self.body(issued_at=hbt.stamp(self.now + 30), expires_at=hbt.stamp(self.now + 330)), b)
        self.assertEqual(lease.verify(ahead, self.m1, self.now), 330)   # 30 s of skew between two authenticated clocks

    def test_the_quote_must_be_a_tpm_quote_over_this_lease_under_the_lease_domain(self):
        body, b = self.body(), self.keys["b"]
        no_domain = {"lease": body, "signature": b.signer()(hashlib.sha256(m.canonical(body)).digest())}
        self.refused("the quote is not over this lease", lease.verify, no_domain, self.m1, self.now)
        heartbeat_domain = {"lease": body, "signature": b.signer()(hashlib.sha256(hb.DOMAIN + m.canonical(body)).digest())}
        self.refused("the quote is not over this lease", lease.verify, heartbeat_domain, self.m1, self.now)
        good = sign(body, b)
        for label, reason, change in (
                ("an altered signature", "signature does not verify", lambda s: s.update(sig=s["sig"][:-2] + ("00" if s["sig"][-2:] != "00" else "01"))),
                ("an altered quote", "signature does not verify", lambda s: s.update(quote=s["quote"][:-2] + "ff")),
                ("not a TPM structure", "lease signature is refused", lambda s: s.update(quote="00" * 40)),
                ("an unrestricted key", "restricted, sign-only", lambda s: s.update(ak_public=s["ak_public"].replace("00050072", "00040072", 1))),
                ("uppercase hex", "signature.sig must be lowercase hex", lambda s: s.update(sig=s["sig"].upper())),
                ("an oversized quote", "signature.quote must be lowercase hex, at most 1024 bytes", lambda s: s.update(quote="00" * 1025)),
                ("an extra field", "signature fields mismatch", lambda s: s.update(key="x"))):
            with self.subTest(label):
                envelope = copy.deepcopy(good)
                change(envelope["signature"])
                self.refused(reason, lease.verify, envelope, self.m1, self.now)
        self.refused("envelope fields mismatch", lease.verify, dict(good, extra=1), self.m1, self.now)
        self.assertEqual(lease.verify(good, self.m1, self.now), 300)

    def test_poc_14_3_a_manifest_that_revokes_the_subject_or_the_issuer_kills_the_lease_at_once(self):
        envelope = self.issue()
        for state in ("QUARANTINED", "RETIRED", "REVOKED_STOLEN", "MAINTENANCE"):
            with self.subTest(subject=state):
                revoked = self.manifest(2, m.digest(self.m1), a=state)
                self.refused("a may not serve under epoch 2 (%s)" % state, lease.verify, envelope, revoked, self.now)
        for state in ("QUARANTINED", "RETIRED", "REVOKED_STOLEN", "MAINTENANCE", "DRAINING"):
            with self.subTest(issuer=state):
                self.refused("b may not authorize under epoch 2", lease.verify, envelope, self.manifest(2, m.digest(self.m1), b=state), self.now)
        # an unrelated change (c drained) does not: the verifier's own manifest still lets a serve and b authorize
        self.assertEqual(lease.verify(envelope, self.manifest(2, m.digest(self.m1), c="DRAINING"), self.now), 300)
        draining = self.manifest(a="DRAINING")           # a DRAINING node still serves, so it is still vouched for
        self.beat(draining)
        self.assertEqual(lease.verify(self.issue(manifest=draining), draining, self.now), 300)

    def test_malformed_leases_are_refused(self):
        for label, reason, change in (
                ("unknown field", "lease fields mismatch", lambda b: b.update(site="sitea")),
                ("missing nonce", "lease fields mismatch", lambda b: b.pop("nonce")),
                ("schema", "schema must be", lambda b: b.update(schema="regalia.runtime-lease/v0")),
                ("node id", "node_id must be a node ID", lambda b: b.update(node_id="A")),
                ("issuer", "issuer must be a node ID", lambda b: b.update(issuer="")),
                ("ak_name", "ak_name must be 68 lowercase hex", lambda b: b.update(ak_name="00")),
                ("epoch", "epoch must be an integer >= 1", lambda b: b.update(epoch=True)),
                ("session", "session_id must be 64 lowercase hex", lambda b: b.update(session_id="5E" * 32)),
                ("nonce", "nonce must be 64 lowercase hex", lambda b: b.update(nonce="1")),
                ("time", "issued_at must be UTC", lambda b: b.update(issued_at=self.now))):
            with self.subTest(label):
                body = self.body()
                change(body)
                self.refused(reason, lease.verify, sign(body, self.keys["b"]), self.m1, self.now)


class Issue(Case):
    """What a peer requires before it vouches."""

    def test_poc_14_1_an_active_peer_with_fresh_membership_issues_to_a_node_that_re_attested(self):
        request = self.holder.request()
        envelope = self.issue(request=request)
        self.assertEqual(envelope["lease"], self.body(nonce=request["nonce"]))
        self.assertEqual(self.holder.install(envelope, self.m1), 300)
        self.assertEqual(self.holder.check(self.m1), 300)

    def test_a_lease_never_outlives_the_issuer_s_heartbeat(self):
        self.later(hb.MAX_LIFETIME - 60 - 100)          # the heartbeat has 100 s left
        envelope = self.issue()
        self.assertEqual(lease.verify(envelope, self.m1, self.now), 100)
        self.later(100)
        self.refused("EXPIRED: the heartbeat expired", self.issue)

    def test_who_may_issue_and_to_whom(self):
        for state in ("MAINTENANCE", "DRAINING", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"):
            with self.subTest(issuer=state):
                self.refused("b may not authorize under epoch 1", self.issue, manifest=self.manifest(b=state))
        for state in ("MAINTENANCE", "QUARANTINED", "RETIRED", "REVOKED_STOLEN"):
            with self.subTest(subject=state):
                self.refused("a may not serve under epoch 1: no lease", self.issue, manifest=self.manifest(a=state))
        self.refused("z may not authorize", self.issue, issuer="z")
        self.refused("a node does not vouch for itself", self.issue, issuer="a")
        self.refused("z may not serve", self.issue, request={"node_id": "z", "session_id": SESSION, "nonce": "11" * 32})

    def test_partition_and_authority_outage_a_peer_without_a_live_heartbeat_issues_nothing(self):
        cut_off = self.peer("b", "-cut-off")             # a peer that never received a heartbeat
        self.refused("no heartbeat is held", self.issue, freshness=cut_off["freshness"])
        m2 = self.manifest(2, m.digest(self.m1), c="DRAINING")
        self.refused("the heartbeat is for epoch 1, the current manifest is epoch 2", self.issue, manifest=m2)   # new epoch, no heartbeat for it yet
        self.later(hb.MAX_LIFETIME)                      # the authority is down for a day
        self.refused("EXPIRED: the heartbeat expired", self.issue)
        self.beat(self.m1, issued=self.now)
        self.assertEqual(lease.verify(self.issue(), self.m1, self.now), 300)

    def test_time_must_be_authenticated_and_not_run_backwards(self):
        self.authenticated = False
        self.refused("time is not authenticated", self.issue)
        self.authenticated = True
        self.issue()
        self.now -= 3600
        self.refused("the clock went backwards", self.issue)

    def test_the_subject_must_have_just_re_attested_as_the_node_the_manifest_names(self):
        self.refused("has not re-attested", self.issue, attested=None)
        for field, value in (("node", "c"), ("session_id", OTHER_SESSION), ("epoch", 7)):
            with self.subTest(field=field):
                self.refused("the attestation is for another %s" % field, self.issue, attested=self.verdict(self.m1, **{field: value}))
        b = self.peers["b"]
        b["attester"].nodes["a"]["ek_name"] = self.keys["c"].ek_name
        self.refused("does not pin the manifest's EK for a", self.issue)
        b["attester"].nodes["a"]["ek_name"] = self.keys["a"].ek_name
        self.enroll(b["attester"], self.keys["c"].ak_public)
        self.refused("the attested AK is not the AK the manifest names for a", self.issue)
        with open(b["attester"].state_path, "w") as f:
            json.dump({"schema": attest.STATE_SCHEMA, "nodes": {}, "nonces": {}}, f)
        self.refused("the attested AK is not the AK the manifest names for a", self.issue)
        with open(b["attester"].state_path, "w") as f:
            f.write("{")
        self.refused("the attestation state is refused", self.issue)
        del b["attester"].nodes["a"]
        self.refused("does not pin the manifest's EK for a", self.issue)

    def test_a_malformed_request_is_refused(self):
        for label, reason, request in (("extra field", "lease request fields mismatch", {"node_id": "a", "session_id": SESSION, "nonce": "11" * 32, "ttl": 9}),
                                       ("node id", "node_id must be a node ID", {"node_id": "A!", "session_id": SESSION, "nonce": "11" * 32}),
                                       ("session", "session_id must be 64 lowercase hex", {"node_id": "a", "session_id": "x", "nonce": "11" * 32}),
                                       ("nonce", "nonce must be 64 lowercase hex", {"node_id": "a", "session_id": SESSION, "nonce": "11"})):
            with self.subTest(label):
                self.refused(reason, self.issue, request=request)

    def test_a_tpm_that_cannot_sign_is_a_refusal(self):
        for failing in ("tpm2_readpublic", "tpm2_quote"):
            with self.subTest(failing=failing):
                run = lambda argv, **kw: subprocess.CompletedProcess(argv, 1 if argv[0] == failing else 0, b"", b"no")
                self.refused("%s failed: the lease cannot be signed" % failing, self.issue, signer=lease.TpmSigner(run=run))


class Hold(Case):
    """The running node's side."""

    def test_only_a_lease_that_answers_this_node_s_own_request_is_installed_and_only_once(self):
        self.refused("no runtime lease is held", self.holder.check, self.m1)
        envelope = self.issue()
        self.assertEqual(self.holder.install(envelope, self.m1), 300)
        self.refused("answers no request this node has outstanding", self.holder.install, envelope, self.m1)          # replayed
        foreign = self.issue(request={"node_id": "a", "session_id": SESSION, "nonce": "ab" * 32})                       # asked for by someone else
        self.refused("answers no request this node has outstanding", self.holder.install, foreign, self.m1)
        self.assertEqual(self.holder.check(self.m1), 300)

    def test_a_lease_does_not_survive_the_subject_s_reboot(self):
        envelope = self.issue()
        self.holder.install(envelope, self.m1)
        rebooted = lease.Holder("a", OTHER_SESSION, self.clock, lambda: self.ticks, self.holder.state_path)
        self.refused("another boot session of this node", rebooted.check, self.m1)      # even if /run had survived
        fresh = lease.Holder("a", OTHER_SESSION, self.clock, lambda: self.ticks, os.path.join(self.d, "after-reboot.json"))
        request = self.holder.request()                  # a request made before the reboot, answered after it
        self.refused("another boot session of this node", fresh.install, self.issue(request=request), self.m1)
        self.refused("no runtime lease is held", fresh.check, self.m1)
        new = fresh.request()
        self.assertEqual(new["session_id"], OTHER_SESSION)
        self.assertEqual(fresh.install(self.issue(request=new, attested=self.verdict(self.m1, session_id=OTHER_SESSION)), self.m1), 300)

    def test_a_lease_for_another_node_is_not_installed(self):
        other = lease.Holder("c", SESSION, self.clock, lambda: self.ticks, os.path.join(self.d, "c.json"))
        request = other.request()
        self.refused("the lease is for a, not for this node", other.install, self.issue(request=dict(request, node_id="a")), self.m1)

    def test_poc_14_2_when_one_peer_stops_the_other_renews_and_nothing_else_changes(self):
        before = copy.deepcopy(self.m1)
        self.holder.install(self.issue("b"), self.m1)
        self.later(100)
        self.assertTrue(self.holder.due(self.m1))        # a third used: renew
        request = self.holder.request()
        self.refused("no heartbeat is held", self.issue, "b", request=request, freshness=self.peer("b", "-gone")["freshness"])   # b is gone
        renewed = self.issue("c", request=request)
        self.assertEqual(self.holder.install(renewed, self.m1), 300)
        self.assertFalse(self.holder.due(self.m1))
        with open(self.holder.state_path) as f:
            self.assertEqual(json.load(f)["envelope"]["lease"]["issuer"], "c")
        # c vouching changed no membership and named no site: a lease has no field that could promote anyone
        self.assertEqual(self.m1, before)
        self.assertEqual(set(renewed["lease"]) & {"site", "state", "role", "active", "fencing_epoch"}, set())

    def test_conflicting_renewals_keep_the_later_expiry(self):
        to_b, to_c = self.holder.request(), self.holder.request()
        from_b = self.issue("b", request=to_b)
        self.later(10)
        from_c = self.issue("c", request=to_c)
        self.assertEqual(self.holder.install(from_c, self.m1), 300)
        self.assertEqual(self.holder.install(from_b, self.m1), 300)      # the earlier one arrives late: the later expiry stays
        with open(self.holder.state_path) as f:
            state = json.load(f)
        self.assertEqual((state["envelope"]["lease"]["issuer"], state["nonces"]), ("c", []))
        self.later(291)
        self.refused("EXPIRED", lease.verify, from_b, self.m1, self.now)
        self.assertEqual(self.holder.check(self.m1), 9)

    def test_poc_14_3_a_revoked_running_node_is_refused_renewal_and_stops_within_the_lease_bound(self):
        self.holder.install(self.issue("b"), self.m1)
        revoked = self.manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        self.beat(revoked, issued=self.now)                              # b and c have the revoking manifest and a heartbeat for it
        for peer in ("b", "c"):
            self.refused("a may not serve under epoch 2: no lease", self.issue, peer, manifest=revoked, attested=self.verdict(revoked))
        # wherever the manifest has arrived, the lease is dead already
        self.refused("a may not serve under epoch 2", self.holder.check, revoked)
        with open(self.holder.state_path) as f:
            held = json.load(f)["envelope"]
        self.refused("a may not serve under epoch 2", lease.verify, held, revoked, self.now)
        # a node that never took the manifest runs out at the lease's expiry, and no later
        self.later(lease.MAX_LIFETIME - 1)
        self.assertEqual(self.holder.check(self.m1), 1)
        self.later(1)
        self.refused("EXPIRED: the runtime lease expired", self.holder.check, self.m1)
        self.assertTrue(self.holder.due(self.m1))

    def test_poc_14_4_stale_authorization_is_refused_by_the_node_and_by_everyone_else(self):
        self.holder.install(self.issue("b"), self.m1)
        with open(self.holder.state_path) as f:
            stale = json.load(f)["envelope"]
        self.later(lease.MAX_LIFETIME + 5)
        self.refused("EXPIRED", self.holder.check, self.m1)
        # cooperative control: the local clock set back does not revive it,
        self.now -= lease.MAX_LIFETIME
        self.refused("the clock went backwards", self.holder.check, self.m1)
        self.authenticated = False
        self.refused("time is not authenticated", self.holder.check, self.m1)
        self.authenticated = True
        # nor does deleting the node's own floor (a local process with root can do that) ...
        with open(self.holder.state_path) as f:
            state = json.load(f)
        state["floor"] = None
        with open(self.holder.state_path, "w") as f:
            json.dump(state, f)
        self.assertGreater(self.holder.check(self.m1), 0)                # ... the LOCAL check is then fooled: it is cooperative
        # external control: a verifier with its own authenticated clock is not
        self.refused("EXPIRED", lease.verify, stale, self.m1, T0 + 60 + lease.MAX_LIFETIME + 5)
        forged = copy.deepcopy(stale)
        forged["lease"].update(issued_at=hbt.stamp(T0 + 60 + lease.MAX_LIFETIME), expires_at=hbt.stamp(T0 + 60 + 2 * lease.MAX_LIFETIME))
        self.refused("the quote is not over this lease", lease.verify, forged, self.m1, T0 + 60 + lease.MAX_LIFETIME + 5)
        self_signed = sign(self.body(issuer="a", issued_at=hbt.stamp(T0 + 400), expires_at=hbt.stamp(T0 + 700)), self.keys["a"])
        self.refused("a node does not vouch for itself", lease.verify, self_signed, self.m1, T0 + 500)

    def test_renewal_is_due_at_a_third_of_the_lifetime(self):
        self.assertTrue(self.holder.due(self.m1))        # nothing held
        self.holder.install(self.issue(), self.m1)
        self.later(99)
        self.assertFalse(self.holder.due(self.m1))
        self.later(1)
        self.assertTrue(self.holder.due(self.m1))

    def test_the_state_file_is_strict_private_and_bounded(self):
        for _ in range(lease.MAX_OUTSTANDING + 3):
            last = self.holder.request()
        with open(self.holder.state_path) as f:
            good = json.load(f)
        self.assertEqual(len(good["nonces"]), lease.MAX_OUTSTANDING)
        self.assertEqual(good["nonces"][-1], last["nonce"])
        self.assertEqual(os.stat(self.holder.state_path).st_mode & 0o777, 0o600)
        for label, reason, doc in (("unknown field", "lease state fields mismatch", dict(good, extra=1)),
                                   ("too many nonces", "nonces must be a short list", dict(good, nonces=["11" * 32] * 5)),
                                   ("bad nonce", "a stored nonce must be 64 lowercase hex", dict(good, nonces=["x"])),
                                   ("bad floor", "floor fields mismatch", dict(good, floor={"time": 1}))):
            with self.subTest(label):
                with open(self.holder.state_path, "w") as f:
                    json.dump(doc, f)
                self.refused(reason, self.holder.check, self.m1)
        with open(self.holder.state_path, "w") as f:
            f.write(" " * (lease.MAX_BYTES + 1))
        self.refused("oversized", self.holder.request)
        self.refused("node_id must be a node ID", lease.Holder, "A", SESSION, self.clock, lambda: 0, "x")
        self.refused("session_id must be 64 lowercase hex", lease.Holder, "a", "x", self.clock, lambda: 0, "x")


class OnSwtpm(unittest.TestCase):
    """Two software TPMs: node a re-attests to peer b (attest.py), b signs the lease with its own TPM, a
    holds it; a is revoked; a reboots. Where the tools are provisioned (REGALIA_EXPECT_SWTPM=1) a missing
    one is a failure, not a skip."""

    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_createak", "tpm2_quote", "tpm2_nvdefine", "openssl")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm, tpm2-tools and openssl are expected here and were not found")
            self.skipTest("needs swtpm, tpm2-tools and openssl")
        self.d = tempfile.mkdtemp(dir="/tmp")            # short: unix socket paths
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pids = {}
        self.addCleanup(lambda: [os.kill(pid, 15) for pid in self.pids.values()])
        self.tcti = {name: self.boot(name) for name in ("a", "b")}
        for name in ("a", "b"):
            os.mkdir(self.d + "/" + name)
            self.on(name, attest.node_init, self.d + "/" + name)
        self.now = T0 + 60
        self.clock = lambda: (self.now, True)
        names = {n: {k: attest.name_of(attest.public_area(slurp("%s/%s/%s.pub" % (self.d, n, k)), k)).hex()
                     for k in ("ek", "ak")} for n in ("a", "b")}
        self.manifest = lambda epoch=1, prev="", **states: {
            "schema": m.SCHEMA, "epoch": epoch, "prev_digest": prev, "policy_version": "p1", "issued_at": "2026-09-21T09:00:00Z",
            "revocation_keys": [hbt.pub(hbt.REVOKE)],
            "nodes": [{"node_id": n, "state": states.get(n, "ACTIVE"), "ek_name": names[n]["ek"], "ak_name": names[n]["ak"],
                       "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": ("%02x" % (0xa0 + i)) * 32,
                       "hsm_serials": ["DENK04041%02d" % i]} for i, n in enumerate(("a", "b"))]}
        self.m1 = self.manifest()
        # peer b: its heartbeat counter and clock on its own TPM, and its attestation verifier for a (intake + enrollment)
        counter = hb.Counter("0x1500018", tcti=self.tcti["b"], lock_path=self.d + "/lock")
        counter.define()
        self.freshness = hb.Freshness(counter, self.clock, hb.TpmClock(tcti=self.tcti["b"]), self.d + "/freshness.json")
        self.freshness.accept(hbt.beat(self.m1, 1), self.m1)
        probe = self.quote("a", "00" * 32, "00" * 32)[0]
        policy = {"schema": attest.POLICY_SCHEMA, "nodes": {"a": {"ek_name": names["a"]["ek"], "pcrs": {"7": "00" * 32},
                                                                  "tpm_firmware_version": attest.parse_quote(probe)["firmware_version"]}}}
        self.attester = attest.Verifier(policy, self.d + "/attest.json")
        credential = self.attester.challenge("a", *(slurp("%s/a/%s.pub" % (self.d, k)) for k in ("ek", "ak")))
        with open(self.d + "/cred", "wb") as f:
            f.write(credential)
        self.on("a", attest.node_activate, self.d + "/cred", self.d + "/secret")
        with open(self.d + "/secret", "rb") as f:
            self.attester.enroll("a", f.read())
        self.signer = lease.TpmSigner(tcti=self.tcti["b"])

    def boot(self, name):
        """Start (or restart) a node's TPM: TPM2_Startup(CLEAR), as a reboot does."""
        if name in self.pids:
            os.kill(self.pids.pop(name), 15)
            time.sleep(0.3)
        state, sock = "%s/tpm-%s" % (self.d, name), "%s/%s.sock" % (self.d, name)
        os.makedirs(state, exist_ok=True)
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + state, "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=%s/%s.pid" % (self.d, name)], check=True, capture_output=True)
        time.sleep(0.5)
        with open("%s/%s.pid" % (self.d, name)) as f:
            self.pids[name] = int(f.read())
        return "swtpm:path=" + sock

    def on(self, name, fn, *args):
        """attest.py's node-side calls talk to the TPM named by TPM2TOOLS_TCTI."""
        with unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI=self.tcti[name]):
            return fn(*args)

    def quote(self, name, session, nonce, epoch=1):
        paths = (self.d + "/q.msg", self.d + "/q.sig")
        self.on(name, attest.node_quote, name, epoch, bytes.fromhex(session), b"ephemeral key of boot " + bytes.fromhex(session), bytes.fromhex(nonce), [7], *paths)
        return tuple(slurp(p) for p in paths)

    def reattest(self, session, manifest):
        """Node a proves its boot session to peer b with a fresh quote; returns b's verdict."""
        nonce = self.attester.nonce("a")
        quote, signature = self.quote("a", session, nonce.hex(), manifest["epoch"])
        return self.attester.verify("a", manifest["epoch"], bytes.fromhex(session), b"ephemeral key of boot " + bytes.fromhex(session), nonce, quote, signature)

    def issue(self, holder, manifest, session):
        return lease.issue(manifest, "b", holder.request(), self.attester, self.reattest(session, manifest), self.freshness, self.clock, self.signer)

    def refused(self, reason, fn, *args):
        with self.assertRaises(m.Refused) as caught:
            fn(*args)
        self.assertIn(reason, str(caught.exception))

    def test_issue_hold_revoke_and_reboot_on_real_tpm_quotes(self):
        holder = lease.Holder("a", SESSION, self.clock, hb.TpmClock(tcti=self.tcti["a"]), self.d + "/lease.json")
        # 14.1: b's TPM signs a lease for the re-attested a; a holds it
        envelope = self.issue(holder, self.m1, SESSION)
        self.assertEqual(holder.install(envelope, self.m1), 300)
        self.assertEqual(lease.verify(envelope, self.m1, self.now), 300)
        self.refused("answers no request this node has outstanding", holder.install, envelope, self.m1)
        altered = copy.deepcopy(envelope)
        altered["lease"]["expires_at"] = hbt.stamp(self.now + 299)
        self.refused("the quote is not over this lease", lease.verify, altered, self.m1, self.now)
        # a's own TPM signing for itself, as issuer b: not the AK the manifest names for b
        forged = {"lease": envelope["lease"], "signature": lease.TpmSigner(tcti=self.tcti["a"])(lease.signed_digest(envelope["lease"]))}
        self.refused("not signed by the AK the manifest names for b", lease.verify, forged, self.m1, self.now)
        # renewal
        self.now += 100
        self.assertTrue(holder.due(self.m1))
        self.assertEqual(holder.install(self.issue(holder, self.m1, SESSION), self.m1), 300)
        # 14.3: a is revoked; b has the manifest and a heartbeat for it; no renewal, and the held lease is dead under it
        revoked = self.manifest(2, m.digest(self.m1), a="REVOKED_STOLEN")
        self.freshness.accept(hbt.beat(revoked, 2, issued=self.now), revoked)
        self.refused("a may not serve under epoch 2: no lease", self.issue, holder, revoked, SESSION)
        self.refused("a may not serve under epoch 2", holder.check, revoked)
        self.now += lease.MAX_LIFETIME
        self.refused("EXPIRED: the runtime lease expired", holder.check, self.m1)

    def test_a_reboot_of_the_subject_needs_a_new_attested_session(self):
        holder = lease.Holder("a", SESSION, self.clock, hb.TpmClock(tcti=self.tcti["a"]), self.d + "/lease.json")
        old_request = holder.request()
        holder.install(self.issue(holder, self.m1, SESSION), self.m1)
        self.tcti["a"] = self.boot("a")                  # a reboots: /run is gone, the TPM's resetCount moves on
        rebooted = lease.Holder("a", OTHER_SESSION, self.clock, hb.TpmClock(tcti=self.tcti["a"]), self.d + "/lease-after-reboot.json")
        self.refused("no runtime lease is held", rebooted.check, self.m1)
        with self.assertRaises(attest.Refused) as caught:    # the old session cannot be re-attested after the reboot
            self.reattest(SESSION, self.m1)
        self.assertIn("from an earlier boot", str(caught.exception))
        # a peer handed the old boot's request with the new boot's attestation refuses: the sessions differ
        self.refused("the attestation is for another session_id", lease.issue, self.m1, "b", old_request, self.attester,
                     self.reattest(OTHER_SESSION, self.m1), self.freshness, self.clock, self.signer)
        self.assertEqual(rebooted.install(self.issue(rebooted, self.m1, OTHER_SESSION), self.m1), 300)


if __name__ == "__main__":
    unittest.main()
