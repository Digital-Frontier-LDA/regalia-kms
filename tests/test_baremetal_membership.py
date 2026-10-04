"""deploy/baremetal/membership.py (#68, Phase 8): signed manifests, the capability matrix, root versus
revocation authority, the epoch chain, and the TPM-backed high-water mark with its manifest-digest record
(PoC 8.3 runs on swtpm)."""
import copy
import fcntl
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

from deploy.baremetal import membership as m
from deploy.baremetal import replacement
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

    def test_issued_at_is_ascii_digits_at_full_width(self):
        """Signed correctly, so only the timestamp refuses them; the pre-root Go reader refuses the same (#66).
        strptime alone accepts each of these."""
        for label, at in (("Arabic-Indic digits", "٢٠٢٦-١٠-٠٢T٠٩:٠٠:٠٠Z"), ("a fullwidth year", "２０２６-10-02T09:00:00Z"),
                          ("a Devanagari year", "२०२६-10-02T09:00:00Z"), ("an unpadded month", "2026-1-02T09:00:00Z"),
                          ("unpadded fields", "2026-10-2T9:0:0Z"), ("a one-digit second", "2026-10-02T09:00:0Z"),
                          ("a day padded with a space", "2026-10- 2T09:00:00Z"), ("lowercase t and z", "2026-10-02t09:00:00z"),
                          ("a trailing newline", "2026-10-02T09:00:00Z\n"), ("no such date", "2026-02-30T09:00:00Z")):
            with self.subTest(label):
                man = manifest(2, m.digest(self.m1), three())
                man["issued_at"] = at
                with self.assertRaisesRegex(m.Refused, "issued_at must be UTC"):
                    m.accept(self.m1, sign(man, ROOT), ROOT_PUB)

    def test_ambiguous_encodings_are_refused_at_parse(self):
        for raw in ('{"a": 1, "a": 2}', '{"epoch": 1.0}', '{"epoch": NaN}'):
            with self.subTest(raw=raw), self.assertRaises(m.Refused):
                m.load(raw)

    def test_hostile_input_is_a_refusal_never_another_exception(self):
        """48's findings: both are reachable with an unsigned envelope, before any signature is checked."""
        with self.assertRaisesRegex(m.Refused, "not valid JSON: nested too deeply"):
            m.load(b"[" * 30000 + b"]" * 30000)                                  # was a RecursionError
        for label, bad in (("v1", manifest(2, m.digest(self.m1), three())), ("v2", manifest2(2, m.digest(self.m1), v2(three())))):
            for state in (["ACTIVE"], {"ACTIVE": 1}, None, 1):                   # a list or dict was a TypeError (unhashable)
                with self.subTest(schema=label, state=state):
                    bad["nodes"][0]["state"] = state
                    with self.assertRaisesRegex(m.Refused, r"nodes\[0\].state .* is not a known state"):
                        m.accept(self.m1, sign(bad, ROOT), ROOT_PUB)

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


def ssh(n):
    return ("%02x" % (0xd0 + n)) * 32


def v2(nodes, bare=()):
    """The same nodes under schema v2: each with its SSH host key, except those named in `bare`."""
    return [entry if entry["node_id"] in bare else dict(entry, ssh_host_pub=ssh(i)) for i, entry in enumerate(nodes)]


def manifest2(epoch, prev, nodes, life=86400, **kw):
    return dict(manifest(epoch, prev, nodes, **kw), schema=m.SCHEMA_V2, heartbeat_max_lifetime_s=life)


class SchemaV2(unittest.TestCase):
    """#143: regalia.membership/v2 adds the required node field ssh_host_pub, an identity like the others.
    The chain moves from v1 to v2 in a root-signed manifest only, and never back."""

    def setUp(self):
        self.m1 = m.accept(None, sign(manifest(1, "", three()), ROOT), ROOT_PUB)                       # v1
        self.e2 = sign(manifest2(2, m.digest(self.m1), v2(three())), ROOT)                             # the switch
        self.m2 = m.accept(self.m1, self.e2, ROOT_PUB)

    def refused(self, reason, current, man, key=ROOT, signer="root"):
        with self.assertRaises(m.Refused) as caught:
            m.accept(current, sign(man, key, signer), ROOT_PUB)
        self.assertIn(reason, str(caught.exception))

    def next2(self, nodes, **kw):
        return manifest2(3, m.digest(self.m2), nodes, **kw)

    def test_a_chain_moves_from_v1_to_v2_and_verifies_from_epoch_1(self):
        self.assertEqual((self.m1["schema"], self.m2["schema"]), ("regalia.membership/v1", "regalia.membership/v2"))
        self.assertEqual(self.m2["nodes"][0]["ssh_host_pub"], ssh(0))
        e1 = sign(manifest(1, "", three()), ROOT)
        e3 = sign(self.next2(v2(three(a="MAINTENANCE"))), REVOKE, "revocation")                        # v2 goes on under v2
        tip = m.accept_chain(None, [e1, self.e2, e3], ROOT_PUB)
        self.assertEqual((tip["epoch"], tip["schema"], m.may(tip, "a", "serve"), m.may(tip, "b", "serve")), (3, m.SCHEMA_V2, False, True))

    def test_a_first_manifest_may_be_v2(self):
        first = m.accept(None, sign(manifest2(1, "", v2(three())), ROOT), ROOT_PUB)
        self.assertEqual((first["epoch"], first["schema"]), (1, m.SCHEMA_V2))

    def test_only_the_root_changes_the_schema(self):
        self.refused("only the root can change the schema (regalia.membership/v1 to regalia.membership/v2)",
                     self.m1, manifest2(2, m.digest(self.m1), v2(three())), REVOKE, "revocation")

    def test_the_schema_never_goes_back(self):
        back = manifest(3, m.digest(self.m2), three())
        self.refused("schema regalia.membership/v1 cannot follow regalia.membership/v2: the schema only moves forward", self.m2, back)
        self.refused("the schema only moves forward", self.m2, back, REVOKE, "revocation")
        self.assertEqual(m.accept(self.m2, sign(self.next2(v2(three())), ROOT), ROOT_PUB)["schema"], m.SCHEMA_V2)

    def test_an_unknown_schema_is_refused(self):
        every = "schema must be regalia.membership/v1 or regalia.membership/v2 or regalia.membership/v3 or regalia.membership/v4"
        for bad in ("regalia.membership/v5", "regalia.membership/v0", "", None, 2, ["regalia.membership/v2"]):
            with self.subTest(schema=bad):
                self.refused(every, self.m2, dict(self.next2(v2(three())), schema=bad))
        missing = self.next2(v2(three()))
        del missing["schema"]
        self.refused(every, self.m2, missing)
        with self.assertRaisesRegex(m.Refused, "manifest must be an object"):
            m.validate([missing])

    def test_the_heartbeat_lifetime_is_a_required_field_of_v2_within_the_hard_limits(self):
        self.assertEqual((m.HEARTBEAT_MIN_S, m.HEARTBEAT_HARD_MAX_S), (3600, 604800))
        for good in (3600, 86400, 172800, 604800):
            with self.subTest(life=good):
                self.assertEqual(m.accept(self.m2, sign(self.next2(v2(three()), life=good), ROOT), ROOT_PUB)["heartbeat_max_lifetime_s"], good)
        for bad in (3599, 604801, 0, -86400, 86400.0, "86400", True, None, [86400]):
            with self.subTest(life=bad):
                self.refused("heartbeat_max_lifetime_s must be an integer from 3600 to 604800", self.m2, self.next2(v2(three()), life=bad))
        absent = self.next2(v2(three()))
        del absent["heartbeat_max_lifetime_s"]
        self.refused("manifest fields mismatch: missing=['heartbeat_max_lifetime_s']", self.m2, absent)              # no default
        self.refused("manifest fields mismatch: missing=[] unknown=['heartbeat_max_lifetime_s']", self.m1,
                     dict(manifest(2, m.digest(self.m1), three()), heartbeat_max_lifetime_s=86400))                  # and not a v1 field

    def test_only_the_root_changes_the_heartbeat_lifetime(self):
        for life in (172800, 3600):                                              # longer or shorter: neither is a restriction a revocation key may make
            with self.subTest(life=life):
                self.refused("a revocation key cannot change heartbeat_max_lifetime_s", self.m2, self.next2(v2(three(a="QUARANTINED")), life=life), REVOKE, "revocation")
                self.assertEqual(m.accept(self.m2, sign(self.next2(v2(three()), life=life), ROOT), ROOT_PUB)["heartbeat_max_lifetime_s"], life)
        kept = m.accept(self.m2, sign(self.next2(v2(three(a="QUARANTINED"))), REVOKE, "revocation"), ROOT_PUB)
        self.assertEqual((kept["heartbeat_max_lifetime_s"], m.may(kept, "a", "serve")), (86400, False))

    def test_each_manifest_is_validated_under_the_schema_it_names(self):
        self.refused("nodes[0] fields mismatch: missing=['ssh_host_pub']", self.m2, self.next2(three()))                 # v2 without the field
        self.refused("nodes[1] fields mismatch: missing=['ssh_host_pub']", self.m2, self.next2(v2(three())[:1] + three()[1:]))
        self.refused("nodes[0] fields mismatch: missing=[] unknown=['ssh_host_pub']", self.m1, manifest(2, m.digest(self.m1), v2(three())))   # v1 with it
        for bad in ("a", None, ["node_id"]):
            with self.subTest(node=bad):
                self.refused("nodes[2] must be an object", self.m2, self.next2(v2(three())[:2] + [bad]))
        for bad in ("d0" * 31, "D0" * 32, "d0" * 33, "ssh-ed25519 AAAA", None, 7):
            with self.subTest(ssh_host_pub=bad):
                nodes = v2(three())
                nodes[2]["ssh_host_pub"] = bad
                self.refused("nodes[2].ssh_host_pub must be 64 lowercase hex", self.m2, self.next2(nodes))

    def test_an_ssh_host_key_is_unique_across_every_node_and_role(self):
        for label, reason, change in (
                ("another node's SSH key", "ssh_host_pub of b is already used (ssh_host_pub of a)", lambda n: n[1].update(ssh_host_pub=n[0]["ssh_host_pub"])),
                ("another node's WireGuard key", "ssh_host_pub of b is already used (wg_boot_pub of a)", lambda n: n[1].update(ssh_host_pub=n[0]["wg_boot_pub"])),
                ("its own WireGuard key", "ssh_host_pub of a is already used (wg_service_pub of a)", lambda n: n[0].update(ssh_host_pub=n[0]["wg_service_pub"])),
                ("a WireGuard key that is an earlier node's SSH key", "wg_boot_pub of c is already used (ssh_host_pub of a)", lambda n: n[2].update(wg_boot_pub=n[0]["ssh_host_pub"]))):
            with self.subTest(label):
                nodes = v2(three())
                change(nodes)
                self.refused(reason, self.m2, self.next2(nodes))

    def test_a_revocation_key_cannot_change_an_ssh_host_key(self):
        nodes = v2(three(a="QUARANTINED"))
        nodes[1]["ssh_host_pub"] = "ee" * 32
        self.refused("a revocation key cannot change ssh_host_pub of b", self.m2, self.next2(nodes), REVOKE, "revocation")
        self.assertEqual(m.accept(self.m2, sign(self.next2(nodes), ROOT), ROOT_PUB)["nodes"][1]["ssh_host_pub"], "ee" * 32)   # the root rotates a live node's

    def test_a_tombstone_keeps_its_ssh_host_key_and_it_is_never_enrolled_again(self):
        retiring = v2(three(c="RETIRED"))
        retiring[2]["ssh_host_pub"] = "ee" * 32
        self.refused("tombstone: c becomes RETIRED and its ssh_host_pub cannot change in the same manifest", self.m2, self.next2(retiring))
        m3 = m.accept(self.m2, sign(self.next2(v2(three(c="RETIRED"))), ROOT), ROOT_PUB)
        after = lambda nodes: manifest2(4, m.digest(m3), nodes)
        changed = v2(three(c="RETIRED"))
        changed[2]["ssh_host_pub"] = "ee" * 32
        self.refused("tombstone: c is RETIRED and its ssh_host_pub cannot change", m3, after(changed))
        reuse = v2(three(c="RETIRED")) + [dict(node("d", n=3), ssh_host_pub=ssh(2))]                   # new hardware, c's old SSH key
        self.refused("ssh_host_pub of d is already used (ssh_host_pub of c)", m3, after(reuse))
        fresh = v2(three(c="RETIRED")) + [dict(node("d", n=3), ssh_host_pub=ssh(3))]
        self.assertEqual(len(m.accept(m3, sign(after(fresh), ROOT), ROOT_PUB)["nodes"]), 4)

    def test_a_node_retired_under_v1_is_never_given_an_ssh_host_key(self):
        """Its hardware may be gone, and a key invented for it would be a fabricated identity in the chain:
        its tombstone keeps exactly the fields it had, at the switch and for ever after."""
        m2 = m.accept(self.m1, sign(manifest(2, m.digest(self.m1), three(c="RETIRED")), REVOKE, "revocation"), ROOT_PUB)      # retired under v1
        switch = lambda nodes: manifest2(3, m.digest(m2), nodes)
        self.refused("tombstone: c is RETIRED and its fields cannot change (ssh_host_pub is neither added nor dropped)", m2, switch(v2(three(c="RETIRED"))))
        m3 = m.accept(m2, sign(switch(v2(three(c="RETIRED"), bare="c")), ROOT), ROOT_PUB)              # the switch, c as it was
        self.assertEqual((m3["schema"], m3["nodes"][2], "ssh_host_pub" in m3["nodes"][0]), (m.SCHEMA_V2, three(c="RETIRED")[2], True))
        moved = v2(three(c="RETIRED"), bare="c")
        moved[2] = dict(moved[2], wg_boot_pub="ee" * 32)
        self.refused("tombstone: c is RETIRED and its wg_boot_pub cannot change", m2, switch(moved))   # the switch changes nothing else of it
        after = lambda nodes: manifest2(4, m.digest(m3), nodes)
        for key, signer in ((ROOT, "root"), (REVOKE, "revocation")):
            with self.subTest(signer=signer):                                                          # nor later, by anyone
                self.refused("tombstone: c is RETIRED and its fields cannot change", m3, after(v2(three(c="RETIRED"))), key, signer)
        m4 = m.accept(m3, sign(after(v2(three(c="REVOKED_STOLEN"), bare="c")), REVOKE, "revocation"), ROOT_PUB)   # still only RETIRED -> REVOKED_STOLEN
        self.assertEqual((m4["nodes"][2]["state"], "ssh_host_pub" in m4["nodes"][2]), ("REVOKED_STOLEN", False))
        self.assertEqual(replacement.identities(m4["nodes"][2]), replacement.identities(three()[2]))  # its v1 identities stay counted

    def test_only_a_tombstone_may_lack_an_ssh_host_key_under_v2(self):
        for state in ("ACTIVE", "MAINTENANCE", "DRAINING", "QUARANTINED"):
            with self.subTest(state=state):
                self.refused("nodes[2] fields mismatch: missing=['ssh_host_pub']", self.m2, self.next2(v2(three(c=state), bare="c")))
        # a live v2 node cannot shed its key by being retired: the retiring manifest records it as it was
        for state in ("RETIRED", "REVOKED_STOLEN"):
            for key, signer in ((ROOT, "root"), (REVOKE, "revocation")):
                with self.subTest(state=state, signer=signer):
                    self.refused("tombstone: c becomes %s and its fields cannot change in the same manifest" % state,
                                 self.m2, self.next2(v2(three(c=state), bare="c")), key, signer)
        # and once retired with its key, it does not lose it
        m3 = m.accept(self.m2, sign(self.next2(v2(three(c="RETIRED"))), ROOT), ROOT_PUB)
        self.refused("tombstone: c is RETIRED and its fields cannot change", m3, manifest2(4, m.digest(m3), v2(three(c="RETIRED"), bare="c")))
        # a v1 node retired IN the switching manifest is recorded as it was too: no key
        self.refused("tombstone: c becomes RETIRED and its fields cannot change in the same manifest",
                     self.m1, manifest2(2, m.digest(self.m1), v2(three(c="RETIRED"))))
        retired_at_switch = m.accept(self.m1, sign(manifest2(2, m.digest(self.m1), v2(three(c="RETIRED"), bare="c")), ROOT), ROOT_PUB)
        self.assertNotIn("ssh_host_pub", retired_at_switch["nodes"][2])
        # a malformed key on a tombstone is still refused, and a keyless tombstone under v1 rules gains no v2 field
        nodes = v2(three(c="RETIRED"))
        nodes[2]["ssh_host_pub"] = "zz" * 32
        self.refused("nodes[2].ssh_host_pub must be 64 lowercase hex", self.m2, self.next2(nodes))

    def test_a_store_holds_a_chain_that_changes_schema(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        hw = m.HighWater("0x1500016", lock_path=d + "/hw.lock", run=FakeTpm())
        hw.define()
        store = m.Store(d + "/membership.json", ROOT_PUB, hw)
        store.commit(sign(manifest(1, "", three()), ROOT))
        store.commit(self.e2)
        again = m.Store(d + "/membership.json", ROOT_PUB, hw)
        self.assertEqual((again.load()["schema"], hw.record()), (m.SCHEMA_V2, (2, m.digest(self.m2))))
        self.assertEqual([e["manifest"]["schema"] for e in again.envelopes()], [m.SCHEMA, m.SCHEMA_V2])
        with self.assertRaisesRegex(m.Refused, "the schema only moves forward"):
            again.commit(sign(manifest(3, m.digest(self.m2), three()), ROOT))
        self.assertEqual(again.load()["epoch"], 2)

    def test_identity_keys_follow_the_node_entry(self):
        one, two = three()[0], v2(three())[0]
        self.assertEqual((m.identity_keys(one), m.identity_keys(two)),
                         (("ek_name", "ak_name", "wg_boot_pub", "wg_service_pub"), ("ek_name", "ak_name", "wg_boot_pub", "wg_service_pub", "ssh_host_pub")))
        self.assertEqual(replacement.identities(two) - replacement.identities(one), {ssh(0)})          # node replacement counts it too
        self.assertEqual(len(replacement.identities(one)), 5)


@unittest.skipUnless(shutil.which("swtpm") and shutil.which("tpm2_nvdefine"), "needs swtpm and tpm2-tools")
class _Swtpm(unittest.TestCase):
    """A fresh swtpm per test, with the HighWater defined on it."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        # Unix sockets in the test's own directory. With TCP the control port was the server's + 1, which
        # nothing reserved: on a busy runner five tries in a row found it taken (CI on #146).
        sock = self.d + "/swtpm.sock"
        r = subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=" + self.d, "--server", "type=unixio,path=" + sock,
                            "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                            "--pid", "file=%s/pid" % self.d], capture_output=True)
        self.assertEqual(r.returncode, 0, "swtpm did not start: %s" % r.stderr.decode(errors="replace"))
        with open(self.d + "/pid") as f:
            pid = int(f.read())
        self.addCleanup(os.kill, pid, 15)
        time.sleep(0.5)
        self.tcti = "swtpm:path=" + sock
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
        for idx in ("0x1500030", "0x1500031", "0x1500034", "0x1500035", "0x1500016", "0x1500017", "0x150001a", "0x150001b"):
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

    def test_define_creates_the_record_at_epoch_0_with_a_zero_digest_in_both_slots(self):
        zero = (0, "00" * 32)
        self.assertEqual((self.hw.record_indices, self.hw.record(), self.hw.slots(), self.hw.pinned(), self.hw.unusable()),
                         (("0x150001a", "0x150001b"), zero, [zero, zero], True, None))
        for index in self.hw.record_indices:
            public = self.nv("nvreadpublic", index).stdout.decode()
            self.assertRegex(public, r"size: 48\b")
            self.assertRegex(public, r"value: 0x20060002\b")             # ordinary; owner write only (no authwrite); owner and auth read; written
            self.assertEqual(self.nv("nvread", index, "-C", "o", "-s", "48").stdout, m.HighWater.slot_bytes(0, "00" * 32))
        self.assertEqual(self.hw.verify(lambda epoch: "00" * 32), 0)
        # a counter without a record (the heartbeat's) defines no record index, and has none to read
        class Plain(m.HighWater):
            RECORD = False
        plain = Plain("0x1500030", tcti=self.tcti, lock_path=self.d + "/plain.lock")
        plain.define()
        self.assertEqual((plain.record_indices, plain.advance(2)), ((), 2))
        for index in ("0x1500034", "0x1500035"):
            self.assertNotEqual(self.nv("nvreadpublic", index).returncode, 0)
        with self.assertRaisesRegex(m.Refused, "this counter keeps no record"):
            plain.record()
        with self.assertRaisesRegex(m.Refused, "the record takes two different NV indices"):
            m.HighWater("0x1500016", record_indices=("0x150001a",))
        with self.assertRaisesRegex(m.Refused, "the record takes two different NV indices"):
            m.HighWater("0x1500016", record_indices=("0x150001a", "0x150001a"))

    def test_the_indices_cannot_be_written_with_their_own_authorization(self):
        """51's third read, on a real (software) TPM: with authwrite and an empty index authorization, a plain
        `tpm2_nvwrite` (the index authorizing itself) and `tpm2_nvincrement` succeeded. Now each needs the owner."""
        for argv, data in ((("nvwrite", "0x150001a", "-i", "-"), m.HighWater.slot_bytes(9, "99" * 32)),
                           (("nvwrite", "0x150001b", "-C", "0x150001b", "-i", "-"), m.HighWater.slot_bytes(9, "99" * 32)),
                           (("nvincrement", "0x1500016"), None),
                           (("nvincrement", "0x1500016", "-C", "0x1500016"), None)):
            with self.subTest(argv=argv):
                self.assertNotEqual(self.nv(*argv, input=data).returncode, 0)
        self.assertEqual((self.hw.value(), self.hw.slots()), (0, [(0, "00" * 32)] * 2))
        # reading stays open: the record is not secret
        self.assertEqual(self.nv("nvread", "0x150001a", "-C", "0x150001a", "-s", "48").stdout, m.HighWater.slot_bytes(0, "00" * 32))

    def test_every_read_works_whatever_the_owner_authorization_is(self):
        """#242: the anchor is read with each index's own authorization, never the owner's, so readers keep
        working once the owner authorization is set and kept off the host. Writes still take the owner (until
        the policy layout), so here they are refused."""
        digest = lambda epoch: "%02x" % epoch * 32 if epoch else "00" * 32
        self.hw.anchor(3, digest)
        reads = lambda: (self.hw.value(), self.hw.record(), self.hw.slots(), self.hw.unusable(), self.hw.verify(digest), self.hw.check(3),
                         self.hw.remains())
        before = reads()
        self.assertEqual(before[:2] + before[3:6], (3, (3, "03" * 32), None, 3, 3))
        self.assertEqual(self.nv("changeauth", "-c", "o", "owner-secret-of-this-test").returncode, 0)
        self.assertNotEqual(self.nv("nvread", "0x1500016", "-C", "o", "-s", "8").returncode, 0)          # the owner's empty password no longer reads
        self.assertEqual(reads(), before)
        with self.assertRaises(m.Refused):
            self.hw.advance(4)
        self.assertEqual(self.hw.value(), 3)

    def test_a_slot_the_owner_cannot_read_still_counts_and_is_replaced(self):
        """51's fourth read, on a real (software) TPM: a slot defined ownerwrite|authread holding a record made
        every owner read fail, and the node had no tooled way out. Now it is an unusable anchor, its record is
        read through its own authorization by remains(), and a re-anchor replaces it."""
        self.hw.anchor(3, lambda epoch: "%02x" % epoch * 32 if epoch else "00" * 32)
        self.assertEqual(self.nv("nvundefine", "0x150001b", "-C", "o").returncode, 0)
        self.assertEqual(self.nv("nvdefine", "0x150001b", "-C", "o", "-s", "48", "-a", "ownerwrite|authread").returncode, 0)
        self.assertEqual(self.nv("nvwrite", "0x150001b", "-C", "o", "-i", "-", input=m.HighWater.slot_bytes(4, "04" * 32)).returncode, 0)
        self.assertNotEqual(self.nv("nvread", "0x150001b", "-C", "o", "-s", "48").returncode, 0)        # the owner cannot read it
        self.assertRegex(self.hw.unusable(), "NV index 0x150001b does not have this anchor's attributes")
        self.assertEqual(self.hw.remains(), (3, [(3, "03" * 32), (4, "04" * 32)]))
        self.hw.redefine(5, "05" * 32)
        self.assertEqual((self.hw.value(), self.hw.slots(), self.hw.unusable()), (5, [(5, "05" * 32)] * 2, None))

    def test_define_refuses_a_record_index_that_exists(self):
        self.assertEqual(self.nv("nvdefine", "0x1500035", "-C", "o", "-s", "48").returncode, 0)
        other = m.HighWater("0x1500030", tcti=self.tcti, lock_path=self.d + "/other.lock")
        with self.assertRaisesRegex(m.Refused, "NV index 0x1500035 already exists"):
            other.define()
        self.assertNotEqual(self.nv("nvreadpublic", "0x1500030").returncode, 0)     # refused before anything was defined

    def test_a_record_index_that_is_gone_or_is_not_one_fails_closed(self):
        """Not what a power cut leaves: an index deleted, or one that is not a 48-byte ordinary index. One good
        slot beside it does not make up for that."""
        zero = lambda epoch: "00" * 32
        for index in self.hw.record_indices:
            cases = (
                ("missing", (), "cannot read NV index %s: the high-water anchor is unavailable \\(fail closed\\)" % index),
                ("a counter", (("nvdefine", index, "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread|authwrite"),
                               ("nvincrement", index, "-C", "o")), "record index %s is not an ordinary index" % index),
                ("too short", (("nvdefine", index, "-C", "o", "-s", "8", "-a", "ownerread|ownerwrite|authread"),
                               ("nvwrite", index, "-C", "o", "-i", "-")), "record index %s is 8 bytes, not 48" % index),
            )
            for label, commands, reason in cases:
                with self.subTest(index=index, case=label):
                    self.nv("nvundefine", index, "-C", "o")
                    self.assertNotEqual(self.nv("nvreadpublic", index).returncode, 0)
                    for argv in commands:
                        self.assertEqual(self.nv(*argv, input=b"\0" * 8 if argv[0] == "nvwrite" else None).returncode, 0, argv)
                    for call in (self.hw.record, self.hw.pinned, self.hw.slots, lambda: self.hw.verify(zero), lambda: self.hw.anchor(1, zero)):
                        with self.assertRaisesRegex(m.Refused, reason):
                            call()
                    self.assertRegex(self.hw.unusable(), reason)
                    self.assertEqual(self.hw.value(), 0)                 # and the counter did not move
            self.nv("nvundefine", index, "-C", "o")                      # put the slot back for the other index's turn
            self.assertEqual(self.nv("nvdefine", index, "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread").returncode, 0)

    def test_a_slot_that_was_never_written_or_holds_garbage_is_passed_over(self):
        digest_of = lambda epoch: "%02x" % epoch * 32 if epoch else "00" * 32
        self.nv("nvundefine", "0x150001a", "-C", "o")                    # defined again and never written: define() cut after its nvdefine
        self.assertEqual(self.nv("nvdefine", "0x150001a", "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread").returncode, 0)
        self.assertEqual((self.hw.slots(), self.hw.record(), self.hw.unusable()), ([None, (0, "00" * 32)], (0, "00" * 32), None))
        self.assertEqual(self.hw.anchor(1, digest_of), 1)                # and that is the slot the next write takes
        self.assertEqual(self.hw.slots(), [(1, "01" * 32), (0, "00" * 32)])
        self.assertEqual(self.nv("nvwrite", "0x150001b", "-C", "o", "-i", "-", input=b"\xa5" * 48).returncode, 0)   # garbage in the older slot
        self.assertEqual((self.hw.slots(), self.hw.record(), self.hw.pinned()), ([(1, "01" * 32), None], (1, "01" * 32), True))
        self.assertEqual(self.hw.anchor(2, digest_of), 2)
        self.assertEqual(self.hw.slots(), [(1, "01" * 32), (2, "02" * 32)])
        self.assertEqual(self.nv("nvwrite", "0x150001b", "-C", "o", "-i", "-", input=b"\xa5" * 48).returncode, 0)   # garbage in the NEWER slot:
        self.assertEqual((self.hw.record(), self.hw.pinned(), self.hw.unusable()), ((1, "01" * 32), False, None))    # the crash window, and repaired
        self.assertEqual((self.hw.anchor(2, digest_of), self.hw.slots()), (2, [(1, "01" * 32), (2, "02" * 32)]))
        for index in self.hw.record_indices:                            # neither slot: nothing to go by
            self.assertEqual(self.nv("nvwrite", index, "-C", "o", "-i", "-", input=b"\xa5" * 48).returncode, 0)
        for call in (self.hw.record, self.hw.pinned, lambda: self.hw.verify(digest_of), lambda: self.hw.anchor(3, digest_of)):
            with self.assertRaisesRegex(m.Refused, "NO RECORD: neither record slot \\(0x150001a, 0x150001b\\) holds a valid record"):
                call()
        self.assertEqual((self.hw.slots(), self.hw.value()), ([None, None], 2))
        self.assertRegex(self.hw.unusable(), "NO RECORD")

    def test_redefine_gives_a_new_anchor_at_the_epoch_asked_for_above_every_old_counter_value(self):
        digest_of = lambda epoch: "%02x" % epoch * 32 if epoch else "00" * 32
        self.hw.anchor(3, digest_of)
        old_counter = int.from_bytes(self.nv("nvread", "0x1500016", "-C", "o", "-s", "8").stdout, "big")
        self.nv("nvundefine", "0x150001b", "-C", "o")                    # one index already gone: the rest is still replaced
        base = self.hw.redefine(7, "07" * 32)
        counter = int.from_bytes(self.nv("nvread", "0x1500016", "-C", "o", "-s", "8").stdout, "big")
        self.assertGreater(counter, old_counter)                         # a new counter, and the old epochs cannot be read back as new ones
        self.assertEqual(counter - base, 7)
        self.assertEqual((self.hw.value(), self.hw.slots(), self.hw.pinned(), self.hw.unusable()), (7, [(7, "07" * 32)] * 2, True, None))
        self.assertEqual(self.hw.anchor(8, lambda epoch: "%02x" % epoch * 32), 8)
        with self.assertRaisesRegex(m.Refused, "a manifest digest must be 64 lowercase hex"):
            self.hw.redefine(9, "nope")
        self.assertEqual(self.hw.value(), 8)                             # refused before anything was deleted

    def test_a_tpm_that_is_not_there_is_a_refusal_not_an_unusable_anchor(self):
        gone = m.HighWater("0x1500016", tcti="swtpm:path=%s/absent.sock" % self.d, lock_path=self.d + "/x.lock")
        for call in (gone.unusable, gone.remains, gone.value, gone.record):
            with self.assertRaisesRegex(m.Refused, "the TPM does not answer .* \\(fail closed\\)") as caught:
                call()
            self.assertNotIsInstance(caught.exception, m.Unusable)


class RecordWrites(unittest.TestCase):
    """What the TPM can refuse or get wrong when the record is written (a TPM that says no cannot be had
    from swtpm on demand: FakeTpm)."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.calls = []
        self.fault = lambda argv: None

    def run_tpm(self, argv, **kw):
        self.calls.append((argv[0][len("tpm2_"):], argv[1]))
        verdict = self.fault(argv)
        if isinstance(verdict, bytes):                       # the tool succeeds and prints this
            return subprocess.CompletedProcess(argv, 0, verdict, b"")
        if isinstance(verdict, tuple):                       # the tool FAILS and still prints this
            return subprocess.CompletedProcess(argv, verdict[0], verdict[1], b"")
        if verdict is not None:
            return subprocess.CompletedProcess(argv, verdict, b"", b"")
        return self.tpm(argv, **kw)

    def anchor(self):
        return m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.run_tpm)

    def test_the_record_takes_two_different_indices(self):
        for bad in (("0x150001a",), ("0x150001a", "0x150001a"), ("0x150001a", "0x150001b", "0x150001c")):
            with self.subTest(record_indices=bad), self.assertRaisesRegex(m.Refused, "the record takes two different NV indices"):
                m.HighWater("0x1500016", record_indices=bad)
        self.assertEqual(m.HighWater("0x1500016", record_indices=["0x1500020", "0x1500021"]).record_indices, ("0x1500020", "0x1500021"))

    def test_redefine_stops_at_an_index_it_cannot_delete(self):
        hw = self.defined()
        hw.anchor(2, lambda epoch: "%02x" % epoch * 32)
        self.fault = lambda argv: 1 if argv[:2] == ["tpm2_nvundefine", "0x1500017"] else None
        del self.calls[:]
        with self.assertRaisesRegex(m.Refused, "cannot delete NV index 0x1500017"):
            hw.redefine(2, "02" * 32)
        # the new record goes in first, then the counter and its base are replaced; no valid record slot is deleted
        self.assertEqual([index for tool, index in self.calls if tool == "nvundefine"], ["0x1500016", "0x1500017"])
        self.assertEqual(hw.remains(), (None, [(2, "02" * 32), (2, "02" * 32)]))     # the new record went in first, over the older slot
        self.fault = lambda argv: None
        hw.redefine(2, "02" * 32)
        self.assertEqual((hw.value(), hw.slots()), (2, [(2, "02" * 32)] * 2))

    def test_define_refuses_an_anchor_any_of_whose_indices_exists(self):
        for index in ("0x1500016", "0x1500017", "0x150001a", "0x150001b"):
            with self.subTest(index=index):
                self.tpm = FakeTpm()
                self.tpm(["tpm2_nvdefine", index, "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite"])
                del self.calls[:]
                with self.assertRaisesRegex(m.Refused, "NV index %s already exists" % index):
                    self.anchor().define()
                self.assertEqual([tool for tool, _ in self.calls if tool in ("nvdefine", "nvwrite", "nvincrement")], [])

    def test_redefine_keeps_the_record_slots_and_writes_the_new_record_into_them(self):
        hw = self.defined()
        hw.anchor(3, lambda epoch: "%02x" % epoch * 32)
        del self.calls[:]
        hw.redefine(5, "05" * 32)
        order = [(tool, index) for tool, index in self.calls if tool in ("nvundefine", "nvdefine", "nvwrite")]
        self.assertEqual(order, [("nvwrite", "0x150001b"), ("nvundefine", "0x1500016"), ("nvundefine", "0x1500017"),
                                 ("nvdefine", "0x1500016"), ("nvdefine", "0x1500017"), ("nvwrite", "0x1500017"), ("nvwrite", "0x150001a")])
        self.assertEqual((hw.value(), hw.slots()), (5, [(5, "05" * 32)] * 2))
        # a slot that is not a proper record slot is replaced
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        self.tpm(["tpm2_nvdefine", "0x150001b", "-C", "o", "-s", "40", "-a", "ownerread|ownerwrite|authread"])
        del self.calls[:]
        hw.redefine(6, "06" * 32)
        self.assertEqual([index for tool, index in self.calls if tool == "nvundefine"], ["0x150001b", "0x1500016", "0x1500017"])
        self.assertEqual((hw.value(), hw.slots()), (6, [(6, "06" * 32)] * 2))

    def test_a_lock_free_verify_for_readers_that_cannot_take_the_lock(self):
        """48's request: the node's root services read the published chain and cannot write the lock's directory."""
        hw = self.defined()
        hw.anchor(3, lambda epoch: "%02x" % epoch * 32)
        reader = m.HighWater("0x1500016", lock_path="/nonexistent/dir/hw.lock", run=self.run_tpm)
        good = lambda epoch: "%02x" % epoch * 32
        self.assertEqual(reader.verify(good, lock=False), 3)
        with self.assertRaises(OSError):
            reader.verify(good)                                          # the locking form needs the lock
        with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 3 is not the one this node's TPM recorded"):
            reader.verify(lambda epoch: "aa" * 32 if epoch == 3 else good(epoch), lock=False)
        self.tpm(["tpm2_nvincrement", "0x1500016", "-C", "o"])             # a commit in progress: the counter moved, the record not yet
        slots = hw.slots()
        del self.calls[:]                                                # before the call (51: a repair on THIS call was not seen)
        self.assertEqual(reader.verify(good, lock=False), 4)
        self.assertEqual([tool for tool, _ in self.calls if tool in ("nvwrite", "nvincrement", "nvdefine", "nvundefine")], [])   # repairs nothing
        self.assertEqual(hw.slots(), slots)
        # a redefinition between the reads (the base changes under the reader): refused, not answered with a mixed epoch
        reads = []
        real = reader._base

        def base_then_redefined():
            reads.append(1)
            if len(reads) == 2:
                hw.redefine(9, "09" * 32)
            return real()
        with unittest.mock.patch.object(reader, "_base", base_then_redefined):
            with self.assertRaisesRegex(m.Refused, "changed during the read: read again"):
                reader.verify(lambda epoch: "%02x" % epoch * 32 if epoch in (3, 4, 9) else good(epoch), lock=False)
        # the base comes back the same and only the counter moved (two redefinitions in quick succession): still refused
        epochs = iter([9, 10])
        real_epoch = reader._epoch
        with unittest.mock.patch.object(reader, "_epoch", lambda base: next(epochs)):
            with self.assertRaisesRegex(m.Refused, "changed during the read: read again"):
                reader.verify(lambda epoch: "%02x" % epoch * 32, lock=False)

    def test_redefine_refuses_a_digest_that_is_not_one_before_deleting_anything(self):
        hw = self.defined()
        hw.anchor(2, lambda epoch: "%02x" % epoch * 32)
        del self.calls[:]
        for bad in ("nope", "AB" * 32, None):
            with self.subTest(digest=bad), self.assertRaisesRegex(m.Refused, "a manifest digest must be 64 lowercase hex"):
                hw.redefine(3, bad)
        self.assertEqual([tool for tool, _ in self.calls if tool in ("nvundefine", "nvdefine")], [])
        self.assertEqual((hw.value(), hw.record()), (2, (2, "02" * 32)))

    def test_remains_does_not_mistake_a_failing_read_for_a_missing_index(self):
        """What remains of an anchor is a floor for re-anchoring. A read that FAILS must not shrink it."""
        hw = self.defined()
        hw.anchor(3, lambda epoch: "%02x" % epoch * 32)
        self.assertEqual(hw.remains(), (3, [(3, "03" * 32), (2, "02" * 32)]))
        for label, fault in (("the counter", lambda argv: 1 if argv[:2] == ["tpm2_nvread", "0x1500016"] else None),
                             ("the base", lambda argv: 1 if argv[:2] == ["tpm2_nvreadpublic", "0x1500017"] else None),
                             ("a slot", lambda argv: 1 if argv[:2] == ["tpm2_nvread", "0x150001b"] else None),
                             ("a slot's public area", lambda argv: 1 if argv[:2] == ["tpm2_nvreadpublic", "0x150001a"] else None)):
            with self.subTest(label):
                self.fault = fault
                with self.assertRaises(m.Refused) as caught:
                    hw.remains()
                self.assertNotIsInstance(caught.exception, m.Unusable)
        self.fault = lambda argv: None
        self.tpm(["tpm2_nvundefine", "0x1500016", "-C", "o"])                 # the TPM SAYS the counter is gone: that is a remains without it
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        self.assertEqual(hw.remains(), (None, [(3, "03" * 32)]))

    def test_what_is_wrong_with_the_anchor_is_told_apart_from_a_tpm_that_fails(self):
        """Unusable is what re-anchoring repairs; a plain Refused is a TPM or a tool that did not answer."""
        hw = self.defined()
        for label, fault, kind, reason in (
                ("the TPM answers nothing", lambda argv: 1, m.Refused, "the TPM does not answer"),
                ("the counter does not read though the TPM lists it", lambda argv: 1 if argv[:2] == ["tpm2_nvreadpublic", "0x1500016"] else None,
                 m.Refused, "the TPM lists it and did not give it"),
                ("a read of the counter fails", lambda argv: 1 if argv[:2] == ["tpm2_nvread", "0x1500016"] else None, m.Refused, "cannot read 8 bytes"),
                ("a read of a slot fails", lambda argv: 1 if argv[:2] == ["tpm2_nvread", "0x150001b"] else None, m.Refused, "cannot read 48 bytes")):
            with self.subTest(label):
                self.fault = fault
                with self.assertRaises(m.Refused) as caught:
                    hw.unusable()
                self.assertIn(reason, str(caught.exception))
                self.assertIs(type(caught.exception), kind)
        self.fault = lambda argv: None
        self.tpm(["tpm2_nvundefine", "0x1500017", "-C", "o"])
        self.assertEqual(hw.unusable(), "cannot read NV index 0x1500017: the high-water anchor is unavailable (fail closed): the index is not defined")
        with self.assertRaises(m.Unusable):
            hw.value()
        self.assertEqual(hw.remains(), (None, [(0, "00" * 32), (0, "00" * 32)]))

    def test_a_record_read_that_fails_is_refused_whatever_it_printed(self):
        hw = self.defined()
        whole = m.HighWater.slot_bytes(0, "00" * 32)
        self.fault = lambda argv: (1, whole) if argv[:2] == ["tpm2_nvread", "0x150001a"] else None
        with self.assertRaisesRegex(m.Refused, "cannot read 48 bytes from the record index 0x150001a"):
            hw.record()

    def defined(self):
        hw = self.anchor()
        hw.define()
        del self.calls[:]
        return hw

    def test_a_record_index_that_cannot_be_defined(self):
        for index in ("0x150001a", "0x150001b"):
            with self.subTest(index=index):
                self.tpm = FakeTpm()
                self.fault = lambda argv: 1 if argv[:2] == ["tpm2_nvdefine", index] else None
                with self.assertRaisesRegex(m.Refused, "cannot define the record index %s" % index):
                    self.anchor().define()

    def test_a_record_write_the_tpm_refuses(self):
        hw = self.defined()
        self.fault = lambda argv: 1 if argv[:2] == ["tpm2_nvwrite", "0x150001a"] else None
        with self.assertRaisesRegex(m.Refused, "cannot write the record index 0x150001a"):
            hw.anchor(1, lambda epoch: "ab" * 32 if epoch else "00" * 32)
        self.assertEqual((hw.value(), hw.record(), hw.pinned()), (1, (0, "00" * 32), False))     # the crash window, as left

    def test_a_record_write_that_does_not_take(self):
        hw = self.defined()
        self.fault = lambda argv: 0 if argv[:2] == ["tpm2_nvwrite", "0x150001a"] else None      # says yes, stores nothing
        with self.assertRaisesRegex(m.Refused, "the record index 0x150001a did not take the write"):
            hw.anchor(1, lambda epoch: "ab" * 32 if epoch else "00" * 32)

    def test_a_record_read_of_another_length_is_refused(self):
        # tpm2_nvread -s 48 gives 48 bytes or fails; a tool that gave fewer or more must not be parsed as a record
        hw = self.defined()
        for index in hw.record_indices:
            for out in (b"", b"\0" * 47, b"\0" * 49):
                self.fault = lambda argv: out if argv[:2] == ["tpm2_nvread", index] else None
                for call in (hw.record, hw.pinned, lambda: hw.verify(lambda epoch: "00" * 32), lambda: hw.anchor(1, lambda epoch: "00" * 32)):
                    with self.subTest(index=index, length=len(out)), self.assertRaisesRegex(m.Refused, "cannot read 48 bytes from the record index %s" % index):
                        call()
        self.fault = lambda argv: None
        self.assertEqual((hw.value(), hw.record()), (0, (0, "00" * 32)))

    def test_a_slot_is_a_record_only_if_its_tag_matches(self):
        hw = self.defined()
        good = m.HighWater.slot_bytes(7, "ab" * 32)
        self.assertEqual((len(good), good[:8], good[8:40]), (48, (7).to_bytes(8, "big"), b"\xab" * 32))
        for label, data in (("another epoch under the same tag", (8).to_bytes(8, "big") + good[8:]),
                            ("another digest under the same tag", good[:8] + b"\xac" + good[9:]),
                            ("a tag off by one bit", good[:47] + bytes([good[47] ^ 1])),
                            ("a tag made without the domain prefix", good[:40] + __import__("hashlib").sha256(good[:40]).digest()[:8]),
                            ("all zero", b"\0" * 48), ("all ones", b"\xff" * 48)):
            with self.subTest(label):
                self.fault = lambda argv: data if argv[:2] == ["tpm2_nvread", "0x150001b"] else None
                self.assertEqual(hw.slots(), [(0, "00" * 32), None])
        self.fault = lambda argv: good if argv[:2] == ["tpm2_nvread", "0x150001b"] else None
        self.assertEqual(hw.slots(), [(0, "00" * 32), (7, "ab" * 32)])

    def test_an_index_that_is_not_a_written_ordinary_one(self):
        # the same on swtpm in HighWaterOnSwtpm; here so that it runs where no TPM tools are installed
        hw = self.defined()
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        self.tpm(["tpm2_nvdefine", "0x150001b", "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread"])
        self.assertEqual((hw.slots(), hw.record()), ([(0, "00" * 32), None], (0, "00" * 32)))        # never written: passed over
        self.assertEqual(hw.anchor(1, lambda epoch: "01" * 32 if epoch else "00" * 32), 1)
        self.assertEqual(hw.slots(), [(0, "00" * 32), (1, "01" * 32)])                               # and it took the write
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        self.tpm(["tpm2_nvdefine", "0x150001b", "-C", "o", "-s", "8", "-a", "nt=counter|ownerread|ownerwrite|authread|authwrite"])
        self.tpm(["tpm2_nvincrement", "0x150001b", "-C", "o"])
        for call in (hw.record, hw.slots, hw.pinned):
            with self.assertRaisesRegex(m.Refused, "record index 0x150001b is not an ordinary index"):
                call()
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        with self.assertRaisesRegex(m.Refused, "cannot read NV index 0x150001b: the high-water anchor is unavailable"):
            hw.record()
        with self.assertRaisesRegex(m.Refused, "this counter keeps no record"):
            type("Plain", (m.HighWater,), {"RECORD": False})("0x1500030", lock_path=self.d + "/p.lock", run=self.run_tpm).slots()

    def test_an_index_anyone_could_write_is_not_this_anchors(self):
        """51's third read: the indices were defined authwrite with an empty index authorization, so anyone who
        could open the TPM wrote a record (and incremented the counter) with no owner authorization at all."""
        hw = self.defined()
        for index, attributes in (("0x1500016", "nt=counter|ownerread|ownerwrite|authread|authwrite"),
                                  ("0x1500016", "nt=counter|ownerread|authread|authwrite"),
                                  ("0x1500016", "nt=counter|ownerread|authread"),             # neither write bit (51: a surviving mutant)
                                  ("0x150001a", "ownerread|ownerwrite|authread|authwrite"),
                                  ("0x150001a", "ownerread|ownerwrite|authread|policywrite"),
                                  ("0x150001a", "ownerread|ownerwrite|authread|ppwrite"),
                                  ("0x150001a", "ownerwrite|authread"),                       # no ownerread: the owner could not read it
                                  ("0x150001b", "ownerread|authread|authwrite"),
                                  ("0x150001b", "ownerread|authread"),
                                  ("0x150001a", "ownerread|ownerwrite|authread|no_da"),       # bits outside the mask (51: untested)
                                  ("0x150001b", "ownerread|ownerwrite|authread|orderly"),
                                  ("0x150001b", "ownerread|ownerwrite|authread|clear_stclear"),
                                  ("0x1500017", "ownerread|ownerwrite|authread|authwrite|writedefine")):   # the base too
            with self.subTest(index=index, attributes=attributes):
                self.tpm = FakeTpm()
                hw = self.defined()
                self.tpm(["tpm2_nvundefine", index, "-C", "o"])
                self.tpm(["tpm2_nvdefine", index, "-C", "o", "-s", "8" if index == "0x1500016" else "48", "-a", attributes])
                if index == "0x1500016":
                    self.tpm(["tpm2_nvincrement", index, "-C", "o"])
                if index == "0x1500017":
                    self.tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=b"\0" * 8)
                    self.tpm(["tpm2_nvwritelock", index, "-C", "o"])
                self.assertRegex(hw.unusable(), "NV index %s does not have this anchor's attributes" % index)
                with self.assertRaisesRegex(m.Unusable, "does not have this anchor's attributes"):
                    hw.record() if index not in ("0x1500016", "0x1500017") else hw.value()
        # what this code defines passes, and the attributes it asks for say so
        self.tpm = FakeTpm()
        hw = self.defined()
        self.assertIsNone(hw.unusable())
        for index in ("0x1500016", "0x1500017", "0x150001a", "0x150001b"):
            attributes = self.tpm.nv[index][0]
            self.assertTrue(attributes & 0x2 and not attributes & (0x4 | 0x8), (index, hex(attributes)))
        # and a slot of the wrong kind is not kept by a re-anchor: it is replaced
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        self.tpm(["tpm2_nvdefine", "0x150001b", "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread|authwrite"])
        hw.redefine(4, "04" * 32)
        self.assertEqual((hw.value(), hw.slots(), hw.unusable()), (4, [(4, "04" * 32)] * 2, None))
        self.tpm(["tpm2_nvwritelock", "0x150001a", "-C", "o"])               # 51's finding 4: a write-locked slot strands every attempt
        self.assertRegex(hw.unusable(), "NV index 0x150001a is write-locked")
        hw.redefine(5, "05" * 32)
        self.assertEqual((hw.value(), hw.slots(), hw.unusable()), (5, [(5, "05" * 32)] * 2, None))

    def test_what_a_wrongly_defined_slot_holds_still_counts_and_is_written_over_only_by_the_newer_record(self):
        """51's fourth read: remains() dropped a slot whose attributes were wrong, and redefine() deleted it, so
        a valid record at the highest epoch was forgotten and a re-anchor could go below it."""
        hw = self.defined()
        hw.anchor(7, lambda epoch: "%02x" % epoch * 32)
        self.assertEqual(hw.slots(), [(7, "07" * 32), (6, "06" * 32)])
        record7 = self.tpm.nv["0x150001a"][1]
        self.tpm(["tpm2_nvundefine", "0x150001a", "-C", "o"])                 # slot a re-defined authwrite, still holding the epoch-7 record
        self.tpm(["tpm2_nvdefine", "0x150001a", "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread|authwrite"])
        self.tpm(["tpm2_nvwrite", "0x150001a", "-C", "o", "-i", "-"], input=record7)
        self.assertRegex(hw.unusable(), "does not have this anchor's attributes")
        self.assertEqual(hw.remains(), (7, [(7, "07" * 32), (6, "06" * 32)]))     # the record still counts
        # a slot the owner cannot read, holding a record: read through its own authorization, and it counts
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        self.tpm(["tpm2_nvdefine", "0x150001b", "-C", "o", "-s", "48", "-a", "ownerwrite|authread"])
        self.tpm(["tpm2_nvwrite", "0x150001b", "-C", "o", "-i", "-"], input=m.HighWater.slot_bytes(8, "08" * 32))
        self.assertEqual(hw.remains()[1], [(7, "07" * 32), (8, "08" * 32)])
        # redefine at 9: no slot this software defined, so each is replaced and written at once; the result is whole
        del self.calls[:]
        hw.redefine(9, "09" * 32)
        order = [(tool, index) for tool, index in self.calls if tool in ("nvundefine", "nvdefine", "nvwrite")]
        self.assertEqual(order[:6], [("nvundefine", "0x150001a"), ("nvdefine", "0x150001a"), ("nvwrite", "0x150001a"),
                                     ("nvundefine", "0x150001b"), ("nvdefine", "0x150001b"), ("nvwrite", "0x150001b")])
        self.assertEqual((hw.value(), hw.slots(), hw.unusable()), (9, [(9, "09" * 32)] * 2, None))
        # with one slot of the right kind, the new record goes into it BEFORE the wrong one is deleted
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])
        self.tpm(["tpm2_nvdefine", "0x150001b", "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread|authwrite"])
        self.tpm(["tpm2_nvwrite", "0x150001b", "-C", "o", "-i", "-"], input=m.HighWater.slot_bytes(9, "09" * 32))
        del self.calls[:]
        hw.redefine(10, "10" * 32)
        order = [(tool, index) for tool, index in self.calls if tool in ("nvundefine", "nvwrite")]
        self.assertEqual(order[:2], [("nvwrite", "0x150001a"), ("nvundefine", "0x150001b")])
        self.assertEqual((hw.value(), hw.slots()), (10, [(10, "10" * 32)] * 2))

    def test_a_missing_slot_is_filled_before_a_wrong_one_holding_a_record_is_deleted(self):
        """51's fifth read: one wrongly attributed slot holding the highest record and the other slot absent (the
        shape of an upgrade, here with a 48-byte tagged record; main's own 40-byte record is not read at all, see
        MEMBERSHIP-RECOVERY.md) deleted the wrong slot first, so a cut there lost the highest record. A missing
        slot is now written first."""
        hw = self.defined()
        hw.anchor(7, lambda epoch: "%02x" % epoch * 32)
        self.tpm(["tpm2_nvundefine", "0x150001a", "-C", "o"])
        self.tpm(["tpm2_nvdefine", "0x150001a", "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread|authwrite"])
        self.tpm(["tpm2_nvwrite", "0x150001a", "-C", "o", "-i", "-"], input=m.HighWater.slot_bytes(8, "08" * 32))
        self.tpm(["tpm2_nvundefine", "0x150001b", "-C", "o"])                # missing
        self.assertEqual(hw.remains(), (7, [(8, "08" * 32)]))
        del self.calls[:]
        self.fault = lambda argv: 1 if argv[:2] == ["tpm2_nvundefine", "0x150001a"] else None    # a cut at the first delete
        with self.assertRaisesRegex(m.Refused, "cannot delete NV index 0x150001a"):
            hw.redefine(9, "09" * 32)
        self.assertEqual([(tool, index) for tool, index in self.calls if tool in ("nvdefine", "nvwrite", "nvundefine")][:3],
                         [("nvdefine", "0x150001b"), ("nvwrite", "0x150001b"), ("nvundefine", "0x150001a")])
        self.assertEqual(sorted(hw.remains()[1]), [(8, "08" * 32), (9, "09" * 32)])     # nothing was lost, and the new record is in
        self.fault = lambda argv: None
        hw.redefine(9, "09" * 32)
        self.assertEqual((hw.value(), hw.slots(), hw.unusable()), (9, [(9, "09" * 32)] * 2, None))
        # both slots wrong: the one holding nothing goes first, then the lower record
        for index, record in (("0x150001a", m.HighWater.slot_bytes(12, "12" * 32)), ("0x150001b", b"\x5a" * 48)):
            self.tpm(["tpm2_nvundefine", index, "-C", "o"])
            self.tpm(["tpm2_nvdefine", index, "-C", "o", "-s", "48", "-a", "ownerread|ownerwrite|authread|authwrite"])
            self.tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=record)
        del self.calls[:]
        hw.redefine(13, "13" * 32)
        self.assertEqual([index for tool, index in self.calls if tool == "nvundefine"][:2], ["0x150001b", "0x150001a"])
        self.assertEqual((hw.value(), hw.slots()), (13, [(13, "13" * 32)] * 2))

    def test_a_counter_or_base_of_another_size_is_an_unusable_anchor_that_re_anchoring_replaces(self):
        """regalia-kms-ed, porting the reader to Go: a base smaller than 8 bytes was a plain Refused ("cannot read
        8 bytes"), which re-anchoring treats as a TPM that failed, so the node had no way back."""
        for index, size in (("0x1500017", 4), ("0x1500017", 16), ("0x1500016", 16)):
            with self.subTest(index=index, size=size):
                self.tpm = FakeTpm()
                hw = self.defined()
                hw.anchor(3, lambda epoch: "%02x" % epoch * 32)
                self.tpm(["tpm2_nvundefine", index, "-C", "o"])
                if index == "0x1500017":
                    self.tpm(["tpm2_nvdefine", index, "-C", "o", "-s", str(size), "-a", "ownerread|ownerwrite|authread|writedefine"])
                    self.tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=b"\0" * size)
                    self.tpm(["tpm2_nvwritelock", index, "-C", "o"])
                else:
                    self.tpm(["tpm2_nvdefine", index, "-C", "o", "-s", str(size), "-a", "nt=counter|ownerread|ownerwrite|authread"])
                    self.tpm(["tpm2_nvincrement", index, "-C", "o"])
                self.assertEqual(hw.unusable(), "NV index %s is %d bytes, not 8" % (index, size))
                with self.assertRaises(m.Unusable):
                    hw.value()
                hw.redefine(3, "03" * 32)                                     # and a re-anchor's TPM half replaces it
                self.assertEqual((hw.value(), hw.unusable()), (3, None))

    def test_two_valid_slots_that_disagree_at_one_epoch_are_refused(self):
        hw = self.defined()
        hw.anchor(1, lambda epoch: "01" * 32 if epoch else "00" * 32)
        other = m.HighWater.slot_bytes(1, "02" * 32)                     # valid, the same epoch, another manifest: no crash leaves this
        self.fault = lambda argv: other if argv[:2] == ["tpm2_nvread", "0x150001b"] else None
        for call in (hw.record, hw.pinned, lambda: hw.verify(lambda epoch: "01" * 32)):
            with self.assertRaisesRegex(m.Refused, "the two record slots name different manifests at epoch 1"):
                call()
        self.assertRegex(hw.unusable(), "name different manifests")
        older = m.HighWater.slot_bytes(0, "02" * 32)                     # disagreement BELOW the newest epoch does not matter: that slot is history
        self.fault = lambda argv: older if argv[:2] == ["tpm2_nvread", "0x150001b"] else None
        self.assertEqual(hw.record(), (1, "01" * 32))

    def test_a_digest_that_is_not_one_is_never_written(self):
        hw = self.defined()
        for bad in ("AB" * 32, "ab" * 31, None, b"\0" * 32):
            with self.subTest(bad=bad), self.assertRaisesRegex(m.Refused, "a manifest digest must be 64 lowercase hex"):
                hw._write_record(1, bad)
        self.assertNotIn("nvwrite", [tool for tool, _ in self.calls])

    def test_the_order_is_counter_then_record_for_every_epoch_and_the_slots_alternate(self):
        hw = self.defined()
        self.assertEqual(hw.anchor(5, lambda epoch: "%02x" % epoch * 32), 5)
        self.assertEqual([call for call in self.calls if call[0] in ("nvincrement", "nvwrite")],
                         [("nvincrement", "0x1500016"), ("nvwrite", "0x150001a"), ("nvincrement", "0x1500016"), ("nvwrite", "0x150001b"),
                          ("nvincrement", "0x1500016"), ("nvwrite", "0x150001a"), ("nvincrement", "0x1500016"), ("nvwrite", "0x150001b"),
                          ("nvincrement", "0x1500016"), ("nvwrite", "0x150001a")])
        self.assertEqual((hw.record(), hw.slots(), hw.pinned()), ((5, "05" * 32), [(5, "05" * 32), (4, "04" * 32)], True))


class TornWrites(unittest.TestCase):
    """A power cut during the record's NV write. The slot being written is left with part of the new record
    over the old one; the command fails, and the process is gone. Whatever the cut, the node comes back: the
    other slot still holds the record for the epoch before, which load() repairs as the crash window."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.tpm = FakeTpm()
        self.cut_after = None                                # bytes of the record write to cut that reach the TPM; None: no cut
        self.cut_skip = 0                                    # record writes let through whole before that one
        self.writes = []
        self.hw = m.HighWater("0x1500016", lock_path=self.d + "/hw.lock", run=self.run_tpm)
        self.hw.define()
        self.path = self.d + "/membership.json"
        self.envs, cur = [], None
        for e in range(1, 8):
            env = sign(manifest(e, m.digest(cur) if cur else "", three(a="DRAINING" if e % 2 else "ACTIVE")), ROOT)
            cur = m.accept(cur, env, ROOT_PUB)
            self.envs.append(env)
        del self.writes[:]

    def run_tpm(self, argv, input=None, **kw):
        if argv[0] == "tpm2_nvwrite" and argv[1] in ("0x150001a", "0x150001b"):
            before = self.hw._slots() if hasattr(self, "hw") else [None, None]
            self.writes.append((argv[1], before))
            if self.cut_after is not None and self.cut_skip:
                self.cut_skip -= 1
            elif self.cut_after is not None:
                kept, self.cut_after = self.cut_after, None
                if kept:
                    self.tpm(argv, input=input[:kept], **kw)     # FakeTpm keeps the old bytes after a short write
                return subprocess.CompletedProcess(argv, 1, b"", b"power lost")
        return self.tpm(argv, input=input, **kw)

    def store(self):
        return m.Store(self.path, ROOT_PUB, self.hw)

    def digest(self, epoch):
        return m.digest(self.envs[epoch - 1]["manifest"])

    def test_a_write_cut_at_any_byte_is_repaired_by_the_next_load(self):
        store = self.store()
        store.commit(self.envs[0])
        store.commit(self.envs[1])
        epoch = 2
        for kept in range(0, 49):
            with self.subTest(bytes_written=kept):
                epoch += 1
                if epoch > len(self.envs):                   # start again on a fresh anchor: the chain is only seven long
                    self.tpm.nv.clear()
                    self.hw.define()
                    os.unlink(self.path)
                    store = self.store()
                    store.commit(self.envs[0])
                    store.commit(self.envs[1])
                    epoch = 3
                self.cut_after = kept
                try:
                    self.store().commit(self.envs[epoch - 1])
                    cut = False                              # all 48 bytes arrived before the cut: the write is whole
                except m.Refused as refusal:
                    cut = True
                    self.assertRegex(str(refusal), "cannot write the record index")
                self.assertEqual(self.hw.value(), epoch)     # the counter had moved, and the disk before it
                self.assertIsNone(self.hw.unusable())
                self.assertIn(self.hw.record(), ((epoch - 1, self.digest(epoch - 1)), (epoch, self.digest(epoch))))
                self.assertEqual(self.store().load()["epoch"], epoch)
                self.assertEqual((self.hw.record(), self.hw.pinned(), sorted(self.hw.slots())),
                                 ((epoch, self.digest(epoch)), True, [(epoch - 1, self.digest(epoch - 1)), (epoch, self.digest(epoch))]))
                self.assertTrue(cut or kept == 48)

    def test_the_newest_valid_slot_is_never_the_one_written(self):
        store = self.store()
        for env in self.envs:
            store.commit(env)
        self.assertEqual(len(self.writes), 7)
        for index, before in self.writes:
            valid = [slot for slot in before if slot is not None]
            written = before[self.hw.record_indices.index(index)]
            with self.subTest(index=index, before=before):
                self.assertTrue(written is None or written == min(valid), "the write went to the newest valid record")

    def test_a_cut_during_the_repair_is_repaired_too(self):
        store = self.store()
        store.commit(self.envs[0])
        self.cut_after = 13
        with self.assertRaises(m.Refused):
            self.store().commit(self.envs[1])                # cut: the record stays at epoch 1, the counter is at 2
        self.cut_after = 31
        with self.assertRaisesRegex(m.Refused, "cannot write the record index"):
            self.store().load()                              # the repair is cut as well
        self.assertEqual((self.hw.value(), self.hw.record(), self.hw.unusable()), (2, (1, self.digest(1)), None))
        self.assertEqual(self.store().load()["epoch"], 2)
        self.assertEqual(self.hw.record(), (2, self.digest(2)))

    def test_cuts_all_the_way_through_a_restore_never_strand_the_node(self):
        self.store().commit(self.envs[0])
        os.unlink(self.path)
        attempts, done = 0, None
        while done is None:
            attempts += 1
            self.assertLess(attempts, 30)
            # each attempt gets one record write through whole (the repair of the last cut), and the next is cut
            self.cut_after, self.cut_skip = (attempts * 7) % 48, 0 if attempts == 1 else 1
            try:
                done = self.store().restore(self.envs) if not os.path.exists(self.path) else self.store().load()
            except m.Refused as refusal:
                self.assertRegex(str(refusal), "cannot write the record index")
                self.assertIsNone(self.hw.unusable())
            self.cut_after = None
        self.assertEqual((done["epoch"], self.hw.value(), self.hw.record()), (7, 7, (7, self.digest(7))))
        self.assertEqual(attempts, 7)                        # the restore, cut at epoch 2; then one epoch gained per load, each cut again

    def test_both_slots_lost_is_the_only_way_to_strand_and_it_says_what_to_do(self):
        store = self.store()
        store.commit(self.envs[0])
        store.commit(self.envs[1])
        for index in self.hw.record_indices:
            self.tpm(["tpm2_nvwrite", index, "-C", "o", "-i", "-"], input=b"\x5a" * 48)
        for call in (self.store().load, self.store().envelopes, lambda: self.store().restore(self.envs[:2]), lambda: self.store().commit(self.envs[2])):
            with self.assertRaisesRegex(m.Refused, "NO RECORD: neither record slot .* re-anchor it"):
                call()
        self.assertEqual(self.hw.value(), 2)


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
        ahead = m.HighWater.slot_bytes(9, self.digest(3))
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
