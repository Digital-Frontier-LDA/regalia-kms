"""Rolling a new boot image through three nodes (#75, Phase 15): deploy/baremetal/measurements.py (the
document the membership manifest commits to, CURRENT and NEXT) and deploy/baremetal/rollout.py (may this
node reboot now; may CURRENT be retired).

The TPM identities and the lease signatures are the OpenSSL fixtures of tests/test_baremetal_lease.py.
The same sequence on three software TPMs, with real quotes, is e2e/rolling-policy-swtpm.sh."""
import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from deploy.baremetal import attest, lease, measurements, replacement, rollout
from deploy.baremetal import heartbeat as hb
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt

FW = "0" * 16
IMAGE1, IMAGE2, IMAGE3 = ({"7": "00" * 32, "11": c * 32} for c in ("a1", "b2", "c3"))


def one(label, pcrs, fw=FW):
    return {"label": label, "tpm_firmware_version": fw, "pcrs": dict(pcrs)}


def document(name, **nodes):
    """document("v2", a=[one(...), one(...)], ...)"""
    return {"schema": measurements.SCHEMA, "name": name, "nodes": {n: {"accepted": sets} for n, sets in nodes.items()}}


def uki(label, initrd, system, fw=FW):
    """A set of a host that boots a UKI: PCR 7 once, PCR 11 in the initrd and once booted (#57, #156)."""
    return {"label": label, "tpm_firmware_version": fw, "pcrs": {"7": "00" * 32},
            "phases": {"initrd": {"11": initrd * 32}, "system": {"11": system * 32}}}


CURRENT = document("v1", **{n: [one("image-1", IMAGE1)] for n in "abc"})
BOTH = document("v2", **{n: [one("image-1", IMAGE1), one("image-2", IMAGE2)] for n in "abc"})
NEXT = document("v3", **{n: [one("image-2", IMAGE2)] for n in "abc"})


class Case(lt.Case):
    def under(self, doc, epoch=1, prev="", **states):
        """A manifest that commits to `doc`."""
        return dict(self.manifest(epoch, prev, **states), policy_version=measurements.version(doc))

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))
        return str(caught.exception)


class Document(Case):
    def test_the_version_is_a_digest_of_the_whole_document_and_fits_the_manifest_field(self):
        v = measurements.version(BOTH)
        self.assertRegex(v, r"^m1-[A-Za-z0-9_-]{29}$")                 # base64url: 174 bits of the SHA-256
        self.assertEqual(len(v), 32)
        full = base64.urlsafe_b64encode(hashlib.sha256(m.canonical(BOTH)).digest()).decode()
        self.assertEqual(v, "m1-" + full[:29])
        m.validate(self.under(BOTH))                                   # 32 characters: a valid policy_version
        self.assertEqual(v, measurements.version(copy.deepcopy(BOTH)))
        changed = copy.deepcopy(BOTH)
        changed["nodes"]["c"]["accepted"][1]["pcrs"]["11"] = "b3" * 32   # one hex digit of one PCR of one node
        self.assertNotEqual(measurements.version(changed), v)
        renamed = dict(copy.deepcopy(BOTH), name="v2b")
        self.assertNotEqual(measurements.version(renamed), v)
        # key order is not content, and neither is how the file was written out
        reordered = {"nodes": dict(reversed(list(BOTH["nodes"].items()))), "name": "v2", "schema": measurements.SCHEMA}
        self.assertEqual(measurements.version(reordered), v)
        for text in (json.dumps(BOTH, indent=4), json.dumps(BOTH, separators=(",", ":")), "\n\n  " + json.dumps(reordered, indent="\t") + "\n"):
            self.assertEqual(measurements.version(measurements.load(text)), v)
        # every part of the content is: each field of each set of each node
        for change in (lambda d: d["nodes"]["a"]["accepted"][0].update(label="image-1b"),
                       lambda d: d["nodes"]["b"]["accepted"][0].update(tpm_firmware_version="1" * 16),
                       lambda d: d["nodes"]["a"]["accepted"][0]["pcrs"].update({"7": "01" * 32}) or d["nodes"]["a"]["accepted"][1]["pcrs"].update({"7": "01" * 32}),
                       lambda d: d["nodes"]["c"]["accepted"].reverse(),
                       lambda d: d["nodes"]["c"]["accepted"].pop(),
                       lambda d: d["nodes"].pop("c")):
            other = copy.deepcopy(BOTH)
            change(other)
            self.assertNotEqual(measurements.version(other), v)

    def test_only_the_root_approves_or_retires_an_image(self):
        """A revocation key signs restrictive changes only, and a manifest that names another document is
        not one: it cannot approve NEXT, and it cannot retire CURRENT either."""
        root = hbt.pub(hbt.ROOT)
        m1 = self.under(CURRENT)

        def signed(manifest, key, signer):
            return {"manifest": manifest, "signature": {"signer": signer, "key": hbt.pub(key),
                                                        "sig": key.sign(m.DOMAIN + m.canonical(manifest)).hex()}}
        approve = self.under(BOTH, epoch=2, prev=m.digest(m1))
        self.refused("a revocation key cannot change the policy version", m.accept, m1, signed(approve, hbt.REVOKE, "revocation"), root)
        m2 = m.accept(m1, signed(approve, hbt.ROOT, "root"), root)
        measurements.bind(m2, BOTH)
        retire = self.under(NEXT, epoch=3, prev=m.digest(m2))
        self.refused("a revocation key cannot change the policy version", m.accept, m2, signed(retire, hbt.REVOKE, "revocation"), root)
        # what a revocation key CAN sign leaves the document in force, for the nodes that remain
        quarantine = self.under(BOTH, epoch=3, prev=m.digest(m2), c="QUARANTINED")
        m3 = m.accept(m2, signed(quarantine, hbt.REVOKE, "revocation"), root)
        self.assertEqual(sorted(measurements.bind(m3, BOTH)), ["a", "b", "c"])
        self.assertEqual(rollout.attesting(m3), ["a", "b"])
        m4 = m.accept(m3, signed(self.under(NEXT, epoch=4, prev=m.digest(m3), c="QUARANTINED"), hbt.ROOT, "root"), root)
        measurements.bind(m4, NEXT)

    def test_a_document_is_accepted_only_under_the_manifest_that_commits_to_it(self):
        bound = measurements.bind(self.under(BOTH), BOTH)
        self.assertEqual(sorted(bound), ["a", "b", "c"])
        self.assertEqual([s["label"] for s in bound["a"]["accepted"]], ["image-1", "image-2"])
        # the older document under the newer manifest: the rollback a restored policy file would be
        self.refused("it is not the one the root approved, or it is an older or newer one", measurements.bind, self.under(NEXT), BOTH)
        self.refused("is not the one the root approved", measurements.bind, self.under(BOTH), NEXT)
        # a manifest that names no document at all (the pre-#75 free text)
        self.refused("commits to measurements p1", measurements.bind, self.manifest(), CURRENT)
        # one changed value is another document
        changed = copy.deepcopy(BOTH)
        changed["nodes"]["a"]["accepted"][1]["pcrs"]["11"] = "ff" * 32
        self.refused("is not the one the root approved", measurements.bind, self.under(BOTH), changed)

    def test_every_node_that_may_attest_needs_an_entry_and_no_stranger_gets_one(self):
        two = document("two", a=[one("image-1", IMAGE1)], b=[one("image-1", IMAGE1)])
        self.refused("no entry for c, which the manifest lets attest", measurements.bind, self.under(two), two)
        measurements.bind(self.under(two, c="QUARANTINED"), two)      # a node that may do nothing needs none
        measurements.bind(self.under(two, c="RETIRED"), two)
        extra = document("extra", **{n: [one("image-1", IMAGE1)] for n in ("a", "b", "c", "z")})
        self.refused("nodes the manifest does not list: z", measurements.bind, self.under(extra), extra)

    def test_the_bound_document_is_what_the_attestation_policy_is_built_from(self):
        manifest = self.under(BOTH)
        policy = measurements.attest_policy(manifest, BOTH, peer_id="b")
        self.assertEqual(policy, replacement.attest_policy(manifest, measurements.bind(manifest, BOTH), peer_id="b"))
        self.refused("is not the one the root approved", measurements.attest_policy, manifest, NEXT, "b")
        for stranger in ("zz", 7, None, ["b"]):
            with self.subTest(peer=repr(stranger)):
                self.refused("is not a node of the manifest", measurements.attest_policy, manifest, BOTH, stranger)
        self.assertEqual(sorted(policy["nodes"]), ["a", "c"])
        self.assertEqual(policy["nodes"]["a"], {"ek_name": self.keys["a"].ek_name, "accepted": BOTH["nodes"]["a"]["accepted"]})
        nodes = attest.validate_policy(policy)
        self.assertEqual([s["label"] for s in nodes["c"]["accepted"]], ["image-1", "image-2"])

    def test_a_node_replacement_carries_the_document_with_it(self):
        """#76 replaces a by a new node in one manifest. Under bound measurements the new node needs an
        entry, so the document and policy_version change in that manifest, and nothing else may."""
        keys = dict(self.keys, d=lt.Key(self.keydir, "d", 9))
        m1 = self.under(CURRENT)

        def entry(node_id, i, state="ACTIVE"):
            return {"node_id": node_id, "state": state, "ek_name": keys[node_id].ek_name, "ak_name": keys[node_id].ak_name,
                    "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": ("%02x" % (0xa0 + i)) * 32, "hsm_serials": ["DENK04041%02d" % i]}

        def replaced(doc):
            return dict(m1, epoch=2, prev_digest=m.digest(m1), policy_version=measurements.version(doc),
                        nodes=[entry("a", 0, "RETIRED"), entry("b", 1), entry("c", 2), entry("d", 3)])
        with_d = document("v1d", **dict({n: [one("image-1", IMAGE1)] for n in "bc"}, d=[one("image-1", IMAGE1)]))
        keep_a = document("v1d", **{n: [one("image-1", IMAGE1)] for n in "abcd"})
        for doc in (with_d, keep_a):
            m2 = replaced(doc)
            measurements.check_replacement(m1, m2, CURRENT, doc, "a", "d")
            self.assertEqual(sorted(measurements.attest_policy(m2, doc, "b")["nodes"]), ["c", "d"])
        m2 = replaced(with_d)
        # the old rule still holds where it is asked without documents: policy_version must not change
        self.refused("a replacement does not change policy_version", replacement.check_replacement, m1, m2, "a", "d")
        # and with them, nothing else rides along
        sneaks = dict({n: [one("image-1", IMAGE1)] for n in "bd"}, c=[one("image-1", IMAGE1), one("image-2", IMAGE2)])
        self.refused("a replacement does not change the measurements of c", measurements.check_replacement, m1,
                     replaced(document("s", **sneaks)), CURRENT, document("s", **sneaks), "a", "d")
        no_d = document("v1x", **{n: [one("image-1", IMAGE1)] for n in "bc"})
        self.refused("no entry for d, which the manifest lets attest", measurements.check_replacement, m1, replaced(no_d), CURRENT, no_d, "a", "d")
        self.refused("is not the one the root approved", measurements.check_replacement, m1, m2, CURRENT, keep_a, "a", "d")
        # the new node gets the sets the others already have, by name: no approval rides in with it
        for sets in ([one("image-1", IMAGE1), one("image-2", IMAGE2)], [one("image-9", IMAGE3)], [one("zzz", IMAGE1)]):
            with self.subTest(labels=[e["label"] for e in sets]):
                doc = document("v1n", **dict({n: [one("image-1", IMAGE1)] for n in "bc"}, d=sets))
                self.refused("a replacement gives the new node the sets a node that attests already has (['image-1'])",
                             measurements.check_replacement, m1, replaced(doc), CURRENT, doc, "a", "d")
        # ... and in the same form. Where the others hold the image per boot phase, a new node that gives it one value
        # per PCR would be judged the same in both phases: its booted system could ask for a disk key.
        phased = document("p1", **{n: [uki("image-1", "a1", "a2")] for n in "abc"})
        p1 = self.under(phased)
        for label, sets, reason in (
                ("per phase like the others", [dict(uki("image-1", "a1", "a2"), pcrs={"7": "dd" * 32})], None),
                ("the label, with one value per PCR", [one("image-1", {"7": "dd" * 32, "11": "d2" * 32})],
                 "d is enrolled with the sets ['image-1']; a replacement gives the new node the sets a node that attests already has (['image-1 (per phase)'])")):
            with self.subTest(label):
                doc = document("p1d", **dict({n: [uki("image-1", "a1", "a2")] for n in "bc"}, d=sets))
                candidate = dict(p1, epoch=2, prev_digest=m.digest(p1), policy_version=measurements.version(doc),
                                 nodes=[entry("a", 0, "RETIRED"), entry("b", 1), entry("c", 2), entry("d", 3)])
                if reason:
                    self.refused(reason, measurements.check_replacement, p1, candidate, phased, doc, "a", "d")
                else:
                    measurements.check_replacement(p1, candidate, phased, doc, "a", "d")
        own_hardware = document("v1h", **dict({n: [one("image-1", IMAGE1)] for n in "bc"}, d=[one("image-1", {"7": "dd" * 32, "11": "a1" * 32})]))
        measurements.check_replacement(m1, replaced(own_hardware), CURRENT, own_hardware, "a", "d")   # its own PCR values are fine
        # ... and "a node that attests" is not a quarantined one with a stale list: its retired image-0 must
        # not come back for the new node (bind() lets a node with nothing to do keep any entry)
        zero = {"7": "00" * 32, "11": "a0" * 32}
        stale = document("stale", a=[one("image-1", IMAGE1)], b=[one("image-1", IMAGE1)], c=[one("image-0", zero), one("image-1", IMAGE1)])
        m1q = dict(self.under(stale), nodes=[dict(n, state="QUARANTINED") if n["node_id"] == "c" else n for n in self.under(stale)["nodes"]])
        revived = document("revived", b=[one("image-1", IMAGE1)], c=[one("image-0", zero), one("image-1", IMAGE1)],
                           d=[one("image-0", IMAGE3), one("image-1", IMAGE1)])
        m2q = dict(m1q, epoch=2, prev_digest=m.digest(m1q), policy_version=measurements.version(revived),
                   nodes=[entry("a", 0, "RETIRED"), entry("b", 1), dict(entry("c", 2), state="QUARANTINED"), entry("d", 3)])
        self.refused("d is enrolled with the sets ['image-0', 'image-1']; a replacement gives the new node the sets a node that attests "
                     "already has (['image-1'])", measurements.check_replacement, m1q, m2q, stale, revived, "a", "d")
        # the switch that lets policy_version change is not on the public function
        self.assertNotIn("measurements_change", replacement.check_replacement.__code__.co_varnames)
        self.assertNotIn("policy_version_may_change", replacement.check_replacement.__code__.co_varnames[:replacement.check_replacement.__code__.co_argcount])
        for ids in ((["a"], "d"), ("a", {"d": 1}), (("a", "x"), "d")):
            with self.subTest(ids=repr(ids)):
                self.refused("node IDs are text", measurements.check_replacement, m1, m2, CURRENT, with_d, *ids)
        self.refused("is not the one the root approved", measurements.check_replacement, m1, m2, BOTH, with_d, "a", "d")

    def test_schema_refusals(self):
        ok = lambda: copy.deepcopy(BOTH)   # noqa: E731
        cases = (
            ("another schema", "schema must be", lambda d: d.update(schema="regalia.measurements/v0")),
            ("an unknown field", "fields mismatch", lambda d: d.update(note="x")),
            ("no name", "fields mismatch", lambda d: d.pop("name")),
            ("a name with a space", "short plain name", lambda d: d.update(name="v 2")),
            ("no nodes", "at least one node", lambda d: d.update(nodes={})),
            ("a node ID in capitals", "is not a node ID", lambda d: d["nodes"].update(A=d["nodes"]["a"])),
            ("three sets", "one or two measurement sets", lambda d: d["nodes"]["a"]["accepted"].append(one("image-3", IMAGE3))),
            ("no set", "one or two measurement sets", lambda d: d["nodes"]["a"].update(accepted=[])),
            ("a set twice", "share the label", lambda d: d["nodes"]["a"]["accepted"].__setitem__(1, one("image-1", IMAGE2))),
            ("an entry with extra fields", "fields mismatch", lambda d: d["nodes"]["a"].update(ek_name="x")),
        )
        for label, reason, change in cases:
            with self.subTest(label):
                doc = ok()
                change(doc)
                self.refused(reason, measurements.validate, doc)
                self.refused(reason, measurements.version, doc)
        self.refused("floats are not allowed", measurements.load, b'{"schema": 1.5}')
        self.refused("nested too deeply", measurements.load, "[" * 100000)
        # a PCR index is ASCII digits: "1" + ARABIC-INDIC DIGIT ONE reads as 11 to int(), beside a real "11"
        twice = copy.deepcopy(CURRENT)
        twice["nodes"]["a"]["accepted"][0]["pcrs"]["1\u0661"] = "00" * 32
        self.refused("is not a PCR 0-23", measurements.validate, twice)
        self.refused("duplicate field", measurements.load, b'{"schema": "a", "schema": "b"}')
        self.assertEqual(measurements.load(m.canonical(BOTH)), BOTH)

    def test_the_target_is_the_last_set(self):
        self.assertEqual(measurements.target(CURRENT, "a")["label"], "image-1")
        self.assertEqual(measurements.target(BOTH, "a")["label"], "image-2")
        self.refused("no entry for z", measurements.target, BOTH, "z")


class Transition(Case):
    def test_a_rollout_is_approve_then_retire(self):
        self.assertEqual(measurements.transition(CURRENT, BOTH), "approve")
        self.assertEqual(measurements.transition(BOTH, NEXT), "retire")
        self.assertEqual(measurements.transition(BOTH, dict(copy.deepcopy(BOTH), name="again")), "unchanged")

    def test_the_same_image_under_other_signing_keys_is_another_set(self):
        """#267: a set names the keys its image is signed with. The same PCRs re-signed with another initrd key (it is
        not measured) are never "unchanged": refused under its old label, and under a new one."""
        signed = lambda label, initrd: dict(uki(label, "a1", "a2"), signing={"initrd": initrd * 32, "system": "5b" * 32,   # noqa: E731
                                                                              "secure_boot_cert": "5c" * 32})
        before = document("v1", **{n: [signed("image-1", "1a")] for n in "abc"})
        self.assertEqual(measurements.transition(before, dict(copy.deepcopy(before), name="again")), "unchanged")
        # under its old label: a changed image, refused even in an emergency
        same_label = document("v2", **{n: [signed("image-1", "1b")] for n in "abc"})
        self.refused("has other measurements than before; a changed image gets a new label", measurements.transition, before, same_label,
                     emergency=True)
        # under a new label: it cannot sit beside the old set (the same measurements), and an emergency that drops the old
        # one still accepts its measurements; so a key rotation comes with a rebuilt image (a new PCR 11), never a re-sign
        relabelled = document("v2", **{n: [signed("image-1-resigned", "1b")] for n in "abc"})
        self.refused("would still accept the same measurements under another label", measurements.transition, before, relabelled,
                     emergency=True)
        self.refused("", measurements.transition, before, relabelled)

    def test_giving_next_up_is_not_called_a_retirement(self):
        """Both leave one set per node. Signing the wrong half after retire_ready passed would lock out
        every node, so the two have different names."""
        self.assertEqual(measurements.transition(BOTH, CURRENT), "abandon")
        mixed = document("mixed", a=[one("image-2", IMAGE2)], b=[one("image-1", IMAGE1)], c=[one("image-2", IMAGE2)])
        why = self.refused("one document does two things", measurements.transition, BOTH, mixed)
        self.assertIn("abandon on b", why)
        self.assertIn("retire on a, c", why)

    def test_dropping_current_with_no_overlap_is_refused_unless_it_is_an_emergency(self):
        why = self.refused("would be locked out", measurements.transition, CURRENT, NEXT)
        self.assertIn("a: image-1 is dropped in the same step that adds image-2", why)
        self.assertEqual(measurements.transition(CURRENT, NEXT, emergency=True), "replace-without-overlap")

    def test_an_emergency_still_checks_every_node(self):
        """The first replaced node must not end the examination of the others."""
        relabel_b = document("e", a=[one("image-2", IMAGE2)], b=[one("image-1", IMAGE3)], c=[one("image-1", IMAGE1)])
        self.refused("b: the set 'image-1' has other measurements than before", measurements.transition, CURRENT, relabel_b, emergency=True)
        and_approve = document("e", a=[one("image-2", IMAGE2)], b=[one("image-1", IMAGE1), one("image-2", IMAGE2)], c=[one("image-1", IMAGE1)])
        self.refused("an emergency replacement (a) must not also approve (b)", measurements.transition, CURRENT, and_approve, emergency=True)
        # a replaced node ends on the replacing image alone: nothing kept beside it, no second new set
        for label, sets in (("the target moved past a set it had", [one("image-2", IMAGE2), one("image-3", IMAGE3)]),
                            ("the new set listed first", [one("image-3", IMAGE3), one("image-2", IMAGE2)])):
            with self.subTest(label):
                self.refused("an emergency replacement leaves the node on the replacing image alone", measurements.transition,
                             BOTH, document("e", **{n: sets for n in "abc"}), emergency=True)
        four = {"7": "00" * 32, "11": "d4" * 32}
        two_new = document("e", **{n: [one("image-3", IMAGE3), one("image-4", four)] for n in "abc"})
        self.refused("leaves the node on the replacing image alone, not on image-3, image-4", measurements.transition, CURRENT, two_new, emergency=True)
        # and every replaced node goes to the SAME image
        split = document("e", a=[one("image-3", IMAGE3)], b=[one("image-4", four)], c=[one("image-3", IMAGE3)])
        self.refused("puts every replaced node on ONE image, not on image-3, image-4", measurements.transition, CURRENT, split, emergency=True)
        # dropping both sets of a node for the one replacing image is still one emergency
        self.assertEqual(measurements.transition(BOTH, document("e", **{n: [one("image-3", IMAGE3)] for n in "abc"}), emergency=True),
                         "replace-without-overlap")

        swapped_c = document("e", a=[one("image-3", IMAGE3)], b=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                             c=[one("image-2", IMAGE2), one("image-1", IMAGE1)])
        self.refused("c: its two sets changed places", measurements.transition, BOTH, swapped_c, emergency=True)

    def test_an_emergency_drops_the_compromised_image_everywhere_at_once(self):
        """After a per-node approve, a already has both sets and b and c only the old one. Dropping the old
        image at once is a replacement on b and c and a retirement on a, in one document."""
        only_a = document("a-first", a=[one("image-1", IMAGE1), one("image-2", IMAGE2)], b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1)])
        self.assertEqual(measurements.transition(only_a, NEXT, emergency=True), "replace-without-overlap")
        self.refused("would be locked out", measurements.transition, only_a, NEXT)
        # a must lose the compromised image, not the other one: keeping only image-1 while b and c replace it
        keeps = document("x", a=[one("image-1", IMAGE1)], b=[one("image-3", IMAGE3)], c=[one("image-3", IMAGE3)])
        self.refused("an emergency replacement drops image-1; a loses another set (image-2)", measurements.transition, only_a, keeps, emergency=True)
        # nor may it simply stay beside the new one
        stays = document("x", a=[one("image-1", IMAGE1), one("image-2", IMAGE2)], b=[one("image-2", IMAGE2)], c=[one("image-2", IMAGE2)])
        self.refused("an emergency replacement drops image-1, but a would still accept it", measurements.transition, only_a, stays, emergency=True)

    def test_an_emergency_drops_the_compromised_image_whichever_set_it_is(self):
        """A 0 -> 1 rollout already retired on b and c, still open on a; then image-1 is found compromised.
        The right document drops image-1 on a (its LAST set) and replaces it on b and c."""
        zero = {"7": "00" * 32, "11": "a0" * 32}
        before = document("mid", a=[one("image-0", zero), one("image-1", IMAGE1)], b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1)])
        right = document("drop-1", a=[one("image-0", zero)], b=[one("image-2", IMAGE2)], c=[one("image-2", IMAGE2)])
        self.assertEqual(measurements.transition(before, right, emergency=True), "replace-without-overlap")
        wrong = document("keep-1", a=[one("image-1", IMAGE1)], b=[one("image-2", IMAGE2)], c=[one("image-2", IMAGE2)])
        self.refused("an emergency replacement drops image-1; a loses another set (image-0)", measurements.transition, before, wrong, emergency=True)
        # the mirror: NEXT already the only set on a, then NEXT (image-2) is the compromised one
        retired_on_a = document("r", a=[one("image-2", IMAGE2)], b=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                                c=[one("image-1", IMAGE1), one("image-2", IMAGE2)])
        back = document("drop-2", a=[one("image-3", IMAGE3)], b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1)])
        self.assertEqual(measurements.transition(retired_on_a, back, emergency=True), "replace-without-overlap")
        stays_on_c = document("drop-2", a=[one("image-3", IMAGE3)], b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1), one("image-2", IMAGE2)])
        self.refused("drops image-2, but c would still accept it", measurements.transition, retired_on_a, stays_on_c, emergency=True)
        # a newly enrolled node may not bring the compromised image back either
        with_d = document("drop-2d", a=[one("image-3", IMAGE3)], b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1)], d=[one("image-2", IMAGE2)])
        self.refused("drops image-2, but d would still accept it", measurements.transition, retired_on_a, with_d, emergency=True)

    def test_a_set_keeps_its_label(self):
        """The same measurements under a new name are the same image. Renamed, a set would be neither added
        nor removed, and the image an emergency drops could stay on under another label."""
        renamed = document("r", a=[one("clean", IMAGE1)], b=[one("image-3", IMAGE3)], c=[one("image-3", IMAGE3)])
        self.refused("a: the set 'image-1' is renamed 'clean' with the same measurements; a set keeps its label",
                     measurements.transition, CURRENT, renamed, emergency=True)
        only_a = document("a-first", a=[one("image-1", IMAGE1), one("image-2", IMAGE2)], b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1)])
        beside = document("r", a=[one("image-1b", IMAGE1), one("image-2", IMAGE2)], b=[one("image-2", IMAGE2)], c=[one("image-2", IMAGE2)])
        self.refused("is renamed 'image-1b' with the same measurements", measurements.transition, only_a, beside, emergency=True)
        # the same rule with no emergency: a rename is not "unchanged", an approval or an abandonment
        for label, old, new in (
                ("one set renamed", CURRENT, document("r", **{n: [one("image-9", IMAGE1)] for n in "abc"})),
                ("both renamed", BOTH, document("r", **{n: [one("x", IMAGE1), one("y", IMAGE2)] for n in "abc"})),
                ("renamed while approving", CURRENT, document("r", **{n: [one("image-1b", IMAGE1), one("image-3", IMAGE3)] for n in "abc"})),
                ("renamed while abandoning", BOTH, document("r", **{n: [one("new", IMAGE1)] for n in "abc"}))):
            with self.subTest(label):
                self.refused("with the same measurements; a set keeps its label", measurements.transition, old, new)
        # a NEW node carrying the dropped image's measurements under a fresh label: found by measurement
        fresh = document("r", **dict({n: [one("image-3", IMAGE3)] for n in "abc"}, d=[one("fresh", IMAGE1)]))
        self.refused("drops image-1, but d would still accept the same measurements under another label",
                     measurements.transition, CURRENT, fresh, emergency=True)

    def test_dropped_is_a_list_of_node_ids(self):
        for bad in (None, 5, "ab", "c", {"c": 1}, [1], [["c"]]):
            with self.subTest(dropped=repr(bad)):
                self.refused("`dropped` is a list of node IDs", measurements.transition, CURRENT, CURRENT, dropped=bad)

    def test_one_node_at_a_time_may_be_approved_but_not_approved_and_retired_in_one_document(self):
        only_a = document("a-first", a=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                          b=[one("image-1", IMAGE1)], c=[one("image-1", IMAGE1)])
        self.assertEqual(measurements.transition(CURRENT, only_a), "approve")
        mixed = document("mixed", a=[one("image-2", IMAGE2)], b=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                         c=[one("image-1", IMAGE1)])
        self.refused("one document does two things: approve on b; retire on a", measurements.transition, only_a, mixed)

    def test_per_phase_values_are_part_of_the_set(self):
        """A UKI image's set gives PCR 11 in the initrd and once booted. Both are the image: they are in the
        version, a label keeps them, and a dropped image is recognised by either."""
        u1, u2, u3 = uki("uki-1", "a1", "a2"), uki("uki-2", "b1", "b2"), uki("uki-3", "c1", "c2")
        v1, v2, v3 = (document(name, **{n: list(sets) for n in "abc"}) for name, sets in (("u1", [u1]), ("u2", [u1, u2]), ("u3", [u2])))
        self.assertEqual([measurements.transition(*step) for step in ((v1, v2), (v2, v3), (v2, v1))], ["approve", "retire", "abandon"])
        self.assertEqual(measurements.target(v2, "a"), u2)
        # the version covers the per-phase values
        changed = document("u1", **{n: [uki("uki-1", "a1", "a3")] for n in "abc"})
        self.assertNotEqual(measurements.version(changed), measurements.version(v1))
        # a label keeps them: one phase's value changed under the same label is another image
        self.refused("the set 'uki-1' has other measurements than before; a changed image gets a new label", measurements.transition, v1, changed)
        self.refused("has other measurements than before", measurements.transition, v1,
                     document("u2", **{n: [uki("uki-1", "a1", "a3"), u2] for n in "abc"}))
        # the move from GRUB (PCR 11 stays zero) to a UKI is an approval like any other
        grub = one("grub", {"7": "00" * 32, "11": "00" * 32})
        g1, g2 = document("g1", **{n: [grub] for n in "abc"}), document("g2", **{n: [grub, u1] for n in "abc"})
        self.assertEqual(measurements.transition(g1, g2), "approve")
        self.assertEqual(measurements.transition(g2, v1), "retire")
        # an emergency drops uki-1. A "new" image that keeps uki-1's INITRD value would still get its disk unlocked.
        self.assertEqual(measurements.transition(v1, document("e", **{n: [u3] for n in "abc"}), emergency=True), "replace-without-overlap")
        for label, disguise in (("the initrd value kept", uki("fresh", "a1", "c2")), ("the booted value kept", uki("fresh", "c1", "a2")),
                                ("the two swapped", uki("fresh", "a2", "a1")),
                                ("as a one-value set", one("fresh", {"7": "00" * 32, "11": "a1" * 32}))):
            with self.subTest(label):
                self.refused("drops uki-1, but a, b, c would still accept the same measurements under another label",
                             measurements.transition, v1, document("e", **{n: [disguise] for n in "abc"}), emergency=True)
                new_node = document("e", **dict({n: [u3] for n in "abc"}, d=[disguise]))
                self.refused("drops uki-1, but d would still accept the same measurements under another label",
                             measurements.transition, v1, new_node, emergency=True)
        # ... and so would a set that measures LESS, or something else: with one set left per node nothing else
        # holds the selection, and a set over PCR 11 alone accepts the dropped image's initrd for a disk and a lease
        for label, disguise in (("PCR 7 no longer selected", {"label": "fresh", "tpm_firmware_version": FW, "pcrs": {"11": "a1" * 32}}),
                                ("the booted value alone", {"label": "fresh", "tpm_firmware_version": FW, "pcrs": {"11": "a2" * 32}}),
                                ("one more PCR selected", dict(uki("fresh", "c1", "c2"), pcrs={"4": "44" * 32, "7": "00" * 32})),
                                ("PCR 11 once, another PCR per phase", {"label": "fresh", "tpm_firmware_version": FW, "pcrs": {"7": "00" * 32, "11": "a1" * 32},
                                                                         "phases": {"initrd": {"4": "41" * 32}, "system": {"4": "42" * 32}}})):
            with self.subTest(label):
                self.refused("an emergency replaces an image, it does not change what is measured",
                             measurements.transition, v1, document("e", **{n: [disguise] for n in "abc"}), emergency=True)
                # on a NEW node, which has no dropped set of its own: a set over other PCRs than the dropped image
                # was measured on cannot be shown to be another image, and does not come in with an emergency
                new_node = document("e", **dict({n: [u3] for n in "abc"}, d=[disguise]))
                self.refused("d comes in with the set 'fresh' over PCRs", measurements.transition, v1, new_node, emergency=True)
        grown = dict(uki("fresh", "a1", "a2"), pcrs={"4": "44" * 32, "7": "00" * 32})
        self.refused("d comes in with the set 'fresh' over PCRs 4, 7, 11, which cannot be compared with the dropped image (measured on PCRs 7, 11): "
                     "enrol it in a step of its own", measurements.transition, v1, document("e", **dict({n: [u3] for n in "abc"}, d=[grown])), emergency=True)
        # the same dropped image under another TPM firmware version is the same image
        self.refused("would still accept the same measurements under another label", measurements.transition, v1,
                     document("e", **dict({n: [u3] for n in "abc"}, d=[uki("fresh", "a1", "a2", fw="1" * 16)])), emergency=True)
        # a new node on the replacing image, on its own hardware (another PCR 7), is not a disguise
        own = dict(uki("uki-3", "c1", "c2"), pcrs={"7": "dd" * 32})
        self.assertEqual(measurements.transition(v1, document("e", **dict({n: [u3] for n in "abc"}, d=[own])), emergency=True), "replace-without-overlap")
        # A MIXED cluster (the move from GRUB to a UKI): b is still on GRUB, untouched, and shares only the Secure
        # Boot PCR with the dropped image. Its set was approved before and is not a suspect: the emergency goes through.
        grub = one("grub-1", {"4": "b4" * 32, "7": "00" * 32})
        mixed = document("m1", a=[u1], b=[grub], c=[uki("uki-1", "c1", "c2")])
        dropped = document("m2", a=[uki("uki-2", "a3", "a4")], b=[grub], c=[uki("uki-2", "c3", "c4")])
        self.assertEqual(measurements.transition(mixed, dropped, emergency=True), "replace-without-overlap")
        # ... b's set CHANGED in that document is judged like any other: the same label with other values, or a new image
        self.refused("b: the set 'grub-1' has other measurements than before", measurements.transition, mixed,
                     document("m2", a=dropped["nodes"]["a"]["accepted"], b=[one("grub-1", {"4": "b5" * 32, "7": "00" * 32})], c=dropped["nodes"]["c"]["accepted"]),
                     emergency=True)
        self.refused("puts every replaced node on ONE image, not on grub-2, uki-2", measurements.transition, mixed,
                     document("m2", a=dropped["nodes"]["a"]["accepted"], b=[one("grub-2", {"4": "b5" * 32, "7": "00" * 32})], c=dropped["nodes"]["c"]["accepted"]),
                     emergency=True)
        # ... and a NEW node with a GRUB-shaped set does not come in with that emergency
        self.refused("d comes in with the set 'grub-1' over PCRs 4, 7, which cannot be compared with the dropped image (measured on PCRs 7, 11)",
                     measurements.transition, mixed, document("m2", **dict({n: e["accepted"] for n, e in dropped["nodes"].items()}, d=[grub])),
                     emergency=True)
        # a node that had the dropped image beside another keeps the other, unchanged and uncompared
        beside = document("m1", a=[u1], b=[u2, u1], c=[u1])
        self.assertEqual(measurements.transition(beside, document("m2", **{n: [u2] for n in "abc"}), emergency=True), "replace-without-overlap")
        # the schema refusals of attest.py reach a document
        self.refused("nodes.a.accepted[0].phases: the two phases hold the same values", measurements.version,
                     document("x", a=[uki("uki-1", "a1", "a1")]))
        self.refused("'uki-1' and 'other' hold the same PCR values in one of their phases", measurements.version,
                     document("x", a=[u1, uki("other", "a2", "d2")]))

    def test_a_label_keeps_its_measurements_and_the_newcomer_is_listed_last(self):
        relabelled = document("v2", **{n: [one("image-1", IMAGE3), one("image-2", IMAGE2)] for n in "abc"})
        self.refused("has other measurements than before", measurements.transition, CURRENT, relabelled)
        self.refused("has other measurements than before", measurements.transition, CURRENT, relabelled, emergency=True)
        backwards = document("v2", **{n: [one("image-2", IMAGE2), one("image-1", IMAGE1)] for n in "abc"})
        self.refused("must be listed last", measurements.transition, CURRENT, backwards)

    def test_two_sets_changing_places_is_not_unchanged(self):
        """The target is the last set: a swap would turn every node's target back to the old image."""
        swapped = document("v2", **{n: [one("image-2", IMAGE2), one("image-1", IMAGE1)] for n in "abc"})
        self.refused("its two sets changed places, so its target would become image-1", measurements.transition, BOTH, swapped)
        self.assertEqual(measurements.target(swapped, "a")["label"], "image-1")

    def test_a_node_leaves_the_document_only_when_named_and_only_when_the_manifest_gives_it_nothing_to_do(self):
        """A node silently dropped and re-added with only the new image would be a replacement with no
        overlap and no emergency flag. Dropping it needs `dropped`, and bind() needs the manifest to
        have taken its capabilities away first; coming back is then an enrollment the root signs."""
        without_c = document("no-c", a=[one("image-1", IMAGE1)], b=[one("image-1", IMAGE1)])
        self.refused("c is no longer in the measurements", measurements.transition, CURRENT, without_c)
        self.assertEqual(measurements.transition(CURRENT, without_c, dropped=("c",)), "unchanged")
        self.refused("`dropped` names nodes that are still in the new document or never were in the old one: a, z",
                     measurements.transition, CURRENT, without_c, dropped=("a", "c", "z"))
        # and a manifest that still lets c attest does not accept the document without it
        self.refused("no entry for c, which the manifest lets attest", measurements.bind, self.under(without_c), without_c)
        measurements.bind(self.under(without_c, c="QUARANTINED"), without_c)
        # the come-back: c returns with only image-2. transition sees an enrollment ("unchanged" for a and b);
        # what stood between was the manifest that had to quarantine c, and the root restoring it.
        back = document("c-back", a=[one("image-1", IMAGE1)], b=[one("image-1", IMAGE1)], c=[one("image-2", IMAGE2)])
        self.assertEqual(measurements.transition(without_c, back), "unchanged")
        self.refused("c: image-1 is dropped in the same step that adds image-2", measurements.transition, CURRENT, back)

    def test_a_new_node_is_enrolled_without_blocking_a_step(self):
        with_d = document("v2d", a=[one("image-1", IMAGE1), one("image-2", IMAGE2)], b=[one("image-1", IMAGE1), one("image-2", IMAGE2)],
                          c=[one("image-1", IMAGE1), one("image-2", IMAGE2)], d=[one("image-2", IMAGE2)])
        self.assertEqual(measurements.transition(CURRENT, with_d), "approve")


class Reboot(Case):
    """Node order is a, b, c. A verifier's state says which set it last saw each peer on."""

    def setUp(self):
        super().setUp()
        self.manifest2 = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)))

    def state(self, **seen):
        """state(a="image-2") or state(a=("image-2", 1)): what this node's verifier recorded."""
        nodes = {}
        for node, value in seen.items():
            label, epoch = value if isinstance(value, tuple) else (value, self.manifest2["epoch"])
            nodes[node] = {"measurement": {"label": label, "epoch": epoch}}
        return {"schema": attest.STATE_SCHEMA, "nodes": nodes, "nonces": {}}

    def lease_for(self, node, issuer, manifest=None, **override):
        manifest = manifest or self.manifest2
        body = dict(self.body(manifest), node_id=node, ak_name=self.keys[node].ak_name, issuer=issuer)
        body.update(override)
        return lt.sign(body, self.keys[issuer])

    def leases(self, node, manifest=None):
        return [self.lease_for(node, peer, manifest) for peer in lt.NAMES if peer != node]

    def ask(self, node, state=None, leases=None, running="image-1", session=lt.SESSION):
        return rollout.may_reboot(self.manifest2, BOTH, node, running, session, state if state is not None else self.state(),
                                  self.leases(node) if leases is None else leases, self.now)

    def allowed(self, running, seen):
        """Which nodes may reboot at one instant. `running` is what each node runs; `seen` is what the
        OTHER nodes' verifiers last saw it on. A peer issues a lease only after re-attesting the node, so
        a node holds leases for its current boot exactly when its peers' record of it is current
        (seen == running); otherwise the leases it holds are from the boot the peers last saw."""
        out = []
        for node in lt.NAMES:
            leases = self.leases(node) if seen[node] == running[node] else \
                [self.lease_for(node, peer, session_id=lt.OTHER_SESSION) for peer in lt.NAMES if peer != node]
            try:
                self.ask(node, self.state(**{p: seen[p] for p in lt.NAMES if p != node}), leases, running=running[node])
                out.append(node)
            except m.Refused:
                pass
        return out

    def test_the_first_node_reboots_when_both_peers_vouch_for_it(self):
        self.assertEqual(self.ask("a"), {"target": "image-2", "authorizers": ["b", "c"], "seconds": 300})

    def test_the_second_node_waits_until_it_has_itself_seen_the_first_back_on_next(self):
        self.refused("WAIT: it is not b's turn. a updates first", self.ask, "b")
        self.refused("not verified under epoch 2", self.ask, "b")
        self.refused("last verified on 'image-1' at epoch 2, not on image-2", self.ask, "b", self.state(a="image-1"))
        # seen on NEXT, but under the previous manifest: that verdict is not about this rollout
        self.refused("not verified under epoch 2", self.ask, "b", self.state(a=("image-2", 1)))
        self.assertEqual(self.ask("b", self.state(a="image-2"))["authorizers"], ["a", "c"])

    def test_the_third_node_waits_for_both(self):
        self.refused("a updates first", self.ask, "c", self.state(b="image-2"))
        self.refused("b updates first", self.ask, "c", self.state(a="image-2", b="image-1"))
        self.ask("c", self.state(a="image-2", b="image-2"))

    def test_at_every_stage_of_the_rollout_exactly_one_node_may_reboot(self):
        """Every node asks at the same instant, holding every lease it could want. The turn rule alone
        must leave one: the first, in order, that is not on its target."""
        one, two = "image-1", "image-2"
        stages = (
            ("nobody has updated", dict(a=one, b=one, c=one), ["a"]),
            ("a is back on NEXT", dict(a=two, b=one, c=one), ["b"]),
            ("a and b are back", dict(a=two, b=two, c=one), ["c"]),
            ("all three are on NEXT", dict(a=two, b=two, c=two), []),
            ("b fell back to CURRENT after c went", dict(a=two, b=one, c=two), ["b"]),
            ("a fell back after everyone went", dict(a=one, b=two, c=two), ["a"]),
        )
        for label, running, want in stages:
            with self.subTest(label):
                self.assertEqual(self.allowed(running, seen=running), want)
        # a is down (rebooting): b and c have not seen it back, whatever they run
        self.assertEqual(self.allowed(dict(a=two, b=one, c=one), seen=dict(a=one, b=one, c=one)), [])

    def test_with_stale_records_too_never_more_than_one_node_may_reboot(self):
        """Every combination of what the three nodes run and what their peers last saw them on (64). A
        record goes stale when a node reboots or falls back and has not been re-attested yet; its leases
        are then from the boot the peers last saw. Never two nodes at once. The model: ALL of a node's
        peers hold the same record of it. When only some have re-attested it, see the limit below."""
        labels = ("image-1", "image-2")
        combos = [dict(a=a, b=b, c=c) for a in labels for b in labels for c in labels]
        more_than_one = [(running, seen, self.allowed(running, seen)) for running in combos for seen in combos]
        self.assertEqual(len(more_than_one), 64)
        self.assertEqual([(r, s, who) for r, s, who in more_than_one if len(who) > 1], [])
        # and with every record current, it is exactly the first node not on its target (none when all are)
        self.assertEqual([who for running, seen, who in more_than_one if running == seen],
                         [[n for n in lt.NAMES if running[n] == "image-1"][:1] for running in combos])

    def test_the_limit_a_node_may_pass_on_a_record_it_has_not_refreshed(self):
        """Stated in rollout.py's LIMITS, pinned here so nobody reads "one at a time" as more than it is. a
        fell back to CURRENT in a new boot; c has re-attested it, b has not yet. a is refused (b's lease
        is for its previous boot). b, whose own record of a is from before the fallback, still passes:
        for up to the lease lifetime two nodes can be off their feet. Three cannot."""
        self.refused("its lease is for another boot session of a", self.ask, "a",
                     leases=[self.lease_for("a", "b", session_id=lt.OTHER_SESSION), self.lease_for("a", "c")])
        self.assertEqual(self.ask("b", self.state(a="image-2"))["authorizers"], ["a", "c"])
        # once b re-attests a (its next lease renewal for a), b's record says image-1 and b waits
        self.refused("a updates first", self.ask, "b", self.state(a="image-1"))
        # c, which has seen the fallback, waits throughout
        self.refused("a updates first", self.ask, "c", self.state(a="image-1", b="image-1"))

    def test_a_lease_from_before_a_fallback_is_for_another_boot_and_is_refused(self):
        """a booted NEXT, both peers vouched, and within the five minutes a fell back to CURRENT. Its leases
        are still valid signatures; b's record still says a is on NEXT, so b would pass. a must not."""
        from_the_other_boot = [self.lease_for("a", peer, session_id=lt.OTHER_SESSION) for peer in ("b", "c")]
        why = self.refused("WAIT: no valid lease from b (its lease is for another boot session of a: that peer has not seen this boot)",
                           self.ask, "a", leases=from_the_other_boot)
        self.assertIn("c (its lease is for another boot session of a", why)
        self.ask("b", self.state(a="image-2"))                             # the node b believes is back
        self.ask("a", leases=from_the_other_boot, session=lt.OTHER_SESSION)  # control: the same leases, in the boot they are for
        for bad in ("", "5e" * 31, "5E" * 32, None, 5):
            with self.subTest(session=repr(bad)):
                self.refused("session_id must be 64 lowercase hex", self.ask, "a", session=bad)

    def test_a_node_already_on_its_target_has_nothing_to_reboot_for(self):
        self.refused("a is already on its target (image-2): nothing to reboot for", self.ask, "a", running="image-2")
        self.refused("a says it runs 'image-9', which is neither of its accepted sets", self.ask, "a", running="image-9")
        self.refused("neither of its accepted sets", self.ask, "a", running=None)

    def test_with_no_update_approved_nobody_is_told_to_reboot(self):
        """Under a one-set document the target is the running image; that is not a rollout."""
        manifest = self.under(CURRENT)
        for node in lt.NAMES:
            with self.subTest(node):
                self.refused("no update is approved for %s: the measurements list one set (image-1)" % node, rollout.may_reboot,
                             manifest, CURRENT, node, "image-1", lt.SESSION, self.state(), self.leases(node, manifest), self.now)
        after = self.under(NEXT, epoch=3, prev=m.digest(self.manifest2))
        self.refused("no update is approved for a", rollout.may_reboot, after, NEXT, "a", "image-2", lt.SESSION, self.state(), self.leases("a", after), self.now)

    def test_a_peer_that_cannot_vouch_stops_the_reboot(self):
        self.refused("WAIT: no valid lease from c (none presented)", self.ask, "a", leases=[self.lease_for("a", "b")])
        self.refused("no valid lease from b (none presented); c (none presented)", self.ask, "a", leases=[])
        expired = self.lease_for("a", "c", expires_at=hbt.stamp(self.now - 1), issued_at=hbt.stamp(self.now - 200))
        self.refused("no valid lease from c (EXPIRED", self.ask, "a", leases=[self.lease_for("a", "b"), expired])
        # a lease the peer gave ANOTHER node says nothing about this one
        self.refused("no valid lease from c (its lease is for b)", self.ask, "a", leases=[self.lease_for("a", "b"), self.lease_for("b", "c")])
        # a lease signed by somebody else in the peer's name
        forged = lt.sign(self.lease_for("a", "c")["lease"], self.keys["b"])
        self.refused("no valid lease from c (", self.ask, "a", leases=[self.lease_for("a", "b"), forged])

    def test_things_that_are_not_leases_are_refused_not_crashed_on(self):
        good = self.lease_for("a", "b")
        for junk in (None, [], "lease", {"lease": []}, {"lease": {"issuer": []}}, {"lease": {"issuer": {"x": 1}}},
                     dict(good, lease=dict(good["lease"], issuer=["c"]))):
            with self.subTest(junk=repr(junk)[:40]):
                self.refused("WAIT: no valid lease from c (none presented)", self.ask, "a", leases=[good, junk])

    def test_a_peer_still_on_the_previous_manifest_does_not_count(self):
        """It would judge the rebooted node by the OLD measurements, which do not list NEXT."""
        old = self.lease_for("a", "c", self.under(CURRENT))
        why = self.refused("no valid lease from c", self.ask, "a", leases=[self.lease_for("a", "b"), old])
        self.assertIn("its lease is from epoch 1: that peer has not accepted epoch 2", why)

    def test_a_node_taken_out_by_the_manifest_is_neither_waited_for_nor_counted_on(self):
        """a is down for repair. A signed manifest says so (QUARANTINED: a revocation key may sign it);
        b then goes on c's word alone. There is no unsigned way to skip a node."""
        self.refused("a updates first", self.ask, "b", self.state(), leases=[self.lease_for("b", "c")])
        manifest = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), a="QUARANTINED")
        verdict = rollout.may_reboot(manifest, BOTH, "b", "image-1", lt.SESSION, self.state(), [self.lease_for("b", "c", manifest)], self.now)
        self.assertEqual(verdict["authorizers"], ["c"])
        self.assertNotIn("skip", rollout.may_reboot.__code__.co_varnames)
        # and with both others out, nobody would unlock b
        alone = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), a="QUARANTINED", c="DRAINING")
        self.refused("no other node may authorize under epoch 2: nobody would unlock b", rollout.may_reboot, alone, BOTH, "b",
                     "image-1", lt.SESSION, self.state(), [], self.now)

    def test_only_an_active_node_is_rebooted_by_the_rollout(self):
        for state in ("MAINTENANCE", "DRAINING", "QUARANTINED", "RETIRED"):
            with self.subTest(state):
                manifest = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), a=state)
                self.refused("a is %s under epoch 2: only an ACTIVE node is rebooted by the rollout" % state, rollout.may_reboot,
                             manifest, BOTH, "a", "image-1", lt.SESSION, self.state(), self.leases("a", manifest), self.now)
        self.refused("z is not listed", rollout.may_reboot, self.manifest2, BOTH, "z", "image-1", lt.SESSION, self.state(), [], self.now)

    def test_the_document_must_be_the_one_the_manifest_commits_to(self):
        self.refused("is not the one the root approved", rollout.may_reboot, self.manifest2, NEXT, "a", "image-1", lt.SESSION, self.state(), self.leases("a"), self.now)
        self.refused("is not the one the root approved", rollout.may_reboot, self.under(CURRENT), BOTH, "a", "image-1", lt.SESSION, self.state(), [], self.now)

    def test_arguments_of_the_wrong_kind_are_refused_not_crashed_on(self):
        self.refused("leases is a list of lease envelopes", self.ask, "a", leases=5)
        self.refused("leases is a list", rollout.may_reboot, self.manifest2, BOTH, "a", "image-1", lt.SESSION, self.state(), None, self.now)
        for now in (None, "x", True):
            with self.subTest(now=repr(now)):
                self.refused("now is the node's authenticated time", rollout.may_reboot, self.manifest2, BOTH, "a", "image-1",
                             lt.SESSION, self.state(), self.leases("a"), now)
        self.refused("node_id is text", rollout.may_reboot, self.manifest2, BOTH, ["a"], "image-1", lt.SESSION, self.state(), [], self.now)

    def test_a_record_counts_only_with_an_integer_epoch_and_a_text_label(self):
        for record in ({"label": "image-2", "epoch": 2.0}, {"label": "image-2", "epoch": True}, {"label": "image-2", "epoch": "2"},
                       {"label": ["image-2"], "epoch": 2}, {"label": "image-2"}, "image-2", None):
            with self.subTest(record=repr(record)):
                state = {"nodes": {"a": {"measurement": record}}}
                self.refused("a updates first", self.ask, "b", state)
        # True == 1 in Python: a record at epoch True must not pass for epoch 1 either
        manifest1 = self.under(BOTH)
        self.assertIsNone(rollout.last_seen({"nodes": {"a": {"measurement": {"label": "image-2", "epoch": True}}}}, manifest1, "a"))
        self.assertEqual(rollout.last_seen({"nodes": {"a": {"measurement": {"label": "image-2", "epoch": 1}}}}, manifest1, "a"), "image-2")


class SeenUp(Case):
    """Where the sets are per boot phase, a node verified in its initrd has asked for its disk; it is not a
    node that came up. Only a sighting from the booted system counts as "back on its target"."""

    U1, U2 = uki("uki-1", "a1", "a2"), uki("uki-2", "b1", "b2")

    def setUp(self):
        super().setUp()
        self.current = document("u1", **{n: [self.U1] for n in "abc"})
        self.both = document("u2", **{n: [self.U1, self.U2] for n in "abc"})
        self.manifest2 = self.under(self.both, epoch=2, prev=m.digest(self.under(self.current)))

    @staticmethod
    def record(label, phase="system", epoch=2):
        last = {"label": label, "epoch": epoch}
        if phase != "absent":
            last["phase"] = phase
        return {"measurement": last}

    def state(self, **records):
        return {"schema": attest.STATE_SCHEMA, "nonces": {}, "nodes": records}

    def leases(self, node):
        return [lt.sign(dict(self.body(self.manifest2), node_id=node, ak_name=self.keys[node].ak_name, issuer=peer), self.keys[peer])
                for peer in lt.NAMES if peer != node]

    def test_a_node_seen_only_in_its_initrd_is_not_back(self):
        seen = lambda **kw: rollout.seen_on_target(self.state(a=self.record("uki-2", **kw)), self.manifest2, self.both, "a")
        self.assertEqual(seen(), (True, "on uki-2 at epoch 2"))
        self.assertEqual(seen(phase="initrd"), (False, "last verified in the initrd of uki-2 at epoch 2: it asked for its disk and has not been seen up since"))
        # a record from before the phase was recorded, or with no phase, does not show the node up either
        self.assertFalse(seen(phase="absent")[0])
        self.assertFalse(seen(phase=None)[0])
        for junk in ("boot", "System", 1, True, ["system"]):
            with self.subTest(phase=junk):
                self.assertEqual(seen(phase=junk), (False, "not verified under epoch 2"))
        self.assertEqual(rollout.last_seen(self.state(a=self.record("uki-2", "initrd")), self.manifest2, "a"), "uki-2")
        self.assertEqual(rollout.seen_on_target(self.state(a=self.record("uki-1")), self.manifest2, self.both, "a"),
                         (False, "last verified on 'uki-1' at epoch 2, not on uki-2"))

    def test_the_next_node_waits_for_the_one_before_to_be_up_not_merely_unlocked(self):
        ask = lambda state: rollout.may_reboot(self.manifest2, self.both, "b", "uki-1", lt.SESSION, state, self.leases("b"), self.now)
        self.refused("WAIT: it is not b's turn. a updates first and this node has not seen it back on its target (last verified in the "
                     "initrd of uki-2 at epoch 2", ask, self.state(a=self.record("uki-2", "initrd")))
        self.assertEqual(ask(self.state(a=self.record("uki-2")))["target"], "uki-2")

    def test_current_is_not_retired_for_a_node_that_never_came_up_on_next(self):
        def states(c_seen_by_a="system", c_seen_by_b="system"):
            up = self.record("uki-2")
            return {"a": self.state(b=up, c=self.record("uki-2", c_seen_by_a)), "b": self.state(a=up, c=self.record("uki-2", c_seen_by_b)),
                    "c": self.state(a=up, b=up)}
        self.assertEqual(rollout.retire_ready(self.manifest2, self.both, states()), {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]})
        why = self.refused("NOT YET: retiring now would lock out c", rollout.retire_ready, self.manifest2, self.both, states("initrd", "initrd"))
        self.assertIn("c (a last saw it in the initrd of 'uki-2', not up; b last saw it in the initrd of 'uki-2', not up, not on uki-2)", why)
        # one peer that saw it only in its initrd is enough to wait, as one that saw it fall back is
        self.refused("b last saw it in the initrd of 'uki-2', not up", rollout.retire_ready, self.manifest2, self.both, states("system", "initrd"))
        self.refused("a's state has an unreadable measurement for c: it cannot be counted, and it cannot be ignored",
                     rollout.retire_ready, self.manifest2, self.both, states("boot"))
        self.refused("a last saw it in the initrd of 'uki-2', not up", rollout.retire_ready, self.manifest2, self.both, states("absent"))

    def test_sets_with_one_value_per_pcr_count_any_sighting_as_before(self):
        manifest2 = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)))
        for phase in ("absent", None):
            with self.subTest(phase=phase):
                self.assertEqual(rollout.seen_on_target(self.state(a=self.record("image-2", phase)), manifest2, BOTH, "a"), (True, "on image-2 at epoch 2"))


class Retire(Case):
    def setUp(self):
        super().setUp()
        self.manifest2 = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)))

    def states(self, **by_peer):
        """states(a={"b": "image-2", "c": "image-2"}, ...): each peer's record of the others."""
        return {peer: {"schema": attest.STATE_SCHEMA, "nonces": {}, "nodes": {
            node: {"measurement": {"label": v[0], "epoch": v[1]} if isinstance(v, tuple) else {"label": v, "epoch": 2}}
            for node, v in seen.items()}} for peer, seen in by_peer.items()}

    def test_current_is_retired_only_when_every_node_was_seen_on_next_by_a_peer(self):
        done = self.states(a={"b": "image-2", "c": "image-2"}, b={"a": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})
        self.assertEqual(rollout.retire_ready(self.manifest2, BOTH, done), {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]})
        lagging = self.states(a={"b": "image-2", "c": "image-1"}, b={"a": "image-2", "c": "image-1"}, c={"a": "image-2", "b": "image-2"})
        why = self.refused("NOT YET: retiring now would lock out c", rollout.retire_ready, self.manifest2, BOTH, lagging)
        self.assertIn("a last saw it on 'image-1'; b last saw it on 'image-1', not on image-2", why)
        self.assertNotIn("lock out a", why)

    def test_one_peer_that_saw_a_node_fall_back_is_enough_to_wait(self):
        """c booted NEXT (a and b recorded it), fell back to CURRENT, and only b re-attested it. The first
        peer to say yes must not decide: retiring now would lock c out."""
        fell_back = self.states(a={"b": "image-2", "c": "image-2"}, b={"a": "image-2", "c": "image-1"}, c={"a": "image-2", "b": "image-2"})
        why = self.refused("NOT YET: retiring now would lock out c (b last saw it on 'image-1', not on image-2)",
                           rollout.retire_ready, self.manifest2, BOTH, fell_back)
        self.assertNotIn("a last saw it", why)
        # a peer that has not seen the node under this epoch says nothing either way
        partly = self.states(a={"b": "image-2", "c": ("image-1", 1)}, b={"a": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})
        self.assertEqual(rollout.retire_ready(self.manifest2, BOTH, partly)["c"], ["b"])

    def test_leaving_a_peers_state_out_does_not_make_it_ready(self):
        """The same case with the dissenting file not collected: forgetting one is the mistake to catch."""
        without_b = self.states(a={"b": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})
        self.refused("the state of b is missing. Every node that may authorize is a witness", rollout.retire_ready, self.manifest2, BOTH, without_b)
        self.refused("the state of b, c is missing", rollout.retire_ready, self.manifest2, BOTH, self.states(a={"b": "image-2", "c": "image-2"}))

    def test_a_node_does_not_vouch_for_itself_and_an_old_epoch_does_not_count(self):
        self_only = self.states(a={"a": "image-2", "b": "image-2", "c": "image-2"}, b={}, c={})
        self.refused("lock out a (no other node has verified it under epoch 2)", rollout.retire_ready, self.manifest2, BOTH, self_only)
        stale = self.states(a={"b": "image-2", "c": "image-2"}, b={"a": ("image-2", 1), "c": "image-2"}, c={"a": ("image-2", 1), "b": "image-2"})
        self.refused("lock out a (no other node has verified it under epoch 2)", rollout.retire_ready, self.manifest2, BOTH, stale)

    def test_only_a_node_that_may_authorize_is_a_witness(self):
        manifest = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), c="QUARANTINED")
        from_c = self.states(c={"a": "image-2", "b": "image-2"})
        self.refused("state from nodes that may not authorize under epoch 2: c", rollout.retire_ready, manifest, BOTH, from_c)
        done = self.states(a={"b": "image-2"}, b={"a": "image-2"})
        self.assertEqual(rollout.retire_ready(manifest, BOTH, done), {"a": ["b"], "b": ["a"]})   # and c is not waited for

    def test_a_collected_state_that_is_empty_or_not_a_state_is_not_a_witness(self):
        """a and c report everyone on NEXT; the dissenting b's file was collected empty, or is something
        else. That is the same mistake as leaving it out."""
        good = self.states(a={"b": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})
        for junk in ({}, [], "x", None, {"nodes": {}}, {"schema": attest.STATE_SCHEMA, "nodes": []}, {"schema": "nope", "nodes": {}},
                     {"schema": attest.STATE_SCHEMA}):
            with self.subTest(junk=repr(junk)):
                self.refused("the state given for b is not an attestation verifier's state", rollout.retire_ready,
                             self.manifest2, BOTH, dict(good, b=junk))
        # a real, empty-of-records state from b: it has seen nobody under this epoch, and says nothing
        seen_nobody = dict(good, b={"schema": attest.STATE_SCHEMA, "nodes": {}, "nonces": {}})
        self.assertEqual(rollout.retire_ready(self.manifest2, BOTH, seen_nobody)["b"], ["a", "c"])

    def test_refusals_about_the_inputs(self):
        self.refused("no verifier state was given", rollout.retire_ready, self.manifest2, BOTH, {})
        self.refused("no verifier state was given", rollout.retire_ready, self.manifest2, BOTH, {7: {}})
        self.refused("state from nodes the manifest does not list: z", rollout.retire_ready, self.manifest2, BOTH, self.states(z={}))
        self.refused("is not the one the root approved", rollout.retire_ready, self.manifest2, NEXT, self.states(a={}, b={}, c={}))
        # a state file that is not a state file refuses; it does not crash

    def test_a_witness_whose_record_cannot_be_read_or_is_from_a_later_manifest_is_not_silence(self):
        """a and c report everyone on NEXT. b's record of a node is unreadable, or b saw it fall back under
        a NEWER manifest than the one the operator is judging. Neither may count as "b says nothing"."""
        good = self.states(a={"b": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})

        def b_says(**nodes):
            return dict(good, b={"schema": attest.STATE_SCHEMA, "nonces": {}, "nodes": nodes})
        for label, reason, nodes in (
                ("a record that is text", "b's state has a record of a that is not a record", {"a": "x"}),
                ("a record that is null... is no record", None, {"a": None}),
                ("a measurement that is text", "b's state has an unreadable measurement for a", {"a": {"measurement": "image-1"}}),
                ("an epoch that is a float", "b's state has an unreadable measurement for a", {"a": {"measurement": {"label": "image-1", "epoch": 2.0}}}),
                ("an epoch that is text", "b's state has an unreadable measurement for c", {"c": {"measurement": {"label": "image-1", "epoch": "2"}}}),
                ("a label that is a list", "b's state has an unreadable measurement for a", {"a": {"measurement": {"label": ["image-2"], "epoch": 2}}}),
                ("a fallback seen under a later manifest", "b last verified a under epoch 3, later than the manifest given (epoch 2): use the current manifest",
                 {"a": {"measurement": {"label": "image-1", "epoch": 3}}})):
            with self.subTest(label):
                if reason is None:
                    self.assertEqual(rollout.retire_ready(self.manifest2, BOTH, b_says(**nodes))["a"], ["c"])
                else:
                    self.refused(reason, rollout.retire_ready, self.manifest2, BOTH, b_says(**nodes))
        # an enrolled node that was never verified has a record with no measurement: that is silence
        self.assertEqual(rollout.retire_ready(self.manifest2, BOTH, b_says(a={"ak_public": "00"}, c={"ak_public": "00"}))["a"], ["c"])
        # and a record from an EARLIER epoch is silence too (the node was not seen under this manifest)
        self.assertEqual(rollout.retire_ready(self.manifest2, BOTH, b_says(a={"measurement": {"label": "image-1", "epoch": 1}}))["a"], ["c"])



class Stranded(Retire):
    """`propose` asks stranded() before any document that takes a set away: a retire, an abandon or an
    emergency must not lock out a node that is still running the set that goes (#75)."""
    def test_a_retire_strands_whoever_retire_ready_would_wait_for(self):
        done = self.states(a={"b": "image-2", "c": "image-2"}, b={"a": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})
        self.assertEqual(rollout.stranded(self.manifest2, BOTH, NEXT, done), {})
        fell_back = self.states(a={"b": "image-2", "c": "image-2"}, b={"a": "image-2", "c": "image-1"}, c={"a": "image-2", "b": "image-2"})
        self.assertEqual(rollout.stranded(self.manifest2, BOTH, NEXT, fell_back), {"c": "b last saw it on 'image-1', not on image-2"})
        never = self.states(a={"b": "image-2"}, b={"a": "image-2"}, c={"a": "image-2", "b": "image-2"})
        self.assertEqual(rollout.stranded(self.manifest2, BOTH, NEXT, never), {"c": "no other node has verified it under epoch 2"})

    def test_abandoning_next_strands_a_node_already_on_it(self):
        """The other half: NEXT is dropped while a is on it. Nothing guarded this before."""
        a_moved = self.states(a={"b": "image-1", "c": "image-1"}, b={"a": "image-2", "c": "image-1"}, c={"a": "image-2", "b": "image-1"})
        self.assertEqual(measurements.transition(BOTH, CURRENT), "abandon")
        self.assertEqual(rollout.stranded(self.manifest2, BOTH, CURRENT, a_moved),
                         {"a": "b last saw it on 'image-2'; c last saw it on 'image-2', not on image-1"})
        nobody = self.states(a={"b": "image-1", "c": "image-1"}, b={"a": "image-1", "c": "image-1"}, c={"a": "image-1", "b": "image-1"})
        self.assertEqual(rollout.stranded(self.manifest2, BOTH, CURRENT, nobody), {})

    def test_an_emergency_strands_every_node_still_on_the_compromised_image(self):
        m1 = self.under(CURRENT)
        on_1 = self.states(a={"b": ("image-1", 1), "c": ("image-1", 1)}, b={"a": ("image-1", 1), "c": ("image-1", 1)},
                           c={"a": ("image-1", 1), "b": ("image-1", 1)})
        self.assertEqual(measurements.transition(CURRENT, NEXT, emergency=True), "replace-without-overlap")
        self.assertEqual(sorted(rollout.stranded(m1, CURRENT, NEXT, on_1)), ["a", "b", "c"])

    def test_seen_only_in_the_initrd_of_the_kept_set_is_not_up(self):
        both = document("v2", **{n: [uki("image-1", "11", "12"), uki("image-2", "21", "22")] for n in "abc"})
        nxt = document("v3", **{n: [uki("image-2", "21", "22")] for n in "abc"})
        manifest = self.under(both, epoch=2, prev=m.digest(self.under(CURRENT)))

        def seen(phase_of_c):
            rec = {"label": "image-2", "epoch": 2, "phase": "system"}
            return {p: {"schema": attest.STATE_SCHEMA, "nonces": {}, "nodes": {
                n: {"measurement": dict(rec, phase=phase_of_c) if n == "c" else rec} for n in "abc" if n != p}} for p in "abc"}
        self.assertEqual(rollout.stranded(manifest, both, nxt, seen("system")), {})
        self.assertEqual(rollout.stranded(manifest, both, nxt, seen("initrd")),
                         {"c": "a last saw it in the initrd of 'image-2', not up; b last saw it in the initrd of 'image-2', not up, not on image-2"})

    def test_the_witnesses_are_checked_as_retire_ready_checks_them(self):
        without_b = self.states(a={"b": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})
        self.refused("the state of b is missing", rollout.stranded, self.manifest2, BOTH, NEXT, without_b)
        self.refused("is not the one the root approved", rollout.stranded, self.manifest2, NEXT, CURRENT, without_b)

    def test_a_node_that_neither_unlocks_nor_serves_is_not_judged_but_named(self):
        manifest = self.under(BOTH, epoch=2, prev=m.digest(self.under(CURRENT)), c="QUARANTINED")
        done = self.states(a={"b": "image-2"}, b={"a": "image-2"})
        self.assertEqual(rollout.stranded(manifest, BOTH, NEXT, done), {})
        self.assertEqual(rollout.unwatched(manifest, BOTH, NEXT), ["c"])
        self.assertEqual(rollout.unwatched(self.manifest2, BOTH, NEXT), [])

def sign(manifest, key=hbt.ROOT, signer="root"):
    return {"manifest": manifest, "signature": {"signer": signer, "key": hbt.pub(key),
                                                "sig": key.sign(m.DOMAIN + m.canonical(manifest)).hex()}}


class OnSwtpm(unittest.TestCase):
    """Three software TPMs, a, b and c. Each is a node that boots an image and a peer that judges the
    other two: its own membership store anchored in its TPM, its own heartbeat counter, its own
    attestation verifier, and leases signed by its TPM. A "boot" restarts the TPM (PCRs zeroed, the reset
    counter up by one) and extends PCR 7 (a Secure Boot stand-in) and PCR 11 (the image, then the phase
    "enter-initrd", as systemd-stub and systemd-pcrphase do on a UKI host). The node is then in its initrd,
    where it asks for its disk; `up()` takes it through the rest of the boot (PCR 11 extended by
    "leave-initrd", "sysinit", "ready"), where it asks for leases. One image, two PCR 11 values.
    Where the tools are provisioned (REGALIA_EXPECT_SWTPM=1) a missing one is a failure, not a skip."""

    NODES = ("a", "b", "c")
    PCR7 = hashlib.sha256(b"secure boot stand-in").hexdigest()
    IMAGES = {name: hashlib.sha256(name.encode()).hexdigest() for name in ("image-1", "image-2")}

    def setUp(self):
        if not all(shutil.which(t) for t in ("swtpm", "tpm2_createak", "tpm2_quote", "tpm2_nvdefine", "tpm2_pcrextend", "openssl")):
            if os.environ.get("REGALIA_EXPECT_SWTPM") == "1":
                self.fail("swtpm, tpm2-tools and openssl are expected here and were not found")
            self.skipTest("needs swtpm, tpm2-tools and openssl")
        self.d = tempfile.mkdtemp(dir="/tmp")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.pid, self.tcti, self.names, self.session, self.image, self.phase, self.boots = {}, {}, {}, {}, {}, {}, 0
        self.addCleanup(lambda: [self.stop(n) for n in list(self.pid)])
        for name in self.NODES:
            self.tcti[name] = "swtpm:path=%s/%s.sock" % (self.d, name)
            os.makedirs("%s/tpm-%s" % (self.d, name))
            os.mkdir("%s/%s" % (self.d, name))
            self.boot(name, "image-1")
            self.on(name, attest.node_init, "%s/%s" % (self.d, name))
            self.names[name] = {k: attest.name_of(attest.public_area(lt.slurp("%s/%s/%s.pub" % (self.d, name, k)), k)).hex()
                                for k in ("ek", "ak")}
        # The wall clock must advance with the TPMs' own clocks: heartbeat.authenticated_now refuses a clock
        # that reads earlier than its last reading plus the TPM time elapsed since. A frozen test clock passed
        # on a quiet machine and failed ("the clock went backwards") whenever the run took longer.
        self.started, self.offset = time.monotonic(), 0
        self.clock = lambda: (self.now, True)
        self.root = hbt.pub(hbt.ROOT)
        self.sequence = 0
        self.store, self.freshness, self.signer, self.att = {}, {}, {}, {}
        for name in self.NODES:
            highwater = m.HighWater("0x1500016", tcti=self.tcti[name], lock_path="%s/%s-hw.lock" % (self.d, name))
            highwater.define()
            self.store[name] = m.Store("%s/%s-membership.json" % (self.d, name), self.root, highwater)
            counter = hb.Counter("0x1500018", tcti=self.tcti[name], lock_path="%s/%s-hb.lock" % (self.d, name))
            counter.define()
            self.freshness[name] = hb.Freshness(counter, self.clock, hb.TpmClock(tcti=self.tcti[name]), "%s/%s-freshness.json" % (self.d, name))
            self.signer[name] = lease.TpmSigner(tcti=self.tcti[name])

    @property
    def now(self):
        return lt.T0 + 60 + int(time.monotonic() - self.started) + self.offset

    # ---- the machines ----

    def stop(self, name):
        pid = self.pid.pop(name, None)
        if pid:
            subprocess.run(["tpm2_shutdown", "-c"], env=dict(os.environ, TPM2TOOLS_TCTI=self.tcti[name]), capture_output=True)
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
            time.sleep(0.3)

    def boot(self, name, image):
        """One boot of `name` into `image`: a new boot session."""
        self.stop(name)
        sock = "%s/%s.sock" % (self.d, name)
        subprocess.run(["swtpm", "socket", "--tpm2", "--tpmstate", "dir=%s/tpm-%s" % (self.d, name), "--server", "type=unixio,path=" + sock,
                        "--ctrl", "type=unixio,path=" + sock + ".ctrl", "--flags", "not-need-init,startup-clear", "--daemon",
                        "--pid", "file=%s/%s.pid" % (self.d, name)], check=True, capture_output=True)
        with open("%s/%s.pid" % (self.d, name)) as f:
            self.pid[name] = int(f.read())
        # not a fixed sleep: on a busy machine the TPM may take longer to answer than it usually does
        for _ in range(50):
            if self.on(name, subprocess.run, ["tpm2_pcrread", "sha256:7"], capture_output=True).returncode == 0:
                break
            time.sleep(0.2)
        self.on(name, subprocess.run, ["tpm2_pcrextend", "7:sha256=" + self.PCR7, "11:sha256=" + self.IMAGES[image]], check=True, capture_output=True)
        self.extend_phases(name, self.INITRD)
        self.boots += 1
        self.session[name] = hashlib.sha256(b"boot %d" % self.boots).hexdigest()
        self.image[name], self.phase[name] = image, "initrd"

    INITRD, SYSTEM = ("enter-initrd",), ("leave-initrd", "sysinit", "ready")

    def extend_phases(self, name, phases):
        for phase in phases:
            self.on(name, subprocess.run, ["tpm2_pcrextend", "11:sha256=" + hashlib.sha256(phase.encode()).hexdigest()], check=True, capture_output=True)

    def up(self, name):
        """`name` leaves its initrd and finishes booting (once per boot)."""
        if self.phase[name] == "initrd":
            self.extend_phases(name, self.SYSTEM)
            self.phase[name] = "system"

    def on(self, tpm, fn, *args, **kw):
        with unittest.mock.patch.dict(os.environ, TPM2TOOLS_TCTI=self.tcti[tpm]):
            return fn(*args, **kw)

    @staticmethod
    def extended(*digests):
        """A PCR that started at zero and was extended by each digest in turn."""
        value = bytes(32)
        for digest in digests:
            value = hashlib.sha256(value + bytes.fromhex(digest)).digest()
        return value.hex()

    # ---- what the root signs ----

    def reference(self, image, firmware):
        """The set of one image: PCR 7 once, PCR 11 as it is in the initrd and as it is once booted."""
        initrd = [self.IMAGES[image]] + [hashlib.sha256(p.encode()).hexdigest() for p in self.INITRD]
        system = initrd + [hashlib.sha256(p.encode()).hexdigest() for p in self.SYSTEM]
        return {"label": image, "tpm_firmware_version": firmware, "pcrs": {"7": self.extended(self.PCR7)},
                "phases": {"initrd": {"11": self.extended(*initrd)}, "system": {"11": self.extended(*system)}}}

    def doc(self, name, firmware, *images):
        return {"schema": measurements.SCHEMA, "name": name,
                "nodes": {n: {"accepted": [self.reference(i, firmware) for i in images]} for n in self.NODES}}

    def manifest(self, epoch, previous, document):
        return {"schema": m.SCHEMA, "epoch": epoch, "prev_digest": m.digest(previous) if previous else "",
                "policy_version": measurements.version(document), "issued_at": "2026-09-21T09:00:00Z", "revocation_keys": [hbt.pub(hbt.REVOKE)],
                "nodes": [{"node_id": n, "state": "ACTIVE", "ek_name": self.names[n]["ek"], "ak_name": self.names[n]["ak"],
                           "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": ("%02x" % (0xa0 + i)) * 32,
                           "hsm_serials": ["DENK04041%02d" % i]} for i, n in enumerate(self.NODES)]}

    def publish(self, manifest, document):
        """Every node accepts the root-signed manifest (durably, anchored in its TPM), gets a heartbeat for
        it, and rebuilds its attestation policy from the document that manifest commits to."""
        self.sequence += 1
        for name in self.NODES:
            self.assertEqual(self.store[name].commit(sign(manifest)), manifest)
            self.freshness[name].accept(hbt.beat(manifest, self.sequence, issued=self.now), manifest)
            self.verifier(name, manifest, document)
        self.manifest_now, self.document_now = manifest, document

    def verifier(self, peer, manifest, document):
        self.att[peer] = attest.Verifier(measurements.attest_policy(manifest, document, peer_id=peer), "%s/%s-attest.json" % (self.d, peer))
        return self.att[peer]

    def enroll(self, peer, node):
        credential = self.att[peer].challenge(node, lt.slurp("%s/%s/ek.pub" % (self.d, node)), lt.slurp("%s/%s/ak.pub" % (self.d, node)))
        cred, secret = "%s/cred-%s-%s" % (self.d, peer, node), "%s/secret-%s-%s" % (self.d, peer, node)
        with open(cred, "wb") as f:
            f.write(credential)
        self.on(node, attest.node_activate, cred, secret)
        self.att[peer].enroll(node, lt.slurp(secret))

    # ---- what the nodes do ----

    def evidence(self, peer, node, manifest=None):
        manifest = manifest or self.manifest_now
        nonce, session = self.att[peer].nonce(node), self.session[node]
        paths = ("%s/q.msg" % self.d, "%s/q.sig" % self.d)
        key = b"ephemeral key of boot " + bytes.fromhex(session)
        self.on(node, attest.node_quote, node, manifest["epoch"], bytes.fromhex(session), key, nonce, [7, 11], *paths)
        return {"ephemeral_public": key.hex(), "nonce": nonce.hex(), "quote": lt.slurp(paths[0]).hex(), "signature": lt.slurp(paths[1]).hex()}

    def unlock(self, peer, node):
        """`peer` decides whether to help `node` boot: the #59 unlock decision. The node asks from wherever
        it is; a test that wants the refusal of a booted node asks after up()."""
        return replacement.may_unlock(self.manifest_now, peer, node, self.session[node], self.evidence(peer, node),
                                      self.att[peer], self.freshness[peer])

    def vouch(self, peer, node, booted=True):
        """A runtime lease for `node`, signed by `peer`'s TPM after it re-attested the node. A node asks for
        leases once it is up, so it finishes booting first (`booted=False`: it asks from its initrd)."""
        if booted:
            self.up(node)
        request = {"node_id": node, "session_id": self.session[node], "nonce": os.urandom(32).hex()}
        return lease.issue(self.manifest_now, peer, request, self.att[peer], self.evidence(peer, node), self.freshness[peer], self.signer[peer])

    def state(self, peer):
        with open("%s/%s-attest.json" % (self.d, peer)) as f:
            return json.load(f)

    def seen(self, peer, node):
        return self.state(peer)["nodes"][node].get("measurement", {}).get("label")

    def seen_in(self, peer, node):
        return self.state(peer)["nodes"][node].get("measurement", {}).get("phase")

    def may_reboot(self, node, leases=None):
        if leases is None:
            leases = [self.vouch(peer, node) for peer in self.NODES if peer != node]
        return rollout.may_reboot(self.manifest_now, self.document_now, node, self.image[node], self.session[node], self.state(node), leases, self.now)

    def others(self, node):
        return [n for n in self.NODES if n != node]

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))
        return str(caught.exception)

    def test_an_update_rolls_through_three_nodes_and_the_old_image_is_then_refused(self):
        # ---- intake: the firmware version is read from a quote, the PCR values are computed ----
        probe = "%s/probe" % self.d
        self.on("a", attest.node_quote, "a", 1, bytes(32), b"k", bytes(32), [7, 11], probe + ".msg", probe + ".sig")
        firmware = attest.parse_quote(lt.slurp(probe + ".msg"))["firmware_version"]
        v1, v2, v3 = self.doc("v1", firmware, "image-1"), self.doc("v2", firmware, "image-1", "image-2"), self.doc("v3", firmware, "image-2")
        m1 = self.manifest(1, None, v1)
        m2 = self.manifest(2, m1, v2)
        m3 = self.manifest(3, m2, v3)

        # ---- 15.1: CURRENT. Every node is enrolled with both peers and unlocked on image-1 ----
        self.publish(m1, v1)
        for peer in self.NODES:
            for node in self.others(peer):
                self.enroll(peer, node)
                self.assertGreater(self.unlock(peer, node), 0)
                self.assertEqual(self.seen(peer, node), "image-1")
        # ---- the phase rule: one image has two PCR 11 values, and each request is accepted from one of them ----
        # b, still in its initrd, asks for a lease: an initrd does not get one
        self.refused("the node is in the initrd phase of image-1; this request is accepted only from the system phase",
                     self.vouch, "a", "b", booted=False)
        self.assertGreater(self.unlock("a", "b"), 0)                      # ... and that refusal cost it nothing
        # b finishes booting, gets its leases, and now asks for a disk key: a booted system does not get one
        self.assertGreater(lease.verify(self.vouch("a", "b"), m1, self.now), 280)
        self.refused("the node is in the system phase of image-1; this request is accepted only from the initrd phase", self.unlock, "a", "b")
        self.refused("the node is in the system phase of image-1", self.unlock, "c", "b")
        self.assertEqual(self.seen("a", "b"), "image-1")
        # an image nobody approved yet: c boots image-2 before the root has signed anything
        self.boot("c", "image-2")
        self.refused("the subject's attestation is refused: the quoted PCR digest is not the expected PCR values", self.unlock, "a", "c")
        self.refused("the quoted PCR digest is not the expected PCR values", self.vouch, "b", "c")
        self.boot("c", "image-1")
        self.assertGreater(self.unlock("a", "c"), 0)                      # the fallback: CURRENT still boots
        # no update is approved yet: nobody is told to reboot
        self.refused("no update is approved for a: the measurements list one set (image-1)", self.may_reboot, "a")

        # ---- 15.2/15.3: the root approves CURRENT and NEXT ----
        self.assertEqual(measurements.transition(v1, v2), "approve")
        self.publish(m2, v2)
        # 15.4: one node at a time, in order. Asked at the same moment, only a may go.
        self.assertEqual(self.may_reboot("a")["authorizers"], ["b", "c"])
        self.refused("WAIT: it is not b's turn. a updates first", self.may_reboot, "b")
        self.refused("WAIT: it is not c's turn. a updates first", self.may_reboot, "c")
        self.refused("NOT YET: retiring now would lock out a", rollout.retire_ready, m2, v2, {n: self.state(n) for n in self.NODES})

        # a updates. 15.5: its peers unlock it on NEXT, automatically, and it serves again.
        self.boot("a", "image-2")
        self.refused("a updates first and this node has not seen it back", self.may_reboot, "b")   # a is down: b waits
        for peer in ("b", "c"):
            self.assertGreater(self.unlock(peer, "a"), 0)
            self.assertEqual((self.seen(peer, "a"), self.seen_in(peer, "a")), ("image-2", "initrd"))
        # a has its disk and is not up yet. An unlock is not "back": b still waits, and nothing is ready to retire.
        self.refused("a updates first and this node has not seen it back on its target (last verified in the initrd of image-2",
                     self.may_reboot, "b")
        self.refused("a (b last saw it in the initrd of 'image-2', not up; c last saw it in the initrd of 'image-2', not up",
                     rollout.retire_ready, m2, v2, {n: self.state(n) for n in self.NODES})
        self.refused("a is already on its target (image-2): nothing to reboot for", self.may_reboot, "a")
        held = [self.vouch(peer, "a") for peer in ("b", "c")]
        self.assertEqual([self.seen_in(peer, "a") for peer in ("b", "c")], ["system", "system"])
        # a is up on NEXT, and asks for a disk key: refused by name, with two sets accepted
        self.refused("the node is in the system phase of image-2; this request is accepted only from the initrd phase", self.unlock, "b", "a")
        self.assertTrue(all(lease.verify(e, m2, self.now) > 280 for e in held))      # five minutes, less this run's seconds
        # a, on NEXT, still vouches for b and c on CURRENT: both sets work during the rollout
        self.assertTrue(all(lease.verify(self.vouch("a", n), m2, self.now) > 280 for n in ("b", "c")))
        why = self.refused("NOT YET: retiring now would lock out b", rollout.retire_ready, m2, v2, {n: self.state(n) for n in self.NODES})
        self.assertIn("c (a last saw it on 'image-1'; b last saw it on 'image-1', not on image-2)", why)

        # 15.6: b's turn, since b has itself seen a back on NEXT. Without c's word it waits.
        self.refused("WAIT: no valid lease from c (none presented)", self.may_reboot, "b", [self.vouch("a", "b")])
        self.refused("WAIT: it is not c's turn. b updates first", self.may_reboot, "c")
        self.assertEqual(self.may_reboot("b")["authorizers"], ["a", "c"])
        self.boot("b", "image-2")
        self.assertGreater(self.unlock("a", "b"), 0)
        # b's new image fails and it falls back to CURRENT: still unlocked, because both are approved
        before_fallback = [self.vouch(peer, "b") for peer in ("a", "c")]     # leases b holds on image-2
        self.boot("b", "image-1")
        # those leases are still valid signatures, and a's record still says b is on NEXT; they are for another boot
        self.refused("its lease is for another boot session of b: that peer has not seen this boot", self.may_reboot, "b", before_fallback)
        self.assertGreater(self.unlock("c", "b"), 0)
        self.assertEqual(self.seen("c", "b"), "image-1")
        self.refused("WAIT: it is not c's turn. b updates first", self.may_reboot, "c")   # c saw b fall back
        # a saw b on NEXT, c saw it fall back: one peer saying "behind" is enough to wait
        self.refused("lock out b (c last saw it on 'image-1', not on image-2)", rollout.retire_ready, m2, v2, {n: self.state(n) for n in self.NODES})
        self.assertEqual(self.may_reboot("b")["target"], "image-2")                       # and it is b's turn again
        self.boot("b", "image-2")
        for peer in ("a", "c"):
            self.assertGreater(self.unlock(peer, "b"), 0)
        # b is unlocked, not up: c does not go yet
        self.refused("WAIT: it is not c's turn. b updates first and this node has not seen it back on its target (last verified in the "
                     "initrd of image-2", self.may_reboot, "c")
        self.vouch("c", "b")                                                              # b is up, and c has seen it
        self.assertEqual(self.may_reboot("c")["authorizers"], ["a", "b"])
        self.boot("c", "image-2")
        for peer in ("a", "b"):
            self.assertGreater(self.unlock(peer, "c"), 0)

        # ---- 15.7: retire CURRENT, once every node was seen UP on NEXT by a peer ----
        # c has its disk on NEXT and is not up: not yet
        self.refused("NOT YET: retiring now would lock out", rollout.retire_ready, m2, v2, {n: self.state(n) for n in self.NODES})
        for node in self.NODES:
            self.refused("%s is already on its target" % node, self.may_reboot, node)     # the rollout is over: nobody reboots
        self.assertEqual(rollout.retire_ready(m2, v2, {n: self.state(n) for n in self.NODES}), {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]})
        self.assertEqual(measurements.transition(v2, v3), "retire")
        before_retirement = {n: lt.slurp(self.store[n].path) for n in self.NODES}
        old_lease_for_c = self.vouch("a", "c")
        self.publish(m3, v3)
        for peer, node in (("b", "a"), ("c", "b"), ("a", "c")):
            self.assertGreater(lease.verify(self.vouch(peer, node), m3, self.now), 280)   # NEXT keeps working

        # ---- 15.8: the old image is booted again. Its peers refuse it. ----
        for peer in ("a", "b"):
            self.boot("c", "image-1")                                     # each peer refuses it in its initrd, then once up
            self.refused("the subject's attestation is refused: the quoted PCR digest is not the expected PCR values", self.unlock, peer, "c")
            self.refused("the quoted PCR digest is not the expected PCR values", self.vouch, peer, "c")
            self.assertEqual(self.seen(peer, "c"), "image-2")             # a refusal does not rewrite the record
        # the lease c held from before the retirement was issued under epoch 2 and is still inside its five minutes:
        # the lease bound, as lease.py states it. It is not renewed.
        self.assertGreater(lease.verify(old_lease_for_c, m3, self.now), 0)
        self.offset += lease.MAX_LIFETIME
        self.refused("EXPIRED", lease.verify, old_lease_for_c, m3, self.now)

        # the older document, handed to a peer that holds the newer manifest
        self.refused("it is not the one the root approved, or it is an older or newer one", measurements.bind, m3, v2)
        # DISK ROLLBACK on peer a: its membership file restored to the chain that still approved image-1
        with open(self.store["a"].path, "wb") as f:
            f.write(before_retirement["a"])
        self.refused("ROLLBACK: the membership on disk is epoch 2 but the TPM high-water is 3", self.store["a"].load)
        # and the same file on a TPM that never saw epoch 3 would load: the anchor is what refuses
        self.assertEqual(m.accept_chain(None, m.load(before_retirement["a"], limit=m.MAX_CHAIN_BYTES), self.root)["epoch"], 2)

        # c boots NEXT again and is back: unlocked by both peers under the retiring manifest, and vouched for once up
        self.boot("c", "image-2")
        for peer in ("a", "b"):
            self.assertGreater(self.unlock(peer, "c"), 0)
        self.assertGreater(lease.verify(self.vouch("b", "c"), m3, self.now), 0)


if __name__ == "__main__":
    unittest.main()
