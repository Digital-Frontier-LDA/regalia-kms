"""deploy/baremetal/survivor.py (ADR-0002 D32 item 6, #432 item (e)): the owner's one authorization for a lone survivor,
held only at the quarantine epoch with every other server stopped; and the owner's directive, which only disables."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from deploy.baremetal import membership as m, survivor as sv
from tests.test_baremetal_fence import BOXES, redfish_evidence
from tests.test_baremetal_membership_v4 import NODE_KEYS, OWNER_KEYS, ed25519, manifest4, nodes4, p256_sig, pub

T0 = 1791201600                                              # 2026-10-05T12:00:00Z
FENCED = "b and c are powered off at their PDUs"


class OwnerKey:
    def __init__(self, key):
        self.key = key

    def public(self):
        return pub(self.key)

    def sign(self, message):
        return self.key.sign(message)


class Case(unittest.TestCase):
    def setUp(self):
        self.m1 = manifest4(1, "", nodes4())
        self.m2 = manifest4(2, m.digest(self.m1), nodes4(b="QUARANTINED", c="QUARANTINED"))     # the quarantine epoch

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))
        return str(caught.exception)

    def authorize(self, tip=None, who="a", typed=None, key=None, life_s=None, scope="stateless", fence=None, inventory=BOXES):
        tip = tip or self.m2
        want = {}

        def confirm(text):
            want["text"] = text
            return typed if typed is not None else text.split("Type exactly: ")[1].split("\n")[0]
        return sv.make_authorization(tip, who, "powered off at their PDUs", T0, confirm, lambda: OwnerKey(key or OWNER_KEYS[0]), life_s=life_s,
                                     scope=scope, fence=fence, inventory=inventory)


class Authorization(Case):
    def test_the_owner_authorizes_a_survivor_at_the_quarantine_epoch(self):
        signed = self.authorize()
        self.assertEqual(sv.in_force(signed, self.m2, "a", T0 + 60), (T0 + sv.MAX_AUTHORIZATION_S, "stateless"))
        self.assertIn("b, c: powered off at their PDUs; they will not rejoin until they hold epoch 2", signed["authorization"]["fenced"])

    def test_any_new_epoch_ends_it(self):
        signed = self.authorize()
        m3 = manifest4(3, m.digest(self.m2), nodes4(b="QUARANTINED", c="QUARANTINED"))
        self.refused("a new epoch ends it", sv.in_force, signed, m3, "a", T0 + 60)
        back = manifest4(3, m.digest(self.m2), nodes4(c="QUARANTINED"))      # b readmitted
        self.refused("a new epoch ends it", sv.verify_authorization, signed, back)

    def test_only_with_every_other_server_stopped_and_never_for_a_stopped_survivor(self):
        half = manifest4(2, m.digest(self.m1), nodes4(c="QUARANTINED"))
        self.refused("quarantine b first", self.authorize, half)
        all_stopped = manifest4(2, m.digest(self.m1), nodes4(a="QUARANTINED", b="QUARANTINED", c="QUARANTINED"))
        self.refused("b does not count under epoch 2", self.authorize, all_stopped, "b")
        forged = dict(self.authorize(), authorization=dict(self.authorize()["authorization"], node_id="b"))
        self.refused("survivor authorization", sv.verify_authorization, forged, self.m2)

    def test_the_owner_s_key_and_the_typed_line(self):
        self.refused("not one of the tip manifest's owner_keys", self.authorize, key=ed25519(99))
        self.refused("the line typed is not this authorization's", self.authorize, typed="authorize a")
        signed = self.authorize()
        tampered = dict(signed, authorization=dict(signed["authorization"], expires_at="2026-10-06T12:00:00Z"))
        self.refused("survivor authorization", sv.verify_authorization, tampered, self.m2)

    def test_its_life_and_its_window(self):
        self.refused("lives at most %d s" % sv.MAX_AUTHORIZATION_S, self.authorize, life_s=sv.MAX_AUTHORIZATION_S + 1)
        signed = self.authorize(life_s=3600)
        self.refused("EXPIRED", sv.in_force, signed, self.m2, "a", T0 + 3600)
        self.refused("ahead of this node's clock", sv.in_force, signed, self.m2, "a", T0 - 3600)
        self.refused("is for a, not b", sv.in_force, signed, self.m2, "b", T0)


def raw_authorization(tip, who="a", others=("b", "c")):
    """An authorization signed by the owner WITHOUT the tool's checks: what verify must judge on its own."""
    return {"schema": sv.AUTH_SCHEMA, "node_id": who, "quarantine_epoch": tip["epoch"], "quarantine_digest": m.digest(tip),
            "not_before": "2026-10-05T12:00:00Z", "expires_at": "2026-10-06T12:00:00Z", "fenced": "b, c: off", "scope": "stateless",
            "fence": {"method": "attested", "nodes": {o: {"power_state": "unreachable", "read_at": "2026-10-05T12:00:00Z"} for o in others}}}


class FullScope(Case):
    """The owner's one-server decision (#432): "full" keeps stateful operations on a lone survivor, from full_from()
    on: the attestation plus a request's longest life plus the skew (1e, A1), plus more for a fence only typed (d9, G1)."""

    def fence(self, state="Off"):
        return redfish_evidence(state=state)

    def test_full_begins_after_the_wait_and_sooner_with_a_power_readback(self):
        read = self.authorize(scope="full", fence=self.fence())
        start = T0 + sv.REQUEST_LIFE_S + sv.SKEW_S
        self.assertEqual(sv.in_force(read, self.m2, "a", start - 1)[1], "stateless")
        self.assertEqual(sv.in_force(read, self.m2, "a", start)[1], "full")
        typed = self.authorize(scope="full")                              # no readback: the typed fallback waits longer
        self.assertEqual(sv.in_force(typed, self.m2, "a", start)[1], "stateless")
        self.assertEqual(sv.in_force(typed, self.m2, "a", start + sv.FALLBACK_EXTRA_S)[1], "full")
        self.assertEqual(sv.in_force(self.authorize(), self.m2, "a", start + 10 ** 5)[1], "stateless")    # stateless stays so

    def test_the_fence_evidence_names_every_other_node_powered_off(self):
        self.refused("reads Off for every fenced node", self.authorize, scope="full", fence=self.fence("On"))
        partial = redfish_evidence(("b",))
        self.refused("the fence evidence names ['b']", self.authorize, scope="full", fence=partial)
        self.refused("scope must be one of", self.authorize, scope="everything")

    def test_the_fence_reaches_every_other_node_but_the_retired_and_stolen(self):
        """05 on #516: no full scope while a node that may still run is not in the evidence; a RETIRED or REVOKED_STOLEN
        node's hardware may be gone, so asking for its readback would make a redfish fence impossible forever."""
        tip = manifest4(2, m.digest(self.m1), nodes4(b="QUARANTINED", c="RETIRED"))
        signed = self.authorize(tip=tip, scope="full", fence=redfish_evidence(("b",)))
        self.assertEqual(set(signed["authorization"]["fence"]["nodes"]), {"b"})
        self.refused("the fence evidence names ['b', 'c']; the nodes to fence are ['b']", self.authorize, tip=tip, scope="full",
                     fence=redfish_evidence(("b", "c")))
        self.refused("the fence evidence names ['b']; the nodes to fence are ['b', 'c']", self.authorize, scope="full",
                     fence=redfish_evidence(("b",)))
        typed = self.authorize(tip=tip, scope="full")                  # the typed fallback names the same set
        self.assertEqual(set(typed["authorization"]["fence"]["nodes"]), {"b"})

    def test_no_survivor_when_every_other_node_is_retired_or_stolen(self):
        """regalia-4rt: with no node left to fence, none can ever count again, so this is a one-node membership, which a
        new manifest commissions; it is not an outage. The refusal says so, before any fence or typed line."""
        for others in ({"b": "RETIRED", "c": "REVOKED_STOLEN"}, {"b": "RETIRED", "c": "RETIRED"}):
            tip = manifest4(2, m.digest(self.m1), nodes4(**others))
            for scope in ("stateless", "full"):
                self.refused("every other node is RETIRED or REVOKED_STOLEN under epoch 2: nothing is left to fence",
                             self.authorize, tip=tip, scope=scope)
        # a misspelt survivor is refused as one that does not count, not told to commission itself
        gone = manifest4(2, m.digest(self.m1), nodes4(a="RETIRED", b="RETIRED", c="REVOKED_STOLEN"))
        self.refused("z does not count under epoch 2", self.authorize, tip=gone, who="z")

    def test_no_survivor_authorization_for_the_only_node(self):
        """regalia-4rt, 57's case: membership accepts a one-node manifest; its node counts alone, with nothing to fence."""
        one = manifest4(2, m.digest(self.m1), nodes4()[:1], heartbeat_signers={"threshold": 2, "parties": ["a", "owner"]},
                        activation_signers={"threshold": 2, "parties": ["a", "owner"]},
                        revocation_signers=[{"threshold": 2, "parties": ["a", "owner"]}, {"threshold": 1, "parties": ["owner"]}])
        m.validate(one)
        self.refused("a is the only node under epoch 2: it counts alone, and no survivor authorization applies",
                     self.authorize, tip=one)

    def test_the_evidence_is_this_outage_s(self):
        """05 on #516: read after the quarantine was signed, and again within the hour before the owner signs; a drill's
        or an earlier outage's evidence against the same inventory does not replay."""
        early = manifest4(2, m.digest(self.m1), nodes4(b="QUARANTINED", c="QUARANTINED"), issued_at="2026-10-05T11:59:30Z")
        self.refused("b was read Off at 2026-10-05T11:59:00Z, before epoch 2's quarantine was signed (2026-10-05T11:59:30Z)",
                     self.authorize, tip=early, scope="full", fence=redfish_evidence())
        stale = redfish_evidence(day="2026-10-04")
        self.refused("b's second Off readback (2026-10-04T11:59:10Z) is not within 3600 s before the owner signed", self.authorize,
                     scope="full", fence=stale)
        ahead = redfish_evidence(day="2026-10-06")
        self.refused("b's second Off readback (2026-10-06T11:59:10Z) is not within 3600 s", self.authorize, scope="full", fence=ahead)

    def test_a_redfish_fence_is_signed_only_against_the_inventory(self):
        """05 on #432: the box in the evidence is the box commissioned for that node, checked again where the owner signs."""
        self.refused("a redfish fence is checked against the fence inventory: give it", self.authorize, scope="full", fence=self.fence(),
                     inventory=None)
        moved = self.fence()
        moved["nodes"]["b"]["serial"] = "CZJ59999Q"
        self.refused("b's box reports serial 'CZJ59999Q'; the inventory's is 'CZJ50001Q'", self.authorize, scope="full", fence=moved)
        swapped = self.fence()
        swapped["nodes"]["c"]["ilo_cert_sha256"] = BOXES["b"]["ilo_cert_sha256"]
        self.refused("c's iLO certificate is not the one pinned for it", self.authorize, scope="full", fence=swapped)

    def test_the_typed_line_names_the_scope(self):
        self.refused("the line typed is not this authorization's", self.authorize, scope="full",
                     typed="authorize a alone stateless 2 until 2026-10-12T12:00:00Z")


class VerifiedOnItsOwn(Case):
    """verify_authorization does not rely on the owner's tool having checked: a hand-made one is judged in full."""

    def owner(self, auth, tip):
        return {"authorization": auth, "signature": {"party": m.OWNER, "key": pub(OWNER_KEYS[0]),
                                                     "sig": OWNER_KEYS[0].sign(sv.authorization_message(auth)).hex()}}

    def test_an_owner_signed_authorization_with_a_server_still_counting_is_refused(self):
        half = manifest4(2, m.digest(self.m1), nodes4(c="QUARANTINED"))
        self.refused("b is not", sv.verify_authorization, self.owner(raw_authorization(half), half), half)

    def test_a_node_s_signature_is_not_the_owner_s(self):
        auth = raw_authorization(self.m2)
        by_a = {"authorization": auth, "signature": {"party": "a", "key": pub(NODE_KEYS["a"]), "sig": p256_sig(NODE_KEYS["a"], sv.authorization_message(auth))}}
        self.refused("is not the owner's", sv.verify_authorization, by_a, self.m2)


class Directive(Case):
    def directive(self, object_id="release-signing", typed=None, state="disabled"):
        def confirm(text):
            return typed if typed is not None else text.split("Type exactly: ")[1].split("\n")[0]
        return sv.make_directive(self.m2, object_id, "the release card was stolen", T0, confirm, lambda: OwnerKey(OWNER_KEYS[1]), state=state)

    def test_a_directive_only_disables_never_enables_never_destroys(self):
        """d9 and 24 on #432 and #493: monotone, and never irreversible. Neither the tool, the schema nor the verifier takes
        "enabled" or "destroyed": destruction stays a majority-time, approval-gated operation."""
        for state in ("enabled", "destroyed"):
            with self.subTest(state):
                self.refused("a directive only disables, never %r" % state, self.directive, state=state)
                signed = self.directive()
                forged = dict(signed, directive=dict(signed["directive"], state=state))
                self.refused("a directive only disables, never %r" % state, sv.verify_directive, forged, self.m2)

    def test_it_is_judged_against_its_own_quarantine_manifest_so_the_majority_can_commit_it_later(self):
        signed = self.directive()
        self.assertEqual(sv.verify_directive(signed, self.m2)["object_id"], "release-signing")
        self.refused("is for epoch 2's manifest", sv.verify_directive, signed, self.m1)

    def store(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        return sv.Directives(os.path.join(d, "directives.jsonl"), owner_uid=os.getuid())

    def test_the_survivor_keeps_the_signed_directives_and_derives_the_disabled_keys_from_them(self):
        store = self.store()
        self.assertEqual(store.disabled(), set())
        first = self.directive()
        self.assertEqual(store.apply(first, self.m2), {"release-signing"})
        self.assertEqual(store.apply(first, self.m2), {"release-signing"})                 # the same one again: kept once
        self.assertEqual(store.apply(self.directive("ci-signing"), self.m2), {"release-signing", "ci-signing"})
        held = store.held()
        self.assertEqual([h["directive"]["object_id"] for h in held], ["release-signing", "ci-signing"])
        self.assertEqual(sv.verify_directive(held[0], self.m2), first["directive"])          # the envelopes, for the majority

    def test_apply_verifies_itself(self):
        store = self.store()
        signed = self.directive()
        by_a = {"directive": signed["directive"], "signature": {"party": "a", "key": pub(NODE_KEYS["a"]),
                                                                "sig": p256_sig(NODE_KEYS["a"], sv.directive_message(signed["directive"]))}}
        self.refused("is not the owner's", store.apply, by_a, self.m2)
        self.refused("is for epoch 2's manifest", store.apply, signed, self.m1)
        self.assertEqual(store.held(), [])

    def test_a_corrupt_file_refuses_every_key_never_reads_as_nothing_disabled(self):
        store = self.store()
        store.apply(self.directive(), self.m2)
        with open(store.path, "ab") as f:
            f.write(b'{"directive": {"state": "enabled"}}\n')
        self.refused("every key is refused", store.disabled)

    def test_the_store_is_a_singly_linked_file_only_its_owner_may_write(self):
        store = self.store()
        store.apply(self.directive(), self.m2)
        os.chmod(store.path, 0o666)
        self.refused("is not a regular, singly linked file", store.disabled)
        self.refused("is not a regular, singly linked file", store.apply, self.directive("ci-signing"), self.m2)
        os.chmod(store.path, 0o640)
        other = store.path + ".other"
        os.link(store.path, other)                                         # a hard link: never appended to, never read
        self.refused("is not a regular, singly linked file", store.apply, self.directive("ci-signing"), self.m2)
        self.refused("is not a regular, singly linked file", store.disabled)
        os.unlink(other)
        # not the owner's: its directory is this test user's too, so that is refused first (StoreOnDisk); the file's own
        # owner check stands behind it for a file planted in root's directory
        self.refused("is not a directory of root's", sv.Directives(store.path, owner_uid=os.getuid() + 1).disabled)
        os.unlink(store.path)
        os.symlink(other, store.path)
        self.refused("cannot be opened", store.disabled)

    def test_a_wiped_store_replayed_can_only_disable_again(self):
        """The store is not an anti-replay record: a directive only disables, so presenting an old one again after the
        store is lost (its disk replaced: since regalia-kds it outlives a reboot) disables its key again, never enables
        one; and one signed under an earlier epoch is refused against the node's current manifest. What a lost store
        does lose is the disabled set itself, which is why it is on the disk (StoreOnDisk), not a replay."""
        store = self.store()
        old = self.directive()
        store.apply(old, self.m2)
        os.unlink(store.path)                                             # the store lost
        self.assertEqual(store.disabled(), set())                         # the loss, measured
        self.assertEqual(store.apply(old, self.m2), {"release-signing"})  # the replay: the same key disabled again
        self.refused("is for epoch 2's manifest", store.apply, old, self.m1)

    def test_a_node_s_directive_is_not_the_owner_s(self):
        directive = self.directive()["directive"]
        by_a = {"directive": directive, "signature": {"party": "a", "key": pub(NODE_KEYS["a"]), "sig": p256_sig(NODE_KEYS["a"], sv.directive_message(directive))}}
        self.refused("is not the owner's", sv.verify_directive, by_a, self.m2)

    def test_the_typed_line_and_the_owner_alone(self):
        self.refused("the line typed is not this directive's", self.directive, typed="disabled other-key")
        signed = self.directive()
        by_node = dict(signed, signature=dict(signed["signature"], party="a"))
        with self.assertRaises(m.Refused):
            sv.verify_directive(by_node, self.m2)


class OwnerTool(Case):
    """owner.py sign-survivor and sign-directive, through main() with their exact argv (the hand-over is tested where it
    is made): the chain verified from the pinned root, the line typed at the terminal, the file written once."""

    def setUp(self):
        super().setUp()
        import json
        import tests.test_baremetal_heartbeat as hbt
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

        def signed(manifest):
            return {"manifest": manifest, "signature": {"signer": "root", "key": hbt.pub(hbt.ROOT),
                                                        "sig": hbt.ROOT.sign(m.DOMAIN + m.canonical(manifest)).hex()}}
        self.chain = os.path.join(self.d, "chain.json")
        with open(self.chain, "w") as f:
            json.dump([signed(self.m1), signed(self.m2)], f)
        self.root = hbt.pub(hbt.ROOT)

    def run_tool(self, argv, typed):
        import json
        from unittest import mock
        from deploy.baremetal import keyfd, owner, p11sign
        with mock.patch.object(p11sign, "Pkcs11Signer", lambda *a, **k: OwnerKey(OWNER_KEYS[0])), \
                mock.patch.object(keyfd, "tty_line", lambda prompt: typed), mock.patch.object(owner, "off_the_nodes", lambda: None), \
                mock.patch.object(owner.time, "time", lambda: T0), mock.patch("builtins.print"):
            code = owner.main(argv + ["--module", "/nonexistent/opensc-pkcs11.so", "--serial", "12345678"])
        out = argv[argv.index("--out") + 1]
        return code, (json.load(open(out)) if os.path.exists(out) else None)

    def test_sign_survivor_writes_an_authorization_that_holds(self):
        out = os.path.join(self.d, "auth.json")
        code, signed = self.run_tool(["sign-survivor", "--chain", self.chain, "--root-key", self.root, "--node-id", "a",
                                      "--how", "powered off at their PDUs", "--life-s", "86400", "--out", out],
                                     "authorize a alone stateless 2 until 2026-10-06T12:00:00Z")
        self.assertEqual(code, 0)
        self.assertEqual(sv.in_force(signed, self.m2, "a", T0 + 60), (T0 + 86400, "stateless"))

    def test_sign_directive_writes_a_disable_only_directive_and_has_no_state_to_choose(self):
        out = os.path.join(self.d, "directive.json")
        code, signed = self.run_tool(["sign-directive", "--chain", self.chain, "--root-key", self.root, "--object-id", "release-signing",
                                      "--reason", "the card was stolen", "--out", out], "disabled release-signing")
        self.assertEqual(code, 0)
        self.assertEqual(sv.verify_directive(signed, self.m2)["state"], "disabled")
        with self.assertRaises(SystemExit):                            # the tool has no --state: it only disables
            self.run_tool(["sign-directive", "--chain", self.chain, "--root-key", self.root, "--object-id", "x", "--state", "destroyed",
                           "--reason", "r", "--out", os.path.join(self.d, "no.json")], "destroyed x")

    def test_sign_survivor_with_the_fence_evidence_checks_it_against_the_inventory(self):
        from tests.test_baremetal_fence import INVENTORY
        evidence, inventory = os.path.join(self.d, "fence.json"), os.path.join(self.d, "inventory.json")
        with open(evidence, "w") as f:
            json.dump(redfish_evidence(), f)
        with open(inventory, "w") as f:
            json.dump(INVENTORY, f)
        line = "authorize a alone full 2 until 2026-10-06T12:00:00Z"
        argv = ["sign-survivor", "--chain", self.chain, "--root-key", self.root, "--node-id", "a", "--how", "ForceOff at the iLOs",
                "--life-s", "86400", "--scope", "full", "--fence-evidence", evidence]
        code, signed = self.run_tool(argv + ["--out", os.path.join(self.d, "no.json")], line)
        self.assertEqual((code, signed), (1, None))                    # no inventory: nothing signed
        code, signed = self.run_tool(argv + ["--inventory", inventory, "--out", os.path.join(self.d, "auth.json")], line)
        self.assertEqual(code, 0)
        self.assertEqual(signed["authorization"]["fence"], redfish_evidence())
        self.assertEqual(sv.in_force(signed, self.m2, "a", T0 + sv.REQUEST_LIFE_S + sv.SKEW_S), (T0 + 86400, "full"))

    def test_a_wrong_line_writes_nothing(self):
        out = os.path.join(self.d, "auth.json")
        code, signed = self.run_tool(["sign-survivor", "--chain", self.chain, "--root-key", self.root, "--node-id", "a",
                                      "--how", "off", "--out", out], "authorize b")
        self.assertEqual((code, signed), (1, None))


class StoreOnDisk(Case):
    """regalia-kds: the applied directives outlive a reboot. They live in STORE_DIR, a directory of root's on the disk that
    no group or other may enter, never in /run; the store is read and written through that directory's descriptor, and a
    directory that is not such a one refuses every key (never "nothing disabled")."""

    def directive(self, object_id="release-signing"):
        return sv.make_directive(self.m2, object_id, "stolen", T0, lambda text: text.split("Type exactly: ")[1].split("\n")[0],
                                 lambda: OwnerKey(OWNER_KEYS[1]))

    def directory(self, mode=0o700):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.chmod(d, mode)
        return d

    def test_the_store_is_root_s_on_the_disk_never_in_run(self):
        self.assertFalse(sv.STORE_DIR.startswith("/run"), "a reboot empties /run, and with it the keys the owner disabled")
        import pathlib
        conf = (pathlib.Path(__file__).resolve().parents[1] / "deploy" / "baremetal" / "units" / "regalia.tmpfiles.conf").read_text()
        self.assertIn("d %s 0700 root root -" % sv.STORE_DIR, conf.splitlines())

    def test_a_restart_reads_the_same_disabled_set(self):
        path = os.path.join(self.directory(), sv.DIRECTIVES_FILE)
        sv.Directives(path, owner_uid=os.getuid()).apply(self.directive(), self.m2)
        self.assertEqual(sv.Directives(path, owner_uid=os.getuid()).disabled(), {"release-signing"})     # a new process, same disk

    def test_a_directory_others_may_enter_or_another_s_refuses_every_key(self):
        for mode in (0o750, 0o705, 0o770):
            with self.subTest(oct(mode)):
                store = sv.Directives(os.path.join(self.directory(mode), sv.DIRECTIVES_FILE), owner_uid=os.getuid())
                self.refused("only root may enter (0700): every key is refused", store.disabled)
                self.refused("only root may enter (0700): every key is refused", store.apply, self.directive(), self.m2)
        store = sv.Directives(os.path.join(self.directory(), sv.DIRECTIVES_FILE), owner_uid=os.getuid() + 1)
        self.refused("is not a directory of root's", store.disabled)

    def test_a_link_in_place_of_the_directory_or_none_refuses_every_key(self):
        real = self.directory()
        link = real + ".link"
        os.symlink(real, link)
        self.addCleanup(os.unlink, link)
        self.refused("cannot be opened", sv.Directives(os.path.join(link, sv.DIRECTIVES_FILE), owner_uid=os.getuid()).disabled)
        self.refused("cannot be opened", sv.Directives(os.path.join(real, "gone", sv.DIRECTIVES_FILE), owner_uid=os.getuid()).disabled)


class OnTheNode(Case):
    """survivor.py install / remove / directive (root, at the node's console) and the admission's reader, seconds_left."""

    def setUp(self):
        super().setUp()
        import json
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.store_dir = tempfile.mkdtemp(dir=self.d)                       # STORE_DIR's stand-in, 0700 as tmpfiles makes it
        self.signed = self.authorize(life_s=3600)
        self.auth = os.path.join(self.d, "auth.json")
        with open(self.auth, "w") as f:
            json.dump(self.signed, f)

    def run_main(self, argv, now=T0 + 60, authenticated=True):
        from unittest import mock
        from deploy.baremetal import node as node_module
        fake = mock.Mock(node_id="a", runtime=self.d)                     # root's run directory
        fake.held.side_effect = lambda name: self.fail("%s is put in the admission user's own directory" % name)
        fake.manifest.return_value = self.m2
        fake.clock.return_value = lambda: (now, authenticated)
        with mock.patch.object(node_module, "Node", lambda cfg: fake), mock.patch.object(node_module, "load", lambda path: {}), \
                mock.patch.object(sv.os, "geteuid", lambda: 0), mock.patch("builtins.print") as said, \
                mock.patch.object(sv, "Directives", lambda path, real=sv.Directives: real(path, owner_uid=os.getuid())), \
                mock.patch.object(sv, "STORE_DIR", self.store_dir):
            code = sv.main(["--config", "/etc/regalia/node.json"] + argv)
        self.said = " ".join(str(c.args[0]) for c in said.call_args_list if c.args)
        return code

    def test_install_through_main_writes_what_the_admission_reads(self):
        self.assertEqual(self.run_main(["install", "--authorization", self.auth]), 0)
        path = os.path.join(self.d, sv.AUTH_FILE)
        self.assertEqual(sv.installed(path, owner_uid=os.getuid()), self.signed)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o644)
        clock = lambda: (T0 + 100, True)                                   # noqa: E731
        self.assertEqual(sv.seconds_left(path, self.m2, "a", clock, owner_uid=os.getuid()), 3600 - 100)
        m3 = manifest4(3, m.digest(self.m2), nodes4(b="QUARANTINED", c="QUARANTINED"))
        self.refused("a new epoch ends it", sv.seconds_left, path, m3, "a", clock, owner_uid=os.getuid())
        self.refused("EXPIRED", sv.seconds_left, path, self.m2, "a", lambda: (T0 + 3600, True), owner_uid=os.getuid())
        self.refused("time is not authenticated", sv.seconds_left, path, self.m2, "a", lambda: (T0 + 100, False), owner_uid=os.getuid())
        self.assertEqual(self.run_main(["remove"]), 0)
        self.assertIsNone(sv.seconds_left(path, self.m2, "a", clock, owner_uid=os.getuid()))

    def test_install_refuses_what_does_not_hold_and_writes_nothing(self):
        self.assertEqual(self.run_main(["install", "--authorization", self.auth], now=T0 + 7200), 1)          # expired
        self.assertEqual(self.run_main(["install", "--authorization", self.auth], authenticated=False), 1)
        self.assertFalse(os.path.exists(os.path.join(self.d, sv.AUTH_FILE)))

    def test_the_reader_takes_only_a_root_owned_file_only_root_may_write(self):
        path = os.path.join(self.d, sv.AUTH_FILE)
        sv._write_root(path, self.signed)
        self.refused("is not a regular file of root's", sv.installed, path, owner_uid=os.getuid() + 1)    # another's (root's, as root)
        os.chmod(path, 0o666)
        self.refused("is not a regular file of", sv.installed, path, owner_uid=os.getuid())
        os.unlink(path)
        os.symlink(self.auth, path)
        self.refused("cannot be opened", sv.installed, path, owner_uid=os.getuid())
        os.unlink(path)
        sv._write_root(self.auth + ".kept", self.signed)
        os.link(self.auth + ".kept", path)                                 # a hard link to another such file
        self.refused("has 2 links", sv.installed, path, owner_uid=os.getuid())

    def test_a_malformed_document_is_a_refusal_never_a_crash_of_the_round(self):
        path = os.path.join(self.d, sv.AUTH_FILE)
        for label, doc in (("not an object", [1, 2]), ("no authorization", {"signature": {}}),
                           ("wrong types", {"authorization": "x", "signature": 3})):
            with self.subTest(label):
                sv._write_root(path, doc)
                with self.assertRaises(m.Refused):
                    sv.seconds_left(path, self.m2, "a", lambda: (T0 + 100, True), owner_uid=os.getuid())

    def test_a_clock_that_cannot_be_read_is_a_refusal_with_its_reason(self):
        path = os.path.join(self.d, sv.AUTH_FILE)
        sv._write_root(path, self.signed)

        def clock():
            raise OSError(5, "Input/output error", "/run/regalia/authtime.json")
        self.refused("cannot be read as one: [Errno 5]", sv.seconds_left, path, self.m2, "a", clock, owner_uid=os.getuid())

    def test_remove_says_when_nothing_was_installed(self):
        self.assertEqual(self.run_main(["remove"]), 0)
        self.assertIn("NOTHING INSTALLED", self.said)

    def test_directive_through_main_applies_a_disable(self):
        import json
        directive = sv.make_directive(self.m2, "release-signing", "stolen", T0,
                                      lambda text: text.split("Type exactly: ")[1].split("\n")[0], lambda: OwnerKey(OWNER_KEYS[1]))
        f = os.path.join(self.d, "directive.json")
        with open(f, "w") as out:
            json.dump(directive, out)
        self.assertEqual(self.run_main(["directive", "--file", f]), 0)
        self.assertEqual(sv.Directives(os.path.join(self.store_dir, sv.DIRECTIVES_FILE), owner_uid=os.getuid()).disabled(),
                         {"release-signing"})
        self.assertFalse(os.path.lexists(os.path.join(self.d, sv.DIRECTIVES_FILE)), "written in the run directory, which a reboot empties")

    def test_the_admission_service_is_wired_to_the_installed_authorization(self):
        from unittest import mock
        from deploy.baremetal import node as node_module
        fake = mock.Mock(node_id="a", runtime=self.d, run=None)
        fake.held.side_effect = lambda name: os.path.join(self.d, "admission", name)
        fake.clock.return_value = lambda: (T0 + 60, True)
        with mock.patch.object(node_module, "boot_session", return_value=("ab" * 32, b"pub")), \
                mock.patch.object(node_module.lease, "Holder"), mock.patch.object(node_module, "Trail"):
            service = node_module.admission_service(fake, daemon_started=lambda: None)
        self.assertIsNone(service.survivor(self.m2))                        # none installed
        path = os.path.join(self.d, sv.AUTH_FILE)                           # in root's run directory, not admission's
        sv._write_root(path, self.signed)
        if os.getuid() == 0:
            os.chown(path, 65534, 65534)                                    # as root: make it another's, so the refusal is real
        self.refused("is not a regular file of root's", service.survivor, self.m2)    # the real reader: root's file only


if __name__ == "__main__":
    unittest.main()


class DirectivesVector(unittest.TestCase):
    """tests/vectors/survivor-directives-v1.json is what Directives decides for each file, and internal/admission's
    ReadDisabled is held to it (TestSurvivorDirectivesVector): the daemon refuses the keys the survivor applied (j18)."""

    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def load(self):
        with open(os.path.join(self.ROOT, "tests", "vectors", "survivor-directives-v1.json")) as f:
            return json.load(f)

    def test_the_vector_is_what_the_generator_makes_now(self):
        made = subprocess.run([sys.executable, "-Es", os.path.join(self.ROOT, "tests", "vectors", "make-survivor-directives-v1.py")],
                              capture_output=True, text=True, check=True, cwd=self.ROOT).stdout
        self.assertEqual(json.loads(made), self.load(),
                         "regenerate: python3 -Es tests/vectors/make-survivor-directives-v1.py > tests/vectors/survivor-directives-v1.json")

    def test_both_answers_and_every_field_are_reached(self):
        cases = self.load()["cases"]
        self.assertTrue(any(c["disabled"] == "refused" for c in cases) and any(c["disabled"] != "refused" for c in cases))
        self.assertTrue(any(isinstance(c["disabled"], list) and len(c["disabled"]) == 2 for c in cases))
        names = " ".join(c["name"] for c in cases)
        for field in ("object ID", "epoch", "digest", "reason", "schema", "state", "signature", "CR"):
            self.assertIn(field, names)
