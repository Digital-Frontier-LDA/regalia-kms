"""deploy/baremetal/survivor.py (ADR-0002 D32 item 6, #432 item (e)): the owner's one authorization for a lone survivor,
held only at the quarantine epoch with every other server stopped; and the owner's directive, which only disables."""
import json
import os
import shutil
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
        return sv.Directives(os.path.join(d, "directives.jsonl"))

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


if __name__ == "__main__":
    unittest.main()
