"""Exercise the fixture's synthetic authorization and runtime refusal proof."""
from unittest.mock import Mock, patch
from types import SimpleNamespace
import unittest

from deploy.baremetal import membership, survivor
from tests.test_baremetal_membership_v4 import O1, pub
from tests.test_baremetal_membership_v5 import single5
from tests.test_one_node_revocation import one_node, threenode


class SurvivorProof(unittest.TestCase):
    def test_fixture_is_schema_valid_and_owner_signed_but_profile_refused(self):
        tip = single5(1, "")
        owner = O1[1]
        signer = SimpleNamespace(public=lambda: pub(owner), sign=owner.sign)
        signed = one_node.synthetic_survivor(tip, signer, 1800000000)
        message = survivor.authorization_message(signed["authorization"])
        self.assertEqual(membership.counting_parties(tip, message, [signed["signature"]], "authorization"), {membership.OWNER})
        with self.assertRaisesRegex(membership.Refused, "refused under the single-node profile"):
            survivor.verify_authorization(signed, tip, "a")
        with self.assertRaises(membership.Refused):
            one_node.synthetic_survivor(tip, SimpleNamespace(public=lambda: pub(owner), sign=lambda _: b"\0" * 64), 1800000000)

    def test_runtime_proof_names_the_profile_and_restores_the_issuer_on_timeout(self):
        tip = single5(1, "")
        for reason, expected in (("recovery is refused under the single-node profile", True),
                                 ("no runtime lease is held", False), (None, False)):
            with self.subTest(reason=reason):
                calls = []
                now = [0]
                member = SimpleNamespace(run=one_node.pathlib.Path("/unused"))
                cluster = SimpleNamespace(nodes={"a": member}, manifest=tip, unit=lambda *_: "fixture-a-sync",
                                          _run=lambda *args: calls.append(("restore", args)))

                def read(*args):
                    self.assertEqual(calls, [("stop", ("systemctl", "stop", "fixture-a-sync"))])
                    return {"reason": reason} if reason else None

                clock = SimpleNamespace(monotonic=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
                with patch.object(one_node, "non_serving_admission", side_effect=read), \
                        patch.object(one_node, "sh", side_effect=lambda *args: calls.append(("stop", args))), \
                        patch.object(threenode, "time", clock):
                    self.assertIs(one_node.survivor_runtime_refusal(cluster, {}), expected)
                self.assertEqual(calls[-1], ("restore", (member, "sync")))

    def test_polling_error_is_not_a_runtime_refusal(self):
        member = SimpleNamespace(run=one_node.pathlib.Path("/unused"))
        cluster = SimpleNamespace(nodes={"a": member}, manifest=single5(1, ""), unit=Mock(), _run=Mock())
        now = [0]
        with patch.object(one_node, "non_serving_admission", side_effect=OSError("read failed")), \
                patch.object(one_node, "sh"), patch.object(threenode, "time", SimpleNamespace(
                    monotonic=lambda: now[0], sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))):
            self.assertFalse(one_node.survivor_runtime_refusal(cluster, {}))
        cluster._run.assert_called_once_with(member, "sync")
