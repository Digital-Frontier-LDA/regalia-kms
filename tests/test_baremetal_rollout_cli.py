"""The operator command over measurements.py and rollout.py: `python3 -m deploy.baremetal.rollout …`
(#156, KERNEL-UPDATE.md). Every subcommand reads; `propose` prints an UNSIGNED manifest; none signs.

The fixtures are those of tests/test_baremetal_rollout.py (OpenSSL TPM identities, signed leases)."""
import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from deploy.baremetal import attest, measurements, rollout
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt
import tests.test_baremetal_lease as lt
import tests.test_baremetal_rollout as rt

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CURRENT, BOTH, NEXT = rt.CURRENT, rt.BOTH, rt.NEXT


class Case(rt.Case):
    def setUp(self):
        super().setUp()
        self.root = hbt.pub(hbt.ROOT)
        self.m1 = self.under(CURRENT)
        self.m2 = self.under(BOTH, epoch=2, prev=m.digest(self.m1))

    def write(self, name, value):
        path = os.path.join(self.d, name)
        with open(path, "w") as f:
            json.dump(value, f)
        return path

    def chain(self, *manifests, name="membership.json"):
        return self.write(name, [rt.sign(manifest) for manifest in manifests])

    def run_cli(self, *argv):
        """(exit status, standard output, standard error)."""
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                rc = rollout.main(list(argv))
            except SystemExit as stop:      # argparse: a usage error
                rc = stop.code
        return rc, out.getvalue(), err.getvalue()

    def as_json(self, *argv):
        rc, out, _ = self.run_cli("--json", *argv)
        return rc, json.loads(out)

    def on(self, manifests, name="membership.json"):
        return ["--membership", self.chain(*manifests, name=name), "--root-key", self.root]


class Documents(Case):
    def test_version_prints_what_the_manifest_must_carry(self):
        path = self.write("both.json", BOTH)
        rc, out, err = self.run_cli("version", "--measurements", path)
        self.assertEqual((rc, out, err), (0, "%s  (v2)\n" % measurements.version(BOTH), ""))
        rc, result = self.as_json("version", "--measurements", path)
        self.assertEqual(result, {"ok": True, "command": "version", "name": "v2", "policy_version": measurements.version(BOTH),
                                  "nodes": {n: ["image-1", "image-2"] for n in "abc"}})

    def test_the_documented_invocation_runs_from_the_repository_root(self):
        done = subprocess.run([sys.executable, "-m", "deploy.baremetal.rollout", "--json", "version", "--measurements", self.write("d.json", NEXT)],
                              cwd=ROOT_DIR, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["policy_version"], measurements.version(NEXT))

    def test_transition_names_the_step_or_refuses_it(self):
        current, both, nxt = (self.write(n, d) for n, d in (("1.json", CURRENT), ("2.json", BOTH), ("3.json", NEXT)))
        self.assertEqual(self.run_cli("transition", "--old", current, "--new", both), (0, "approve\n", ""))
        self.assertEqual(self.run_cli("transition", "--old", both, "--new", nxt)[1], "retire\n")
        self.assertEqual(self.run_cli("transition", "--old", both, "--new", current)[1], "abandon\n")
        rc, out, err = self.run_cli("transition", "--old", current, "--new", nxt)
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("transition: NO: a: image-1 is dropped in the same step that adds image-2", err)
        self.assertEqual(self.run_cli("transition", "--old", current, "--new", nxt, "--emergency")[1], "replace-without-overlap\n")
        rc, result = self.as_json("transition", "--old", current, "--new", nxt)
        self.assertEqual((rc, result["ok"], result["command"]), (1, False, "transition"))
        self.assertIn("would be locked out", result["refused"])
        without_c = self.write("no-c.json", rt.document("no-c", a=[rt.one("image-1", rt.IMAGE1)], b=[rt.one("image-1", rt.IMAGE1)]))
        self.assertEqual(self.run_cli("transition", "--old", current, "--new", without_c)[0], 1)
        self.assertEqual(self.run_cli("transition", "--old", current, "--new", without_c, "--dropped", "c")[1], "unchanged\n")

    def test_unreadable_and_malformed_inputs_are_refusals_with_the_reason(self):
        rc, _, err = self.run_cli("version", "--measurements", os.path.join(self.d, "absent.json"))
        self.assertEqual(rc, 1)
        self.assertIn("cannot read", err)
        with open(os.path.join(self.d, "bad.json"), "w") as f:
            f.write("{")
        self.assertIn("not valid JSON", self.run_cli("version", "--measurements", os.path.join(self.d, "bad.json"))[2])
        self.assertEqual(self.run_cli("version")[0], 2)                      # usage
        self.assertEqual(self.run_cli("sign", "--anything")[0], 2)           # there is no such command


class Epoch(Case):
    def test_the_manifest_a_node_holds(self):
        rc, result = self.as_json("epoch", *self.on([self.m1, self.m2]))
        self.assertEqual(rc, 0)
        self.assertEqual(result, {"ok": True, "command": "epoch", "epoch": 2, "manifest_digest": m.digest(self.m2),
                                  "policy_version": measurements.version(BOTH), "issued_at": self.m2["issued_at"],
                                  "nodes": {"a": "ACTIVE", "b": "ACTIVE", "c": "ACTIVE"}, "checked_against_tpm": False})
        rc, out, _ = self.run_cli("epoch", *self.on([self.m1, self.m2]))
        self.assertIn("epoch 2, measurements %s" % measurements.version(BOTH), out)
        self.assertIn("NOT checked against this host's TPM epoch counter", out)

    def test_the_chain_is_verified_from_the_root_key_given(self):
        other = hbt.pub(hbt.OTHER)
        rc, _, err = self.run_cli("epoch", "--membership", self.chain(self.m1), "--root-key", other)
        self.assertEqual(rc, 1)
        self.assertIn("a root key that is not the pinned root", err)
        self.assertIn("--root-key must be 64 lowercase hex", self.run_cli("epoch", "--membership", self.chain(self.m1), "--root-key", "x")[2])
        skipped = self.under(NEXT, epoch=3, prev=m.digest(self.m2))
        self.assertIn("epoch 3 does not follow 1", self.run_cli("epoch", *self.on([self.m1, skipped]))[2])
        self.assertIn("non-empty list of signed manifests", self.run_cli("epoch", "--membership", self.write("e.json", []), "--root-key", self.root)[2])

    def test_with_a_tpm_index_the_epoch_counter_is_read_and_never_advanced(self):
        argv = ["epoch", *self.on([self.m1, self.m2]), "--tpm-index", "0x1500016"]
        advanced = mock.Mock(side_effect=AssertionError("the check advanced the TPM counter"))
        with mock.patch.object(m.HighWater, "advance", advanced), mock.patch.object(m.HighWater, "_advance", advanced), \
                mock.patch.object(m.HighWater, "define", advanced):
            for high_water, want in ((2, None), (3, "ROLLBACK: "), (1, "which this host has not anchored yet (TPM high-water 1)")):
                with self.subTest(high_water=high_water), mock.patch.object(m.HighWater, "value", return_value=high_water), \
                        mock.patch.object(m.HighWater, "verify", return_value=high_water), mock.patch.object(m.HighWater, "pinned", return_value=True):
                    rc, out, err = self.run_cli(*argv)
                    if want is None:
                        self.assertEqual((rc, err), (0, ""))
                        self.assertNotIn("NOT checked", out)
                        self.assertTrue(self.as_json(*argv)[1]["checked_against_tpm"])
                    else:
                        self.assertEqual(rc, 1)
                        self.assertIn(want, err)
            with mock.patch.object(m.HighWater, "value", return_value=2), mock.patch.object(m.HighWater, "verify", return_value=3), \
                    mock.patch.object(m.HighWater, "pinned", return_value=True):
                self.assertIn("TPM high-water moved during the check: run it again", self.run_cli(*argv)[2])
            with mock.patch.object(m.HighWater, "value", side_effect=m.Refused("cannot read NV index 0x1500016")):
                self.assertIn("cannot read NV index", self.run_cli(*argv)[2])
        advanced.assert_not_called()

    def anchored(self, *manifests):
        """A HighWater on a fake TPM that a node's Store has anchored to this chain."""
        tpm = hbt.FakeTpm()
        anchor = m.HighWater("0x1500016", lock_path=os.path.join(self.d, "hw.lock"), run=tpm)
        anchor.define()
        store = m.Store(os.path.join(self.d, "node-membership.json"), self.root, anchor)
        for manifest in manifests:
            store.commit(rt.sign(manifest))
        return tpm, anchor, store

    def test_with_a_tpm_index_a_substituted_chain_of_the_same_length_is_refused(self):
        """The counter alone cannot tell two root-signed chains of one length apart; the TPM's record of the
        manifest does, and membership.Store.load refuses the other. So must the operator's check."""
        tpm, anchor, store = self.anchored(self.m1)
        rival = self.under(NEXT, epoch=2, prev=m.digest(self.m1))
        self.assertNotEqual(m.digest(rival), m.digest(self.m2))
        mine = ["epoch", *self.on([self.m1, self.m2]), "--tpm-index", "0x1500016"]
        substituted = self.on([self.m1, rival], name="rival.json")
        with mock.patch.object(rollout.membership, "HighWater", return_value=anchor) as built:
            # The crash window, as a crash leaves it: the chain with epoch 2 is on disk, the counter moved to 2,
            # the record still names epoch 1. The service completes it on its next load; the operator's check
            # does not, and does not vouch for epoch 2 meanwhile.
            self.write("node-membership.json", [rt.sign(self.m1), rt.sign(self.m2)])
            anchor.advance(2)
            self.assertFalse(anchor.pinned())
            behind = repr(sorted(tpm.nv.items()))
            for chain in (mine[1:-2], substituted):
                rc, out, err = self.run_cli("epoch", *chain, "--tpm-index", "0x1500016")
                self.assertEqual((rc, out), (1, ""))
                self.assertIn("records the manifest at epoch 1, not yet the one at its high-water 2", err)
                self.assertIn("restart the node's service", err)
            self.assertEqual(repr(sorted(tpm.nv.items())), behind)                   # nothing was repaired
            self.assertEqual(store.load()["epoch"], 2)                               # the service's load completes the record
            self.assertTrue(anchor.pinned())
            before = repr(sorted(tpm.nv.items()))
            rc, out, err = self.run_cli(*mine)
            self.assertEqual((rc, err), (0, ""))
            self.assertTrue(self.as_json(*mine)[1]["checked_against_tpm"])
            built.assert_called_with("0x1500016")
            for argv in (["epoch", *substituted], ["propose", *substituted, "--old", self.write("o.json", BOTH), "--new", self.write("n.json", NEXT)]):
                with self.subTest(argv[0]):
                    rc, out, err = self.run_cli(*argv, "--tpm-index", "0x1500016")
                    self.assertEqual((rc, out), (1, ""))
                    self.assertIn("CONFLICT: the manifest at epoch 2 is not the one this node's TPM recorded", err)
                    rc, report = self.as_json(*argv, "--tpm-index", "0x1500016")
                    self.assertEqual(rc, 1)
                    self.assertNotIn("checked_against_tpm", report)
                    self.assertNotIn("unsigned_manifest", report)
            self.assertEqual(self.run_cli("epoch", *substituted)[0], 0)          # without the TPM it is believed, and the output says so
            self.assertIn("NOT checked", self.run_cli("epoch", *substituted)[1])
            self.assertEqual(repr(sorted(tpm.nv.items())), before)               # the checks wrote nothing to the TPM
            # the service commits epoch 3 between the command's two readings of the anchor: refused, not a traceback
            m3 = self.under(NEXT, epoch=3, prev=m.digest(self.m2))
            store.commit(rt.sign(m3))
            with mock.patch.object(anchor, "value", return_value=2):     # the first reading, taken before that commit
                rc, out, err = self.run_cli(*mine)
            self.assertEqual((rc, out), (1, ""))
            self.assertIn("TPM high-water moved during the check: run it again", err)
            self.assertNotIn("Traceback", err)

    def test_a_malformed_tpm_index_is_refused_and_never_reaches_the_tpm(self):
        with mock.patch.object(rollout.membership, "HighWater", side_effect=AssertionError("the TPM was reached")):
            for index in ("zz", "1500016", "0x", "0x1500016 ", "0x15000160000", "-0x1"):
                with self.subTest(index=index):
                    argv = ["epoch", *self.on([self.m1]), "--tpm-index=" + index]
                    rc, out, err = self.run_cli(*argv)
                    self.assertEqual((rc, out), (1, ""))
                    self.assertIn("--tpm-index must be an NV index as 0x followed by 1 to 8 hex digits", err)
                    rc, report = self.as_json(*argv)
                    self.assertEqual(rc, 1)
                    self.assertIn("--tpm-index must be", json.dumps(report))


class Propose(Case):
    def args(self, old, new, manifests=None, *extra):
        self.calls = getattr(self, "calls", 0) + 1       # each call its own files: several are built before any is run
        return ["propose", *self.on(manifests or [self.m1]), "--old", self.write("old-%d.json" % self.calls, old),
                "--new", self.write("new-%d.json" % self.calls, new),
                "--issued-at", "2026-11-03T10:00:00Z", *extra]

    def test_the_proposal_is_the_next_manifest_unsigned_and_a_root_signature_makes_it_acceptable(self):
        rc, result = self.as_json(*self.args(CURRENT, BOTH))
        self.assertEqual(rc, 0)
        proposal = result["unsigned_manifest"]
        self.assertEqual(result["transition"], "approve")
        self.assertEqual(proposal, dict(self.m1, epoch=2, prev_digest=m.digest(self.m1), policy_version=measurements.version(BOTH),
                                        issued_at="2026-11-03T10:00:00Z"))
        self.assertNotIn("signature", json.dumps(result).replace("signs_over", ""))
        self.assertEqual(result["follows"]["epoch"], 1)
        # exactly what has to be signed: the root's signature over it is accepted as the next manifest
        self.assertEqual(m.accept(self.m1, rt.sign(proposal), self.root), proposal)
        measurements.bind(proposal, BOTH)
        rc, out, _ = self.run_cli(*self.args(CURRENT, BOTH))
        self.assertTrue(out.startswith("approve: UNSIGNED manifest for the root to sign (nothing here signs)\n{"))
        self.assertEqual(json.loads(out.split("\n", 1)[1]), proposal)

    def test_retire_and_emergency_proposals(self):
        rc, result = self.as_json(*self.args(BOTH, NEXT, [self.m1, self.m2]))
        self.assertEqual((rc, result["transition"], result["unsigned_manifest"]["epoch"]), (0, "retire", 3))
        self.assertEqual(self.as_json(*self.args(CURRENT, NEXT))[0], 1)
        rc, result = self.as_json(*self.args(CURRENT, NEXT, None, "--emergency"))
        self.assertEqual((rc, result["transition"]), (0, "replace-without-overlap"))

    def test_what_is_not_proposed(self):
        for label, argv, reason in (
                ("nothing changes", self.args(CURRENT, dict(CURRENT)), "changes nothing: there is no manifest to propose"),
                ("the old document is not the current one", self.args(BOTH, NEXT), "is not the one the root approved"),
                ("a step that is refused", self.args(CURRENT, NEXT), "would be locked out"),
                ("a date that is not one", self.args(CURRENT, BOTH)[:-1] + ["tomorrow"], "issued_at must be UTC")):
            with self.subTest(label):
                rc, _, err = self.run_cli(*argv)
                self.assertEqual(rc, 1)
                self.assertIn(reason, err)

    def test_no_subcommand_writes_a_file_or_holds_a_signing_key(self):
        argv = self.args(CURRENT, BOTH)
        before = sorted(os.listdir(self.d))
        self.assertEqual(self.run_cli(*argv)[0], 0)
        self.assertEqual(sorted(os.listdir(self.d)), before)
        with open(rollout.__file__) as f:
            source = f.read()
        for word in ("PrivateKey", ".sign(", "private_bytes", "open(path, \"w", "os.replace", "nvincrement", "advance("):
            self.assertNotIn(word, source.split("# ---- the command ----")[1], word)


class Decisions(Case):
    def state(self, **seen):
        return {"schema": attest.STATE_SCHEMA, "nonces": {},
                "nodes": {node: {"measurement": {"label": label, "epoch": 2}} for node, label in seen.items()}}

    def lease(self, node, issuer, **override):
        body = dict(self.body(self.m2), node_id=node, ak_name=self.keys[node].ak_name, issuer=issuer)
        body.update(override)
        return self.write("lease-%s-%s.json" % (node, issuer), lt.sign(body, self.keys[issuer]))

    def reboot(self, node, state, *extra, now=True):
        argv = ["may-reboot", *self.on([self.m1, self.m2]), "--measurements", self.write("doc.json", BOTH), "--node-id", node,
                "--running", "image-1", "--session-id", lt.SESSION, "--attest-state", self.write("state-%s.json" % node, state)]
        for peer in lt.NAMES:
            if peer != node:
                argv += ["--lease", self.lease(node, peer)]
        return argv + (["--now", str(self.now)] if now else []) + list(extra)

    def test_may_reboot_says_yes_to_the_first_node_and_wait_to_the_second(self):
        rc, result = self.as_json(*self.reboot("a", self.state()))
        self.assertEqual(rc, 0)
        self.assertEqual(result, {"ok": True, "command": "may-reboot", "node_id": "a", "target": "image-2", "authorizers": ["b", "c"],
                                  "seconds": 300, "epoch": 2, "checked_against_tpm": False, "time_authenticated": True})
        rc, out, _ = self.run_cli(*self.reboot("a", self.state()))
        self.assertIn("YES: a may reboot into image-2", out)
        self.assertIn("Wait until this host is back and serving before starting the next one", out)
        self.assertIn("NOT checked against this host's TPM epoch counter", out)
        rc, out, err = self.run_cli(*self.reboot("b", self.state()))
        self.assertEqual((rc, out), (1, ""))
        self.assertIn("may-reboot: NO: WAIT: it is not b's turn. a updates first", err)
        self.assertEqual(self.run_cli(*self.reboot("b", self.state(a="image-2")))[0], 0)

    def test_without_now_the_system_clock_is_used_and_the_answer_says_so(self):
        with mock.patch.object(rollout.time, "time", return_value=float(self.now)):
            rc, result = self.as_json(*self.reboot("a", self.state(), now=False))
            self.assertEqual((rc, result["time_authenticated"]), (0, False))
            self.assertIn("TIME IS THE SYSTEM CLOCK, not authenticated", self.run_cli(*self.reboot("a", self.state(), now=False))[1])
        # with the machine's real clock, days later, the same leases have run out
        rc, _, err = self.run_cli(*self.reboot("a", self.state(), now=False))
        self.assertEqual(rc, 1)
        self.assertIn("EXPIRED", err)

    def test_may_reboot_reads_its_files_strictly(self):
        argv = self.reboot("a", self.state())
        at = argv.index("--attest-state") + 1
        argv[at] = self.write("list.json", [1])
        self.assertIn("must hold one JSON object", self.run_cli(*argv)[2])
        argv = self.reboot("a", self.state())
        argv[argv.index("--session-id") + 1] = "nope"
        self.assertIn("session_id must be 64 lowercase hex", self.run_cli(*argv)[2])
        argv = self.reboot("a", self.state())
        argv[argv.index("--measurements") + 1] = self.write("next.json", NEXT)
        self.assertIn("is not the one the root approved", self.run_cli(*argv)[2])

    def retire(self, **states):
        argv = ["retire-ready", *self.on([self.m1, self.m2]), "--measurements", self.write("doc.json", BOTH)]
        for node, seen in states.items():
            argv += ["--state", "%s=%s" % (node, self.write("witness-%s.json" % node, self.state(**seen)))]
        return argv

    def test_retire_ready(self):
        done = dict(a={"b": "image-2", "c": "image-2"}, b={"a": "image-2", "c": "image-2"}, c={"a": "image-2", "b": "image-2"})
        rc, result = self.as_json(*self.retire(**done))
        self.assertEqual((rc, result["ready"], result["seen_on_target_by"]), (0, True, {"a": ["b", "c"], "b": ["a", "c"], "c": ["a", "b"]}))
        self.assertIn("The state files are unsigned", self.run_cli(*self.retire(**done))[1])
        rc, _, err = self.run_cli(*self.retire(**dict(done, b={"a": "image-2", "c": "image-1"})))
        self.assertEqual(rc, 1)
        self.assertIn("retire-ready: NO: NOT YET: retiring now would lock out c (b last saw it on 'image-1'", err)
        self.assertIn("the state of c is missing", self.run_cli(*self.retire(a=done["a"], b=done["b"]))[2])
        argv = self.retire(**done)
        self.assertIn("--state takes NODE=FILE", self.run_cli(*argv[:-1], "nonsense")[2])
        self.assertIn("--state names a twice", self.run_cli(*argv, "--state", argv[argv.index("--state") + 1])[2])

    def test_check_replacement(self):
        keys = dict(self.keys, d=lt.Key(self.keydir, "d", 9))

        def entry(node_id, i, state="ACTIVE"):
            return {"node_id": node_id, "state": state, "ek_name": keys[node_id].ek_name, "ak_name": keys[node_id].ak_name,
                    "wg_boot_pub": ("%02x" % (0x70 + i)) * 32, "wg_service_pub": ("%02x" % (0xa0 + i)) * 32, "hsm_serials": ["DENK04041%02d" % i]}
        with_d = rt.document("v1d", **dict({n: [rt.one("image-1", rt.IMAGE1)] for n in "bc"}, d=[rt.one("image-1", rt.IMAGE1)]))
        candidate = dict(self.m1, epoch=2, prev_digest=m.digest(self.m1), policy_version=measurements.version(with_d),
                         nodes=[entry("a", 0, "RETIRED"), entry("b", 1), entry("c", 2), entry("d", 3)])
        base = ["check-replacement", *self.on([self.m1]), "--old", self.write("old.json", CURRENT), "--old-id", "a", "--new-id", "d"]
        for label, shown in (("bare", candidate), ("in its signed envelope", rt.sign(candidate))):
            with self.subTest(label):
                rc, out, err = self.run_cli(*base, "--new", self.write("new.json", with_d), "--candidate", self.write("cand.json", shown))
                self.assertEqual((rc, err), (0, ""))
                self.assertIn("the candidate replaces a by d and changes nothing else (epoch 2", out)
        sneaks = rt.document("s", b=[rt.one("image-1", rt.IMAGE1)], c=[rt.one("image-1", rt.IMAGE1), rt.one("image-2", rt.IMAGE2)],
                             d=[rt.one("image-1", rt.IMAGE1)])
        rc, _, err = self.run_cli(*base, "--new", self.write("new.json", sneaks),
                                  "--candidate", self.write("cand.json", dict(candidate, policy_version=measurements.version(sneaks))))
        self.assertEqual(rc, 1)
        self.assertIn("a replacement does not change the measurements of c", err)


if __name__ == "__main__":
    unittest.main()
