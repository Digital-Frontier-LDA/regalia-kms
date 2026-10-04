"""deploy/baremetal/manifest.py, regalia-manifest (#156): the membership root's operator proposes, compares,
signs and verifies manifests. The root is ECDSA P-256 on an offline Nitrokey; here the token is the PyKCS11
stand-in of the authority's tests, so the signer is the real authority.Pkcs11Signer (#262)."""
import io
import json
import os
import shutil
import tempfile
import unittest
import unittest.mock

from cryptography.hazmat.primitives import serialization

from deploy.baremetal import attest, authority, manifest as tool, measurements, membership as m
from tests.test_baremetal_authority import FakeToken
from tests.test_baremetal_membership import REVOKE_PUB, manifest, three
import tests.test_baremetal_revocation_keys as tk
import tests.test_baremetal_rollout as rt

SERIAL, LABEL = "DENK0404380", "membership-root"
URI = "pkcs11:serial=%s;token=%s;id=%%51;type=private" % (SERIAL, LABEL)


def point(key):
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.state = os.path.join(self.d, "state")
        os.mkdir(self.state, 0o700)
        self.fake = FakeToken({0: SERIAL}, b"")
        self.fake.labels = {0: LABEL}
        self.fake.point = b"\x04\x41" + point(self.fake.key)
        self.root = {"alg": "ecdsa-p256", "key": point(self.fake.key).hex()}
        first = tk.v3(manifest(1, "", three()))
        self.chain = [{"manifest": first, "signature": {"signer": "root", "key": self.root["key"],
                                                         "sig": tk.sign_p256(self.fake.key, m.DOMAIN + m.canonical(first))}}]
        self.current = m.accept_chain(None, self.chain, self.root)
        self.pin, self.said = "648219", []

    def signer(self, uri=URI, pin=None):
        return tool.token_signer(uri, "/usr/lib/opensc-pkcs11.so", None, pin or (lambda: self.pin),
                                 os.path.join(self.state, tool.LATCH), pkcs11=self.fake)

    def proposal(self, **states):
        return tool.propose_states(self.current, states or {"c": "MAINTENANCE"}, "2026-10-03T12:00:00Z")

    def sign(self, candidate=None, expected=1, role="root", confirm=None, out="e2.json", chain_out=None, open_signer=None, chain=None,
             step=None):
        candidate = candidate or self.proposal()
        confirm = confirm or (lambda prompt: "%d %s" % (candidate["epoch"], m.digest(candidate)[:8]))
        return tool.sign(chain or self.chain, self.root, expected, candidate, role, open_signer or self.signer, confirm,
                         os.path.join(self.d, out), self.state, chain_out and os.path.join(self.d, chain_out), say=self.said.append,
                         step=step)

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def record(self):
        path = os.path.join(self.state, tool.RECORD)
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f]


class Signing(Case):
    def test_the_token_signs_an_envelope_every_node_accepts(self):
        envelope = self.sign()
        self.assertEqual(m.accept(self.current, envelope, self.root)["nodes"][2]["state"], "MAINTENANCE")
        with open(os.path.join(self.d, "e2.json"), "rb") as f:
            self.assertEqual(json.loads(f.read()), envelope)
        self.assertEqual(self.fake.logins, [(0, self.pin)])
        record = self.record()
        self.assertEqual([(r["epoch"], r["signer"], r["token_serial"], r["token_label"]) for r in record], [(2, "root", SERIAL, LABEL)])
        self.assertNotIn(self.pin, json.dumps(record))
        self.assertIn("node c: state: \"ACTIVE\" -> \"MAINTENANCE\"", "\n".join(self.said))

    def test_two_manifests_in_one_session_approve_then_retire(self):
        self.sign(chain_out="chain2.json")
        chain2 = tool.read_json(os.path.join(self.d, "chain2.json"), m.MAX_CHAIN_BYTES)
        second = tool.propose_states(tool.verify_chain(chain2, self.root), {"c": "RETIRED"}, "2026-10-03T12:05:00Z")
        self.sign(second, expected=2, out="e3.json", chain=chain2)
        self.assertEqual(m.accept_chain(None, chain2 + [tool.read_json(os.path.join(self.d, "e3.json"), m.MAX_BYTES)],
                                        self.root)["epoch"], 3)
        self.assertEqual([r["epoch"] for r in self.record()], [2, 3])

    def test_a_revocation_key_on_a_token_signs_a_restrictive_change(self):
        revocation = {"alg": "ecdsa-p256", "key": self.root["key"]}
        other, other_root = tk.p256()
        first = tk.v3(manifest(1, "", three(), keys=[revocation]))
        self.chain = [{"manifest": first, "signature": {"signer": "root", "key": other_root["key"],
                                                         "sig": tk.sign_p256(other, m.DOMAIN + m.canonical(first))}}]
        self.root = other_root
        self.current = m.accept_chain(None, self.chain, self.root)
        envelope = self.sign(self.proposal(c="REVOKED_STOLEN"), role="revocation")
        self.assertEqual(envelope["signature"]["signer"], "revocation")
        self.refused("not the pinned root", self.sign, self.proposal(c="REVOKED_STOLEN"), out="x.json")


class RefusedBeforeTheToken(Case):
    """Steps 1 and 2: nothing a node would refuse reaches the token, and the token is not even opened."""

    def unopened(self):
        return unittest.mock.Mock(side_effect=AssertionError("the token was opened"))

    def test_a_chain_that_does_not_end_at_the_expected_epoch(self):
        for expected in (0, 2):
            self.refused("not the %d expected" % expected, self.sign, expected=expected, open_signer=self.unopened())

    def test_what_transition_refuses(self):
        tampered = self.proposal()
        tampered["nodes"] = tampered["nodes"][:2]                                   # a node removed, not retired
        self.refused("cannot be removed", self.sign, tampered, open_signer=self.unopened())
        policy = dict(self.proposal(), policy_version="p2")
        self.refused("cannot change the policy version", self.sign, policy, role="revocation", open_signer=self.unopened())

    def test_a_proposal_that_is_not_schema_v3(self):
        v2 = dict(self.proposal(), schema=m.SCHEMA_V2)
        self.refused("signs only schema regalia.membership/v3", self.sign, v2, open_signer=self.unopened())

    def test_an_existing_output_is_never_replaced(self):
        open(os.path.join(self.d, "e2.json"), "w").close()
        self.refused("nothing is overwritten", self.sign, open_signer=self.unopened())


class RefusedBeforeThePin(Case):
    """Steps 3 to 5: the PIN reaches only the pinned root's token, and only after the operator confirmed."""

    def test_a_key_that_is_not_the_pinned_root(self):
        _, self.fake_root = tk.p256()
        other_key, other = tk.p256()
        first = tk.v3(manifest(1, "", three()))
        self.chain = [{"manifest": first, "signature": {"signer": "root", "key": other["key"],
                                                         "sig": tk.sign_p256(other_key, m.DOMAIN + m.canonical(first))}}]
        self.root = other
        self.refused("is not the pinned root", self.sign)
        self.assertEqual(self.fake.logins, [])

    def test_a_confirmation_that_does_not_match_signs_nothing(self):
        for typed in ("2", "2 00000000", "3 " + m.digest(self.proposal())[:8], ""):
            with self.subTest(typed=typed):
                self.refused("does not match", self.sign, confirm=lambda prompt: typed)
        self.assertEqual((self.fake.logins, self.record()), ([], []))
        self.assertNotIn("sign", self.fake.calls)

    def test_two_tokens_attached(self):
        self.fake.serials, self.fake.labels = {0: SERIAL, 1: "DENK0404547"}, {0: LABEL, 1: "other"}
        self.refused("2 initialised tokens are attached", self.sign)
        self.assertEqual(self.fake.logins, [])

    def test_an_uninitialised_slot_beside_the_token_is_not_counted(self):
        self.fake.serials, self.fake.labels = {0: SERIAL, 1: ""}, {0: LABEL}
        original = self.fake.PyKCS11Lib.getTokenInfo

        def info(lib, slot):
            got = original(lib, slot)
            if slot == 1:
                got.flags = 0                                                       # not CKF_TOKEN_INITIALIZED
            return got
        with unittest.mock.patch.object(self.fake.PyKCS11Lib, "getTokenInfo", info):
            self.sign()
        self.assertEqual(self.fake.logins, [(0, self.pin)])

    def test_the_token_label_is_asserted_beside_the_serial(self):
        self.fake.labels = {0: "revocation"}
        self.refused("no token with serial %s and label %r" % (SERIAL, LABEL), self.sign)
        self.assertEqual(self.fake.logins, [])

    def test_a_label_swapped_after_the_listing_never_gets_the_pin(self):
        original = self.fake.PyKCS11Lib.openSession

        def relabel(lib, slot):
            self.fake.labels[slot] = "swapped"
            return original(lib, slot)
        with unittest.mock.patch.object(self.fake.PyKCS11Lib, "openSession", relabel):
            self.refused("refused before the PIN", self.sign)
        self.assertEqual(self.fake.logins, [])

    def test_a_key_label_two_keys_share_is_refused(self):
        self.fake.objects = [{"class": "public", "label": "root"}, {"class": "public", "label": "root"}]
        uri = "pkcs11:serial=%s;token=%s;object=root;type=private" % (SERIAL, LABEL)
        self.refused("2 objects", self.signer, uri)

    def test_a_uri_that_does_not_name_the_card_and_the_key(self):
        for uri, reason in (("pkcs11:serial=%s;id=%%51;type=private" % SERIAL, "serial= and token="),
                            ("pkcs11:serial=%s;token=%s;type=private" % (SERIAL, LABEL), "object= or id="),
                            ("pkcs11:serial=%s;token=%s;id=%%51" % (SERIAL, LABEL), "type=private"),
                            (URI + ";pin-value=1234", "not one of"),
                            (URI + "?pin-value=1234", "query part")):
            with self.subTest(uri=uri):
                self.refused(reason, self.signer, uri)


class Pin(Case):
    def test_a_refused_pin_latches_and_is_never_presented_again(self):
        self.fake.login_error = FakeToken.CKR_PIN_INCORRECT
        self.refused("latched", self.sign)
        self.refused("latched", self.sign)                                          # a second run: no login at all
        self.assertEqual(len(self.fake.logins), 1)
        self.assertTrue(os.path.exists(os.path.join(self.state, tool.LATCH)))
        self.fake.login_error = None
        with unittest.mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(tool.main(["clear-pin-latch", "--state-dir", self.state]), 0)
        self.sign()
        self.assertEqual(len(self.fake.logins), 2)

    def test_a_token_with_its_last_tries_is_refused_before_any_login(self):
        self.fake.flags |= FakeToken.CKF_USER_PIN_FINAL_TRY
        self.refused("last tries are kept", self.sign)
        self.assertEqual(self.fake.logins, [])

    def test_the_pin_comes_from_the_named_variable_once_and_leaves_the_environment(self):
        with unittest.mock.patch.dict(os.environ, {"ROOT_PIN": self.pin, tool.TEST_SWITCH: "1"}):
            reader = tool._pin_reader("ROOT_PIN")
            self.assertNotIn("ROOT_PIN", os.environ)
            self.refused("not set", tool._pin_reader, "ROOT_PIN")
            self.refused("names an environment variable", tool._pin_reader, "root pin")
        self.assertEqual(reader(), self.pin)

    def test_a_pin_from_the_environment_is_refused_outside_a_test_before_any_token_is_opened(self):
        """regalia-kms-24's decision: at a ceremony the root PIN is typed at the console."""
        chain = os.path.join(self.d, "chain.json")
        with open(chain, "w") as f:
            json.dump(self.chain, f)
        proposal = os.path.join(self.d, "p.json")
        with open(proposal, "w") as f:
            json.dump(self.proposal(), f)
        err = io.StringIO()
        with unittest.mock.patch.dict(os.environ, {"ROOT_PIN": self.pin}), unittest.mock.patch("sys.stderr", err), \
                unittest.mock.patch.object(tool, "token_signer", side_effect=AssertionError("a token was opened")):
            os.environ.pop(tool.TEST_SWITCH, None)
            code = tool.main(["sign", "--chain", chain, "--root-key", json.dumps(self.root), "--expected-epoch", "1",
                              "--proposal", proposal, "--signer", "root", "--key", URI, "--module", "/usr/lib/opensc-pkcs11.so",
                              "--pin-env", "ROOT_PIN", "--state-dir", self.state, "--out", os.path.join(self.d, "e2.json")])
            self.assertEqual(os.environ.get("ROOT_PIN"), self.pin)            # not even read
        self.assertEqual(code, 2)
        self.assertIn("typed at the console", err.getvalue())
        self.assertEqual(self.record(), [])

    def test_the_record_says_where_the_pin_came_from(self):
        self.sign()
        self.assertEqual(self.record()[0]["pin_source"], "terminal")

    def test_a_pin_that_is_not_a_pin_never_reaches_the_token(self):
        self.refused("not a PIN", self.sign, open_signer=lambda: self.signer(pin=lambda: "12 34"))
        self.assertEqual(self.fake.logins, [])

    def test_the_command_takes_no_pin_argument(self):
        with self.assertRaises(SystemExit), unittest.mock.patch("sys.stderr", io.StringIO()):
            tool.main(["sign", "--pin", "648219"])

    def test_no_backend_signs_with_a_key_file(self):
        self.assertFalse([a for a in dir(tool) if "file" in a.lower() and "signer" in a.lower()])
        self.assertIn("pkcs11", tool.token_signer.__code__.co_names + tool.token_signer.__code__.co_varnames)


class Writing(Case):
    def test_a_write_that_fails_part_way_leaves_no_file(self):
        path, real, calls = os.path.join(self.d, "e2.json"), os.write, []

        def short(fd, data):                     # ten bytes land, then the disk is full
            calls.append(1)
            if len(calls) > 1:
                raise OSError(28, "No space left on device")
            return real(fd, bytes(data[:10]))
        with unittest.mock.patch("os.write", short), self.assertRaises(OSError):
            tool._write_new(path, b"x" * 100)
        self.assertFalse(os.path.exists(path))

    def test_short_writes_are_finished(self):
        path = os.path.join(self.d, "e2.json")
        real = os.write
        with unittest.mock.patch("os.write", lambda fd, data: real(fd, bytes(data[:7]))):
            tool._write_new(path, b"y" * 100)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), b"y" * 100)


class Proposing(Case):
    def test_a_state_change_chains_to_the_current_manifest(self):
        candidate = self.proposal()
        self.assertEqual((candidate["epoch"], candidate["prev_digest"]), (2, m.digest(self.current)))
        self.refused("is not a node", tool.propose_states, self.current, {"z": "ACTIVE"}, "2026-10-03T12:00:00Z")
        self.refused("not a state", tool.propose_states, self.current, {"c": "ASLEEP"}, "2026-10-03T12:00:00Z")
        self.refused("already ACTIVE", tool.propose_states, self.current, {"c": "ACTIVE"}, "2026-10-03T12:00:00Z")

    def test_rollout_s_proposal_is_taken_as_it_is_if_it_follows_this_chain(self):
        candidate = self.proposal()
        self.assertEqual(tool.propose_from_rollout(self.current, {"unsigned_manifest": candidate}), candidate)
        self.refused("does not follow", tool.propose_from_rollout, self.current, {"unsigned_manifest": dict(candidate, epoch=3)})
        self.refused("not the output", tool.propose_from_rollout, self.current, candidate)

    def test_the_diff_names_every_change(self):
        candidate = self.proposal(c="MAINTENANCE")
        candidate["policy_version"] = "p2"
        candidate["revocation_keys"] = []
        lines = tool.diff(self.current, candidate)
        for expected in ('epoch: 1 -> 2', 'policy_version: "p1" -> "p2"', 'revocation_keys: ["%s"] -> []' % REVOKE_PUB,
                         'node c: state: "ACTIVE" -> "MAINTENANCE"', "issued_at"):
            self.assertTrue([line for line in lines if expected in line], expected)



class MeasurementStep(Case):
    """#75: a proposal that changes the measurements is judged by this tool from the documents and the peers'
    state files, at propose and again at sign, never from the proposal's own word (the owner's rule: the
    signing path checks for itself)."""
    def setUp(self):
        super().setUp()
        self.under(rt.BOTH)

    def under(self, doc, **states):
        """Re-root the chain at a first manifest that commits to `doc` (node states as given)."""
        first = dict(tk.v3(manifest(1, "", three(**states))), policy_version=measurements.version(doc))
        self.chain = [{"manifest": first, "signature": {"signer": "root", "key": self.root["key"],
                                                         "sig": tk.sign_p256(self.fake.key, m.DOMAIN + m.canonical(first))}}]
        self.current = m.accept_chain(None, self.chain, self.root)

    def to(self, doc):
        return dict(self.current, epoch=2, prev_digest=m.digest(self.current), policy_version=measurements.version(doc),
                    issued_at="2026-10-03T12:00:00Z")

    @staticmethod
    def states(**by_peer):
        return {peer: {"schema": attest.STATE_SCHEMA, "nonces": {}, "nodes": {
            n: {"measurement": {"label": label, "epoch": 1}} for n, label in seen.items()}} for peer, seen in by_peer.items()}

    def everyone_on(self, label, peers="abc"):
        return self.states(**{p: {n: label for n in "abc" if n != p} for p in peers})

    def lagging(self):
        return self.states(a={"b": "image-2", "c": "image-1"}, b={"a": "image-2", "c": "image-1"}, c={"a": "image-2", "b": "image-2"})

    def step(self, old=rt.BOTH, new=rt.NEXT, states=None, emergency=False, locked_out=()):
        return {"old": old, "new": new, "states": states if states is not None else self.everyone_on("image-2"),
                "emergency": emergency, "locked_out": list(locked_out)}

    def test_a_measurements_change_is_not_signed_without_the_documents(self):
        self.refused("the proposal changes the measurements (policy_version", self.sign, self.to(rt.NEXT))
        self.assertNotIn("sign", self.fake.calls)

    def test_a_retire_is_signed_once_every_node_is_on_next(self):
        self.sign(self.to(rt.NEXT), step=self.step())
        self.assertIn("measurements: retire", self.said)

    def test_a_retire_that_locks_out_a_node_still_on_current_is_refused_at_the_signing_tool(self):
        self.refused("NOT YET: this retire would lock out c", self.sign, self.to(rt.NEXT), step=self.step(states=self.lagging()))
        self.refused("this retire locks out c", self.sign, self.to(rt.NEXT), step=self.step(states=self.lagging(), emergency=True))
        self.refused("the state of b is missing", self.sign, self.to(rt.NEXT), step=self.step(states=self.everyone_on("image-2", "ac")))
        self.refused("is not the one the root approved", self.sign, self.to(rt.NEXT), step=self.step(old=rt.CURRENT))
        self.refused("is not the one the root approved", self.sign, self.to(rt.NEXT), step=self.step(new=rt.CURRENT))
        self.assertNotIn("sign", self.fake.calls)
        self.sign(self.to(rt.NEXT), step=self.step(states=self.lagging(), emergency=True, locked_out=["c"]))
        self.assertTrue(any("LOCKS OUT c" in line for line in self.said), self.said)

    def test_a_node_that_neither_unlocks_nor_serves_must_be_named_and_needs_no_emergency(self):
        self.under(rt.BOTH, c="QUARANTINED")
        on_next = self.states(a={"b": "image-2"}, b={"a": "image-2"})
        self.refused("this retire locks out c (it may neither be unlocked nor serve under epoch 1", self.sign, self.to(rt.NEXT),
                     step=self.step(states=on_next))
        self.sign(self.to(rt.NEXT), step=self.step(states=on_next, locked_out=["c"]))

    def test_a_proposal_that_keeps_the_measurements_reads_no_documents(self):
        self.refused("policy_version unchanged", self.sign, self.proposal(), step=self.step())

    def test_rollout_s_output_is_recomputed_and_an_edited_one_is_refused(self):
        candidate = self.to(rt.NEXT)
        honest = {"transition": "retire", "unsigned_manifest": candidate, "emergency": False, "locked_out": []}
        just_docs = {"old": rt.BOTH, "new": rt.NEXT, "states": self.everyone_on("image-2")}
        self.assertEqual(tool.propose_from_rollout(self.current, honest, just_docs), candidate)
        self.refused("give --old, --new and --state", tool.propose_from_rollout, self.current, honest)
        self.refused("the proposal says 'approve', but the documents make it 'retire'", tool.propose_from_rollout, self.current,
                     dict(honest, transition="approve"), just_docs)
        self.refused("the proposal says it locks out None", tool.propose_from_rollout, self.current,
                     {k: v for k, v in honest.items() if k != "locked_out"}, just_docs)
        lag = dict(just_docs, states=self.lagging())
        self.refused("NOT YET: this retire would lock out c", tool.propose_from_rollout, self.current, honest, lag)
        # an emergency whose list was emptied, or that names one node too many
        self.refused("this retire locks out c", tool.propose_from_rollout, self.current, dict(honest, emergency=True), lag)
        self.refused("--locked-out names b, which this document does not lock out", tool.propose_from_rollout, self.current,
                     dict(honest, emergency=True, locked_out=["b", "c"]), lag)
        self.assertEqual(tool.propose_from_rollout(self.current, dict(honest, emergency=True, locked_out=["c"]), lag), candidate)

class Command(Case):
    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch("sys.stdout", out), unittest.mock.patch("sys.stderr", err):
            code = tool.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_verify_propose_and_diff(self):
        chain = os.path.join(self.d, "chain.json")
        with open(chain, "w") as f:
            json.dump(self.chain, f)
        root = json.dumps(self.root)
        code, out, _ = self.run_main("verify", "--chain", chain, "--root-key", root)
        self.assertEqual(code, 0)
        self.assertIn("epoch 1", out)
        proposal = os.path.join(self.d, "p.json")
        code, out, _ = self.run_main("propose", "--chain", chain, "--root-key", root, "--set-state", "c=MAINTENANCE",
                                     "--issued-at", "2026-10-03T12:00:00Z", "--out", proposal)
        self.assertEqual(code, 0)
        self.assertIn("UNSIGNED epoch 2", out)
        code, out, _ = self.run_main("diff", "--chain", chain, "--root-key", root, "--proposal", proposal)
        self.assertIn('node c: state: "ACTIVE" -> "MAINTENANCE"', out)
        code, _, err = self.run_main("propose", "--chain", chain, "--root-key", root, "--set-state", "c=ACTIVE", "--out", proposal)
        self.assertEqual(code, 2)
        self.assertIn("refused", err)

    def test_a_chain_from_another_root_is_refused(self):
        chain = os.path.join(self.d, "chain.json")
        with open(chain, "w") as f:
            json.dump(self.chain, f)
        code, _, err = self.run_main("verify", "--chain", chain, "--root-key", json.dumps(tk.p256()[1]))
        self.assertEqual(code, 2)
        self.assertIn("not the pinned root", err)

    def test_a_state_dir_others_can_read_is_refused(self):
        os.chmod(self.state, 0o755)
        code, _, err = self.run_main("clear-pin-latch", "--state-dir", self.state)
        self.assertEqual(code, 2)
        self.assertIn("mode 0700", err)


CARD_CHAIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors", "root-card-chain-v3.json")


def card_chain():
    """The vector's chain and root as the code reads them (public keys are composed in the file; see its "about")."""
    with open(CARD_CHAIN) as f:
        text = f.read()
    doc = json.loads(text)

    def entry(e):
        return {"alg": e["alg"], "key": e["public"]} if isinstance(e, dict) else e
    chain = []
    for env in doc["chain"]:
        manifest_ = dict(env["manifest"], revocation_keys=[entry(k) for k in env["manifest"]["revocation_keys"]])
        chain.append({"manifest": manifest_, "signature": dict(env["signature"], key=env["signature_public"])})
    return text, doc, chain, entry(doc["root_public"])


class CardMadeChain(unittest.TestCase):
    """A chain signed on a real Nitrokey (DENK0404380, 2026-10-03; tests/vectors/root-card-chain-v3.json), for
    every verifier: here membership.py, and the initrd's Go reader (#293) reads the same file."""

    def test_the_card_signed_chain_is_accepted_and_any_change_refused(self):
        text, doc, chain, root = card_chain()
        self.assertNotIn('"key"', text)                                  # composed: nothing the scanner reads as a credential
        self.assertEqual(m.accept_chain(None, chain, root)["epoch"], doc["expected_epoch"])
        for i in range(len(chain)):
            flipped = json.loads(json.dumps(chain))
            sig = bytearray.fromhex(flipped[i]["signature"]["sig"])
            sig[40] ^= 1
            flipped[i]["signature"]["sig"] = sig.hex()
            high = json.loads(json.dumps(chain))
            raw = bytes.fromhex(high[i]["signature"]["sig"])
            s_ = m.P256_ORDER - int.from_bytes(raw[32:], "big")
            high[i]["signature"]["sig"] = (raw[:32] + s_.to_bytes(32, "big")).hex()
            for name, bad in (("a flipped byte", flipped), ("the high-S twin", high)):
                with self.subTest(envelope=i, change=name), self.assertRaises(m.Refused):
                    m.accept_chain(None, bad, root)

    def test_the_tool_verifies_it(self):
        _, _, chain, root = card_chain()
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        with open(os.path.join(d, "chain.json"), "w") as f:
            json.dump(chain, f)
        out = io.StringIO()
        with unittest.mock.patch("sys.stdout", out):
            self.assertEqual(tool.main(["verify", "--chain", os.path.join(d, "chain.json"), "--root-key", json.dumps(root)]), 0)
        self.assertIn("epoch 2", out.getvalue())


class OnSoftHsm(unittest.TestCase):
    """The same PKCS#11 calls the Nitrokey gets, through SoftHSM: the token label, the key found by CKA_LABEL,
    and a root signature a node accepts (skipped where PyKCS11 or SoftHSM is missing, required in CI)."""
    setUp = __import__("tests.test_baremetal_authority", fromlist=["Pkcs11"]).Pkcs11.setUp

    def test_the_root_on_a_token_signs_a_manifest_nodes_accept(self):
        state = os.path.join(self.d, "state")
        os.mkdir(state, 0o700)
        uri = "pkcs11:serial=%s;token=revocation;object=revocation;type=private" % self.serial
        from tests.test_baremetal_authority import SOFTHSM
        signer = tool.token_signer(uri, SOFTHSM, None, lambda: self.pin, os.path.join(state, tool.LATCH))
        root = {"alg": "ecdsa-p256", "key": signer.public()}
        first = tk.v3(manifest(1, "", three()))
        chain = [{"manifest": first, "signature": {"signer": "root", "key": root["key"],
                                                   "sig": signer.sign(m.DOMAIN + m.canonical(first)).hex()}}]
        current = m.accept_chain(None, chain, root)
        candidate = tool.propose_states(current, {"c": "MAINTENANCE"}, "2026-10-03T12:00:00Z")
        envelope = tool.sign(chain, root, 1, candidate, "root", lambda: signer,
                             lambda prompt: "2 %s" % m.digest(candidate)[:8], os.path.join(self.d, "e2.json"), state, say=lambda line: None)
        self.assertEqual(m.accept(current, envelope, root)["epoch"], 2)
        with self.assertRaises(m.Refused):
            tool.token_signer(uri.replace("token=revocation", "token=other"), SOFTHSM, None, lambda: self.pin, None)


if __name__ == "__main__":
    unittest.main()
