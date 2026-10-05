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


def marked(state, root):
    """The ceremony laptop's state directory as the card ceremony, run first, leaves it: its marker naming the root (#403)."""
    from deploy.baremetal import cardrecord
    key = m.root_entries(root)[0][1]
    path = os.path.join(state, cardrecord.SIGNING_STATE)
    with open(path, "w") as f:
        json.dump({"schema": cardrecord.SIGNING_STATE_SCHEMA, "root": key}, f)
    os.chmod(path, 0o600)
    return state


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
        marked(self.state, self.root)
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
        self.assertEqual([(r["epoch"], r["signer"], r["token_serial"], r["token_label"], r["verified"], r["reason"]) for r in record],
                         [(2, "root", SERIAL, LABEL, True, "")])
        self.assertNotIn(self.pin, json.dumps(record))
        self.assertIn("node c: state: \"ACTIVE\" -> \"MAINTENANCE\"", "\n".join(self.said))

    def bad_signer(self, how):
        """The real token signer, whose signatures are then spoiled: a token that misbehaves, or another key."""
        real = self.signer()

        class Spoiled:
            serial, label = real.serial, real.label

            def public(self):
                return real.public()

            def sign(self, message):
                return how(real.sign(message))
        return lambda: Spoiled()

    def test_a_signature_that_does_not_verify_is_recorded_and_nothing_is_written(self):
        """regalia-kms-95 and 3e on #156: every use of the root key is on the record, the digest it was asked to sign
        included, even when the signature then fails verification; and such a signature never leaves the tool."""
        candidate = self.proposal()
        flip = lambda sig: sig[:-1] + bytes([sig[-1] ^ 1])
        self.refused("does not verify", self.sign, candidate, open_signer=self.bad_signer(flip))
        record = self.record()
        self.assertEqual([(r["epoch"], r["digest"], r["verified"]) for r in record], [(2, m.digest(candidate), False)])
        self.assertIn("does not verify", record[0]["reason"])
        self.assertFalse(os.path.exists(os.path.join(self.d, "e2.json")))
        self.assertIn("sign", self.fake.calls)                                  # the token did sign: that is why it is recorded

    def test_a_bad_signature_that_cannot_be_recorded_names_both(self):
        flip = lambda sig: sig[:-1] + bytes([sig[-1] ^ 1])
        with unittest.mock.patch.object(tool, "_append_record", side_effect=OSError(28, "No space left on device")):
            self.refused("the token's signature did not verify (", self.sign, self.proposal(), open_signer=self.bad_signer(flip))
            self.refused("AND it could not be recorded ([Errno 28] No space left on device)", self.sign, self.proposal(),
                         open_signer=self.bad_signer(flip), out="e2b.json")
        self.assertFalse(os.path.exists(os.path.join(self.d, "e2.json")))

    def test_an_unrecorded_signature_never_leaves_the_tool(self):
        """95's ask: if the record line cannot be written, the envelope is not written either, and it is a refusal."""
        with unittest.mock.patch.object(tool, "_append_record", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                self.sign()
        self.assertFalse(os.path.exists(os.path.join(self.d, "e2.json")))

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


class OfflineRoot(unittest.TestCase):
    """ADR-0002 D28: the root is an Ed25519 software key, reconstructed by regalia-ceremony's offline-keys.py and
    handed down on a sealed memfd (`--key-fd`), never a file on disk. Every step of `sign` runs as for a token."""

    SESSION = "0123456789abcdef0123456789abcdef"

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.state = os.path.join(self.d, "state")
        os.mkdir(self.state, 0o700)
        self.key = Ed25519PrivateKey.generate()
        self.root = self.raw(self.key).hex()
        marked(self.state, self.root)
        first = manifest(1, "", three())
        self.chain = [{"manifest": first, "signature": {"signer": "root", "key": self.root,
                                                         "sig": self.key.sign(m.DOMAIN + m.canonical(first)).hex()}}]
        self.current = m.accept_chain(None, self.chain, self.root)
        self.paths = {name: os.path.join(self.d, name) for name in ("chain.json", "p.json", "e2.json")}
        with open(self.paths["chain.json"], "w") as f:
            json.dump(self.chain, f)
        self.candidate = tool.propose_states(self.current, {"c": "MAINTENANCE"}, "2026-10-04T12:00:00Z")
        with open(self.paths["p.json"], "w") as f:
            json.dump(self.candidate, f)
        self.typed = "%d %s" % (self.candidate["epoch"], m.digest(self.candidate)[:8])

    @staticmethod
    def raw(key):
        return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @staticmethod
    def pem(key):
        return bytearray(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def memfd(self, key=None):
        """The key as offline-keys.py passes it: a sealed memfd."""
        from deploy.baremetal import keyfd
        return keyfd.sealed_memfd(self.pem(key or self.key))

    def run_sign(self, *extra, fd=None, typed=None, signer="root"):
        fd = self.memfd() if fd is None else fd
        args = ["sign", "--chain", self.paths["chain.json"], "--root-key", self.root, "--expected-epoch", "1",
                "--proposal", self.paths["p.json"], "--signer", signer, "--state-dir", self.state, "--out", self.paths["e2.json"],
                "--key-fd", str(fd), "--offline-session", self.SESSION] + list(extra)
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch("sys.stdout", out), unittest.mock.patch("sys.stderr", err), \
                unittest.mock.patch.object(tool.keyfd, "tty_line", lambda prompt: self.typed if typed is None else typed):
            code = tool.main(args)
        return code, err.getvalue()

    def record(self):
        path = os.path.join(self.state, tool.RECORD)
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f]

    def test_a_valid_session_signs_and_the_record_names_it(self):
        code, err = self.run_sign()
        self.assertEqual(code, 0, err)
        with open(self.paths["e2.json"]) as f:
            envelope = json.load(f)
        self.assertEqual(m.accept(self.current, envelope, self.root)["epoch"], 2)
        line = self.record()[-1]
        self.assertEqual((line["provenance"], line["verified"], line["key"]), ("offline-keys session " + self.SESSION, True, self.root))
        self.assertEqual(line["pin_source"], "none (offline key)")
        self.assertNotIn("PRIVATE", json.dumps(line))

    def test_a_later_epoch_is_signed_only_on_the_root_s_signing_state(self):
        """#403: a later epoch too: a directory without the root's marker signs nothing."""
        from deploy.baremetal import cardrecord
        os.unlink(os.path.join(self.state, cardrecord.SIGNING_STATE))
        code, err = self.run_sign()
        self.assertEqual(code, 2)
        self.assertIn("has no regalia-signing-state.json: it is not the root's signing state", err)
        self.assertEqual((self.record(), os.path.exists(self.paths["e2.json"])), ([], False))

    def test_a_key_that_is_not_the_pinned_root_is_refused_before_anything_is_signed(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        code, err = self.run_sign(fd=self.memfd(Ed25519PrivateKey.generate()))
        self.assertEqual(code, 2)
        self.assertIn("is not the pinned root", err)
        self.assertFalse(os.path.exists(self.paths["e2.json"]))
        self.assertEqual(self.record(), [])                         # nothing was signed, so nothing to record

    def test_a_key_on_disk_is_refused(self):
        path = os.path.join(self.d, "root.pem")
        with open(path, "wb") as f:
            f.write(self.pem(self.key))
        fd = os.open(path, os.O_RDONLY)
        code, err = self.run_sign(fd=fd)
        self.assertEqual(code, 2)
        self.assertIn("a key is never read from a file on disk", err)
        self.assertFalse(os.path.exists(self.paths["e2.json"]))
        with self.assertRaises(OSError):
            os.fstat(fd)                                             # closed all the same
        with self.assertRaises(SystemExit), unittest.mock.patch("sys.stderr", io.StringIO()):
            tool.main(["sign", "--chain", self.paths["chain.json"], "--root-key", self.root, "--expected-epoch", "1",
                       "--proposal", self.paths["p.json"], "--signer", "root", "--state-dir", self.state, "--out", self.paths["e2.json"],
                       "--key-fd", path, "--offline-session", self.SESSION])          # a path is not a descriptor

    def test_an_unsealed_memfd_is_refused_and_a_pipe_is_taken(self):
        fd = os.memfd_create("k", os.MFD_CLOEXEC)
        os.write(fd, self.pem(self.key))
        os.lseek(fd, 0, os.SEEK_SET)
        code, err = self.run_sign(fd=fd)
        self.assertEqual(code, 2)
        self.assertIn("not sealed against writing", err)
        r, w = os.pipe()
        os.write(w, self.pem(self.key))
        os.close(w)
        code, err = self.run_sign(fd=r)
        self.assertEqual(code, 0, err)

    def test_the_buffer_is_zeroed_once_the_key_is_loaded(self):
        seen = []
        real = tool.keyfd.read

        def kept(fd, what):
            seen.append(real(fd, what))
            return seen[-1]
        with unittest.mock.patch.object(tool.keyfd, "read", kept):
            code, err = self.run_sign()
        self.assertEqual(code, 0, err)
        self.assertTrue(seen and not any(seen[0]), "the key's buffer still holds the key")

    def test_every_other_step_still_runs(self):
        code, err = self.run_sign(typed="2 00000000")
        self.assertEqual(code, 2)
        self.assertIn("the confirmation does not match: nothing was signed", err)
        self.assertEqual(self.record(), [])
        code, err = self.run_sign("--expected-epoch", "2")[0], None
        self.assertEqual(code, 2)                                    # the chain ends at 1, not the epoch the operator said

    def test_the_offline_path_takes_nothing_of_a_token_and_only_the_root(self):
        for extra, reason in ((("--module", "/usr/lib/opensc-pkcs11.so"), "is not given with --key, --module"),
                              (("--key", URI), "is not given with --key, --module")):
            with self.subTest(reason):
                code, err = self.run_sign(*extra)
                self.assertEqual(code, 2)
                self.assertIn(reason, err)
        code, err = self.run_sign(signer="revocation")
        self.assertIn("a revocation key signs on its token", err)
        args = ["sign", "--chain", self.paths["chain.json"], "--root-key", self.root, "--expected-epoch", "1", "--proposal", self.paths["p.json"],
                "--signer", "root", "--state-dir", self.state, "--out", self.paths["e2.json"], "--key-fd", str(self.memfd())]
        for session, reason in ((None, "--offline-session is 32 lowercase hex"), ("ABC", "--offline-session is 32 lowercase hex")):
            err = io.StringIO()
            with unittest.mock.patch("sys.stderr", err):
                self.assertEqual(tool.main(args + ([] if session is None else ["--offline-session", session])), 2)
            self.assertIn(reason, err.getvalue())

    def test_the_confirmation_needs_a_terminal(self):
        from deploy.baremetal import keyfd
        import errno

        def no_tty(path, flags, *a):
            raise OSError(errno.ENXIO, "No such device or address")
        with unittest.mock.patch.object(keyfd.os, "open", no_tty):
            with self.assertRaises(m.Refused) as caught:
                keyfd.tty_line("type: ")
        self.assertIn("no controlling terminal", str(caught.exception))


class Genesis(unittest.TestCase):
    """The first ceremony (`sign --genesis`, ADR-0002 D28): epoch 1 signed by the offline root with no chain before it.
    At this one moment the pin vouches for itself, so the operator types the root key's full SHA-256 fingerprint from
    the ceremony record (regalia-kms-24, regalia-kms-51)."""

    SESSION = "00112233445566778899aabbccddeeff"

    def setUp(self):
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from tests.test_baremetal_membership_v4 import manifest4, nodes4
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.state = os.path.join(self.d, "state")
        os.mkdir(self.state, 0o700)
        self.key = Ed25519PrivateKey.generate()
        self.root = OfflineRoot.raw(self.key).hex()
        marked(self.state, self.root)
        self.fingerprint = hashlib.sha256(bytes.fromhex(self.root)).hexdigest()
        self.manifest4, self.nodes4 = manifest4, nodes4
        self.first = manifest4(1, "", nodes4())
        self.paths = {n: os.path.join(self.d, n) for n in ("p.json", "e1.json", "chain.json")}
        self.write(self.first)

    def write(self, proposal):
        with open(self.paths["p.json"], "w") as f:
            json.dump(proposal, f)

    def run_genesis(self, *extra, key=None, typed=None, fd=None):
        from deploy.baremetal import keyfd
        fd = keyfd.sealed_memfd(OfflineRoot.pem(key or self.key)) if fd is None else fd
        answers = list(typed if typed is not None else [self.fingerprint, "1 %s" % m.digest(self.first)[:8]])
        asked = []
        args = ["sign", "--genesis", "--root-key", self.root, "--proposal", self.paths["p.json"], "--signer", "root",
                "--key-fd", str(fd), "--offline-session", self.SESSION, "--state-dir", self.state, "--out", self.paths["e1.json"]] + list(extra)
        out, err = io.StringIO(), io.StringIO()

        def tty(prompt):
            asked.append(prompt)
            return answers.pop(0) if answers else ""
        with unittest.mock.patch("sys.stdout", out), unittest.mock.patch("sys.stderr", err), \
                unittest.mock.patch.object(tool.keyfd, "tty_line", tty):
            code = tool.main(args)
        self.asked, self.out = asked, out.getvalue()
        return code, err.getvalue()

    def record(self):
        path = os.path.join(self.state, tool.RECORD)
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(line) for line in f]

    def test_the_state_dir_must_be_the_root_s_signing_state(self):
        """#403, regalia-kms-d9's reads of #408: one log of the root's uses. A directory without the marker, or another
        root's, signs nothing, and this tool never makes one: the card ceremony, run first, does."""
        from deploy.baremetal import cardrecord
        self.write(self.first)
        marker = os.path.join(self.state, cardrecord.SIGNING_STATE)
        os.unlink(marker)
        code, err = self.run_genesis()
        self.assertEqual(code, 2)
        self.assertIn("has no regalia-signing-state.json: it is not the root's signing state", err)
        self.assertEqual((self.record(), os.path.exists(self.paths["e1.json"]), os.path.exists(marker)), ([], False, False))
        marked(self.state, "9b" * 32)
        code, err = self.run_genesis()
        self.assertIn("is another root's signing state: nothing is signed", err)
        self.assertEqual((self.record(), os.path.exists(self.paths["e1.json"])), ([], False))

    def test_there_is_no_way_to_start_a_signing_state_here(self):
        """d9: --new-state-dir was a second-log hatch (the proposal was already made against the marked directory); gone."""
        self.write(self.first)
        with unittest.mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            self.run_genesis("--new-state-dir")
        self.assertFalse(os.path.exists(self.paths["e1.json"]))

    def test_the_genesis_signs_on_the_state_the_card_ceremony_left(self):
        """regalia-kms-51 on #408: at the first ceremony the card ceremony runs first, so the genesis meets the marker and
        card-record line 1, and signs there; the card reader then takes the whole log."""
        from deploy.baremetal import cardrecord
        self.write(self.first)
        line = {"kind": "card-record", "sequence": 1, "digest": "cd" * 32, "key": self.root, "at": "2026-10-04T10:00:00Z"}
        with open(os.path.join(self.state, tool.RECORD), "w") as f:
            f.write(json.dumps(line) + "\n")
        os.chmod(os.path.join(self.state, tool.RECORD), 0o600)
        code, err = self.run_genesis()
        self.assertEqual(code, 0, err)
        self.assertEqual([l["kind"] for l in cardrecord.read_signing_state(self.state, self.root)], ["card-record", "manifest"])


    def test_the_offline_root_signs_epoch_1_after_the_fingerprint_and_the_digest_are_typed(self):
        code, err = self.run_genesis("--chain-out", self.paths["chain.json"])
        self.assertEqual(code, 0, err)
        with open(self.paths["chain.json"]) as f:
            chain = json.load(f)
        self.assertEqual(m.accept_chain(None, chain, self.root)["epoch"], 1)
        self.assertIn("ROOT-FINGERPRINT", self.asked[0])                        # the ceremony sheet's line, by its name
        self.assertNotIn(self.fingerprint, self.out + "".join(self.asked))       # read from the ceremony record, never shown
        line = self.record()[-1]
        self.assertEqual((line["genesis"], line["verified"], line["provenance"]), (True, True, "offline-keys session " + self.SESSION))

    def test_a_wrong_or_short_fingerprint_signs_nothing(self):
        for typed in (["0" * 64, "1 %s" % m.digest(self.first)[:8]], [self.fingerprint[:8], "1 %s" % m.digest(self.first)[:8]]):
            with self.subTest(typed[0][:8]):
                code, err = self.run_genesis(typed=typed)
                self.assertEqual(code, 2)
                self.assertIn("the fingerprint typed is not this key's: nothing was signed", err)
        self.assertFalse(os.path.exists(self.paths["e1.json"]))
        self.assertEqual(self.record(), [])

    def test_a_key_that_is_not_the_pin_is_refused_before_anything_is_typed(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        code, err = self.run_genesis(key=Ed25519PrivateKey.generate())
        self.assertEqual(code, 2)
        self.assertIn("is not the pinned root", err)
        self.assertEqual((self.asked, self.record()), ([], []))

    def test_only_a_fresh_epoch_1_v4_manifest_is_a_genesis(self):
        """Refused by THIS rule, by its message: a well-formed v3 epoch 1, and a well-formed v4 epoch 2."""
        from tests.test_baremetal_membership_v4 import manifest3
        v3 = manifest3(1, "", [{k: v for k, v in n.items() if k != "signing_key"} for n in self.nodes4()])
        m.validate(v3)                                                    # a well-formed manifest: only the schema is wrong
        later = self.manifest4(2, "cd" * 32, self.nodes4())
        m.validate(later)                                                 # a well-formed epoch 2: only "fresh" is wrong
        for proposal in (v3, later):
            with self.subTest(schema=proposal["schema"], epoch=proposal["epoch"]):
                self.write(proposal)
                code, err = self.run_genesis()
                self.assertEqual(code, 2, err)
                self.assertIn("the genesis is a fresh epoch-1 %s manifest with no prev_digest" % m.SCHEMA_V4, err)
        # an epoch 1 naming a previous manifest is not even well-formed: validate's own rule refuses it first
        self.write(self.manifest4(1, "ab" * 32, self.nodes4()))
        self.assertIn("epoch 1 has no previous manifest", self.run_genesis()[1])
        self.assertEqual(self.record(), [])

    def test_genesis_takes_no_chain_no_expected_epoch_and_no_token(self):
        chain = os.path.join(self.d, "c.json")
        with open(chain, "w") as f:
            json.dump([], f)
        for extra, reason in ((("--chain", chain), "--genesis takes no --chain"), (("--expected-epoch", "0"), "--genesis takes no --chain"),
                              (("--module", "/usr/lib/opensc-pkcs11.so"), "--key-fd and --offline-session only"),
                              (("--old", chain), "--genesis takes no measurements step")):
            with self.subTest(reason):
                code, err = self.run_genesis(*extra)
                self.assertEqual(code, 2)
                self.assertIn(reason, err)

    def test_without_genesis_a_chain_is_still_required(self):
        err = io.StringIO()
        with unittest.mock.patch("sys.stderr", err):
            self.assertEqual(tool.main(["sign", "--root-key", self.root, "--proposal", self.paths["p.json"], "--signer", "root",
                                        "--key-fd", "3", "--offline-session", self.SESSION, "--state-dir", self.state,
                                        "--out", self.paths["e1.json"]]), 2)
        self.assertIn("give --chain and --expected-epoch (or --genesis)", err.getvalue())


class ProposeGenesis(unittest.TestCase):
    """`propose --genesis` (regalia-kms-24's decisions, 2026-10-04): epoch 1 from the nodes' `enrol entry` outputs, the
    measurements document, the owner's two card keys and the release card's (refused as an owner), with the default
    policy printed for review; written only after the operator types the two cards' serials at the console. The keys
    come from the card ceremony's record, verified under the pinned root (--card-record): never typed. Each refusal
    below is the one guard's own."""
    MAIN, BACKUP = "40000001", "40000002"

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from tests.test_baremetal_membership_v4 import nodes4, OWNER_KEYS, typed
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.root_key = Ed25519PrivateKey.generate()
        self.root = OfflineRoot.raw(self.root_key).hex()
        self.entries = [{k: v for k, v in n.items() if k != "state"} for n in nodes4()]
        self.document = {"schema": measurements.SCHEMA, "name": "genesis", "nodes": {
            e["node_id"]: {"accepted": [{"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "07" * 32},
                                         "phases": {"initrd": {"11": "aa" * 32}, "system": {"11": "bb" * 32}}}]} for e in self.entries}}
        # what each node's AK quoted at `enrol activate` (#399): booted, on the reviewed image
        self.enrolled = {e["node_id"]: {"7": "07" * 32, "11": "bb" * 32} for e in self.entries}
        self.owner_a, self.owner_b = typed(OWNER_KEYS[0])["key"], typed(OWNER_KEYS[1])["key"]
        self.release = typed(OWNER_KEYS[2])["key"]

    def owners(self):
        return {self.MAIN: self.owner_a, self.BACKUP: self.owner_b}

    def propose(self, entries=None, owners=None, release=None, policy=None, document=None):
        return tool.propose_genesis(self.entries if entries is None else entries, document or self.document,
                                    self.owners() if owners is None else owners, release or self.release, self.root,
                                    "2026-10-04T12:00:00Z", policy)

    def card_record(self, signer=None, change=None):
        """The card ceremony's record of the owner's two cards and the release card, as regalia-ceremony writes it
        (tests/vectors/card-ceremony-record/), signed by `signer` (default: the pinned root)."""
        import copy
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from deploy.baremetal import cardrecord
        from tests.test_baremetal_cardrecord import raw, ssh
        signer = signer or self.root_key
        record = {
            "schema": cardrecord.SCHEMA, "event": cardrecord.EVENT, "session": "cd" * 16, "tool": "offline-keys.py test",
            "at": "2026-10-04T11:00:00Z", "root_entry": {"alg": "ed25519", "key": raw(signer)},
            "root_fingerprint": hashlib.sha256(bytes.fromhex(raw(signer))).hexdigest(),
            "owner_keys": [{"role": "dev-main", "serial": self.MAIN, "alg": "ed25519", "key": self.owner_a, "attested": True,
                            "attestation_sha256": {"sig": "a1" * 32, "dec": "a2" * 32}},
                           {"role": "dev-backup", "serial": self.BACKUP, "alg": "ed25519", "key": self.owner_b, "attested": True,
                            "attestation_sha256": {"sig": "b1" * 32, "dec": "b2" * 32}}],
            "ownerauth_recipients": [{"serial": self.MAIN, "primary": "A" * 40, "subkey": "B" * 40},
                                     {"serial": self.BACKUP, "primary": "C" * 40, "subkey": "D" * 40}],
            "ssh_signers": [{"serial": s, "key": ssh(Ed25519PrivateKey.generate())} for s in (self.MAIN, self.BACKUP)],
            "release_key": {"alg": "ed25519", "key": self.release, "fingerprint": "E" * 40, "cards": ["40000003", "40000004"],
                            "imported": True, "attested": False},
            "sequence": 1, "supersedes": ""}
        record = copy.deepcopy(record)
        if change:
            change(record)
        return {"record": record, "signature": signer.sign(cardrecord.RECORD_DOMAIN + m.canonical(record)).hex()}

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def test_a_genesis_a_node_accepts_from_the_root(self):
        candidate = self.propose()
        self.assertEqual((candidate["schema"], candidate["epoch"], candidate["prev_digest"]), (m.SCHEMA_V4, 1, ""))
        self.assertEqual(candidate["policy_version"], measurements.version(self.document))
        self.assertEqual([n["state"] for n in candidate["nodes"]], ["ACTIVE"] * 3)
        self.assertEqual(candidate["owner_keys"], [{"alg": "ed25519", "key": self.owner_a}, {"alg": "ed25519", "key": self.owner_b}])
        self.assertEqual((candidate["heartbeat_max_lifetime_s"], candidate["owner_heartbeat_lifetime_s"]), (21600, 3600))
        self.assertEqual(candidate["heartbeat_signers"], {"threshold": 2, "parties": ["a", "b", "c", "owner"]})
        self.assertEqual(candidate["revocation_signers"], [{"threshold": 2, "parties": ["a", "b", "c"]}, {"threshold": 1, "parties": ["owner"]}])
        envelope = {"manifest": candidate, "signature": {"signer": "root", "key": self.root,
                                                         "sig": self.root_key.sign(m.DOMAIN + m.canonical(candidate)).hex()}}
        self.assertEqual(m.accept(None, envelope, self.root)["epoch"], 1)

    def test_owner_keys_exactly_two_cards_two_keys(self):
        """The library's own check (the card record already holds these): a caller giving owners otherwise."""
        self.refused("the owner's keys are exactly two cards'", self.propose, owners={self.MAIN: self.owner_a})
        self.refused("the two owner cards have the same key: they are one card", self.propose, owners={self.MAIN: self.owner_a, self.BACKUP: self.owner_a})
        self.refused("the owner card 40000002's key is not a raw Ed25519 public key", self.propose, owners={self.MAIN: self.owner_a, self.BACKUP: "AB" * 32})

    def test_a_bench_card_is_never_an_owner_card_even_from_a_library_caller(self):
        """95's read on #392, fixed at 24's request: the card record refuses bench serials, and so does propose_genesis
        itself, for a caller that gives the owners otherwise."""
        self.refused("the owner card 36345471 is a bench token: the ceremony never uses a bench serial",
                     self.propose, owners={"36345471": self.owner_a, self.BACKUP: self.owner_b})

    def test_the_release_card_root_and_signing_keys_are_never_owner_keys(self):
        self.refused("the release key is one of the owner keys: the release card is never an owner key", self.propose, release=self.owner_b)
        self.refused("the owner card 40000001's key is the pinned root's", self.propose, owners={self.MAIN: self.root, self.BACKUP: self.owner_b})
        reused = [dict(e, signing_key={"alg": "ed25519", "key": self.owner_b}) if e["node_id"] == "b" else e for e in self.entries]
        self.refused("the owner card 40000002's key is b's signing key", self.propose, entries=reused)

    def test_the_release_card_is_neither_the_root_nor_a_node(self):
        """regalia-kms-d9's read: the release key was compared with the owner keys only."""
        self.refused("the release card's key is the pinned root's", self.propose, release=self.root)
        reused = [dict(e, signing_key={"alg": "ed25519", "key": self.release}) if e["node_id"] == "c" else e for e in self.entries]
        self.refused("the release card's key is c's signing key", self.propose, entries=reused)

    def test_a_bench_token_is_never_a_production_node_s(self):
        """regalia-kms-d9's read: D28.5, never a bench serial; genesis is where the root first vouches for the tokens."""
        bench = [dict(e, hsm_serials=e["hsm_serials"] + ["denk0404380"]) if e["node_id"] == "b" else e for e in self.entries]
        self.refused("the entry of b names a bench token (denk0404380)", self.propose, entries=bench)
        for token in ("35718625", "000635718625", "ESP41D722E2"):        # YubiKey decimal and OpenPGP forms, a Pico HSM
            with self.subTest(token=token):
                bench = [dict(e, hsm_serials=e["hsm_serials"] + [token]) if e["node_id"] == "a" else e for e in self.entries]
                self.refused("the entry of a names a bench token (%s)" % token, self.propose, entries=bench)

    def test_an_entry_from_an_older_enrolment_or_with_no_serial_is_refused(self):
        older = [{k: v for k, v in e.items() if k != "ssh_host_pub"} if e["node_id"] == "c" else e for e in self.entries]
        self.refused("the entry of c lacks ssh_host_pub", self.propose, entries=older)
        none = [dict(e, hsm_serials=[]) if e["node_id"] == "a" else e for e in self.entries]
        self.refused("the entry of a names no token serial", self.propose, entries=none)
        self.refused("no node entry given", self.propose, entries=[])

    def test_the_measurements_must_cover_every_node(self):
        partial = dict(self.document, nodes={k: v for k, v in self.document["nodes"].items() if k != "c"})
        self.refused("the measurements have no entry for c", self.propose, document=partial)

    def test_a_policy_override_below_its_floor_is_refused(self):
        self.refused("owner_heartbeat_lifetime_s must be an integer from 300", self.propose, policy={"owner_heartbeat_lifetime_s": 100})
        self.assertEqual(self.propose(policy={"heartbeat_max_lifetime_s": 7200})["heartbeat_max_lifetime_s"], 7200)

    def state(self, *records):
        """The ceremony laptop's state directory (#403): the marker naming the pinned root, and a signing record holding a
        manifest line and one card-record line per record given, in order."""
        from deploy.baremetal import cardrecord
        state = os.path.join(self.d, "state")
        os.makedirs(state, mode=0o700, exist_ok=True)
        with open(os.path.join(state, cardrecord.SIGNING_STATE), "w") as f:
            json.dump({"schema": cardrecord.SIGNING_STATE_SCHEMA, "root": self.root}, f)
        with open(os.path.join(state, cardrecord.SIGNING_RECORD), "w") as f:
            f.write(json.dumps({"kind": "manifest", "epoch": 7, "digest": "ab" * 32, "signer": "root"}) + "\n")
            for envelope in records:
                f.write(json.dumps({"kind": "card-record", "sequence": envelope["record"]["sequence"],
                                    "digest": cardrecord.digest(envelope["record"]), "key": self.root, "at": "2026-10-04T11:00:01Z"}) + "\n")
        for name in (cardrecord.SIGNING_STATE, cardrecord.SIGNING_RECORD):
            os.chmod(os.path.join(state, name), 0o600)
        return state

    def run_cli(self, *extra, typed="40000001 40000002", record=None, root=None, with_record=True, logged=None, with_state=True):
        record = record or self.card_record()
        nodes = []
        for e in self.entries:                       # each node's three files; their proof is enrol's (stubbed below, tested there)
            files = []
            for kind, content in (("bundle", e), ("keep", {"node_id": e["node_id"]}), ("activation", {"node_id": e["node_id"]})):
                files.append(os.path.join(self.d, "%s-%s.json" % (kind, e["node_id"])))
                with open(files[-1], "w") as f:
                    json.dump(content, f)
            nodes.append(files)
        pub = os.path.join(self.d, "system.pub.pem")
        with open(pub, "w") as f:
            f.write("system-phase PCR key (stub)\n")
        doc = os.path.join(self.d, "doc.json")
        with open(doc, "w") as f:
            json.dump(self.document, f)
        cards = os.path.join(self.d, "cards.record.json")
        with open(cards, "w") as f:
            json.dump(record, f)
        out = os.path.join(self.d, "e1.json")
        args = ["propose", "--genesis", "--root-key", root or self.root, "--measurements", doc, "--out", out,
                "--issued-at", "2026-10-04T12:00:00Z"] + (["--card-record", cards] if with_record else []) \
            + (["--state-dir", self.state(*(logged or [record]))] if with_state else [])
        args += ["--system-pub", pub]
        for files in nodes:
            args += ["--node"] + files

        def proven(bundle, system_pub, keep, activation, run=None):
            self.assertEqual((system_pub, keep["node_id"], activation["node_id"]), (b"system-phase PCR key (stub)\n",) + (bundle["node_id"],) * 2)
            return bundle, self.enrolled[bundle["node_id"]]
        stdout, stderr = io.StringIO(), io.StringIO()
        with unittest.mock.patch("sys.stdout", stdout), unittest.mock.patch("sys.stderr", stderr), \
                unittest.mock.patch.object(tool.keyfd, "tty_line", lambda prompt: typed), unittest.mock.patch.object(tool.enrol, "proven_entry", proven):
            code = tool.main(args + list(extra))
        return code, stdout.getvalue(), stderr.getvalue(), out

    def test_the_command_prints_every_field_and_writes_only_after_the_serials_are_typed(self):
        code, out, err, path = self.run_cli(typed="40000002 40000001")
        self.assertEqual(code, 2)
        self.assertIn("the serials typed are not the owner cards above: nothing was written", err)
        self.assertFalse(os.path.exists(path))
        code, out, err, path = self.run_cli()
        self.assertEqual(code, 0, err)
        for shown in ("owner card 40000001 (dev-main): key " + self.owner_a, "owner card 40000002 (dev-backup): key " + self.owner_b,
                      "card record: session " + "cd" * 16 + ", made 2026-10-04T11:00:00Z, signed by the pinned root",
                      "card record 1 of 1 (the newest on this laptop's signing record), digest ",
                      "supersedes nothing (the first): check both against the ceremony sheet",
                      "release card key (not in the manifest", "heartbeat_max_lifetime_s", "revocation_signers", "node c: ADDED"):
            self.assertIn(shown, out)
        written = json.load(open(path))
        self.assertEqual((written["epoch"], written["owner_keys"]), (1, [{"alg": "ed25519", "key": self.owner_a}, {"alg": "ed25519", "key": self.owner_b}]))
        self.assertNotIn(self.release, json.dumps(written))

    def test_the_keys_come_only_from_a_record_the_pinned_root_signed(self):
        """24, 2026-10-04: --card-record is the one path; the typed --owner-key/--release-key are gone, never mixed."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        code, _, err, path = self.run_cli(with_record=False)
        self.assertEqual(code, 2)
        self.assertIn("--genesis needs --measurements, --card-record and --state-dir", err)
        code, _, err, path = self.run_cli(record=self.card_record(signer=Ed25519PrivateKey.generate()))
        self.assertIn("the card record names another root than the pinned one", err)
        self.assertFalse(os.path.exists(path))
        forged = self.card_record()
        forged["record"]["owner_keys"][1]["key"] = self.release                     # the release key passed off as an owner's
        code, _, err, path = self.run_cli(record=forged)
        self.assertIn("the card record's signature is not the pinned root's", err)
        self.assertFalse(os.path.exists(path))
        for flag in ("--owner-key", "--release-key"):
            with self.subTest(flag=flag), unittest.mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                self.run_cli(flag, "40000001=" + self.owner_a if flag == "--owner-key" else self.release)

    def test_the_genesis_root_is_one_ed25519_key(self):
        code, _, err, path = self.run_cli(root=json.dumps(tk.p256()[1]))           # a P-256 root on a card (#156's path)
        self.assertEqual(code, 2, err)
        self.assertIn("the genesis root is one Ed25519 key (D28)", err)
        self.assertFalse(os.path.exists(path))

    def test_the_card_record_is_for_genesis_only(self):
        stderr = io.StringIO()
        with unittest.mock.patch("sys.stderr", stderr):
            self.assertEqual(tool.main(["propose", "--root-key", self.root, "--chain", os.path.join(self.d, "none.json"),
                                        "--card-record", os.path.join(self.d, "x.json"), "--set-state", "c=MAINTENANCE",
                                        "--out", os.path.join(self.d, "x")]), 2)
        self.assertIn("--node, --system-pub, --measurements, --card-record, --state-dir and the lifetimes are for --genesis only", stderr.getvalue())

    def test_each_node_was_enrolled_on_the_reviewed_image(self):
        """#399 (regalia-kms-d9): the PCR 11 each node's AK quoted at activation is the SYSTEM-phase value the genesis
        measurements accept for it; its initrd-phase value, or an image they do not list (a bench one), is refused."""
        for node, value, reason in (("b", "aa" * 32, "b was enrolled booted on PCR 11 %s, not the system-phase value %s" % ("aa" * 32, "bb" * 32)),
                                    ("c", "cc" * 32, "c was enrolled booted on PCR 11 %s" % ("cc" * 32))):
            with self.subTest(node=node):
                self.enrolled[node] = dict(self.enrolled[node], **{"11": value})
                self.refused(reason, tool.judge_enrolled, self.document, self.enrolled)
                code, _, err, path = self.run_cli()
                self.assertIn(reason, err)
                self.assertFalse(os.path.exists(path))
                self.enrolled[node] = dict(self.enrolled[node], **{"11": "bb" * 32})
        self.enrolled["a"] = dict(self.enrolled["a"], **{"7": "77" * 32})
        self.refused("a was enrolled with PCR 7 (Secure Boot state) %s, not %s as the measurements give" % ("77" * 32, "07" * 32),
                     tool.judge_enrolled, self.document, self.enrolled)
        # no PCR 7 in the measurements: compared across the nodes only
        bare = {"schema": measurements.SCHEMA, "name": "genesis", "nodes": {n: {"accepted": [{"label": "image-1", "tpm_firmware_version": "0" * 16,
                "pcrs": {"0": "00" * 32}, "phases": {"initrd": {"11": "aa" * 32}, "system": {"11": "bb" * 32}}}]} for n in self.enrolled}}
        self.refused("the nodes a, b, c were enrolled with different Secure Boot states (PCR 7)", tool.judge_enrolled, bare, self.enrolled)
        self.enrolled["a"] = dict(self.enrolled["a"], **{"7": "07" * 32})
        tool.judge_enrolled(bare, self.enrolled)

    def test_the_summary_shows_what_each_node_booted_and_entry_files_are_gone(self):
        code, out, err, path = self.run_cli()
        self.assertEqual(code, 0, err)
        self.assertIn("node a enrolled booted on PCR 7 %s, PCR 11 %s (its AK's quote at activation; PCR 11 judged against the "
                      "measurements' system phase, PCR 7 too)" % ("07" * 32, "bb" * 32), out)
        os.unlink(path)
        with unittest.mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            tool.main(["propose", "--genesis", "--root-key", self.root, "--entry", os.path.join(self.d, "entry-a.json")])
        err = io.StringIO()
        with unittest.mock.patch("sys.stderr", err):
            self.assertEqual(tool.main(["propose", "--genesis", "--root-key", self.root, "--measurements", "m", "--card-record", "c",
                                        "--state-dir", "s", "--out", path, "--node", "b", "k", "a"]), 2)
        self.assertIn("--genesis needs --node BUNDLE KEEP ACTIVATION for each node, and --system-pub", err.getvalue())

    def test_only_the_newest_card_record_on_the_laptop_s_signing_record(self):
        """#403: an older record, still validly signed, is refused once a newer one is on the laptop's signing record; and
        without the laptop's state directory nothing is judged."""
        first = self.card_record()
        second = self.card_record(change=lambda r: r.update(sequence=2, supersedes=tool.cardrecord.digest(first["record"]),
                                                            at="2026-10-05T11:00:00Z"))
        code, _, err, path = self.run_cli(record=first, logged=[first, second])
        self.assertEqual(code, 2, err)
        self.assertIn("this card record (sequence 1) is not the newest the root signed (sequence 2", err)
        self.assertFalse(os.path.exists(path))
        code, out, err, path = self.run_cli(record=second, logged=[first, second])
        self.assertEqual(code, 0, err)
        self.assertIn("card record 2 of 2 (the newest on this laptop's signing record)", out)
        self.assertIn("supersedes %s" % tool.cardrecord.digest(first["record"]), out)
        os.unlink(path)
        code, _, err, path = self.run_cli(with_state=False)
        self.assertIn("--genesis needs --measurements, --card-record and --state-dir", err)
        self.assertFalse(os.path.exists(path))

    def test_genesis_takes_no_chain_and_the_other_proposals_still_need_one(self):
        chain = os.path.join(self.d, "c.json")
        with open(chain, "w") as f:
            json.dump([], f)
        code, _, err, _ = self.run_cli("--chain", chain)
        self.assertIn("--genesis takes no --chain", err)
        stderr = io.StringIO()
        with unittest.mock.patch("sys.stderr", stderr):
            self.assertEqual(tool.main(["propose", "--root-key", self.root, "--set-state", "c=MAINTENANCE", "--out", os.path.join(self.d, "x")]), 2)
        self.assertIn("give --chain (or --genesis)", stderr.getvalue())
