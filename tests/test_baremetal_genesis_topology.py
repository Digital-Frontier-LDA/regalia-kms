"""regalia-kms-dx7.2: `manifest propose --genesis --topology single-node|multi-node` and the typed single-node
acknowledgement (docs/design/single-node.md 4.2 and 6).

The topology is required and never inferred from the --node count; the signer rules come from it; a single-node genesis
prints docs/single-node-limits.md verbatim, reads `single node: I accept the limits <8 hex>` at the console only, and
records the shipped text's SHA-256 in topology.single_node_limits_sha256; `sign --genesis` shows the profile and the
digest once the root fingerprint is confirmed and refuses any other digest. A three-node genesis is today's, byte for
byte, but for the v5 schema line and its topology field (MultiNodeIsToday's: a digest recorded from main 36a36c62)."""
import hashlib
import io
import json
import os
import pathlib
import unittest
import unittest.mock

from deploy.baremetal import keyfd
from deploy.baremetal import manifest as tool
from deploy.baremetal import membership as m
from tests import test_baremetal_manifest as tbm
from tests.test_baremetal_membership_v5 import LIMITS, SINGLE, alone, manifest5, one

LIMITS_FILE = pathlib.Path(__file__).resolve().parents[1] / "docs" / "single-node-limits.md"
PHRASE = "single node: I accept the limits %s"
SERIALS = "40000001 40000002"
# SHA-256 of what `propose_genesis` wrote for ProposeGenesis's three-node fixture on main 36a36c62 (schema v4, no topology),
# computed there before this change: the multi-node output now, with its topology removed and its schema line put back
# to v4, must be those bytes exactly.
TODAY_THREE_NODE_SHA256 = "28a7e666c5a7d2b81bd757a1bde2c1ba11b43cae2b03a08504361366926a852b"


def fixture(case, kind, method):
    """An instance of test_baremetal_manifest's `kind` set up as a helper (its fixtures, not its tests)."""
    helper = kind(method)
    helper.setUp()
    case.addCleanup(helper.doCleanups)
    return helper


class ShippedText(unittest.TestCase):
    def test_the_constant_is_the_shipped_file_s_digest(self):
        data = LIMITS_FILE.read_bytes()
        self.assertEqual(tool.SINGLE_NODE_LIMITS_SHA256, hashlib.sha256(data).hexdigest())
        self.assertEqual(pathlib.Path(tool.SINGLE_NODE_LIMITS).resolve(), LIMITS_FILE)
        self.assertIn(b"\nVersion: regalia.single-node-limits/v2\n", data)
        self.assertEqual(tool.single_node_limits(), data.decode("ascii"))

    def test_a_changed_text_is_refused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "limits.md")
            with open(path, "wb") as f:
                f.write(LIMITS_FILE.read_bytes().replace(b"| degraded |", b"| supported |", 1))
            with self.assertRaises(m.Refused) as caught:
                tool.single_node_limits(path)
            self.assertIn("not the %s this tool ships" % tool.SINGLE_NODE_LIMITS_SHA256, str(caught.exception))
            with self.assertRaises(m.Refused) as caught:
                tool.single_node_limits(os.path.join(d, "absent.md"))
            self.assertIn("cannot be read", str(caught.exception))


class Topology(unittest.TestCase):
    """The profile is the operator's: required, and each node count other than its designed size refused."""

    def setUp(self):
        self.g = fixture(self, tbm.ProposeGenesis, "propose")

    def refused(self, reason, fn, *args, **kw):
        with self.assertRaises(m.Refused) as caught:
            fn(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def test_no_topology_is_refused_and_never_inferred(self):
        for count in (1, 3):
            with self.subTest(count=count):
                self.refused("--topology is required", self.g.propose, entries=self.g.entries[:count], topology=None)
        code, _, err, path = self.g.run_cli(topology=None)
        self.assertEqual(code, 2)
        self.assertIn("--topology is required, single-node or multi-node: it is never inferred from the --node count", err)
        self.assertFalse(os.path.exists(path))
        with unittest.mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            self.g.run_cli(topology="three-node")                   # argparse's choices: only the two

    def test_a_node_count_other_than_the_profile_s_is_refused(self):
        for profile, count in (("multi-node", 1), ("multi-node", 2), ("single-node", 3), ("single-node", 2)):
            with self.subTest(profile=profile, count=count):
                self.refused("--topology %s is a %d-node genesis: %d --node given" % (profile, 3 if profile == "multi-node" else 1, count),
                             self.g.propose, entries=self.g.entries[:count], topology=profile)
        self.g.entries = self.g.entries[:1]
        code, _, err, path = self.g.run_cli(typed=lambda prompt: self.fail("nothing is asked: %s" % prompt))
        self.assertEqual(code, 2)
        self.assertIn("--topology multi-node is a 3-node genesis: 1 --node given", err)
        self.assertFalse(os.path.exists(path))

    def test_topology_is_for_the_genesis_only(self):
        err = io.StringIO()
        with unittest.mock.patch("sys.stderr", err):
            self.assertEqual(tool.main(["propose", "--root-key", self.g.root, "--chain", "c.json", "--topology", "single-node",
                                        "--set-state", "a=MAINTENANCE", "--out", os.path.join(self.g.d, "x")]), 2)
        self.assertIn("--topology and the lifetimes are for --genesis only", err.getvalue())

    def test_the_thresholds_come_from_the_topology(self):
        three = self.g.propose()
        self.assertEqual(three["heartbeat_signers"], {"threshold": 2, "parties": ["a", "b", "c", "owner"]})
        self.assertEqual(three["activation_signers"], {"threshold": 2, "parties": ["a", "b", "c", "owner"]})
        self.assertEqual(three["revocation_signers"], [{"threshold": 2, "parties": ["a", "b", "c"]}, {"threshold": 1, "parties": ["owner"]}])
        self.assertEqual(m.node_floor(three), 2)
        alone_ = self.single()
        self.assertEqual(alone_["topology"], {"profile": "single-node", "nodes": 1,
                                              "single_node_limits_sha256": hashlib.sha256(LIMITS_FILE.read_bytes()).hexdigest()})
        self.assertEqual({k: alone_[k] for k in ("heartbeat_signers", "activation_signers", "revocation_signers")}, alone("a"))
        self.assertEqual(m.profile(alone_), m.SINGLE_NODE)

    def single(self):
        self.g.document = dict(self.g.document, nodes={"a": self.g.document["nodes"]["a"]})
        return self.g.propose(entries=self.g.entries[:1], document=self.g.document, topology="single-node")


class MultiNodeIsToday(unittest.TestCase):
    def test_a_three_node_genesis_is_today_s_but_for_its_schema_and_topology(self):
        g = fixture(self, tbm.ProposeGenesis, "propose")
        candidate = g.propose()
        self.assertEqual((candidate["schema"], candidate["topology"]), (m.SCHEMA_V5, {"profile": "multi-node", "nodes": 3}))
        today = {k: v for k, v in candidate.items() if k != "topology"}
        today["schema"] = m.SCHEMA_V4
        data = json.dumps(today, indent=2, sort_keys=True).encode() + b"\n"
        self.assertEqual(hashlib.sha256(data).hexdigest(), TODAY_THREE_NODE_SHA256)


class SingleNodeAcknowledgement(unittest.TestCase):
    """The limits text printed verbatim, the phrase read at the console only, the digest in the manifest."""

    def setUp(self):
        self.g = fixture(self, tbm.ProposeGenesis, "propose")
        self.g.entries = self.g.entries[:1]
        self.g.document = dict(self.g.document, nodes={"a": self.g.document["nodes"]["a"]})
        self.g.enrolled = {"a": self.g.enrolled["a"]}
        self.phrase = PHRASE % hashlib.sha256(LIMITS_FILE.read_bytes()).hexdigest()[:8]
        self.asked = []

    def console(self, phrase):
        def tty(prompt):
            self.asked.append(prompt)
            return phrase if "accept these limits" in prompt else SERIALS
        return tty

    def test_the_text_is_printed_verbatim_and_the_typed_phrase_records_its_digest(self):
        code, out, err, path = self.g.run_cli(typed=self.console(self.phrase), topology="single-node")
        self.assertEqual(code, 0, err)
        self.assertIn(LIMITS_FILE.read_text(), out)                                         # every byte of it, in order
        self.assertIn(self.phrase, self.asked[0])
        self.assertEqual(len(self.asked), 2)                                                # then the cards' serials
        self.assertLess(out.index(LIMITS_FILE.read_text()), out.index("UNSIGNED genesis"))
        with open(path) as f:
            written = json.load(f)
        self.assertEqual(written["topology"]["single_node_limits_sha256"], hashlib.sha256(LIMITS_FILE.read_bytes()).hexdigest())
        self.assertEqual(written["schema"], m.SCHEMA_V5)
        envelope = {"manifest": written, "signature": {"signer": "root", "key": self.g.root,
                                                       "sig": self.g.root_key.sign(m.DOMAIN + m.canonical(written)).hex()}}
        self.assertEqual(m.profile(m.accept(None, envelope, self.g.root)), m.SINGLE_NODE)
        self.assertIn("SINGLE-NODE (1 node)", out)

    def test_a_wrong_or_absent_phrase_writes_nothing(self):
        for typed in ("", "yes", self.phrase.upper(), PHRASE % "00000000", self.phrase + " please", "single node: I accept the limits",
                      " " + self.phrase, self.phrase + " ", self.phrase + "\t", "\t" + self.phrase + " "):     # exactly, no padding (#738)
            with self.subTest(typed=typed):
                code, _, err, path = self.g.run_cli(typed=self.console(typed), topology="single-node")
                self.assertEqual(code, 2)
                self.assertIn("the acknowledgement typed is not \"%s\": nothing was written" % self.phrase, err)
                self.assertFalse(os.path.exists(path))

    def test_the_phrase_is_never_an_argument(self):
        for flag in ("--acknowledgement", "--accept", "--ack"):
            with self.subTest(flag=flag), unittest.mock.patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
                self.g.run_cli(flag, self.phrase, typed=self.console(self.phrase), topology="single-node")

    def test_without_a_terminal_it_is_refused(self):
        real, real_open = keyfd.tty_line, os.open

        def no_tty(path, *args, **kw):
            if path == "/dev/tty":
                raise OSError(6, "No such device or address", path)
            return real_open(path, *args, **kw)
        with unittest.mock.patch.object(keyfd.os, "open", no_tty):
            code, _, err, path = self.g.run_cli(typed=lambda prompt: real(prompt), topology="single-node")
        self.assertEqual(code, 2)
        self.assertIn("the confirmation is typed at the console: no controlling terminal", err)
        self.assertFalse(os.path.exists(path))

    def test_a_changed_text_on_disk_is_refused_before_anything_is_asked(self):
        with unittest.mock.patch.object(tool, "SINGLE_NODE_LIMITS_SHA256", "ab" * 32):
            code, _, err, path = self.g.run_cli(typed=self.console(self.phrase), topology="single-node")
        self.assertEqual(code, 2)
        self.assertIn("this tool ships: nothing is acknowledged but the shipped text", err)
        self.assertEqual((self.asked, os.path.exists(path)), ([], False))

    def test_the_multi_node_genesis_asks_no_acknowledgement(self):
        g = fixture(self, tbm.ProposeGenesis, "propose")
        code, out, err, _ = g.run_cli(typed=self.console(self.phrase))
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.asked), 1)
        self.assertNotIn("accept these limits", self.asked[0])
        self.assertNotIn("Version: regalia.single-node-limits", out)
        self.assertIn("topology: MULTI-NODE (3 nodes)", out)


class SignGenesis(unittest.TestCase):
    """`sign --genesis`: the profile and the digest shown once the root fingerprint is confirmed; another digest refused."""

    def setUp(self):
        self.g = fixture(self, tbm.Genesis, "run_genesis")

    def single(self, digest):
        return manifest5(1, "", [one("a")], dict(SINGLE, single_node_limits_sha256=digest), **alone("a"))

    def test_single_node_is_shown_with_its_digest_beside_the_fingerprint(self):
        self.g.first = self.single(tool.SINGLE_NODE_LIMITS_SHA256)
        self.g.write(self.g.first)
        code, err = self.g.run_genesis()
        self.assertEqual(code, 0, err)
        self.assertIn("root fingerprint confirmed; GENESIS topology: SINGLE-NODE (1 node); single-node limits acknowledged, "
                      "SHA-256 %s" % tool.SINGLE_NODE_LIMITS_SHA256, self.g.out)
        self.assertLess(self.g.out.index("SINGLE-NODE"), self.g.out.index("manifest digest"))

    def test_multi_node_is_shown(self):
        code, err = self.g.run_genesis()
        self.assertEqual(code, 0, err)
        self.assertIn("root fingerprint confirmed; GENESIS topology: MULTI-NODE (3 nodes)", self.g.out)
        self.assertNotIn("SINGLE-NODE", self.g.out)

    def test_a_digest_other_than_the_shipped_text_s_signs_nothing(self):
        self.assertNotEqual(LIMITS, tool.SINGLE_NODE_LIMITS_SHA256)
        self.g.first = self.single(LIMITS)
        m.validate(self.g.first)                                     # well-formed: only the digest is wrong
        self.g.write(self.g.first)
        code, err = self.g.run_genesis()
        self.assertEqual(code, 2)
        self.assertIn("the genesis names single-node limits SHA-256 %s, not the %s this tool ships" % (LIMITS, tool.SINGLE_NODE_LIMITS_SHA256), err)
        self.assertEqual((self.g.asked, self.g.record(), os.path.exists(self.g.paths["e1.json"])), ([], [], False))


if __name__ == "__main__":
    unittest.main()
