"""#419: under v4 every owner-authorized step of enrolment is the ROOT parent's, so the TPM owner authorization never
enters a process of regalia-sync (enrol.define_anchors, enrol.define_first_counter; enrol.commit wires them in).

  * define_anchors defines the anchor and the signing counter, through the owner channel, and leaves a resumed
    enrolment's as they are; a half-defined pair is refused;
  * define_first_counter starts the heartbeat counter from heartbeats the root parent VERIFIES ITSELF (regalia-kms-24):
    at max(sequence - 1, 0); at 0 only at a bootstrap; otherwise refused, nothing defined. A forged or withheld
    heartbeat can only make it refuse, never lower its start."""
import json
import os
import pathlib
import shutil
import tempfile
import unittest

from deploy.baremetal import enrol, membership as m, ownerauth
import tests.test_baremetal_heartbeat as hbt
from tests.test_baremetal_heartbeat import FakeTpm
from tests.test_baremetal_ownerauth import PIN, RECORD, value

ROOT = pathlib.Path(__file__).resolve().parent.parent


class Case(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(self.d + "/state")
        self.auth = ownerauth.from_envelope(value("a"), RECORD, PIN, "a")
        self.tpm = FakeTpm(owner_auth=self.auth._raw)
        example = json.loads((ROOT / "deploy" / "baremetal" / "node.example.json").read_text())
        self.config = self.d + "/node.json"
        with open(self.config, "w") as f:
            json.dump(dict(example, node_id="a", root_key=hbt.pub(hbt.ROOT), state_dir=self.d + "/state"), f)
        self.cfg = json.load(open(self.config))
        # a lab chain's document (unsigned images: no system key, so the indices are owner-written, and every write of
        # theirs the owner's): what these tests need, the owner channel, and the node's store holding it by digest
        from deploy.baremetal import measurements
        entry = {"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32}}
        document = {"schema": measurements.SCHEMA, "name": "v1", "nodes": {n: {"accepted": [entry]} for n in "abc"}}
        enrol.store_documents(self.d + "/state", document, chown=False)
        self.man = dict(hbt.manifest(), policy_version=measurements.version(document))
        from tests.test_baremetal_membership import sign
        self.chain = [sign(self.man, hbt.ROOT)]

    def present(self, *indices):
        return [i for i in indices if self.tpm(["tpm2_nvreadpublic", i]).returncode == 0]

    def counter_indices(self):
        from deploy.baremetal import heartbeat
        c = heartbeat.Counter(self.cfg["nv_heartbeat"])
        return (c.index, c.base_index)                                           # as the code spells them


class TheFirstCounter(Case):
    def define(self, probed, bootstrap=False, owner_auth="given"):
        return enrol.define_first_counter(self.config, self.man, probed, self.d, self.auth if owner_auth == "given" else owner_auth,
                                          bootstrap, run=self.tpm)

    def test_from_a_heartbeat_the_root_parent_verifies(self):
        self.assertEqual(self.define(([{"source": "b", "envelope": hbt.beat(self.man, 7)}], [])), 6)
        self.assertEqual(len(self.present(*self.counter_indices())), 2)
        self.assertIsNone(self.define(([], [])))                                  # a resumed commit: left as it is

    def test_a_forged_heartbeat_counts_for_nothing(self):
        forged = hbt.beat(self.man, 900, key=hbt.OTHER)                           # not the manifest's key
        with self.assertRaisesRegex(enrol.Refused, "no source gave a heartbeat that verifies under epoch 1 \\(b: "):
            self.define(([{"source": "b", "envelope": forged}], []))
        self.assertEqual(self.present(*self.counter_indices()), [])               # nothing defined

    def test_the_highest_verified_one_wins_and_a_forged_higher_one_is_ignored(self):
        probed = [{"source": "b", "envelope": hbt.beat(self.man, 5)}, {"source": "c", "envelope": hbt.beat(self.man, 9)},
                  {"source": "x", "envelope": hbt.beat(self.man, 50, key=hbt.OTHER)}]
        self.assertEqual(self.define((probed, [])), 8)

    def test_at_zero_only_at_a_bootstrap(self):
        with self.assertRaisesRegex(enrol.Refused, "no source gave a heartbeat that verifies under epoch 1 \\(c: holds none newer\\)"):
            self.define(([], ["c: holds none newer"]))
        self.assertEqual(self.present(*self.counter_indices()), [])
        self.assertEqual(self.define(([], ["c: holds none newer"]), bootstrap=True), 0)

    def test_half_defined_is_refused(self):
        lo, _ = self.counter_indices()
        self.tpm.nv[lo] = [0x10, None, 8]                                         # one of the pair only
        with self.assertRaisesRegex(enrol.Refused, "the heartbeat counter is half defined"):
            self.define(([{"source": "b", "envelope": hbt.beat(self.man, 7)}], []))

    def test_only_with_the_owner_authorization(self):
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is set and none was given"):
            self.define(([{"source": "b", "envelope": hbt.beat(self.man, 7)}], []), owner_auth=None)


class TheAnchors(Case):
    def test_defined_by_the_root_parent_and_left_on_a_resume(self):
        chain = self.chain
        self.assertEqual(enrol.define_anchors(self.config, chain, self.d, self.auth, run=self.tpm), ["anchor", "signing counter"])
        from deploy.baremetal import heartbeat
        anchor = m.HighWater(self.cfg["nv_epoch"])._indices()
        signing = heartbeat.Counter(self.cfg["nv_signing"])
        self.assertEqual(self.present(*anchor, signing.index, signing.base_index), list(anchor) + [signing.index, signing.base_index])
        self.assertEqual(enrol.define_anchors(self.config, chain, self.d, self.auth, run=self.tpm), [])

    def test_only_with_the_owner_authorization(self):
        with self.assertRaisesRegex(m.Refused, "the TPM's owner authorization is set and none was given"):
            enrol.define_anchors(self.config, self.chain, self.d, None, run=self.tpm)


def setUpModule():
    global _saved
    _saved, ownerauth._tools_checked = getattr(ownerauth, "_tools_checked", False), True


def tearDownModule():
    ownerauth._tools_checked = _saved


if __name__ == "__main__":
    unittest.main()
