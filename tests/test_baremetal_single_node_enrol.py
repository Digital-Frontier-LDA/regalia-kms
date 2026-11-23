"""dx7.10.1: single-node genesis through owner-authorized commit on a software TPM.

The v4 three-node control stays in test_baremetal_enrol. Cards and the signed image are
fixtures; challenge/activation, proposal validation, policy writes and the TPM anchor are real.
"""
import base64
import contextlib
import copy
import io
import json
import os
import re
import subprocess
import time
import types
import unittest
from unittest.mock import patch

from deploy.baremetal import beat, bootnet, enrol, heartbeat, manifest, measurements, membership, node, ownerauth, signkey
from tests import test_baremetal_enrol as existing
from tests import test_baremetal_membership as tm
from tests import test_baremetal_node as nt
from tests import test_baremetal_ownerauth as toa
from tests import test_baremetal_manifest as ceremony_fixtures


class SingleNodeGenesisOnSwtpm(unittest.TestCase):
    # Reuse the isolated TPM and init helpers without inheriting the three-node test methods.
    setUp = existing.InitOnSwtpm.setUp
    init = existing.InitOnSwtpm.init
    proven = existing.InitOnSwtpm.proven
    _record_file = existing.InitOnSwtpm._record_file

    def test_single_node_genesis_commits_with_owner_as_only_peer(self):
        self.ceremony()

    def test_mutant_commit_without_owner_auth_is_refused(self):
        self.ceremony("without-owner-auth")

    def test_lower_tpm_guard_refuses_commit_without_owner_auth(self):
        """Defence in depth: with enrolment's own ownerauth guard bypassed IN THIS TEST ONLY, the TPM's owner
        authorization still refuses the owner-authorized anchor definition (membership's guard), and no NV anchor
        and no committed manifest chain exist afterwards. OBSERVED, not asserted: by then commit() has already
        installed the configuration (enrol.py install_config) and stored the measurements document
        (store_documents); whether those pre-refusal writes should be rolled back or moved is regalia-kms-r7e."""
        self.ceremony("lower-guard")

    def test_mutant_wrong_topology_is_refused(self):
        self.ceremony("wrong-topology")

    def test_mutant_second_enrolment_after_single_node_genesis_is_refused(self):
        self.ceremony("second-enrolment")

    def test_replacement_after_the_owners_revocation_commits_and_signs_its_first_heartbeat(self):
        """regalia-kms-dx7.19: the owner revokes the only node, the root enrols this TPM in its place, commit starts the
        heartbeat counter at 0 with no peer heartbeat, and the node's own first heartbeat is taken."""
        self.replacement()

    def test_mutant_replacement_typed_for_another_node_is_refused_before_any_write(self):
        self.replacement("another-id")

    def test_mutant_later_single_node_enrolment_without_a_heartbeat_is_refused_before_any_write(self):
        self.replacement("gap")

    def nv_indices(self):
        result = subprocess.run(["tpm2_getcap", "handles-nv-index"], check=True, capture_output=True, text=True)
        return {int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", result.stdout)}

    def config_inventory(self, *roots):
        """Presence, modes and bytes of the configuration and state commit may install."""
        inventory = {}
        for root in roots:
            if not os.path.exists(root):
                inventory[root] = None
                continue
            for directory, names, files in os.walk(root):
                names.sort()
                inventory[directory] = ("directory", os.stat(directory).st_mode)
                for name in sorted(files):
                    path = os.path.join(directory, name)
                    with open(path, "rb") as f:
                        inventory[path] = ("file", os.stat(path).st_mode, f.read())
        return inventory

    def prepare(self, topology="single-node"):
        """This TPM initialised as node a, its owner authorization set, the signed image booted, and the root's genesis
        proposal for it made from its real bundle, challenge and activation. Returns what the steps after it use."""
        from e2e.lib import signed_boot as sb

        os.makedirs(self.d + "/keys")
        private, public = sb.key(self.d + "/keys")
        with open(public, "rb") as f:
            pem = f.read()
        # Invented ceremony serials; never a physical device's identity.
        with patch.object(enrol, "token_serials", lambda module, run=None: ["DENK0500001", "36000001"]):
            bundle = self.init(system_pub=pem)
        root = tm.ROOT_PUB
        value = toa.VECTOR["values"]["a"][:64]
        for argv in (["tpm2_createprimary", "-C", "o", "-c", self.d + "/srk.ctx"],
                     ["tpm2_evictcontrol", "-C", "o", "-c", self.d + "/srk.ctx", ownerauth.SRK],
                     ["tpm2_flushcontext", "-t"]):
            subprocess.run(argv, check=True, capture_output=True)
        record, record_root = toa.resigned(lambda r: None, key=tm.ROOT)
        self.assertEqual(record_root, root)
        enrol.set_ownerauth("a", root, self._record_file(record), io.BytesIO((value + "\n").encode()), directory=self.dir)
        auth_file = self.d + "/auth"
        with open(auth_file, "w") as f:
            f.write("hex:" + value)
        subprocess.run(["tpm2_changeauth", "-c", "l", "file:" + auth_file], check=True, capture_output=True)
        os.unlink(auth_file)
        ownerauth.require_production()  # Both owner and lockout auths are actually set on this TPM.

        image = sb.image("approved")
        signature, system_pcr = sb.signature(image, private, public)
        signature_path = self.d + "/tpm2-pcr-signature.json"
        with open(signature_path, "w") as f:
            json.dump({"sha256": [signature]}, f)
        sb.boot(image)
        keep, activation = self.proven(bundle)
        entry = enrol.entry(bundle, pem, keep, activation)
        signed = {"label": "image-1", "tpm_firmware_version": bundle["tpm_firmware_version"], "pcrs": {"7": "00" * 32},
                  "phases": {"initrd": {"11": "a1" * 32}, "system": {"11": system_pcr}},
                  "signing": {"initrd": "11" * 32, "system": signkey.pcr_key_fingerprint(pem), "secure_boot_cert": "22" * 32},
                  "usr_roothash": "6e" * 32}
        document = {"schema": measurements.SCHEMA, "name": "single-node-signed-image", "nodes": {"a": {"accepted": [signed]}}}

        # Only the offline ceremony records are fixtures. The proposal reads this TPM's
        # real bundle, challenge and activation; proven_entry is never stubbed.
        fixtures = ceremony_fixtures.ProposeGenesis()
        fixtures.setUp()
        self.addCleanup(fixtures.doCleanups)
        fixtures.root_key, fixtures.root = tm.ROOT, root
        cards = fixtures.card_record()

        def write(name, content):
            path = self.d + "/" + name + ".json"
            with open(path, "w") as f:
                json.dump(content, f)
            return path

        candidate_path = self.d + "/genesis.json"
        args = ["propose", "--genesis", "--topology", topology,
                "--root-key", root, "--measurements", write("measurements", document),
                "--card-record", write("cards", cards), "--state-dir", fixtures.state(cards),
                "--offline-keys-record", write("offline-keys", fixtures.generation_record()),
                "--system-pub", public, "--owner-wg-pub", "0e" * 32,
                "--issued-at", "2026-10-04T12:00:00Z", "--out", candidate_path,
                "--node", self.dir + "/bundle.json", write("keep", keep), write("activation", activation)]
        phrase = manifest.ACKNOWLEDGEMENT % manifest.SINGLE_NODE_LIMITS_SHA256[:8]
        answers = unittest.mock.Mock(side_effect=[phrase, "40000001 40000002"])
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(manifest.keyfd, "tty_line", answers), patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            status = manifest.main(args)
        given = ownerauth.read_value(io.BytesIO((value + "\n").encode())), record
        return types.SimpleNamespace(status=status, stdout=stdout, stderr=stderr, answers=answers, candidate_path=candidate_path,
                                     entry=entry, document=document, root=root, given=given, public=public, pem=pem,
                                     signature_path=signature_path)

    def site(self):
        """The single-node site (the owner the boot mesh's only peer), the node.json example, and its /etc directory."""
        site = copy.deepcopy(nt.SITE)
        site["boot_mesh"].update(peers=[], owner={"underlay": "203.0.113.50", "address": "10.89.0.9"})
        site["service_mesh"] = None
        etc = self.d + "/etc-regalia/"
        os.makedirs(etc)
        example = {"schema": "regalia.node/v1", "node_id": "x", "site": etc + "site.json", "root_key": "00" * 32,
                   "tcti": os.environ["TPM2TOOLS_TCTI"], "nv_epoch": "0x01500016", "nv_heartbeat": "0x01500018",
                   "nv_signing": "0x0150001c", "state_dir": self.d + "/state", "admission_dir": self.d + "/admission",
                   "run_dir": self.d + "/run", "admission_log_dir": self.d + "/log-admission", "wg_service_key": self.wg,
                   "measurements": etc + "measurements.json", "pcrs": [7, 11],
                   "time_servers": ["nts.netnod.se", "ptbtime1.ptb.de", "time.cloudflare.com"], "pull_interval": 60, "beat_interval_s": 900}
        return site, etc, example

    @contextlib.contextmanager
    def installed(self, etc, public, signature_path):
        """commit's configuration paths under this test's directory, and the running image's PCR key and signature."""
        with patch.object(enrol, "CONFIG_DIR", etc), patch.object(enrol, "NODE_JSON", etc + "node.json"), \
                patch.object(enrol, "RESTORE_PENDING", etc + "restore-pending"), \
                patch.object(enrol, "CHRONY_CONF", self.d + "/etc-chrony/regalia.conf"), \
                patch.object(signkey, "PCR_PUBLIC_KEY_PATH", public), patch.object(signkey, "PCR_SIGNATURE_PATHS", (signature_path,)):
            yield

    def ceremony(self, mutant=None):
        p = self.prepare("multi-node" if mutant == "wrong-topology" else "single-node")
        status, stdout, stderr, answers, candidate_path = p.status, p.stdout, p.stderr, p.answers, p.candidate_path
        entry, document, root, given, pem = p.entry, p.document, p.root, p.given, p.pem
        if mutant == "wrong-topology":
            self.assertEqual(status, 2, stderr.getvalue())
            self.assertIn("--topology multi-node is a 3-node genesis: 1 --node given", stderr.getvalue())
            answers.assert_not_called()
            self.assertFalse(os.path.exists(candidate_path))
            self.assertEqual(self.nv_indices(), set())
            return
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertEqual(answers.call_count, 2)
        self.assertIn(manifest.single_node_limits().strip(), stdout.getvalue())
        with open(candidate_path) as f:
            man = json.load(f)
        self.assertEqual(man["nodes"], [dict(entry, state="ACTIVE")])
        self.assertEqual(man["topology"], {"profile": "single-node", "nodes": 1,
                                         "single_node_limits_sha256": manifest.SINGLE_NODE_LIMITS_SHA256})
        envelope = tm.sign(man, tm.ROOT)
        site, etc, example = self.site()
        handed = []

        def in_process(config, chain, owner_auth=None):
            handed.append(owner_auth)
            return enrol.anchor_and_store(config, chain, owner_auth=owner_auth)

        with self.installed(etc, p.public, p.signature_path):
            def commit(chain=envelope, authorization=given):
                return enrol.commit(self.dir, chain, root, enrol.fingerprint(root), document, site, example,
                                    as_sync=in_process, out=io.StringIO(), bootstrap=True, ownerauth_given=authorization,
                                    probe=lambda config: ([], ["no other node exists"]))

            if mutant == "without-owner-auth":
                before_nv = self.nv_indices()
                self.assertEqual(before_nv, set(), "the fixture starts with no NV indices")
                config_roots = (etc, self.d + "/etc-chrony", example["state_dir"])
                before_config = self.config_inventory(*config_roots)
                with self.assertRaises((enrol.Refused, membership.Refused)) as refused:
                    commit(authorization=None)
                after_nv = self.nv_indices()
                after_config = self.config_inventory(*config_roots)
                with self.subTest(assertion="ownerauth guard message"):
                    self.assertIn("the TPM's owner authorization is set and enrolment takes it from this node's envelope",
                                  str(refused.exception))
                with self.subTest(assertion="no NV writes before ownerauth refusal"):
                    self.assertEqual(after_nv, before_nv)
                with self.subTest(assertion="no config writes before ownerauth refusal"):
                    self.assertEqual(after_config, before_config)
                self.assertEqual(handed, [])
                # Positive control: the very same inputs commit once the authorization is supplied.
            if mutant == "lower-guard":
                self.assertEqual(self.nv_indices(), set(), "the fixture starts with no NV indices")
                upper = enrol.commit_owner_auth

                def without_upper_guard(manifest_, given_, root_key, node_id, run=subprocess.run, directory=None):
                    try:
                        return upper(manifest_, given_, root_key, node_id, run, directory)
                    except enrol.Refused:
                        return None     # the test bypasses enrolment's guard; production code is unchanged

                with patch.object(enrol, "commit_owner_auth", without_upper_guard), \
                        self.assertRaises((enrol.Refused, membership.Refused)) as refused:
                    commit(authorization=None)
                with self.subTest(assertion="lower TPM guard message"):
                    self.assertIn("the TPM's owner authorization is set and none was given", str(refused.exception))
                with self.subTest(assertion="no NV anchor after lower-guard refusal"):
                    self.assertEqual(self.nv_indices(), set())
                with self.subTest(assertion="no committed manifest chain after lower-guard refusal"):
                    self.assertFalse(os.path.exists(os.path.join(example["state_dir"], "membership.json")))
                self.assertEqual(handed, [])
                return
            epoch, digest = commit()
            self.assertEqual((epoch, digest), (1, membership.digest(man)))
            self.assertEqual(handed, [None], "the policy-writing sync step receives no owner authorization")
            here = node.Node(node.load(etc + "node.json"))
            chain_path = here.path("membership.json")
            self.assertTrue(os.path.isfile(chain_path), "committed manifest chain is missing: " + chain_path)
            try:
                with open(chain_path, "rb") as f:
                    held_chain = membership.load(f.read(membership.MAX_CHAIN_BYTES + 1), membership.MAX_CHAIN_BYTES)
                committed_manifest = membership.accept_chain(None, held_chain, root)
            except (OSError, membership.Refused) as refusal:
                self.fail("committed manifest chain is not readable and verifiable: " + str(refusal))
            self.assertEqual(committed_manifest, man)
            self.assertEqual((here.anchor().value(), here.anchor().record()), (1, (1, digest)))
            self.assertEqual(here.store().load(), man)
            self.assertTrue({int(example[k], 16) for k in ("nv_epoch", "nv_heartbeat", "nv_signing")} <= self.nv_indices())
            area = subprocess.run(["tpm2_nvreadpublic", example["nv_epoch"]], check=True, capture_output=True, text=True).stdout
            self.assertIn("authorization policy: " + signkey.policy(pem).hex().upper(), area)
            self.assertTrue(enrol.Journal(self.dir, "a").get("heartbeat_first")["bootstrap"])
            # regalia-kms-dx7.26: genesis (--bootstrap) holds nothing back: etcd and the daemon start at the first boot
            self.assertFalse(os.path.lexists(etc + "restore-pending"))
            self.assertEqual(bootnet.unlock_endpoints(site, man), {"owner": "10.89.0.9:7443"})
            wg = bootnet.boot_wg_conf(site, man)
            self.assertEqual(wg.count("[Peer]"), 1)
            self.assertIn(base64.b64encode(bytes.fromhex(man["owner_wg_pub"])).decode(), wg)

            if mutant == "second-enrolment":
                second = dict(copy.deepcopy(man), epoch=2, prev_digest=digest, issued_at="2026-10-05T12:00:00Z")
                chain = [envelope, tm.sign(second, tm.ROOT)]
                self.assertEqual(membership.accept_chain(None, chain, root), second, "the chain itself is valid")
                before = enrol.Journal(self.dir, "a").doc
                with self.assertRaisesRegex(enrol.Refused, "a single-node manifest enrols its node at epoch 1, or as the replacement that "
                                            "follows the owner's revocation of its only node, not at epoch 2"):
                    commit(chain)
                self.assertEqual(enrol.Journal(self.dir, "a").doc, before)
                self.assertEqual(here.store().load(), man)
                self.assertEqual(here.anchor().record(), (1, digest))
                self.assertEqual(handed, [None])

    def replacement(self, mutant=None):
        """Epoch 1: b alone (a fixture: not this TPM). Epoch 2, the owner's quorum: b REVOKED_STOLEN. Epoch 3, root-signed:
        this TPM's node a, from its real bundle and activation (the genesis proposal's entry), b kept as its tombstone.
        "gap": a root-signed epoch between the revocation and the enrolment; "another-id": --replace names another node."""
        from tests import test_baremetal_membership_v4 as v4
        from tests import test_baremetal_membership_v5 as v5
        p = self.prepare()
        self.assertEqual(p.status, 0, p.stderr.getvalue())
        with open(p.candidate_path) as f:
            man = json.load(f)
        first = dict(copy.deepcopy(man), nodes=[v5.one("b", i=1)], **v5.alone("b"))
        stolen = dict(copy.deepcopy(first), epoch=2, prev_digest=membership.digest(first), issued_at="2026-10-05T12:00:00Z",
                      nodes=[v5.one("b", "REVOKED_STOLEN", i=1)])
        chain = [tm.sign(first, tm.ROOT), v4.quorum(stolen, v5.O1)]          # the owner's card alone revokes it
        previous = stolen
        if mutant == "gap":
            previous = dict(copy.deepcopy(stolen), epoch=3, prev_digest=membership.digest(stolen), issued_at="2026-10-06T12:00:00Z")
            chain.append(tm.sign(previous, tm.ROOT))
        third = dict(copy.deepcopy(man), epoch=previous["epoch"] + 1, prev_digest=membership.digest(previous),
                     issued_at="2026-10-07T12:00:00Z", nodes=[copy.deepcopy(stolen["nodes"][0])] + man["nodes"])
        chain.append(tm.sign(third, tm.ROOT))
        self.assertEqual(membership.accept_chain(None, chain, p.root), third, "the chain itself is valid")
        site, etc, example = self.site()
        handed, out = [], io.StringIO()

        def in_process(config, chain, owner_auth=None):
            handed.append(owner_auth)
            return enrol.anchor_and_store(config, chain, owner_auth=owner_auth)

        def commit(replace):
            return enrol.commit(self.dir, chain, p.root, enrol.fingerprint(p.root), p.document, site, example, as_sync=in_process,
                                out=out, replace=replace, ownerauth_given=p.given, probe=lambda config: ([], ["no other node exists"]))

        with self.installed(etc, p.public, p.signature_path):
            if mutant:
                self.assertEqual(self.nv_indices(), set(), "the fixture starts with no NV indices")
                config_roots = (etc, self.d + "/etc-chrony", example["state_dir"])
                before_config, before_journal = self.config_inventory(*config_roots), enrol.Journal(self.dir, "a").doc
                replace, reason = (("z", "does not replace z \\(it replaces b after its revocation\\): not the replacement typed")
                                   if mutant == "another-id" else
                                   (None, "a single-node manifest enrols its node at epoch 1, or as the replacement that follows "
                                    "the owner's revocation of its only node, not at epoch 4"))
                with self.assertRaisesRegex(enrol.Refused, reason):
                    commit(replace)
                self.assertEqual(self.nv_indices(), set(), "no NV index is defined before the refusal")
                self.assertEqual(self.config_inventory(*config_roots), before_config, "nothing is installed before the refusal")
                self.assertEqual(enrol.Journal(self.dir, "a").doc, before_journal)
                self.assertEqual(handed, [])
                return
            installing = enrol.install_config

            def install_config(*args, **kw):
                # regalia-kms-dx7.26: the marker is the commit's first persistent write, before node.json exists
                self.assertTrue(os.path.isfile(etc + "restore-pending"), "node.json is installed before the restore-pending marker")
                self.assertFalse(os.path.lexists(etc + "node.json"))
                return installing(*args, **kw)

            with patch.object(enrol, "install_config", install_config):
                self.assertEqual(commit("b"), (3, membership.digest(third)))
            with open(etc + "restore-pending") as f:
                self.assertEqual(json.load(f)["schema"], "regalia.restore-pending/v1")
            self.assertIn("RESTORE-PENDING:", out.getvalue())
            self.assertEqual(handed, [None], "the policy-writing sync step receives no owner authorization")
            here = node.Node(node.load(etc + "node.json"))
            self.assertEqual(here.store().load(), third)
            self.assertEqual(here.anchor().record(), (3, membership.digest(third)))
            first_counter = enrol.Journal(self.dir, "a").get("heartbeat_first")
            self.assertEqual((first_counter["sequence"], first_counter["bootstrap"], first_counter["replacement"]), (0, False, True))
            self.assertIn("FIRST HEARTBEAT: sole-node replacement: the counter starts at 0; the node signs heartbeat 1 itself",
                          out.getvalue())
            self.assertEqual(node.heartbeat_counter(here.cfg, here.run).value(), 0)

            # the node's first heartbeat, signed by itself alone: its TPM signing key, its signing counter, its own freshness
            self.assertEqual(beat.cosigners_needed(third), 0)
            now = int(time.time())
            freshness = heartbeat.Freshness(node.heartbeat_counter(here.cfg, here.run), lambda: (now, True), here.tpm_clock(),
                                            here.path("freshness.json"))
            signer, trail = node.node_beat_signer(here, pem_path=p.public), []
            proposer = beat.Proposer("a", lambda: third, freshness, lambda: (now, True), signer,
                                     lambda *asked: self.fail("no other node is asked to co-sign"), trail.append)
            envelope = proposer.propose(third, now)
            self.assertEqual((envelope["heartbeat"]["epoch"], envelope["heartbeat"]["sequence"]), (3, 1))
            self.assertEqual([s["party"] for s in envelope["signatures"]], ["a"])
            self.assertEqual(heartbeat.verify(envelope, third)["sequence"], 1)
            self.assertEqual((beat.held_sequence(freshness, third), freshness.counter.value(), signer.signed()), (1, 1, 1))
            self.assertEqual(trail[-1]["outcome"], "ALLOW")


class RestorePendingAtEnrolment(unittest.TestCase):
    """regalia-kms-dx7.26: a single-node commit without --bootstrap (a replacement disk: no live etcd history on it) writes
    /etc/regalia/restore-pending before node.json, so neither etcd nor the daemon starts at any boot until a restore has
    exchanged a store holding a raised state epoch. Genesis (--bootstrap), a resumed commit and multi-node write nothing."""

    def setUp(self):
        import tempfile
        self.d = os.path.realpath(tempfile.mkdtemp())        # enrolment follows no link on the way down (macOS: /var)
        self.addCleanup(__import__("shutil").rmtree, self.d)
        self.marker, self.node_json = self.d + "/restore-pending", self.d + "/node.json"
        self.single = {"schema": membership.SCHEMA_V5, "epoch": 3, "topology": {"profile": membership.SINGLE_NODE}}

    def hold(self, manifest_=None, bootstrap=False):
        out = io.StringIO()
        held = enrol.hold_restore_pending(manifest_ or self.single, self.marker, self.node_json, bootstrap, out)
        return held, out.getvalue()

    def test_a_replacement_writes_it_whole(self):
        held, said = self.hold()
        self.assertTrue(held)
        with open(self.marker) as f:
            doc = json.load(f)
        self.assertEqual((doc["schema"], sorted(doc)), ("regalia.restore-pending/v1", ["reason", "schema", "written_at"]))
        self.assertIn("RESTORE-PENDING: %s written" % self.marker, said)
        self.assertEqual(sorted(os.listdir(self.d)), ["restore-pending"])          # no temporary file left

    def test_genesis_writes_nothing(self):
        self.assertEqual(self.hold(dict(self.single, epoch=1), bootstrap=True), (False, ""))
        self.assertFalse(os.path.lexists(self.marker))

    def test_multi_node_writes_nothing(self):
        self.assertEqual(self.hold(dict(self.single, topology={"profile": membership.MULTI_NODE})), (False, ""))
        self.assertFalse(os.path.lexists(self.marker))

    def test_a_resumed_commit_writes_nothing(self):
        """node.json is there: an earlier run of this commit decided, before it installed node.json. A genesis resumed
        without --bootstrap is not held back."""
        with open(self.node_json, "w") as f:
            f.write("{}")
        self.assertEqual(self.hold(dict(self.single, epoch=1)), (False, ""))
        self.assertFalse(os.path.lexists(self.marker))

    def test_bootstrap_keeps_a_marker_already_there_and_says_so(self):
        with open(self.marker, "w") as f:
            f.write("{}")
        held, said = self.hold(dict(self.single, epoch=1), bootstrap=True)
        self.assertFalse(held)
        self.assertTrue(os.path.isfile(self.marker))
        self.assertIn("NOTE: %s is kept" % self.marker, said)

    def test_the_path_is_the_units_and_the_restore_s(self):
        from deploy.baremetal import restore
        self.assertEqual(enrol.RESTORE_PENDING, restore.PENDING)
        self.assertEqual(enrol.stored(enrol.RESTORE_PENDING), restore.STORED_PENDING)
