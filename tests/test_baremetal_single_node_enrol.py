"""dx7.10.1: single-node genesis through owner-authorized commit on a software TPM.

The v4 three-node control stays in test_baremetal_enrol. Cards and the signed image are
fixtures; challenge/activation, proposal validation, policy writes and the TPM anchor are real.
"""
import base64
import copy
import io
import json
import os
import re
import subprocess
import unittest
from unittest.mock import patch

from deploy.baremetal import bootnet, enrol, manifest, measurements, membership, node, ownerauth, signkey
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

    def test_mutant_wrong_topology_is_refused(self):
        self.ceremony("wrong-topology")

    def test_mutant_second_enrolment_after_single_node_genesis_is_refused(self):
        self.ceremony("second-enrolment")

    def nv_indices(self):
        result = subprocess.run(["tpm2_getcap", "handles-nv-index"], check=True, capture_output=True, text=True)
        return {int(h, 16) for h in re.findall(r"0x[0-9a-fA-F]+", result.stdout)}

    def ceremony(self, mutant=None):
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
        args = ["propose", "--genesis", "--topology", "multi-node" if mutant == "wrong-topology" else "single-node",
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
        handed = []

        def in_process(config, chain, owner_auth=None):
            handed.append(owner_auth)
            return enrol.anchor_and_store(config, chain, owner_auth=owner_auth)

        given = ownerauth.read_value(io.BytesIO((value + "\n").encode())), record
        with patch.object(enrol, "CONFIG_DIR", etc), patch.object(enrol, "NODE_JSON", etc + "node.json"), \
                patch.object(enrol, "CHRONY_CONF", self.d + "/etc-chrony/regalia.conf"), \
                patch.object(signkey, "PCR_PUBLIC_KEY_PATH", public), patch.object(signkey, "PCR_SIGNATURE_PATHS", (signature_path,)):
            def commit(chain=envelope, authorization=given):
                return enrol.commit(self.dir, chain, root, enrol.fingerprint(root), document, site, example,
                                    as_sync=in_process, out=io.StringIO(), bootstrap=True, ownerauth_given=authorization,
                                    probe=lambda config: ([], ["no other node exists"]))

            if mutant == "without-owner-auth":
                with self.assertRaisesRegex(enrol.Refused, "the TPM's owner authorization is set and enrolment takes it"):
                    commit(authorization=None)
                self.assertEqual(self.nv_indices(), set())
                self.assertEqual(handed, [])
                self.assertFalse(os.path.exists(etc + "node.json"))
                # Positive control: the very same inputs commit once the authorization is supplied.
            epoch, digest = commit()
            self.assertEqual((epoch, digest), (1, membership.digest(man)))
            self.assertEqual(handed, [None], "the policy-writing sync step receives no owner authorization")
            here = node.Node(node.load(etc + "node.json"))
            self.assertEqual((here.anchor().value(), here.anchor().record()), (1, (1, digest)))
            self.assertEqual(here.store().load(), man)
            self.assertTrue({int(example[k], 16) for k in ("nv_epoch", "nv_heartbeat", "nv_signing")} <= self.nv_indices())
            area = subprocess.run(["tpm2_nvreadpublic", example["nv_epoch"]], check=True, capture_output=True, text=True).stdout
            self.assertIn("authorization policy: " + signkey.policy(pem).hex().upper(), area)
            self.assertTrue(enrol.Journal(self.dir, "a").get("heartbeat_first")["bootstrap"])
            self.assertEqual(bootnet.unlock_endpoints(site, man), {"owner": "10.89.0.9:7443"})
            wg = bootnet.boot_wg_conf(site, man)
            self.assertEqual(wg.count("[Peer]"), 1)
            self.assertIn(base64.b64encode(bytes.fromhex(man["owner_wg_pub"])).decode(), wg)

            if mutant == "second-enrolment":
                second = dict(copy.deepcopy(man), epoch=2, prev_digest=digest, issued_at="2026-10-05T12:00:00Z")
                chain = [envelope, tm.sign(second, tm.ROOT)]
                self.assertEqual(membership.accept_chain(None, chain, root), second, "the chain itself is valid")
                before = enrol.Journal(self.dir, "a").doc
                with self.assertRaisesRegex(enrol.Refused, "a single-node manifest enrols its node only at epoch 1 for now, not epoch 2"):
                    commit(chain)
                self.assertEqual(enrol.Journal(self.dir, "a").doc, before)
                self.assertEqual(here.store().load(), man)
                self.assertEqual(here.anchor().record(), (1, digest))
                self.assertEqual(handed, [None])
