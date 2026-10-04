"""regalia-node enrol check (#190): before anything is written, the manifest must be the root-signed epoch 1
of the root whose fingerprint was typed by hand, name THIS host exactly as its identity bundle does, and
commit to the measurements document given. No TPM: the bundle is the one `init` wrote."""
import base64
import copy
import json
import os
import shutil
import tempfile
import unittest

from deploy.baremetal import enrol, measurements
from deploy.baremetal import membership as m
import tests.test_baremetal_heartbeat as hbt

WG_SERVICE, WG_BOOT = base64.b64encode(bytes(range(32))).decode(), base64.b64encode(bytes(range(32, 64))).decode()


def document(name="v1"):
    entry = {"label": "image-1", "tpm_firmware_version": "0" * 16, "pcrs": {"7": "00" * 32, "11": "a1" * 32}}
    return {"schema": measurements.SCHEMA, "name": name, "nodes": {n: {"accepted": [entry]} for n in "abc"}}


class Check(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        self.bundle = {"schema": enrol.SCHEMA_BUNDLE, "node_id": "a", "ek_public": "00", "ek_name": "000b" + "e1" * 32,
                       "ak_public": "00", "ak_name": "000b" + "e2" * 32, "ek_certificate": None,
                       "wg_service_pub": WG_SERVICE, "wg_boot_pub": WG_BOOT, "tpm_firmware_version": "0" * 16,
                       "hsm_serials": ["DENK0500001", "35718625"]}
        with open(self.d + "/bundle.json", "w") as f:
            json.dump(self.bundle, f)
        self.document = document()
        self.root = hbt.pub(hbt.ROOT)

    def manifest(self, **change_a):
        man = hbt.manifest()
        man["policy_version"] = measurements.version(self.document)
        a = man["nodes"][0]
        a.update(ek_name=self.bundle["ek_name"], ak_name=self.bundle["ak_name"],
                 wg_service_pub=bytes(range(32)).hex(), wg_boot_pub=bytes(range(32, 64)).hex(), hsm_serials=["35718625", "DENK0500001"])
        a.update(change_a)
        return man

    def envelope(self, man, key=None, signer="root"):
        key = key or hbt.ROOT
        return {"manifest": man, "signature": {"signer": signer, "key": hbt.pub(key),
                                               "sig": key.sign(m.DOMAIN + m.canonical(man)).hex()}}

    def check(self, envelope, typed=None, document=None):
        return enrol.check_manifest(self.d, envelope, self.root, typed if typed is not None else enrol.fingerprint(self.root),
                                    document or self.document)

    def refused(self, reason, *args, **kw):
        with self.assertRaises(enrol.Refused) as caught:
            self.check(*args, **kw)
        self.assertIn(reason, str(caught.exception))

    def test_the_manifest_lists_exactly_this_hosts_tokens(self):
        """#363: the daemon serves only from tokens the manifest lists, so commit and check hold it to the ones init read."""
        self.refused("are not this host's tokens", self.envelope(self.manifest(hsm_serials=["DENK0500001"])))
        self.refused("are not this host's tokens", self.envelope(self.manifest(hsm_serials=["DENK0500001", "35718625", "DENK0599999"])))
        with open(self.d + "/bundle.json", "w") as f:
            json.dump({k: v for k, v in self.bundle.items() if k != "hsm_serials"}, f)
        self.refused("it was made before #363", self.envelope(self.manifest()))

    def test_the_manifest_that_names_this_host_is_accepted(self):
        man = self.manifest()
        self.assertEqual(self.check(self.envelope(man)), man)
        # the fingerprint may be typed in groups, with colons or in upper case
        fp = enrol.fingerprint(self.root).upper()
        self.check(self.envelope(man), typed=" ".join(fp[i:i + 4] for i in range(0, 64, 4)))

    def test_a_v4_manifest_names_this_hosts_signing_key(self):
        """#199: under v4 the node entry's signing_key must be the one this host made (its bundle's), as every other
        identity is; a bundle made before #199 has none and is refused for a v4 manifest."""
        from tests import test_baremetal_membership_v4 as v4
        man = v4.manifest4(1, "", v4.nodes4(), policy_version=measurements.version(self.document))
        man["nodes"][0].update(hsm_serials=self.bundle["hsm_serials"])
        man["nodes"][0].update(ek_name=self.bundle["ek_name"], ak_name=self.bundle["ak_name"],
                               wg_service_pub=bytes(range(32)).hex(), wg_boot_pub=bytes(range(32, 64)).hex())
        mine = man["nodes"][0]["signing_key"]["key"]
        self.refused("this host's bundle has no signing key: it was made before #199", self.envelope(man))
        for point, accepted in ((v4.typed(v4.NODE_KEYS["b"])["key"], False), (mine, True)):
            with open(self.d + "/bundle.json", "w") as f:
                json.dump(dict(self.bundle, signing_key=point), f)
            if accepted:
                self.assertEqual(self.check(self.envelope(man)), man)
            else:
                self.refused("the manifest's signing_key for a is not this host's", self.envelope(man))

    def test_a_signing_key_a_manifest_before_v4_does_not_name_is_said(self):
        """51's read of #358: a host with a signing key checked against a v3 (or older) manifest passes, and is told its key
        waits for v4."""
        man = self.manifest()
        self.check(self.envelope(man))
        self.assertIsNone(enrol.signing_note(self.d, man))                   # a bundle from before #199: nothing to say
        with open(self.d + "/bundle.json", "w") as f:
            json.dump(dict(self.bundle, signing_key="04" + "ab" * 64), f)
        self.assertEqual(self.check(self.envelope(man)), man)
        self.assertIn("names no signing key for a; this host's key at 0x81010003", enrol.signing_note(self.d, man))

    def test_the_fingerprint_typed_must_be_the_root_keys(self):
        other = enrol.fingerprint(hbt.pub(hbt.OTHER))
        self.refused("is not the one typed", self.envelope(self.manifest()), typed=other)
        self.refused("not 64 hex digits", self.envelope(self.manifest()), typed="1234")

    def test_only_the_root_signed_epoch_one_is_accepted(self):
        self.refused("manifest chain is refused", self.envelope(self.manifest(), key=hbt.OTHER))
        self.refused("manifest chain is refused", self.envelope(self.manifest(), key=hbt.REVOKE, signer="revocation"))
        later = dict(self.manifest(), epoch=2, prev_digest="00" * 32)
        self.refused("first manifest must be the root-signed epoch 1", self.envelope(later))
        tampered = self.envelope(self.manifest())
        tampered["manifest"]["nodes"][1]["state"] = "QUARANTINED"
        self.refused("manifest chain is refused", tampered)

    def test_each_identity_must_be_this_hosts(self):
        for field, value in (("ek_name", "000b" + "33" * 32), ("ak_name", "000b" + "44" * 32),
                             ("wg_service_pub", "55" * 32), ("wg_boot_pub", "66" * 32)):
            with self.subTest(field=field):
                self.refused("manifest's %s for a is not this host's" % field, self.envelope(self.manifest(**{field: value})))

    def test_a_manifest_that_does_not_name_this_host_or_names_it_unenrolled(self):
        man = self.manifest()
        man["nodes"][0]["node_id"] = "z"
        self.refused("does not name this host", self.envelope(man))
        self.refused("not enrolled", self.envelope(self.manifest(state="QUARANTINED")))

    def test_the_measurements_must_be_the_ones_the_manifest_commits_to(self):
        self.refused("measurements are refused", self.envelope(self.manifest()), document=document("v2"))

    def test_nothing_is_written(self):
        before = sorted(os.listdir(self.d))
        self.check(self.envelope(self.manifest()))
        self.assertEqual(sorted(os.listdir(self.d)), before)


    def test_a_host_first_named_at_a_later_epoch_enrols_on_the_whole_chain(self):
        """A fourth node, or a replacement (#76): not in epoch 1, named first at epoch 3 by the root."""
        first = self.manifest()
        first["nodes"] = first["nodes"][1:]                         # epoch 1: b and c only
        second = dict(copy.deepcopy(first), epoch=2, prev_digest=m.digest(first))
        third = dict(copy.deepcopy(second), epoch=3, prev_digest=m.digest(second))
        third["nodes"] = [self.manifest()["nodes"][0]] + third["nodes"]
        chain = [self.envelope(first), self.envelope(second), self.envelope(third)]
        self.assertEqual(self.check(chain)["epoch"], 3)
        self.refused("does not name this host", chain[:2])          # a chain that stops before it
        # a revocation-signed epoch cannot add a node (only the root can): the chain is refused
        revoked = dict(copy.deepcopy(third), epoch=3)
        self.refused("manifest chain is refused", [chain[0], chain[1], self.envelope(revoked, key=hbt.REVOKE, signer="revocation")])
        # and a chain whose last epoch dropped this host, by a revocation, does not enrol it
        fourth = dict(copy.deepcopy(third), epoch=4, prev_digest=m.digest(third))
        fourth["nodes"][0]["state"] = "QUARANTINED"
        self.refused("not enrolled", chain + [self.envelope(fourth, key=hbt.REVOKE, signer="revocation")])

    def replacement_chain(self, retire="x", extra=None):
        """epoch 1: x, b, c. epoch 2, root-signed: x RETIRED, this host (a) added; `extra` changes it further."""
        first = self.manifest()
        first["nodes"][0] = hbt.node("x", "ACTIVE", 7)
        second = dict(copy.deepcopy(first), epoch=2, prev_digest=m.digest(first))
        for entry in second["nodes"]:
            if entry["node_id"] == retire:
                entry["state"] = "RETIRED"
        second["nodes"].insert(0, self.manifest()["nodes"][0])
        if extra:
            extra(second)
        return [self.envelope(first), self.envelope(second)]

    def test_a_replacement_is_enrolled_only_as_the_replacement_typed(self):
        """#76: the manifest that first names this host retires x. Without --replace it is refused (never a plain
        addition by accident); with --replace x it is checked by replacement's rules; another ID is refused."""
        chain = self.replacement_chain()
        check = lambda replace: enrol.check_manifest(self.d, chain, self.root, enrol.fingerprint(self.root), self.document, replace)  # noqa: E731
        with self.assertRaisesRegex(enrol.Refused, "it is a replacement, enrolled only with `commit --replace x`"):
            check(None)
        self.assertEqual(check("x")["epoch"], 2)
        with self.assertRaisesRegex(enrol.Refused, "does not replace b .it retires x.: not the replacement typed"):
            check("b")

    def test_a_replacement_that_changes_anything_else_is_refused(self):
        def change_b(manifest):
            manifest["nodes"][2]["wg_service_pub"] = "5d" * 32
        chain = self.replacement_chain(extra=change_b)
        with self.assertRaisesRegex(enrol.Refused, "the replacement of x by a is refused: a replacement does not change b"):
            enrol.check_manifest(self.d, chain, self.root, enrol.fingerprint(self.root), self.document, "x")

    def test_an_addition_or_a_founding_node_is_not_a_replacement(self):
        with self.assertRaisesRegex(enrol.Refused, "a is named from epoch 1: it replaces nobody"):
            enrol.check_manifest(self.d, self.envelope(self.manifest()), self.root, enrol.fingerprint(self.root), self.document, "x")

    def test_a_malformed_bundle_is_a_refusal(self):
        with open(self.d + "/bundle.json", "w") as f:
            json.dump({"schema": enrol.SCHEMA_BUNDLE, "node_id": "a"}, f)
        self.refused("not a complete identity bundle", self.envelope(self.manifest()))

    def test_the_fingerprint_is_read_from_a_terminal_only(self):
        """`enrol check < file` would make a file a trust anchor again."""
        for name, content in (("manifest.json", self.envelope(self.manifest())), ("doc.json", self.document)):
            with open(os.path.join(self.d, name), "w") as f:
                json.dump(content, f)
        import io
        import sys as _sys
        import unittest.mock
        with unittest.mock.patch.object(_sys, "stdin", io.StringIO(enrol.fingerprint(self.root) + "\n")), \
                unittest.mock.patch.object(_sys, "stderr", io.StringIO()) as err:
            code = enrol.main(["check", "--manifest", self.d + "/manifest.json", "--root-key", self.root,
                               "--measurements", self.d + "/doc.json", "--enrol-dir", self.d])
        self.assertEqual(code, 1)
        self.assertIn("standard input is not a terminal", err.getvalue())


if __name__ == "__main__":
    unittest.main()
