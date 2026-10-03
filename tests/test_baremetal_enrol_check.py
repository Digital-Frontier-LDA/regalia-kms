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
                       "wg_service_pub": WG_SERVICE, "wg_boot_pub": WG_BOOT, "tpm_firmware_version": "0" * 16}
        with open(self.d + "/bundle.json", "w") as f:
            json.dump(self.bundle, f)
        self.document = document()
        self.root = hbt.pub(hbt.ROOT)

    def manifest(self, **change_a):
        man = hbt.manifest()
        man["policy_version"] = measurements.version(self.document)
        a = man["nodes"][0]
        a.update(ek_name=self.bundle["ek_name"], ak_name=self.bundle["ak_name"],
                 wg_service_pub=bytes(range(32)).hex(), wg_boot_pub=bytes(range(32, 64)).hex())
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

    def test_the_manifest_that_names_this_host_is_accepted(self):
        man = self.manifest()
        self.assertEqual(self.check(self.envelope(man)), man)
        # the fingerprint may be typed in groups, with colons or in upper case
        fp = enrol.fingerprint(self.root).upper()
        self.check(self.envelope(man), typed=" ".join(fp[i:i + 4] for i in range(0, 64, 4)))

    def test_the_fingerprint_typed_must_be_the_root_keys(self):
        other = enrol.fingerprint(hbt.pub(hbt.OTHER))
        self.refused("is not the one typed", self.envelope(self.manifest()), typed=other)
        self.refused("not 64 hex digits", self.envelope(self.manifest()), typed="1234")

    def test_only_the_root_signed_epoch_one_is_accepted(self):
        self.refused("manifest is refused", self.envelope(self.manifest(), key=hbt.OTHER))
        self.refused("manifest is refused", self.envelope(self.manifest(), key=hbt.REVOKE, signer="revocation"))
        later = dict(self.manifest(), epoch=2, prev_digest="00" * 32)
        self.refused("first manifest must be the root-signed epoch 1", self.envelope(later))
        tampered = self.envelope(self.manifest())
        tampered["manifest"]["nodes"][1]["state"] = "QUARANTINED"
        self.refused("manifest is refused", tampered)

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


if __name__ == "__main__":
    unittest.main()
