"""deploy/baremetal/bootcreds.py (#66): the boot credentials a host's initrd reads, rendered from the signed
manifest and the site config. Deterministic (a peer recomputes them, and from them PCR 12), composed of the
renderers that already exist, and handed out by esp_files only for a chain that verifies."""
import copy
import json
import unittest

from deploy.baremetal import bootcreds, bootnet, espcreds, sitecfg, unlock
from deploy.baremetal import membership as m
import tests.test_baremetal_bootnet as bn
import tests.test_baremetal_heartbeat as hbt

DEVICE = "/dev/disk/by-partlabel/regalia-root"


def sign(manifest, key=hbt.ROOT, signer="root"):
    return {"manifest": manifest, "signature": {"signer": signer, "key": hbt.pub(key),
                                                "sig": key.sign(m.DOMAIN + m.canonical(manifest)).hex()}}


def chain(*manifests):
    """Root-signed envelopes, each chained to the one before."""
    out, prev = [], ""
    for epoch, man in enumerate(manifests, 1):
        man = dict(man, epoch=epoch, prev_digest=prev)
        out.append(sign(man))
        prev = m.digest(man)
    return out


class Render(unittest.TestCase):
    def setUp(self):
        self.cfg = sitecfg.validate(bn.site())
        self.m1 = hbt.manifest()

    def test_the_four_credentials_are_the_existing_renderers_output(self):
        files = bootcreds.render(self.m1, self.cfg, DEVICE)
        self.assertEqual(sorted(files), sorted(bootcreds.RENDERED))
        self.assertEqual(json.loads(files["regalia.unlock-config"]),
                         unlock.boot_config(self.m1, "a", DEVICE, [7, 11, 12], bootnet.unlock_endpoints(self.cfg, self.m1)))
        self.assertEqual(files["regalia.unlock-config"], m.canonical(json.loads(files["regalia.unlock-config"])))     # canonical bytes
        self.assertEqual(files["regalia.wg-boot-conf"], bootnet.boot_wg_conf(self.cfg, self.m1).encode())
        self.assertEqual(files["regalia.boot-nft"], bootnet.boot_ruleset(self.cfg, self.m1).encode())
        self.assertEqual(files["regalia.boot-env"], b"BOOT_NIC_MAC=52:54:00:12:34:56\nBOOT_ADDRESS=192.0.2.10/32\nBOOT_GATEWAY=\nBOOT_TUNNEL=10.89.0.1\n")
        for body in files.values():
            self.assertIsInstance(body, bytes)

    def test_boot_env_carries_the_prefix_and_the_gateway(self):
        routed = sitecfg.validate(bn.site(prefix=24, gateway="192.0.2.1"))
        self.assertEqual(bootcreds.boot_env(routed), b"BOOT_NIC_MAC=52:54:00:12:34:56\nBOOT_ADDRESS=192.0.2.10/24\nBOOT_GATEWAY=192.0.2.1\nBOOT_TUNNEL=10.89.0.1\n")
        single = sitecfg.validate(dict(bn.site(), boot_mesh=None))
        with self.assertRaisesRegex(m.Refused, "single-site host"):
            bootcreds.boot_env(single)

    def test_deterministic_across_equal_inputs_and_sensitive_to_every_one(self):
        files = bootcreds.render(self.m1, self.cfg, DEVICE)
        self.assertEqual(files, bootcreds.render(copy.deepcopy(self.m1), sitecfg.validate(bn.site()), DEVICE))
        changed = {"a peer quarantined": bootcreds.render(hbt.manifest(c="QUARANTINED"), self.cfg, DEVICE),
                   "another card": bootcreds.render(self.m1, sitecfg.validate(bn.site(nic_mac="52:54:00:12:34:57")), DEVICE),
                   "another device": bootcreds.render(self.m1, self.cfg, "/dev/sda2")}
        for label, other in changed.items():
            with self.subTest(label):
                self.assertNotEqual(espcreds.pcr12({n + ".cred": b for n, b in files.items()}),
                                    espcreds.pcr12({n + ".cred": b for n, b in other.items()}))

    def test_a_manifest_that_leaves_no_peer_is_refused(self):
        with self.assertRaisesRegex(m.Refused, "no peer"):
            bootcreds.render(hbt.manifest(b="RETIRED", c="REVOKED_STOLEN"), self.cfg, DEVICE)


class EspFiles(unittest.TestCase):
    def setUp(self):
        self.cfg = sitecfg.validate(bn.site())
        self.root = hbt.pub(hbt.ROOT)

    def test_the_files_of_the_chain_current_manifest_under_loader_credentials(self):
        envelopes = chain(hbt.manifest(), hbt.manifest(c="QUARANTINED"))
        files = bootcreds.esp_files(self.cfg, envelopes, self.root, DEVICE)
        current = m.accept_chain(None, envelopes, self.root)
        self.assertEqual(files, {"loader/credentials/%s.cred" % n: b for n, b in bootcreds.render(current, self.cfg, DEVICE).items()})
        self.assertNotIn("# c", files["loader/credentials/regalia.wg-boot-conf.cred"].decode())        # the current manifest's, not epoch 1's
        # what espcreds measures from the ESP is what a peer computes from esp_files
        self.assertEqual(espcreds.pcr12({k.rsplit("/", 1)[1]: v for k, v in files.items()}),
                         espcreds.pcr12({n + ".cred": b for n, b in bootcreds.render(current, self.cfg, DEVICE).items()}))

    def test_nothing_for_a_chain_that_does_not_verify(self):
        good = chain(hbt.manifest(), hbt.manifest(c="QUARANTINED"))
        tampered = copy.deepcopy(good)
        tampered[1]["manifest"]["nodes"][2]["state"] = "ACTIVE"
        other = chain(hbt.manifest())
        other[0]["signature"] = sign(other[0]["manifest"], hbt.OTHER)["signature"]
        cases = {"a tampered manifest": (tampered, self.root, "does not verify"),
                 "another root": (other, self.root, "not the pinned root"),
                 "a gap in the chain": ([good[1]], self.root, "the first manifest must be the root-signed epoch 1"),
                 "no chain": ([], self.root, "non-empty list"),
                 "not a list": (good[0], self.root, "non-empty list")}
        for label, (envelopes, root, why) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(m.Refused, why):
                    bootcreds.esp_files(self.cfg, envelopes, root, DEVICE)


if __name__ == "__main__":
    unittest.main()
