"""deploy/baremetal/bootcreds.py (#66): the boot credentials a host's initrd reads, rendered from the signed
manifest and the site config. Deterministic (a peer recomputes them, and from them PCR 12), composed of the
renderers that already exist, and handed out by esp_files only for a chain that verifies."""
import copy
import json
import shutil
import tempfile
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
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.tpm = hbt.FakeTpm()
        self.anchor = m.HighWater("0x1500016", run=self.tpm, lock_path=d + "/hw.lock")
        self.anchor.define()

    def anchor_to(self, envelopes):
        """This host's TPM anchored through `envelopes`, as Store does after it accepts each."""
        digests = m.Store._digests([m.accept_chain(None, envelopes[:i], self.root) for i in range(1, len(envelopes) + 1)])
        for epoch in range(1, len(envelopes) + 1):
            self.anchor.anchor(epoch, digests)

    def test_the_site_document_the_chain_and_the_earlier_stage_removed(self):
        """#66 B3: the ESP holds the measured site document and the signed chain (not measured), and the four
        credentials an earlier stage rendered are removed (None): the initrd renders them from the chain."""
        envelopes = chain(hbt.manifest(), hbt.manifest(c="QUARANTINED"))
        self.anchor_to(envelopes)
        files = bootcreds.esp_files(self.cfg, envelopes, self.root, DEVICE, self.anchor)
        self.assertEqual(files, {**{"loader/credentials/%s.cred" % n: None for n in bootcreds.RENDERED},
                                 "loader/credentials/regalia.site.cred": bootcreds.site_document(self.cfg, DEVICE),
                                 "EFI/regalia/membership.json": m.canonical(envelopes)})
        self.assertEqual(list(files), sorted(files))
        # what the initrd reads back: the same chain (from the root, against the anchor), the same site
        self.assertEqual(bootcreds.anchored(m.load(files["EFI/regalia/membership.json"], m.MAX_CHAIN_BYTES), self.root, self.anchor),
                         m.accept_chain(None, envelopes, self.root))
        self.assertEqual(bootcreds.read_site(files["loader/credentials/regalia.site.cred"]), (self.cfg_site(), DEVICE))
        # PCR 12 measures the site document only: a membership change does not move it
        moved = chain(hbt.manifest(), hbt.manifest(c="QUARANTINED"), hbt.manifest())   # c back, by the root
        self.anchor.anchor(3, m.Store._digests([m.accept_chain(None, moved[:i], self.root) for i in range(1, 4)]))
        later = bootcreds.esp_files(self.cfg, moved, self.root, DEVICE, self.anchor)
        measured = lambda f: espcreds.pcr12({k.rsplit("/", 1)[1]: v for k, v in f.items() if k.startswith("loader/credentials/") and v is not None})
        self.assertEqual(measured(later), measured(files))
        self.assertNotEqual(later["EFI/regalia/membership.json"], files["EFI/regalia/membership.json"])

    def cfg_site(self):
        """The site read_site gives back for self.cfg: host_ipv4 and boot_mesh."""
        return {"host_ipv4": self.cfg["host_ipv4"], "boot_mesh": self.cfg["boot_mesh"]}

    def test_a_chain_that_leaves_the_host_no_peer_writes_nothing(self):
        """esp_files renders what the initrd will render, and refuses as it would: nothing is written for a chain
        the host would boot to the recovery prompt under."""
        envelopes = chain(hbt.manifest(), hbt.manifest(b="RETIRED", c="REVOKED_STOLEN"))
        self.anchor_to(envelopes)
        with self.assertRaises(m.Refused):
            bootcreds.esp_files(self.cfg, envelopes, self.root, DEVICE, self.anchor)

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
                    bootcreds.esp_files(self.cfg, envelopes, root, DEVICE, self.anchor)

    def test_nothing_for_a_validly_signed_chain_the_tpm_did_not_anchor(self):
        """The writer applies the initrd's rule: a stale chain (a restored disk, a withheld update) would render
        an older manifest's peers, a node revoked since among them; a fork is a substitution."""
        # c may authorize at epochs 1 and 2, and is revoked as stolen at 3
        current = chain(hbt.manifest(), hbt.manifest(a="MAINTENANCE"), hbt.manifest(a="MAINTENANCE", c="REVOKED_STOLEN"))
        self.anchor_to(current)
        stale = current[:2]                                   # signed by the root, and c still a peer in it
        self.assertIn("# c", bootcreds.render(m.accept_chain(None, stale, self.root), self.cfg, DEVICE)["regalia.wg-boot-conf"].decode())
        with self.assertRaisesRegex(m.Refused, "ROLLBACK: the chain ends at epoch 2 but the TPM high-water is 3"):
            bootcreds.esp_files(self.cfg, stale, self.root, DEVICE, self.anchor)
        fork = chain(hbt.manifest(), hbt.manifest(a="MAINTENANCE"), hbt.manifest(a="MAINTENANCE", c="RETIRED"))    # another epoch 3, root-signed
        with self.assertRaisesRegex(m.Refused, "CONFLICT: the manifest at epoch 3 is not the one this node's TPM recorded"):
            bootcreds.esp_files(self.cfg, fork, self.root, DEVICE, self.anchor)
        ahead = chain(hbt.manifest(), hbt.manifest(a="MAINTENANCE"), hbt.manifest(a="MAINTENANCE", c="REVOKED_STOLEN"), hbt.manifest(c="REVOKED_STOLEN"))
        written = bootcreds.esp_files(self.cfg, ahead, self.root, DEVICE, self.anchor)["EFI/regalia/membership.json"]
        self.assertNotIn("# c", bootcreds.render(m.accept_chain(None, m.load(written, m.MAX_CHAIN_BYTES), self.root), self.cfg, DEVICE)["regalia.wg-boot-conf"].decode())
        # a commit between the floor and the verify (value() read before the TPM moved on): a ROLLBACK, not a crash
        stale_value, self.anchor.value = self.anchor.value, lambda: 2
        with self.assertRaisesRegex(m.Refused, "ROLLBACK: the chain ends at epoch 2 but the TPM recorded epoch 3"):
            bootcreds.esp_files(self.cfg, stale, self.root, DEVICE, self.anchor)
        self.anchor.value = stale_value
        self.tpm.broken = True
        with self.assertRaisesRegex(m.Refused, "does not answer"):
            bootcreds.esp_files(self.cfg, current, self.root, DEVICE, self.anchor)


if __name__ == "__main__":
    unittest.main()


class SiteDocument(unittest.TestCase):
    """regalia.site: what the initrd needs of the site configuration (B3), measured, read back strictly."""

    def test_written_canonical_and_read_back_to_the_same_render(self):
        cfg = sitecfg.validate(bn.site(prefix=24, gateway="192.0.2.1"))
        raw = bootcreds.site_document(cfg, DEVICE)
        self.assertEqual(raw, m.canonical(json.loads(raw)))
        self.assertEqual(sorted(json.loads(raw)), sorted(bootcreds.SITE_KEYS))
        site, device = bootcreds.read_site(raw)
        self.assertEqual(device, DEVICE)
        self.assertEqual(bootcreds.render(hbt.manifest(), site, device), bootcreds.render(hbt.manifest(), cfg, DEVICE))
        self.assertEqual(raw, bootcreds.site_document(sitecfg.validate(bn.site(prefix=24, gateway="192.0.2.1")), DEVICE))   # deterministic

    def test_refused(self):
        good = json.loads(bootcreds.site_document(sitecfg.validate(bn.site()), DEVICE))

        def doc(fn):
            d = copy.deepcopy(good)
            fn(d)
            return m.canonical(d)
        cases = {"not canonical": (json.dumps(good).encode(), "canonical"),
                 "a newline": (m.canonical(good) + b"\n", "canonical"),
                 "another schema": (doc(lambda d: d.update(schema="x")), "schema must be"),
                 "an extra field": (doc(lambda d: d.update(extra=1)), "fields mismatch"),
                 "a device with a space": (doc(lambda d: d.update(device="a b")), "device must be a plain path"),
                 "no boot_mesh": (doc(lambda d: d.update(boot_mesh=None)), "must not be null"),
                 "an upper-case MAC": (doc(lambda d: d["boot_mesh"].update(nic_mac="52:54:00:AB:CD:01")), "nic_mac must be a unicast MAC"),
                 "a gateway off the link": (doc(lambda d: d["boot_mesh"].update(prefix=24, gateway="192.0.3.1")), "gateway must be another address"),
                 "the tunnel at the host": (doc(lambda d: d["boot_mesh"].update(address="192.0.2.10")), "not host_ipv4"),
                 "oversized": (b" " * (bootcreds.SITE_MAX_BYTES + 1), "at most")}
        for label, (raw, why) in cases.items():
            with self.subTest(label):
                with self.assertRaisesRegex(m.Refused, why):
                    bootcreds.read_site(raw)
        with self.assertRaisesRegex(m.Refused, "single-site host"):
            bootcreds.site_document(sitecfg.validate(dict(bn.site(), boot_mesh=None)), DEVICE)
