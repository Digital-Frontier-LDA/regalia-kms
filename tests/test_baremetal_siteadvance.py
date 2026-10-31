"""deploy/baremetal/siteadvance.py: which accepted set a node will boot on after its site document changes
(#615). The sets are built here and passed through attest.validate_sets first, as a manifest's are, so
nothing below judges a set the real validator would have refused."""
import unittest

from deploy.baremetal import attest, siteadvance

FW = "2019102300163636"
OLD_SITE, NEW_SITE = "a1" * 32, "b2" * 32        # PCR 12 under the current and the new site document
PHASES = {"initrd": {"11": "c3" * 32}, "system": {"11": "d4" * 32}}


def a_set(label, pcr12, fw=FW, phases=PHASES, pcr7="77" * 32):
    return {"label": label, "tpm_firmware_version": fw, "pcrs": {"7": pcr7, "12": pcr12}, "phases": phases}


def accepted(*sets):
    """`sets` as attest.validate_sets accepts them, or a failing test if it does not."""
    attest.validate_sets(list(sets), "nodes.a")
    return list(sets)


class TargetTests(unittest.TestCase):
    def test_epoch_n_accepts_the_new_site_document(self):
        # the move's first epoch: the set the node booted on, and the same set with the new PCR 12
        sets = accepted(a_set("current", OLD_SITE), a_set("moved", NEW_SITE))
        self.assertEqual(siteadvance.target(sets, "current", NEW_SITE), "moved")

    def test_a_reboot_between_epoch_n_and_the_site_change_stays_on_its_set(self):
        # epoch N is anchored, the site document is not yet written: the node boots on its old set, and the
        # document it still measures keeps matching that set
        sets = accepted(a_set("current", OLD_SITE), a_set("moved", NEW_SITE))
        self.assertEqual(siteadvance.target(sets, "current", OLD_SITE), "current")

    def test_a_rerun_after_the_write_is_accepted(self):
        # the document is written and the node rebooted onto the new set: running again changes nothing
        sets = accepted(a_set("current", OLD_SITE), a_set("moved", NEW_SITE))
        self.assertEqual(siteadvance.target(sets, "moved", NEW_SITE), "moved")

    def test_an_old_set_listed_again_in_a_higher_epoch_is_accepted(self):
        # an aborted move undone: after the retire epoch the root lists the old site's set again, in a NEW
        # epoch. The TPM high-water refuses a lower epoch, not this, and neither does the reader.
        sets = accepted(a_set("moved", NEW_SITE), a_set("back", OLD_SITE))
        self.assertEqual(siteadvance.target(sets, "moved", OLD_SITE), "back")

    def test_a_site_document_the_root_has_not_approved_is_refused(self):
        # one set, no epoch N yet: the new PCR 12 is in no accepted set
        sets = accepted(a_set("current", OLD_SITE))
        with self.assertRaisesRegex(attest.Refused, "has not approved this site document"):
            siteadvance.target(sets, "current", NEW_SITE)

    def test_a_pcr_12_in_neither_set_is_refused(self):
        sets = accepted(a_set("current", OLD_SITE), a_set("moved", NEW_SITE))
        with self.assertRaisesRegex(attest.Refused, "has not approved this site document"):
            siteadvance.target(sets, "current", "e5" * 32)

    def test_an_image_update_in_flight_is_refused_even_when_pcr_12_matches(self):
        # NEXT is another image (PCR 11 differs) that happens to carry the new PCR 12: matching PCR 12 alone
        # would write a document whose boot, on this image, no peer accepts
        nxt = a_set("next-image", NEW_SITE, phases={"initrd": {"11": "e6" * 32}, "system": {"11": "f7" * 32}})
        sets = accepted(a_set("current", OLD_SITE), nxt)
        with self.assertRaisesRegex(attest.Refused, "image update is rolling through"):
            siteadvance.target(sets, "current", NEW_SITE)

    def test_each_measurement_but_pcr_12_must_be_the_booted_sets(self):
        # one test per field a site change must leave alone, so no one of them can drop out of the comparison
        for name, other in (("firmware", a_set("next", NEW_SITE, fw="2020010100000001")),
                            ("PCR 7", a_set("next", NEW_SITE, pcr7="78" * 32)),
                            ("PCR 11, initrd", a_set("next", NEW_SITE, phases={"initrd": {"11": "e6" * 32}, "system": PHASES["system"]})),
                            ("PCR 11, system", a_set("next", NEW_SITE, phases={"initrd": PHASES["initrd"], "system": {"11": "f7" * 32}}))):
            with self.subTest(name):
                sets = accepted(a_set("current", OLD_SITE), other)
                with self.assertRaisesRegex(attest.Refused, "image update is rolling through"):
                    siteadvance.target(sets, "current", NEW_SITE)

    def test_a_signing_key_change_is_an_image_update(self):
        signed = dict(a_set("current", OLD_SITE), signing={"initrd": "01" * 32, "system": "02" * 32, "secure_boot_cert": "03" * 32})
        resigned = dict(a_set("next", NEW_SITE), signing={"initrd": "01" * 32, "system": "04" * 32, "secure_boot_cert": "03" * 32})
        sets = accepted(signed, resigned)
        with self.assertRaisesRegex(attest.Refused, "image update is rolling through"):
            siteadvance.target(sets, "current", NEW_SITE)

    def test_the_booted_set_must_be_accepted(self):
        sets = accepted(a_set("current", OLD_SITE))
        with self.assertRaisesRegex(attest.Refused, "not one of its accepted sets"):
            siteadvance.target(sets, "retired", OLD_SITE)

    def test_a_set_without_pcr_12_cannot_judge_a_site_change(self):
        sets = accepted({"label": "current", "tpm_firmware_version": FW, "pcrs": {"7": "77" * 32}, "phases": PHASES})
        with self.assertRaisesRegex(attest.Refused, "does not attest PCR 12"):
            siteadvance.target(sets, "current", NEW_SITE)

    def test_the_predicted_pcr_12_must_be_a_digest(self):
        sets = accepted(a_set("current", OLD_SITE))
        for bad in (OLD_SITE.upper(), OLD_SITE[:-2], OLD_SITE + "00", None, 12):
            with self.subTest(bad=bad), self.assertRaisesRegex(attest.Refused, "64 lowercase hex"):
                siteadvance.target(sets, "current", bad)


class ValidatorStaysOpenTests(unittest.TestCase):
    """The rule above is site-advance's alone. attest.validate_sets judges every manifest, and an image
    update's CURRENT and NEXT differ in the firmware and PCR 11 by design: tightening the validator to the
    site rule would refuse every image update."""

    def test_an_image_update_pair_is_still_accepted(self):
        nxt = a_set("next-image", OLD_SITE, fw="2020010100000001", phases={"initrd": {"11": "e6" * 32}, "system": {"11": "f7" * 32}})
        attest.validate_sets([a_set("current", OLD_SITE), nxt], "nodes.a")

    def test_a_third_set_is_refused(self):
        # the cap that makes a move and an image update exclusive
        sets = [a_set("current", OLD_SITE), a_set("moved", NEW_SITE), a_set("third", "e5" * 32)]
        with self.assertRaisesRegex(attest.Refused, "one or two measurement sets"):
            attest.validate_sets(sets, "nodes.a")


if __name__ == "__main__":
    unittest.main()
