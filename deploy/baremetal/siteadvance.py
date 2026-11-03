#!/usr/bin/env python3
"""Which accepted measurement set a node will boot on after its site document changes (#615, the reader).

A node's site document, regalia.site.cred on its ESP, is measured into PCR 12 (bootcreds.py, espcreds.py).
Moving a node to a new address changes that document on every node, so it changes every node's PCR 12.
The peers accept a PCR 12 only as part of a set in the measurement document a root-signed manifest names
(measurements.py), so the root approves every new value before it is used: one epoch lists, for each node,
the set it boots on now and the same set with only PCR 12 replaced. The site-advance step writes the new
document only when this module says the result is such a set.

    target(sets, booted, pcr12)     the label of the set the node will match once its ESP measures `pcr12`

THE PREDICTION IS THE WHOLE SET, NOT PCR 12 ALONE. Replacing the site document changes PCR 12 and nothing
else: the image, its PCR 11 in both phases, PCR 7 and the TPM firmware are those of the set the node booted
on. So the prediction is that set with PCR 12 replaced, and it must equal an accepted set in every
measurement. Matching PCR 12 alone would take a set made for another image: the node would write a site
document whose boot no peer accepts. PCR 11 has one value per boot phase, and the running host shows only
the system phase, so the prediction takes it from the booted set rather than from the TPM.

ONE MOVE AT A TIME, AND NO IMAGE UPDATE DURING IT. A node carries at most two sets (attest.MAX_SETS), and a
move needs both. When the node holds two sets that differ in anything but PCR 12, an image update is rolling
through, and this refuses: the move waits for that update's retire epoch. attest.validate_sets must NOT carry
that rule. It validates every manifest, and an image update's two sets differ in PCR 11 and the firmware by
design.

`sets` are a node's accepted sets as attest.validate_sets left them, and `booted` is the label of the one its
quote matched. Nothing here reads a file or a TPM.
"""
from deploy.baremetal import attest

Refused, require = attest.Refused, attest.require

SITE_PCR = "12"


def _without_site(entry):
    """Everything a set measures or names, with PCR 12 taken out: what a site change must leave alone."""
    pcrs = {i: v for i, v in entry["pcrs"].items() if i != SITE_PCR}
    return (entry["tpm_firmware_version"], pcrs, entry.get("phases"), entry.get("signing"))


def target(sets, booted, pcr12):
    """The label of the accepted set a node booted on `booted` will match once its ESP measures `pcr12`
    into PCR 12, or Refused (the module text)."""
    require(attest.is_hex(pcr12, 64), "the predicted PCR 12 must be 64 lowercase hex")
    by_label = {entry["label"]: entry for entry in sets}       # labels are distinct: attest.validate_sets
    require(booted in by_label, "the node booted on %r, which is not one of its accepted sets (%s)" % (
        booted, ", ".join(sorted(by_label))))
    current = by_label[booted]
    require(SITE_PCR in current["pcrs"], "the set %r does not attest PCR 12: a site change cannot be judged against it" % booted)
    if len(sets) == 2:
        other = next(entry for entry in sets if entry["label"] != booted)
        require(_without_site(other) == _without_site(current),
                "the node holds two sets that differ in more than PCR 12 (%r and %r): an image update is rolling through, "
                "and a move must wait for the epoch that retires one of them" % (booted, other["label"]))
    # every accepted set is now the booted one in all but PCR 12, so a set with this PCR 12 IS the prediction,
    # the booted set with PCR 12 replaced, in every measurement
    for entry in sets:
        if entry["pcrs"].get(SITE_PCR) == pcr12:
            return entry["label"]
    raise Refused("no accepted set is the booted set %r with PCR 12 %s: the root has not approved this site document "
                  "for this node yet" % (booted, pcr12))
