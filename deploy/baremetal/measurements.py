#!/usr/bin/env python3
"""The measurement document: which boot images each node may run, CURRENT and NEXT (#75, Phase 15 of #59).

attest.py judges a node's quote against reference values. Until now those were a local file written at
intake, with one set per node, so a kernel update meant editing every peer's policy at once, and nothing
stopped a peer from being handed an older file. This module makes the reference values a document the
SIGNED MEMBERSHIP MANIFEST COMMITS TO, with one or two sets per node.

    document = {"schema": "regalia.measurements/v1",
                "name": "<a short human name, e.g. 2026.11-kernel-6.12.57>",
                "nodes": {"<node_id>": {"accepted": [
                    {"label": "<image name>", "tpm_firmware_version": "<16 hex>", "pcrs": {"0": "<64 hex>", ...}},
                    ...]}}}                     # one set, or two while an update rolls through

HOW IT IS AUTHENTICATED. The document is not signed. The manifest's `policy_version` field is the
document's version: version(document) = "m1-" + the first 29 hex digits of SHA-256 over its canonical
JSON (116 bits: membership.canonical, sorted keys and no spaces, so the same content has one version
however it was written out). bind() accepts a document only under a manifest whose policy_version is
exactly that. 116 bits is the strength against finding ANOTHER document for a version the root signed
(a second preimage). Two documents made to share a version (a collision) cost about 2^58, and only whoever
writes both can try: that is the root's own operator, who could sign either document openly.
The manifest is root-signed, chained by epoch, and its epoch is anchored in the TPM (membership.py), so:
  * a document nobody approved has a version no manifest names;
  * an OLDER document is refused by the manifest a peer holds now, and that manifest cannot be rolled
    back by restoring a disk (the TPM high-water);
  * there is no second signing path, and no question of two documents under one name;
  * a revocation key cannot change policy_version (membership.py), so only the root approves or retires
    an image.

WHY THE PEERS, AND NOT THE TPM'S OWN POLICY, RETIRE AN IMAGE. The local seal of the PIN and the disk is
a signed PCR 11 policy: the TPM accepts any image the PCR-signing key ever signed, for ever. It has no
counter. Retirement therefore has to be a decision somebody makes with current knowledge: a peer, under
the manifest it holds, refusing to help an image the document no longer lists.

A ROLLOUT IS THREE DOCUMENTS, each named by its own manifest epoch:
    CURRENT            ->  CURRENT + NEXT (approve)  ->  NEXT (retire)
transition(old, new) names the step and refuses anything else, unless the caller says it is an
emergency: dropping CURRENT with no overlap locks out every node still running it, which is the right
thing to do to a compromised image and the wrong thing to do by accident. It is the check the root's
operator runs before signing; peers do not enforce it, because the root must be able to revoke an image
at once.

The LAST set of a node is the image it should end up on: `target(document, node_id)`. During a rollout
that is NEXT.

NOT HERE: how the reference values are obtained (pcr_survey.py on the real hosts, systemd-measure for
PCR 11), the PCR-signing key's custody, and the reboot itself. rollout.py holds the two decisions an
update asks for: may this node reboot now, and may CURRENT be retired.
"""
import hashlib
import re

from deploy.baremetal import attest, membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.measurements/v1"
VERSION_PREFIX = "m1-"
MAX_BYTES = 256 * 1024


def validate(document):
    """Schema. Returns {node_id: [set, ...]}, each set as attest.py's ({label, tpm_firmware_version, pcrs})."""
    membership.exact(document, ("schema", "name", "nodes"), "measurements")
    require(document["schema"] == SCHEMA, "schema must be %s" % SCHEMA)
    require(isinstance(document["name"], str) and re.fullmatch(r"[A-Za-z0-9._-]{1,64}", document["name"]) is not None,
            "name must be a short plain name")
    nodes = document["nodes"]
    require(isinstance(nodes, dict) and nodes, "nodes must name at least one node")
    out = {}
    for node_id, entry in nodes.items():
        require(isinstance(node_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", node_id) is not None,
                "nodes: %r is not a node ID" % (node_id,))
        membership.exact(entry, ("accepted",), "nodes.%s" % node_id)
        try:
            attest.validate_sets(entry["accepted"], "nodes.%s" % node_id)
        except attest.Refused as refusal:
            raise Refused(str(refusal))
        out[node_id] = entry["accepted"]
    return out


def version(document):
    """What a manifest's policy_version must be to approve this document."""
    validate(document)
    return VERSION_PREFIX + hashlib.sha256(membership.canonical(document)).hexdigest()[:32 - len(VERSION_PREFIX)]


def load(raw):
    document = membership.load(raw, limit=MAX_BYTES)
    validate(document)
    return document


def bind(manifest, document):
    """The reference values a peer uses under `manifest`: {node_id: {"accepted": [...]}} for
    replacement.attest_policy. Refused unless the manifest commits to exactly this document, every node
    the manifest lets attest has an entry, and no entry is for a node the manifest does not list."""
    sets = validate(document)
    nodes = membership.validate(manifest)
    want = version(document)
    require(manifest["policy_version"] == want,
            "the manifest at epoch %d commits to measurements %s; this document (%s) is %s: it is not the one the root approved, "
            "or it is an older or newer one" % (manifest["epoch"], manifest["policy_version"], document["name"], want))
    unknown = sorted(set(sets) - set(nodes))
    require(not unknown, "the measurements name nodes the manifest does not list: %s" % ", ".join(unknown))
    for node_id, node in nodes.items():
        if membership.CAPABILITIES[node["state"]] & {"request", "serve"}:
            require(node_id in sets, "the measurements have no entry for %s, which the manifest lets attest" % node_id)
    return {node_id: {"accepted": accepted} for node_id, accepted in sets.items()}


def target(document, node_id):
    """The set `node_id` should end up on: the last of its accepted sets (NEXT during a rollout)."""
    sets = validate(document)
    require(node_id in sets, "the measurements have no entry for %s" % node_id)
    return sets[node_id][-1]


def _key(entry):
    return (entry["tpm_firmware_version"], tuple(sorted(entry["pcrs"].items())))


def transition(old, new, emergency=False):
    """What `new` does to `old`: "approve" (every node keeps its sets and at least one gains NEXT),
    "retire" (every node keeps a set it had and at least one loses CURRENT) or "unchanged". Anything
    else is refused: a set that appears while another disappears on the same node (no overlap: a node
    still on the old image is locked out with no step in which both were accepted), or a set whose
    label was given other measurements. With `emergency` the no-overlap case is returned as
    "replace-without-overlap" instead of refused; a relabelled set is refused always.

    Nodes may be added or dropped between documents (a replacement, #76); only nodes in both are compared."""
    before, after = validate(old), validate(new)
    gained = lost = False
    for node_id in sorted(set(before) & set(after)):
        b = {e["label"]: _key(e) for e in before[node_id]}
        a = {e["label"]: _key(e) for e in after[node_id]}
        for label in set(a) & set(b):
            require(a[label] == b[label], "%s: the set %r has other measurements than before; a changed image gets a new label"
                    % (node_id, label))
        added, removed = set(a.values()) - set(b.values()), set(b.values()) - set(a.values())
        if added and removed:
            require(emergency, "%s: %s is dropped in the same step that adds %s. A node still running the old image would "
                    "be locked out: approve the new image first (both sets), retire the old one afterwards"
                    % (node_id, ", ".join(sorted(set(b) - set(a))), ", ".join(sorted(set(a) - set(b)))))
            return "replace-without-overlap"
        if added:
            # target() reads the LAST set as the image to end up on, so the newcomer goes last.
            require(_key(after[node_id][-1]) in added, "%s: the newly approved set must be listed last (it is the target)" % node_id)
        gained, lost = gained or bool(added), lost or bool(removed)
    require(not (gained and lost), "one document both approves a new image on one node and retires one on another: "
            "two steps, two documents")
    return "approve" if gained else "retire" if lost else "unchanged"
