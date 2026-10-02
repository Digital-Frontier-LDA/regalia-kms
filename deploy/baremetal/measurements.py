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
document's version: version(document) = "m1-" + the first 29 characters of the base64url SHA-256 of its
canonical JSON (membership.canonical: sorted keys, no spaces, so the same content has one version however
it was written out). That is 174 bits of the digest, all that the 32-character field holds. bind()
accepts a document only under a manifest whose policy_version is exactly that. The manifest is
root-signed, chained by epoch, and its epoch is anchored in the TPM (membership.py), so:
  * a document nobody approved has a version no manifest names;
  * an OLDER document is refused by the manifest a peer holds now, and that manifest cannot be rolled
    back by restoring a disk (the TPM high-water);
  * there is no second signing path, and no question of two documents under one name;
  * a revocation key cannot change policy_version (membership.py), so only the root approves or retires
    an image.
WHO COULD CHEAT IT. Whoever PREPARES the document (it is written on a build host, before and apart from
the signing) could look for two documents with one version, have the harmless one signed and deliver the
other. With 174 bits that collision costs about 2^87 hash computations. (A first draft kept 116 bits, as
hex: 2^58, which is within reach of a determined preparer.) Finding another document for a version that
is already signed costs 2^174. The root's operator computes the version from the file in hand, at
signing time, and signs that.

WHY THE PEERS, AND NOT THE TPM'S OWN POLICY, RETIRE AN IMAGE. The local seal of the PIN and the disk is
a signed PCR 11 policy: the TPM accepts any image the PCR-signing key ever signed, for ever. It has no
counter. Retirement therefore has to be a decision somebody makes with current knowledge: a peer, under
the manifest it holds, refusing to help an image the document no longer lists.

A ROLLOUT IS THREE DOCUMENTS, each named by its own manifest epoch:
    CURRENT            ->  CURRENT + NEXT (approve)  ->  NEXT (retire)
The LAST set of a node is the image it should end up on: `target(document, node_id)`. During a rollout
that is NEXT. transition(old, new) names what a new document does and refuses what is not one clean step:

    approve    nodes gain a set, listed last (the new target); nobody loses one
    retire     nodes lose their FIRST set (CURRENT) and keep their target; nobody gains one
    abandon    nodes lose their LAST set (NEXT is given up) and fall back to the other; nobody gains one
    unchanged  the same sets in the same order

Refused: a set dropped in the step that adds another on the same node (no overlap: a node still running
the old image is locked out with no step in which both were accepted), unless the caller says it is an
EMERGENCY (a compromised image is dropped at once: "replace-without-overlap"); two sets swapped (the
target would change with nothing approved or retired); a label given other measurements; approving
and retiring, or retiring and abandoning, in one document; and a node that disappears from the document
unless the caller names it in `dropped` (a retired or replaced node: bind() lets a node have no entry
only when the manifest leaves it nothing to do). Every node is checked, in an emergency too.

transition() is the check the root's operator runs before signing. Peers do not enforce it: the root
must be able to revoke an image at once.

NOT HERE: how the reference values are obtained (pcr_survey.py on the real hosts, systemd-measure for
PCR 11), the PCR-signing key's custody, and the reboot itself. rollout.py holds the two decisions an
update asks for: may this node reboot now, and may CURRENT be retired.
"""
import base64
import hashlib
import re

from deploy.baremetal import attest, membership, replacement

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.measurements/v1"
VERSION_PREFIX = "m1-"
VERSION_CHARS = 32 - len(VERSION_PREFIX)     # of base64url: 6 bits each, 174 bits in all
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
    digest = hashlib.sha256(membership.canonical(document)).digest()
    return VERSION_PREFIX + base64.urlsafe_b64encode(digest).decode("ascii")[:VERSION_CHARS]


def load(raw):
    try:
        document = membership.load(raw, limit=MAX_BYTES)
    except RecursionError:
        raise Refused("not a measurements document: nested too deeply")
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


def attest_policy(manifest, document, peer_id=None):
    """The attestation policy `peer_id` holds under `manifest`, from the document that manifest commits
    to and from nothing else. This is the call a peer should make: replacement.attest_policy takes any
    reference values it is handed, bound or not."""
    return replacement.attest_policy(manifest, bind(manifest, document), peer_id=peer_id)


def target(document, node_id):
    """The set `node_id` should end up on: the last of its accepted sets (NEXT during a rollout)."""
    sets = validate(document)
    require(node_id in sets, "the measurements have no entry for %s" % node_id)
    return sets[node_id][-1]


def _key(entry):
    return (entry["tpm_firmware_version"], tuple(sorted(entry["pcrs"].items())))


def transition(old, new, emergency=False, dropped=()):
    """What `new` does to `old`: "approve", "retire", "abandon", "unchanged", or, with `emergency`,
    "replace-without-overlap". Raises Refused for anything that is not one clean step (the module text
    lists them). `dropped` names the nodes that are meant to leave the document; a node that is new in
    `new` (an enrollment) is not compared."""
    before, after = validate(old), validate(new)
    gone, dropped = set(before) - set(after), set(dropped)
    require(gone <= dropped, "%s is no longer in the measurements. A node that still attests cannot lose its entry; if it was "
            "retired or replaced, name it in `dropped`" % ", ".join(sorted(gone - dropped)))
    require(dropped <= gone, "`dropped` names nodes that are still in the new document or never were in the old one: %s"
            % ", ".join(sorted(dropped - gone)))
    kinds, replaced = {}, []
    for node_id in sorted(set(before) & set(after)):
        b, a = before[node_id], after[node_id]
        was, now = {e["label"]: _key(e) for e in b}, {e["label"]: _key(e) for e in a}
        for label in set(was) & set(now):
            require(was[label] == now[label], "%s: the set %r has other measurements than before; a changed image gets a new label"
                    % (node_id, label))
        added, removed = set(now.values()) - set(was.values()), set(was.values()) - set(now.values())
        if added and removed:
            require(emergency, "%s: %s is dropped in the same step that adds %s. A node still running the old image would "
                    "be locked out: approve the new image first (both sets), retire the old one afterwards"
                    % (node_id, ", ".join(sorted(set(was) - set(now))), ", ".join(sorted(set(now) - set(was)))))
            replaced.append(node_id)
        elif added:
            # target() reads the LAST set as the image to end up on, so the newcomer goes last.
            require(_key(a[-1]) in added, "%s: the newly approved set must be listed last (it is the target)" % node_id)
            kinds.setdefault("approve", []).append(node_id)
        elif removed:
            # one set left, of two: the old target (CURRENT is retired) or the old first set (NEXT is abandoned)
            kinds.setdefault("retire" if _key(a[-1]) == _key(b[-1]) else "abandon", []).append(node_id)
        else:
            require([_key(e) for e in a] == [_key(e) for e in b], "%s: its two sets changed places, so its target would become %s "
                    "with nothing approved or retired" % (node_id, a[-1]["label"]))
    if replaced:
        require(not kinds, "an emergency replacement (%s) must not also %s (%s) in the same document"
                % (", ".join(replaced), " or ".join(sorted(kinds)), ", ".join(sorted(n for v in kinds.values() for n in v))))
        return "replace-without-overlap"
    require(len(kinds) <= 1, "one document does two things: %s. One step, one document"
            % "; ".join("%s on %s" % (k, ", ".join(v)) for k, v in sorted(kinds.items())))
    return next(iter(kinds), "unchanged")
