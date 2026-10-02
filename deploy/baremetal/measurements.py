#!/usr/bin/env python3
"""The measurement document: which boot images each node may run, CURRENT and NEXT (#75, Phase 15 of #59).

attest.py judges a node's quote against reference values. Until now those were a local file written at
intake, with one set per node, so a kernel update meant editing every peer's policy at once, and nothing
stopped a peer from being handed an older file. This module makes the reference values a document the
SIGNED MEMBERSHIP MANIFEST COMMITS TO, with one or two sets per node.

    document = {"schema": "regalia.measurements/v1",
                "name": "<a short human name, e.g. 2026.11-kernel-6.12.57>",
                "nodes": {"<node_id>": {"accepted": [
                    {"label": "<image name>", "tpm_firmware_version": "<16 hex>", "pcrs": {"0": "<64 hex>", ...},
                     "phases": {"initrd": {"11": "<64 hex>"}, "system": {"11": "<64 hex>"}}},    # optional
                    ...]}}}                     # one set, or two while an update rolls through

PER BOOT PHASE. A host that boots a unified kernel image has two PCR 11 values for one image: in the
initrd, where it asks a peer for its disk, and once booted, where it asks for a lease (attest.py, "PCR
VALUES PER BOOT PHASE"). Such an image's set gives PCR 11 under "phases"; both values come from the
image's build record (#57). A peer accepts an unlock only from the initrd value and a lease only from
the booted one. They are part of the set: a label keeps them, and they are in the version.

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
EMERGENCY (a compromised image is dropped at once, everywhere: "replace-without-overlap"; a node whose
only sets it was ends on the ONE replacing image, the same for all; a node that had it beside another
set loses it, whichever of its two it was; no node may keep it, lose any other set, or gain an approval
in the same document); two sets swapped (the
target would change with nothing approved or retired); a label given other measurements; approving
and retiring, or retiring and abandoning, in one document; and a node that disappears from the document
unless the caller names it in `dropped` (a retired or replaced node: bind() lets a node have no entry
only when the manifest leaves it nothing to do). Every node is checked, in an emergency too.

transition() is the check the root's operator runs before signing. Peers do not enforce it: the root
must be able to revoke an image at once.

WHAT IT CANNOT SEE. A label is a name, and the PCR values of one image differ between machines. The
checks compare labels across nodes and measurements within a node (a set keeps its label; a label keeps
its measurements), and in an emergency refuse the dropped measurements wherever the document brings
them in: a set that is new in the document and holds a dropped image's PCR state, in any of its
phases; a replacing set that selects other PCRs than the one it replaces; and a new node's set that
selects other PCRs than the dropped image was measured on. A set carried over unchanged is not
compared: it was approved before, and no node may keep the dropped label. They
cannot recognise the compromised image on OTHER hardware under a new label, nor an unapproved image
enrolled under an approved label. The control for both is the operator comparing the document with
each node's PCR survey (pcr_survey.py) before signing.

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


def attest_policy(manifest, document, peer_id):
    """The attestation policy `peer_id` holds under `manifest`, from the document that manifest commits
    to and from nothing else. This is the call a peer should make: replacement.attest_policy takes any
    reference values it is handed, bound or not. `peer_id` must be a node of the manifest: a peer's
    policy never lists the peer itself."""
    bound = bind(manifest, document)
    require(isinstance(peer_id, str) and peer_id in membership.validate(manifest), "%r is not a node of the manifest" % (peer_id,))
    return replacement.attest_policy(manifest, bound, peer_id=peer_id)


def check_replacement(current, candidate, old_document, new_document, old_id, new_id):
    """A node replacement (#76) under bound measurements: `candidate` replaces `old_id` by `new_id`, and
    the document it commits to is the old one with the new node's entry added, the replaced node's entry
    kept or removed, and NOTHING else changed: no other node gains, loses or reorders a set in the same
    step. Raises Refused with the reason."""
    bind(current, old_document)
    replacement._check_replacement(current, candidate, old_id, new_id, policy_version_may_change=True)
    bind(candidate, new_document)
    before, after = validate(old_document), validate(new_document)
    require(new_id in after and new_id not in before, "the new document must add an entry for %s" % new_id)
    # The new node gets the images the cluster already accepts, under their names: its PCR values are its
    # own hardware's, but a replacement is not the step that approves an image nobody else runs.
    # "Another node" is one that attests under the current manifest. A QUARANTINED or RETIRED node may keep a
    # stale entry (bind() allows it), and its retired image must not come back through a replacement.
    nodes = membership.validate(current)
    # ... and in the same form: an image the others hold per boot phase is per phase on the new node too.
    # Given with one value per PCR it would be judged the same in both phases, and the new node's booted
    # system could ask for a disk key.
    shape = lambda sets: tuple(e["label"] + (" (per phase)" if "phases" in e else "") for e in sets)
    known = sorted({shape(sets) for node_id, sets in before.items()
                    if membership.CAPABILITIES[nodes[node_id]["state"]] & {"request", "serve"}})
    require(shape(after[new_id]) in known, "%s is enrolled with the sets %s; a replacement gives the new node the sets a node that attests "
            "already has (%s), and approving a new image is a step of its own"
            % (new_id, list(shape(after[new_id])), " or ".join(str(list(k)) for k in known)))
    require(set(after) - set(before) == {new_id} and set(before) - set(after) <= {old_id},
            "a replacement changes the entries of %s and %s only (added: %s; removed: %s)"
            % (old_id, new_id, ", ".join(sorted(set(after) - set(before))) or "none", ", ".join(sorted(set(before) - set(after))) or "none"))
    for node_id in sorted(set(before) & set(after)):
        require(after[node_id] == before[node_id], "a replacement does not change the measurements of %s" % node_id)


def target(document, node_id):
    """The set `node_id` should end up on: the last of its accepted sets (NEXT during a rollout)."""
    sets = validate(document)
    require(node_id in sets, "the measurements have no entry for %s" % node_id)
    return sets[node_id][-1]


def _key(entry):
    """A set's measurements, whole: the per-phase values are as much the image as the others."""
    return (entry["tpm_firmware_version"], tuple(sorted(entry["pcrs"].items())),
            tuple((phase, tuple(sorted(pcrs.items()))) for phase, pcrs in sorted(entry.get("phases", {}).items())))


def _states(entry):
    """Every PCR state a node on this set is accepted in, as {PCR: value}: one per phase, or one."""
    return [attest.values(entry, phase) for phase in (attest.PHASES if "phases" in entry else (None,))]


def _pcrs(state):
    return ", ".join(sorted(state, key=int))


def transition(old, new, emergency=False, dropped=()):
    """What `new` does to `old`: "approve", "retire", "abandon", "unchanged", or, with `emergency`,
    "replace-without-overlap". Raises Refused for anything that is not one clean step (the module text
    lists them). `dropped` names the nodes that are meant to leave the document (a list of node IDs); a
    node that is new in `new` (an enrollment) is not compared."""
    require(isinstance(dropped, (list, tuple, set, frozenset)) and all(isinstance(n, str) for n in dropped),
            "`dropped` is a list of node IDs")
    before, after = validate(old), validate(new)
    gone, dropped = set(before) - set(after), set(dropped)
    require(gone <= dropped, "%s is no longer in the measurements. A node that still attests cannot lose its entry; if it was "
            "retired or replaced, name it in `dropped`" % ", ".join(sorted(gone - dropped)))
    require(dropped <= gone, "`dropped` names nodes that are still in the new document or never were in the old one: %s"
            % ", ".join(sorted(dropped - gone)))
    kinds, replaced, compromised, compromised_states, replacing, lost = {}, [], set(), {}, set(), {}
    for node_id in sorted(set(before) & set(after)):
        b, a = before[node_id], after[node_id]
        was, now = {e["label"]: _key(e) for e in b}, {e["label"]: _key(e) for e in a}
        for label in set(was) & set(now):
            require(was[label] == now[label], "%s: the set %r has other measurements than before; a changed image gets a new label"
                    % (node_id, label))
        # ... and the other way round: the same measurements under a new name are the same image. Renamed, a set
        # would be neither added nor removed, and a dropped image could stay on under another label.
        names_was, names_now = {key: label for label, key in was.items()}, {key: label for label, key in now.items()}
        for key in set(names_was) & set(names_now):
            require(names_was[key] == names_now[key], "%s: the set %r is renamed %r with the same measurements; a set keeps its label"
                    % (node_id, names_was[key], names_now[key]))
        added, removed = set(now.values()) - set(was.values()), set(was.values()) - set(now.values())
        if added and removed:
            require(emergency, "%s: %s is dropped in the same step that adds %s. A node still running the old image would "
                    "be locked out: approve the new image first (both sets), retire the old one afterwards"
                    % (node_id, ", ".join(sorted(set(was) - set(now))), ", ".join(sorted(set(now) - set(was)))))
            # the node ends on the replacing image and nothing else: a second new set, or the target moved past
            # a set it already had, is an approval, and no approval rides along with an emergency
            require(len(a) == 1, "%s: an emergency replacement leaves the node on the replacing image alone, not on %s"
                    % (node_id, ", ".join(e["label"] for e in a)))
            # ... judged on the same PCRs as the image it replaces. With one set left, nothing else holds the
            # selection: fewer PCRs would accept more than the new image, the dropped one included.
            require(attest.selection(a[0]) == attest.selection(b[0]), "%s: the replacing set selects PCRs %s where the dropped one "
                    "selected %s; an emergency replaces an image, it does not change what is measured"
                    % (node_id, attest.selection(a[0]), attest.selection(b[0])))
            replaced.append(node_id)
            compromised |= set(was) - set(now)       # the labels the emergency drops
            # and their measurements, on this node's hardware: every state the dropped image is accepted in
            compromised_states[node_id] = [s for e in b if _key(e) in removed for s in _states(e)]
            replacing.add(a[0]["label"])
        elif added:
            # target() reads the LAST set as the image to end up on, so the newcomer goes last.
            require(_key(a[-1]) in added, "%s: the newly approved set must be listed last (it is the target)" % node_id)
            kinds.setdefault("approve", []).append(node_id)
        elif removed:
            # one set left, of two: the old target (CURRENT is retired) or the old first set (NEXT is abandoned)
            kinds.setdefault("retire" if _key(a[-1]) == _key(b[-1]) else "abandon", []).append(node_id)
            lost[node_id] = set(was) - set(now)
        else:
            require([_key(e) for e in a] == [_key(e) for e in b], "%s: its two sets changed places, so its target would become %s "
                    "with nothing approved or retired" % (node_id, a[-1]["label"]))
    if replaced:
        # An emergency drops ONE thing, the compromised image, everywhere at once. A node that had it beside
        # another set simply loses it, whichever of its two sets it was. Nothing else rides along: no approval,
        # no other set lost, and the compromised image left on nobody.
        approving = kinds.get("approve", [])
        require(not approving, "an emergency replacement (%s) must not also approve (%s) in the same document"
                % (", ".join(replaced), ", ".join(approving)))
        other = sorted(n for n, labels in lost.items() if not labels <= compromised)
        require(not other, "an emergency replacement drops %s; %s loses another set (%s) in the same document"
                % (", ".join(sorted(compromised)), ", ".join(other), ", ".join(sorted(set().union(*(lost[n] for n in other)) - compromised))))
        require(len(replacing) == 1, "an emergency replacement puts every replaced node on ONE image, not on %s"
                % ", ".join(sorted(replacing)))
        kept = sorted(n for n, sets in after.items() if {e["label"] for e in sets} & compromised)
        require(not kept, "an emergency replacement drops %s, but %s would still accept it"
                % (", ".join(sorted(compromised)), ", ".join(kept)))
        # the same measurements under another name, on a node that was not compared (a new one) or anywhere else
        # A disguise can only come in with a set this document INTRODUCES: the replacing set of a replaced node, or
        # any set of a new node. A set carried over unchanged was approved before, under its own label, and the
        # label rule above covers it (a GRUB host beside the dropped UKI image shares its Secure Boot PCR and
        # nothing that tells images apart: it is not a suspect). An introduced set is compared with the states of
        # the dropped image, in any of its phases and whatever the TPM firmware version: on a replaced node with
        # that node's own (same hardware, same PCRs: checked above), on a new node with every node's. One that
        # selects other PCRs than the dropped image was measured on cannot be shown to be another image.
        disguised = []
        for node_id, sets in sorted(after.items()):
            carried = {_key(e) for e in before.get(node_id, [])}
            against = compromised_states.get(node_id) if node_id in before else [s for states in compromised_states.values() for s in states]
            for entry in sets:
                if _key(entry) in carried:
                    continue
                for state in _states(entry):
                    for was in against or []:
                        require(set(state) == set(was), "an emergency replacement drops %s; %s comes in with the set %r over PCRs %s, which cannot "
                                "be compared with the dropped image (measured on PCRs %s): enrol it in a step of its own"
                                % (", ".join(sorted(compromised)), node_id, entry["label"], _pcrs(state), _pcrs(was)))
                        if state == was and node_id not in disguised:
                            disguised.append(node_id)
        require(not disguised, "an emergency replacement drops %s, but %s would still accept the same measurements under "
                "another label" % (", ".join(sorted(compromised)), ", ".join(disguised)))
        return "replace-without-overlap"
    require(len(kinds) <= 1, "one document does two things: %s. One step, one document"
            % "; ".join("%s on %s" % (k, ", ".join(v)) for k, v in sorted(kinds.items())))
    return next(iter(kinds), "unchanged")
