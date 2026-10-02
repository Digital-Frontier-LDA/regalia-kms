# When a KMS node refuses its own membership: what it means and what to do (#68)

A node keeps the signed membership chain on disk and anchors it in its TPM: a counter for the epoch it
has accepted, and a record of which manifest that was (`membership.py`). When the disk and the anchor
disagree the node refuses to load its membership, authorizes nobody and serves under no new lease.
That is deliberate. This page says, for each refusal, what happened and how the node comes back.

## The refusals

| The node says | What happened | Who can fix it | How |
|---|---|---|---|
| `ROLLBACK: the membership on disk is epoch N but the TPM high-water is M` | The file is older than what this node accepted: a restored disk, or the file was lost | The node, from a peer | `convergence.recover`: one source is enough while the record names the manifest at the anchored epoch |
| `CONFLICT: the manifest at epoch N is not the one this node's TPM recorded` | The file holds another validly signed chain: a substituted disk, and a key that signed twice for one epoch | The node, from a peer, **and an incident** | `convergence.recover`; if the disk still holds the other chain the restore refuses it too: record the incident, keep the file as evidence, remove it, recover |
| `recovery needs whole chains from 2 different sources` | A crash fell between the counter and the record; the record names the epoch below | The node, from two sources | `convergence.recover` with a peer's chain and the authority's |
| `cannot write the record index …` / `did not take the write` | The TPM refused a write, or power was lost during one | Nobody needs to | Start the service again: `load()` completes it. A record write that was cut half-way damages one slot only; the other still holds the epoch before |
| `the fetched chain ends at epoch N, below the TPM high-water M` | The peer asked is itself behind | The node | Ask another peer, or the authority |
| `epoch jump N exceeds the bound 1000: anomaly` | The chain offered is more than 1000 epochs ahead | An operator | Find out why before anything else. No real history does this |
| `NO RECORD: neither record slot … holds a valid record` | Both record slots are unreadable as records. Two cut writes in a row cannot do it (the second write goes to the slot the first one damaged); a failing TPM or a deliberate write can | **An operator, on the host** | Re-anchor (below) |
| `cannot read NV index …: the high-water anchor is unavailable` | An index of the anchor is gone, or the TPM does not answer | **An operator** | If the TPM is present and only an index is missing: re-anchor. If the TPM is dead or was replaced: this is a node replacement (`replacement.py`), not a repair |
| `the TPM record is for epoch N but the TPM high-water is M: the anchor is inconsistent` | The counter was moved by something other than this software (`tpm2_nvincrement` by hand), or the record was written by hand | **An operator** | Re-anchor, on a chain that reaches the counter. If no manifest reaches epoch M, the root signs manifests up to it; the counter is never lowered |
| `the two record slots name different manifests at epoch N` | Something other than this software wrote a record | **An operator, and an incident** | Re-anchor, after finding out what wrote it |

Everything above the line "An operator" is automatic or needs only a peer. The four rows that need an
operator have one thing in common: the anchor itself can no longer say which chain this node accepted,
so no chain a peer sends can be checked against it.

## Re-anchoring

Re-anchoring deletes the node's membership anchor and defines a new one on a chain the operator has
established. **It is the one operation that resets a node's rollback protection.** After it, the node
believes the chain it was given, exactly as a newly enrolled node does. So:

- it is a command an operator runs on the host, never something a service or a peer can trigger;
- it needs whole chains from **the revocation authority and at least one peer**, agreeing at every epoch
  (two peers alone are refused, and so is the authority alone);
- it refuses when the anchor is usable (that case is `recover`'s, under the anchor as it is);
- while the old counter still reads, the chain must reach its epoch: it is not a way back;
- everything is verified before the TPM is touched, and a refusal changes nothing;
- the operator types a phrase naming the node, the epoch and the manifest digest;
- the request and its outcome are appended to an audit log, and without a writable log nothing is done.

```sh
python3 -m deploy.baremetal.reanchor --membership /var/lib/regalia/membership.json --root-key "$ROOT_KEY_HEX" \
    --tpm-index 0x1500016 --node-id b --authority authority-chain.json --peer c=c-chain.json \
    --audit-log /var/log/regalia/reanchor.jsonl
```

It needs the TPM's owner authorization, as defining the anchor did at commissioning.

### Deciding that the sources are right

The command checks signatures, the chain, and that the sources agree. It cannot check that the files
are what the authority and the peer really hold. That is the operator's part, before typing the phrase:

1. **Fetch each chain yourself, from its holder**, over the channel you already trust for that host
   (the authority's own machine; the peer over SSH under its manifest-pinned host key, `SSH.md`). Do not
   take both files from one place, and never from the node being re-anchored.
2. **Compare the epoch and digest the command prints with what a healthy peer reports for itself**
   (`python3 -m deploy.baremetal.rollout epoch --membership … --root-key … --tpm-index 0x1500016` on that
   peer: it checks the peer's chain against the peer's own TPM). The digest must be the same.
3. **Compare with the last signing record** for the root or revocation key: the newest epoch signed is
   the epoch you expect. A chain that ends below it is old.
4. **Ask why the anchor is unusable** before repairing it. A power cut explains one damaged slot, not
   two. If you cannot explain it, treat the host as suspect: quarantine the node in a manifest first,
   and re-anchor it afterwards.

If the sources disagree with each other, stop: two manifests were signed for one epoch. That is an
incident for the root key's holder, not something to resolve on this host.

## What is tested, and what is not

- A record write cut at every byte is repaired by the next load; cuts all the way through a restore
  never strand the node; the newest valid slot is never the one written
  (`tests/test_baremetal_membership.py`, `TornWrites`). Each refusal of the re-anchor command, the audit
  log, and the two crash points inside a re-anchor (`tests/test_baremetal_reanchor.py`), on a software
  TPM as well.
- **Not tested: a physical TPM.** Whether a real TPM can leave a half-written NV index after a power
  cut is not known for these hosts, and a software TPM cannot show it. The two slots are the protection
  whatever the answer is. The drill (cut power to a DL360 during record writes, many times, and read
  both slots back) is still to run.
- Nothing fetches the chains for the operator; the transport is #80.
