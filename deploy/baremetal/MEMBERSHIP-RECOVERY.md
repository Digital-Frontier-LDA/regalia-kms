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
| `cannot read NV index …: … the index is not defined` | The TPM answers, and says an index of the anchor does not exist: it was deleted, or the anchor was never defined | **An operator** | Re-anchor |
| `record index … is N bytes, not 48` / `is not an ordinary index` / `is not a written counter` | An index of the anchor exists and is not what this software defines (for example an anchor defined by an older version, whose single record was 40 bytes) | **An operator** | Re-anchor |
| `the TPM record is for epoch N but the TPM high-water is M: the anchor is inconsistent` | The counter was moved by something other than this software (`tpm2_nvincrement` by hand), or the record was written by hand | **An operator** | Re-anchor, on a chain that reaches the counter and carries what each valid slot records. If no manifest reaches epoch M, the root signs manifests up to it; the counter is never lowered |
| `the two record slots name different manifests at epoch N` | Something other than this software wrote a record | **An operator, and an incident** | Find out what wrote it. Re-anchoring honours every slot that still holds a valid record, so it refuses while two disagree: delete the index that is wrong (`tpm2_nvundefine`, owner authorization) once you know which, then re-anchor |
| `the TPM does not answer` / `… the TPM lists it and did not give it` / `cannot read N bytes from …` | The TPM, or the tool that talks to it, failed. This says nothing about the anchor | **An operator, but not by re-anchoring** | The command refuses. Fix the TPM access (the device, `tpm2-abrmd`, permissions) and start the service again. If the TPM is dead or was replaced, this is a node replacement (`replacement.py`), not a repair |

Everything above the line "An operator" is automatic or needs only a peer. The rows that are repaired
by re-anchoring have one thing in common: the TPM answered, and what it holds can no longer say which
chain this node accepted, so no chain a peer sends can be checked against it.

## Re-anchoring

Re-anchoring deletes the node's membership anchor and defines a new one on a chain the operator has
established. **It is the one operation that resets a node's rollback protection.** After it, the node
believes the chain it was given, exactly as a newly enrolled node does. So:

- it is a command an operator runs on the host, never something a service or a peer can trigger;
- it needs whole chains from **the revocation authority and at least one other node**, agreeing at every
  epoch they share. Two peers alone are refused, the authority alone is refused, the node being
  re-anchored is not accepted as its own peer, and **the chain anchored is the authority's**: a peer
  that is ahead of the authority is refused, because its newest epochs would rest on that peer alone;
- it refuses when the anchor is usable (that case is `recover`'s, under the anchor as it is), and when
  the TPM does not answer (nothing is known about the anchor then);
- **nothing the TPM still holds is forgotten**: the chain must reach the old counter's epoch while it
  reads, must reach the epoch of every record slot that still holds a valid record, and must carry that
  slot's manifest at that epoch;
- everything is verified before anything is changed, and a refusal changes nothing;
- **the new record goes into a record slot before the old counter is touched, and the new counter is
  defined at the chain's epoch.** No valid record slot is deleted. Interrupted at any point, the node
  holds what it held before, or the new record beside a counter out of step with it (unusable), or the
  finished anchor: never less than it held, and never an empty anchor that would accept another chain;
- the operator types a phrase naming the node, the epoch and the manifest digest, at a terminal;
- the request (naming the epoch and manifest) and then the outcome are appended to an audit log, and
  without a writable log nothing is done.

```sh
python3 -Es -m deploy.baremetal.reanchor --membership /var/lib/regalia/membership.json --root-key "$ROOT_KEY_HEX" \
    --tpm-index 0x1500016 --node-id b --authority authority-chain.json --peer c=c-chain.json \
    --audit-log /var/log/regalia/reanchor.jsonl
```

It needs the TPM's owner authorization, as defining the anchor did at commissioning. The TPM is
tpm2-tools' default one, or the one named with `--tcti`; a `TPM2TOOLS_TCTI` left in the environment is
refused, because it could point at another TPM, which would truthfully report the indices missing. That
authorization is what authorizes the change. The typed phrase is a deliberate act, not a secret: it can
be computed from the chain files.

| Exit status | Audit line | Meaning | What to do |
|---|---|---|---|
| 0 | `ALLOW` | Done | Start the service |
| 1 | `DENY`, or none if the arguments were refused | Refused. Nothing was changed | Read the reason |
| 3 | `INCOMPLETE` | The anchor was being replaced and it did not finish (a TPM command failed, power was lost). The verified chain is on disk; the node's membership does not load | **Run the same command again with the same chains.** It completes from wherever it stopped. A shorter or different chain is refused: the file on disk and whatever the TPM still holds bind the second attempt |
| 4 | request line only | Done, but the outcome could not be written to the audit log | Record it by hand; the message gives the epoch and digest |

### Deciding that the sources are right

The command checks signatures, the chain, and that the sources agree. It cannot check that the files
are what the authority and the peer really hold. That is the operator's part, before typing the phrase:

1. **Fetch each chain yourself, from its holder**, over the channel you already trust for that host
   (the authority's own machine; the peer over SSH under its manifest-pinned host key, `SSH.md`). Do not
   take both files from one place, and never from the node being re-anchored. The command refuses the
   node as its own peer by name; it cannot tell that two files with different names came from one place.
2. **Compare the epoch and digest the command prints with what a healthy peer reports for itself**
   (`python3 -Es -m deploy.baremetal.rollout epoch --membership … --root-key … --tpm-index 0x1500016` on that
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
  (`tests/test_baremetal_membership.py`, `TornWrites`).
- Re-anchoring (`tests/test_baremetal_reanchor.py`): each refusal, with the TPM and the file untouched;
  a record slot that still reads binds the chain when the counter is gone; a TPM that does not answer
  is refused; **power lost at every single TPM command of the redefinition**, from no valid record and
  from two valid ones with the counter gone, after each of which the TPM still holds at least the epoch
  it held, every record it holds is the chain's, the node refuses an older chain and a fork, and the
  command run again completes; the audit lines, `INCOMPLETE` included (also when that line cannot be
  written); a `TPM2TOOLS_TCTI` in the environment is refused and the TPM used is named in the log. One
  run on a software TPM.
- **A damaged newest slot leaves no trace.** If the newer slot is unreadable, the node falls back to
  the older one and repairs from the disk, as after a crash. Nothing records that it happened.
- **Not tested: a physical TPM.** Whether a real TPM can leave a half-written NV index after a power
  cut is not known for these hosts, and a software TPM cannot show it. The two slots are the protection
  whatever the answer is. The drill (cut power to a DL360 during record writes, many times, and read
  both slots back) is still to run.
- Nothing fetches the chains for the operator; the transport is #80.
- **No migration from the first layout** (#146: one 40-byte record). Nothing was commissioned with it.
  A node that had been would report `record index … is 40 bytes, not 48` and would be re-anchored,
  with its counter as the floor and its old record not read.
