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
| `recovery needs whole chains from 2 different sources` | A crash fell between the counter and the record; the record names the epoch below | The node, from two sources | `convergence.recover` with the chains of two other nodes the manifest lets authorize (#199: there is no authority to be the second source). With only one such node left (the other revoked or down), nothing goes on by itself: an operator calls `convergence.recover(..., minimum=1)` deliberately, after checking that node's chain by hand as for a re-anchor (below), against the chain the owner signs revocations against. No tool does this yet |
| `cannot write the record index …` / `did not take the write` | The TPM refused a write, or power was lost during one | Nobody needs to | Start the service again: `load()` completes it. A record write that was cut half-way damages one slot only; the other still holds the epoch before |
| `the fetched chain ends at epoch N, below the TPM high-water M` | The peer asked is itself behind | The node | Ask another peer |
| `epoch jump N exceeds the bound 1000: anomaly` | The chain offered is more than 1000 epochs ahead of this node's anchor | The node, in steps; an operator to look first | Manifests change rarely, so first find out why a node is so far behind. Then: a node whose chain on disk is intact catches up through `convergence.catch_up`, which applies at most 1000 envelopes a message and commits them one by one. A node whose chain is lost restores the chain cut at its anchored epoch + 1000 (`Store.restore` of the first epochs), then catches up the rest the same way. Nothing is anchored more than 1000 epochs at a time, and nothing needs a re-anchor |
| `NO RECORD: neither record slot … holds a valid record` | Both record slots are unreadable as records. Two cut writes in a row cannot do it (the second write goes to the slot the first one damaged); a failing TPM or a deliberate write can | **An operator, on the host** | Re-anchor (below) |
| `cannot read NV index …: … the index is not defined` | The TPM answers, and says an index of the anchor does not exist: it was deleted, or the anchor was never defined | **An operator** | Re-anchor |
| `record index … is N bytes, not 48` / `is not an ordinary index` / `is not a written counter` | An index of the anchor exists and is not what this software defines (for example an anchor defined by an older version, whose single record was 40 bytes) | **An operator** | Re-anchor. The counter's epoch is kept as the floor, but an old 40-byte record is NOT read: it had no integrity tag, so its digest cannot be told from garbage, and the chain is not compared with it. No host was commissioned with that layout |
| `NV index … does not have this anchor's attributes` / `… is write-locked` | An index of the anchor can be written or read otherwise than this software defines (for example by its own empty authorization), or is locked | **An operator** | Re-anchor. What the index holds still counts as a floor before it is replaced |
| `the TPM record is for epoch N but the TPM high-water is M: the anchor is inconsistent` | The counter was moved by something other than this software (`tpm2_nvincrement` by hand), or the record was written by hand | **An operator** | Re-anchor, on a chain that reaches the counter and carries what each valid slot records. If no manifest reaches epoch M, the root signs manifests up to it; the counter is never lowered |
| `cannot read N bytes from NV index …: what the anchor holds cannot be known` (when re-anchoring) | A record slot, or the counter or its base, can be read neither with the owner's authorization nor its own (defined that way, or read-locked). Re-anchoring refuses: it cannot know what that index holds, and deleting it could drop the highest record, or the counter's floor | **An operator, deliberately** | Find out what defined it so. If you accept losing what it holds, delete it (`tpm2_nvundefine <index> -C o`), then re-anchor |
| `the fetched chain ends at epoch N, below epoch M, which this node's TPM still holds (a record slot)`, with an M no real chain has reached | A record slot holds a valid-looking record far above anything signed: written by something other than this software (the tag is not a secret) | **An operator, and an incident** | Re-anchoring cannot lower a floor, by design. Find out what wrote it, then delete EVERY slot holding a record above the signed chain (`tpm2_nvundefine <index> -C o`; both, if both were written) and re-anchor |
| `the two record slots name different manifests at epoch N` | Something other than this software wrote a record | **An operator, and an incident** | Find out what wrote it. Re-anchoring honours every slot that still holds a valid record, so it refuses while two disagree: delete the index that is wrong (`tpm2_nvundefine`, owner authorization) once you know which, then re-anchor |
| `the TPM does not answer` / `… the TPM lists it and did not give it` / `cannot read N bytes from …` | The TPM, or the tool that talks to it, failed. This says nothing about the anchor | **An operator, but not by re-anchoring** | The command refuses. Fix the TPM access (the device, `tpm2-abrmd`, permissions) and start the service again. If the TPM is dead or was replaced, this is a node replacement (`replacement.py`), not a repair |
| `the anchor's write policy is not this node's approved-image policy` (#242) | An index of the anchor is written under a policy, and not this node's: defined under another system-phase PCR key (a key rotation, until #361), or by someone else | **An operator** | Re-anchor with `--node-config`: the new indices are defined under the policy of the key the node's signed measurements approve |
| `NV index … is owner-written: under regalia.membership/v4 the anchor is written by policy only` (#242 B3) | The chain's tip is v4 and an index of the anchor is owner-written: defined before the chain moved to v4, or by someone holding the owner authorization | **An operator** | Re-anchor with `--node-config` (it defines by policy). See the ordering note below |
| `this node's approved-image write policy cannot be established: …` (#242) | The policy-written anchor cannot be judged: the image's `.pcrpkey`, the chain, or the measurements document its manifest commits to is missing, or the image's key is not one they approve. This says nothing about the anchor | **An operator, but not by re-anchoring** | Find what is missing (`/run/systemd/tpm2-pcr-public-key.pem`, the store's measurements) and start the service again. A key no signed set approves means this boot is not an approved image |

**Moving a chain to v4 (#242 B3, regalia-kms-ed).** Under a v4 tip the anchor is written by policy only. A node whose anchor
is owner-written (a v1-v3 lab node) cannot take the root's v3 -> v4 step: the commit is judged by the NEW tip and refused
before the disk is written, so the node stays at v3, its anchor as it was. Re-anchor such a node by policy first, with
`--node-config` and an image whose signed measurements name its system-phase key; then it takes the v4 step. Production
networks start at a v4 genesis, so their nodes are enrolled by policy from the beginning and never meet this.

Everything above the line "An operator" is automatic or needs only a peer. The rows that are repaired
by re-anchoring have one thing in common: the TPM answered, and what it holds can no longer say which
chain this node accepted, so no chain a peer sends can be checked against it.

## Re-anchoring

Re-anchoring deletes the node's membership anchor and defines a new one on a chain the operator has
established. **It is the one operation that resets a node's rollback protection.** After it, the node
believes the chain it was given, exactly as a newly enrolled node does. So:

- it is a command an operator runs on the host, never something a service or a peer can trigger;
- it needs whole chains from **at least two other nodes** that the newest manifest lets authorize, agreeing at
  every epoch and **ending at the same epoch** (#199: there is no authority host, so no single source is
  trusted more than another; the trust is the nodes' quorum, as for heartbeats and revocations). One node
  alone is refused, the node being re-anchored is not accepted as its own peer, and chains that end at
  different epochs are refused: the newest epochs of the longer one would rest on that node alone. Fetch
  each node's current chain again, after the newest epoch has reached both;
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
    --tpm-index 0x1500016 --node-id b --peer a=a-chain.json --peer c=c-chain.json \
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
| 2 | none | The command line itself is wrong (a missing or unknown option). Nothing was read or changed | Correct the arguments |
| 3 | `INCOMPLETE` | The re-anchor had begun and a step failed (the chain file could not be written, or a TPM command was refused). The verified chain may or may not be on disk yet; the node's membership does not load | If the reason is a storage error (disk full, read-only), fix that first. Then **run the same command again with the same chains**: it completes from wherever it stopped. A shorter or different chain is refused: the file on disk, if it was written, and whatever the TPM still holds bind the second attempt |
| none | a `reanchor-requested` line with no outcome after it | The process was killed or the power was lost while it ran: there is no exit status and no outcome line. Anything from nothing changed to finished is possible | The same as status 3: run the same command again with the same chains. If the anchor is already usable, it says so and changes nothing; start the service |
| 4 | request line only | Done, but the outcome could not be written to the audit log | Record it by hand; the message gives the epoch and digest |

### Deciding that the sources are right

The command checks signatures, the chain, and that the sources agree. It cannot check that the files
are what the two peers really hold. That is the operator's part, before typing the phrase:

1. **Fetch each chain yourself, from its holder**, over the channel you already trust for that host
   (each peer over SSH under its manifest-pinned host key, `SSH.md`). Do not
   take both files from one place, and never from the node being re-anchored. The command refuses the
   node as its own peer by name; it cannot tell that two files with different names came from one place.
2. **Compare the epoch and digest the command prints with what a healthy peer reports for itself**
   (`python3 -Es -m deploy.baremetal.rollout epoch --membership … --root-key … --tpm-index 0x1500016` on that
   peer: it checks the peer's chain against the peer's own TPM). The digest must be the same.
3. **Compare with the last signing record** for the root, and with the last revocation the nodes or the
   owner signed (`revoke.py`): the newest epoch signed is the epoch you expect. A chain that ends below it is old.
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
- **Who can rewrite the anchor.** Every index of the anchor is written with the TPM's owner
  authorization only (an index that also takes its own authorization, or a policy, is refused). With
  the empty owner authorization a TPM has from the factory, that is anyone who can open the TPM device
  (root, the tss group), and this software itself relies on that today. So the anchor protects against
  a restored or substituted disk, not against code running as root on the host. That is the decided
  trust boundary, not an oversight: owner and endorsement authorization stay empty, and access to
  `/dev/tpmrm0` is limited to root and a `tss` group that holds only these units (decision on #190,
  https://github.com/Digital-Frontier-LDA/regalia-kms/issues/190#issuecomment-5969483031). A non-empty
  owner authorization would have to sit on disk for the service to advance the counter, and would
  protect nothing against root. `host_probe.py` checking the `tss` group is part of #190.
- Nothing fetches the chains for the operator; the transport is #80.
- **No migration from the first layout** (#146: one 40-byte record). Nothing was commissioned with it.
  A node that had been would report `record index … is 40 bytes, not 48` and would be re-anchored,
  with its counter as the floor and its old record not read.
