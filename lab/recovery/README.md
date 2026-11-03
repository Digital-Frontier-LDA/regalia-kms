# Recovery interruption matrix

Run only on disposable laboratory fixtures:

```sh
python3 -Es lab/recovery/matrix.py \
  --script deploy/baremetal/recovery-key.sh --output /private/evidence/recovery-matrix.json
```

Requires Linux, Python 3, Bash, real cryptsetup and strace. Missing tools fail; nothing is
skipped. No root, device mapper, loop devices, mounts, physical disks or TPM are
used. Each fixture is a private 32 MiB regular file. Its random keys live only in
memory and anonymous descriptors. The intentionally fast fixture PBKDF is for
these disposable test volumes.

The successful enrollment and replacement runs count **every cryptsetup call**.
Each call is then repeated with failure before, failure after, TERM after, KILL
before and KILL after. The matrix also discovers the cleanup after every possible single command
failure and interrupts every subsequent command on those paths. An additional
run closes the stderr reader. Child process
groups are separate from the test driver. Each scenario checks the real header,
tests each known fixture key against every slot, checks diagnostic/argument secret
leakage, tries a normal retry, and performs an explicit laboratory reconciliation.

**Inside each call (#175).** The successful run is also traced with strace to count each call's
`fsync`s; every call that writes the header (cryptsetup 2.7.5: `luksAddKey` 3, `token import` 2,
`luksKillSlot` 3, `token remove` 2) is then re-run once per sync N with that sync answered by a KILL
(the whole run dies with it), a TERM (the run receives it once the call returns) or EIO (a failing
write). After a single command failure, the later calls interrupted are those that write the header.
Scenarios run in parallel, one private directory and image per worker.

**Observing never touches a run's image.** cryptsetup repairs a header whose secondary copy is stale
(a write cut between the two copies) on ANY load, a read-only `isLuks` included. So every observation
reads a copy, the header a fault left is saved byte for byte before anything reads it, and a stale
secondary header is a level-2 baseline of its own. Before this, level-2 sync faults were planned on
one header and run on its repaired twin, and `fault_not_injected` caught it.

**Level 2 (#175, d9's read).** Each distinct header a level-1 fault left unfinished is kept, and the
run that resumes it (the operator's next run after a crash) is faulted in turn: each of its
header-writing calls under each call fault, and each of their syncs under KILL, TERM and EIO. Each
level-2 case is followed by an ordinary run, which must finish it.

**The fixture.** Keyslot 0 is the installer's passphrase. Keyslot 1 is a TPM stand-in with a
`systemd-tpm2` token (no TPM): after every fault and every retry, that keyslot and token must be
byte-identical, and its key must still open the volume. Enrol starts from these two keyslots. Replace
starts from a commissioned header: the old recovery key enrolled by the script, and the installer's
passphrase wiped.

**The gate (#175).** A case is a finding when:
- the state the script printed last (`STATE: …`) differs from the state read here independently
  of the script (`header_state`, written separately from `deploy/baremetal/recovery_state.py`);
- the script says the header is unchanged while it is not;
- the identical retry does not FINISH the run (`ordinary_retry_does_not_reconcile`). Finishing means
  the expected state (enrol: `orphan-keyslot` with only the installer's keyslot unnamed; replace:
  `clean`), exactly one recovery keyslot, opened by the expected key (enrol: old, replace: new). For
  replace, the used key must also open nothing, by cryptsetup's own exit 2. The TPM keyslot must be
  untouched. A retry that ends with the right shape but the wrong key is a finding
  (`tests/test_recovery_matrix_observer.py` runs a mutated script that does this, and the matrix
  refuses it);
- a sync fault whose injection strace did not log (`fault_not_injected`).

Losing every card key, or the TPM stand-in, aborts the run. A header that is changed and not finished
right after the fault (`header_needs_reconciliation`) is recorded as an **observation**: any script
that writes the header more than once leaves one when it is killed between two writes.

**Repair.** With `--reconciler deploy/baremetal/recovery-reconcile.py`, a header that the retry did not
finish is repaired by that tool itself, as a custodian with every card would. Without it, a laboratory
repair is used.

**Shards.** `--mode enrol|replace` and `--shard i/n` run the level-1 scenarios whose position modulo n
is i-1, and level 2 from the headers those scenarios left. `lab/recovery/merge.py` checks the shards
as one run: all present and passed, they agree on the level-1 total and the sync table, and together
they ran that total exactly. CI (`recovery-matrix.yml`) runs 2 modes × 8 shards and the merge.

A failed enrollment leaving its original uncommissioned header is an expected
refusal. A changed header needing repair, an unchanged claim contradicted by the
header, or a retry that cannot reconcile remains a finding. The CLI exits 1 with
`completed-with-findings`; the report must not be described as production passing.

The fixture repair keeps the known old recovery key if it survives, otherwise the
known new key; it proves candidate slots before selecting one, removes only this
fixture's surplus slots/tokens, and verifies its installer key still works. This
is an observer's repair using all disposable keys, **not a production custody
policy or an authorized automatic deletion algorithm**.

When running inside Docker, use `--init` to reap orphaned children after KILL.
A missing target call is reported as incomplete fault coverage, never passing.

Scope: command boundaries of successful and single-failure cleanup paths, and every header sync of
every call that writes the header. It does not cover writes that reach the disk out of order (a real
power loss), recursively failing cleanup paths, or arbitrary repeated signals beyond the second level. This work supplies repeatable evidence for
the existing script and can also observe a proposed script by explicit path/hash.
