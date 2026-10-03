# Recovery interruption matrix

Run only on disposable laboratory fixtures:

```sh
python3 lab/recovery/matrix.py \
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

**The gate (#175).** A case is a finding when:
- the state the script printed last (`STATE: …`) differs from the state read here independently
  of the script (`header_state`);
- the script says the header is unchanged while it is not;
- the identical retry does not end clean (`ordinary_retry_does_not_reconcile`).
Losing every old/new key, or the installer key, aborts the run. A header that is changed and not
clean right after the fault (`header_needs_reconciliation`) is recorded as an **observation**:
any script that writes the header more than once leaves one when it is killed between two writes.

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
power loss), recursively failing cleanup paths, arbitrary repeated signals, or `--host-generated`
(systemd-cryptenroll's own writes, measured once on #175 and refused until the owner decides). This work supplies repeatable evidence for
the existing script and can also observe a proposed script by explicit path/hash.
