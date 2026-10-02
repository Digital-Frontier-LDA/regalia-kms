# Recovery interruption matrix

Run only on disposable laboratory fixtures:

```sh
python3 lab/recovery/matrix.py \
  --script deploy/baremetal/recovery-key.sh --output /private/evidence/recovery-matrix.json
```

Requires Linux, Python 3, Bash and real cryptsetup. Missing tools fail; nothing is
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

Scope: command boundaries of successful and single-failure cleanup paths. This does not enumerate every
sector write inside libcryptsetup, all possible recursively failing cleanup paths or arbitrary repeated signals,
physical power loss, or systemd-cryptenroll's internal enrollment/wipe writes.
Those remain separate gates in #175. This work supplies repeatable evidence for
the existing script and can also observe a proposed script by explicit path/hash.
