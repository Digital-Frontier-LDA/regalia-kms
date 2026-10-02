# Explicit reconciliation checkpoint — 2026-10-02

Native Debian arm64, real cryptsetup 2.7.5, disposable 32 MiB regular-file LUKS2
volumes. Unsigned development tools image:
`sha256:d1eaa43878780eaa7ca5f7ad2f34e57917be9caf82e270933e656dabd8d457a1`.
No root, device mapper, loop devices, hardware TPM, host credentials or host disks.
The container used `--init`, no capabilities/new privileges, readonly source and
private temporary fixture storage. Tested utility bytes were frozen before use.

**110/110 interruption points passed**, across 22 cryptsetup command boundaries
and five faults: failure before/after, TERM after, KILL before/after. Every
same-card/same-selection retry finished. The installer and an unknown keyslot
retained identical metadata and normal unlock availability. Four negative
controls refused wrong cards, non-recovery ownership and a retired card that
still opens an unselected copy. That copy remains available for a custodian's
explicit decision. Four unit guards also pass, including alias mutual exclusion.

Final utility SHA-256: `8327ad267048adc61cd8cd305a448a957e6cb907aa36ce339cb79a0e44cd6b39`.
Full local report SHA-256: `d55d75830027dbab640332c181e649364392eeef582e45fc6e0723d3526b1bb8`.
Report: `/tmp/regalia-recovery-evidence/reconcile-retirement-final.json`.
Elapsed: 102.754 seconds. The test rejects an ambiguous
command failure as retirement proof; normal wrong-passphrase exit status is
required. CI also verifies that refusal at the final card-check boundary.
This is command-boundary evidence, not internal sector-write qualification.

An earlier revision (`a08f98831ffa70278019dbe301d0d8de042deed56be845316ba82f78517712b6`)
completed explicit custodian repair across **622/622** legacy interruption states,
retaining all unlock paths. Its inner legacy report still had 172 finding cases;
no release admission was granted. Summary is retained at
`/tmp/regalia-recovery-evidence/legacy-operator-reviewed-operator-summary.json`.
The final stricter version is undergoing the same full CI experiment; earlier
source hashes are not substituted for final-source verification.

A first prototype tried to lock the device inode; real cryptsetup also locks it,
so that prototype timed out. It was rejected. The tested revision uses a separate
private mutex, validates owner/type/link count/permissions, and preserves
cryptsetup's own locking. External writers still require console serialization.

The existing merged recovery script remains distinct: 622/622 interruption
scenarios, 172 finding cases and 68 retries needing explicit repair. No gate is
waived. This utility requires custodian choices and card proofs and does not
replace enrollment or decide generated-key custody under #175.
