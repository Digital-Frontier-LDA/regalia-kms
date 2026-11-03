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
The final stricter version also passed the full CI experiment, as recorded below;
earlier source hashes are not substituted for final-source verification.

## Final-source Linux CI evidence

[Run 37071509470](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37071509470)
passed with real cryptsetup 2.7.0 on Ubuntu 24.04. The downloaded
`explicit-recovery-reconciliation-evidence` artifact was checked against the
current utility SHA-256 above and against its own full legacy report hash:

| Report | SHA-256 | Result |
| --- | --- | --- |
| `matrix.json` | `5a4d103c0b51055e33d32266c6703714d4c1ac6e1198fd480e685b572ef05116` | 110/110 cuts reached and passed; four negative controls; unknown keys retained |
| `legacy.json` | `dcf0105dd3421719f3e0c8c859e47e78f3c564a74dc6b3cda9e47394321127e6` | 622/622 legacy cuts reached; 172 findings remain |
| `legacy-operator-summary.json` | `9fd2c84a2bebbaf347b7fd0f80328078bdad352e998b803a520d08d7ce622fe9` | All 622 explicit repairs clean; all unlock paths preserved |

The legacy script SHA-256 was
`47e08272c808863fff8b524faa5146620e3375db7af5810ffa20aacb6e77afab`.
The laboratory custodian has all fixture cards and makes explicit slot choices;
this does not qualify automatic production custody decisions. Every report keeps
`production_approved=false`; both legacy reports keep `release_admissible=false`.
The unchanged final code passed again in
[run 37072093025](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37072093025).
Artifact retention is 14 days; this checkpoint retains the verified digests and
results, not a substitute for the complete reports.

A first prototype tried to lock the device inode; real cryptsetup also locks it,
so that prototype timed out. It was rejected. The tested revision uses a separate
private mutex, validates owner/type/link count/permissions, and preserves
cryptsetup's own locking. External writers still require console serialization.

The existing merged recovery script remains distinct: 622/622 interruption
scenarios, 172 finding cases and 68 retries needing explicit repair. No gate is
waived. This utility requires custodian choices and card proofs and does not
replace enrollment or decide generated-key custody under #175.
