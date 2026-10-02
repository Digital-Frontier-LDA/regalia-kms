# Explicit reconciliation checkpoint — 2026-10-02

Native Debian arm64, real cryptsetup 2.7.5, disposable 32 MiB regular-file LUKS2
volumes. Unsigned development tools image:
`sha256:d1eaa43878780eaa7ca5f7ad2f34e57917be9caf82e270933e656dabd8d457a1`.
No root, device mapper, loop devices, hardware TPM, host credentials or host disks.
The container used `--init`, no capabilities/new privileges, readonly source and
private temporary fixture storage. Tested utility bytes were frozen before use.

**105/105 interruption points passed**, across 21 cryptsetup command boundaries
and five faults: failure before/after, TERM after, KILL before/after. Every
same-card/same-selection retry finished, leaving one normal-priority recovery
mapping and no orphan recovery tokens. The installer and an additional unknown
keyslot remained byte-for-byte unchanged in metadata and usable through normal
boot unlock tests. Three negative controls (wrong kept card, wrong retired card,
hardware/shared ownership) refused before any mutation. Four unit guards also
passed, including mutual exclusion across device aliases.

Script SHA-256: `a08f98831ffa70278019dbe301d0d8de042deed56be845316ba82f78517712b6`.
Full report SHA-256: `b12d2351cd43195e581189bded15614ba55d05d184c8d381842d7b3161f506c3`.
Report retained at `/tmp/regalia-recovery-evidence/reconcile-reviewed-final.json`.
Elapsed: 75.606 seconds. This is command-boundary evidence,
not arbitrary internal sector-write or physical power-loss qualification.

A first prototype tried to lock the device inode; real cryptsetup also locks it,
so that prototype timed out. It was rejected. The tested revision uses a separate
private mutex, validates owner/type/link count/permissions, and preserves
cryptsetup's own locking. External writers still require console serialization.

The existing merged recovery script remains distinct: 622/622 interruption
scenarios, 172 finding cases and 68 retries needing explicit repair. No gate is
waived. This utility requires custodian choices and card proofs and does not
replace enrollment or decide generated-key custody under #175.
