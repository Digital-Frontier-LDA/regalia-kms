# Regalia KMS OpenSpec

This is the repository-local contract baseline at source `0a32a901d1240eec51ddff323274e2ad935116f3`. Main capability specs live in `specs/`; the baseline authoring change remains active in `changes/document-kms-spec-baseline/`. These files document accepted contracts and explicit delivery gaps. They do not certify implementation or release acceptance.

Start with the [behavior coverage report](coverage/coverage-report.md). Its exact case ledger, source pin, classifications and discovery gaps define the current evidence boundary. **Coverage is incomplete and CI enforcement is not installed.** Spec, scenario and test totals are not a completeness measure.

- [Capability catalog](coverage/capability-catalog.json)
- [Coverage acceptance policy](coverage/LEDGER-POLICY.md)
- [Baseline checklist](changes/document-kms-spec-baseline/tasks.md)
- [CI ratchet design and remaining work](coverage/RATCHET.md)
- [Separate first-store commissioning plan](changes/close-single-node-no-history-bootstrap/design.md)

The proposed first-store authority, recovery-open guards and compatible rollback work remain separate from the main baseline. Their corrected plan passed independent documentation re-review; implementation, operational authority and physical acceptance remain open. Local unmerged replacement/guard candidates are not delivered evidence.

Validate the main specs with the pinned OpenSpec 2.1.1 CLI using `openspec validate --specs --strict`. Validate active changes separately with `openspec validate <change> --strict`. Validation checks document form and consistency, not the truth of runtime or hardware claims.
