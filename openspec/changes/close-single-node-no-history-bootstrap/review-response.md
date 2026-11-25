# dx7.26 review response and closure map

Status: planned, not fixed. The independent review remains blocking until the evidence below passes. The source review is the parent-owned scratch `dx7-26-genesis-contract/REVIEW.md`, SHA-256 `a88cd0561e409e55881b3d3cb47f4b74be9edf5a87d879612c2b31c30525b1b2`. Its source pin is recorded in design.md. No original review disposition is overwritten.

| Finding | Design / requirement | Implementation slice and closure |
|---|---|---|
| 1 Empty reservation is not unused hardware | D1/D2; KMS-GEN-001–004 | A. Independent durable compare-and-consume authority; fixed live identity/device/layout and lifecycle exclusion. Unknown custody is refused, not declared fresh. |
| 2 Normal etcd can create/open unrelated history | D3; KMS-GEN-005/006/013 | H. Pinned existing-member-only recovery at actual opens; authenticated incarnation; no silent legacy adoption. |
| 3 Staged start and gate release race | D4; KMS-GEN-007–009/012 | S. Single actual activation; durable deny through normal readback; same-start KMS barrier, live manager evidence. |
| 4 Credential producer and service permissions missing | D5; KMS-GEN-010/011/012 | C then I. Real producer/seal/unseal/public-key proof, required name and exact profile, effective DAC/API and readiness handoff. |

## Named acceptance tests

- H: `normal_start_never_bootstraps`; actual pinned build, no-WAL/unreadable/missing/zero/mispair/substitute/swap cases; valid token/ID clone rejected; real restart, compaction/defrag and recoverable crash-tail controls.
- S: `kms_dependency_cannot_skip`, `stage_start_is_single_use`, `post_exchange_kms_stays_gated`, `crash_windows_keep_pending`; shipped Debian PID 1, reboot/lost runtime state, stale loaded overrides, second queued start, owner exit, staged/wrong endpoint, failed readback, concurrent/manual/already-active units. Record manager job, main process, endpoint identity and pending state.
- A: `replay_epoch1_after_disk_loss`, `erased_reservation_same_identity_requires_authority`, `alternate_nv_or_tcti_is_not_fresh`, `inventory_error_is_not_absence`, `consumed_zero_anchor_does_not_resume_genesis`, `commit_disk_before_tpm_is_not_a_grant`, `reanchor_recount_interleavings_keep_consumed`, `concurrent_commission_consumes_once`. Cover every consuming boundary, adopted/partial/unknown/wrong-device/replay state; missing/rolled-back ledger, duplicate consumption, replayed replies and crashes after consume.
- C/I: `wrong_peer_credential`, `successful_genesis_preserves_old_contracts`; TPM binding, exact name/seal/unseal/key equality/certificate validity, effective unit permissions before consumption, actual staged genesis, protected receipt, normal restart, signed restore and multi-node/package controls.

Each slice needs its negative controls caught and no-op/restored controls green. Logical model cases and fixture-only credentials do not close these tests. Physical power loss, reboot and TEST lost-disk restore are separate final acceptance. The earlier 145-test partial guard run is supporting evidence only.

## Second review correction map

The independent genesis-plan-review.md found three additional blockers and a proof-sequencing clarification. The following are artifact corrections, not implementation passes; independent re-review remains pending.

| Finding | Contract correction | Required proof |
|---|---|---|
| Restore staging could use blank genesis fallback | D3; KMS-GEN-005 extends existing-only recovery to signed-restore staging and adoption; creation only under first-store consumption | `restore_stage_never_bootstraps`, including partial snapshot and post-unpack substitution before epoch write |
| Fresh nonce could imply another slot | D1; KMS-GEN-002 keys one stable identity-lineage permit, separate from the response nonce; explicit intake/transition required | `new_nonce_cannot_reissue_first_store`, different concurrent callers/nonces, re-enrol and rolled-back authority |
| Old rollback image could ignore pending | D6/migration; KMS-GEN-013 requires guard-compatible operational image set and actual boot-policy enforcement or independent fence | `rollback_image_keeps_deny`, pending plus lost runtime state; ineligible incompatible image control |
| Replacement gate blocked independent genesis proof; reachable ledger and receipt claims were too broad | D1/D3/D7; KMS-GEN-002/006/014; G is separate from replacement/restore I; authoritative intake and available floor required | `fresh_genesis_proof_independent_of_replacement`, `unavailable_floor_refuses_readiness`, and unknown-custody refusal even with a reachable ledger |
