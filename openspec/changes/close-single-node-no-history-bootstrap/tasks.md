# Tasks

All tasks are open. Planning artifacts do not close implementation or acceptance. H and A can begin in parallel; C follows the A identity interface; S integrates H; Fresh-genesis software proof G requires H+A+C+S. Replacement/restore integration I additionally requires the separately reviewed replacement hook; that restriction must not block G. The designated implementation worker authors each slice and a different reviewer verifies it. No operational authority or hardware action is approved by this checklist.

## 1. H — Existing-history startup and provenance

- [ ] 1.1 Freeze the pinned etcd 3.6.15 source/build and define the existing-member-only interface; verify a source/open-path inventory identifies every backend, WAL and snapshot creation or recovery point.
- [ ] 1.2 Enforce existing-only recovery at actual opens and deny discovery/force-new-cluster on the normal path; verify `normal_start_never_bootstraps` and `restore_stage_never_bootstraps` refuse absent, unreadable, zero, corrupt and post-unpack substituted backend/WAL on normal, signed-restore and adoption paths before serving or writing a raised epoch.
- [ ] 1.3 Bind a unique history incarnation inside the member and in a protected external receipt; verify a separately initialized valid store with identical token/member IDs and a mismatched WAL/backend pair both refuse readiness.
- [ ] 1.4 Bind actual recovery objects through use; verify injected disappearance and pathname substitution after preflight refuse, while real restart, compaction/defrag and recoverable crash-tail controls pass.
- [ ] 1.5 Define authenticated legacy adoption/refusal and the external rollback-floor boundary; verify unknown lineage, older authorized-state floors and `unavailable_floor_refuses_readiness` refuse, and publish operator recovery instructions that never suggest automatic genesis.
- [ ] 1.6 Independently review the source/open boundary and run exact-head CI plus fresh-cache removal/no-op/restored controls; save the tested tree, enforcing assertions, negative results and reproducible build identity.

## 2. A — Independent commissioning authority and one device lifecycle

- [ ] 2.1 Record the authority schema, compare-and-consume protocol, independent monotonic checkpoint and recovery procedure; verify a reviewed contract defines stable identity-lineage permit slots, separately authorized intake/transitions, full genesis/device/layout bindings and response-only nonces. Unknown/used custody without authoritative intake must refuse even with a reachable ledger. Physical issuance remains gated on custody approval.
- [ ] 2.2 Implement fail-closed issuance from that independent authority; verify `new_nonce_cannot_reissue_first_store`, re-enrolment, missing/rolled-back established state, duplicate consumption, replayed replies and crash after consumption never allocate a new unused permit slot. Do not inherit the restore ledger's empty-on-missing behavior.
- [ ] 2.3 Bind all TPM identity, live owner-authorization, inventory and child-tool operations to one protected device/allocation; verify `alternate_nv_or_tcti_is_not_fresh` and `inventory_error_is_not_absence` with a real software TPM and wrong-device controls.
- [ ] 2.4 Enforce one lifecycle exclusion/lock ordering across enrol, re-anchor, recount, restore, publication and normal starts; verify two actual concurrent actors in `concurrent_commission_consumes_once` and `reanchor_recount_interleavings_keep_consumed` cannot create a grant or unsafe publication.
- [ ] 2.5 Refuse occupied/partial/adopted reservations and uncertain-write retries; verify `replay_epoch1_after_disk_loss`, `erased_reservation_same_identity_requires_authority`, `consumed_zero_anchor_does_not_resume_genesis` and `commit_disk_before_tpm_is_not_a_grant` at every consuming crash boundary.
- [ ] 2.6 Document authority custody, loss and burned-attempt recovery; independently review the slice and save software-TPM, mutation-control and exact-head CI evidence without claiming physical acceptance.

## 3. C — Credential producer and effective access

- [ ] 3.1 Implement the operator credential producer using the A identity interface and approved systemd credential path; verify TPM-backed public binding, seal/unseal and private-key/certificate equality before authority consumption.
- [ ] 3.2 Validate exact genesis-rendered config, certificate profile/trust/expiry and `etcd-peer.key` name; verify `wrong_peer_credential` covers wrong key, identity, TPM, name and expired/untrusted certificate and that no plaintext is logged or persisted.
- [ ] 3.3 Implement confined offline history inspection without new etcd/KMS TPM privileges; verify effective UID, 0700 data access, capabilities and permitted file/socket/API operations under shipped units, including denial controls.
- [ ] 3.4 Require supported single-node serving-state configuration; verify omitted watcher/endpoint, wrong socket DAC, unauthorized API and an active staged/wrong member cannot satisfy readiness.
- [ ] 3.5 Document credential production, delivery and failure recovery; independently review and save seal/unseal, permission, mutation-control and exact-head CI evidence. A post-consume failure must leave pending and burn the attempt.

## 4. S — Durable guard and live service-manager coordination

- [ ] 4.1 Integrate the reviewed H recovery boundary into the partial guard candidate and persist pending before boot-eligible publication; verify the patch scope and durable state across each publication/exchange interruption.
- [ ] 4.2 Consume stage authorization at actual execution and cancel/isolate queued or surviving stage jobs; verify `stage_start_is_single_use` under shipped live systemd with second manual activation and owner exit between condition and exec.
- [ ] 4.3 Keep KMS denied through authenticated normal-member readback, then enforce fresh same-start readiness; verify `post_exchange_kms_stays_gated` with concurrent manual starts, failed readback and changes between check and execution.
- [ ] 4.4 Install the guard in verity-covered bare-metal units and positively verify profile exemptions; verify `kms_dependency_cannot_skip` with missing/invalid profile, condition-skipped/retained dependencies, staged endpoints, already-active etcd and a valid multi-node/package control.
- [ ] 4.5 Verify `crash_windows_keep_pending` under live Debian PID 1 across lost runtime state, loaded overrides, cancelled/queued jobs and reboot; record actual manager result, main process, endpoint identity and durable pending state.
- [ ] 4.6 Update the operator service/recovery runbook; independently review lock ordering and manager behavior, and save removal/no-op/restored controls and exact-head CI. Fixture condition evaluation alone is insufficient.

## 5. G then I — Separate software commissioning and replacement integration

- [ ] 5.1 Integrate independently reviewed H+A+C+S on a pinned main without the replacement candidate; verify scope/conflict provenance and run `fresh_genesis_proof_independent_of_replacement` so the pending replacement review cannot block fresh-genesis software evidence.
- [ ] 5.2 Run `successful_genesis_preserves_old_contracts` with actual authorized staged first genesis, durable receipt, normal restart and enforced floor; verify the same single-use permit and preserve owner unlock, self-lease, activation and refusal contracts.
- [ ] 5.3 Obtain completed independent review of the replacement candidate and its pre-publication pending hook through an allowed route; verify an explicit completed disposition. Do not bypass the separate platform restriction. This gates I and physical replacement, not tasks 5.1–5.2.
- [ ] 5.4 Integrate the reviewed replacement/restore hook and signed epoch-raising restore into the G tree; verify existing-only restored-history startup, correct incarnation and fail-closed readiness before and after publication/exchange.
- [ ] 5.5 Run multi-node/package, revocation and fencing controls; complete independent integrated-head review and all applicable hosted CI, verify no blocking finding, preserve the immutable limits document and save the exact tested tree/revision.

## 6. Physical acceptance and milestone reconciliation

- [ ] 6.1 Resolve bench/VSP ownership and verified image-build route before appliance work; verify ownership and image/input identities without bypassing DRIVEN_ELSEWHERE or an unanswered safety gate.
- [ ] 6.2 Prepare fresh TEST image and guard-compatible rollback set; verify local TEST signing, image/install hashes, actual enforced boot eligibility and approved authority/credential scope. Prove `rollback_image_keeps_deny` with pending and lost runtime state; an eligible incompatible operational image blocks commissioning. Diagnostic media needs a separate non-serving fence.
- [ ] 6.3 Execute attended commissioning, distinct normal boots, interruption and lost-disk signed-restore tests on eligible staging hardware; verify real TPM, durable deny, normal existing history and refusal controls with separate boot/process IDs. Never infer TPM reset from an iLO reset or disk wipe.
- [ ] 6.4 Reconcile release/task coverage and rebase both Gantts using measured slice durations and actual approvals; verify every review finding has linked passing evidence and the v0.1 restore gate remains open until physical acceptance completes.

## Workflow follow-up

- After implementation, acceptance and review, synchronize the completed delta and archive through the OpenSpec workflow.
- Keep production ceremony and three-node physical qualification as their own acceptance gates; this change does not grant production release approval.
