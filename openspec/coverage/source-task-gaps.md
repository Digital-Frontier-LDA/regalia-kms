# Source, task and milestone coverage gaps

Source pin `0a32a901d1240eec51ddff323274e2ad935116f3`, tree `347cc36bd44945fcff8a6624237222cb64c0cf17`. Task status and dependencies are from the 21 November 2026 schedule snapshot. This document records proposed slices. It confers no approval to file tasks, change release scope or operate hardware.

[Per-path, per-task and per-case ledger](source-task-coverage.json) · [Behavior coverage report](coverage-report.md)

## Priorities

- **Shared state** — The real daemon opens a local journal at `cmd/regalia-kms/main.go:274`. The watcher starts separately at `:852` and `:877`; the shared reservation constructor exists at `internal/opstate/reserve.go:53`. A component race has one winner. The daemon wiring needed for that outcome at the serving boundary is open. [Service integration contract](../specs/runtime/service-integration/spec.md)
- **No-history service startup** — The pinned etcd unit uses its ordinary config and checks config presence. Single-member rendering uses `new`. The installed contract still needs actual-open WAL/backend recovery, incarnation and independent floor, distinct one-use staging, and the barrier on each KMS start. The current conflicts include missing history, manual starts, loss of volatile authorization and service startup during exchange. Authority and boot eligibility decisions remain separate implementation prerequisites. [Pinned unit](../../deploy/baremetal/units/regalia-etcd.service#L11) · [ETCD rendering](../../deploy/baremetal/etcdconf.py#L188) · [Commissioning design](../changes/close-single-node-no-history-bootstrap/design.md)
- **Collector policy** — Single-node limitations specify mandatory independent audit collection for stateful operations. The general daemon can construct a nil sink with no URL. Source also exposes local policy state rather than proving the single-node etcd stateful behavior declared in the immutable limits. These require a scope/enforcement decision and actual refusal evidence. A retained receipt supplies a signed position without current time. TEST evidence collection and production policy have distinct acceptance. [Immutable limits](../../docs/single-node-limits.md#L26) · [Daemon sink](../../cmd/regalia-kms/main.go#L712) · [Receipt limitation](../../LIMITATIONS.md#L616)
- **Full CI ratchet** — The prototype checkbox records scoped checker evidence. Discovery, a revision-bound producer/evidence protocol, an accepted precise legacy-gap budget, workflow integration and separate forge policy evidence remain open. The baseline maintains 9 hosted/emulated cases and 454 unresolved/proposed cases. [Ratchet design](RATCHET.md) · [Baseline tasks](../changes/document-kms-spec-baseline/tasks.md)
- **Compatibility and older changes** — Cosmos order/admit/normalize/refuse, fee identity and consumed-signature/sequence recovery require explicit decisions. Existing hashing of original admitted bytes narrows the older claim. The ceremony touch-policy dispute remains external. The custody generator and validator need shared positive and negative vectors. [Runtime discovery gaps](runtime-discovery-gaps.md) · [Cosmos boundaries](../../COSMOS-SUPPORT.md)
- **Candidate evidence** — `695`, `9088` and `5ce` remain unshipped. The restricted replacement review remains paused. Fresh-genesis software proof can proceed independently via H, A, C, S and G. Scoped replacement review and physical restore remain gates for v0.1 as currently defined. [Commissioning tasks](../changes/close-single-node-no-history-bootstrap/tasks.md)

## Critical path and responsibility gaps

Roles below identify who has to confirm each dependency. They do not indicate assignment, bookings or authorization.

| Gate | Type | Snapshot disposition | Responsible role to confirm | Dependency or evidence needed |
| --- | --- | --- | --- | --- |
| Runtime/source freeze | implementation and verification | PR759 source/hosted tree accounted. S16 integrated guard review, exact candidate and unresolved advertised defects remain. | Engineering and independent reviewer | S01 scope; ST-02 through ST-07 as applicable. Do not wait for installed-only 41n or ib0 closures before forming the candidate. |
| Build, console and route | ownership and authorization | Native or approved image build and console/VSP route ownership are unconfirmed. | Build/bench operator and owner | Confirm allowed route, native build/provenance and fail-safe serial/operator access. Existing server availability does not grant access. |
| Additional node access | owner action | Two additional iLO passwords require manual reset. Only one staging node is available. | Owner | Complete iLO access reset before additional-node preflight. Preserve TPM identity and prior eligibility checks. |
| Eligible spare identity and TEST HSM | hardware availability and owner authorization | A timed one-node replacement needs an eligible distinct TPM/TEST HSM; a three-active-host drill needs additional eligible spare capacity. Unconfirmed. | Owner and bench operator | Check intake and distinct custody; dx7.24 is conditional on an applicable lost grant floor. Confirm without assuming a fourth server or a TPM reset. |
| Fresh genesis software proof | implementation and verification | H+A+C+S lead to G with no replacement-review prerequisite. | Engineering and independent reviewer | Advance isolated work under applicable authority. No operational commissioning from software proof alone. |
| Replacement integration and restore | review restriction, implementation and physical proof | Independent replacement implementation review remains blocked. Restore and actual-open service guards are proposals. | Parent/authorized independent route and operator | Reviewed hook + G → I; compatible rollback and trusted floor, rehearsal, then timed hardware restore and canary evidence. No rerouting. |
| One-node TEST milestone | measured acceptance and owner decision | Attended owner card, independent TEST collector, restored-state checks, 72h burn-in and attended reboot are unaccepted here. | Owner, reviewer and bench | Exact image, eligible TEST assets, verified restore and active receipt witness. Preserve selected advertised limitations. |
| Three-colocated-node TEST mesh | qualification and owner scope | TEST-vs-production acceptance map, soak duration/fault budget, spare and physical controlled cases remain unconfirmed. | Owner, reviewer and bench | Protect the shared staging reservation until v0.1 acceptance. Rehearse tested topology and repeat verification after candidate change as required. |
| Three-node production and optional one-node gate | owner authority and production qualification | Three-node production is a new genesis after production-specific prerequisites. Optional single-node production retains its own mandatory criteria. | Owner and production ceremony custodians | Production build/PKI/TPM/HSM intake and ceremony, real-site/witness evidence, scoped pilot signoff. Neither conditional TEST date is a production promise. |

The intended path is one-node v0.1 TEST (`ion`), three-colocated-node TEST staging (`2k9`), then separately qualified three-node production through a **new genesis** (`1h7`). Keep optional single-node production `2jd` independent. Its full production criteria remain applicable if pursued. The Gantt dates remain conditional snapshot forecasts. No date was adjusted and no production date follows from this reconciliation.

## Dependencies and latent sequencing loops

All 146 recorded task `blocks` edges are acyclic. The 57 schedule packages have 77 acyclic predecessor edges, or 78 when the in-burn-in start condition is included. The 69 parent-child, 23 related and 8 discovered-from links are contextual. None should be treated as an acceptance prerequisite by default. The formal graphs miss the following sequencing corrections.

| Recorded relation or boundary | Proposed correction |
| --- | --- |
| S12 after S10 in older schedule | Remove the dependency for H/A/C/S and G only. Keep permitted independent review before I and before physical restore/release. |
| S19 candidate freeze versus S21/S22 installed criteria | Use pinned merged source for the candidate and move the 41n and ib0 installed closures downstream. A demand to close those tasks before forming the image would require evidence of a candidate that cannot be built. |
| S04/S05 upstream of finishing G | Separate confirmed hardware and TEST material readiness from software-only fresh genesis. Keep both as prerequisites to physical issuance, and distinct-device intake before timed replacement. |
| S24 collector evidence versus production witness | Require bounded independent TEST witness before collecting TEST evidence. Separately settle immutable mandatory-collector product claim and later production verification; a release-scope review cannot erase the claim. |
| S06/S07 old failure prerequisite versus S08/S09 now shipped | Record exact-head run and merge at this source pin. Preserve the older c-to-a reset as independent unresolved diagnosis; current source does not establish its fix. |
| M14 reserved bench versus M20 test inventory | Keep S30 before reclaiming the shared staging node. Confirm spare inventory in parallel. Avoid counting a host still needed for v0.1 evidence as a simultaneously free three-node spare. |
| M25/M26 TEST acceptance versus production-only criteria | Record each accepted TEST equivalent before staging milestone closure. Preserve original tasks' full production criteria, and keep the optional 2jd gate off the intended production dependency path. |
| Authority approval versus implementation proof | Decide protected authority/custody before real consumption. Software H/A/C/S/G evidence and eligible-interface design can proceed without operational approval. Require guard-compatible rollback before operational commissioning, not as a post-commission demonstration. |

The source-only improvements still shown open or in progress in the input are `41n`, `4h4`, `5m2`, `9tv`, `a0g`, `dx7.10`, `dx7.14`, `dx7.17`, `dx7.34`, `dx7.35`, `dx7.38`, `ib0` and `r1s.19`. The JSON gives their exact ancestral commit and missing acceptance. For `4h4` and `a0g`, the pinned change improves diagnostics. The cause and repeatability of the original failure remain unproven. For `dx7.10`, the accepted PR tree supplies the scoped software record. The older c-to-a recovery reset remains unresolved.

## Remaining joins

The JSON includes the full 1,244-path and 163-task sets, and the exact unresolved lists in `maintainedOpenSets`. It distinguishes 257 paths with source/assertion case or requirement locators, 722 with source-area context only, 259 needing manual alias/caller or capability review, and six explicit governance/scaffolding paths. The 987 paths without an exact locator include those six. Verification scripts and data, CI dispatch, operators' tools, unit and generated inputs, docs and dependency pins remain in the inventory. No tracked vendor tree is present. Role accounting does not approve exclusions or close interface discovery.

Of the 163 task IDs, 65 have at least one explicit requirement, case or authored gap relation. The remaining 98 have a capability, milestone or scope relation and still need an exact acceptance trace. Among 454 open behavior rows, 25 have a named case-task relationship, five have requirement context only and 424 lack a specific recorded join. Wide umbrella tasks and conditional schedule packages do not imply coverage for each named case. The nine authored gap groups without a bead in the original field have explicit adjacent-task or proposed-slice links in `knownGapProposalLinks`.

## Issue-ready proposed slices

### ST-01 · Specify and wire shared operational state into serving

- **Work type** — implementation plus qualifying verification.
- **Recorded coverage** — No dedicated recorded task for the daemon composition. dx7.26 is adjacent startup work, not shared serving ownership.
- **Scope** — Bind the accepted etcd revision, lease and durable per-operation reservations at the real daemon entry point while preserving local-profile behavior.
- **Acceptance** — Two actual serving nodes contend for a nonce with one result, fail closed on unavailable/stale store and revoke/leader transition, preserve spend/quota/sequence and prove a single-node profile explicitly.
- **Dependencies** — Accepted consistency/state-model decision and reviewed etcd deployment; does not gate isolated fresh-genesis software proof unless its acceptance explicitly depends on shared serving.
- **Trace** — `KMS-RUNTIME-006`, `KMS-ETCD-003`, `KMS.opstate.parallel-shared-reserve`.

### ST-02 · Approve commissioning authority, intake and monotonic lineage floor

- **Work type** — owner design and authority.
- **Recorded coverage** — dx7.26 is a recorded umbrella; no separate intake, floor-custody or authority ownership task was found.
- **Scope** — Choose and authorize the independent checkpoint holder and stable one-use lineage contract across devices, re-enrol and custody changes.
- **Acceptance** — Two actors cannot consume twice; used/unknown intake and absent, replayed or rolled-back authority refuse; post-consume crash cannot mint another permit. Bind the accepted identity and canonical reservation. No physical issuance until recorded approval.
- **Dependencies** — Owner/root authority decision and review of intake/checkpoint custody. H and bounded software simulations may proceed independently.
- **Trace** — `KMS-RESTORE-003`, `KMS-STATE-005`, `KMS.first-store.no-authoritative-floor`, `KMS.first-store.nonce-independent-permit`.

### ST-03 · Enforce existing-history recovery at actual pinned etcd opens

- **Work type** — implementation and qualifying verification.
- **Recorded coverage** — dx7.26 mentions services stopped on replacement; no separate actual-open/provenance implementation task found.
- **Scope** — Implement existing-member-only normal, staging and adoption modes plus a protected incarnation receipt/floor. Leave creation solely to the consumed first-store authorization.
- **Acceptance** — Pinned etcd tests exercise missing/corrupt/mispaired/substituted backend or WAL and same-ID clone, actual-open substitutions, no epoch write or readiness, and legitimate crash-tail/maintenance/restart controls.
- **Dependencies** — Freeze H interface and pin interface/binary; service gating integrates H, while G needs H+A+C+S.
- **Trace** — `KMS-RESTORE-003`, `KMS-ETCD-004`, `KMS.first-store.absent-member-history`, `KMS.first-store.restore-stage-substitute`, `KMS.first-store.wrong-live-member`.

### ST-04 · Produce and validate commissioned peer credentials before authority consumption

- **Work type** — implementation and qualifying verification.
- **Recorded coverage** — Related credential/TPM tasks exist; their scope does not supply the proposed peer TLS producer or DAC/API evidence.
- **Scope** — Build the operator-facing peer TLS producer, boot/device binding and protected systemd delivery path for the intended service.
- **Acceptance** — Prove seal/unseal and cert/key correspondence before consumption; wrong device/key/profile/name/expiry refuse; actual unit DAC/API access is bounded and no plaintext remains in retained artifacts.
- **Dependencies** — Canonical identity interface from A, approved credentials and delivery contract; no real grant needed to exercise software producer.
- **Trace** — `KMS-ETCD-002`, `KMS-ETCD-004`, `KMS-CUSTODY-003`, `BMCASE-enrol-commit-proposed-credential-wrong`.

### ST-05 · Enforce rollback eligibility and durable service handoff

- **Work type** — design, implementation and qualifying verification.
- **Recorded coverage** — dx7.26 and w6m are adjacent. Neither snapshot scope establishes a complete guard-compatible image set at actual boot eligibility.
- **Scope** — Enforce compatible operational image eligibility or an independent fence. Bind one authorized stage and put normal history verification ahead of every KMS start.
- **Acceptance** — An incompatible but signed image cannot serve; approved rollback with volatile state lost stays pending. Manual, queued, already-running, condition-skipped, and failed-readback cases refuse under shipped systemd; state after crash remains conservative.
- **Dependencies** — H plus finalized image/credential fence contract. Approved eligible set blocks operational commissioning. Hold replacement integration behind separately reviewed hook.
- **Trace** — `KMS-RESTORE-003`, `KMS-UPDATE-002`, `KMS.first-store.rollback-image`, `KMS.first-store.staged-manual-restart`, `BMCASE-kms-start-proposed-post-exchange-readback`.

### ST-06 · Separate fresh-genesis software verification from physical replacement acceptance

- **Work type** — sequencing and qualifying verification.
- **Recorded coverage** — dx7.19, dx7.26 and dx7.13 are recorded but the old S12→S10 prerequisite is broader than the corrected plan.
- **Scope** — Schedule G independently, then require reviewed replacement and signed restore integration plus physical restore before accepting v0.1.
- **Acceptance** — Revision-bound fresh G passes without a replacement candidate. Later I proves guarded installed restore, exact retired identity refusal and timed physical recovery restoring distinct canaries.
- **Dependencies** — H+A+C+S→G. G plus permitted independent replacement review→I. I plus guard-compatible rollback, bench and authorized TEST assets→physical drill.
- **Trace** — `KMS-REPLACE-003`, `KMS-RELEASE-002`, `KMS.first-store.fresh-genesis-proof`.

### ST-07 · Resolve single-node mandatory collector policy and TEST witness boundary

- **Work type** — owner scope decision, implementation and verification.
- **Recorded coverage** — dx7.9 tracks monitoring/audit generally; it is missing an explicit topology-level mandatory fail-closed policy acceptance split.
- **Scope** — Keep the immutable acknowledged text. Decide eligible stateful operations, what proves a witness is available, and what product/config proof gates the release claim. Scope admitted TEST witness separately from production operation.
- **Acceptance** — Verify absent/unreachable/foreign collector refuses required stateful operations at real service boundary, restored reachability permits control, and local journal durability/alerts remain attributable. For TEST retain independently persisted witness and verified reconciliation.
- **Dependencies** — S01 release claim decision, owner policy, qualified TEST or production collector as applicable. Do not require production witness acceptance before a TEST-only evidence collection run.
- **Trace** — `KMS-SEC-003`, `KMS-AUDIT-005`, `KMS-STATE-005`.

### ST-08 · Define fresh collector receipts for recovery decisions

- **Work type** — design and verification.
- **Recorded coverage** — 294 already tracks the core stale-receipt defect; it lacks a named acceptance join to restore, floor and re-anchor decisions in the Gantt.
- **Scope** — Specify freshness binding and reachable/unavailable semantics separately from sequence/hash signature verification.
- **Acceptance** — Past valid, foreign, and unavailable witness controls cannot qualify as current, while exact fresh response with the correct held history qualifies. Missing freshness denies only the scope that requires it; report bounded degraded behavior explicitly.
- **Dependencies** — Owner recovery/witness policy; resolve before relying on a receipt as a live authoritative floor.
- **Trace** — `KMS-AUDIT-004`, `KMS-RESTORE-004`, `COLLECTOR.receipt.receipt-freshness`.

### ST-09 · Produce revision-bound discovery and verification input for the coverage ratchet

- **Work type** — tooling implementation and verification.
- **Recorded coverage** — Baseline 1.4–1.6, 2.6, 3.3 and 5.2 cover intent; the 163-task snapshot has no dedicated producer/evidence-protocol record.
- **Scope** — Bind discovery from the pinned tree and machine-readable execution attestations to exact interface/case/expected outcome, revision or identical tree, job/scope and artifact digest. Resolve dynamic registrations, generated interfaces, config and persistence.
- **Acceptance** — Token, stubbed/skipped, wrong-tree/hash/scope and origin-ambiguous records fail qualification; stale discovery fails; exact positive and removal/restored controls pass. Authorization excludes secrets and hardware claims from software results.
- **Dependencies** — Stable aggregate schema and reviewed producer/consumer protocol; coordinate with checker worker without treating prototype acceptance as producer proof.
- **Trace** — `KMS-CI-001`, `KMS-CI-004`.

### ST-10 · Approve exact legacy budget then enforce the coverage ratchet in CI

- **Work type** — policy and qualifying CI integration.
- **Recorded coverage** — Baseline 5.3–5.4 are open; no matching tracker task in the recorded set. Existing ci-gate is a different check.
- **Scope** — Freeze reviewed exact legacy interface/case/gap and exclusion baseline. Run strict OpenSpec plus coverage and change review on eligible exact heads.
- **Acceptance** — Genuine closures pass; new gaps and broadened exclusions, downgrades, unsupported claims and stale proof fail. Partial integrity and require-complete differ. Record live policy evidence separately in an authorized follow-up.
- **Dependencies** — ST-09 and independently reviewed checker integration; no workflow requirement inferred from local declarations.
- **Trace** — `KMS-CI-001`, `KMS-CI-004`, `CI.forge.required-checks`.

### ST-11 · Reconcile compatibility and old Cosmos signing contracts

- **Work type** — design and qualification.
- **Recorded coverage** — 35b, 4g8, bim and 47g cover named pieces. The recorded relation does not resolve competing acceptance decisions.
- **Scope** — Choose admit/normalize/refuse semantics and fee payer/granter binding with upstream schema confirmation. Decide if daemon verifies returned signatures, and establish an independent consumed-sequence recovery contract.
- **Acceptance** — Canonical/reordered and zero-account fixtures, fee identity/refusals, actual signed-bytes comparison and policy-eligible known-chain signature control; crash after reservation cannot silently forget or reuse sequence.
- **Dependencies** — Explicit compatibility decision and correct client/chain target; gate advertised Cosmos support, do not automatically expand TEST scope.
- **Trace** — `KMS-COSMOS-001`, `KMS-COSMOS-002`, `KMS-COSMOS-003`, `STORE.cosmos.field-order`, `STORE.cosmos.payer-granter`, `STORE.cosmos.sequence-recovery`, `STORE.cosmos.signed-output-verification`.

### ST-12 · Resolve ceremony touch policy and backend scope

- **Work type** — cross-repository design and physical qualification.
- **Recorded coverage** — 85g is recorded. Current source/notes do not authorize the ceremony or settle external defaults.
- **Scope** — Reconcile touch policy wording per backend, production key workflow and applicable participant/authority.
- **Acceptance** — Review both actor paths and witness proof of required PIN/touch behavior, refusal, removal and custody without treating software token evidence as ceremony acceptance.
- **Dependencies** — Ceremony repo and independent owner policy review in authorized scope.
- **Trace** — `KMS-TOKEN-004`, `KMS-CUSTODY-004`.

### ST-13 · Confirm bench, iLO access and eligible replacement inventory

- **Work type** — owner action, hardware availability and bench ownership.
- **Recorded coverage** — 5ky covers onboarding; S02/S04/M02 acknowledge separate route/inventory. No accepted usable replacement inventory or booked owner handoff was recorded.
- **Scope** — Confirm approved native build route, console/VSP ownership, two manual iLO password resets, and separately eligible spare TPM identity and TEST HSM for each drill.
- **Acceptance** — Handoff and access are explicitly authorized; record eligibility and sufficient independent spare custody with no private identifiers. Reused affected floor triggers dx7.24. No TPM clear and no assumed spare.
- **Dependencies** — Owner appointments and distinct inventory before S25/M20; G is independent. Confirm spare capacity for three active hosts separately.
- **Trace** — `KMS-TPM-004`, `KMS-HW-002`, `KMS-HW-003`.

### ST-14 · Define mesh TEST acceptance separately from production readiness

- **Work type** — owner scope and qualification.
- **Recorded coverage** — 2k9 links tasks whose full acceptance includes real-WAN or production material; M03/M12 have no adopted reconciliation in the snapshot.
- **Scope** — Record accepted TEST equivalents and what remains for 1h7, plus soak duration, fault budget, residual exceptions and exact release artifact.
- **Acceptance** — A signed or explicitly owner-accepted TEST disposition gives no production waiver. Preserve failure-domain fencing, case-level replay and inspection at the actual TEST topology.
- **Dependencies** — Authorized three-node staging and M03/M12. Production requires new genesis, real hardware/WAN and ceremony policy.
- **Trace** — `KMS-RELEASE-003`, `KMS-HW-003`.

### ST-15 · Trace admitted public interfaces and exact remaining assertions

- **Work type** — test, contract and discovery.
- **Recorded coverage** — OpenSpec baseline tasks cover classes of work; recorded tracker IDs do not cover most exact assertion gaps.
- **Scope** — Split unjoined cases by route, generated unit/consumer, persistent/config input and external business interface. Preserve separate public, internal and undecided discovery status.
- **Acceptance** — Per-route capacity and replay, metrics Allow, SOPS wire numbers/two invokers, mid-restore writes, alarm bounds, receipt/handovers, negative credential and restart paths each have enforcing source, exact scenario and meaningful independent assertion or unresolved disposition.
- **Dependencies** — Known public-surface adoption decision by area, stable IDs and ST-09 for qualifying executions.
- **Trace** — `KMS-API-003`, `KMS-ADAPTER-001`, `KMS-AUDIT-007`, `KMS-CI-004`.

### ST-16 · Diagnose recovery TCP reset with scoped controls

- **Work type** — CI reliability and evidence.
- **Recorded coverage** — Neighboring dqc, b4l, 7jc and other flakes are separately tracked. No recorded issue establishes this transport reset cause.
- **Scope** — Treat the historical c→a post-rate-limit reset separately from successful later runs and TPM broker failures.
- **Acceptance** — Instrument/observe the first failing listener/client path with exact phase/peer/process/queue evidence and reproduce or bound the cause. Verify per-peer rate denial and unrelated peer success; do not infer a fix from a rerun.
- **Dependencies** — Authorized independent reliability review. This document makes no new release-blocking designation.
- **Trace** — `KMS-CI-002`, `CI.recovery.other-peer-after-rate-limit`.

### ST-17 · Reconcile ledger issuance and restore restart edge cases

- **Work type** — authority, implementation and qualifying verification.
- **Recorded coverage** — dx7.26/dx7.7 overlap, but recorded scope lacks individual issuance-ledger loss, stage race and policy journal partial-write acceptance.
- **Scope** — Give issuance/reopen, per-journal target writes, and stage endpoint transitions distinct evidence and admissible states.
- **Acceptance** — Prove loss/replay does not lower consumed epoch, interrupted target writes report actual partial state and refuse unsafe retries, and journal append/sidecar crash boundaries preserve spend or refuse.
- **Dependencies** — Independent authoritative floor and completed H/S where the scenario depends on existing-history restore.
- **Trace** — `KMS-RESTORE-006`, `KMS-RESTORE-007`, `KMS-STATE-004`, `BMCASE-restore-sign-statement-replay-after-loss`, `KMS.restore.write-interruption`, `KMS.policy-journal.append-before-sidecar`.

### ST-18 · Reconcile custody manifest and daemon schema refusals

- **Work type** — compatibility and assertion.
- **Recorded coverage** — 2by, l6z, wd6 name precise discrepancies. The snapshot gives no accepted dual-validator matrix for the affected surface.
- **Scope** — Pin single source of truth for seal-only KEK fields, public-key pin type errors, and secret KEK disjointness at both validation stages.
- **Acceptance** — Common accepts and refuses cover seal-only, malformed pins, and conflicting unwrap reachability with meaningful fail codes. Check both producer and runtime validator.
- **Dependencies** — S01 release-surface decision and accepted schema/registry compatibility contract.
- **Trace** — `KMS-REG-001`, `KMS-ENV-001`, `KMS-ENV-002`.

### ST-19 · Qualify commissioned token provenance and replacement classes

- **Work type** — physical qualification.
- **Recorded coverage** — pgy, 2av, 31t, a2n, ccn and gbe cover named backend slices. None alone supplies cross-backend commissioned KEK continuity and physical replacement evidence.
- **Scope** — Declare the supported physical token/mechanism/site matrix. Qualify commissioned key provenance and replacement continuity for selected profiles, including pull, reinsert and next lease.
- **Acceptance** — Name exact backend/build/profile and enrolled key proof; exercise unavailable, foreign or retired token refusal and controlled recovery. Keep software mechanisms and demonstrably unqualified target-chain cases separate.
- **Dependencies** — Approved test material and eligible target hardware. Production custody requires its independent ceremony and review.
- **Trace** — `KMS-TOKEN-004`, `KMS-ENV-005`, `KMS-HW-002`.

### ST-20 · Close adapter qualification only for claimed deployments

- **Work type** — contract and qualifying integration.
- **Recorded coverage** — 917, 547 and eb6 already cover OpenBao construction/qualification. The task snapshot has no named production SOPS site commissioning or per-invoker delegation task.
- **Scope** — Establish installed SOPS socket ownership, site trust chain and firewall tests across admitted users. If delegation is adopted, keep it a separate feature; if OpenBao is advertised, qualify its real server and recovery.
- **Acceptance** — Check mTLS site identity, socket access controls, two admitted invokers with the specified sidecar identity and a named denied control. OpenBao must exercise the selected real auto-unseal/External Keys paths. Scope unsupported capabilities explicitly.
- **Dependencies** — Feature adoption, site credentials and external test app resources. No optional adapter is an implicit TEST milestone gate.
- **Trace** — `KMS-ADAPTER-002`, `KMS-ADAPTER-004`, `KMS-ADAPTER-005`, `SOPS.encrypt.sidecar-principal`, `SOPS.decrypt.sidecar-principal`.

### ST-21 · Trace collector audit completeness beyond the tested single-node trails

- **Work type** — qualification.
- **Recorded coverage** — dx7.9 and ag9 cover monitoring and update work. They do not establish event/stream completeness for every shared lifecycle, recovery, admission or restore path.
- **Scope** — Inventory required event families per profile and correlate each initiating operation with committed local and remote records, actor/epoch and independent witness boundaries.
- **Acceptance** — Execute named success and denial scenarios with no stale/foreign stream matches or missing records. Collector outages, restart reconciliation and attested result visibility have separate checks.
- **Dependencies** — ST-07 witness scope and approved collector; ST-09 revision-bound execution protocol for claimed verification.
- **Trace** — `KMS-AUDIT-004`, `KMS-AUDIT-005`, `KMS-CI-003`.
