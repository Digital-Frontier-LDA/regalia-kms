# Design

## Context

See proposal.md for the problem and scope. Source is main `0a32a901d1240eec51ddff323274e2ad935116f3`. The independent dx7.26 review found four blocking gaps. Its source references cover enrol publication before complete lifecycle exclusion, configurable TPM/NV selection, etcd's backend creation semantics, condition-skipped units, and missing credential production.

The local pending-guard candidate was mechanically integrated at `5cebe140fcedf910e4c1f3b2aa3e2779ccdecadd`, tested tree `99008fa263e79d560b42dac52b2a77e0309170e7`. Its 145 Linux tests and two integration fault controls do not exercise live PID 1, full no-history protection, or physical power loss. It remains an unmerged partial candidate. Replacement candidate `695a8118fcca19d5613cb499395692f72f762416` has no completed independent review; its review restriction remains a separate unresolved gate.

## Goals / Non-Goals

**Goals:** Give initial commissioning exactly one authorized opportunity to create history; make all later normal starts recover authenticated existing history; preserve a durable KMS deny until the final verification succeeds; produce and deliver credentials without broadening service privilege.

**Non-Goals:** Making single-node highly available, automatic conversion to three nodes, production ceremony approval, physical TPM reset, replacing existing signed restore authority, treating the logical model as implementation proof, or closing the restricted replacement review by another route.

## Decisions

### D1 — Independent authority for used or unknown-custody hardware

**Recommendation, proposed technical design:** use an owner/root-controlled off-host compare-and-consume authority, bound to the full signed genesis digest, live EK/AK/signing identity, canonical NV layout and TPM device, and a transaction nonce. The permit slot has a stable authority namespace and device-identity lineage. The signed genesis and canonical device/layout are bound values; the session nonce only correlates a response and is never an allocation key. A new nonce, enrol directory, node label or re-enrolment cannot create a new slot. Only an explicit, separately owner-approved intake or identity/genesis transition recorded against the prior lineage may allocate a new permit; absence, reachability of the authority endpoint or a caller-supplied new lineage cannot. Unknown or used custody without independently authoritative intake is refused. Its durable consumed record must be committed before any first-store grant is delivered. A lost response burns that attempt; retry requires an explicit recovery disposition, not a second grant. Authority storage must detect missing state, rollback and replay through an independently retained monotonic checkpoint. A fresh empty ledger must never silently replace an established authority.

The authority is needed for commissioning/recovery issuance, not ordinary boot. A signed export alone is insufficient because it can be replayed after local disk loss. The existing restore ledger is not reused unchanged: missing-file means empty there and its epoch issuance is a different contract. Authority enrollment, checkpoint custody, authenticated communication and recovery must be independently reviewed before physical consumption. These are implementation gates, not approval granted by this plan.

Alternative: a fresh-only cohort with verified intake and custody excluding full NV removal. It is simpler but does not fit an unproven history on used DL360s. A new TPM NV flag alone has the same absence ambiguity and is rejected as sole authority. No claim is made that current staging hardware is ineligible; it needs the authority path and normal identity checks.

### D2 — Bind the whole lifecycle to the same device and allocation

Choose one canonical protected TPM/device/NV profile. Enrol checks, child tools, anchor/heartbeat definitions, owner authorization, re-anchor, recount and service startup must use it. A trusted lifecycle lock and fencing rules cover all participants from validation through publication. Unknown inventory, aliases to another device, occupied/partial reservations and uncertain definitions cannot mint a grant. Resume can report an existing transaction but cannot derive fresh authority from epoch 1, a zero anchor, recovered files or a matching journal.

### D3 — Existing-member-only recovery in the pinned etcd build

Implement an explicit existing-member-only normal mode in the pinned etcd build and verify actual recovery objects at their opens. Keep new-store creation confined to the one consumed first-store grant. Signed-restore staging after snapshot unpack and legacy adoption use existing-history-only recovery, never that creation mode. If their WAL/backend is missing, swapped, inconsistent or truncated, refuse before writing a raised state epoch; a valid signed restore statement is not authority to create an empty genesis. This is more maintenance than setting stock `initial-cluster-state=existing`, but that setting alone opens the backend before refusal and cannot establish lineage. A path preflight followed by unrestricted opens is also insufficient. No discovery or force-new-cluster is allowed on the normal path.

Bind a unique commissioned/restored history incarnation both inside durable member history and in a protected receipt outside the etcd-writable tree. Validate WAL metadata, backend/applied-state consistency, actual directory/file identity and the expected incarnation before readiness. Deterministic cluster/member IDs and a missing epoch key cannot stand in for that receipt. Legitimate crash-tail recovery must remain supported. Same-history rollback is governed by an independently available authoritative floor and signed restore authority; a local receipt does not solve replay of its own older copy. If the floor cannot be authenticated or checked when required, readiness refuses rather than assuming zero or trusting the local receipt alone.

### D4 — Keep the deny until normal readiness succeeds

Use the partial pending guard only as a starting candidate. Persist pending before any boot-eligible replacement/config publication. Staged service execution consumes one activation at its actual authorization boundary; `Restart=no` and `ExecCondition` are insufficient. A queued or surviving stage is isolated/cancelled when its transaction ends. Root verification must authenticate the endpoint and history rather than trusting a reachable socket.

After stage verification and durable exchange, start normal existing-history verification while KMS remains denied. Publish final readiness and remove pending only as part of a barrier that every KMS start freshly enforces for the same boot, process and incarnation. Do not clear pending first and re-arm after a failed readback. Manual starts, already-active etcd, skipped dependencies and check/start substitutions must fail closed. Bare-metal guard/profile checks are verity-covered. Only a positively verified multi-node profile gets the appropriate exemption; the separate non-bare-metal package keeps its existing contract.

### D5 — Prepare credentials before spending authority

Add an operator-facing producer for the separate peer TLS key, certificate/profile validation, TPM-backed identity binding and approved systemd credential sealing. Verify an unseal and public-key/certificate match on the selected TPM/boot before consumption. Use `etcd-peer.key`, root-private persistence and manager delivery; do not log or persist plaintext. If a later unseal fails after consumption, keep pending and treat the attempt as burned.

Keep etcd's 0700 data, no capabilities and no TPM access. Put offline history reads in a narrowly confined helper with justified access. Test Unix socket DAC and the configured client APIs in the shipped units; AppArmor permission alone is insufficient and group membership is not a read-only API policy. Supported single-node serving configuration must require its state readiness dependency rather than silently omitting the optional watcher.

### D6 — Guard-compatible rollback and independent proof gates

Every boot-eligible operational image, including recovery/rollback slots, must enforce pending, existing-history recovery and the authoritative floor. Before commissioning, verify the eligible image set and exclude older incompatible operational images through the actual enforced boot/credential policy, not a runbook label. If an old image remains operationally eligible, commissioning and release stay blocked. Diagnostic media may be used only in a separately fenced, non-serving mode; an old baseline image is not an approved operational rollback. Prove boot into the approved compatible rollback image with pending set and runtime state lost.

### D7 — Ordered integration, independent review, then physical acceptance

Implementation is split into four deliverables, not one broad PR. History recovery and authority/credential preparation can proceed in parallel against a frozen interface. Service coordination integrates the history boundary. Fresh-genesis software commissioning waits for H+A+C+S, but not for replacement enrolment. Replacement/restore integration and physical lost-disk acceptance separately require the reviewed replacement hook; the blocked review does not prevent independent fresh-genesis proof. Each slice needs enforcing/refusal tests and fresh-cache mutation controls, then independent review and exact-head hosted CI. Physical acceptance remains a separate gate.

## Workstreams, dependencies and closure evidence

| Workstream | Prerequisites and result | Required proof |
|---|---|---|
| H — Existing history and provenance | Pin build/interface; implement normal recovery and receipt. No authority consumption or hardware required. | `normal_start_never_bootstraps`: missing, zero, corrupt, mispaired, unreadable and substituted files; swap after preflight; valid clone with same token/IDs; crash-tail and restart/compaction/defrag positive controls. |
| A — Commissioning authority and identity | Approve technical/custody contract before physical use; implement independent consume and canonical device/layout exclusion. Can run alongside H. | Eight authority cases in review-response.md plus ledger loss/rollback, duplicate consume, replay and post-consume crash. Real software TPM, two actual actors, not model booleans. |
| C — Credential producer and access | Canonical device identity interface from A; no need to spend a real grant. Can run alongside H and A. | `wrong_peer_credential`: seal/unseal, wrong key/cert/TPM/profile/name/expiry, socket/DAC/API permissions and no plaintext residue. |
| S — Service manager and durable transaction | H contract; integrate/fix partial guard. A/C interfaces can be test doubles until end-to-end validation. | `kms_dependency_cannot_skip`, `stage_start_is_single_use`, `post_exchange_kms_stays_gated`, `crash_windows_keep_pending` under live shipped systemd. |
| G — Independent fresh-genesis software proof | H+A+C+S independently reviewed; replacement implementation is not required. | `successful_genesis_preserves_old_contracts`, `fresh_genesis_proof_independent_of_replacement`, normal readiness and multi-node/package controls. |
| I — Replacement/restore and physical acceptance | G plus separately reviewed replacement hook; no bypass of its review restriction. | Existing-only signed-restore staging, actual replacement/restore readiness, compatible rollback boot, physical reboot/power-loss and TEST lost-disk rehearsal. |

Dependency graph: H → S; A → C identity binding; H+A+C+S → G (fresh-genesis software proof); G+reviewed replacement hook → I → hardware acceptance → v0.1 restore milestone. Compatible rollback and available authoritative-floor proof are required before operational commissioning. Authority contract and custody approval block physical issuance, not isolated software tests. No completion date is asserted while these engineering gates are unmeasured; the existing Gantt must be rebased after slice sizing rather than reusing the earlier optimistic dates.

## Risks / Trade-offs

- [Off-host authority adds recovery/custody work] → Keep it outside normal boot; fail closed on missing/rolled-back authority and test its own recovery procedure.
- [A maintained etcd patch enlarges the supported build] → Pin upstream revision, minimize recovery-mode delta, review actual opens and retain crash-recovery controls in CI.
- [Strict legacy refusal causes operator-visible downtime] → Provide authenticated adoption only with independent lineage; otherwise use signed restore, never automatic genesis.
- [Partial guard tests can overstate systemd coverage] → Require live PID 1 job/process/endpoint evidence and physical power-loss results separately.
- [More locks can deadlock maintenance] → Specify one lock ordering across enrol, service activation, re-anchor/recount and restore; test cancellation and two-actor interleavings.
- [Local history receipts cannot detect all rollback] → Retain the independent floor and signed epoch-raising restore; state the boundary in operator docs.

## Migration Plan

Freeze the current candidates; do not publish the guard as full dx7.26 completion. Implement H, A and C behind explicit interfaces with synthetic/TEST authority. Integrate S, then the reviewed enrol/restore hook. Existing nodes enter a denied migration state until independently authenticated lineage is recorded or signed restore succeeds. There is no silent adoption path. Verify negative controls before positive commissioning. Publish through normal review/CI gates, build a fresh TEST image, then perform attended hardware acceptance with current bench ownership and approved authority. A failed migration keeps pending. Operational rollback is allowed only to a verified guard-compatible eligible image; otherwise stop and retain the operational fence. Established diagnostic media is not automatically a safe operational rollback. Reverting code must not erase a consumed grant or authorize older history.

## Approval and evidence boundary

This is a proposed engineering plan. No operational authority or ceremony approval is implied. All task checkboxes remain open until actual evidence exists. No software TPM result substitutes for physical TPM or power-loss acceptance. The review's original evidence and its hash are recorded in review-response.md.
