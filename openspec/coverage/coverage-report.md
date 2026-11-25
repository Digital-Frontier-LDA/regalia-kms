# Repository behavior coverage status

Source `0a32a901d1240eec51ddff323274e2ad935116f3`; tree `347cc36bd44945fcff8a6624237222cb64c0cf17`. **Discovery and exhaustive coverage remain open. CI enforcement is not installed.**

Both shards account for all 707 original source candidates. Accounting is a disposition, not verified coverage. The initial candidate ledger remains preserved; the current case-level authority is [reconciled-cases.json](reconciled-cases.json), derived from the hashed inputs in [coverage-summary.json](coverage-summary.json).

| Case classification | Count | Meaning |
|---|---:|---|
| verified_shipped | 9 | Nine specific historical hosted/emulated observations at the identical shipped tree; no physical qualification. |
| test_gap | 418 | Contract trace exists but an assertion, adequate scope, execution or physical proof is still missing. |
| spec_gap | 4 | The exact observable case lacks a sufficient accepted scenario trace. |
| contract_conflict | 13 | Source, intended contract, test or older delta disagrees; an explicit disposition is required. |
| proposed | 19 | Unmerged or unapproved behavior; no delivery claim. |

The 70 accepted bare-metal text resolutions move scenario gaps to verification gaps while retaining their stable gap IDs. They do not add execution evidence. The original shard and resolution records remain unchanged.

## Release-critical gaps

- **Single-node startup/restore:** durable pending, authenticated history/floor, existing-only recovery at actual opens, single staged activation and guard-compatible operational rollback are still implementation gates. The corrected commissioning plan has no remaining documentation blocker.
- **Replacement:** independently reviewed single-node replacement and the pre-publication guard remain open; the restricted review has not been bypassed. Fresh-genesis software proof can proceed independently.
- **Production state:** the published daemon uses local file-backed policy state; an optional etcd watcher does not establish shared multi-active reservation wiring. Collector continuity/freshness, deployed access and monitoring acceptance remain distinct gates.
- **Physical milestones:** real TEST image/owner-card initial and repeat boot, timed replacement restore, burn-in and owner acceptance remain open. Three-node deployment requires its own TEST rehearsal, new genesis and production qualification.
- **Compatibility:** Cosmos ordering/fee identity/recovery choices, draft OpenBao support and external ceremony policy conflicts remain explicit rather than silently adopted.

## Discovery and legacy-gap boundaries

All 16 originally detected dynamic sites have source-derived expansions, pending canonical inventory integration. Bare-metal proposes 463 additions and retains 517 original IDs without direct cases. Runtime records 87 expanded registration references, 273 typed field declarations and 85 schema-property occurrences. These are discovery seeds, not passing contracts. No exclusion is approved. The two detailed discovery reports retain per-interface scope and proof gaps.

- [Bare-metal discovery gaps](baremetal-discovery-gaps.md)
- [Runtime discovery gaps](runtime-discovery-gaps.md)
- [Ledger acceptance policy](LEDGER-POLICY.md)
- [CI ratchet design and pending integration](RATCHET.md)


The runtime pass adds 39 scenarios, establishes 40 exact traces without verification promotion, retains 91 text gaps and reclassifies one incomplete shared-reservation product claim as proposed. The raw cases and execution records are preserved.


Nine historical cases now use accepted grouped predicates and narrower exact scenarios. Their earlier flat references remain context only, and their original broader scenarios remain unmodified. The new reviewed proof record does not constitute a fresh run, physical proof or installed CI producer authority.

## Case index

| Case | Classification | Owner | Exact scenario traces |
|---|---|---|---|
| BACKEND.registration.applet-refusal | test_gap | runtime | KMS-TOKEN-005 / Unservable binding |
| BACKEND.registration.applet-sign | test_gap | runtime | KMS-TOKEN-005 / Admissible applet |
| BACKEND.registration.piv-tag-missing | test_gap | runtime | KMS-TOKEN-003 / Required token observation unavailable in this build |
| BACKEND.registration.production-lifecycle | test_gap | runtime | KMS-TOKEN-004 / Qualification handoff |
| BACKEND.token.delisted | test_gap | runtime | KMS-TOKEN-003 / Stale lease or delisted token |
| BACKEND.token.low-budget | test_gap | runtime | KMS-TOKEN-002 / Budget and rejection |
| BACKEND.token.pin-protected | test_gap | runtime | KMS-TOKEN-002 / Protected credential |
| BACKEND.token.rejected-pin | test_gap | runtime | KMS-TOKEN-002 / Budget and rejection |
| BACKEND.token.return-old-lease | test_gap | runtime | KMS-TOKEN-003 / Stale lease or delisted token |
| BACKEND.token.secure-channel-nitrokey | test_gap | runtime | KMS-TOKEN-001 / Channel or key failure |
| BMCASE-admission-expiry | test_gap | baremetal | KMS-LEASE-004 / The serving bound expires |
| BMCASE-admission-expiry-versus-renew | test_gap | baremetal | KMS-LEASE-007 / A stalled renewal does not delay admission lapse |
| BMCASE-admission-late-allow-invalidates | test_gap | baremetal | KMS-RELEASE-005 / A successful sign invalidates pending refusal evidence |
| BMCASE-admission-late-audit-keeps-time | test_gap | baremetal | KMS-RELEASE-005 / A late audit retains the original refusal time |
| BMCASE-admission-live-single | test_gap | baremetal | KMS-LEASE-003 / A current single-node admission carries serving state |
| BMCASE-admission-not-any-503 | test_gap | baremetal | KMS-RELEASE-005 / An unrelated 503 cannot prove admission shutdown |
| BMCASE-admission-reacquire | test_gap | baremetal | KMS-LEASE-006 / A new valid lease restores admission after an outage |
| BMCASE-admission-single-needs-chain | test_gap | baremetal | KMS-LEASE-003 / Single mode requires a verified single-node chain |
| BMCASE-admission-survivor-not-permitted | test_gap | baremetal | KMS-LEASE-003 / Recovery mode cannot admit the sole node |
| BMCASE-admission-wrong-mode | test_gap | baremetal | KMS-LEASE-003 / Incorrect admission mode |
| BMCASE-consumer-check-expected-skip | test_gap | baremetal | KMS-UNLOCK-006 / Both initrd consumers honor the current trusted skip |
| BMCASE-consumer-check-untrusted-skip-marker | test_gap | baremetal | KMS-UNLOCK-006 / An invalid initrd skip marker is rejected |
| BMCASE-enrol-bootstrap-bootstrap-resume | test_gap | baremetal | KMS-ENROL-004 / Legacy bootstrap resumes with a complete zero counter |
| BMCASE-enrol-bootstrap-counter-outside-jump | test_gap | baremetal | KMS-ENROL-004 / Legacy counter is too far behind |
| BMCASE-enrol-bootstrap-epoch-two-override | test_gap | baremetal | KMS-ENROL-003 / Bootstrap flag cannot initialize a later epoch |
| BMCASE-enrol-bootstrap-existing-policy-pair | test_gap | baremetal | KMS-ENROL-004 / An existing pair has incompatible counter attributes |
| BMCASE-enrol-bootstrap-expired-peer-heartbeat | test_gap | baremetal | KMS-ENROL-003 / An expired heartbeat cannot initialize the counter |
| BMCASE-enrol-bootstrap-forged-peer-heartbeat | test_gap | baremetal | KMS-ENROL-003 / A forged heartbeat cannot initialize the counter |
| BMCASE-enrol-bootstrap-genesis-zero | test_gap | baremetal | KMS-ENROL-003 / Explicit epoch-one heartbeat bootstrap |
| BMCASE-enrol-bootstrap-half-index | test_gap | baremetal | KMS-ENROL-004 / Interrupted counter setup |
| BMCASE-enrol-bootstrap-live-adoption | test_gap | baremetal | KMS-ENROL-003 / Legacy enrolment adopts the verified sequence |
| BMCASE-enrol-bootstrap-ordinary-no-source | test_gap | baremetal | KMS-ENROL-003 / Later enrolment has no live heartbeat |
| BMCASE-enrol-bootstrap-production-vs-legacy | spec_gap | baremetal | No exact accepted trace |
| BMCASE-enrol-bootstrap-root-owner-authorization | test_gap | baremetal | KMS-ENROL-004 / Counter definition lacks required owner authorization |
| BMCASE-enrol-bootstrap-verified-parent-floor | test_gap | baremetal | KMS-ENROL-003 / Root initializes a quorum counter from a verified heartbeat |
| BMCASE-enrol-commit-competing-file | test_gap | baremetal | KMS-ENROL-002 / Another writer claims the destination |
| BMCASE-enrol-commit-different-file | test_gap | baremetal | KMS-ENROL-002 / A conflicting file exists |
| BMCASE-enrol-commit-esp-publish-interrupted | test_gap | baremetal | KMS-ENROL-006 / A crash interrupts seal before publication |
| BMCASE-enrol-commit-genesis-check | test_gap | baremetal | KMS-ENROL-001 / Single-node genesis matches this host |
| BMCASE-enrol-commit-later-single-tip | contract_conflict | baremetal | KMS-REPLACE-003 / Post-revocation replacement submitted |
| BMCASE-enrol-commit-malformed-chain | test_gap | baremetal | KMS-ENROL-001 / Wrong root or host details |
| BMCASE-enrol-commit-matching-existing | test_gap | baremetal | KMS-ENROL-002 / Identical configuration on retry |
| BMCASE-enrol-commit-proposed-credential-wrong | proposed | baremetal | KMS-GEN-010 / Wrong peer credential |
| BMCASE-enrol-commit-proposed-resumed-epoch-one | proposed | baremetal | KMS-GEN-004 / Resumed epoch one |
| BMCASE-enrol-commit-published-files | test_gap | baremetal | KMS-ENROL-002 / Checked configurations go to persistent storage |
| BMCASE-enrol-commit-symbolic-link | test_gap | baremetal | KMS-ENROL-002 / A configuration name is a symbolic link |
| BMCASE-enrol-commit-sync-active | test_gap | baremetal | KMS-ENROL-005 / Sync already runs at anchor definition |
| BMCASE-enrol-commit-wrong-local-signing-key | test_gap | baremetal | KMS-ENROL-001 / Wrong root or host details |
| BMCASE-enrol-commit-wrong-measurements | test_gap | baremetal | KMS-ENROL-001 / Wrong root or host details |
| BMCASE-enrol-commit-wrong-root | test_gap | baremetal | KMS-ENROL-001 / Wrong root or host details |
| BMCASE-enrol-replace-missing-intent | test_gap | baremetal | KMS-REPLACE-002 / A retirement accompanies enrolment without replacement intent |
| BMCASE-enrol-replace-owner-revocation-then-replacement | contract_conflict | baremetal | KMS-REPLACE-003 / Post-revocation replacement submitted |
| BMCASE-enrol-replace-typed-legacy | test_gap | baremetal | KMS-REPLACE-002 / A supported multi-node replacement names the exact prior node |
| BMCASE-enrol-replace-unrelated-mutation | test_gap | baremetal | KMS-REPLACE-002 / A replacement also changes another node |
| BMCASE-enrol-replace-wrong-id | test_gap | baremetal | KMS-REPLACE-002 / An operator names the wrong old node |
| BMCASE-etcd-start-config-missing | test_gap | baremetal | KMS-ETCD-004 / No rendered configuration before enrolment |
| BMCASE-etcd-start-configured-unit | test_gap | baremetal | KMS-ETCD-004 / Normal unit invokes etcd with the rendered configuration |
| BMCASE-etcd-start-lost-var-history | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-etcd-start-manual-start-pending | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-etcd-start-one-vs-three | test_gap | baremetal | KMS-ETCD-001 / A single-member loopback configuration is profile-specific |
| BMCASE-etcd-start-proposed-existing-only | proposed | baremetal | KMS-GEN-005 / Missing recovery objects |
| BMCASE-etcd-start-proposed-legacy-lineage | proposed | baremetal | KMS-GEN-013 / Unknown legacy lineage |
| BMCASE-etcd-start-start-during-stage | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-etcd-start-trusted-local-start | test_gap | baremetal | KMS-ETCD-004 / Peer credentials and writable locations are scoped to etcd |
| BMCASE-kms-start-apparmor-missing | test_gap | baremetal | KMS-HOST-001 / AppArmor disabled or its named profile unavailable |
| BMCASE-kms-start-base-vs-appliance | spec_gap | baremetal | No exact accepted trace |
| BMCASE-kms-start-configured-daemon | test_gap | baremetal | KMS-HOST-005 / The appliance KMS unit selects its account and profile |
| BMCASE-kms-start-manual-restart-after-refusal | contract_conflict | baremetal | No exact accepted trace |
| BMCASE-kms-start-no-trusted-history | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-kms-start-proposed-post-exchange-readback | proposed | baremetal | KMS-GEN-008 / Readback fails after exchange |
| BMCASE-kms-start-runtime-not-admitted | test_gap | baremetal | KMS-LEASE-008 / A running daemon lacks required admission |
| BMCASE-kms-start-startup-during-exchange | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-local-lease-bounded-worker | spec_gap | baremetal | No exact accepted trace |
| BMCASE-local-lease-foreign-uid | test_gap | baremetal | KMS-LEASE-001 / Unapproved local caller |
| BMCASE-local-lease-legacy-multi | test_gap | baremetal | KMS-LEASE-001 / The local path refuses a multi-node manifest |
| BMCASE-local-lease-stale-socket | test_gap | baremetal | KMS-LEASE-005 / A stale socket and an unexpected file are handled differently |
| BMCASE-local-lease-uid-can-request | test_gap | baremetal | KMS-LEASE-001 / The admission account uses the local lease exchange |
| BMCASE-local-lease-unknown-operation | test_gap | baremetal | KMS-LEASE-001 / The local listener does not dispatch peer operations |
| BMCASE-local-lease-untrusted-socket-directory | test_gap | baremetal | KMS-LEASE-005 / The listener directory is writable by others |
| BMCASE-owner-unlock-attended-opens | test_gap | baremetal | KMS-OWNER-001 / Approved boot opens the owner path |
| BMCASE-owner-unlock-hardware-repeat-boot | test_gap | baremetal | KMS-OWNER-004 / Only software fixtures are available |
| BMCASE-owner-unlock-late-harness-reply | test_gap | baremetal | KMS-RELEASE-004 / A test reply arrives while the client waits for the mapper |
| BMCASE-owner-unlock-near-deadline | test_gap | baremetal | KMS-OWNER-003 / A connection has only the remaining serving time |
| BMCASE-owner-unlock-past-window | test_gap | baremetal | KMS-OWNER-003 / A connection arrives after the serving window |
| BMCASE-owner-unlock-pin-latch | test_gap | baremetal | KMS-OWNER-003 / The owner card refuses a PIN |
| BMCASE-owner-unlock-retired-image | test_gap | baremetal | KMS-OWNER-001 / Retired image gets no owner contribution |
| BMCASE-owner-unlock-without-owner | test_gap | baremetal | KMS-OWNER-001 / Owner unavailable |
| BMCASE-owner-unlock-wrong-owner-path | test_gap | baremetal | KMS-OWNER-002 / Obsolete path contribution |
| BMCASE-render-check-already-enrolled-missing-site | test_gap | baremetal | KMS-UNLOCK-005 / An enrolled boot has lost the site credential |
| BMCASE-render-check-closed-varargs | test_gap | baremetal | KMS-UNLOCK-005 / Invalid render condition invocation |
| BMCASE-render-check-expected-pre-genesis-skip | test_gap | baremetal | KMS-UNLOCK-005 / An expected pre-genesis render skip |
| BMCASE-render-check-invalidate-old-skip | test_gap | baremetal | KMS-UNLOCK-006 / An enrolled retry replaces a stale skip decision |
| BMCASE-render-check-nv-not-readable | test_gap | baremetal | KMS-UNLOCK-005 / TPM inventory could not establish absence |
| BMCASE-restore-run-absence-is-not-genesis | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-restore-run-already-exchanged-wrong-endpoint | spec_gap | baremetal | No exact accepted trace |
| BMCASE-restore-run-digest-mismatch | test_gap | baremetal | KMS-RESTORE-002 / Snapshot digest mismatch discards the temporary copy |
| BMCASE-restore-run-exchange-fsync-unknown | test_gap | baremetal | KMS-RESTORE-002 / Exchange completed but durability is unknown |
| BMCASE-restore-run-expired-statement | test_gap | baremetal | KMS-RESTORE-001 / Statement is outside its validity window at entry |
| BMCASE-restore-run-leftover-stage-override | test_gap | baremetal | KMS-RESTORE-007 / Earlier transaction left its runtime override |
| BMCASE-restore-run-live-floor-blocks | test_gap | baremetal | KMS-RESTORE-002 / Live state epoch is already high enough to reject the restore |
| BMCASE-restore-run-lost-disk-failed-exchange | test_gap | baremetal | KMS-RESTORE-002 / Failed exchange has no live store to return to |
| BMCASE-restore-run-multi-profile-refusal | test_gap | baremetal | KMS-RESTORE-001 / Single-node restore is requested on a multi-node cluster |
| BMCASE-restore-run-non-owner-signature | test_gap | baremetal | KMS-RESTORE-001 / A node signature cannot authorize snapshot restore |
| BMCASE-restore-run-proposed-stage-missing-recovery | proposed | baremetal | KMS-GEN-005 / Restored objects disappear before stage recovery |
| BMCASE-restore-run-proposed-stage-once | proposed | baremetal | KMS-GEN-007 / Second manual activation |
| BMCASE-restore-run-reboot-loses-override | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-restore-run-restore-lock | test_gap | baremetal | KMS-RESTORE-007 / Another restore holds the host transaction lock |
| BMCASE-restore-run-signed-epoch-readback | test_gap | baremetal | KMS-RESTORE-002 / Verified readback precedes the KMS start |
| BMCASE-restore-run-snapshot-floor-blocks | test_gap | baremetal | KMS-RESTORE-002 / Snapshot already holds the proposed epoch |
| BMCASE-restore-run-stale-manifest-epoch | test_gap | baremetal | KMS-RESTORE-001 / Membership moved after restore authorization |
| BMCASE-restore-run-verify-live-success | test_gap | baremetal | KMS-RESTORE-002 / Verified readback precedes the KMS start |
| BMCASE-restore-run-volatile-authorization-after-restart | contract_conflict | baremetal | KMS-RESTORE-003 / Reboot loses volatile state during restore |
| BMCASE-restore-run-window-expired-in-stage | test_gap | baremetal | KMS-RESTORE-001 / Statement expires before the staged epoch write |
| BMCASE-restore-sign-confirmation-failed | test_gap | baremetal | KMS-RESTORE-001 / A refused confirmation leaves its epoch issued |
| BMCASE-restore-sign-epoch-above-two-floors | test_gap | baremetal | KMS-RESTORE-001 / An epoch has already been issued |
| BMCASE-restore-sign-foreign-key | test_gap | baremetal | KMS-RESTORE-001 / A non-owner key requests a restore statement |
| BMCASE-restore-sign-malformed-ledger | test_gap | baremetal | KMS-RESTORE-006 / The retained issuance history is malformed |
| BMCASE-restore-sign-multi-topology | test_gap | baremetal | KMS-RESTORE-001 / A multi-node chain cannot obtain a single-node statement |
| BMCASE-restore-sign-parallel-issue | test_gap | baremetal | KMS-RESTORE-006 / Concurrent issuance uses distinct epochs |
| BMCASE-restore-sign-runs-on-node | spec_gap | baremetal | No exact accepted trace |
| BMCASE-restore-sign-statement-replay-after-loss | spec_gap | baremetal | No exact accepted trace |
| CI.evidence.failed-run | test_gap | runtime | KMS-CI-004 / Execution failed |
| CI.evidence.plan | test_gap | runtime | KMS-CI-004 / Plan inspected |
| CI.forge.required-checks | spec_gap | runtime | No exact accepted trace |
| CI.gate.added-job | test_gap | runtime | KMS-CI-001 / Workflow drift |
| CI.gate.all-needs | verified_shipped | runtime | KMS-CI-001 / Complete run |
| CI.gate.non-success | test_gap | runtime | KMS-CI-001 / Incomplete run |
| CI.one-node.collector-correlation | verified_shipped | runtime | KMS-CI-003 / Collector holds the revoked node's exact renewal denial |
| CI.one-node.duplicate-todo | test_gap | runtime | KMS-CI-002 / One-node evidence missing |
| CI.one-node.invalid-owner-refusal | test_gap | runtime | KMS-CI-007 / Unsound evidence |
| CI.one-node.lost-poll | test_gap | runtime | KMS-CI-003 / Incomplete or mismatched evidence |
| CI.one-node.owner-off | verified_shipped | runtime | KMS-CI-007 / Owner listener stopped |
| CI.one-node.owner-on | verified_shipped | runtime | KMS-CI-007 / Owner listener enabled |
| CI.one-node.summary | verified_shipped | runtime | KMS-CI-002 / One-node summary complete |
| CI.recovery.other-peer-after-rate-limit | test_gap | runtime | KMS-CI-002 / A rate-limited peer does not exhaust another peer's lease nonce budget |
| COLLECTOR.alarms.bad-body | test_gap | runtime | KMS-AUDIT-006 / Malformed alarm submission is refused |
| COLLECTOR.alarms.durable-report | test_gap | runtime | KMS-AUDIT-004 / Rewritten trail or foreign receipt |
| COLLECTOR.alarms.rate-cap | test_gap | runtime | KMS-AUDIT-006 / An identity exhausts its reported-alarm budget |
| COLLECTOR.events.durable-commit-fails | test_gap | runtime | KMS-AUDIT-003 / Divergence or write failure |
| COLLECTOR.events.next-link | test_gap | runtime | KMS-AUDIT-003 / Commit and exact replay |
| COLLECTOR.events.restart-retains-commit | test_gap | runtime | KMS-AUDIT-003 / Collector reopen retains the acknowledged position |
| COLLECTOR.events.retry-committed | test_gap | runtime | KMS-AUDIT-003 / Commit and exact replay |
| COLLECTOR.events.same-sequence-fork | test_gap | runtime | KMS-AUDIT-003 / Divergence or write failure |
| COLLECTOR.events.sequence-gap | test_gap | runtime | KMS-AUDIT-003 / Divergence or write failure |
| COLLECTOR.events.unauthenticated | test_gap | runtime | KMS-AUDIT-003 / Collector listener and event handler reject missing identities |
| COLLECTOR.handover.handover-restart | test_gap | runtime | KMS-AUDIT-004 / Continuation and handover |
| COLLECTOR.handover.repeat-transfer | test_gap | runtime | KMS-AUDIT-004 / A committed handover cannot be used again |
| COLLECTOR.handover.retired-key | test_gap | runtime | KMS-AUDIT-004 / Continuation and handover |
| COLLECTOR.handover.wrong-authority | test_gap | runtime | KMS-AUDIT-004 / Handover rejects unsuitable proof or an occupied destination |
| COLLECTOR.position.cross-site-certificate | test_gap | runtime | KMS-AUDIT-003 / Positions remain scoped by identity and site |
| COLLECTOR.position.empty-stream | test_gap | runtime | KMS-AUDIT-003 / An empty stream has a zero position |
| COLLECTOR.position.held-head | test_gap | runtime | KMS-AUDIT-003 / Position endpoint reports the held head |
| COLLECTOR.ready.probe-returns-204 | test_gap | runtime | KMS-AUDIT-007 / Collector readiness proves authenticated reachability |
| COLLECTOR.receipt.foreign-stream | test_gap | runtime | KMS-AUDIT-004 / Rewritten trail or foreign receipt |
| COLLECTOR.receipt.held-position | test_gap | runtime | KMS-AUDIT-004 / Receipt binds the held stream position |
| COLLECTOR.receipt.no-signing-key | test_gap | runtime | KMS-AUDIT-004 / A collector without a receipt key refuses a receipt |
| COLLECTOR.receipt.receipt-freshness | spec_gap | runtime | No exact accepted trace |
| GPG.cli.clear-sign | test_gap | runtime | KMS-ADAPTER-003 / Valid signatures |
| GPG.cli.detached | test_gap | runtime | KMS-ADAPTER-003 / Valid signatures |
| GPG.cli.git-form | test_gap | runtime | KMS-ADAPTER-003 / Git signs a commit and tag through the configured command |
| GPG.cli.no-overwrite | spec_gap | runtime | No exact accepted trace |
| GPG.cli.strict-parser | test_gap | runtime | KMS-ADAPTER-006 / Invalid signing grammar is rejected before signing |
| GPG.kms.invalid-key-signature | test_gap | runtime | KMS-ADAPTER-003 / Incorrect result |
| GPG.kms.no-follow | test_gap | runtime | KMS-ADAPTER-003 / Incorrect result |
| GPG.kms.wrong-reply | test_gap | runtime | KMS-ADAPTER-003 / Incorrect result |
| HTTP.certificate-sign.already-reserved | spec_gap | runtime | No exact accepted trace |
| HTTP.certificate-sign.busy | spec_gap | runtime | No exact accepted trace |
| HTTP.certificate-sign.cross-operation-fields | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.certificate-sign.duplicate-key | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.certificate-sign.grant-refused | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| HTTP.certificate-sign.no-principal | test_gap | runtime | KMS-AUTH-002 / Unauthenticated operation |
| HTTP.certificate-sign.operation-result | test_gap | runtime | KMS-RUNTIME-004 / Compliant CSR |
| HTTP.certificate-sign.oversize-invalid-payload | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.certificate-sign.replay-after-restart | spec_gap | runtime | No exact accepted trace |
| HTTP.certificate-sign.router-reaches-handler | test_gap | runtime | KMS-API-001 / Supported route |
| HTTP.certificate-sign.same-header-foreign-nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.certificate-sign.shape-accepted | test_gap | runtime | KMS-API-002 / Valid request |
| HTTP.certificate-sign.trailing-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.certificate-sign.undocumented-path | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.certificate-sign.unknown-field | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.certificate-sign.wrong-method | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.key-agreement.already-reserved | spec_gap | runtime | No exact accepted trace |
| HTTP.key-agreement.busy | spec_gap | runtime | No exact accepted trace |
| HTTP.key-agreement.cross-operation-fields | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.key-agreement.duplicate-key | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.key-agreement.grant-refused | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| HTTP.key-agreement.no-principal | test_gap | runtime | KMS-AUTH-002 / Unauthenticated operation |
| HTTP.key-agreement.operation-result | test_gap | runtime | KMS-CRYPTO-002 / Derived result |
| HTTP.key-agreement.oversize-invalid-payload | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.key-agreement.replay-after-restart | spec_gap | runtime | No exact accepted trace |
| HTTP.key-agreement.router-reaches-handler | test_gap | runtime | KMS-API-001 / Supported route |
| HTTP.key-agreement.same-header-foreign-nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.key-agreement.shape-accepted | test_gap | runtime | KMS-API-002 / Valid request |
| HTTP.key-agreement.trailing-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.key-agreement.undocumented-path | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.key-agreement.unknown-field | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.key-agreement.wrong-method | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.live.minimal-status | test_gap | runtime | KMS-OBS-007 / Healthy service |
| HTTP.live.public-probe | test_gap | runtime | KMS-AUTH-002 / Unauthenticated probe |
| HTTP.live.wrong-method | test_gap | runtime | KMS-OBS-007 / Liveness refuses unsupported methods |
| HTTP.metrics.allowed | test_gap | runtime | KMS-OBS-001 / Allowed scrape |
| HTTP.metrics.empty-allowlist | test_gap | runtime | KMS-OBS-001 / Unauthorized scrape |
| HTTP.metrics.no-cert | test_gap | runtime | KMS-OBS-001 / Unauthorized scrape |
| HTTP.metrics.source-absent | test_gap | runtime | KMS-OBS-003 / Unevaluated or absent |
| HTTP.metrics.unlisted | test_gap | runtime | KMS-OBS-001 / Unauthorized scrape |
| HTTP.metrics.wrong-method | spec_gap | runtime | No exact accepted trace |
| HTTP.ready.dependency-recovers | test_gap | runtime | KMS-OBS-007 / Healthy service |
| HTTP.ready.minimal-status | test_gap | runtime | KMS-OBS-007 / Healthy service |
| HTTP.ready.missing-probes | test_gap | runtime | KMS-OBS-007 / Unready service |
| HTTP.ready.panicking-probe | test_gap | runtime | KMS-OBS-007 / Unready service |
| HTTP.ready.public-probe | test_gap | runtime | KMS-AUTH-002 / Unauthenticated probe |
| HTTP.ready.retry-while-unready | test_gap | runtime | KMS-OBS-007 / Unready service |
| HTTP.ready.self-lease-real-daemon | verified_shipped | runtime | KMS-RUNTIME-002 / Ready under a current single-node self-lease |
| HTTP.ready.unready-probe | test_gap | runtime | KMS-OBS-007 / Unready service |
| HTTP.ready.wrong-method | test_gap | runtime | KMS-OBS-007 / Readiness refuses unsupported methods before probing |
| HTTP.release-secret.already-reserved | spec_gap | runtime | No exact accepted trace |
| HTTP.release-secret.busy | spec_gap | runtime | No exact accepted trace |
| HTTP.release-secret.cross-operation-fields | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.release-secret.duplicate-key | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.release-secret.grant-refused | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| HTTP.release-secret.no-principal | test_gap | runtime | KMS-AUTH-002 / Unauthenticated operation |
| HTTP.release-secret.operation-result | test_gap | runtime | KMS-ENV-002 / Matching release |
| HTTP.release-secret.oversize-invalid-payload | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.release-secret.replay-after-restart | spec_gap | runtime | No exact accepted trace |
| HTTP.release-secret.router-reaches-handler | test_gap | runtime | KMS-API-001 / Supported route |
| HTTP.release-secret.same-header-foreign-nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.release-secret.shape-accepted | test_gap | runtime | KMS-API-002 / Valid request |
| HTTP.release-secret.trailing-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.release-secret.undocumented-path | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.release-secret.unknown-field | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.release-secret.wrong-method | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.request-format.nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.request-format.strict-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.response-format.safe-error | test_gap | runtime | KMS-API-003 / Invalid operation input |
| HTTP.response-format.success | test_gap | runtime | KMS-API-003 / Operation succeeds |
| HTTP.seal-envelope.already-reserved | spec_gap | runtime | No exact accepted trace |
| HTTP.seal-envelope.busy | spec_gap | runtime | No exact accepted trace |
| HTTP.seal-envelope.cross-operation-fields | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.seal-envelope.duplicate-key | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.seal-envelope.grant-refused | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| HTTP.seal-envelope.no-principal | test_gap | runtime | KMS-AUTH-002 / Unauthenticated operation |
| HTTP.seal-envelope.operation-result | test_gap | runtime | KMS-ENV-001 / Valid assembled content |
| HTTP.seal-envelope.oversize-invalid-payload | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.seal-envelope.replay-after-restart | spec_gap | runtime | No exact accepted trace |
| HTTP.seal-envelope.router-reaches-handler | test_gap | runtime | KMS-API-001 / Supported route |
| HTTP.seal-envelope.same-header-foreign-nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.seal-envelope.shape-accepted | test_gap | runtime | KMS-API-002 / Valid request |
| HTTP.seal-envelope.trailing-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.seal-envelope.undocumented-path | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.seal-envelope.unknown-field | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.seal-envelope.wrong-method | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.sign.already-reserved | test_gap | runtime | KMS-API-003 / Immediate signing nonce reuse |
| HTTP.sign.busy | spec_gap | runtime | No exact accepted trace |
| HTTP.sign.cross-operation-fields | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.sign.duplicate-key | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.sign.grant-refused | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| HTTP.sign.no-principal | test_gap | runtime | KMS-AUTH-002 / Unauthenticated operation |
| HTTP.sign.oversize-invalid-payload | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.sign.replay-after-restart | verified_shipped | runtime | KMS-STATE-001 / A spent signing nonce remains spent after daemon restart |
| HTTP.sign.router-reaches-handler | test_gap | runtime | KMS-API-001 / Supported route |
| HTTP.sign.same-header-foreign-nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.sign.shape-accepted | test_gap | runtime | KMS-API-002 / Valid request |
| HTTP.sign.trailing-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.sign.undocumented-path | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.sign.unknown-field | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.sign.verified-signature-single | verified_shipped | runtime | KMS-API-003 / Signed response verifies against the configured key |
| HTTP.sign.wrong-method | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.unwrap.already-reserved | spec_gap | runtime | No exact accepted trace |
| HTTP.unwrap.busy | spec_gap | runtime | No exact accepted trace |
| HTTP.unwrap.cross-operation-fields | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.unwrap.duplicate-key | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.unwrap.grant-refused | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| HTTP.unwrap.no-principal | test_gap | runtime | KMS-AUTH-002 / Unauthenticated operation |
| HTTP.unwrap.operation-result | test_gap | runtime | KMS-CRYPTO-003 / Matching wrap context |
| HTTP.unwrap.oversize-invalid-payload | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.unwrap.replay-after-restart | spec_gap | runtime | No exact accepted trace |
| HTTP.unwrap.router-reaches-handler | test_gap | runtime | KMS-API-001 / Supported route |
| HTTP.unwrap.same-header-foreign-nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.unwrap.shape-accepted | test_gap | runtime | KMS-API-002 / Valid request |
| HTTP.unwrap.trailing-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.unwrap.undocumented-path | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.unwrap.unknown-field | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.unwrap.wrong-method | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.wrap.already-reserved | spec_gap | runtime | No exact accepted trace |
| HTTP.wrap.busy | spec_gap | runtime | No exact accepted trace |
| HTTP.wrap.cross-operation-fields | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.wrap.duplicate-key | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.wrap.grant-refused | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| HTTP.wrap.no-principal | test_gap | runtime | KMS-AUTH-002 / Unauthenticated operation |
| HTTP.wrap.operation-result | test_gap | runtime | KMS-CRYPTO-003 / Matching wrap context |
| HTTP.wrap.oversize-invalid-payload | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.wrap.replay-after-restart | spec_gap | runtime | No exact accepted trace |
| HTTP.wrap.router-reaches-handler | test_gap | runtime | KMS-API-001 / Supported route |
| HTTP.wrap.same-header-foreign-nonce | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.wrap.shape-accepted | test_gap | runtime | KMS-API-002 / Valid request |
| HTTP.wrap.trailing-document | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.wrap.undocumented-path | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| HTTP.wrap.unknown-field | test_gap | runtime | KMS-API-002 / Invalid or ambiguous request |
| HTTP.wrap.wrong-method | test_gap | runtime | KMS-API-001 / Unsupported route or method |
| KMS.admission.current-valid | test_gap | runtime | KMS-RUNTIME-002 / Admission active |
| KMS.admission.expires-during-token | test_gap | runtime | KMS-RUNTIME-002 / Admission absent or expires |
| KMS.admission.expires-while-queued | test_gap | runtime | KMS-RUNTIME-002 / Admission absent or expires |
| KMS.admission.real-revocation | verified_shipped | runtime | KMS-RUNTIME-002 / Signing is refused after observed non-serving admission |
| KMS.admission.single-recovery-refused | test_gap | runtime | KMS-LEASE-003 / Recovery mode cannot admit the sole node |
| KMS.admission.stale-chain | test_gap | runtime | KMS-RUNTIME-002 / Admission follows the current chain tip |
| KMS.admission.unadmitted-before-route | test_gap | runtime | KMS-RUNTIME-002 / Admission absent or expires |
| KMS.admission.wrong-boot | test_gap | runtime | KMS-RUNTIME-002 / Admission belongs only to the current boot and session |
| KMS.admission.wrong-owner | test_gap | runtime | KMS-RUNTIME-002 / Admission rejects untrusted file ownership or ancestry |
| KMS.audit-local.authorization-sink-unavailable | test_gap | runtime | KMS-AUDIT-001 / Authorization unavailable |
| KMS.audit-local.missing-link | test_gap | runtime | KMS-AUDIT-002 / Tampering or unsafe metadata |
| KMS.audit-local.ordered-chain | test_gap | runtime | KMS-AUDIT-002 / Local verification |
| KMS.audit-local.resume-shipping | test_gap | runtime | KMS-AUDIT-002 / Unshipped local events resume in chain order |
| KMS.audit-local.success-sink-unavailable | test_gap | runtime | KMS-AUDIT-001 / Success unavailable |
| KMS.audit-local.unsafe-metadata | test_gap | runtime | KMS-AUDIT-002 / Tampering or unsafe metadata |
| KMS.export.altered-payload | test_gap | runtime | KMS-STATE-006 / Incorrect key or invalid state |
| KMS.export.known-recipient | test_gap | runtime | KMS-STATE-006 / Intact approved export |
| KMS.export.wrong-recipient | test_gap | runtime | KMS-STATE-006 / Incorrect key or invalid state |
| KMS.fencing.expired | test_gap | runtime | KMS-RUNTIME-003 / Unacceptable lease |
| KMS.fencing.rollback-epoch | test_gap | runtime | KMS-RUNTIME-003 / Unacceptable lease |
| KMS.fencing.valid-lease | test_gap | runtime | KMS-RUNTIME-003 / Valid fencing lease |
| KMS.fencing.wrong-signer-or-registry | test_gap | runtime | KMS-RUNTIME-003 / Unacceptable lease |
| KMS.first-store.absent-member-history | proposed | runtime | No exact accepted trace |
| KMS.first-store.fresh-genesis-proof | proposed | runtime | No exact accepted trace |
| KMS.first-store.no-authoritative-floor | proposed | runtime | No exact accepted trace |
| KMS.first-store.nonce-independent-permit | proposed | runtime | No exact accepted trace |
| KMS.first-store.restore-stage-substitute | proposed | runtime | No exact accepted trace |
| KMS.first-store.rollback-image | proposed | runtime | No exact accepted trace |
| KMS.first-store.staged-manual-restart | proposed | runtime | No exact accepted trace |
| KMS.first-store.wrong-live-member | proposed | runtime | No exact accepted trace |
| KMS.inspect-command.wrong-site | test_gap | runtime | KMS-STATE-006 / Incorrect key or invalid state |
| KMS.opstate.confirmed-revision | test_gap | runtime | KMS-RUNTIME-005 / Configured watcher |
| KMS.opstate.other-cluster | test_gap | runtime | KMS-RUNTIME-005 / Watcher rejects a different store cluster |
| KMS.opstate.parallel-shared-reserve | proposed | runtime | No exact accepted trace |
| KMS.opstate.partial-fields | test_gap | runtime | KMS-RUNTIME-005 / Partial watcher settings refuse configuration |
| KMS.opstate.relist-after-stream-failure | test_gap | runtime | KMS-RUNTIME-005 / Watcher relists before recovering liveness |
| KMS.opstate.store-rollback | test_gap | runtime | KMS-RUNTIME-005 / Watcher rejects a lower store revision |
| KMS.opstate.watcher-needs-admission | test_gap | runtime | KMS-RUNTIME-005 / Configured watcher requires admission |
| KMS.opstate.watcher-omitted | test_gap | runtime | KMS-RUNTIME-005 / Watcher absent from configuration |
| KMS.policy-journal.append-before-sidecar | spec_gap | runtime | No exact accepted trace |
| KMS.policy-journal.append-failure-latches | test_gap | runtime | KMS-STATE-001 / Cannot commit |
| KMS.policy-journal.inclusive-quota | test_gap | runtime | KMS-STATE-001 / A reservation may exactly fill the quota |
| KMS.policy-journal.missing-both | proposed | runtime | KMS-STATE-005 / Unproven history |
| KMS.policy-journal.older-epoch | test_gap | runtime | KMS-STATE-001 / Stale epoch |
| KMS.policy-journal.reserve-spent-nonce | test_gap | runtime | KMS-STATE-001 / Restart preserves spend |
| KMS.policy-journal.restart-keeps-quota | test_gap | runtime | KMS-STATE-001 / Restart preserves spend |
| KMS.policy-journal.same-length-replaced | test_gap | runtime | KMS-STATE-002 / Damaged history |
| KMS.policy-journal.second-writer | test_gap | runtime | KMS-STATE-002 / Concurrent writer |
| KMS.policy-journal.truncated | test_gap | runtime | KMS-STATE-002 / Damaged history |
| KMS.policy-reconcile.checkpoint-present | test_gap | runtime | KMS-STATE-003 / Reconciliation succeeds |
| KMS.policy-reconcile.equal-length-divergent | test_gap | runtime | KMS-STATE-003 / Consistent local rollback |
| KMS.policy-reconcile.journal-missing | test_gap | runtime | KMS-STATE-003 / Consistent local rollback |
| KMS.policy-reconcile.older-local-pair | test_gap | runtime | KMS-STATE-003 / Consistent local rollback |
| KMS.policy-reconcile.unreachable | test_gap | runtime | KMS-STATE-003 / Collector unavailable |
| KMS.policy-verify.intact-journal | test_gap | runtime | KMS-STATE-007 / Explicit verification reports the recorded head |
| KMS.policy-verify.missing-journal | test_gap | runtime | KMS-STATE-007 / Explicit verification refuses missing history |
| KMS.preflight.no-new-journal | test_gap | runtime | KMS-RUNTIME-001 / Preflight leaves missing policy history absent |
| KMS.restore.already-exists | test_gap | runtime | KMS-STATE-004 / Restore preflight refusal |
| KMS.restore.fresh-root | test_gap | runtime | KMS-STATE-004 / Verified offline restore |
| KMS.restore.journal-unpaired | test_gap | runtime | KMS-STATE-004 / Restore preflight refusal |
| KMS.restore.missing-explicit-target | spec_gap | runtime | No exact accepted trace |
| KMS.restore.write-interruption | spec_gap | runtime | No exact accepted trace |
| KMS.start.already-locked-preflight | test_gap | runtime | KMS-RUNTIME-001 / Preflight while the writer holds the journal |
| KMS.start.bounded-drain | test_gap | runtime | KMS-RUNTIME-007 / A response outlives the shutdown grace period |
| KMS.start.complete-preflight | test_gap | runtime | KMS-RUNTIME-001 / Coherent configuration |
| KMS.start.grant-missing-object | test_gap | runtime | KMS-RUNTIME-001 / Invalid configuration |
| KMS.start.no-token-no-operations | spec_gap | runtime | No exact accepted trace |
| KMS.start.policy-id-mismatch | test_gap | runtime | KMS-RUNTIME-001 / Invalid configuration |
| SHIP.check.readonly-probe | test_gap | runtime | KMS-AUDIT-007 / Named trail check reads position without shipping |
| SHIP.conformance.wrong-receipt-key | test_gap | runtime | KMS-AUDIT-007 / Reachable collector fails conformance under the wrong receipt key |
| SHIP.run.prune-ahead | test_gap | runtime | KMS-AUDIT-004 / Rewritten trail or foreign receipt |
| SHIP.run.unreachable-retry | test_gap | runtime | KMS-AUDIT-007 / Periodic shipping retries an unavailable collector |
| SOPS.decrypt.admitted-carrier | test_gap | runtime | KMS-ADAPTER-001 / SOPS round trip |
| SOPS.decrypt.malformed-carrier | test_gap | runtime | KMS-ADAPTER-001 / Malformed carrier |
| SOPS.decrypt.mismatched-context | test_gap | runtime | KMS-ADAPTER-001 / Context mismatch |
| SOPS.decrypt.sidecar-principal | spec_gap | runtime | No exact accepted trace |
| SOPS.decrypt.wire | spec_gap | runtime | No exact accepted trace |
| SOPS.encrypt.admitted-carrier | test_gap | runtime | KMS-ADAPTER-001 / SOPS round trip |
| SOPS.encrypt.malformed-carrier | test_gap | runtime | KMS-ADAPTER-001 / Malformed carrier |
| SOPS.encrypt.sidecar-principal | spec_gap | runtime | No exact accepted trace |
| SOPS.encrypt.wire | spec_gap | runtime | No exact accepted trace |
| SOPS.protobuf.wire-numbers | spec_gap | runtime | No exact accepted trace |
| SOPS.socket.ambient-proxy-redirect | test_gap | runtime | KMS-ADAPTER-002 / Unsafe socket or remote trust |
| SOPS.socket.existing-entry | test_gap | runtime | KMS-ADAPTER-002 / Unsafe socket or remote trust |
| SOPS.socket.private | test_gap | runtime | KMS-ADAPTER-002 / Private sidecar |
| SOPS.socket.writable-parent | test_gap | runtime | KMS-ADAPTER-002 / Unsafe socket or remote trust |
| STORE.approval.other-node | test_gap | runtime | KMS-AUTHZ-003 / Approval for another serving node is not counted |
| STORE.cosmos.field-order | contract_conflict | runtime | No exact accepted trace |
| STORE.cosmos.original-digest | test_gap | runtime | KMS-COSMOS-002 / Authorized transaction |
| STORE.cosmos.payer-granter | contract_conflict | runtime | No exact accepted trace |
| STORE.cosmos.sequence-recovery | proposed | runtime | No exact accepted trace |
| STORE.cosmos.signed-output-verification | proposed | runtime | No exact accepted trace |
| STORE.cosmos.zero-account | test_gap | runtime | KMS-COSMOS-001 / Default account number |
| STORE.custody.ambiguity | test_gap | runtime | KMS-REG-001 / Ambiguity or false redundancy |
| STORE.daemon-config.defaults | test_gap | runtime | KMS-API-004 / Minimal local configuration |
| STORE.daemon-config.unsafe-file | test_gap | runtime | KMS-API-004 / Unsafe configuration |
| STORE.envelope.aged-out | test_gap | runtime | KMS-ENV-003 / Aged-out release |
| STORE.envelope.tampered-ciphertext | test_gap | runtime | KMS-ENV-002 / Transplant or tampering |
| STORE.gpg-config.unsafe-input | test_gap | runtime | KMS-ADAPTER-006 / Unsafe deployment inputs fail before remote signing |
| STORE.policy-config.matching-purpose | test_gap | runtime | KMS-AUTHZ-002 / Exact policy |
| STORE.rbac-config.scope-change | test_gap | runtime | KMS-AUTHZ-001 / Changed scope |
| STORE.revocations.reload | test_gap | runtime | KMS-AUTH-003 / Newly revoked certificate |
| STORE.sops-config.bad-origin | test_gap | runtime | KMS-ADAPTER-002 / Unsafe socket or remote trust |
| TOOLS.retirement.planned-replacement | test_gap | runtime | KMS-REG-005 / Only a planned replacement survives |
| TOOLS.retirement.survivors | test_gap | runtime | KMS-REG-005 / Commissioned alternatives survive |
| WORKFLOW.abrmd-probe.abrmd.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.abrmd-probe.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.abrmd-probe.schedule.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.abrmd-probe.workflow_dispatch.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.build-test.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.cosmos-node.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.e2e-netns-disk.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.e2e-sandbox-policy.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.e2e-swtpm.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.govulncheck.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.initrd-reproducible-compare.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.initrd-reproducible-debian.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.initrd-reproducible.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.known-polkit-rules-debian13.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.pcrlock-luks-swtpm.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.peer-unlock-swtpm.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.pkcs11-e2e.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.privileged-and-fuzz.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.push.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.rootfs-reproducible.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.uki-build.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.unlock-boot-qemu.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.ci.verity-boot-qemu.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.codeql.analyze.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.codeql.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.codeql.push.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.codeql.schedule.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.initrd-drift.build.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.initrd-drift.file.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.initrd-drift.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.initrd-drift.schedule.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.initrd-drift.workflow_dispatch.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.audit-ship-systemd.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.node-units-systemd.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.push.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.rolling-threenode.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.schedule.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-leases.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-netns.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-outage.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-reanchor.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-replace.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-site-advance.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-theft.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.node-units.three-node-wan.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.recovery-matrix.matrix.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.recovery-matrix.merge.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.recovery-matrix.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.recovery-matrix.workflow_dispatch.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.recovery-reconcile.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.recovery-reconcile.reconcile.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.recovery-reconcile.workflow_dispatch.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.secret-scan.pull_request.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.secret-scan.push.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.secret-scan.secrets.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.vtpm-probe.vtpm-proxy.declared-registration | spec_gap | runtime | No exact accepted trace |
| WORKFLOW.vtpm-probe.workflow_dispatch.declared-registration | spec_gap | runtime | No exact accepted trace |

API batch 1 adds three exact scenarios for twelve busy/reservation/restart cases. These move from spec gaps to test gaps with the same gap IDs; no route execution or historical proof is promoted. Busy refusal occurs after nonce reservation, so a retry needs a fresh nonce. See [accepted text resolutions](runtime-api-gap-batch1-acceptance.json). The source/task reconciliation remains a dated snapshot of its hashed inputs.

Nine busy/duplicate API cases now have [local candidate HTTP integration tests](runtime-api-http-test-candidate.json). Eleven subtests passed in a fresh parent build on nonroot Linux, and four intended code mutations failed. The candidate uses inert backend hardware and supplied TLS peer state. These remain test gaps pending publication and accepted verification; restart cases are unchanged.

API batch 2 adds three source-supported scenarios for seven remaining operation cases. These move to test gaps without execution promotion. The [expanded local HTTP test candidate](runtime-api-http-test-candidate-batch2.json) now covers thirteen busy/duplicate route cases plus two controls; fifteen subtests passed on nonroot Linux. The three added restart cases remain source/text only.

Interface batch 3 adds seven scenarios across metrics, no-token operation refusal, journal mark lag, signature publication and SOPS local contracts. Six cases move to test gaps. Both SOPS wire cases remain spec gaps: local descriptor fields are documented, while named upstream release compatibility remains unqualified. No new execution is claimed.

Workflow batch 4 records 21 event and 38 job declaration contracts from nine source-pinned workflows. The 59 cases move to test gaps while preserving their exact conditional context; no hosted result, effective permission or forge-required check is inferred. The new [workflow authoring row](workflow-authoring-supplement.json) is UNVERIFIED.

Recovery batch 5 adds thirteen source-contract scenarios. Six cases move to test gaps. Three broader cases stay spec gaps: missing-history statement replay and independent floor, local queue/refusal timing, and substituted post-exchange endpoint lineage. A saved receipt proves its signed commitment, not fresh collector state. Atomic etcd directory exchange and sequential offline journal-file restoration remain separate contracts. No new recovery or physical qualification is asserted.

SOPS batch 6 compares the admitted kms_key wire subset with the official v3.13.3 descriptor at its resolved immutable commit. Three cases move to test gaps; seven new literal wire/method subtests and existing RPC tests passed in a fresh local Linux build. Named-release executable interoperability, unsupported oneof alternatives, nonempty role/profile acceptance and other releases are not qualified. See [upstream contract provenance](sops-3-13-3-upstream-contract.json) and [candidate tests](sops-wire-test-candidate.json).
