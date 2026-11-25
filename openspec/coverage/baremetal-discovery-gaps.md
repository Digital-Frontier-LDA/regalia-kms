# Bare-metal discovery and verification gaps

Frozen source `0a32a901d1240eec51ddff323274e2ad935116f3`. This is a source-led reconciliation pass. `discoveryClosed` remains false.

## How to read the shard

- All 525 scoped original IDs are retained in `baremetal-interface-ledger.json` under `entries[].interfaceId`. There are 421 public, 75 internal and 29 needs-review dispositions. Internal service, build, test and persistent-state interfaces remain in scope where they affect observable behavior.
- The shard contains 463 proposed inventory rows. Its `dynamicExpansions` cover 16 scanned sites and 15 original discovery IDs with 81 explicit child IDs. `registrationSplits` propose splitting 58 literal registrations that were coalesced across commands, while preserving each original ID. Some proposed helper rows share an actual invocation and require parent consolidation.
- Cases record an exact scenario only where its precondition and outcome match, or where a contract conflict or proposal explicitly identifies the target scenario. A nearby requirement about the same topic is insufficient. All execution arrays are empty. 517 original IDs still lack a direct behavior case, and 3623 original-ID facets are explicitly `trace-open`. Even facets with cases retain a remaining-discovery gap. No blanket applicability exclusion was applied.

## Priority interface handoff

| Interface | Ledger ID | Cases | Remaining trace or proof |
| --- | --- | ---: | --- |
| enrol-commit | `IF-79df444eb7b67af4` | 15 | Trace full CLI and no-write versus partial-publication outcomes, including wrong TPM allocation, root context and commit/maintenance interleaving. Existing rechecks and publication assertions are narrower. |
| enrol-bootstrap | `IF-485c7020b33d04f8` | 13 | Separate older exact-sequence adoption from quorum-schema parent initialization at N−1 and first-pull uptake. Trace authenticated time, before/after NV define interruption and full-pair, half-pair and planted-pair behavior through actual CLI. |
| enrol-replace | `IF-72e67b11d4e087e8` | 5 | Keep multi-node typed acceptance, missing intent and wrong ID distinct. Published single-node later-epoch refusal remains a dx7.19 conflict, including guard integration. Restricted independent review of 695a8118 stays unresolved. |
| restore-run | `IF-0fa13aa1dfa73da0` | 20 | Separate authorization refusal, live/staged negative status, same-epoch replay, lost-disk replay, concurrent normal starts, wrong live endpoint and uncertain exchange. Real etcd test definitions do not prove Debian PID 1 or physical reboot. |
| restore-sign | `IF-59f67d725ee8750f` | 8 | Add exact cases for an invalid scope, off-node posture, failed exclusive output after epoch consumption, destroyed/rolled-back ledger and unavailable collector evidence. Allocation is different from protected use. |
| owner-unlock | `IF-ca602dbdcf96caa7` | 9 | Separate positive attended key use, unavailable owner, retired image, obsolete path and responder-window/late-reply behavior. The harness uses synthetic fixtures; physical card, control and repeat boot remain unverified. |
| admission | `IF-f7e1951435211a4a` | 10 | Separate file trust from lease identity, expiry, recovery profile and concurrent renewal. Correlated refusal and timing checks in the test harness do not establish a normal KMS startup barrier. |
| etcd-start | `IF-847603a1f52ffdd2` | 9 | A static ConditionPathExists assertion establishes config presence only. Need PID 1 traces and actual open semantics for absent, cloned, mismatched and rolled-back live history and for the scoped stage exception. |
| local-lease | `BMIF-8ecf83f8d3f0a9cf` | 7 | UID refusal through AF_UNIX and stale socket behavior have fixture assertions. Positive socket test uses a stubbed issuer. Real TPM eligibility, budgets, restart and same-profile service integration remain open. |
| kms-start | `IF-0c83b5373690395b` | 8 | Cross-reference the shared runtime unit. Need exact systemd normal restart, manual start, stale dependency and signed live-history barrier. AppArmor unit checks and request denial remain separate. |
| render-check | `BMIF-7c448850f60c73f2` | 5 | Initrd skip is a volatile diagnostic path. Verify actual systemd skip/failure statuses and restart behavior. No first-store authority follows from it. |
| consumer-check | `BMIF-54d1d7a620d250a5` | 2 | Verify fresh ordering and actual PID 1 result with invalid, absent and stale volatile skip marker after restart. The fixture checks Go status only. |

## Discovery still required

- Reconcile all custom parser forms at their callers. This pass added Go render and condition flags, Python positional service and device verbs, recovery state and trail dispatch, shell create/install/recovery/lockout options, and fixed helper arguments. Complete argument ordering and defaults, parser parent/subcommand reuse, deprecated forms, nested selector grammar, hidden subprocess inputs, environment/build-tag dependent call paths and shell parser branches remain open.
- Finish generated unit surfaces. `units-enabled.txt`, the image builder and systemd drop-ins, template instance registries, generators and initrd boot chains compose additional interfaces. Trace generated target/condition, effective identities, credentials, file permissions and behavior on missing or stale input. Shared KMS/audit worker and CI owners keep their original rows.
- Complete nested and conditional configuration. Discovered node, site and boot JSON fields are seeds. Add accepted/missing/duplicate/type/bound branches per field, conditional defaults, profile-specific combinations, TPM resource-manager/test environment switch, certificate bindings and configuration cross-products. Validate Go/Python version agreement using actual assertions.
- Complete persistent lifecycle. Enrol journal, TPM anchor and counter paired indices, signed chain and boot credentials, owner path/envelope/verifier state, sealed token references, restore staging/member and snapshot copy, signed state epoch, restore ledger, and local or remote lease state need versioned creation, trust, byte/size bounds, atomicity and recovery traces. Topic declarations do not establish migration compatibility.
- Reconcile schema aliases on substance. Proposed links for boot config v1/v2 bind the Python producer to the Go consumer. The initrd-packages producer and UKI consumer share a version. Preserve all discovery origin IDs and independent producer/consumer evidence. Do not merge same-named options belonging to different commands without an actual alias relation.
- Review any remaining transport surfaces, including remote peer sync dispatch and wire envelopes, boot unwrap and owner response versions, and platform and software TPM controls. The local lease endpoint is separate from remote lease dispatch and production issuance must not be inferred from fixture wire responses.
- `needs-review` visibility is explicit for mixed-purpose dispatch or helper-template declarations. Authorization, physical custody, deployment state and applicable test coverage are not implied by the static label.

## Milestone blockers

- **dx7.26** requires durable pending and no-history closure through manual/reboot starts. The published restore's volatile stage configuration and raised-epoch readback are real code. Normal etcd is gated by config presence. Neither it nor KMS has the accepted durable bootstrap/recovery barrier at the pin. Local 9088/5ce are context only. The separate first-store proposal still requires independent authority/lineage, exact staged activation, credential and live service-manager proof, then physical reboot/power-loss and lost-disk restore.
- **dx7.19** requires the reviewed sole-node revocation to root replacement and verified first heartbeat under the accepted chain, plus replacement pre-publication guard integration. Its restricted independent review remains unresolved. No local candidate is credited.
- **Single-node v0.1 TEST** still requires a qualified TEST image, physical initial and repeat owner-card operation, timed DKEK restore-to-replacement, 72-hour clean burn-in and owner TEST acceptance. dx7.24 only applies if activation history is unavailable and refuses pending a reviewed repair. TPM clearing is not a recovery action. dx7.7, dx7.8, dx7.9 and 4h4 remain distinct gaps.
- **Three-node production** requires its own genesis, three-node TEST rehearsal and separate physical commissioning/acceptance. The single-node production gate 2jd applies only if that production profile is selected. Machine-free, software TPM, fixture real-etcd, live Debian service-manager and hardware evidence remain distinct.

Parent reconciliation should retain open facet and case gap IDs, resolve helper/template and shared aliases, then run the authoritative checker only once its schema and closure rules are approved.
