# First-store commissioning

## Purpose

Controls the transition from uncommissioned hardware to authenticated operational history without allowing disk loss, identity reuse or service races to create new authority.

## ADDED Requirements

### Requirement: KMS-GEN-001 Independent first-store authority

The appliance SHALL create first history only under a unique, durably consumed authority bound to the exact device identity and signed genesis. Absence of local history or TPM records SHALL NOT grant that authority.

#### Scenario: Disk loss is not genesis

- **WHEN** an enrolled node loses its disk history and local reservation
- **THEN** normal startup and commissioning refuse new history without independent authority

#### Scenario: One authorized attempt

- **WHEN** a verified independent authority consumes an unused identity/genesis transaction
- **THEN** exactly that transaction can authorize one staged first-store attempt

### Requirement: KMS-GEN-002 Authority loss and replay refusal

The commissioning authority SHALL key consumption to a stable identity-lineage permit slot, independent of session nonces and enrolment retries. Missing, rolled-back, duplicated or replayed authority SHALL refuse; a new permit requires an explicit independently authorized intake or identity transition.

#### Scenario: Lost consumption reply

- **WHEN** consumption is durable but its reply is lost
- **THEN** a retry cannot obtain another first-store grant

#### Scenario: Authority rollback

- **WHEN** a prior authority snapshot or missing established ledger is presented
- **THEN** issuance refuses until independent recovery establishes the current consumed floor

#### Scenario: A new nonce or enrolment retry

- **WHEN** independent callers use different nonces or enrolment directories for the same identity lineage
- **THEN** they share the same consumed permit slot and cannot obtain another first-store attempt

#### Scenario: Reachable authority without authoritative intake

- **WHEN** used or unknown-custody hardware can reach an authority but has no independently authorized intake or transition
- **THEN** commissioning refuses rather than allocating a fresh permit

### Requirement: KMS-GEN-003 One bound device and allocation

The commissioning lifecycle SHALL bind every identity, authorization and reservation check to one approved TPM device and NV allocation. Unknown inventory and occupied or partial state SHALL refuse fresh consumption.

#### Scenario: Alternate device or allocation

- **WHEN** a caller selects another TPM or unused indices for an already used identity
- **THEN** the request cannot be accepted as fresh

#### Scenario: Inventory error

- **WHEN** TPM inventory is unreadable or incomplete
- **THEN** the result is a refusal rather than an empty reservation

### Requirement: KMS-GEN-004 Exclusive lifecycle and irreversible consumption

Commissioning SHALL exclude conflicting lifecycle writers through publication. Existing anchors, recovered journals, maintenance interruptions and resumed transactions SHALL NOT independently authorize a fresh first-store attempt.

#### Scenario: Concurrent commissioning

- **WHEN** two actors request first-store activation for the same identity and genesis
- **THEN** at most one consumes authority and neither observes an unsafe publication window

#### Scenario: Resumed epoch one

- **WHEN** a matching journal or zero/epoch-one anchor exists after interruption
- **THEN** resume cannot mint a new grant from those records

#### Scenario: Maintenance interleaving

- **WHEN** re-anchor or recount overlaps commissioning
- **THEN** the shared lifecycle rules prevent maintenance from creating apparent unused authority

### Requirement: KMS-GEN-005 Normal startup recovers existing history only

Normal startup, signed-restore staging and legacy adoption SHALL recover authenticated existing history or refuse. Only a consumed first-store permit SHALL authorize initial creation. Recovery SHALL NOT initialize fresh history when required objects are missing, unreadable, empty, inconsistent or substituted.

#### Scenario: Missing recovery objects

- **WHEN** a normal start encounters missing WAL or backend history
- **THEN** it refuses without creating a new store or serving an endpoint

#### Scenario: Objects changed after check

- **WHEN** a recovery object is swapped or disappears between preflight and actual use
- **THEN** the actual recovery boundary refuses the substituted or missing object

#### Scenario: Recoverable crash tail

- **WHEN** the member retains authenticated committed history with a supported interrupted tail
- **THEN** normal recovery succeeds without creating a new incarnation

#### Scenario: Restored objects disappear before stage recovery

- **WHEN** a signed snapshot has been unpacked but its required history is removed or substituted before actual staged recovery
- **THEN** recovery refuses before a raised state epoch is written and cannot fall back to blank genesis

#### Scenario: Adoption lacks existing authenticated history

- **WHEN** legacy adoption encounters missing or inconsistent recovery objects
- **THEN** adoption refuses and does not create history under a recovery authorization

### Requirement: KMS-GEN-006 Authenticated history incarnation

Member readiness SHALL match a unique commissioned or restored history incarnation to protected external evidence and durable member history. Reproducible member identifiers and absent state keys SHALL NOT establish lineage.

#### Scenario: Same identifiers different history

- **WHEN** a separately initialized valid store has the expected token and member identifiers
- **THEN** readiness refuses the unrelated incarnation

#### Scenario: Same-history rollback

- **WHEN** an older copy of the same history is offered
- **THEN** the applicable independent floor and signed restore rules remain enforced

#### Scenario: Authoritative floor is unavailable

- **WHEN** required independent old-state validation cannot authenticate or obtain its authoritative floor
- **THEN** readiness refuses rather than trusting a local receipt or assuming zero

### Requirement: KMS-GEN-007 One staged activation

A first-store transaction SHALL authorize at most one actual staged service activation. Expired, duplicated, queued or surviving stage execution SHALL NOT start or expose another member.

#### Scenario: Second manual activation

- **WHEN** another stage start is queued while transaction credentials are still present
- **THEN** only the authorized activation can execute

#### Scenario: Owner exits before execution

- **WHEN** the transaction owner exits after a condition check but before stage execution
- **THEN** the stage refuses or is isolated without exposing usable state

### Requirement: KMS-GEN-008 Durable pending and fresh serving barrier

The appliance SHALL keep KMS denied across interruption, publication and store exchange until fresh verification of the normal member and expected history succeeds for that serving start.

#### Scenario: Readback fails after exchange

- **WHEN** the normal member fails authenticated verification after durable exchange
- **THEN** pending remains effective and concurrent KMS starts cannot serve

#### Scenario: Reboot loses volatile state

- **WHEN** the node reboots with commissioning or restore incomplete
- **THEN** loss of runtime files cannot remove the durable deny

#### Scenario: Dependency appears successful

- **WHEN** a condition-skipped unit, retained result or active staged member is presented
- **THEN** it cannot satisfy the fresh KMS readiness barrier

### Requirement: KMS-GEN-009 Verified host-profile boundary

The bare-metal startup path SHALL refuse missing or invalid trusted host profiles. Any multi-node exemption SHALL require positively verified profile and configuration evidence.

#### Scenario: Missing profile

- **WHEN** a bare-metal host starts with no valid protected profile
- **THEN** the member and KMS fail closed at the required startup boundary

#### Scenario: Verified multi-node profile

- **WHEN** a valid multi-node configuration uses its supported startup contract
- **THEN** single-node commissioning changes do not replace or weaken that contract

### Requirement: KMS-GEN-010 Credential proof before consumption

Commissioning SHALL verify sealed peer credentials against the selected device, certificate identity, trust, validity and expected credential name before spending first-store authority.

#### Scenario: Wrong peer credential

- **WHEN** the unsealed private key does not match the bound peer certificate or device
- **THEN** commissioning refuses before authority consumption

#### Scenario: Later credential failure

- **WHEN** a credential becomes unusable after authority consumption
- **THEN** the transaction remains denied and the consumed attempt is not reissued

### Requirement: KMS-GEN-011 Least-privilege service handoff

Credential and history handoff SHALL preserve service isolation and prove effective access in the shipped configuration. No plaintext private credential SHALL remain in logs or persistent handoff files.

#### Scenario: History inspection

- **WHEN** readiness requires protected history inspection
- **THEN** the confined verifier gets only the justified access while etcd and KMS retain their service boundaries

#### Scenario: Socket permission mismatch

- **WHEN** an intended client lacks required socket permissions or API authorization
- **THEN** the configured readiness path refuses rather than treating AppArmor permission as sufficient

### Requirement: KMS-GEN-012 Required serving-state dependency

Supported single-node serving configuration SHALL require the authenticated operational-state readiness dependency. Omitting an optional watcher configuration SHALL NOT permit serving.

#### Scenario: State configuration omitted

- **WHEN** single-node serving is configured without its required state endpoint or readiness proof
- **THEN** startup refuses before serving

#### Scenario: Wrong active endpoint

- **WHEN** an already-running endpoint belongs to a stage or different member
- **THEN** it cannot satisfy the normal serving dependency

### Requirement: KMS-GEN-013 Explicit legacy transition

Unmarked legacy state SHALL require authenticated adoption or authorized signed restore. Every boot-eligible operational image, including rollback, SHALL enforce pending and required history floors; incompatible images SHALL remain ineligible or independently fenced. Unknown legacy state SHALL NOT imply a fresh appliance.

#### Scenario: Unknown legacy lineage

- **WHEN** an existing store has no independently trusted lineage evidence
- **THEN** migration stays denied until an authorized transition succeeds

#### Scenario: Failed migration rollback

- **WHEN** migration fails after an authority has been consumed
- **THEN** software rollback cannot clear consumption or authorize older history

#### Scenario: Boot into compatible rollback with pending

- **WHEN** an approved rollback image boots while pending remains durable and volatile runtime state is lost
- **THEN** it preserves service denial and authenticates required history before any serving transition

#### Scenario: Older image ignores the guard

- **WHEN** an older image would ignore pending or bootstrap new history
- **THEN** it is ineligible for operational boot or independently fenced before rollback; commissioning cannot claim acceptance while it remains an eligible serving path

### Requirement: KMS-GEN-014 Separate software and physical acceptance

Release acceptance SHALL require the specified real-service negative and positive controls plus separate physical commissioning, reboot and interruption evidence. A logical model alone SHALL NOT close the lifecycle gate.

#### Scenario: Software proof only

- **WHEN** logical and software-TPM tests pass without physical acceptance
- **THEN** the hardware and release gates remain open

#### Scenario: End-to-end preservation

- **WHEN** authorized commissioning and signed restore complete under the supported topology
- **THEN** existing unlock, lease, revocation and multi-node/package refusal contracts still pass

#### Scenario: Fresh-genesis proof while replacement review is pending

- **WHEN** the independent authority, recovery, credential and manager software gates pass but replacement review remains unresolved
- **THEN** fresh-genesis software evidence can be recorded separately while replacement/restore and physical milestones stay blocked
