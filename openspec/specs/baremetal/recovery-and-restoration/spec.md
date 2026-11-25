# baremetal/recovery-and-restoration Specification

## Purpose

Restore only an authorized, verified operational history and keep single-node service fail-closed across interrupted restore or loss of trusted live history.

## Requirements

### Requirement: KMS-RESTORE-001 Require an attended signed restore statement

Single-node snapshot restoration SHALL require an owner statement for the current membership and target snapshot, inside its authenticated time window. The owner issuance process SHALL raise the requested epoch above both the collector record and its issuance ledger.

#### Scenario: An epoch has already been issued
- **WHEN** the owner issues another restore statement for the same genesis
- **THEN** the new epoch exceeds the retained authority floor.

#### Scenario: A non-owner key requests a restore statement
- **WHEN** the selected signing key does not belong to an owner in the verified manifest
- **THEN** the tool refuses without signing or issuing an epoch.

#### Scenario: A refused confirmation leaves its epoch issued
- **WHEN** the owner enters the wrong epoch or digest prefix after an epoch has been allocated
- **THEN** the tool signs no statement and does not reuse that allocated epoch.

#### Scenario: A multi-node chain cannot obtain a single-node statement
- **WHEN** the owner issues a restore statement against a multi-node chain
- **THEN** the tool refuses without allocating an epoch.

#### Scenario: Statement is outside its validity window at entry
- **WHEN** the authenticated start time is before the statement's start or at or beyond its expiry
- **THEN** restore refuses before starting or stopping services or writing restore state.

#### Scenario: Statement expires before the staged epoch write
- **WHEN** the statement was valid at entry but expires before the fresh time check for the staged epoch
- **THEN** restore refuses the new epoch write and does not restart KMS.

#### Scenario: Single-node restore is requested on a multi-node cluster
- **WHEN** the accepted chain is multi-node
- **THEN** the single-node restore refuses before any service lifecycle action.

#### Scenario: A node signature cannot authorize snapshot restore
- **WHEN** the statement is presented with the node's signature instead of an authorized owner's
- **THEN** restore refuses before invoking service lifecycle actions.

#### Scenario: Membership moved after restore authorization
- **WHEN** the owner statement names an earlier manifest epoch than the accepted chain tip
- **THEN** restore refuses before invoking service lifecycle actions.

#### Scenario: On-node restore statement issuance refuses before reading the chain

- **WHEN** the restore sign-statement command receives parsed arguments and its off-node check finds any predefined KMS node marker
- **THEN** it exits unsuccessfully before reading the membership chain, opening the owner signer, allocating an epoch or writing the statement

#### Scenario: Missing live member leaves statement single use to owner procedure

- **WHEN** a current, otherwise accepted restore statement is presented while the live member directory is absent
- **THEN** restore uses the statement's signed floor in place of a live epoch, still requires the raised epoch to exceed the staged snapshot's verified epoch, and makes no independent check that the statement was already used. The owner treats a handed-off statement as consumed and issues a new one before retrying

### Requirement: KMS-RESTORE-002 Verify staged and live history before serving

The restore transaction SHALL verify the staged single-member store, raise the state epoch above any observed live and snapshot epoch, then install the staged store atomically. It SHALL verify the live state epoch with normal etcd configuration before restarting KMS.

#### Scenario: Snapshot already holds the proposed epoch
- **WHEN** the staged snapshot state epoch equals the proposed one
- **THEN** restore refuses and, when live history is lost, leaves etcd and KMS stopped.

#### Scenario: Verified readback precedes the KMS start
- **WHEN** the signed restore succeeds, the staged member is published, and etcd restarts on its normal configuration
- **THEN** the transaction verifies the expected sole member and signed raised epoch before starting KMS.

#### Scenario: Snapshot digest mismatch discards the temporary copy
- **WHEN** the copied snapshot does not match the digest in the owner statement
- **THEN** restore refuses to stage it and removes the temporary copy when cleanup succeeds.

#### Scenario: Live state epoch is already high enough to reject the restore
- **WHEN** the active live store's verified epoch equals or exceeds the proposed epoch
- **THEN** restore refuses without stopping the live services.

#### Scenario: Failed exchange has no live store to return to
- **WHEN** the controlled restore has stopped services, no live member exists, and publication fails before exchange
- **THEN** restore leaves both etcd and KMS stopped rather than opening a fresh live store within that transaction.

#### Scenario: Exchange completed but durability is unknown
- **WHEN** the store rename succeeds and the subsequent directory sync fails
- **THEN** the transaction reports uncertain durability and withholds service restart pending verified normal readback.

#### Scenario: Normal endpoint member mismatch keeps KMS stopped after exchange

- **WHEN** the restore has published the staged member and restarted normal etcd but the endpoint status does not report exactly one endpoint or its member list is not the enrolled node alone
- **THEN** the restore refuses before requesting a KMS start

#### Scenario: Normal endpoint epoch must verify and match after exchange

- **WHEN** normal etcd has restarted after exchange, no restore or take-over override is active, and the expected sole member answers
- **THEN** restore refuses a missing, invalid or different signed state-epoch entry before KMS startup. To start KMS, the entry must match the statement's epoch and verify against the live status cluster ID and a key revision after the entry's recorded prior revision

### Requirement: KMS-RESTORE-003 Keep normal services blocked while restore is unresolved

Normal etcd and KMS SHALL remain stopped across reboot and manual start while single-node restore is pending or trusted live history is unavailable. Only the controlled restore transaction MAY start etcd against verified staging, with KMS blocked until normal configuration and signed live history are verified.

#### Scenario: Reboot loses volatile state during restore
- **WHEN** the durable restore remains unresolved or there is no trusted live history
- **THEN** normal etcd and KMS stay stopped until an authorized transaction verifies and publishes live history.

### Requirement: KMS-RESTORE-004 Recover missing single-node anchor and counter history

Single-node recovery from lost anchor or freshness state SHALL use independently retained signed owner and collector evidence. Ambiguous or missing evidence SHALL prevent resuming service; recovery SHALL NOT clear the TPM as a workaround.

#### Scenario: No peer and no trusted recovery floor
- **WHEN** the sole node has lost its anchor or counter history
- **THEN** automatic recovery cannot treat the absence as a new genesis.

### Requirement: KMS-RESTORE-005 Preserve multi-node history during authorized take-over

When an authorized multi-node survivor performs stateful take-over, it SHALL preserve the cluster identity and at least the applied revision, verify itself as the only member, and verify the raised signed state epoch before serving. It SHALL refuse a backend behind the revision it already applied.

#### Scenario: Stored backend is older than applied history
- **WHEN** the surviving host reports a higher applied revision than the stored backend
- **THEN** take-over refuses before forcing a new cluster.

### Requirement: KMS-RESTORE-006 Preserve the restore issuance ledger

Restore issuance SHALL refuse malformed retained epoch history. Concurrent issuers sharing one ledger MUST allocate distinct increasing epochs.

#### Scenario: Concurrent issuance uses distinct epochs
- **WHEN** two issuers use the same ledger and collector floor concurrently
- **THEN** the allocations are distinct and advance the shared floor in order.

#### Scenario: The retained issuance history is malformed
- **WHEN** the restore ledger lists prior epochs out of order or with duplicates
- **THEN** issuance refuses without replacing the history with a fresh allocation.

### Requirement: KMS-RESTORE-007 Keep concurrent and unfinished restore attempts separate

A controlled restore SHALL refuse entry into its mutation step while another restore holds the host lock. It SHALL refuse a new attempt if it sees an earlier restore's runtime staging override.

#### Scenario: Another restore holds the host transaction lock
- **WHEN** a second restore invocation on the same host reaches the mutation entry while a restore already holds the lock
- **THEN** the second invocation exits with refusal before entering the restore mutation routine.

#### Scenario: Earlier transaction left its runtime override
- **WHEN** a new restore sees a staging override left by an earlier attempt
- **THEN** it refuses before performing service lifecycle actions and reports the leftover override.
