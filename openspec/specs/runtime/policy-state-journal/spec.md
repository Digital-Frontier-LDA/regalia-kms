# runtime/policy-state-journal Specification

## Purpose

Define how durable reservations, audit checkpoints, and exported state preserve policy history.

## Requirements

### Requirement: KMS-STATE-001 Durable policy reservations

The KMS SHALL append and synchronize a reservation before admitting a stateful operation. It SHALL preserve replay and UTC-day quota history across restart, enforce the reservation epoch floor, and fail closed when the journal or its high-water mark cannot be safely advanced.

#### Scenario: A spent signing nonce remains spent after daemon restart

- **WHEN** a ready daemon with its existing journal receives the same nonce again after restarting following a successful signing request
- **THEN** the sign route returns HTTP 409 for the repeated nonce

#### Scenario: Restart preserves spend

- **WHEN** the daemon reopens a valid journal after committing a reservation
- **THEN** the nonce remains spent and the UTC-day total retains the previous amount

#### Scenario: Cannot commit

- **WHEN** the journal cannot append the next reservation
- **THEN** the reservation fails and the local state reports unready

#### Scenario: Stale epoch

- **WHEN** a reservation proposes an epoch lower than the journal floor
- **THEN** it is refused before append

#### Scenario: A reservation may exactly fill the quota

- **WHEN** a valid reservation fills the exact remaining UTC-day quota and a later request attempts to spend another unit
- **THEN** the reservation filling the quota commits, and the later increment is refused

#### Scenario: A reopened daemon refuses spent wrap unwrap and certificate nonces

- **WHEN** the daemon resumes serving after reopening the same intact policy journal and an otherwise eligible POST to `/v1/operations/wrap`, `/v1/operations/unwrap` or `/v1/operations/certificate-sign` reaches reservation with a nonce committed before restart for the same policy, object and principal
- **THEN** the route returns HTTP 409 with `CONFLICT` and `retryable: false` before running the operation

#### Scenario: Agreement release and seal cannot reuse a nonce after restart

- **GIVEN** a restarted daemon has reopened the same intact policy journal and resumed serving
- **WHEN** an otherwise eligible POST to `/v1/operations/key-agreement`, `/v1/operations/release-secret` or `/v1/operations/seal-envelope` reaches reservation with a nonce committed before restart for the same policy, object and principal
- **THEN** the route returns HTTP 409 with `CONFLICT` and `retryable: false` before running the operation

### Requirement: KMS-STATE-002 Local history integrity

Opening the local journal SHALL refuse loss or replacement detected against its high-water mark. A second writer opening the same journal SHALL fail while the first holds its lock.

#### Scenario: Damaged history

- **WHEN** the journal is truncated or replaced with a different chain at the same recorded position
- **THEN** startup refuses with the local history check

#### Scenario: Concurrent writer

- **WHEN** another cooperating process already holds the same journal open
- **THEN** the second open is refused and succeeds after the holder closes

#### Scenario: A durable append ahead of its local mark is recovered

- **WHEN** the sole writer reopens an intact policy journal containing one fully written and synchronized reservation beyond the valid previous high-water mark
- **THEN** the local journal opens and includes the appended reservation in its replay and quota history

### Requirement: KMS-STATE-003 External policy checkpoint

A site configured with the audit collector SHALL reconcile the local policy journal to the collector-acknowledged authorization position before serving. The daemon SHALL refuse a local journal behind or divergent at that position and SHALL refuse startup if the configured collector is unreachable.

#### Scenario: Reconciliation succeeds

- **WHEN** the journal contains the exact collector-acknowledged reservation
- **THEN** startup may continue

#### Scenario: Consistent local rollback

- **WHEN** the journal and local mark agree but end before the collector's checkpoint
- **THEN** startup is refused

#### Scenario: Collector unavailable

- **WHEN** the configured collector cannot provide continuity
- **THEN** startup is refused

### Requirement: KMS-STATE-004 Offline journal restore

The control-plane journal restore SHALL restore each journal and its mark together into absent destinations and verify restored bytes against the export. It SHALL refuse an existing destination during preflight. A filesystem error during the write phase can leave a partial restore requiring operator handling.

#### Scenario: Verified offline restore

- **WHEN** a verified bundle contains paired journals and marks and all destinations are empty
- **THEN** each restored journal and mark matches the exported bytes

#### Scenario: Restore preflight refusal

- **WHEN** a destination already exists or a journal lacks its mark
- **THEN** the operation refuses before writing files

#### Scenario: Interrupted journal restoration can leave occupied destinations

- **WHEN** offline restoration passes destination preflight, then fails in the write or readback phase after a destination has been written
- **THEN** the operation returns an error without rolling back those files. A repeat with the same bundle and root refuses in preflight while any target remains occupied

#### Scenario: Offline restore requires explicit authority key site and root

- **WHEN** the KMS command selects restore-export and any of authority-key-pem, expect-site or restore-root is omitted or empty
- **THEN** it exits unsuccessfully with the required-options error, before opening the export or writing any destination

### Requirement: KMS-STATE-005 Single-node replay and rollback boundary

A production single-node deployment SHALL enforce its accepted state history and collector checkpoint across normal boot and authorized state replacement.

#### Scenario: Unproven history

- **WHEN** the store and its local sidecars are missing or have been rolled back together
- **THEN** normal service stays unavailable unless an independently authorized continuation proves a valid floor

### Requirement: KMS-STATE-006 Control-plane export confidentiality and inspection

The control-plane export SHALL seal state to the designated P-256 custody recipient and SHALL refuse invalid or tampered state during inspection. A sealed file establishes confidentiality to the recipient. The recovery authority must establish export origin and recency independently.

#### Scenario: Intact approved export

- **WHEN** the intended recipient opens a valid export
- **THEN** the original controlled state can be inspected

#### Scenario: Incorrect key or invalid state

- **WHEN** the recipient key is wrong or the payload contains invalid journal evidence
- **THEN** inspection refuses before restore

### Requirement: KMS-STATE-007 Read-only policy history verification

The policy-state verification command SHALL inspect the requested existing journal without opening it as a writer. It SHALL report the verified head for a populated journal and fail if the journal is missing.

#### Scenario: Explicit verification refuses missing history

- **WHEN** the policy-state verification command is run on an absent journal
- **THEN** the command fails without creating a journal or reporting a verified head

#### Scenario: Explicit verification reports the recorded head

- **WHEN** the policy-state verification command reads an intact journal with recorded reservations
- **THEN** it reports the reservation count, recorded head and head hash without writing new state
