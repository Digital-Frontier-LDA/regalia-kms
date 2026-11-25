## Purpose

Gate operation on an attested, current runtime lease tied to the boot session and membership profile, with refusal when admission evidence is untrusted or stale.

## ADDED Requirements

### Requirement: KMS-LEASE-001 Separate local self-issuance from peer leases

Only the admission service's kernel-identified local connection SHALL obtain a self-lease, and only in the single-node profile. The listener SHALL limit requests to lease nonce and lease issuance. Multi-node SHALL continue to use peer issuance.

#### Scenario: Unapproved local caller
- **WHEN** a different UID asks for a lease or nonce
- **THEN** the listener refuses before loading identities or issuing evidence.

#### Scenario: The admission account uses the local lease exchange
- **WHEN** the admission service connects with the expected kernel identity under single-node and submits the supported request sequence
- **THEN** the listener supplies a nonce and dispatches the corresponding lease request once to the local issuer.

#### Scenario: The local listener does not dispatch peer operations
- **WHEN** an authorized local caller sends an operation other than requesting a lease or its nonce
- **THEN** the listener refuses the operation and issues no lease.

#### Scenario: The local path refuses a multi-node manifest
- **WHEN** the local admission identity requests a nonce or lease under a multi-node manifest
- **THEN** the listener refuses before attestation or issuance.

#### Scenario: The local listener closes accepted connections beyond its active limits

- **WHEN** the single-node local listener has accepted a socket and already holds eight active connections overall or two for that socket's kernel UID
- **THEN** it closes the surplus connection without dispatching a lease request or returning a protocol reply, even for the admission UID

#### Scenario: An incomplete local request releases its worker

- **WHEN** a local connection within those limits times out while the listener reads the request using its ten-second read deadline
- **THEN** the listener closes the connection without dispatching it and releases its active slot

### Requirement: KMS-LEASE-002 Bound issuance to current attested state

A runtime lease SHALL bind the current membership digest, subject boot session and serving state. It SHALL require system-phase evidence and expire no later than both the lease maximum and the verified heartbeat expiry.

#### Scenario: Attested and authorized host
- **WHEN** a valid system-phase subject requests a lease
- **THEN** the issued lease is bound to that session and its lifetime is capped by heartbeat freshness.

### Requirement: KMS-LEASE-003 Refuse mismatched or untrusted admission

The daemon SHALL refuse normal requests when the admission state is missing, untrusted, or incompatible with the verified membership profile.

#### Scenario: Incorrect admission mode
- **WHEN** a single-node chain is paired with peer-lease mode or a multi-node chain with single mode
- **THEN** the daemon refuses the request.

#### Scenario: A current single-node admission carries serving state
- **WHEN** the current boot has valid single-mode admission bound to a verified single-node chain
- **THEN** the gate admits the listed token and exposes the lease's state and request time.

#### Scenario: Single mode requires a verified single-node chain
- **WHEN** a single-mode document is available without a configured verified membership chain
- **THEN** the gate refuses serving.

#### Scenario: Recovery mode cannot admit the sole node
- **WHEN** a single-node chain is paired with an otherwise well-formed recovery-mode admission
- **THEN** the gate denies serving.

### Requirement: KMS-LEASE-004 Admission follows the boot-time serving bound

The gate SHALL refuse at and beyond the boot-time serving bound until valid admission is available.

#### Scenario: The serving bound expires
- **WHEN** the current boot reaches the admission document's serving bound without a newer valid admission
- **THEN** the gate refuses further serving at the bound.

### Requirement: KMS-LEASE-005 Bind the local lease socket only in a trusted directory

The local lease listener SHALL refuse a directory writable by its group or others. It SHALL leave an unexpected non-socket entry intact and refuse to bind there.

#### Scenario: A stale socket and an unexpected file are handled differently
- **WHEN** the trusted listener directory already contains an entry at the socket name
- **THEN** a leftover socket may be replaced, and an entry that is not a socket is retained and causes binding to fail.

#### Scenario: The listener directory is writable by others
- **WHEN** the local listener directory is writable by its group or other users
- **THEN** binding refuses and does not create the socket.

### Requirement: KMS-LEASE-006 Resume serving after valid renewal

After lease loss, normal lease-based admission SHALL publish a new serving bound only when the service holds a valid lease for the current boot and membership.

#### Scenario: A new valid lease restores admission after an outage
- **WHEN** an eligible issuer comes back after the previous lease expired and the renewer receives a current valid lease
- **THEN** the service publishes a new serving bound for the admitted boot.

### Requirement: KMS-LEASE-007 Publish loss of admission without waiting for renewal

The expiry watcher SHALL publish non-serving admission when the serving bound is reached and no valid replacement exists, even while renewal is outstanding.

#### Scenario: A stalled renewal does not delay admission lapse
- **WHEN** the serving bound is reached while a renewal request still waits for a peer and no valid replacement is held
- **THEN** the watcher publishes and records non-serving admission without waiting for renewal to return.

### Requirement: KMS-LEASE-008 Separate daemon readiness from process startup

A configured daemon that requires runtime admission SHALL report not ready and refuse governed requests while that admission is absent.

#### Scenario: A running daemon lacks required admission
- **WHEN** the daemon is running with admission required but has no valid serving admission
- **THEN** its readiness reports not ready and governed key operations are refused.
