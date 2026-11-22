## Purpose

Require consent from the attended owner responder for each single-node boot while retaining a separate recovery keyslot and keeping the contribution off the node's disk.

## ADDED Requirements

### Requirement: KMS-OWNER-001 Use only the pinned owner responder

A single-node boot configuration SHALL contain exactly one responder, the owner. The client SHALL verify the response under a pinned owner key and require it for the current session and path in addition to the local TPM contribution.

#### Scenario: Owner unavailable
- **WHEN** the local TPM releases its half but the configured owner responder is unavailable
- **THEN** automatic unlock does not deliver a disk key.

#### Scenario: Approved boot opens the owner path
- **WHEN** an eligible single-node boot has its TPM contribution and receives a valid response from its pinned owner
- **THEN** the client opens the enrolled owner keyslot.

#### Scenario: Retired image gets no owner contribution
- **WHEN** the local TPM releases its contribution but the boot quote no longer matches an approved image
- **THEN** the owner refuses and the boot client opens no keyslot through the owner exchange.

### Requirement: KMS-OWNER-002 Keep the owner contribution separately controlled

The owner's stored path contribution SHALL be encrypted to two distinct owner card decryption identities. Path repair SHALL use a new path epoch and the attended responder SHALL refuse a contribution for the wrong target, TPM, or path.

#### Scenario: Obsolete path contribution
- **WHEN** the node requests its new path with an older owner envelope
- **THEN** the request is refused.

### Requirement: KMS-OWNER-003 Stop on a latched owner card

The attended responder SHALL stop on a latched PIN refusal, keep detailed diagnostics local, and return a generic refusal over the wire. It SHALL refuse exchanges outside the configured serving window.

#### Scenario: The owner card refuses a PIN
- **WHEN** the signing token reports a latched refusal
- **THEN** the peer gets a generic refusal and the tool stops attempting to sign.

#### Scenario: A connection arrives after the serving window
- **WHEN** a connection is accepted by the listener after the configured serving window has ended
- **THEN** the responder closes it without starting a protocol exchange.

#### Scenario: A connection has only the remaining serving time
- **WHEN** a connection arrives shortly before the configured serving window ends
- **THEN** the responder bounds its I/O by the time still available in that window.

### Requirement: KMS-OWNER-004 Qualify the attended card procedure on TEST hardware

Staging acceptance SHALL demonstrate initial and repeat boot with the real attended owner-card procedure and its TPM-bound host. A simulated card or successful startup without the owner-off control SHALL leave this qualification open.

#### Scenario: Only software fixtures are available
- **WHEN** owner signing and boot have been tested using synthetic materials
- **THEN** the physical staging gate stays open.
