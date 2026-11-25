## Purpose

Define the signed membership chain, topology and voting rules that determine which identities retain cluster authority.

## ADDED Requirements

### Requirement: KMS-MEM-001 Pinned chain continuity

Membership verifiers SHALL require a pinned-root genesis and accept only a correctly signed continuation with the next epoch and predecessor digest. Re-delivery of the identical tip is idempotent.

#### Scenario: One continuation follows the tip
- **WHEN** a valid and authorized next epoch names the held digest
- **THEN** it becomes the accepted tip

#### Scenario: Conflicting epoch
- **WHEN** a different document arrives for the held epoch
- **THEN** the conflicting document is refused

### Requirement: KMS-MEM-002 Topology set at genesis

A v5 genesis SHALL explicitly select one or three designed members. A later signer MUST preserve the chosen topology. The legacy v4 profile retains the three-node floor.

#### Scenario: Unsupported size
- **WHEN** a proposal names a five-node topology
- **THEN** validation refuses it

#### Scenario: Outage preserves profile
- **WHEN** only one node of a three-member design remains live
- **THEN** the design size and quorum floor stay three and two

### Requirement: KMS-MEM-003 Profile-specific signer rules

Node signer rules SHALL use the majority floor of the designed membership. In single-node membership, the one named node SHALL sign heartbeats and activation, and only the owner SHALL authorize revocation.

#### Scenario: Single-node signer substitution
- **WHEN** an owner is placed in a single-node heartbeat rule
- **THEN** the signed proposal is refused

#### Scenario: Three-node minority
- **WHEN** an activation rule gives one node sole authority
- **THEN** membership refuses that rule

### Requirement: KMS-MEM-004 Limits acknowledgement

A single-node genesis SHALL bind the digest of the versioned limits shown to the operator and require the typed acknowledgement. Signing SHALL refuse a proposal naming another digest.

#### Scenario: Single-node proposal
- **WHEN** the operator acknowledges the exact displayed limits
- **THEN** the proposal records the digest

#### Scenario: Different limits
- **WHEN** a proposal names another valid-length digest
- **THEN** the root tool refuses to sign it

### Requirement: KMS-MEM-005 Durable terminal identities

Membership SHALL reserve the identity of an enrolled node after retirement or stolen revocation, including its device, communications and HSM bindings. A terminal entry MUST NOT be deleted, rewritten or revived.

#### Scenario: Attempted resurrection
- **WHEN** the root tries to restore service to a stolen identity
- **THEN** the chain refuses the transition

#### Scenario: Preserved tombstone
- **WHEN** a properly signed successor retains the terminal entry
- **THEN** the identity stays reserved
