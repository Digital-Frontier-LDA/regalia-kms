# baremetal/replacement-and-revocation Specification

## Purpose

Exclude terminal hardware identities and allow only an authorized fresh replacement without changing unrelated node identities or policy.

## Requirements

### Requirement: KMS-REPLACE-001 Keep revoked identities terminal

A retired or stolen node SHALL remain in later manifests with its original identities and SHALL lose authorization to request, serve or authorize. A replacement SHALL receive new hardware, signing and network identities wherever the applicable manifest schema records them.

#### Scenario: Retired identity is reused
- **WHEN** a later enrolment claims the old hardware identity or tries to revive the tombstone
- **THEN** the manifest transition is refused.

### Requirement: KMS-REPLACE-002 Require the exact attended replacement

A replacement enrolment SHALL use the verified chain and require the old node identifier to be typed exactly. The transition SHALL retain the old tombstone, enrol the fresh node, and refuse unrelated changes outside its authorized measurement and signer updates.

#### Scenario: An operator names the wrong old node
- **WHEN** a replacement chain is submitted with an unrelated retired identifier
- **THEN** enrolment refuses before publication.

#### Scenario: A supported multi-node replacement names the exact prior node
- **WHEN** a valid multi-node replacement chain names a fresh host and retires the exact old identifier supplied by the operator
- **THEN** the manifest check accepts the replacement epoch.

#### Scenario: A retirement accompanies enrolment without replacement intent
- **WHEN** the accepted chain first names the new host in an epoch that retires an existing node, and the operator supplies no old identifier
- **THEN** the manifest check refuses it as a replacement that must be acknowledged.

#### Scenario: A replacement also changes another node
- **WHEN** the candidate replacement changes another retained node's identity in the same step
- **THEN** the manifest check refuses the replacement.

### Requirement: KMS-REPLACE-003 Restore the sole profile after owner theft revocation

After a verified owner theft revocation removes the sole active node, recovery SHALL require root-authorized enrolment of a fresh replacement under the unchanged single-node genesis. The revoked node SHALL remain terminal and the new node SHALL establish a verified first heartbeat before normal serving.

#### Scenario: Post-revocation replacement submitted
- **WHEN** no existing live node can provide the first heartbeat
- **THEN** the replacement requires the dedicated verified transition; it cannot use an unrelated genesis bypass.
