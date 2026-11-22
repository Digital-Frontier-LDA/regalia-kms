## Purpose

Maintain verified operational history on the topology's etcd members and refuse stateful requests when the watched state cannot support the current lease.

## ADDED Requirements

### Requirement: KMS-ETCD-001 Render topology-specific membership and trust

The single-node etcd configuration SHALL name one loopback member at etcd's default timings. The multi-node configuration SHALL use service-mesh peer URLs and include only eligible members. Both SHALL use certificate-authenticated peer TLS and a Unix client socket.

#### Scenario: Configuration crosses profiles
- **WHEN** a multi-node operator supplies a loopback peer URL
- **THEN** configuration validation refuses it.

#### Scenario: A single-member loopback configuration is profile-specific
- **WHEN** the renderer produces a one-member loopback configuration from a single-node manifest
- **THEN** validation accepts it under single-node and refuses that configuration under multi-node.

### Requirement: KMS-ETCD-002 Authenticate the peer certificate bundle

The configuration renderer SHALL include only certificates bound by the corresponding eligible member's current manifest signing key. A binding for another member or certificate SHALL NOT count.

#### Scenario: Certificate replacement is unbound
- **WHEN** an offered certificate is paired with another key's binding
- **THEN** it does not satisfy member trust and rendering refuses when the member lacks a valid binding.

### Requirement: KMS-ETCD-003 Serve stateful operations from current watched history

Stateful serving SHALL require a live watched store, the same cluster and state epoch as the current serving lease, and an applied revision at least as new as the lease names. A stalled watch or different boot session SHALL fail closed.

#### Scenario: The cache falls behind
- **WHEN** the store has not confirmed freshness within one lease period
- **THEN** the state gate refuses until usable state is observed.

### Requirement: KMS-ETCD-004 Use the appliance's assigned etcd service boundary

The normal appliance etcd unit SHALL require the rendered member configuration, run as the dedicated unprivileged etcd account, and load the peer key as an encrypted service credential. Its explicitly writable host locations SHALL be limited to its private state and runtime socket directories.

#### Scenario: Normal unit invokes etcd with the rendered configuration
- **WHEN** a normal appliance unit is selected to start etcd with its rendered member configuration
- **THEN** the unit invokes etcd with that configuration under the dedicated etcd identity.

#### Scenario: No rendered configuration before enrolment
- **WHEN** the rendered etcd configuration file is absent
- **THEN** the normal unit's configuration presence condition skips starting etcd.

#### Scenario: Peer credentials and writable locations are scoped to etcd
- **WHEN** normal appliance etcd is configured for launch
- **THEN** its unit declares only the encrypted peer key credential and confines explicitly writable host paths to the private state directory and runtime socket directory.
