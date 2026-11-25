## Purpose

Expose each topology's trust and failure limits to the operator and refuse recovery paths that assume independent parties where none exists.

## ADDED Requirements

### Requirement: KMS-SEC-001 Bind the canonical limitations to single-node genesis

Single-node genesis SHALL show the canonical versioned limitations verbatim and require its exact attended acknowledgement. The signed genesis SHALL commit to those bytes and refuse another digest.

#### Scenario: Limits text differs
- **WHEN** the operator presents edited text, an incorrect phrase, or an unsigned replacement digest
- **THEN** the ceremony refuses without publishing an acknowledged genesis.

### Requirement: KMS-SEC-002 Reject survivor authority on the single-node profile

A single-node deployment SHALL refuse survivor authorization and multi-node fencing, take-over, and rejoin operations. The absence of other parties SHALL NOT satisfy their trust predicates.

#### Scenario: Single-node survivor is requested
- **WHEN** an authorization is submitted under single-node membership
- **THEN** the profile is named in the refusal and no recovery serving is authorized.

### Requirement: KMS-SEC-003 Require independent single-node audit evidence

Single-node stateful operation SHALL require the external collector and distinguish collector-detected re-spend after a restore from prevention. Collector-relative monitoring SHALL expose discrepancies that otherwise require an independent node.

#### Scenario: The sole node has no configured collector
- **WHEN** a stateful request would depend on unverifiable local-only history
- **THEN** the accepted contract requires refusal and treats collector-relative validation as open until proved.

### Requirement: KMS-SEC-004 Disclose failure-domain and running-node limits

Operators SHALL be told that single-node has no node or site redundancy, requires attended reboot, and cannot use independent peers to stop a root-compromised or disconnected running node. Three-node availability claims SHALL depend on the qualified independent failure domains.

#### Scenario: A single node is lost or unreachable
- **WHEN** the node is the sole serving and self-issuing party
- **THEN** operators are told to expect an outage after host loss and that an unreachable hot-stolen node may still serve.
