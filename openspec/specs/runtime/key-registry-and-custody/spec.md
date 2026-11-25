# runtime/key-registry-and-custody Specification

## Purpose

Define how a custody manifest authorizes key use, establishes readiness, and governs binding changes.

## Requirements

### Requirement: KMS-REG-001 Unambiguous manifest and custody

The KMS SHALL refuse duplicate key identifiers, ambiguous local assignments, unsupported backends and incompatible capabilities. Production objects SHALL have at least two bindings on distinct devices unless a single-device custody exception is declared.

#### Scenario: Declared exception

- **WHEN** a production object has one binding and explicitly declares exception custody
- **THEN** that object passes the redundancy check

#### Scenario: Ambiguity or false redundancy

- **WHEN** a manifest duplicates a key identifier, declares multiple active local bindings or uses the same device twice for an object
- **THEN** loading is refused

### Requirement: KMS-REG-002 Local assignment and readiness

A routine key operation SHALL use only the configured site's assigned active binding for the requested object, purpose and operation. The KMS SHALL refuse an unavailable assigned binding and track its health in readiness without falling back to a healthy binding at another site.

#### Scenario: Local binding selected

- **WHEN** both sites have healthy active bindings and an operation matches the local object policy
- **THEN** the operation routes to the configured site's binding

#### Scenario: Assigned device unavailable

- **WHEN** the local binding is unhealthy and a remote binding is healthy
- **THEN** the operation is unavailable and only the local binding is probed

#### Scenario: Uncommissioned manifest

- **WHEN** a manifest contains only planned bindings
- **THEN** the registry reports unready

### Requirement: KMS-REG-003 FIDO continuity records

A FIDO continuity entry SHALL describe multiple enrollments on distinct sites with multi-enrollment recovery. A recorded FIDO credential SHALL receive an operation denial and SHALL impose no required runtime backend.

#### Scenario: Separate enrollment custody

- **WHEN** a complete continuity entry uses distinct sites and devices
- **THEN** the manifest loads and the entry remains a custody record

#### Scenario: Refused use

- **WHEN** a client requests a registered FIDO credential operation
- **THEN** the operation is denied without probing hardware

#### Scenario: Invalid continuity

- **WHEN** the entry uses a single site or an incompatible recovery mode
- **THEN** the manifest is refused

### Requirement: KMS-REG-004 Envelope key generations

The KMS SHALL seal new envelopes using the active local key generation and resolve existing envelopes to the eligible local generation named by the envelope. It SHALL deny an unknown or revoked generation, distinguish a revoked match, and allow a healthy eligible retired generation to open existing envelopes.

#### Scenario: Rotation preserves old envelopes

- **WHEN** an active new generation coexists with an eligible retired generation
- **THEN** new envelopes route to the active generation and old envelopes resolve to their retired slot

#### Scenario: Revocation is distinct

- **WHEN** an existing envelope names a revoked generation
- **THEN** the routing refusal identifies revocation

#### Scenario: Unknown generation

- **WHEN** the named generation is absent while another generation is active
- **THEN** routing denies the request without selecting the other slot

### Requirement: KMS-REG-005 FIDO retirement planning

The FIDO retirement planner SHALL refuse removing a credential if the projected commissioned enrollments would span fewer than two sites. It SHALL identify the surviving enrollments when the plan passes. The plan carries no authorization to retire a device.

#### Scenario: Commissioned alternatives survive

- **WHEN** a proposed retirement preserves commissioned enrollments at two distinct sites
- **THEN** the planner identifies the eligible survivors

#### Scenario: Only a planned replacement survives

- **WHEN** the projected continuity depends on an uncommissioned record
- **THEN** the planner refuses the retirement
