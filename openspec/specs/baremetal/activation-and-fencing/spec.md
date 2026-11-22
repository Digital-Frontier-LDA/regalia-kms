# baremetal/activation-and-fencing Specification

## Purpose

Authorize activation under the verified topology and require measured evidence before treating an excluded host as fenced or resuming after loss of a grant record.

## Requirements

### Requirement: KMS-ACT-001 Apply the signed topology's normal activation rule

Activation SHALL count distinct eligible node signatures against the signed topology rule. Three-node activation SHALL require two eligible node signatures; single-node activation SHALL use only the sole eligible node and retain its TPM-backed grant history.

#### Scenario: Minority tries to activate
- **WHEN** one node signs a three-node activation
- **THEN** activation is refused even if that signature verifies.

### Requirement: KMS-ACT-002 Restrict owner-backed multi-node activation

Owner participation SHALL count only on the recovery path, with at least one eligible node signer and every other node party excluded by the current signed manifest.

#### Scenario: Another party still counts
- **WHEN** the owner and survivor sign while another node remains eligible
- **THEN** recovery activation is refused.

### Requirement: KMS-ACT-003 Verify a fenced host remains powered off

The fencing tool SHALL match the approved hardware identity and verify two separated Off readbacks before supplying fence evidence. A host that comes back on between readbacks SHALL NOT count as fenced.

#### Scenario: Host turns back on
- **WHEN** the second readback reports On
- **THEN** the tool refuses to produce fence evidence for that host.

### Requirement: KMS-ACT-004 Recover the single-node activation floor safely

If the activation counter is nonzero and the record is missing or behind it, single-node activation SHALL remain refused until an authorized procedure re-establishes a defensible floor. The counter SHALL NOT be reset to bypass this refusal.

#### Scenario: Grant history is lost
- **WHEN** disk records cannot explain the nonzero counter
- **THEN** the node signs no activation and recovery remains gated.
