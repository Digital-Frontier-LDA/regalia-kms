# baremetal/update-and-site-advance Specification

## Purpose

Advance approved measurements and site configuration without retiring the last acceptable boot or accepting unrelated image changes during a site move.

## Requirements

### Requirement: KMS-UPDATE-001 Approve an overlapping rollout before retirement

An ordinary measurement rollout SHALL add NEXT while CURRENT remains accepted before retiring CURRENT. A direct replacement without overlap SHALL be refused unless explicitly authorized as an emergency.

#### Scenario: Unapproved no-overlap rollout
- **WHEN** an operator proposes replacing the sole accepted set in an ordinary update
- **THEN** the change is refused because it would lock nodes out.

### Requirement: KMS-UPDATE-002 Require evidence of the booted target before retirement

For a phase-qualified multi-node rollout, retirement SHALL require peer evidence of the target image in its system phase. A sighting only in initrd SHALL NOT support retirement.

#### Scenario: A node reaches NEXT initrd only
- **WHEN** a peer has not seen that node complete boot
- **THEN** CURRENT remains required and retirement is refused.

### Requirement: KMS-UPDATE-003 Require a signed compatible site measurement

A site advance SHALL accept the proposed PCR 12 only in a root-approved measurement set for the booted image, without combining that PCR value with unrelated image or firmware measurements.

#### Scenario: Image change is still in flight
- **WHEN** the PCR 12 matches a staged image rather than the current image
- **THEN** the site advance is refused.

### Requirement: KMS-UPDATE-004 Require an explicit single-node planned outage

Single-node update and site advance SHALL acknowledge the unavoidable service outage and require owner-side evidence of the new boot before retiring the former acceptable measurement.

#### Scenario: Single node is scheduled to reboot
- **WHEN** the operator has no live peer to provide restart or retirement evidence
- **THEN** the single-node path requires planned-outage acknowledgement and attended verification.
