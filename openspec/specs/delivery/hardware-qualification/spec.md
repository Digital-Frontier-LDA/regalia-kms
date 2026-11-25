# delivery/hardware-qualification Specification

## Purpose

Qualify each intended physical deployment with target-specific commissioning, boot, custody and recovery evidence, with software checks tracked separately.

## Requirements

### Requirement: KMS-HW-001 Refuse incomplete or contradictory commissioning evidence

The commissioning probe SHALL require all measured controls to pass and, when evidence mode is selected, verify a fresh complete signature-pinned record that agrees with measured behavior. Evidence SHALL NOT substitute for a failed measured control.

#### Scenario: A signed record disagrees with the host
- **WHEN** one measured control fails or a pinned identity disagrees
- **THEN** the probe exits unsuccessfully and identifies the discrepancy.

### Requirement: KMS-HW-002 Qualify the scheduled boot and its physical custody

Commissioning SHALL gather target evidence of actual Secure Boot, TPM-bound unlock and required hardware-backed credential use after boot. The probe's scheduled-image certificate observation SHALL NOT substitute for firmware enforcement or physical restart evidence.

#### Scenario: The probe has selected an image
- **WHEN** the image names the pinned certificate but no actual restart evidence exists
- **THEN** hardware boot acceptance remains open.

### Requirement: KMS-HW-003 Test disks and failure domains before production

Three-node production qualification SHALL observe the intended sites and network failure domains, measure WAL sync behavior on the target storage, and validate recovery, fencing and rejoin on the qualified physical stack.

#### Scenario: Co-located TEST machines pass
- **WHEN** simulated site and software evidence is available without the production environment
- **THEN** qualification for physically independent production sites remains open.
