# baremetal/measured-boot-and-pcr-policy Specification

## Purpose

Bind the approved image and boot phase to a quoted TPM measurement and verify the immutable operating-system image under its recorded verity root.

## Requirements

### Requirement: KMS-BOOT-001 Match phase and firmware as one set

A verifier SHALL require one complete approved measurement set matching the request's boot phase, PCR selection and digest, and TPM firmware. PCR and firmware values from different approved sets SHALL NOT be combined.

#### Scenario: Wrong phase or mixed set
- **WHEN** a system-phase quote is used for an initrd request, or PCRs match a different firmware set
- **THEN** the request is refused.

### Requirement: KMS-BOOT-002 Treat unverified PCR values as diagnostic only

A verifier SHALL check reported PCR values against the quoted selection and digest before using them to explain a refusal. Diagnostics SHALL NOT substitute for an approved measurement.

#### Scenario: Altered PCR report
- **WHEN** reported values disagree with the signed quote
- **THEN** the verifier refuses the report.

### Requirement: KMS-BOOT-003 Show what a PCR survey has proved

The survey SHALL distinguish volatility, recorded changes following a named variation, and stability demonstrated by a repeat plain boot. A missing repeat control SHALL leave stability unproven.

#### Scenario: No plain reboot control
- **WHEN** measurements contain a baseline and a varied boot only
- **THEN** unchanged PCRs are labelled unproven.

### Requirement: KMS-BOOT-004 Verify the installed operating-system image

The installer SHALL verify the immutable operating-system image and hash tree against the recorded verity root before writing and SHALL verify the written partitions again. Invalid content SHALL prevent success.

#### Scenario: Image bytes disagree with the recorded verity root
- **WHEN** a supplied image matches its file checksum but not the verity root
- **THEN** the installer refuses before touching the target.

### Requirement: KMS-BOOT-005 Expose TEST slot diagnostic results

The TEST slot-B harness SHALL check the data and hash partition identifiers and verify the written pair under the recorded root. It SHALL report mismatch or corruption and release its temporary mapping on refusal.

#### Scenario: Invalid TEST slot-B partition or contents
- **WHEN** the partition identifiers differ or the verity readback fails
- **THEN** the harness reports the failed check and cleans up without repair.
