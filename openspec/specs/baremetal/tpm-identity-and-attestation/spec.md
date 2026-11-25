# baremetal/tpm-identity-and-attestation Specification

## Purpose

Establish hardware-bound node identities and verify fresh, session-bound evidence without allowing replay or accepting an unrecorded attestation key.

## Requirements

### Requirement: KMS-TPM-001 Bind the AK to the recorded TPM

Attestation enrolment SHALL challenge the recorded EK and the manifest-named AK, accept only the matching unexpired activation response, and consume the challenge on the first attempt.

#### Scenario: Wrong key or challenge
- **WHEN** a node presents another AK or an invalid response
- **THEN** the identity is refused without enrolling the offered AK.

### Requirement: KMS-TPM-002 Bind every quote to a single-use transcript

A verifier SHALL consume its node-specific nonce and check the signed quote against the recorded TPM, requested manifest epoch, boot session and ephemeral key. It SHALL refuse a reused, unissued, expired or substituted transcript.

#### Scenario: Replayed quote
- **WHEN** the nonce has already been presented
- **THEN** the quote is refused even if the signature is otherwise valid.

### Requirement: KMS-TPM-003 Keep verified session history

A verifier SHALL reject backwards TPM restart or reset counts and reject reuse of a prior boot's session or ephemeral key. A quote that fails another check SHALL leave accepted boot history intact.

#### Scenario: Earlier boot session
- **WHEN** a node offers a previously accepted session after a reboot
- **THEN** the verifier refuses it and accepts a fresh session only when the remaining checks pass.

### Requirement: KMS-TPM-004 Qualify physical TPM and its custody

Production qualification SHALL establish the approved physical TPM identity, firmware and measurements on the target host before acceptance.

#### Scenario: Software-only evidence
- **WHEN** only fixtures or software TPM runs exist
- **THEN** physical TPM qualification remains open.

### Requirement: KMS-TPM-005 Verify vendor endorsement chains at intake

The intake verifier SHALL establish a complete EK certificate chain to its pinned vendor root and match the presented EK public area to the certificate. A partial, foreign or mismatched chain SHALL NOT count as verified.

#### Scenario: The intermediate certificate is accepted as a trust anchor
- **WHEN** the chain does not terminate at the pinned vendor root
- **THEN** intake rejects the certificate.
