# runtime/envelopes-and-secret-release Specification

## Purpose

Define authenticated envelope creation and release, with rotation and hardware-provenance limits.

## Requirements

### Requirement: KMS-ENV-001 Authenticated envelope creation

The KMS SHALL accept assembled AES-256-GCM content only when the supplied data key and nonce authenticate nonempty ciphertext under the canonical object context. It SHALL refuse invalid or oversized inputs before wrapping and SHALL use the selected hardware key for the data key.

#### Scenario: Valid assembled content

- **WHEN** assembled content authenticates under the canonical context
- **THEN** the KMS returns an envelope that opens to the original content

#### Scenario: Tampered content

- **WHEN** a ciphertext byte changes before sealing
- **THEN** the KMS returns an integrity failure before calling the wrapper

### Requirement: KMS-ENV-002 Authenticated secret release

The KMS SHALL derive release context from authorized object, purpose and environment and SHALL refuse caller-supplied release context. It SHALL return plaintext only after the selected hardware unwrap and envelope integrity checks succeed.

#### Scenario: Matching release

- **WHEN** the envelope belongs to the authorized object and authenticates under the derived context
- **THEN** the released bytes equal the original secret

#### Scenario: Transplant or tampering

- **WHEN** the envelope names a different object, is bound to another context, or fails ciphertext authentication
- **THEN** the KMS releases no plaintext

#### Scenario: Client context assertion

- **WHEN** the caller supplies a release context
- **THEN** release is refused

### Requirement: KMS-ENV-003 Envelope age and rotation

The KMS SHALL refuse release past a configured envelope age bound and record an expiry outcome. The envelope format SHALL support rewrapping a data key under a new generation while preserving content ciphertext and nonce. Rewrapping is library functionality at this baseline.

#### Scenario: Within the release bound

- **WHEN** an envelope's age is at or below the configured bound
- **THEN** the otherwise authorized release succeeds

#### Scenario: Aged-out release

- **WHEN** an envelope exceeds the configured bound
- **THEN** the service denies release and audits envelope expiry

#### Scenario: Key rotation

- **WHEN** an envelope is rewrapped under a distinct key generation through the envelope library
- **THEN** its content ciphertext and nonce stay unchanged, and the old generation cannot open the rewrapped data key

### Requirement: KMS-ENV-004 Hardware provenance refusal

For Nitrokey PKCS#11, sealing SHALL require a matching commissioned public-key pin or a runtime check of token key provenance. With no pin, indeterminate SC-HSM provenance SHALL cause refusal. Unwrap SHALL refuse when private-key non-exportability cannot be established.

#### Scenario: Exportable private key

- **WHEN** the token reports that the private KEK is extractable
- **THEN** release fails and the device is quarantined with the exportable-key reason

#### Scenario: Unknown key origin

- **WHEN** no commissioned key pin is configured and the SC-HSM attribute cannot establish provenance
- **THEN** the driver refuses with a provenance-indeterminate error

### Requirement: KMS-ENV-005 Commissioned KEK continuity

Production commissioning SHALL establish that an enrolled hardware KEK can seal and release data and SHALL qualify the restore path on independently provisioned supported hardware.

#### Scenario: Physical restore acceptance

- **WHEN** a commissioned key is restored to the designated replacement device
- **THEN** the operator verifies existing envelopes can be released and qualifies a supported route for new seals
