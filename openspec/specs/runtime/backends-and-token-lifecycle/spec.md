# runtime/backends-and-token-lifecycle Specification

## Purpose

Define token identity checks, credential handling, and conditions for safe return to service.

## Requirements

### Requirement: KMS-TOKEN-001 Token identity and protected channel

The Nitrokey backend SHALL verify the configured token identity and secure channel before sending its PIN or performing a private operation. A commissioned public-key mismatch SHALL quarantine the affected device. Token operations SHALL remain limited to the configured backend capability.

#### Scenario: Matching Nitrokey

- **WHEN** the configured device passes identity and protected-channel checks
- **THEN** login precedes the requested private operation

#### Scenario: Channel or key failure

- **WHEN** channel establishment fails or a configured public-key pin mismatches
- **THEN** the operation is refused before PIN presentation

### Requirement: KMS-TOKEN-002 Credential access and retry budget

The KMS SHALL read a PIN only through an admissible protected credential. It SHALL erase the PIN buffer when released. A token with an exhausted configured retry safety margin SHALL be refused before login, and a rejected presented PIN SHALL latch the affected device until reset.

#### Scenario: Protected credential

- **WHEN** an admissible regular credential is read and released
- **THEN** the returned buffer is cleared

#### Scenario: Unsafe credential

- **WHEN** a PIN entry is unconfigured, symlinked, readable by an unauthorized principal or malformed
- **THEN** no PIN bytes are returned

#### Scenario: Budget and rejection

- **WHEN** the token is near lockout or rejects the presented PIN
- **THEN** a near-lockout token sees no login and a PIN rejection prevents repeat login while latched

### Requirement: KMS-TOKEN-003 Token removal and lease reauthorization

When removable-token reauthorization is enabled, the backend SHALL require an admission lease requested after daemon start and after a token's observed return. It SHALL withhold service under older leases and SHALL check that the serial is admitted.

#### Scenario: Fresh return lease

- **WHEN** an admitted token returns and the node obtains a lease requested after the first observed return
- **THEN** the token may resume service

#### Scenario: Stale lease or delisted token

- **WHEN** the only lease was requested before or during absence, or the token is no longer listed
- **THEN** the token remains unavailable

#### Scenario: Required token observation unavailable in this build

- **WHEN** a build without PIV and PC/SC token-presence observation is configured to serve a removable YubiKey under required admission
- **THEN** startup refuses instead of serving without token observation and reauthorization

### Requirement: KMS-TOKEN-004 Physical token lifecycle acceptance

A commissioned production token and deployed middleware combination SHALL pass the applicable credential, removal, return and replacement acceptance drills under the authorized operator.

#### Scenario: Qualification handoff

- **WHEN** a production token and exact middleware build are staged
- **THEN** operator evidence establishes safe return and refusal before PIN use under the applicable failure conditions

### Requirement: KMS-TOKEN-005 Served OpenPGP applet profile

The PKCS#11 OpenPGP applet backend SHALL serve Ed25519 signing only. Startup SHALL require a token label, a commissioned public-key pin and current local USB evidence for the specific token. The separate OpenPGP driver does not serve legacy unwrap in the daemon.

#### Scenario: Admissible applet

- **WHEN** an Ed25519 sign binding supplies the exact token label, pin and current evidence for its serial
- **THEN** the binding passes the applet startup check

#### Scenario: Unservable binding

- **WHEN** the binding declares RSA, unwrap, an absent label or pin, or evidence for another token
- **THEN** startup refuses and identifies the unsupported binding
