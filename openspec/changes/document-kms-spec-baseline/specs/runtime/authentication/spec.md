## Purpose

Defines how the daemon authenticates client certificate identities and separates workload traffic from health probes.

## ADDED Requirements

### Requirement: KMS-AUTH-001 Verified client identity

Protected requests SHALL derive their principal from a verified, time-valid client certificate with the required usage and exactly one canonical URI SAN in the configured trust namespace. The certificate subject and caller-provided headers do not supply the principal.

#### Scenario: One verified workload

- **WHEN** the verified leaf carries one valid workload URI
- **THEN** that URI is the request principal

#### Scenario: Unverified or malformed identity

- **WHEN** a client has an unverified chain, expired certificate, ambiguous URI or noncanonical identity
- **THEN** authentication fails without a principal

### Requirement: KMS-AUTH-002 Protected routes and TLS

The configured TLS listener SHALL use at least TLS 1.3 and verify any presented client certificate. Protected routes require authenticated principals, while liveness and readiness probes can omit a client certificate.

#### Scenario: Unauthenticated probe

- **WHEN** a caller reaches a health route without a certificate
- **THEN** the HTTP probe is allowed to run

#### Scenario: Unauthenticated operation

- **WHEN** a caller reaches a protected operation without a verified client principal
- **THEN** the request is refused without disclosing the peer address

### Requirement: KMS-AUTH-003 Live certificate revocation

With a revocation list configured, each authentication SHALL check the leaf's serial against the current list and refuse when the list does not safely load or the serial is revoked.

#### Scenario: Newly revoked certificate

- **WHEN** an operator adds the leaf serial to the configured list
- **THEN** the next authentication refuses that leaf

#### Scenario: Unreadable list

- **WHEN** the configured revocation file disappears, cannot be read or cannot be parsed
- **THEN** authentication fails closed
