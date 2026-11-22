## Purpose

Define the checks linking startup configuration, runtime admission, certificate issuance and state readiness.

## ADDED Requirements

### Requirement: KMS-RUNTIME-001 Coherent preflight and startup configuration

Daemon startup preflight SHALL verify that manifest-declared policy IDs are enforced by the loaded policy and that RBAC grants refer to actual manifest operations. A key without a caller grant SHALL be permitted as configured state.

#### Scenario: Coherent configuration

- **WHEN** all manifest declarations match the applied policy and grants reference real operations
- **THEN** preflight permits startup even if a key has no grant

#### Scenario: Invalid configuration

- **WHEN** a policy declaration disagrees or a grant names a nonexistent key or operation
- **THEN** preflight refuses before serving

#### Scenario: Preflight while the writer holds the journal

- **WHEN** a running service holds the policy journal writer lock and preflight inspects the journal
- **THEN** preflight can verify that journal without taking a second writer lock

#### Scenario: Preflight leaves missing policy history absent

- **WHEN** the policy journal is missing during otherwise valid preflight
- **THEN** preflight reports the absent journal and leaves the path absent

#### Scenario: A daemon with no token backend withholds operations

- **WHEN** the daemon is running with otherwise valid configuration and neither a PKCS#11 module nor any YubiKey device configured, and an authenticated request passes its operation route's request validation
- **THEN** the daemon returns HTTP 503 with `DEPENDENCY_UNAVAILABLE` and `retryable: true`, and returns no operation result

#### Scenario: The common KMS unit uses the fixed configuration and operator provisioned credentials

- **WHEN** a flat host starts the common KMS unit without appliance-specific drop-ins
- **THEN** it runs as regalia-kms with /etc/regalia-kms/config.json and supplies no encrypted PIN credential mapping by itself. Any token PIN files required by that configuration are provisioned separately

### Requirement: KMS-RUNTIME-002 Runtime admission gates

When configured to require admission, the daemon SHALL report unready and withhold operations without valid admission. It SHALL recheck admission at execution and before returning output, and SHALL record an admission loss as such.

#### Scenario: Ready under a current single-node self-lease

- **WHEN** an authenticated readiness probe reaches a daemon under a current valid self-issued single-node admission and all other required probes pass
- **THEN** the readiness endpoint returns HTTP 200

#### Scenario: Admission active

- **WHEN** a valid admission remains in force through an authorized operation
- **THEN** the request can complete and return output

#### Scenario: Signing is refused after observed non-serving admission

- **WHEN** the owner revokes the sole node and the scenario observes its trusted non-serving admission in the new epoch
- **THEN** a subsequent signing request is refused with HTTP 503 within the original lease lifetime measured from the revocation attempt, and the daemon's local audit records deny/not-admitted for that request

#### Scenario: Admission absent or expires

- **WHEN** admission is absent at entry or expires while waiting or executing
- **THEN** the request receives no output and the refusal is attributed to admission

#### Scenario: Admission rejects untrusted file ownership or ancestry

- **WHEN** an otherwise valid admission file is owned by the wrong UID or beneath a non-sticky ancestor writable by other users
- **THEN** the daemon admission reader declines the file

#### Scenario: Admission belongs only to the current boot and session

- **WHEN** an admission file names another boot or does not match the current trusted boot-session record
- **THEN** the admission reader reports no admission

#### Scenario: Admission follows the current chain tip

- **WHEN** a verified chain tip differs from the admission document's epoch or manifest digest
- **THEN** the gate withholds admission for the mismatch and can admit a valid document matching the tip

### Requirement: KMS-RUNTIME-003 Optional active-passive fencing

An active-passive deployment with fencing enabled SHALL serve only under a valid signed lease for the configured site and registry and at or above the recorded epoch. It SHALL refuse expired, substituted or rolled-back leases.

#### Scenario: Valid fencing lease

- **WHEN** the active site has a current lease matching the manifest and the recorded epoch floor
- **THEN** fencing permits operations

#### Scenario: Unacceptable lease

- **WHEN** the lease is expired, signed by the wrong key, or names another site, registry or older epoch
- **THEN** fencing withholds service

### Requirement: KMS-RUNTIME-004 Constrained certificate issuance

When certificate issuance is configured, the KMS SHALL verify the CSR, constrain names and validity to the issuer profile, and issue a leaf through the matching routed hardware key. It SHALL refuse a mismatched key or out-of-profile request without returning a certificate.

#### Scenario: Compliant CSR

- **WHEN** a valid CSR is within the delegated profile and the issuer key matches
- **THEN** the returned certificate verifies against the configured issuer

#### Scenario: Incorrect issuer or name

- **WHEN** the token key differs from the issuer or a requested name is outside the allowed namespace
- **THEN** the daemon returns no certificate

### Requirement: KMS-RUNTIME-005 Operational state publication

When the operational-state reader is configured, the daemon SHALL watch the configured local store, publish its session public key, and publish the applied revision after confirmation.

#### Scenario: Configured watcher

- **WHEN** the local store commits a revision and the daemon applies updates
- **THEN** its published position reaches that revision and names the observed cluster

#### Scenario: Watcher absent from configuration

- **WHEN** the operational-state endpoint is omitted
- **THEN** no session key or applied revision is published by the watcher

#### Scenario: Partial watcher settings refuse configuration

- **WHEN** only one or two of the local store endpoint, publication directory and session key directory are configured
- **THEN** daemon configuration validation refuses the incomplete set

#### Scenario: Configured watcher requires admission

- **WHEN** the endpoint and both directories are configured but runtime admission is not required
- **THEN** daemon configuration validation refuses the combination

#### Scenario: Watcher rejects a lower store revision

- **WHEN** an operational-state relist returns a revision below the cache's last verified revision
- **THEN** the watcher rejects that relist and does not adopt the lower revision

#### Scenario: Watcher rejects a different store cluster

- **WHEN** an operational-state relist identifies a different cluster from the one already observed
- **THEN** the watcher rejects the new cluster's data

#### Scenario: Watcher relists before recovering liveness

- **WHEN** the operational-state watch stream fails and the watcher retries
- **THEN** the cache loses liveness and does not mark itself live again until a fresh list succeeds

### Requirement: KMS-RUNTIME-006 Operational state makes serving contingent

A production service using accepted operational state SHALL withhold stateful operations until the relevant verified revision, lease and stateful reservations are enforced at the operation boundary.

#### Scenario: State absent or unusable

- **WHEN** startup cannot establish the required operational history, or a stateful reservation cannot be confirmed
- **THEN** the service withholds the affected operation

### Requirement: KMS-RUNTIME-007 Bounded HTTP shutdown

On a daemon shutdown request, the HTTP service SHALL allow in-flight responses a bounded grace period. If it exhausts that period, it SHALL close the remaining connections and report the shutdown error.

#### Scenario: A response outlives the shutdown grace period

- **WHEN** the daemon receives a shutdown request while a response is still in flight and its configured grace period expires
- **THEN** the remaining connection is closed and the HTTP service reports a shutdown deadline error
