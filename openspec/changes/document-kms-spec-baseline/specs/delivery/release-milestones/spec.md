## Purpose

Track software evidence, TEST staging acceptance and production commissioning as distinct release gates for the chosen deployment topology.

## ADDED Requirements

### Requirement: KMS-RELEASE-001 Enforce the pinned software scenario result

The one-node software gate SHALL require its real scenario to report 26 passed and zero failed, take the resource-manager TPM route, and show each outstanding owner-chain and planned-outage TODO exactly once. TODO items SHALL NOT count as passing checks.

#### Scenario: A covered scenario step is missing or a TODO is duplicated
- **WHEN** the job receives a summary or TODO inventory different from the pinned contract
- **THEN** the job fails.

### Requirement: KMS-RELEASE-002 Complete TEST staging restore and owner acceptance

The single-node v0.1 TEST milestone SHALL use a qualified TEST image, prove initial and repeat boot with the owner card, complete a timed backup restore onto a fresh replacement, record a clean 72-hour burn-in, and obtain owner staging acceptance.

#### Scenario: Boot works but restore or burn-in remains open
- **WHEN** the qualified TEST target has not completed each gate
- **THEN** the TEST milestone remains open.

### Requirement: KMS-RELEASE-003 Require the matching production qualification

A deployment SHALL pass the production gate for its topology. Single-node production SHALL have its own explicit acceptance if selected. Moving from one-node TEST to three-node production SHALL use a new genesis and pass three-node TEST and separate production qualification.

#### Scenario: Three-node production follows single-node TEST
- **WHEN** single-node staging acceptance exists
- **THEN** commissioning still requires new three-node genesis, three-node rehearsal and owner-authorized production evidence.

### Requirement: KMS-RELEASE-004 Consume late replies during the test client's completion wait

The unlock scenario harness SHALL process a valid password-agent reply received while the client waits for the volume to open. It SHALL retain the resulting key-delivery observation.

#### Scenario: A test reply arrives while the client waits for the mapper
- **WHEN** a password-agent reply arrives during the completion wait and the test client is waiting for the mapper
- **THEN** the harness processes the reply, opens the fixture path and retains the key-delivery result.

### Requirement: KMS-RELEASE-005 Measure revocation shutdown with correlated evidence

The one-node scenario SHALL use one monotonic lease deadline to observe a valid non-serving admission and then a matching request refusal. Audit confirmation MAY arrive later for an in-budget response. A successful sign observed while refusal evidence is still pending MUST invalidate that evidence.

#### Scenario: An unrelated 503 cannot prove admission shutdown
- **WHEN** the test sees a non-serving admission and an HTTP 503 without a correlated not-admitted audit for that signing request
- **THEN** the 503 does not satisfy the shutdown check.

#### Scenario: A successful sign invalidates pending refusal evidence
- **WHEN** the test receives a 503 and a subsequent signing request succeeds before the earlier refusal is confirmed
- **THEN** the test cannot use the earlier refusal as proof of shutdown.

#### Scenario: A late audit retains the original refusal time
- **WHEN** a request after verified non-serving admission is denied within the lease deadline and its matching audit arrives later, with no intervening successful sign observed
- **THEN** the harness uses the refusal's original observation time as evidence and keeps the same lease deadline.
