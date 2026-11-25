## Purpose

Bring up the boot network and open the encrypted root through an authorized per-boot exchange while preserving the independent console recovery path.

## ADDED Requirements

### Requirement: KMS-UNLOCK-001 Require both halves of one disk path

Peer-assisted boot SHALL require the target's TPM-sealed local contribution and the authorized peer contribution for the same path. In the multi-node profile, failure of one eligible path SHALL permit trying another eligible path.

#### Scenario: One or both peer paths are unavailable
- **WHEN** the first peer cannot answer
- **THEN** the client can use the other pinned peer, and with neither peer available the disk stays locked.

### Requirement: KMS-UNLOCK-002 Authorize and consume a boot exchange

A contribution SHALL come only from a pinned, eligible peer for the current request, path and boot session. A client SHALL consume the session on the first verified response. A peer with stale heartbeat authority SHALL refuse release.

#### Scenario: Wrong, expired or duplicate exchange
- **WHEN** a later response arrives for a consumed session, or the responder lacks live heartbeat authority
- **THEN** the exchange does not release another key.

### Requirement: KMS-UNLOCK-003 Keep console recovery independent

The boot client SHALL use the cryptsetup password agent interface without taking over the console. If the authorized exchange cannot complete, automatic key delivery SHALL fail while the independent recovery prompt remains available.

#### Scenario: Automatic unlock cannot finish
- **WHEN** boot cannot obtain an authorized peer contribution
- **THEN** the agent does not supply a key or replace the console recovery path.

### Requirement: KMS-UNLOCK-004 Require the topology's boot network shape

Single-node boot SHALL pin the owner WireGuard key from the verified manifest and use only the approved owner endpoint. The single-node site SHALL NOT configure a service mesh or act as a boot responder. Each topology SHALL reject the other topology's site shape.

#### Scenario: Wrong profile at boot
- **WHEN** the approved site has a boot mesh for another topology
- **THEN** boot network rendering refuses it.

### Requirement: KMS-UNLOCK-005 Distinguish an expected initrd skip from failed enrolment evidence

The initrd render condition SHALL skip only on a missing site credential with successfully checked absence of enrolment traces. It SHALL hard-fail on evidence of enrolment, an unreadable check, or invalid invocation. The condition supplies no store-creation authority.

#### Scenario: An expected pre-genesis render skip
- **WHEN** the site credential is missing and successful inspection finds no stub or ESP enrolment artifacts and no TPM membership anchor
- **THEN** the initrd render condition returns the expected skip status and publishes the volatile skip decision for consumers.

#### Scenario: TPM inventory could not establish absence
- **WHEN** the site credential is missing and the TPM membership anchor inventory cannot be read
- **THEN** the initrd render condition returns hard failure rather than an expected skip.

#### Scenario: An enrolled boot has lost the site credential
- **WHEN** the site credential is missing but the ESP, boot stub or TPM already shows enrolment evidence
- **THEN** the initrd render condition returns hard failure and reports the evidence that prevented a skip.

#### Scenario: Invalid render condition invocation
- **WHEN** the render condition receives invalid arguments
- **THEN** it returns hard failure status 255.

### Requirement: KMS-UNLOCK-006 Use only a trusted current initrd skip decision

Initrd consumers SHALL accept only the renderer's trusted volatile skip decision. A render retry SHALL discard a prior decision before inspecting current inputs.

#### Scenario: An enrolled retry replaces a stale skip decision
- **WHEN** a previous render check skipped and then the site credential becomes available before retry
- **THEN** the render check removes the previous decision and permits the initrd consumer to proceed.

#### Scenario: Both initrd consumers honor the current trusted skip
- **WHEN** the renderer records an expected skip in a trusted volatile decision
- **THEN** the boot network and unlock consumers return the expected skip status.

#### Scenario: An invalid initrd skip marker is rejected
- **WHEN** the initrd consumer sees an invalid skip marker at the expected location
- **THEN** it fails hard instead of accepting the marker as permission to skip.
