## Purpose

Keep offline root, owner and hardware credential custody distinct from normal serving authority, with narrowly scoped boot-time access for each host.

## ADDED Requirements

### Requirement: KMS-CUSTODY-001 Use the authorized TPM owner record

An owner-authorized operation SHALL check the supplied authorization against the root-pinned node record. A stale record or another node's value SHALL be refused before a TPM operation that depends on it.

#### Scenario: An old or foreign authorization is supplied
- **WHEN** the value or record does not match the enrolled node
- **THEN** the operation refuses without proceeding to the authorized TPM action.

### Requirement: KMS-CUSTODY-002 Deliver TPM authorization without an argument value

An authorized TPM tool invocation SHALL pass the owner value through a sealed ephemeral descriptor and close it after use. The authorization value SHALL NOT appear on the command line.

#### Scenario: TPM tool uses a supplied owner authorization
- **WHEN** the operation invokes an approved TPM tool
- **THEN** only the descriptor reference is passed and the descriptor is closed afterward.

### Requirement: KMS-CUSTODY-003 Generate only the host's sealed credential names

The measured boot generator SHALL emit only credential-loading directives for regular files with recognized per-host PIN names. It SHALL skip links, directories and malformed names and SHALL NOT import other service settings from writable storage.

#### Scenario: An unexpected file appears in credential storage
- **WHEN** the name is invalid or the file is a link
- **THEN** the generator ignores it while still naming valid sealed credentials.

### Requirement: KMS-CUSTODY-004 Qualify the physical custody and commissioning ceremony

Production release SHALL require an accepted offline ceremony, preserved independent recovery authority, and qualified physical custody for the intended targets. TEST credentials and software fixtures SHALL NOT stand in for production authority.

#### Scenario: Fixture proofs are available
- **WHEN** production ceremony evidence and physical credential acceptance are missing
- **THEN** the commissioning gate remains open.
