# baremetal/enrolment-and-config-publication Specification

## Purpose

Accept only a signed enrolment that matches the target host and publish checked configuration without overwriting unrelated or untrusted local files.

## Requirements

### Requirement: KMS-ENROL-001 Check host identity and the attended root pin

Enrolment SHALL verify the accepted manifest chain against the attended root fingerprint and check the enrolled host's identities and committed measurements before publication.

#### Scenario: Wrong root or host details
- **WHEN** the typed root fingerprint, signed host identity or measurement does not match
- **THEN** the check refuses and writes no enrolment configuration.

#### Scenario: Single-node genesis matches this host
- **WHEN** the attended root fingerprint, first single-node manifest, local identities and measurements agree
- **THEN** the manifest check accepts that genesis.

### Requirement: KMS-ENROL-002 Publish checked files without clobbering

Enrolment SHALL place the checked per-host configuration in persistent configuration storage and permit identical resumed output. It SHALL refuse different existing content, unexpected links and a conflicting file appearing during publication.

#### Scenario: A conflicting file exists
- **WHEN** publication finds different content at the intended name
- **THEN** enrolment fails and retains the file that was already present.

#### Scenario: Checked configurations go to persistent storage
- **WHEN** valid inputs reach the configuration publication step
- **THEN** it writes the checked node, site and time files to persistent configuration storage without writing under transient /etc.

#### Scenario: Identical configuration on retry
- **WHEN** the publication step retries against identical checked node configuration
- **THEN** the existing node file retains its content and modification time.

#### Scenario: A configuration name is a symbolic link
- **WHEN** a persistent enrolment configuration target is a symbolic link
- **THEN** publication refuses and does not create the link's destination.

#### Scenario: Another writer claims the destination
- **WHEN** different content takes the target name before enrolment publishes its file
- **THEN** publication refuses and preserves the competing file.

### Requirement: KMS-ENROL-003 Initialize heartbeat from verified history

A node joining outside the explicit epoch-one bootstrap SHALL adopt validated live heartbeat state and refuse when no suitable source answers. The bootstrap SHALL allow a fresh counter at zero only when no source has a heartbeat and epoch is one.

#### Scenario: Later enrolment has no live heartbeat
- **WHEN** there is no acceptable source and genesis bootstrap does not apply
- **THEN** enrolment refuses without inventing a counter floor.

#### Scenario: Legacy enrolment adopts the verified sequence
- **WHEN** legacy enrolment has an undefined heartbeat counter and receives a live heartbeat for the accepted manifest
- **THEN** it adopts the highest eligible heartbeat and the counter immediately reads that sequence.

#### Scenario: Explicit epoch-one heartbeat bootstrap
- **WHEN** the operator explicitly requests heartbeat bootstrap at epoch one, no peer supplies a heartbeat and the counter pair is absent
- **THEN** enrolment starts the heartbeat counter at zero.

#### Scenario: Bootstrap flag cannot initialize a later epoch
- **WHEN** a later manifest has no suitable heartbeat and the operator requests heartbeat bootstrap
- **THEN** enrolment refuses zero initialization.

#### Scenario: Root initializes a quorum counter from a verified heartbeat
- **WHEN** the quorum enrolment step receives valid, live heartbeat evidence through its fetch helper
- **THEN** the root-owned step initializes the counter one below the highest verified sequence, with a minimum of zero.

#### Scenario: A forged heartbeat cannot initialize the counter
- **WHEN** ordinary quorum enrolment receives only a heartbeat signed by an unrecognized key
- **THEN** it refuses to define the heartbeat counter.

#### Scenario: An expired heartbeat cannot initialize the counter
- **WHEN** ordinary quorum enrolment receives only a correctly signed but expired heartbeat
- **THEN** it refuses to define the counter and reports expired evidence.

#### Scenario: Quorum schema enrolment fetches as sync and verifies in the parent

- **WHEN** an attended root commit for a v4 or v5 manifest reaches its unfinished first-heartbeat step
- **THEN** the regalia-sync child only fetches heartbeat envelopes. The root parent verifies their signatures and authenticated liveness before defining a new counter; a validated existing pair or explicit epoch-one bootstrap follows the existing resume or bootstrap rules

#### Scenario: Legacy lab enrolment adopts heartbeat state in the sync child

- **WHEN** an attended commit for a legacy v1 through v3 manifest reaches its unfinished first-heartbeat step
- **THEN** it dispatches legacy adoption to the regalia-sync child, which verifies and adopts the eligible first heartbeat under the legacy rules, keeping the existing resume and bootstrap guards

### Requirement: KMS-ENROL-004 Refuse unsafe TPM counter resume

Enrolment SHALL refuse a half-defined heartbeat counter and SHALL refuse an existing floor outside the permitted jump from checked live history. Resume SHALL retain a checked complete pair.

#### Scenario: Interrupted counter setup
- **WHEN** one of the required indices exists by itself
- **THEN** enrolment refuses and requires the counter recovery procedure.

#### Scenario: Legacy bootstrap resumes with a complete zero counter
- **WHEN** legacy enrolment retries the explicit epoch-one bootstrap with its complete zero-valued counter and no heartbeat yet
- **THEN** it keeps the existing counter pair.

#### Scenario: Legacy counter is too far behind
- **WHEN** legacy enrolment has a complete counter pair and no heartbeat held, and the verified network sequence is beyond the allowed jump
- **THEN** it refuses to resume and identifies the recount path.

#### Scenario: Counter definition lacks required owner authorization
- **WHEN** a new quorum heartbeat counter must be defined and the TPM has a set owner authorization that was not supplied
- **THEN** counter definition is refused.

#### Scenario: An existing pair has incompatible counter attributes
- **WHEN** both expected index names exist and their definitions are incompatible with the approved counter
- **THEN** enrolment refuses to adopt them.

### Requirement: KMS-ENROL-005 Stop anchor definition when sync is active

Before defining the production trust anchors, enrolment SHALL refuse that step if the sync service's account has a running process.

#### Scenario: Sync already runs at anchor definition
- **WHEN** production enrolment reaches the trust-anchor precheck while a process is running as the sync account
- **THEN** the step refuses before defining the trust anchors.

### Requirement: KMS-ENROL-006 Resume an interrupted sealed credential publication

Enrolment SHALL resume an interrupted seal before ESP publication without exposing a partially written credential at its final name.

#### Scenario: A crash interrupts seal before publication
- **WHEN** the seal is interrupted before the completed credential is published to its ESP name
- **THEN** the final credential remains absent until a resumed seal publishes the complete file and removes its temporary file.
