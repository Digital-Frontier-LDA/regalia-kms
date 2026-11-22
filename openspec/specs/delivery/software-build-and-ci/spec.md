# delivery/software-build-and-ci Specification

## Purpose

Define how software verification gates distinguish completed scenarios from planned or physical evidence.

## Requirements

### Requirement: KMS-CI-001 CI aggregate completeness

The repository CI aggregate SHALL evaluate every other job in its workflow and SHALL refuse missing, skipped, cancelled or failed job outcomes. It SHALL withhold a passing gate for draft pull requests.

#### Scenario: Complete run

- **WHEN** every expected CI job succeeds on a non-draft change
- **THEN** the CI aggregate succeeds

#### Scenario: Incomplete run

- **WHEN** an expected job does not succeed or the change is a draft
- **THEN** the CI aggregate fails

#### Scenario: Workflow drift

- **WHEN** a workflow job is added without a gate dependency
- **THEN** the workflow-structure regression check reports the omission

#### Scenario: ci declares job build-test

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `build-test` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  build-test:
    runs-on: ubuntu-26.04
    timeout-minutes: 20
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `build-test` in `needs`.

#### Scenario: ci declares job e2e-swtpm

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `e2e-swtpm` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  e2e-swtpm:
    runs-on: ubuntu-26.04
    timeout-minutes: 75
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `e2e-swtpm` in `needs`.

#### Scenario: ci declares job e2e-netns-disk

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `e2e-netns-disk` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  e2e-netns-disk:
    runs-on: ubuntu-26.04
    timeout-minutes: 75
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `e2e-netns-disk` in `needs`.

#### Scenario: ci declares job e2e-sandbox-policy

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `e2e-sandbox-policy` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  e2e-sandbox-policy:
    runs-on: ubuntu-26.04
    timeout-minutes: 45
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `e2e-sandbox-policy` in `needs`.

#### Scenario: ci declares job known-polkit-rules-debian13

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `known-polkit-rules-debian13` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  known-polkit-rules-debian13:
    runs-on: ubuntu-26.04
    timeout-minutes: 10
    container:
      image: debian:13.6@sha256:f324c7ff54321e8d9c588493a20244965938ce0aa50bbd1022d38010e9ffc4b1
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `known-polkit-rules-debian13` in `needs`.

#### Scenario: ci declares job govulncheck

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `govulncheck` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  govulncheck:
    runs-on: ubuntu-26.04
    timeout-minutes: 15
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `govulncheck` in `needs`.

#### Scenario: ci declares job pkcs11-e2e

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `pkcs11-e2e` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  pkcs11-e2e:
    runs-on: ubuntu-26.04
    timeout-minutes: 20
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `pkcs11-e2e` in `needs`.

#### Scenario: ci declares job privileged-and-fuzz

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `privileged-and-fuzz` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  privileged-and-fuzz:
    runs-on: ubuntu-26.04
    timeout-minutes: 15
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `privileged-and-fuzz` in `needs`.

#### Scenario: ci declares job cosmos-node

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `cosmos-node` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  cosmos-node:
    runs-on: ubuntu-26.04
    timeout-minutes: 45
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `cosmos-node` in `needs`.

#### Scenario: ci declares job unlock-boot-qemu

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `unlock-boot-qemu` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  unlock-boot-qemu:
    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}
    runs-on: ubuntu-24.04
    timeout-minutes: 60
  ```

  This job declares none of these fields: `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `unlock-boot-qemu` in `needs`.

#### Scenario: ci declares job verity-boot-qemu

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `verity-boot-qemu` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  verity-boot-qemu:
    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}
    runs-on: ubuntu-24.04
    timeout-minutes: 120
  ```

  This job declares none of these fields: `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `verity-boot-qemu` in `needs`.

#### Scenario: ci declares job initrd-reproducible

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `initrd-reproducible` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  initrd-reproducible:
    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}
    runs-on: ubuntu-26.04
    timeout-minutes: 60
    strategy:
      fail-fast: false
      matrix:
        builder: [first, second]
  ```

  This job declares none of these fields: `needs`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `initrd-reproducible` in `needs`.

#### Scenario: ci declares job rootfs-reproducible

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `rootfs-reproducible` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  rootfs-reproducible:
    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}
    runs-on: ubuntu-26.04
    timeout-minutes: 75
  ```

  This job declares none of these fields: `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `rootfs-reproducible` in `needs`.

#### Scenario: ci declares job initrd-reproducible-debian

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `initrd-reproducible-debian` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  initrd-reproducible-debian:
    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}
    runs-on: ubuntu-26.04
    timeout-minutes: 60
    container:
      image: debian:trixie
      options: --privileged
  ```

  This job declares none of these fields: `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `initrd-reproducible-debian` in `needs`.

#### Scenario: ci declares job initrd-reproducible-compare

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `initrd-reproducible-compare` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  initrd-reproducible-compare:
    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}
    needs: [initrd-reproducible, initrd-reproducible-debian]
    runs-on: ubuntu-26.04
    timeout-minutes: 10
  ```

  This job declares none of these fields: `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `initrd-reproducible-compare` in `needs`.

#### Scenario: ci declares job peer-unlock-swtpm

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `peer-unlock-swtpm` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  peer-unlock-swtpm:
    if: ${{ github.event_name != 'pull_request' || !github.event.pull_request.draft }}
    runs-on: ubuntu-26.04
    timeout-minutes: 15
  ```

  This job declares none of these fields: `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `peer-unlock-swtpm` in `needs`.

#### Scenario: ci declares job pcrlock-luks-swtpm

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `pcrlock-luks-swtpm` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  pcrlock-luks-swtpm:
    runs-on: ubuntu-26.04
    timeout-minutes: 10
    container:
      image: debian:13
      options: --privileged -v /dev:/dev
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `pcrlock-luks-swtpm` in `needs`.

#### Scenario: ci declares job uki-build

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `uki-build` is inspected in `.github/workflows/ci.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  uki-build:
    runs-on: ubuntu-26.04
    timeout-minutes: 15
    container:
      image: debian:13
      options: --privileged
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.
  The aggregate `ci-gate` names `uki-build` in `needs`.

### Requirement: KMS-CI-002 Scenario summary gates

The hosted node scenarios SHALL require the declared software TPM transport and expected zero-failure summary. The one-node job SHALL require 26 passes and one explicit TODO per outstanding single-node re-anchor/recount and planned-outage update scenario, with those TODOs outside the pass count.

#### Scenario: One-node summary complete

- **WHEN** the live scenario emits the required transport, the expected totals and each named TODO once
- **THEN** its log gate succeeds

#### Scenario: One-node evidence missing

- **WHEN** a TODO is missing, duplicated, or only mentioned within another line
- **THEN** its log gate refuses

#### Scenario: Shared matrix incomplete

- **WHEN** a shared scenario lacks the expected zero-failure summary
- **THEN** its workflow job fails

#### Scenario: A rate-limited peer does not exhaust another peer's lease nonce budget

- **WHEN** the recovery scenario observes the issuer answer one peer up to its lease request limit and commit an audited rate denial for that peer
- **THEN** the scenario then requires the same issuer to return a successful lease-nonce response to the other admitted peer

### Requirement: KMS-CI-003 Single-node denial evidence integrity

The single-node scenario SHALL correlate the revocation denial to the tested node and committed epoch and require matching collector evidence. Missing evidence or a polling failure SHALL fail the assertion even if a later diagnostic read succeeds.

#### Scenario: Collector holds the revoked node's exact renewal denial

- **WHEN** the sole node's revocation is committed and its renewal is denied for no lease in the new epoch
- **THEN** the scenario passes this check only if the collector holds the matching admission-renew denial for that node, epoch and exact refusal reason

#### Scenario: Correlated denial

- **WHEN** the single node receives the expected refusal at the new epoch and its audit entry reaches the collector
- **THEN** the scenario records a passing revocation assertion

#### Scenario: Incomplete or mismatched evidence

- **WHEN** the collector record is missing, the peer or epoch differs, or polling fails
- **THEN** the revocation assertion fails

### Requirement: KMS-CI-004 Evidence class disclosure

The integration runner SHALL identify the software, emulated or physical scope of each declared mode. A planned execution SHALL report only the evidence it would produce, and a failed run SHALL withhold a successful evidence summary.

#### Scenario: Plan inspected

- **WHEN** the operator selects plan mode
- **THEN** the output says nothing ran

#### Scenario: Execution failed

- **WHEN** a commanded phase fails or its required ceremony substrate is missing
- **THEN** the runner exits nonzero and labels the summary as failed

#### Scenario: Successful run scope

- **WHEN** the run executes only software and emulated phases
- **THEN** the summary identifies that scope and does not claim physical qualification

### Requirement: KMS-CI-005 Qualification evidence boundaries

Release acceptance SHALL identify the exact revision, executed gate assertions and the environment that produced the results. Hardware and witnessed commissioning claims SHALL require their own eligible evidence.

#### Scenario: Qualified release

- **WHEN** reviewers inspect the required logs and approved hardware record
- **THEN** the acceptance record identifies the revision and the guarantees verified in each environment

#### Scenario: Incomplete coverage

- **WHEN** software checks pass while an operator-authorized physical or first-store gate is still pending
- **THEN** those items remain open in the release record

### Requirement: KMS-CI-006 Qualified dependencies and reproducibility controls

Software qualification SHALL check selected token middleware library versions against the pinned stack. Build drift checks SHALL use the reviewed snapshot epoch and boot input set, and image reproduction comparisons SHALL agree on the declared build artifacts.

#### Scenario: Matching qualification inputs

- **WHEN** the dependency versions and build inventory match the reviewed pins
- **THEN** the dependency and build-input checks succeed

#### Scenario: Dependency or build drift

- **WHEN** a token library version changes outside the qualification record or reviewed build inputs are inconsistent
- **THEN** the affected qualification check refuses

### Requirement: KMS-CI-007 Owner-assisted boot evidence

The single-node software scenario SHALL distinguish a reachable pinned owner tunnel with a stopped unlock listener from a successful owner-assisted unlock. The negative phase SHALL show bidirectional client traffic, a separately classified inner TCP refusal and no key. The positive phase SHALL show successful owner unlock and volume readback.

#### Scenario: Owner listener stopped

- **WHEN** the pinned tunnel exchanges client traffic and its owner TCP endpoint refuses the connection
- **THEN** the scenario accepts only an exhausted no-key boot attempt

#### Scenario: Owner listener enabled

- **WHEN** the same tunnel path is used after the owner listener comes up
- **THEN** the real client opens the owner keyslot and reads the filesystem marker

#### Scenario: Unsound evidence

- **WHEN** the peer traffic is missing or one-way, the connection probe fails to start, or a key was received
- **THEN** the negative phase fails

### Requirement: KMS-CI-008 Workflow registration and scheduling

Repository workflows SHALL declare the triggering events and their filters, the workflow-wide concurrency and permissions, and the job registrations and any job-specific selectors, dependencies, matrices, reusable-workflow calls or permission overrides documented below. These declarations describe potential selection. Hosted execution and forge policy require separate evidence.

#### Scenario: abrmd-probe declares event pull_request

- **GIVEN** the workflow-wide settings in `abrmd-probe declares event workflow_dispatch`
- **WHEN** the pinned registration in `.github/workflows/abrmd-probe.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
    paths:
      - e2e/abrmd-probe.sh
      - .github/workflows/abrmd-probe.yml
  ```

#### Scenario: abrmd-probe declares event schedule

- **GIVEN** the workflow-wide settings in `abrmd-probe declares event workflow_dispatch`
- **WHEN** the pinned registration in `.github/workflows/abrmd-probe.yml` is inspected for `schedule`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  schedule:
    - cron: "17 5 * * 1"
  ```

#### Scenario: abrmd-probe declares event workflow_dispatch

- **WHEN** the pinned registration in `.github/workflows/abrmd-probe.yml` is inspected for `workflow_dispatch`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  workflow_dispatch:
  ```

  This entry declares no event-specific filters or inputs.

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: abrmd-probe declares job abrmd

- **GIVEN** the workflow-wide settings in `abrmd-probe declares event workflow_dispatch`
- **WHEN** a workflow run is eligible under its declared event entries (`workflow_dispatch`, `pull_request`, `schedule`) and the job registration for `abrmd` is inspected in `.github/workflows/abrmd-probe.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  abrmd:
    strategy:
      fail-fast: false
      matrix:
        runner: [ubuntu-24.04, ubuntu-26.04]
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 20
  ```

  This job declares none of these fields: `if`, `needs`, `permissions`, `concurrency`, `uses`.

#### Scenario: ci declares event pull_request

- **WHEN** the pinned registration in `.github/workflows/ci.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
  ```

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: ci declares event push

- **GIVEN** the workflow-wide settings in `ci declares event pull_request`
- **WHEN** the pinned registration in `.github/workflows/ci.yml` is inspected for `push`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  push:
    branches: [main]
  ```

#### Scenario: codeql declares event pull_request

- **GIVEN** the workflow-wide settings in `codeql declares event push`
- **WHEN** the pinned registration in `.github/workflows/codeql.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
    branches: [ "main" ]
  ```

#### Scenario: codeql declares event push

- **WHEN** the pinned registration in `.github/workflows/codeql.yml` is inspected for `push`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  push:
    branches: [ "main" ]
  ```

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: codeql declares event schedule

- **GIVEN** the workflow-wide settings in `codeql declares event push`
- **WHEN** the pinned registration in `.github/workflows/codeql.yml` is inspected for `schedule`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  schedule:
    - cron: '24 12 * * 5'
  ```

#### Scenario: codeql declares job analyze

- **GIVEN** the workflow-wide settings in `codeql declares event push`
- **WHEN** a workflow run is eligible under its declared event entries (`push`, `pull_request`, `schedule`) and the job registration for `analyze` is inspected in `.github/workflows/codeql.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ${{ (matrix.language == 'swift' && 'macos-latest') || 'ubuntu-26.04' }}
    permissions:
      security-events: write
      packages: read
      actions: read
      contents: read
    strategy:
      fail-fast: false
      matrix:
        include:
        - language: actions
          build-mode: none
        - language: go
          build-mode: autobuild
        - language: python
          build-mode: none
  ```

  This job declares none of these fields: `if`, `needs`, `concurrency`, `uses`.

#### Scenario: initrd-drift declares event pull_request

- **GIVEN** the workflow-wide settings in `initrd-drift declares event schedule`
- **WHEN** the pinned registration in `.github/workflows/initrd-drift.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
    paths:
      - .github/workflows/initrd-drift.yml
      - e2e/initrd-drift.sh
      - deploy/baremetal/initrd_drift.py
      - deploy/baremetal/initrd/initrd-inventory.txt
  ```

#### Scenario: initrd-drift declares event schedule

- **WHEN** the pinned registration in `.github/workflows/initrd-drift.yml` is inspected for `schedule`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  schedule:
    - cron: "17 6 * * *"
  ```

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: initrd-drift
    cancel-in-progress: false
  ```

#### Scenario: initrd-drift declares event workflow_dispatch

- **GIVEN** the workflow-wide settings in `initrd-drift declares event schedule`
- **WHEN** the pinned registration in `.github/workflows/initrd-drift.yml` is inspected for `workflow_dispatch`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  workflow_dispatch:
  ```

  This entry declares no event-specific filters or inputs.

#### Scenario: initrd-drift declares job build

- **GIVEN** the workflow-wide settings in `initrd-drift declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `workflow_dispatch`, `pull_request`) and the job registration for `build` is inspected in `.github/workflows/initrd-drift.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  build:
    runs-on: ubuntu-26.04
    timeout-minutes: 45
    permissions:
      contents: read
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `concurrency`, `uses`.

#### Scenario: initrd-drift declares job file

- **GIVEN** the workflow-wide settings in `initrd-drift declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `workflow_dispatch`, `pull_request`) and the job registration for `file` is inspected in `.github/workflows/initrd-drift.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  file:
    needs: build
    if: always() && github.event_name != 'pull_request'
    runs-on: ubuntu-26.04
    timeout-minutes: 10
    permissions:
      issues: write
  ```

  This job declares none of these fields: `strategy`, `concurrency`, `uses`.

#### Scenario: node-units declares event pull_request

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** the pinned registration in `.github/workflows/node-units.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
    paths:
      - deploy/baremetal/**
      - e2e/node-units-systemd.py
      - .github/workflows/node-units.yml
      - internal/admission/**
      - internal/config/**
      - cmd/regalia-kms/**
      - cmd/regalia-audit-collector/**
      - cmd/regalia-audit-ship/**
      - internal/audit/**
      - e2e/audit-ship-systemd.py
      - e2e/three-node-netns.py
      - e2e/one-node.py
      - e2e/three-node-recovery.py
      - e2e/three-node-outage.py
      - e2e/three-node-reanchor.py
      - e2e/rolling-threenode.py
      - e2e/three-node-site-advance.py
      - e2e/three-node-theft.py
      - e2e/three-node-leases.py
      - e2e/three-node-wan.py
      - e2e/three-node-replace.py
      - cmd/regalia-unlock/**
      - e2e/lib/threenode.py
      - e2e/lib/tpmdiag.py
      - e2e/lib/apt-install-netem.sh
      - tests/test_baremetal_heartbeat.py
      - deploy/systemd/regalia-kms.sysusers.conf
  ```

#### Scenario: node-units declares event push

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** the pinned registration in `.github/workflows/node-units.yml` is inspected for `push`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  push:
    branches: [main]
    paths:
      - deploy/baremetal/**
      - e2e/node-units-systemd.py
      - .github/workflows/node-units.yml
      - internal/admission/**
      - internal/config/**
      - cmd/regalia-kms/**
      - cmd/regalia-audit-collector/**
      - cmd/regalia-audit-ship/**
      - internal/audit/**
      - e2e/audit-ship-systemd.py
      - e2e/three-node-netns.py
      - e2e/one-node.py
      - e2e/three-node-recovery.py
      - e2e/three-node-outage.py
      - e2e/three-node-reanchor.py
      - e2e/rolling-threenode.py
      - e2e/three-node-site-advance.py
      - e2e/three-node-theft.py
      - e2e/three-node-leases.py
      - e2e/three-node-wan.py
      - e2e/three-node-replace.py
      - cmd/regalia-unlock/**
      - e2e/lib/threenode.py
      - e2e/lib/tpmdiag.py
      - e2e/lib/apt-install-netem.sh
      - tests/test_baremetal_heartbeat.py
      - deploy/systemd/regalia-kms.sysusers.conf
  ```

#### Scenario: node-units declares event schedule

- **WHEN** the pinned registration in `.github/workflows/node-units.yml` is inspected for `schedule`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  schedule:
    - cron: '23 2 * * *'
  ```

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: node-units declares job node-units-systemd

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `node-units-systemd` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  node-units-systemd:
    runs-on: ubuntu-26.04     # was pinned: "the chrony and systemd behaviour observed is 24.04's"; tried on 26.04 (regalia-oiq)
    timeout-minutes: 30
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job audit-ship-systemd

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `audit-ship-systemd` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  audit-ship-systemd:
    runs-on: ubuntu-26.04
    timeout-minutes: 15
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-netns

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-netns` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-netns:
    runs-on: ubuntu-26.04
    timeout-minutes: 20
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job rolling-threenode

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `rolling-threenode` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  rolling-threenode:
    runs-on: ubuntu-26.04
    timeout-minutes: 90
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-site-advance

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-site-advance` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-site-advance:
    runs-on: ubuntu-26.04
    timeout-minutes: 90
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-outage

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-outage` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-outage:
    runs-on: ubuntu-26.04
    timeout-minutes: 60
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-reanchor

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-reanchor` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-reanchor:
    runs-on: ubuntu-26.04
    timeout-minutes: 60
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-replace

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-replace` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-replace:
    runs-on: ubuntu-26.04
    timeout-minutes: 60
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-theft

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-theft` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-theft:
    runs-on: ubuntu-26.04
    timeout-minutes: 60
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-leases

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-leases` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-leases:
    runs-on: ubuntu-26.04
    timeout-minutes: 60
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: node-units declares job three-node-wan

- **GIVEN** the workflow-wide settings in `node-units declares event schedule`
- **WHEN** a workflow run is eligible under its declared event entries (`schedule`, `pull_request`, `push`) and the job registration for `three-node-wan` is inspected in `.github/workflows/node-units.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  three-node-wan:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: recovery-matrix declares event pull_request

- **WHEN** the pinned registration in `.github/workflows/recovery-matrix.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
    paths:
      - 'lab/recovery/**'
      - 'deploy/baremetal/recovery-key.sh'
      - 'deploy/baremetal/recovery_state.py'
      - 'deploy/baremetal/recovery-reconcile.py'
      - 'tests/test_recovery_matrix_observer.py'
      - '.github/workflows/recovery-matrix.yml'
  ```

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: recovery-matrix declares event workflow_dispatch

- **GIVEN** the workflow-wide settings in `recovery-matrix declares event pull_request`
- **WHEN** the pinned registration in `.github/workflows/recovery-matrix.yml` is inspected for `workflow_dispatch`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  workflow_dispatch:
  ```

  This entry declares no event-specific filters or inputs.

#### Scenario: recovery-matrix declares job matrix

- **GIVEN** the workflow-wide settings in `recovery-matrix declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `workflow_dispatch`) and the job registration for `matrix` is inspected in `.github/workflows/recovery-matrix.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  matrix:
    runs-on: ubuntu-26.04
    timeout-minutes: 60
    strategy:
      fail-fast: false
      matrix:
        mode: [enrol, replace]
        shard: [1, 2, 3, 4, 5, 6, 7, 8]
  ```

  This job declares none of these fields: `if`, `needs`, `permissions`, `concurrency`, `uses`.

#### Scenario: recovery-matrix declares job merge

- **GIVEN** the workflow-wide settings in `recovery-matrix declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `workflow_dispatch`) and the job registration for `merge` is inspected in `.github/workflows/recovery-matrix.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  merge:
    needs: matrix
    if: always()
    runs-on: ubuntu-26.04
    timeout-minutes: 5
  ```

  This job declares none of these fields: `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: recovery-reconcile declares event pull_request

- **WHEN** the pinned registration in `.github/workflows/recovery-reconcile.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
    paths:
      - 'deploy/baremetal/recovery-reconcile.py'
      - 'deploy/baremetal/recovery_state.py'
      - 'deploy/baremetal/recovery-key.sh'
      - 'lab/recovery/**'
      - 'tests/test_recovery_reconcile.py'
      - '.github/workflows/recovery-reconcile.yml'
  ```

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: recovery-reconcile declares event workflow_dispatch

- **GIVEN** the workflow-wide settings in `recovery-reconcile declares event pull_request`
- **WHEN** the pinned registration in `.github/workflows/recovery-reconcile.yml` is inspected for `workflow_dispatch`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  workflow_dispatch:
  ```

  This entry declares no event-specific filters or inputs.

#### Scenario: recovery-reconcile declares job reconcile

- **GIVEN** the workflow-wide settings in `recovery-reconcile declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `workflow_dispatch`) and the job registration for `reconcile` is inspected in `.github/workflows/recovery-reconcile.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  reconcile:
    runs-on: ubuntu-26.04
    timeout-minutes: 30
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: secret-scan declares event pull_request

- **WHEN** the pinned registration in `.github/workflows/secret-scan.yml` is inspected for `pull_request`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  pull_request:
  ```

  This entry declares no event-specific filters or inputs.

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: secret-scan declares event push

- **GIVEN** the workflow-wide settings in `secret-scan declares event pull_request`
- **WHEN** the pinned registration in `.github/workflows/secret-scan.yml` is inspected for `push`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  push:
    branches: [main]
  ```

#### Scenario: secret-scan declares job secrets

- **GIVEN** the workflow-wide settings in `secret-scan declares event pull_request`
- **WHEN** a workflow run is eligible under its declared event entries (`pull_request`, `push`) and the job registration for `secrets` is inspected in `.github/workflows/secret-scan.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  secrets:
    runs-on: ubuntu-26.04
    timeout-minutes: 15
  ```

  This job declares none of these fields: `if`, `needs`, `strategy`, `permissions`, `concurrency`, `uses`.

#### Scenario: vtpm-probe declares event workflow_dispatch

- **WHEN** the pinned registration in `.github/workflows/vtpm-probe.yml` is inspected for `workflow_dispatch`
- **THEN** the event entry under `on` is as follows. It only declares the trigger and any local filters.

  ```yaml
  workflow_dispatch:
  ```

  This entry declares no event-specific filters or inputs.

  The following settings apply workflow-wide.

  ```yaml
  permissions:
    contents: read
  concurrency:
    group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.run_id }}
    cancel-in-progress: ${{ github.event_name == 'pull_request' }}
  ```

#### Scenario: vtpm-probe declares job vtpm-proxy

- **GIVEN** the workflow-wide settings in `vtpm-probe declares event workflow_dispatch`
- **WHEN** a workflow run is eligible under its declared event entries (`workflow_dispatch`) and the job registration for `vtpm-proxy` is inspected in `.github/workflows/vtpm-probe.yml`
- **THEN** the job is declared under `jobs` with the following settings for potential selection.

  ```yaml
  vtpm-proxy:
    strategy:
      fail-fast: false
      matrix:
        runner: [ubuntu-24.04, ubuntu-26.04]
    runs-on: ${{ matrix.runner }}
    timeout-minutes: 15
  ```

  This job declares none of these fields: `if`, `needs`, `permissions`, `concurrency`, `uses`.

### Requirement: KMS-CI-009 Validate OpenSpec reference integrity

The local checker SHALL validate current declared references against the supplied snapshot and explicit pinned source. A check SHALL emit JSON with its integrity outcome and leave verification authority unassessed and coverage incomplete. Command-line help and usage diagnostics SHALL be separate from checked JSON output.

#### Scenario: Current references resolve

- **WHEN** the caller supplies the complete snapshot, local source repository and full product revision options, and the declared references resolve
- **THEN** the checker returns exit 0 and a JSON object with referenceIntegrity true, verificationAuthority not-assessed, coverageComplete false, counts and input hashes.

#### Scenario: Expected input or reference checks fail

- **WHEN** an invocation reaches checking and its snapshot, required local source commit, declared reference or required offline cache entry is missing, malformed or differs from the bound input
- **THEN** the checker returns exit 1 and JSON with referenceIntegrity false and a diagnostic, with verificationAuthority not-assessed and coverageComplete false.

#### Scenario: A required option is missing or a long option is abbreviated

- **WHEN** the caller does not request help and omits a required option, uses an unrecognized option, or uses a shortened long option name
- **THEN** the command-line parser returns exit 2 with usage information on stderr and emits no checked JSON.

#### Scenario: Help displays usage

- **WHEN** the caller supplies -h or --help alone
- **THEN** the parser returns exit 0 with usage and the option descriptions on stdout and performs no reference check.

#### Scenario: Nonconforming versioned JSON refuses

- **WHEN** a consumed versioned document supplies a schema version other than JSON integer 1, or any consumed JSON includes a duplicate key or NaN, Infinity or -Infinity as an unquoted value
- **THEN** the checker returns the exit 1 refusal form even when the value appears in opaque metadata.

#### Scenario: A scenario name belongs under a different requirement

- **WHEN** a case reference names a scenario that exists only under another requirement, or uses a proposed-only scenario as a direct baseline reference
- **THEN** the checker returns the exit 1 refusal form.

#### Scenario: Product candidate and external source domains stay distinct

- **WHEN** a current reference names pinned product bytes, candidate test content or an external descriptor
- **THEN** it resolves only in its declared source domain. A missing pinned product blob, candidate without its current record and matching hash, or external descriptor without its bound offline cache entry returns the exit 1 refusal form.

#### Scenario: Historical and metadata records supply context only

- **WHEN** the snapshot contains older scenario pointers, superseded candidate references, inactive proposals or evidence and review metadata
- **THEN** the checker applies the declared reference treatment for each input, keeps related and proposed-only pointers separate from direct baseline links, and derives no authority or coverage verification from those records.

### Requirement: KMS-CI-010 Enforce the finite OpenSpec checks in build-test

The existing build-test job SHALL require strict validation of the main specs and active OpenSpec changes with the pinned CLI, the focused checker tests, and a successful reference check with locally present pinned product objects. Any required preparation or check failure SHALL fail build-test.

#### Scenario: Strict syntax and references pass

- **WHEN** an eligible build-test run reaches the OpenSpec checks with the pinned toolchain and exact product source locally available
- **THEN** it runs strict validation, the focused tests and the reference check. They can succeed with declared legacy gaps still open and without changing the checker authority fields.

#### Scenario: The product pin is absent or wrong

- **WHEN** preparation cannot establish the required product commit and tree in the local source repository
- **THEN** build-test fails and does not substitute the workflow checkout revision or use network fallback in the checker.

#### Scenario: A required check fails

- **WHEN** strict validation rejects a specification, a focused test fails, or the reference checker returns nonzero
- **THEN** build-test fails and the aggregate observes its failure using the existing job dependency.

### Requirement: KMS-CI-011 Resolve an explicitly pinned tooling authoring domain

The reference checker SHALL resolve an explicitly declared tooling authoring shard against its own local Git commit and tree. The existing product inputs SHALL remain the source for legacy authoring. Tooling references SHALL validate exact scope and bytes. Reference integrity SHALL leave verification authority unassessed and coverage incomplete.

#### Scenario: A legacy caller checks a product-only snapshot

- **WHEN** the snapshot has neither the tooling authoring shard nor any adopted KMS-CI-009 through KMS-CI-012 requirement and the caller supplies the three existing options
- **THEN** the checker retains the existing result schema, exit behavior and product-reference resolution, and performs no tooling lookup

#### Scenario: CLI help and usage remain separate from checking

- **WHEN** the caller requests help, uses an abbreviated or unknown long option, or supplies just one of `--tooling-source-repo` and `--tooling-source-revision`
- **THEN** help lists both new options, returns exit 0 and reads no snapshot or repository. Malformed usage without help returns exit 2 with usage on stderr and emits no checked JSON

#### Scenario: Tooling is enabled by the declared shard and exact pair

- **GIVEN** `openspec/coverage/tooling-authoring.json` declares the version-1 tooling domain, its full commit ID and tree
- **WHEN** the caller supplies both tooling options, the full revision matches, the explicit local repository contains the bound commit and tree, the repository is a non-bare checkout root (including a linked worktree), and each eligible locator resolves
- **THEN** the checker returns the successful reference envelope and includes `toolingSourceRevision` and `toolingSourceTree` for the independently resolved tooling input

#### Scenario: Declaration or local pin does not match

- **WHEN** a declared tooling shard lacks the CLI pair, the pair accompanies a snapshot with no tooling declaration, or the supplied local repository, commit or tree is absent, unqualified or mismatched, including a bare repository, selected subdirectory or symlink root
- **THEN** the checker emits the exit 1 integrity refusal with a diagnostic identifying the missing declaration or binding. It uses no working-tree, product-domain, transport or lazy-fetch fallback

#### Scenario: Tooling authoring is restricted to its declared contribution

- **WHEN** tooling authoring participates in the baseline
- **THEN** its declared tooling owner joins only the existing runtime-owned delivery capability requirements KMS-CI-009 through KMS-CI-012. Each ID has exactly one matching title and authoring row in the common baseline. Only declared regular paths in the tooling scope can supply its source and test anchors. Existing catalog owners, case origins and product source selection are preserved

#### Scenario: Adopted tooling cannot use the legacy authoring path

- **WHEN** any of KMS-CI-009 through KMS-CI-012 is registered in the baseline but the four-ID set or tooling shard is absent, or a legacy shard claims a tooling ID
- **THEN** the checker returns the exit 1 integrity refusal rather than treating the snapshot as product-only or resolving those IDs through product authoring

#### Scenario: Version, scope or anchor binding is invalid

- **WHEN** a tooling shard uses an unsupported JSON version or shape, changes its domain or owner, claims an ineligible capability, requirement or path, duplicates an authoring identity, or supplies a missing or mismatched file hash, line, exact anchor text or anchor hash
- **THEN** the checker returns the exit 1 reference refusal and identifies the violated binding. A match at the same path in a different source domain does not satisfy the claim

#### Scenario: Tooling source observation carries no verification authority

- **WHEN** a tooling locator validates or a record references a historical hosted observation
- **THEN** the result retains `verificationAuthority=not-assessed` and `coverageComplete=false`. No observation changes canonical case ownership, classification, or accepted evidence scope

### Requirement: KMS-CI-012 Prepare immutable tooling source for reference checks

The existing build-test workflow SHALL prepare a separate, immutable local tooling Git checkout when the snapshot declares tooling authoring. A declared tooling input SHALL pass commit and tree preflight before reference checking. A preparation or check failure SHALL fail build-test and reach the existing aggregate.

#### Scenario: A declared tooling pin is prepared before checking

- **WHEN** an eligible build-test run has a valid tooling declaration
- **THEN** it reserves an unused separate location, checks out the declared commit from the same repository without persisting credentials, verifies the commit and tree locally and supplies the tooling pair to the reference checker. The product checkout and primary analyzed revision retain their separate identities

#### Scenario: A legacy snapshot needs no tooling fetch

- **WHEN** a snapshot has no tooling declaration and has no adopted tooling requirements
- **THEN** build-test makes no tooling checkout and still runs the existing strict, test and product-reference checks

#### Scenario: Declared preparation fails closed

- **WHEN** the declaration is malformed, the reserved location is occupied, the exact same-repository commit cannot be prepared, or preflight detects a wrong commit, tree or primary checkout identity
- **THEN** build-test fails without substituting product or primary objects and does not report a passed reference check. The existing aggregate observes the build-test failure

#### Scenario: The checker detects a post-preparation binding error

- **WHEN** a prepared job reaches the checker and the declared tooling bindings fail to resolve, or the checker reports an unsuccessful result
- **THEN** build-test fails through its existing required check path and the aggregate observes the failure
