# runtime/observability Specification

## Purpose

Define who may inspect service health and how metric values express freshness and bounded labels.

## Requirements

### Requirement: KMS-OBS-001 Authorized metrics access

The KMS SHALL require an authenticated configured reader to serve Prometheus text metrics. An authenticated principal outside the reader list SHALL be refused, and an empty list SHALL refuse every authenticated caller.

#### Scenario: Allowed scrape

- **WHEN** a configured reader sends an authenticated GET
- **THEN** the endpoint returns Prometheus text series

#### Scenario: Unauthorized scrape

- **WHEN** the certificate is missing or its principal is absent from the metrics reader list
- **THEN** the endpoint refuses with the applicable authentication or authorization status

#### Scenario: Metrics POST advertises GET

- **WHEN** a configured reader sends an authenticated POST to `/v1/metrics`
- **THEN** the endpoint returns HTTP 405 with `Allow: GET` and no metrics body

### Requirement: KMS-OBS-002 Bounded metric dimensions

The KMS SHALL use fixed or configuration-known metric dimensions. Unrecognized request paths SHALL use one fixed unknown bucket without incorporating arbitrary request paths into label values.

#### Scenario: Known route

- **WHEN** an admitted operation path is recorded
- **THEN** the counter uses its static route and response class

#### Scenario: Unknown route

- **WHEN** instrumentation sees an unrecognized path
- **THEN** the counter uses the unknown bucket without exposing the supplied path

### Requirement: KMS-OBS-003 Freshness and missing state

Metrics SHALL emit timestamps for cached PIN, fencing, audit verification and readiness observations. They SHALL omit unavailable source series, distinguish a never-evaluated lease from an evaluated unheld lease, and publish supported counters from zero.

#### Scenario: Freshness visible

- **WHEN** a source provides a recorded value and time
- **THEN** both appear in its applicable metric series

#### Scenario: Unevaluated or absent

- **WHEN** a lease has never been evaluated or its source is absent
- **THEN** the scrape distinguishes that state from a real lease-loss observation

### Requirement: KMS-OBS-004 Dropped audit visibility

The KMS SHALL count failed-to-persist refusal audit records by their fixed outcome. A refusal whose audit event was durably stored SHALL leave the drop counter unchanged.

#### Scenario: Denied event is lost

- **WHEN** the refusal cannot persist its audit event
- **THEN** the refusal still returns no output and the applicable outcome counter increments

#### Scenario: Denied event is stored

- **WHEN** the same refusal records successfully
- **THEN** its drop count does not increase

### Requirement: KMS-OBS-005 Production monitoring acceptance

The deployed monitoring service SHALL demonstrate authorized collection and alert delivery for relevant service, audit and custody failures before production acceptance.

#### Scenario: Monitoring acceptance

- **WHEN** the intended monitoring service watches the deployed nodes
- **THEN** an authorized check demonstrates expected failure alerts reach their designated recipients

### Requirement: KMS-OBS-006 Alert rule behavior

The repository alert rules SHALL have an explicit failure scenario for each deployed KMS alert and SHALL remain silent under its corresponding healthy control.

#### Scenario: Rule qualification

- **WHEN** the synthetic fault and healthy histories are evaluated using the required rule engine
- **THEN** each rule fires on its applicable failure and stays silent for the healthy control

#### Scenario: Rule missing a proof

- **WHEN** a rule lacks an assigned fault scenario or its file does not load
- **THEN** rule validation fails

### Requirement: KMS-OBS-007 Liveness and readiness responses

Liveness SHALL return a minimal status response when the HTTP service answers. Readiness SHALL succeed only when every required probe is available and SHALL return a minimal unavailable response when a probe is absent, fails or panics.

#### Scenario: Healthy service

- **WHEN** the listener is alive and every required dependency reports ready
- **THEN** liveness and readiness respond successfully with only their status

#### Scenario: Unready service

- **WHEN** a dependency fails, panics or no readiness probes are present
- **THEN** readiness returns 503 without exposing internal details

#### Scenario: Liveness refuses unsupported methods

- **WHEN** a client sends a non-GET request to the liveness route
- **THEN** the handler returns HTTP 405 with an empty response body

#### Scenario: Readiness refuses unsupported methods before probing

- **WHEN** a client sends a non-GET request to the readiness route
- **THEN** the handler returns HTTP 405 with an empty response body without executing readiness probes
