# runtime/api-and-configuration Specification

## Purpose

Defines the versioned operation interface, request and response contracts, and safe daemon configuration boundary.

## Requirements

### Requirement: KMS-API-001 Versioned operation routes

The API SHALL expose sign, wrap, unwrap, certificate-sign, key-agreement, release-secret and seal-envelope through POST on their exact /v1/operations paths.

#### Scenario: Supported route

- **WHEN** an authenticated client submits a valid operation request
- **THEN** the request reaches that operation

#### Scenario: Unsupported route or method

- **WHEN** a caller uses an unversioned or unsupported path, or a non-POST method on a known path
- **THEN** the API returns 404 for the path or 405 with Allow: POST for the method

### Requirement: KMS-API-002 Closed and bounded requests

Operation requests SHALL use one bounded JSON document with the required request ID, JSON media type and idempotency key matching the context nonce. The API SHALL reject ambiguous fields, wrong operation fields and invalid or oversized encoded inputs before dispatch.

#### Scenario: Valid request

- **WHEN** the headers, context and payload satisfy the selected operation's schema
- **THEN** the operation is eligible for dispatch

#### Scenario: Invalid or ambiguous request

- **WHEN** JSON repeats a key, adds an unknown field, has a second document or has an out-of-bound payload
- **THEN** the request is refused without reaching a backend

### Requirement: KMS-API-003 Structured results and errors

A successful operation SHALL return JSON with request, operation and object identifiers, result media type and base64 result. A handler error SHALL use the documented request ID, code, message and retryable fields without echoing sensitive input.

#### Scenario: Signed response verifies against the configured key

- **WHEN** an authorized signing request under valid admission succeeds for the configured token key
- **THEN** the sign route returns HTTP 200 with a signature that verifies for the submitted message under that key's public key

#### Scenario: Operation succeeds

- **WHEN** the coordinator returns a successful result
- **THEN** the API returns the correlated result as no-store JSON

#### Scenario: Invalid operation input

- **WHEN** an authenticated operation has an invalid document
- **THEN** the API returns a stable structured error with no supplied payload

#### Scenario: Immediate signing nonce reuse

- **WHEN** a caller resubmits the same signing request after its nonce has been durably reserved and the first submission succeeded
- **THEN** the sign route returns HTTP 409 rather than a successful signature

#### Scenario: An operation request reaches a full execution pool

- **WHEN** an otherwise valid and authorized POST to `/v1/operations/sign`, `/v1/operations/wrap`, `/v1/operations/unwrap`, `/v1/operations/certificate-sign` or `/v1/operations/key-agreement` has committed its reservation, passed required authorization audit and serving checks, and reaches the executor with a live request context and every execution slot occupied
- **THEN** the executor refuses without waiting for a slot and the route returns HTTP 429 with `RESOURCE_EXHAUSTED` and `retryable: true`; the committed nonce remains spent

#### Scenario: A reserved operation nonce receives a conflict

- **WHEN** an otherwise eligible POST to `/v1/operations/wrap`, `/v1/operations/unwrap`, `/v1/operations/certificate-sign` or `/v1/operations/key-agreement` reaches reservation with an already committed nonce for the same policy, object and principal
- **THEN** the route returns HTTP 409 with `CONFLICT` and `retryable: false` before running the operation, with no cached operation result

#### Scenario: Release and seal requests at executor capacity

- **GIVEN** an otherwise eligible POST to `/v1/operations/release-secret` with a parseable, age-eligible envelope and usable named KEK, or to `/v1/operations/seal-envelope` with valid assembled content and a uniquely usable sealing KEK, has committed its reservation and passed the required audit and serving checks
- **WHEN** the live request reaches the executor while all slots are occupied
- **THEN** the executor refuses without waiting for a slot and the route returns HTTP 429 with `RESOURCE_EXHAUSTED` and `retryable: true`; the committed nonce remains spent and no operation result is returned

#### Scenario: Release or seal reuses a committed nonce

- **GIVEN** a POST to `/v1/operations/release-secret` or `/v1/operations/seal-envelope` still passes its pre-execution route and policy checks up to reservation
- **WHEN** the request reaches reservation with an already committed nonce for the same policy, object and principal
- **THEN** the route returns HTTP 409 with `CONFLICT` and `retryable: false` before the release or seal callback runs, with no cached operation result

### Requirement: KMS-API-004 Constrained daemon configuration

The daemon SHALL load a single bounded JSON configuration from a regular file without group or world write permission, apply safe defaults, refuse unknown fields, validate allowed operation and shutdown limits, and require complete dependent settings for enabled services.

#### Scenario: Minimal local configuration

- **WHEN** an otherwise valid document omits optional settings
- **THEN** the daemon selects a loopback listener and bounded timeouts and concurrency

#### Scenario: Unsafe configuration

- **WHEN** the document contains an unknown field, a second document, incomplete dependency settings or unsafe bounds
- **THEN** configuration is refused
