## Purpose

Describes how an authenticated principal obtains a specific operation grant, satisfies policy, and supplies request-bound approvals.

## ADDED Requirements

### Requirement: KMS-AUTHZ-001 Exact scoped grants

Authorization SHALL require an explicit grant for the authenticated principal, object, operation and environment. Policy loading SHALL refuse wildcard grants and duplicate principals.

#### Scenario: Exact grant

- **WHEN** every request dimension is permitted by one grant
- **THEN** the RBAC decision permits further policy evaluation

#### Scenario: Changed scope

- **WHEN** the object, operation, environment or principal differs from the grant
- **THEN** RBAC refuses

### Requirement: KMS-AUTHZ-002 Contextual policy and freshness

An operation SHALL satisfy the policy selected by object and operation, including purpose, environment, algorithm, content type, payload bound and a future expiry within the configured window. Refusals SHALL precede the durable reservation.

#### Scenario: Exact policy

- **WHEN** the request matches its policy and valid freshness window
- **THEN** the request can reserve state

#### Scenario: Invalid context

- **WHEN** one bound, expiry or binding is invalid
- **THEN** the request is denied without reserving it

### Requirement: KMS-AUTHZ-003 Bound distinct approvals

Where policy requires approvals, the service SHALL count only distinct configured approvers with valid signatures for the bound request and permitted expiry. Claimed identifiers, unknown keys and evidence signed for different request bytes SHALL NOT satisfy the threshold.

#### Scenario: Valid approval

- **WHEN** a configured approver signs the expected binding
- **THEN** the approver can count once

#### Scenario: Replayed or duplicate evidence

- **WHEN** a signature binds another request or the same signer is supplied twice
- **THEN** the foreign signature counts zero and duplicates cannot increase the count

#### Scenario: Approval for another serving node is not counted

- **WHEN** an otherwise valid approval is bound to a serving node other than the node evaluating the operation
- **THEN** that approval does not count toward the local quorum and cannot enable a signing call

### Requirement: KMS-AUTHZ-004 Agent secret-release exclusion

Agent principals SHALL be refused direct secret release even if a grant or test authorizer would otherwise allow it.

#### Scenario: Accidental grant

- **WHEN** an RBAC policy grants an agent direct secret release
- **THEN** the loader refuses the policy

#### Scenario: Agent at operation boundary

- **WHEN** an agent sends a release request with an otherwise permissive authorizer
- **THEN** the request is refused under the agent rule
