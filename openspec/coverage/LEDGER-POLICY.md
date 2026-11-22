# Acceptance and evidence contract

## Declared scope

The target is regalia-kms public/operator/machine-facing behavior, not df-agent-tooling Driver/MCP behavior. Inventory discovery includes deployment and recovery interfaces, compatibility formats and persistent records. Every static candidate needs an explicit public/internal/excluded disposition with rationale; every known dynamic registration must be expanded or carry an approved scope exclusion. An unexplored dynamic registry is a discovery gap, never an exclusion.

No exhaustive claim is valid while `discoveryClosed` is false, parse errors remain, required manual discovery is open, a candidate is unreviewed, duplicate declaration/implementation interfaces are unreconciled, or a public interface lacks a complete behavior trace.

## Behavior traces

For each supported interface, review normal, failure, permission, retry, concurrency, compatibility and recovery facets. A facet is applicable with observable case records, or not applicable with a reviewed behavior-specific explanation. A generic 'not relevant' is insufficient. Split cases when outcomes differ; for example restore with pending, disk loss without pending, unknown lineage, consumed authority, wrong endpoint and a repeated stage request are distinct cases.

Each case records a stable case ID, interface ID, input/precondition and observable outcome, exact spec path/requirement ID/scenario name, enforcing source reference, assertion path/symbol/location, verification evidence, classification and unresolved gap references. A broad shared scenario can cover several interfaces only when its scope and verification prove each named interface. A handler-only test does not establish router reachability; a mocked service lifecycle does not establish live PID 1 behavior.

## Reconciliation classifications

- `verified_shipped`: contract, enforcing source and meaningful assertion agree, and qualifying verification evidence matches the shipped revision or byte-identical relevant source. Record revision/tree, command or hosted job, result, assertion scope and artifact identity. Test existence alone does not qualify.
- `spec_gap`: accepted/observed behavior has no reconciled scenario trace. State whether the gap is genuinely missing contract text or only an uncompleted trace; never infer implementation absence from this status.
- `test_gap`: a scenario lacks a meaningful assertion or qualifying execution evidence. Distinguish an assertion gap, stale evidence and a physical/service-manager evidence gap.
- `contract_conflict`: code, accepted docs/specs, tests or old deltas disagree. Record both sides and the decision needed; do not silently make either normative.
- `proposed`: unapproved or unmerged behavior. Record intended scenario and remaining acceptance; it cannot count as shipped coverage.

Reviewed explicit exclusions additionally need their exact scope, rationale and review provenance. They cannot exempt a supported public behavior from a release promise. Requirements coverage states IMPLEMENTED/PARTIAL/MISSING/UNVERIFIED are a separate axis; IMPLEMENTED in an authoring shard does not promote a case to verified_shipped without execution evidence.

## Old deltas and conflicts

Reconcile old local tracking-repository changes individually against the frozen implementation. An unchecked task can already be shipped; a checked task can lack acceptance. Preserve the original delta status, identify the actual code/assertions, and resolve discrepancies with a recorded decision before adopting baseline contract text. The restricted replacement review remains unresolved and must not be routed around.

## Exhaustive claim

Coverage is exhaustive only for a versioned, declared interface scope when discovery is closed and every applicable case has a verified contract plus qualifying evidence, or an explicit reviewed exclusion. Report remaining gaps by interface, case, classification and milestone. Capability/spec/test totals are descriptive, not a completeness proof.
