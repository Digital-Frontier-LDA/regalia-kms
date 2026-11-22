# Proposal

## Why

The reference checker resolves authoring locators against the frozen product release. The finite OpenSpec checker and its CI preparation were added later, so synchronizing KMS-CI-009/010 needs a separate source binding and a contract for the resolver that can itself be traced.

## What Changes

- Add an optional, explicit local tooling Git repository/revision pair for snapshots containing one versioned tooling authoring shard. Preserve the existing product pin, callers and non-authorizing result.
- Specify the CLI, tooling authoring and resolution rules as KMS-CI-011 and the matching same-repository CI preparation as KMS-CI-012. Keep KMS-CI-009/010 in their original active delta until adoption prerequisites are met.
- Sequence a frozen implementation commit before the adoption record that names its commit, tree, paths and hashes. Add reviewed authoring and exact main/baseline-delta blocks together only after that source is available.
- Keep canonical case ownership, the 463 classifications and nine historical proof scopes intact. Discovery closure, N/A approval, legacy-gap or deletion/budget authority, review authority, verification promotion, runtime permissions, commissioning, qualification and hardware evidence remain separate.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `delivery/software-build-and-ci`: declare the tooling-source input, bounded authoring resolution and required CI preparation when that domain is enabled.

## Impact

Implementation is scoped to the reference checker, its focused tests, same-repository source preparation, workflow wiring and the new tooling authoring record. Reviewed adoption affects the existing delivery capability's main spec and baseline delta together. Product code, product source hashes, existing authoring owners, runtime permission paths, hardware and dependencies stay outside this slice.

The accepted PR #764 run supplies prior tooling observations. Its exact-head review and two unresolved threads remain separate. Completing this proposal is a planning milestone.
