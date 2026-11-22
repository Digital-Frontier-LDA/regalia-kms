# Public behavior coverage ledger

**Status: initial source discovery, not exhaustive coverage.** Source pin: `0a32a901d1240eec51ddff323274e2ad935116f3`. The repository's 31 proposed baseline capabilities organize contracts; their count is not a coverage measure.

## Files and current gaps

- `interface-inventory.json`: 707 static interface candidates, including commands/arguments, routes, configuration documents, schema versions, service units and workflow triggers/jobs. Some are internal rather than public; visibility must be reviewed. OpenAPI and implementation registrations are deliberately separate discovery records until reconciled into one interface.
- `behavior-ledger.json`: a record for each candidate and seven behavior facets: normal, failure, permission, retry, concurrency, compatibility and recovery. Every facet starts unreconciled. A provisional `spec_gap` means an inventory-to-scenario trace has not been established; it does not assert that implementation, specs or tests are absent.
- `source-snapshot.json`: source revision and tracked-file hashes used by discovery. It is provenance, not evidence of semantic coverage.
- `LEDGER-POLICY.md`: the acceptance/evidence contract and closure rule.
- `RATCHET.md`: enforceable CI design and remaining implementation gates. CI is not wired by these documents.
- Existing `runtime.json` / `baremetal.json` authoring shards, when present, provide per-requirement evidence. They must be joined to this interface ledger; they cannot replace it.

The scanner did not execute the product or import operator modules. It found no Python/YAML parse errors. It recorded 16 dynamic registration sites (15 unique candidate identities); these remain open discovery work. It cannot establish all custom parser dispatch, generated registrations, nested configuration or persistent state contracts. The manual-discovery list in the inventory is mandatory scope closure work.

## First reconciliation priorities

1. Enrol `commit`, `--bootstrap`, `--replace`, enrol journal and signed membership: permissions, partial publication, repeated/resumed commit, wrong TPM/allocation, revoked identity, interrupted maintenance. The frozen unmerged candidates are proposed evidence, not shipped fixes.
2. Restore `run` / `sign-statement`, normal etcd startup, history incarnation, restore ledger, pending marker and KMS readiness: no-history versus genesis, uncertain consume, replay, concurrent activation, readback failure, reboot and lost volatile state. See the separate `close-single-node-no-history-bootstrap` change and its unresolved review response.
3. Owner-assisted unlock and admission/self-lease: owner unavailable, stale/expired state, wrong UID/quote, concurrent/repeated request, late replies and safe recovery. Keep single-node limitations explicit.
4. HTTP operation/health/metrics routes through the actual router, not just handler tests; authentication, authorization, bounded input, structured error, retry/idempotency and state consistency.
5. Remaining commands, adapters/RPCs, backend-dependent behavior, service-manager interfaces, config/state versions and workflow/ruleset contracts.

The first deliverable is the reconciled ledger and an exact gap report. It is not a declaration that every item above has been verified. Runtime and bare-metal writers are still authoring baseline contracts; their follow-up must reconcile these entries and leave every unknown visible.

## Current reconciliation

The initial inventory remains a preserved discovery snapshot. Read [coverage-report.md](coverage-report.md) and [reconciled-cases.json](reconciled-cases.json) for the current 463-case status and exact gaps; [coverage-summary.json](coverage-summary.json) pins its input hashes. Both owners account for all original candidates, but discovery and case coverage remain open. The nine verified cases are historical hosted/emulated observations at the matching source tree. They confer no physical acceptance.

`workflow-authoring-supplement.json` supplies the UNVERIFIED KMS-CI-008 row for exact workflow declarations; `workflow-contract-gap-batch4-acceptance.json` accepts text traces only.

The [reference-integrity helper](../../tools/check_openspec_references.py) is implemented locally. Its [candidate CLI contract](reference-integrity-cli-proposal.json) and [ratchet plan](RATCHET.md) keep reference consistency separate from evidence authority and exhaustive coverage. CI integration remains open.

## Portable source and historical provenance

`source-snapshot.json` schema 2 uses `digestAlgorithm: "sha256"` and a
`trackedFiles` array of `{"path": "...", "digest": "..."}` records.
The v1 path-to-digest map and the v2 records decode to the same ordered set
of paths and lowercase 64-digit SHA-256 values at the named product revision.
The first API gap proposal retains its outer schema 1. Its `sourceFiles`
collection uses schema 2 with the same algorithm and records under `entries`.
The reference checker reads that proposal's referenced assertion groups and
checks the proposal content hash. It does not consume either digest list.

Historical inputs with `kind: "external-historical-artifact"` name retained
off-repository artifacts by opaque `artifactId` and captured `sha256`.
Inputs with `kind: "repository-relative"` name a repository-root path and
captured `sha256`. A captured digest can identify an earlier version at that
path. These locators convey no access to private artifacts.

[Publication representation migration](publication-representation-migration.json)
records prior and portable byte bindings. The original approval timestamps,
case proofs, historical patch/binary/log hashes and evidence scopes retain
their original meaning. A current proposal or candidate hash binds the
portable bytes and does not authenticate a new review or execution.
