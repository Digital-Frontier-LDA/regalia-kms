# Tasks

## 1. Establish the implementation base

- [x] 1.1 Record PR #764 disposition and select the exact candidate base. Local unpublished A may use the isolated 3378 candidate without implying approval or merge. Publication/adoption require normal review and base compatibility; revalidate affected bindings if the base moves. Confirm unique KMS-CI-009 through 012 ownership and save base/product commit/tree plus unchanged case/authoring/spec hashes.

## 2. Implement and freeze the compatible tooling domain

- [x] 2.1 Implement the exact optional pair and legacy dispatch in `tools/check_openspec_references.py` with actual entrypoint tests in `tests/test_check_openspec_references.py`. Verify legacy three-option JSON keys and statuses, help without reads, unknown/abbreviated/partial pair usage, and both pair-without-shard and shard-without-pair JSON refusals.
- [x] 2.2 Implement KMS-CI-011's closed version-1 owner/ID/file binding, local commit-type/tree verification, and exact authored locators. Add fixture tests for wrong repository, missing object, noncommit, wrong revision/tree, duplicate IDs/paths, illegal domain/owner/capability/path, and wrong file/line hash or anchor; adopted IDs without a shard, partial adoption, and a legacy shard claiming a tooling ID. Verify a non-bare checkout and linked-worktree root, and refusal of a selected subdirectory, bare repository or symlink root. Use different same-path blobs to catch any product/worktree fallback. Preserve existing candidate, external, historical, zero-authority, and strict-JSON controls. Document the tooling authoring schema in AUTHORING.md.
- [x] 2.3 Implement KMS-CI-012 preparation in `.github/workflows/ci.yml`, `tools/openspec-ci/plan-tooling-source.py`, `check-source.sh` and the envelope guard. Extend `wiring.test.cjs` to verify optional steps, exact pin/output and credential policy, separate roots, primary HEAD retention, legacy branch behavior, and fail-fast execution of the actual shell bodies on each preparatory and checker failure. Use a disposable local real Git fixture for two distinct immutable source checkouts and missing/incorrect object controls.
- [x] 2.4 Run focused non-operational Python/checker/isolation and actual Node wiring tests, strict OpenSpec, and real reference checks for the legacy and enabled fixture paths. Under explicitly local Heavy, use fresh caches and intended removal mutants of the tooling pin, domain isolation and hash checks, plus an unchanged no-op and restored control. Require named assertion failures rather than setup errors. Freeze verified implementation commit A/tree and exact source/assertion hashes before adding any real adopting shard.

## 3. Adopt reviewed contracts against the frozen implementation

- [x] 3.1 Bind the reviewed `openspec/coverage/tooling-authoring.json` to A in later adoption commit B. Use exact source and assertion anchors for all four tooling requirements, including the domain CLI/schema assertions and the CI preparation tests from A. Verify conservative authoring, bounded IDs/path allowlist, distinct A/B revisions, unchanged catalog owner and preservation of product/case/earlier hosted observation hashes.
- [x] 3.2 Under authorized adoption, add the reviewed KMS-CI-009 through KMS-CI-012 blocks to both existing delivery main and baseline delta specs, with tooling inventory and authoring membership in the same adoption change. Compare exact normalized blocks, recompute the resulting inventory from actual artifacts, verify all other spec blocks and existing 463 cases/nine historical scopes unchanged, then pass strict and actual reference checks. Keep the active deltas available for review until adoption is accepted.

## 4. Verify integrated hosted behavior

- [x] 4.1 Collect authorized, fresh exact-head non-draft CI on B. Verify evaluated commit/tree and parent linkage, both independent local source preflights, exact resolver output and false authority/coverage flags, scoped tests, and successful logged aggregate needs. Record source/tool hashes, step/job/run/attempt and total build-test time under 20 minutes. Preserve 9115/3378 records as historical.

## Workflow follow-up

- Independently review the adopted main/baseline-delta identity and body parity, authoring bindings and exact-head hosted evidence before any authorized archive.
- Archive the original finite CI delta and the tooling-domain change only after reviewed adoption and proof. Keep full-ratchet, authority, discovery, product acceptance and hardware gates separate.
