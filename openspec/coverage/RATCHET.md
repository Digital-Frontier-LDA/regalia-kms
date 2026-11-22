# CI ratchet design and implementation gates

**Current state: the finite strict OpenSpec and reference-only build-test checks passed on the evaluated PR #764 ready-run tree. The full coverage ratchet remains open.** The interface inventory and ledger are the first discovery snapshot, with legacy traces still open. Do not enable a gate that falsely labels those traces verified or makes all existing work impossible.

## Required checks

1. Validate main specs and active changes with the repository's pinned OpenSpec version and strict mode after baseline authoring/synchronization completes. Resolve invalid planning state rather than skipping arbitrary files.
2. Validate ledger schema, unique IDs, scope dispositions, all local paths, requirement/scenario identities, assertion references and evidence artifact identities. Resolve references in the authoritative planning root; never accept a path merely because its filename looks plausible.
3. Compare source-derived interface discovery against the checked inventory. New declarations, changed relevant source/schema/registration hashes, removed interfaces and unresolved dynamic registries require reconciliation. Source changes outside known declarations still require a public-behavior disposition; static extraction cannot prove semantics.
4. For changed public behavior, require its inventory/case/scenario/evidence update. For genuinely unchanged contracts or internal-only changes, require an explicit compatibility/no-public-change disposition identifying the reviewed changed sources. No automatic pass from a 'docs-only' label or a grep count.
5. Keep exact legacy gaps in a separate versioned baseline keyed by interface/case/gap ID. A PR may close gaps; it cannot silently add IDs, broaden an exclusion, downgrade verified evidence or refresh stale evidence as though it ran. Intentional scope or legacy-budget changes require explicit review under the repository's existing policy.
6. Evidence is revision-bound. Record source/test hashes for reuse across documentation-only commits; invalidate on relevant changes. Real-service and hardware cases retain their own evidence tiers and cannot be promoted by unit-test execution.

## Local reference check

Run from the repository root:

```sh
python3 -BEs tools/check_openspec_references.py --snapshot . --source-repo . --source-revision 0a32a901d1240eec51ddff323274e2ad935116f3
```

This checks the declared catalog, authoring, current case links and byte-bound product/candidate/external references. It reports `verificationAuthority: not-assessed` and `coverageComplete: false`. It does not validate evidence truth, approve N/A, enforce a legacy budget, preserve deleted obligations, or compare changed public behavior. The earlier checker reviews and findings remain unresolved. Its [CLI inventory proposal](reference-integrity-cli-proposal.json) is outside the frozen product interface inventory pending explicit tooling integration.

## Implementation sequence and pass/fail acceptance

- [ ] Reconcile the initial candidate inventory, deduplicate declared/implemented routes, expand all dynamic sites and version the declared scope. Pass: every source discovery item is accounted for; no count-based assertion of completeness.
- [x] Implement the finite local reference-integrity helper: 31 focused tests, the earlier six reference-guard removals and four CI/parser mutations, no-op/restored controls and the actual snapshot pass. This completes the reference-only slice.
- [ ] Complete a reviewed checker with meaningful negative fixtures. Pass: dangling scenario, nonexistent assertion, duplicate ID, missing source disposition, stale evidence, unexpanded dynamic item and weakened exclusion are detected. Valid closure and justified non-applicability controls pass.
- [ ] Establish the exact legacy gap baseline after review. Pass: adding one gap fails, closing one passes and unrelated capability additions cannot hide an old gap.
- [ ] Exercise changed-interface enforcement. Pass: new route/subcommand/config field, removed contract, changed registration and persistent-version migration each fail without reconciliation; reviewed internal-only/no-contract-change controls pass.
- [x] Wire the finite reference checker and pinned strict OpenSpec validation into the local build-test workflow. Local controls cover immutable product inputs, pinned tools, malformed specs/references/schema, and actual check-step status propagation.
- [x] Record finite hosted reference enforcement. The [ready-run observation](reference-ci-hosted-observation.json) binds run 44988104217 attempt 1 to head `91151a4d`, its evaluated merge/tree, the tool preparation and phase results, and the non-draft aggregate. Later documentation updates have a separate source identity.
- [ ] Verify current forge required checks separately from workflow declarations. Pass: record their actual source and observation time. A job named 'gate' or a locally declared workflow is not proof of required branch protection.

Start reconciliation with enrol/restore/startup/admission and owner unlock, then runtime API and remaining public surfaces. Discovery, changed-source comparison, legacy-gap and deletion preservation, reviewed non-applicability, and evidence authority remain open. The cited forge-policy observation is dated and separate from the workflow result. Tooling-domain integration, main/delta synchronization, and merge review remain separate gates.
