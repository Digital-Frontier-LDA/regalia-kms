# Design

## Context

See the proposal for motivation. This design is grounded in PR #764 head
`3378b31fa3d7bc46d5782ce654c00eeb446df3b2`, tree
`dc40eaf76bfcf54a8176ca12f9ff3dd5d8d12e02`. The current checker
requires an exact catalog capability set and main/baseline-delta identity
parity at lines 263–289. Its named authoring shard and product-only locator
logic at lines 253–257 and 292–343 cannot resolve the newer checker,
tests, or CI tail against product `0a32`. The existing separate source
checkout in `.github/workflows/ci.yml:183–205` prepares only that product
object. The KMS-CI-009/010 contracts are in
`add-openspec-reference-integrity-ci` and remain active. The accepted
hosted observations apply to their respective evaluated trees. They
cannot attest to the proposed resolver.

## Goals / Non-Goals

**Goals:** Keep product `0a32a901d1240eec51ddff323274e2ad935116f3`
and tree `347cc36bd44945fcff8a6624237222cb64c0cf17`. Add one positively
declared local tooling source and a closed authoring contract, with a
deployable implementation-before-adoption sequence. Retain the existing
three-option path and its failure semantics.

**Non-Goals:** Changes to the 463 canonical case identities/classifications
or nine historical proof scopes. This slice confers no N/A approval,
legacy-budget or deletion authority, verification qualification,
independent review approval, discovery completion, runtime permission or
commissioning/hardware acceptance.

## Decisions

### D1. One versioned authoring shard and a bounded owner join

Use `openspec/coverage/tooling-authoring.json`. Its closed top-level
object requires `schemaVersion` (JSON integer 1), `sourceDomain`
(`tooling`), `sourceRevision`, `sourceTree`, `owner` (`tooling`),
`files`, `requirements`, `sourceAreas` and `knownGaps`. Reject
duplicate JSON keys, nonstandard constants, unknown keys and version
coercions just as the existing profile does. Commit and tree are lowercase
40-hex Git IDs. The schema is independent of the product shards. There is
no per-reference domain override or implicit file path inference.

- `files` is a unique array of `{path, fileSha256}` declarations. Paths
  are normalized repo-relative POSIX paths in the finite allowlist below.
  SHA-256 is lowercase 64-hex. Require it to match the regular Git blob.
  The declared file set equals the union of source/test references and
  source-area paths. Reject orphan entries, duplicate paths and undeclared
  claims.
- `requirements` contains exactly KMS-CI-009 through KMS-CI-012 when
  adopted. Titles match the main/baseline-delta identity and the exact
  capability `delivery/software-build-and-ci`. The shard's declared
  tooling owner joins only these IDs to the existing catalog owner
  `runtime`. Register these IDs exactly once across all shards even if
  a legacy shard tries to claim one. A valid record cannot be used to
  authorize a runtime/baremetal owner change.
- Keep existing authoring row fields for ID, capability, title, status,
  sources, tests, rationale, executionEvidence and beads. For this slice
  use `UNVERIFIED`, omit `caseIds`, leave `executionEvidence` empty,
  and require at least one enforcing source anchor and one actual
  assertion anchor per requirement. Each locator requires exactly
  `path, line, symbol, supports, fileSha256, text, lineSha256`.
  Quality of the assertion remains separately reviewed. File SHA-256 must
  equal the declaration and blob. Line is a positive integer within bounds,
  text is exact and unstripped, and line SHA-256 is over the UTF-8 line
  without its line terminator.
- `sourceAreas` and `knownGaps` use the existing shapes documented
  in AUTHORING.md, with only this capability and with source-area paths
  resolved through the same tooling pins. A tooling row does not add a
  canonical case or promote an existing one.

Once any of KMS-CI-009 through KMS-CI-012 appears in the registered
baseline, all four IDs and the tooling shard are required together.
An absent shard or partial adoption is a checked integrity refusal, even
if a legacy shard tries to claim the tooling IDs. Presence of a tooling
CLI pair alone cannot create a declared domain.

The finite source/test path allowlist is `.github/workflows/ci.yml`,
`tools/check_openspec_references.py`,
`tests/test_check_openspec_references.py`, and these exact paths under
`tools/openspec-ci/`: `check-source.sh`, `plan-tooling-source.py`,
`install-runtime.sh`, `package.json`, `package-lock.json`,
`check-lock.cjs`, `check-result.py`, `wiring.test.cjs`. No glob
against the worktree is permitted. File bytes from the pinned tree
must be regular files, never symlinks, submodules or directories.
The candidate domain is source provenance, separate from the local-test
candidate and offline external descriptor domains.

### D2. Explicit optional input pair with strict refusal semantics

Keep the required `--snapshot`, `--source-repo` and `--source-revision`
options and add exact long options `--tooling-source-repo` and
`--tooling-source-revision`. Without a shard and without the pair, the
legacy interface uses product-only resolution and the same result keys.
A partial CLI pair is a usage error (exit 2 with stderr usage, no JSON).
Help lists the options and exits 0 without reading either input. Preserve
disabled abbreviation matching. For a complete pair with no shard,
refuse with `TOOLING_DOMAIN_UNDECLARED`. For a valid shard without the
pair, use `TOOLING_DOMAIN_REQUIRED`. These are checked input refusals
(exit 1 JSON). Compare the supplied full tooling revision with the shard,
then verify the commit kind and exact tree from the explicitly named local
Git repository. Reject a missing or invalid repository, wrong commit/tree,
or invalid declared domain/path/hash/anchor with a specific refusal;
existing low-level Git or input diagnostics can be reused. Do not search
parent repositories from the candidate directory or follow a symlink to
a different selected checkout. A locality check must bind the named
candidate repository root before reading blobs.
The first tooling profile accepts the root of a non-bare checkout,
including a linked Git worktree. A bare repository, a selected
subdirectory, or a supplied root that is itself a symlink is refused.
This restriction is specific to the new tooling input; the legacy
product reader keeps its existing contract.

Resolve through a separate Git reader retaining the existing protections
against transports, lazy fetch, prompts and replacement objects. No
current-file fallback and no use of product objects as a tooling fallback,
even when paths match. A successful opted-in JSON result adds only
`toolingSourceRevision` and `toolingSourceTree` to the current envelope
and accounts for the loaded shard in its input hashes. Expected failures
retain the existing refusal envelope. Legacy authoring shapes, candidate
and external joins, and the fixed non-authorizing result fields stay
unchanged. The pin binds content integrity. It never certifies review or
qualifies execution. Rebasing the entire product snapshot would break
these bounds and require a separately reviewed migration.

### D3. Prepare pinned objects in existing build-test

Extend the tail after existing pinned Python setup, retaining all
current triggers, jobs, permissions, product preparation and aggregate
dependency semantics. Use an internal `tools/openspec-ci/plan-tooling-source.py`
script to parse strict JSON and validate the closed root declaration and
pin fields. A wholly absent shard is an explicit disabled result. A
malformed declaration or unreadable or symlinked path is a failure, not
disabled. The script emits only `present` and, when enabled, the validated
hex `revision` and `tree` to the workflow output. The full authoring
reader validates the locators and blob bindings independently.

On enabled inputs, reserve `.openspec-tooling-source` using the existing
collision policy, then use the same pinned checkout action, same
repository, literal validated commit, depth 1 and no persisted credentials.
No arbitrary ref, remote URL or repo is controlled by the shard. Only
this declared immutable commit is materialized. Extend `check-source.sh`
with a distinct tooling verification mode to enforce separate
repository root, unchanged primary HEAD, and exact tooling commit/tree.
The checker receives the explicit pair using an argument array and
reads only local objects. The result guard verifies expected tooling
identities when enabled and the legacy envelope without them otherwise.
The planning helper's outputs are internal to this workflow, never
unchecked shell syntax. A malformed declaration, checkout/preflight
failure or checker refusal fails the actual required job. A legacy run
without the shard skips only the tooling-specific preparation steps.
The absence of a required shard or pair after adoption must still fail
reference checks.

## Risks / Trade-offs

- **Shallow history or stale pin** → explicitly prepare the exact
  immutable commit. Report unavailability and keep the existing
  fail-closed checkout/domain checks. No checkout of a branch tip.
- **Partial main/delta adoption or a self-referential tree** → stage
  the code and the adopting data separately. Compare exact normalized
  requirement/scenario blocks as well as the checker's identity maps.
- **Extra hosted overhead** → record the preparation, checker phases and
  total job time on the exact adopted tree. Keep within the existing
  20-minute build-test budget without changing timeout or suppressing
  a failed phase. The observed older run is a comparison point only.
- **Provenance mistaken for authority** → keep authoring conservative
  and retain prior hosted records at their executed revisions. A new
  digest record implies neither approval nor new qualification.

## Migration Plan

1. Record PR #764 status and choose the exact candidate source base.
   Unpublished local implementation A may start from the isolated 3378
   candidate without claiming that it was approved or merged. Publication
   and adoption must respect PR #764 review and base compatibility; if
   that base changes, recheck affected code, tests, and pins. Recheck
   collisions in the delivery capability and the KMS-CI-009/010 delta.
2. Create implementation commit A for the reader, preparation and focused
   fixtures. Do not add an adopted tooling shard or sync any requirement
   in A. The default hosted snapshot retains the legacy path and matrix.
   Exercise enabled adoption with disposable fixture objects. Verify
   the new code, then freeze the full commit/tree and file digests.
3. In a later commit B, add the concrete authoring record that names A
   and bind its exact paths/assertions. Adopt the reviewed KMS-CI-009/010
   and new 011/012 blocks into both the main delivery spec and the
   existing baseline delta atomically. Keep unrelated blocks byte-identical.
   Compare entire normalized blocks and recompute counts from actual
   artifacts. The new 011/012 authoring traces point to the already
   frozen A code and tests, resolving the bootstrap dependency.
4. Collect fresh exact-head hosted outputs on the adopted source, including
   object pinning, all check phases and non-draft gate participation.
   Independent adoption review and explicit archive authorization
   are separate. Keep both active changes until those conditions are met.
5. To roll back, revert the adoption metadata and scoped mirrored blocks
   before reverting the compatible reader/preparation commit. Preserve
   observed historical runs. Future code changes can be tested and frozen
   before a later rebind; do not silently refresh existing proof.

The exact IDs for commit A/tree and its measured runner timings will only
exist after authorized implementation and validation. They are outputs of
the above sequence. The proposed schema, boundary and preparation choices
are concrete for planning review.
