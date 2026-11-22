# Evidence contract

Source pin: `0a32a901d1240eec51ddff323274e2ad935116f3`.

Each shard is a JSON object with `schemaVersion: 1`, `sourceRevision`, `owner`, `requirements`, `sourceAreas`, and `knownGaps`.

Each requirement row has `id`, `capability`, `title`, `status` (IMPLEMENTED/PARTIAL/MISSING/UNVERIFIED), `sources` and `tests` arrays, `rationale`, `executionEvidence` array, and `beads` array. Each source/test reference has `path`, `line` (positive integer), `symbol`, and `supports` explaining the enforcing behavior or assertion. Use repo-relative existing paths at the source pin. Evidence from another revision/repo must identify it explicitly and cannot alone establish IMPLEMENTED at the pin.

`sourceAreas` rows have `paths` (explicit existing paths), `capabilities`, and `rationale`. List every assigned product-bearing module, CLI, adapter, unit, script and policy area; use explicit exclusions for fixtures/generated/vendor/nonproduct material. Parent reconciles the complete inventory and task mapping. `knownGaps` rows have `id`, `capabilities`, `description`, `beads`, and `releaseGate`.

Do not invent an assertion, claim a suite ran merely because it exists, copy secrets, or treat a unit name as proof. Every IMPLEMENTED row needs enforcing source and an actual assertion. Hardware coverage stays UNVERIFIED unless named physical evidence is independently available. Proposed decisions are outside the accepted baseline. Requirements state observable behavior; implementation details belong in this ledger.

## Pinned tooling authoring

`tooling-authoring.json` is an opt-in shard for KMS-CI-009 through
KMS-CI-012 in `delivery/software-build-and-ci`. Adopt all four together
in main and the baseline delta. Supply the shard and the exact
`--tooling-source-repo` / `--tooling-source-revision` pair. The tooling
owner joins only these four requirements to the existing runtime catalog
owner. Product authoring keeps the frozen product pin.

The closed object contains integer `schemaVersion: 1`,
`sourceDomain: "tooling"`, `owner: "tooling"`, lowercase full Git IDs
`sourceRevision` and `sourceTree`, and four arrays `files`, `requirements`,
`sourceAreas` and `knownGaps`. Use unique `{path, fileSha256}` declarations
for the union of source/test anchor paths and source-area paths. Only
the explicitly allowlisted tooling files resolve, and all must be
regular blobs in the selected non-bare checkout's pinned commit.

Tooling rows use the existing authoring fields, preserve
`status: "UNVERIFIED"`, leave `executionEvidence` empty, and omit
`caseIds`. Both sources and tests need at least one locator. Each
locator contains `path`, `line`, `symbol`, `supports`, `fileSha256`,
`text`, and `lineSha256`. Use exact, unstripped anchor text. Hash the
UTF-8 line without its terminator and hash the file over its full bytes.
Source areas and gaps can name only the delivery capability. Pins and
anchors establish reference integrity, with verification authority
unassessed and coverage incomplete.
