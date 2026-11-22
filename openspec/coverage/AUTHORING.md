# Evidence contract

Source pin: `0a32a901d1240eec51ddff323274e2ad935116f3`.

Each shard is a JSON object with `schemaVersion: 1`, `sourceRevision`, `owner`, `requirements`, `sourceAreas`, and `knownGaps`.

Each requirement row has `id`, `capability`, `title`, `status` (IMPLEMENTED/PARTIAL/MISSING/UNVERIFIED), `sources` and `tests` arrays, `rationale`, `executionEvidence` array, and `beads` array. Each source/test reference has `path`, `line` (positive integer), `symbol`, and `supports` explaining the enforcing behavior or assertion. Use repo-relative existing paths at the source pin. Evidence from another revision/repo must identify it explicitly and cannot alone establish IMPLEMENTED at the pin.

`sourceAreas` rows have `paths` (explicit existing paths), `capabilities`, and `rationale`. List every assigned product-bearing module, CLI, adapter, unit, script and policy area; use explicit exclusions for fixtures/generated/vendor/nonproduct material. Parent reconciles the complete inventory and task mapping. `knownGaps` rows have `id`, `capabilities`, `description`, `beads`, and `releaseGate`.

Do not invent an assertion, claim a suite ran merely because it exists, copy secrets, or treat a unit name as proof. Every IMPLEMENTED row needs enforcing source and an actual assertion. Hardware coverage stays UNVERIFIED unless named physical evidence is independently available. Proposed decisions are outside the accepted baseline. Requirements state observable behavior; implementation details belong in this ledger.
