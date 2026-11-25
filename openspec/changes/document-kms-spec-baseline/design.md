# Design

## Context

See proposal.md for motivation and the capability catalog. The source baseline is main `0a32a901d1240eec51ddff323274e2ad935116f3`. Existing implementation, accepted design documents, and tests live outside OpenSpec. Local replacement and restore candidates are unmerged and cannot establish delivered behavior. Physical acceptance and first-store authority are unresolved.

## Goals / Non-Goals

**Goals:** Build a navigable behavior contract with stable requirement IDs, source/assertion traceability, and an explicit statement of every known implementation or evidence gap. Account for all tracked source areas and the recorded KMS task inventory.

**Non-Goals:** Runtime changes, retrospective approval of proposals, fabricated test execution, hardware acceptance, production qualification, new ceremony authority, or edits to the genesis-acknowledged single-node limits document.

## Decisions

1. Use the 31 cohesive capability paths in proposal.md. A single huge spec would conceal trust boundaries; a file-per-module spec would describe implementation structure rather than product behavior. Each requirement has a stable catalog prefix and number, SHALL/MUST language, and observable scenarios. Traceability stays in a separate coverage ledger.
2. Document accepted contracts and observed intended behavior. Label coverage IMPLEMENTED only with both a concrete enforcing source location and a concrete assertion; use PARTIAL, MISSING or UNVERIFIED otherwise. IMPLEMENTED is a code-and-assertion coverage classification, not a claim that tests ran in this documentation task or that hardware passed. Record execution evidence and its source revision separately.
3. Keep unapproved first-store authority and fixes in a separate proposed change. The baseline records the accepted fail-closed restoration contract and its gaps, without claiming the local partial guard or a logical model closes them. Never equate an absent TPM reservation, absent disk history, deterministic member IDs, or a skipped condition unit with commissioning authority.
4. Two documentation writers own disjoint delta-spec and coverage files. Runtime owns the first 14 catalog entries; baremetal owns the other 17. Parent owns shared design, proposal, indexing, task/source reconciliation, synchronization and validation. Writers do not stage, commit, push, or edit product files.
5. Coverage evidence uses repo-relative paths at the pinned source revision, line numbers plus symbols/assertions, and an explanation of the behavior enforced. References to unmerged candidates or the tracking repository are explicitly marked. Unknown evidence is retained as a gap, not guessed from a filename or test count.
6. Preserve the five partial local tracking-repository specs and five active changes. Cross-reference them for context, and do not overwrite them or import unapproved draft behavior as accepted KMS requirements.

## Risks / Trade-offs

- [Broad source inventory can hide omissions] → Reconcile every tracked file and every recorded KMS bead to a capability or explicit non-product/deferred disposition; retain unmapped rows as validation failures.
- [Specs can overstate current delivery] → Keep per-requirement coverage and separate execution/physical evidence; review IMPLEMENTED citations before claiming completeness.
- [Parallel writing can conflict] → Fixed ownership and distinct coverage shards; only the parent edits shared artifacts or git state.
- [Source advances during audit] → Freeze source revision and record later changes as reconciliation work rather than silently changing pins.

## Migration Plan

Create delta specs, validate them strictly, review coverage and gap accounting, then synchronize only CLI-reported delta paths into main specs. Validate main specs and local links. Commit documentation on the isolated branch. Existing product files and limits document must remain byte-identical to the source pin. A documentation rollback removes that commit without affecting appliance state.
