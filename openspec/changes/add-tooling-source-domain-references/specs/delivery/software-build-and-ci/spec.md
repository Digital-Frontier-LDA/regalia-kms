## ADDED Requirements

### Requirement: KMS-CI-011 Resolve an explicitly pinned tooling authoring domain

The reference checker SHALL resolve an explicitly declared tooling authoring shard against its own local Git commit and tree. The existing product inputs SHALL remain the source for legacy authoring. Tooling references SHALL validate exact scope and bytes. Reference integrity SHALL leave verification authority unassessed and coverage incomplete.

#### Scenario: A legacy caller checks a product-only snapshot

- **WHEN** the snapshot has neither the tooling authoring shard nor any adopted KMS-CI-009 through KMS-CI-012 requirement and the caller supplies the three existing options
- **THEN** the checker retains the existing result schema, exit behavior and product-reference resolution, and performs no tooling lookup

#### Scenario: CLI help and usage remain separate from checking

- **WHEN** the caller requests help, uses an abbreviated or unknown long option, or supplies just one of `--tooling-source-repo` and `--tooling-source-revision`
- **THEN** help lists both new options, returns exit 0 and reads no snapshot or repository. Malformed usage without help returns exit 2 with usage on stderr and emits no checked JSON

#### Scenario: Tooling is enabled by the declared shard and exact pair

- **GIVEN** `openspec/coverage/tooling-authoring.json` declares the version-1 tooling domain, its full commit ID and tree
- **WHEN** the caller supplies both tooling options, the full revision matches, the explicit local repository contains the bound commit and tree, the repository is a non-bare checkout root (including a linked worktree), and each eligible locator resolves
- **THEN** the checker returns the successful reference envelope and includes `toolingSourceRevision` and `toolingSourceTree` for the independently resolved tooling input

#### Scenario: Declaration or local pin does not match

- **WHEN** a declared tooling shard lacks the CLI pair, the pair accompanies a snapshot with no tooling declaration, or the supplied local repository, commit or tree is absent, unqualified or mismatched, including a bare repository, selected subdirectory or symlink root
- **THEN** the checker emits the exit 1 integrity refusal with a diagnostic identifying the missing declaration or binding. It uses no working-tree, product-domain, transport or lazy-fetch fallback

#### Scenario: Tooling authoring is restricted to its declared contribution

- **WHEN** tooling authoring participates in the baseline
- **THEN** its declared tooling owner joins only the existing runtime-owned delivery capability requirements KMS-CI-009 through KMS-CI-012. Each ID has exactly one matching title and authoring row in the common baseline. Only declared regular paths in the tooling scope can supply its source and test anchors. Existing catalog owners, case origins and product source selection are preserved

#### Scenario: Adopted tooling cannot use the legacy authoring path

- **WHEN** any of KMS-CI-009 through KMS-CI-012 is registered in the baseline but the four-ID set or tooling shard is absent, or a legacy shard claims a tooling ID
- **THEN** the checker returns the exit 1 integrity refusal rather than treating the snapshot as product-only or resolving those IDs through product authoring

#### Scenario: Version, scope or anchor binding is invalid

- **WHEN** a tooling shard uses an unsupported JSON version or shape, changes its domain or owner, claims an ineligible capability, requirement or path, duplicates an authoring identity, or supplies a missing or mismatched file hash, line, exact anchor text or anchor hash
- **THEN** the checker returns the exit 1 reference refusal and identifies the violated binding. A match at the same path in a different source domain does not satisfy the claim

#### Scenario: Tooling source observation carries no verification authority

- **WHEN** a tooling locator validates or a record references a historical hosted observation
- **THEN** the result retains `verificationAuthority=not-assessed` and `coverageComplete=false`. No observation changes canonical case ownership, classification, or accepted evidence scope

### Requirement: KMS-CI-012 Prepare immutable tooling source for reference checks

The existing build-test workflow SHALL prepare a separate, immutable local tooling Git checkout when the snapshot declares tooling authoring. A declared tooling input SHALL pass commit and tree preflight before reference checking. A preparation or check failure SHALL fail build-test and reach the existing aggregate.

#### Scenario: A declared tooling pin is prepared before checking

- **WHEN** an eligible build-test run has a valid tooling declaration
- **THEN** it reserves an unused separate location, checks out the declared commit from the same repository without persisting credentials, verifies the commit and tree locally and supplies the tooling pair to the reference checker. The product checkout and primary analyzed revision retain their separate identities

#### Scenario: A legacy snapshot needs no tooling fetch

- **WHEN** a snapshot has no tooling declaration and has no adopted tooling requirements
- **THEN** build-test makes no tooling checkout and still runs the existing strict, test and product-reference checks

#### Scenario: Declared preparation fails closed

- **WHEN** the declaration is malformed, the reserved location is occupied, the exact same-repository commit cannot be prepared, or preflight detects a wrong commit, tree or primary checkout identity
- **THEN** build-test fails without substituting product or primary objects and does not report a passed reference check. The existing aggregate observes the build-test failure

#### Scenario: The checker detects a post-preparation binding error

- **WHEN** a prepared job reaches the checker and the declared tooling bindings fail to resolve, or the checker reports an unsuccessful result
- **THEN** build-test fails through its existing required check path and the aggregate observes the failure
