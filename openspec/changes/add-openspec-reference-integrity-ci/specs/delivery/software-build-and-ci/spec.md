## ADDED Requirements

### Requirement: KMS-CI-009 Validate OpenSpec reference integrity

The local checker SHALL validate current declared references against the supplied snapshot and explicit pinned source. A check SHALL emit JSON with its integrity outcome and leave verification authority unassessed and coverage incomplete. Command-line help and usage diagnostics SHALL be separate from checked JSON output.

#### Scenario: Current references resolve

- **WHEN** the caller supplies the complete snapshot, local source repository and full product revision options, and the declared references resolve
- **THEN** the checker returns exit 0 and a JSON object with referenceIntegrity true, verificationAuthority not-assessed, coverageComplete false, counts and input hashes.

#### Scenario: Expected input or reference checks fail

- **WHEN** an invocation reaches checking and its snapshot, required local source commit, declared reference or required offline cache entry is missing, malformed or differs from the bound input
- **THEN** the checker returns exit 1 and JSON with referenceIntegrity false and a diagnostic, with verificationAuthority not-assessed and coverageComplete false.

#### Scenario: A required option is missing or a long option is abbreviated

- **WHEN** the caller does not request help and omits a required option, uses an unrecognized option, or uses a shortened long option name
- **THEN** the command-line parser returns exit 2 with usage information on stderr and emits no checked JSON.

#### Scenario: Help displays usage

- **WHEN** the caller supplies -h or --help alone
- **THEN** the parser returns exit 0 with usage and the option descriptions on stdout and performs no reference check.

#### Scenario: Nonconforming versioned JSON refuses

- **WHEN** a consumed versioned document supplies a schema version other than JSON integer 1, or any consumed JSON includes a duplicate key or NaN, Infinity or -Infinity as an unquoted value
- **THEN** the checker returns the exit 1 refusal form even when the value appears in opaque metadata.

#### Scenario: A scenario name belongs under a different requirement

- **WHEN** a case reference names a scenario that exists only under another requirement, or uses a proposed-only scenario as a direct baseline reference
- **THEN** the checker returns the exit 1 refusal form.

#### Scenario: Product candidate and external source domains stay distinct

- **WHEN** a current reference names pinned product bytes, candidate test content or an external descriptor
- **THEN** it resolves only in its declared source domain. A missing pinned product blob, candidate without its current record and matching hash, or external descriptor without its bound offline cache entry returns the exit 1 refusal form.

#### Scenario: Historical and metadata records supply context only

- **WHEN** the snapshot contains older scenario pointers, superseded candidate references, inactive proposals or evidence and review metadata
- **THEN** the checker applies the declared reference treatment for each input, keeps related and proposed-only pointers separate from direct baseline links, and derives no authority or coverage verification from those records.

### Requirement: KMS-CI-010 Enforce the finite OpenSpec checks in build-test

The existing build-test job SHALL require strict validation of the main specs and active OpenSpec changes with the pinned CLI, the focused checker tests, and a successful reference check with locally present pinned product objects. Any required preparation or check failure SHALL fail build-test.

#### Scenario: Strict syntax and references pass

- **WHEN** an eligible build-test run reaches the OpenSpec checks with the pinned toolchain and exact product source locally available
- **THEN** it runs strict validation, the focused tests and the reference check. They can succeed with declared legacy gaps still open and without changing the checker authority fields.

#### Scenario: The product pin is absent or wrong

- **WHEN** preparation cannot establish the required product commit and tree in the local source repository
- **THEN** build-test fails and does not substitute the workflow checkout revision or use network fallback in the checker.

#### Scenario: A required check fails

- **WHEN** strict validation rejects a specification, a focused test fails, or the reference checker returns nonzero
- **THEN** build-test fails and the aggregate observes its failure using the existing job dependency.
