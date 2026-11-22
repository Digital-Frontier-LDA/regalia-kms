# Tasks

## 1. Stabilize the local CLI surface

- [x] 1.1 Add full-option, omitted/unknown/shortened-option and help entrypoint tests. Check JSON success/refusal separately from argparse exit 2 and help exit 0, including stdout/stderr and no input read on help.
- [x] 1.2 Apply the proposed exact-name policy and keep the current schema, reference and non-authorizing outputs. Verify the parser regressions and focused checker suite, catch a parser regression with the abbreviation guard removed, and refresh the local tooling trace with the tested candidate bytes.

## 2. Prepare pinned CI inputs

- [x] 2.1 Add the bounded second checkout and local commit/type/tree preflight at the tail of build-test, with the original HEAD unchanged. Exercise good, absent and wrong-source fixtures, a reserved-directory collision, and no-lazy-fetch refusal. Document the source-preparation boundary.
- [x] 2.2 Add the isolated OpenSpec manifest and reviewed integrity lock. Verify the documented Node archive checksum, exact Node/npm/OpenSpec versions and locked install with lifecycle scripts disabled. Verify the selected Python action asset and exact interpreter. Prove these checks fail on missing or mismatched pins.

## 3. Wire and falsify the finite CI slice

- [x] 3.1 Add strict validation, focused unittest discovery and the reference command to existing build-test. Show a valid snapshot with open gaps passes, and invalid OpenSpec, a broken reference and nonconforming schema each fail for their intended reason. Keep the existing job graph and permissions.
- [x] 3.2 Add a workflow wiring regression that reads the actual YAML and exercises the extracted check step's status propagation. In isolated copies catch removal of strict validation, suppression of the checker failure and replacement of the immutable pin. Require baseline, no-op and restored runs with fresh caches.

## 4. Verify hosted execution

- [ ] 4.1 After authorized publication, record the exact evaluated commit and tree, PR head if distinct, workflow run/attempt and build-test job ID, all phase results and timings, tool/pin output and the checker JSON boundary. Verify the aggregate consumes build-test. Retain hosted proof as tooling evidence, with coverage gaps and separate review obligations open.

## Workflow follow-up

- Keep the change separate from the frozen baseline. Any later baseline synchronization or archive that changes main/delta parity needs coordinated authoring and source-trace review.
