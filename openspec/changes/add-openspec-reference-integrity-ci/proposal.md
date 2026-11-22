# Proposal

## Why

The local OpenSpec checker already resolves current declarations against explicit sources, but a broken reference can still enter CI without failing the build. The docs baseline is strict-valid, so syntax and reference integrity can be enforced independently of the incomplete coverage ratchet.

## What Changes

- Document the bounded helper CLI, its separate JSON and argparse channels, the supported reference inputs, and the non-authorizing result.
- Prefer exact long option names for this interface. **BREAKING for abbreviated invocations of the local candidate** if the proposed parser hardening is applied.
- Plan strict OpenSpec validation, focused checker tests and the offline reference command inside the existing build-test job. Provision the immutable product commit separately from the workflow checkout.
- Keep coverage verification, exclusions, legacy budgets, changed-interface enforcement, and unrelated commissioning authority outside this change.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- delivery/software-build-and-ci gains the reference checker contract and the finite build-test integration contract.

## Impact

The planned implementation affects the helper parser and tests, the CI toolchain pins and lock, and steps inside build-test. The local implementation currently lives at docs commit f66a5cd6a3bdf223baf5d46d9622739d868ea29a. The frozen product reference revision remains 0a32a901d1240eec51ddff323274e2ad935116f3. Candidate inventory and future hosted observations remain separate from product-baseline acceptance. The proposal does not change the existing workflow trigger, job graph, permissions or forge settings.
