# Proposal

## Why

The dx7.26 review identifies four blockers that allow missing history, incomplete commissioning, or service ordering to be mistaken for permission to serve. Single-node v0.1 cannot pass lost-disk restoration acceptance until first genesis is distinguishable from erased or substituted history and the complete startup path enforces that distinction.

## What Changes

- Introduce a first-store commissioning lifecycle that binds one-use authority to the exact TPM identity, signed genesis, device selection and NV allocation; used or unknown-custody hardware requires independent durable authority.
- Enforce existing-history-only recovery for normal startup, signed-restore staging and legacy adoption at actual etcd opens. Only a consumed first-store permit can create initial history; a fresh session nonce cannot create a new permit slot.
- Require every boot-eligible operational image, including rollback, to enforce the pending deny and history floor; incompatible images remain fenced.
- Make staged activation single-use and keep the durable KMS deny through exchange and successful normal-store verification.
- Add a real credential producer and verify key/certificate binding, service delivery and access before consuming commissioning authority.
- Add real pinned-etcd, systemd, software-TPM and physical acceptance gates for each review finding. Preserve signed restore, topology restrictions and existing multi-node/package contracts.
- **BREAKING:** Unmarked legacy stores or used TPMs with no independent authority cannot be silently adopted or treated as fresh genesis. They require an explicit authenticated adoption/restore procedure.

## Capabilities

### New Capabilities

- `baremetal/first-store-commissioning`: Authority consumption, store provenance, staged activation and readiness for the transition from uncommissioned hardware to an operational member. This cohesive lifecycle complements the baseline enrolment, etcd and restore contracts; it does not replace those general capabilities.

### Modified Capabilities

None. The main baseline is being authored separately; this proposed lifecycle is not a claim of delivered behavior and must not be synchronized into the baseline before implementation and acceptance.

## Impact

Likely implementation areas: deploy/baremetal/{enrol,membership,recount,restore,etcdconf,takeover}.py, node lifecycle coordination, bare-metal systemd units, image build/pinned etcd, protected profile/history records, credential tooling, KMS state-readiness configuration, and corresponding tests. Exact source baseline: 0a32a901d1240eec51ddff323274e2ad935116f3. No product code, hardware state, authority approval, production ceremony or existing limits document is changed by this planning change.
