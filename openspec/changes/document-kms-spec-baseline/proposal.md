# Proposal

## Why

The repository has substantial runtime, bare-metal and release contracts but no complete OpenSpec baseline. A source-traceable baseline is needed to distinguish delivered behavior, accepted requirements with known gaps, hardware evidence still pending, and unapproved designs before planning release work.

## What Changes

- Record the existing and accepted KMS contract in cohesive capability specifications with stable requirement IDs and positive/refusal scenarios. This changes documentation only, not product behavior.
- Add a coverage matrix with source/test evidence and IMPLEMENTED, PARTIAL, MISSING or UNVERIFIED status; preserve known defects and physical acceptance gaps.
- Map every tracked KMS task and every product-bearing source area to a capability or explicit scope disposition.
- Cross-reference existing partial tracking-repository OpenSpec and accepted design/limitation documents without overwriting or silently approving them.
- Keep the dx7.26 commissioning choices in a separate proposed change and retain owner-only ceremony, hardware and production gates.

## Capabilities

### New Capabilities

- `runtime/api-and-configuration`: Operation API, errors, input limits and daemon configuration.
- `runtime/authentication`: Client identity, certificate/SPIFFE validation and principal mapping.
- `runtime/authorization-and-approvals`: Policy decisions, contextual authorization, approval binding and expiry.
- `runtime/key-registry-and-custody`: Registry object/binding validation, custody and backend-slot isolation.
- `runtime/cryptographic-operations`: Sign, decrypt, wrap and hardware-result semantics.
- `runtime/envelopes-and-secret-release`: Envelope AEAD, KEK use and secret-release boundaries.
- `runtime/cosmos-policy`: SignDoc/fee parsing, signing contract and supported transaction scope.
- `runtime/policy-state-journal`: Spend-once, replay/quota/sequence state and recovery contracts.
- `runtime/backends-and-token-lifecycle`: PKCS11, HSM/OpenPGP/PIV providers, PIN custody and token lifecycle.
- `runtime/client-adapters`: SOPS and GPG adapters and explicitly partial OpenBao integrations.
- `runtime/audit-and-collector`: Hash chains, audit shipping/receipts, completeness and reconciliation.
- `runtime/observability`: Metrics, health endpoints, alerting and operational diagnostics.
- `runtime/service-integration`: Process lifecycle, executor bounds and operational-state integration.
- `delivery/software-build-and-ci`: Pinned inputs, reproducibility, feature flags, CI proof and release checks.
- `baremetal/membership-and-topology`: Signed membership, immutable topology, quorum and epoch/tombstone rules.
- `baremetal/tpm-identity-and-attestation`: EK/AK/node identities, TPM counters, fresh quotes and enrollment proof.
- `baremetal/measured-boot-and-pcr-policy`: Signed UKIs, measurements, PCR authorization and imported credentials.
- `baremetal/enrolment-and-config-publication`: Checked enrolment, trust anchors, configuration ordering and resume.
- `baremetal/boot-network-and-unlock`: Initrd network, peer unlock, key delivery and cleanup.
- `baremetal/single-node-owner-unlock`: Owner contribution and attended single-node boot.
- `baremetal/runtime-leases-and-admission`: Measured runtime leases, local self-lease and admission.
- `baremetal/activation-and-fencing`: Activation quorum, overlap restrictions, fencing and recovery authorization.
- `baremetal/etcd-and-operational-state`: Member configuration, state history, startup and client access.
- `baremetal/recovery-and-restoration`: Signed epoch-raising restore, pending state and crash-safe recovery.
- `baremetal/replacement-and-revocation`: Restrictive revocation, fresh replacement, retired hardware rejection.
- `baremetal/update-and-site-advance`: Image approval, rolling/planned-outage updates and site transitions.
- `baremetal/offline-authorities-and-credentials`: Root/owner authorities, offline records and sealed credential handoff.
- `baremetal/appliance-and-service-hardening`: Verity/per-host etc, service users, firewall, AppArmor and storage.
- `delivery/hardware-qualification`: Real TPM/HSM/card/firmware qualification and evidence boundaries.
- `delivery/release-milestones`: Single-node TEST, three-node TEST and separate production acceptance.
- `security/threat-model-and-limitations`: Trust boundaries, topology limitations, scope and approved decisions.

### Modified Capabilities

None: this is the initial OpenSpec baseline. Existing behavior and approved contracts are documented, not widened.

## Impact

Documentation under openspec/ only, grounded in main0a32a901d1240eec51ddff323274e2ad935116f3. Runtime, adapters, tools, bare-metal deployment, CI and hardware acceptance are in the coverage inventory. No source-code edits, new operational authority, hardware action, production approval, or mutation of the genesis-acknowledged single-node limits document is included.
