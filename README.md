# Regalia KMS

**A self-hosted, hardware-backed key-management service for the everyday key needs of a small or
medium software company.** Keys are used through one centralized service, rooted in dedicated
hardware you own — SmartCard-HSM tokens (Nitrokey HSM 2, or a Raspberry Pi Pico running
[Pico-HSM](https://github.com/polhenarejos/pico-hsm), which is supported but not yet qualified),
YubiKey PIV, and OpenPGP cards. Clients call a **mutually-authenticated API** and never receive a PIN, a PKCS#11 path, a key
handle, or raw key bytes. Every operation is authenticated, policy-checked, and written to a
tamper-evident audit log. No cloud KMS, no vendor-held custody, no per-call billing.

Written in Go. Single binary. Fail-closed by default.

> ⚠️ **Status: pre-production / pre-1.0.** The software — API, operation stack, policy/registry,
> audit, envelope storage, and the PKCS#11 backend — is implemented and covered by an extensive Go
> test suite (unit, contract, property, and mutation-swept guards). **Production hardware
> qualification (Nitrokey HSM 2) is not yet complete.** Use it for development, testing, and staging;
> don't protect production keys with it yet. See [does / doesn't do](#what-it-does--doesnt-do).

## What it covers

One device serving every cryptographic role a small company actually has:

| Capability | What it's for | Evidence boundary |
|---|---|---|
| **SOPS data-key wrap/unwrap** | secrets, commit & release signing via [SOPS](https://github.com/getsops/sops)/GPG | local + E2E-tested KMS adapter |
| **Signing** (release, commit, SSH, wallet) | purpose-shaped signing over a policy-gated API | KMS signing API + policy |
| **X.509 CA / key agreement** | internal certificate issuance, service TLS | operation stack + E2E coverage |
| **Opaque secrets** (API tokens, passwords, symmetric keys) | hardware-rooted envelope custody | seal, release, and re-wrap |
| **Cosmos / Akash wallet ops** | secp256k1 transaction signing (optional) | SignDoc binding; policy gates apply |
| **RBAC · mTLS · policy · fencing · audit** | the control plane around all of the above | implemented contracts; production gates explicit |

"Covered" ≠ "production-qualified" — see the backend status below.

## Features

- **Operations execute on the token.** Signatures and certificate signing never expose the private
  key. Opaque secrets get hardware custody via **AES-256-GCM** data keys wrapped by a hardware-held
  KEK; plaintext is size- and lifetime-bounded and zeroized after use. ([`ENVELOPE.md`](ENVELOPE.md))
- **mTLS identity + purpose-bound policy.** The caller *is* its verified certificate chain — no
  bearer tokens, no shared secrets — and a declarative registry decides who may do what, to which
  object, for which purpose. ([`IDENTITY.md`](IDENTITY.md), [`POLICY.md`](POLICY.md), [`config/REGISTRY.md`](config/REGISTRY.md))
- **Tamper-evident audit** — a hash-chained journal, shippable off-host. ([`AUDIT.md`](AUDIT.md))
- **Serving by majority lease** (decided, ADR-0002 D32, not built): every server serves while it holds its own lease, which 2 of the 3 servers co-sign. Stateful operations commit on a majority before the HSM is used. Today's code still runs the superseded single-signer fence. ([`FENCING.md`](FENCING.md))
- **SOPS sidecar** — a local Unix-socket adapter makes Regalia the decryption authority; clients
  hold no age/PGP identities. ([`SOPS-TRANSPORT.md`](SOPS-TRANSPORT.md))

## Backends

Three token configurations are supported — Pico HSM alone, Pico HSM + YubiKey, and Nitrokey HSM 2 +
YubiKey. What each can serve, and which are qualified, is in [`CONFIGURATIONS.md`](CONFIGURATIONS.md).

| Backend | Transport | Status | Notes |
|---|---|---|---|
| **Nitrokey HSM 2** (SmartCard-HSM) | PKCS#11 | ✅ software · 🚧 production qualification | The designated production HSM (audited NXP firmware). Device-cert identity and on-token key-provenance probes await final hardware sign-off. |
| **Pico HSM** — RP2350 running [Pico-HSM](https://github.com/polhenarejos/pico-hsm) | PKCS#11 | ✅ software · 🚧 not qualified | An open-hardware SmartCard-HSM (~$5 board), supported as a key-holding HSM but with no qualified stack yet ([`CONFIGURATIONS.md`](CONFIGURATIONS.md)). Digital Frontier's own fleet reserves production for the Nitrokey (policy D1) — a trust decision. Firmware/drills: [regalia-ceremony](https://github.com/Digital-Frontier-LDA/regalia-ceremony). |
| **YubiKey PIV** | PIV (`-tags piv`) | ✅ implemented · ⚠️ not wired into the default daemon | Built only under `-tags piv`; the default build links a stub. P-256, P-384, RSA-2048 and, on firmware 5.7 and later, Ed25519. Beside the PKCS#11 backend it needs OpenSC to ignore the YubiKey ([`deploy/opensc/ignore-yubikey.conf`](deploy/opensc/ignore-yubikey.conf)). |
| **YubiKey OpenPGP applet** | PKCS#11, through OpenSC's OpenPGP card driver | ✅ served for Ed25519 signing · 🚧 not qualified | An alternative home for an Ed25519 key, for a host that does not serve its YubiKeys through PIV (PIV slots are the default home). Needs a `local-usb` attestation and a `token_label` ([`OPENPGP-COMPATIBILITY.md`](OPENPGP-COMPATIBILITY.md)). The hand-written PC/SC adapter in `internal/backend/openpgp` is not served. |
| Software / file-based KEK | — | ❌ refused in production **by design** | Production KEKs must be non-exportable hardware keys; there is no software fallback. |

## What it does / doesn't do

**Does**
- ✅ Root every production key operation in hardware, with **no software key-material fallback**.
- ✅ Authenticate every client by mTLS; gate every operation by declarative, purpose-bound policy.
- ✅ Give hardware custody to non-token-native secrets via wrapped envelopes.
- ✅ Produce a tamper-evident audit trail and enforce single-signer fencing.
- ✅ Act as the SOPS decryption authority and sign Cosmos-SDK transactions.

**Deliberately doesn't**
- ❌ Export private keys, recovery sources, token credentials, or unwrapped KEKs.
- ❌ Let clients choose a reader, slot, backend, or arbitrary mechanism.
- ❌ Fall back to software cryptography or another token in production.
- ❌ Authenticate human administrators through the cryptographic-operation API.
- ❌ Manage public TLS certificates: no ACME client, DNS-provider API or certificate distribution
  ([`CERTIFICATES.md`](CERTIFICATES.md)).
- ❌ Promise transparent hot high-availability between two signing devices (see the trade below).
- ❌ Turn rotation/revocation/destruction into unreviewed runtime verbs — those are manifest- and
  ceremony-controlled workflows ([regalia-ceremony](https://github.com/Digital-Frontier-LDA/regalia-ceremony)).

**Not yet**
- ⚠️ **The full list of current limitations** (not built, not measured, accepted risks) is in [`LIMITATIONS.md`](LIMITATIONS.md).
- ⚠️ **Not production-qualified** — Nitrokey HSM 2 hardware qualification is open.
- ⚠️ **No OpenBao plugin yet** — the contract it will meet is [`OPENBAO-COMPATIBILITY.md`](OPENBAO-COMPATIBILITY.md); nothing in it is a support claim until its real-server tests pass.
- ⚠️ **Not a KMIP server** — Regalia exposes its own minimal mTLS API ([`api/openapi.json`](api/openapi.json)), not KMIP.
- ⚠️ **Not a general-purpose cloud KMS** — no cloud/database/disk-encryption integrations.

## 1 node or 3 nodes?

Regalia KMS is designed for three nodes at three sites, and a one-node deployment is being added as a supported
topology (regalia-kms-dx7, [design](docs/design/single-node.md)). The node count is chosen at genesis and signed into
the membership manifest; it is never inferred from how many nodes answer. Some guarantees do not exist on one node,
and the operator acknowledges them at genesis.

**Status on `main`: a one-node deployment is not built.** Built: the membership format only. Schema
`regalia.membership/v5` carries the root-signed `topology` and validates a one-node manifest, in Python and Go
(dx7.1, #734). Not built: everything else. `manifest propose --genesis` still writes a v4 manifest with thresholds
of 2 (`deploy/baremetal/manifest.py`), so a one-node genesis cannot even be proposed, and no lease, unlock, update
or recovery path knows the profile. The table is the design; each row's status is in [LIMITATIONS](LIMITATIONS.md#single-node-deployments).

The table is copied from [`docs/single-node-limits.md`](docs/single-node-limits.md), the text the operator
acknowledges at genesis, and a test keeps the two equal. **supported**: the guarantee holds as on three nodes;
**degraded**: it works, with the consequence named; **not supported**: it does not exist on one node.

| Feature or guarantee | 1 node | 3 nodes | Consequence with 1 node |
|---|---|---|---|
| Signing and decryption (stateless operations) | supported | supported | One HSM per node holds the keys either way |
| Stateful operations (approval spend-once, Cosmos sequence, key state) | degraded | supported | Committed to a single-member etcd on one disk, with no replica: a lost disk loses the latest spends. A restore raises the state epoch, and the audit collector detects a re-spend; it does not prevent one. Refused while no audit collector is configured |
| Activation (who may serve) | degraded | supported | The node activates itself (1 of 1): no second signer can refuse a root-compromised node |
| Runtime lease (a revoked or cut-off node stops within 30 s) | degraded | supported | Self-issued: it still binds the measured boot and the current state, but nobody outside the node can withhold it |
| Survives the loss of a node | not supported | supported | Any node failure, reboot or maintenance is a full outage of the KMS |
| Survives a site, provider or network-path outage | not supported | supported | One site is a single failure domain |
| Unattended reboot | not supported | supported | Every boot needs the owner's card, or the disk recovery key. A power cut means downtime until the owner acts |
| Theft of a powered-off node | supported | supported | The disk opens only with the owner's contribution (3 nodes: a peer's), so a stolen box does not unlock |
| Theft of a running node (hot theft) | degraded | supported | No peer stops leasing it: it serves until it loses power or the owner's revocation is imported on that node, so a revocation does not reach a stolen node that is no longer reachable |
| Root compromise of the node | not supported | degraded | The node is its only signer (3 nodes: no lease without two co-signers) |
| Retiring an old signed boot image | supported | supported | The owner's unlock tool refuses an image the manifest no longer lists (3 nodes: the peers) |
| Revocation | degraded | supported | The owner alone revokes. Revoking or quarantining the only node stops the KMS |
| Heartbeats | degraded | supported | Self-signed: they prove only the node's own freshness, with no peer bound to stop helping a revoked node |
| Rolling measured-boot update | degraded | supported | Each reboot is a planned outage, with the owner present to judge the new image |
| Site advance (PCR 12) | degraded | supported | The same: a planned outage, and the owner judges the new site configuration |
| Rollback protection of the membership (TPM anchor) | supported | supported | The TPM counter and record work on one node |
| Re-anchor after anchor damage | degraded | supported | From the owner's copy of the chain, cross-checked against the audit collector, instead of two independent nodes. A compromised owner laptop can roll the node back, but not below what the collector saw. A compromised laptop and a compromised collector together are not bounded |
| Recovery after a total outage | degraded | supported | One owner-attended boot. There is no rest of the cluster to restore from, and anchor damage is the re-anchor row above |
| Lone-survivor mode, fencing, take-over, rejoin | not supported | supported | Nothing to survive or fence: each is refused, naming the profile |
| Cross-node detection (fleet alerts, a withheld chain) | not supported | supported | No fleet to compare with. Replaced by comparison with the audit collector |
| Audit trail | supported | supported | The external audit collector is mandatory: it is the only witness besides the owner |
| Operation approvals (m-of-n card holders) | supported | supported | Not bound to nodes. An approval names the one node, with no failover |
| Key backup and restore (DKEK, Shamir) | supported | supported | Unchanged. With no peer, a restore onto a replacement node is the recovery path |
| Latency of stateful operations | supported | supported | No majority round trip: faster than 3 nodes |

## Why self-hosted — the trade, stated honestly

Two HSMs you buy once, on hosts you already run, instead of a metered cloud service:

| | AWS CloudHSM | Regalia |
|---|---|---|
| **cost** | ~$25,400/yr (2 HSMs for HA × [$1.45/hr](https://aws.amazon.com/cloudhsm/pricing/) × 8,760 h) | ~€220 once — two Nitrokey HSM 2 (~€99–109 each) |
| **who holds the keys** | the provider, in their regions | you, in your racks |
| **recovery** | provider-dependent | k-of-n Shamir shares (4-of-6 by default) on metal, offline, no original device needed |

What you give up — this is a real trade, not a free lunch:
- **Throughput:** ~12–14 signatures/sec (with a large spread by key type), not thousands. Fine for
  treasury ops, secrets, and a CA; not for high-volume token issuance.
- **Availability:** cold standby with a human RTO of hours, not managed multi-AZ failover — a
  deliberate choice, because two hot signers on one account is worse than an outage.
- **No FIPS 140-2 Level 3 validation.** If you're procuring against that box, this isn't it.
- **You are the support contract.**

If your key operations are treasury-scale rather than transaction-scale, the trade is
overwhelmingly favourable. If not, buy the managed service.

## Quick start

```sh
go build ./...            # Go 1.26+
go test ./...
go run ./cmd/regalia-kms -listen 127.0.0.1:8443   # loopback dev mode
```

The daemon serves mutual TLS once `tls_certificate_path`, `tls_private_key_path`, and
`tls_client_ca_path` are set, and refuses a non-loopback listener without them. Configuration is one
strict JSON object (≤32 KiB) with **no** fields for PINs, credentials, or key material; examples in
[`config/`](config/). The YubiKey PIV backend compiles only under `-tags piv`.

## Repository layout

| Path | What it is |
|---|---|
| `cmd/regalia-kms/` | Daemon entry point |
| `internal/` | Server, operations, backends (PKCS#11 / PIV / OpenPGP), registry, policy, audit, fencing, envelope |
| `adapters/sops/` | SOPS key-service sidecar adapter (separate Go module) |
| `adapters/gpgsign/` | `regalia-sign`: OpenPGP release, commit and tag signatures from a KMS-held key (separate Go module) |
| `api/` | OpenAPI contract |
| `config/` | Example configs and the custody-manifest JSON schema |
| `tools/` | Developer tooling (mutation-guard enumerator, inventory, PKCS#11 throughput benchmark) |
| `*.md` | Per-component design docs (`API`, `IDENTITY`, `POLICY`, `ENVELOPE`, `AUDIT`, `OBSERVABILITY`, `FENCING`, `PIN-CUSTODY`, `SOPS-TRANSPORT`, `COSMOS-SUPPORT`, `CONFIGURATIONS`, `OPENPGP-COMPATIBILITY`, `OPENBAO-COMPATIBILITY`, `CERTIFICATES`, `TESTING`, `LIMITATIONS`) |

## Security

- **No secrets in the repository.** Secret scanning runs over the whole tree with content-only
  allowlists (never path allowlists). See [`.gitleaks.toml`](.gitleaks.toml).
- **Report vulnerabilities** privately via GitHub Security Advisories, not a public issue.

## Related

- [regalia-ceremony](https://github.com/Digital-Frontier-LDA/regalia-ceremony) — air-gapped Qubes
  key-ceremony tooling, the Pico HSM staging emulator, and the RP2350 firmware work.

## Design records

Some code comments and docs cite internal design records (`ADR-0001`, the threat model, requirements)
that live in the operators' private repository and are not part of this release. The in-repo `*.md`
files are self-contained for understanding and using the code.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
