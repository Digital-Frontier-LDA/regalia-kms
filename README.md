# Regalia KMS

**A self-hosted, hardware-backed key-management service for the everyday key needs of a small or
medium software company.** Keys are used through one centralized service, rooted in dedicated
hardware you own — SmartCard-HSM tokens (Nitrokey HSM 2 for production, or a Raspberry Pi Pico
running [Pico-HSM](https://github.com/polhenarejos/pico-hsm) for staging), YubiKey PIV, and OpenPGP
cards. Clients call a **mutually-authenticated API** and never receive a PIN, a PKCS#11 path, a key
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
- **Single-signer fencing** — never two active signers across sites. ([`FENCING.md`](FENCING.md))
- **SOPS sidecar** — a local Unix-socket adapter makes Regalia the decryption authority; clients
  hold no age/PGP identities. ([`SOPS-TRANSPORT.md`](SOPS-TRANSPORT.md))

## Backends

| Backend | Transport | Status | Notes |
|---|---|---|---|
| **Nitrokey HSM 2** (SmartCard-HSM) | PKCS#11 | ✅ software · 🚧 production qualification | The designated production HSM (audited NXP firmware). Device-cert identity and on-token key-provenance probes await final hardware sign-off. |
| **Pico HSM** — RP2350 running [Pico-HSM](https://github.com/polhenarejos/pico-hsm) | PKCS#11 | ✅ staging | A fully-capable open-hardware SmartCard-HSM (~$5 board). It *could* hold production keys; Regalia **chooses** not to (policy D1) and reserves production for the Nitrokey — a trust decision, not a capability gap. Firmware/drills: [regalia-ceremony](https://github.com/Digital-Frontier-LDA/regalia-ceremony). |
| **YubiKey PIV** | PIV (`-tags piv`) | ✅ implemented · ⚠️ not wired into the default daemon | Built only under `-tags piv`; the default build links a stub. |
| **OpenPGP card** | PC/SC (`-tags piv`) | 🚧 admission + protocol done; transport/wiring pending | ([`OPENPGP-COMPATIBILITY.md`](OPENPGP-COMPATIBILITY.md)) |
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
- ❌ Promise transparent hot high-availability between two signing devices (see the trade below).
- ❌ Turn rotation/revocation/destruction into unreviewed runtime verbs — those are manifest- and
  ceremony-controlled workflows ([regalia-ceremony](https://github.com/Digital-Frontier-LDA/regalia-ceremony)).

**Not yet**
- ⚠️ **Not production-qualified** — Nitrokey HSM 2 hardware qualification is open.
- ⚠️ **Not a KMIP server** — Regalia exposes its own minimal mTLS API ([`api/openapi.json`](api/openapi.json)), not KMIP.
- ⚠️ **Not a general-purpose cloud KMS** — no cloud/database/disk-encryption integrations.

## Why self-hosted — the trade, stated honestly

Two HSMs you buy once, on hosts you already run, instead of a metered cloud service:

| | AWS CloudHSM | Regalia |
|---|---|---|
| **cost** | ~$25,400/yr (2 HSMs for HA × [$1.45/hr](https://aws.amazon.com/cloudhsm/pricing/) × 8,760 h) | ~€220 once — two Nitrokey HSM 2 (~€99–109 each) |
| **who holds the keys** | the provider, in their regions | you, in your racks |
| **recovery** | provider-dependent | 4-of-6 Shamir shares on metal, offline, no original device needed |

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
| `api/` | OpenAPI contract |
| `config/` | Example configs and the custody-manifest JSON schema |
| `tools/` | Developer tooling (mutation-guard enumerator, inventory, PKCS#11 throughput benchmark) |
| `*.md` | Per-component design docs (`API`, `IDENTITY`, `POLICY`, `ENVELOPE`, `AUDIT`, `OBSERVABILITY`, `FENCING`, `PIN-CUSTODY`, `SOPS-TRANSPORT`, `COSMOS-SUPPORT`, `OPENPGP-COMPATIBILITY`, `TESTING`) |

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
