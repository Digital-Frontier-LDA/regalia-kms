# Regalia KMS

**A hardware-backed key-management service.** Regalia KMS keeps private keys on dedicated hardware —
SmartCard-HSM tokens (Nitrokey HSM 2 for production, or a Raspberry Pi Pico running
[Pico-HSM](https://github.com/polhenarejos/pico-hsm) for staging), YubiKey PIV, and OpenPGP cards —
and exposes signing, key-wrapping, and opaque-secret release over a **mutually-authenticated API**.
Clients never receive a PIN, a PKCS#11 path, a key handle, or raw key bytes; every operation is
authenticated, policy-checked, and written to a tamper-evident audit log.

Written in Go. Single binary. Fail-closed by default.

> ⚠️ **Status: pre-production.** The software — API, operation stack, policy/registry, audit,
> envelope storage, and the PKCS#11 backend — is implemented and covered by an extensive Go test
> suite (unit, contract, property, and mutation-swept guards). **Production hardware qualification
> (Nitrokey HSM 2) is not yet complete.** Do not protect production keys with it yet — see
> [What it does / doesn't do](#what-regalia-kms-does--doesnt-do).

## Features

**Cryptographic operations — on the token**
- Digital signatures and certificate signing execute on the HSM; the private key never leaves it.
- **Envelope storage for opaque secrets** (API tokens, passwords, symmetric keys): a hardware-held
  KEK wraps per-secret **AES-256-GCM** data keys, so non-token-native secrets still get hardware
  custody. Plaintext is size- and lifetime-bounded and zeroized after use. ([`ENVELOPE.md`](ENVELOPE.md))
- Key rotation by re-wrap, without changing ciphertext.

**Access control & governance**
- **Mutual-TLS client identity** — the caller *is* its verified certificate chain; no bearer tokens,
  no shared secrets. ([`IDENTITY.md`](IDENTITY.md))
- **Purpose-bound policy** over a declarative custody registry: which principal may perform which
  operation on which object, for which purpose. ([`POLICY.md`](POLICY.md), [`config/REGISTRY.md`](config/REGISTRY.md))
- **Tamper-evident audit** — a hash-chained journal, shippable off-host. ([`AUDIT.md`](AUDIT.md), [`OBSERVABILITY.md`](OBSERVABILITY.md))
- **Single-signer fencing** — never two active signers across sites. ([`FENCING.md`](FENCING.md))

**Integrations**
- **SOPS** — a local Unix-socket sidecar makes Regalia the decryption authority for
  [SOPS](https://github.com/getsops/sops)-encrypted files; clients hold no age/PGP identities.
  ([`SOPS-TRANSPORT.md`](SOPS-TRANSPORT.md), [`adapters/sops/`](adapters/sops/))
- **Cosmos / Akash** — SignDoc binding and digest handling for Cosmos-SDK transaction signing.
  ([`COSMOS-SUPPORT.md`](COSMOS-SUPPORT.md))

## Backends

| Backend | Transport | Status | Notes |
|---|---|---|---|
| **Nitrokey HSM 2** (SmartCard-HSM) | PKCS#11 | ✅ software · 🚧 production qualification | The intended production HSM. Device-cert identity and on-token key-provenance probes await final hardware sign-off. |
| **Pico HSM** — RP2350 running [Pico-HSM](https://github.com/polhenarejos/pico-hsm) | PKCS#11 | ✅ staging | An open-hardware SmartCard-HSM (~$5 board) for development/staging. Under policy D1 a Pico measurement never informs a production decision. Firmware patches, upstream fixes, and hardware drills live in [regalia-ceremony](https://github.com/Digital-Frontier-LDA/regalia-ceremony). |
| **YubiKey PIV** | PIV (`-tags piv`) | ✅ implemented · ⚠️ not wired into the default daemon | Built only under `-tags piv`; the default build links a stub. |
| **OpenPGP card** | PC/SC (`-tags piv`) | 🚧 admission + protocol done; transport/wiring pending | ([`OPENPGP-COMPATIBILITY.md`](OPENPGP-COMPATIBILITY.md)) |
| Software / file-based KEK | — | ❌ refused in production **by design** | Production KEKs must be non-exportable hardware keys; there is no software fallback. |

## What Regalia KMS does / doesn't do

**Does**
- ✅ Root every production key operation in hardware, with **no software key-material fallback**.
- ✅ Authenticate every client by mTLS and gate every operation by declarative, purpose-bound policy.
- ✅ Give hardware custody to non-token-native secrets via wrapped envelopes.
- ✅ Produce a tamper-evident audit trail and enforce single-signer fencing.
- ✅ Act as the SOPS decryption authority and sign Cosmos-SDK transactions.

**Doesn't (yet)**
- ❌ **Not production-qualified.** Nitrokey HSM 2 hardware qualification (device-cert identity,
  on-token key provenance) is still open. Treat the project as pre-production.
- ❌ **Not a KMIP server.** Regalia exposes its own minimal mTLS API ([`api/openapi.json`](api/openapi.json)),
  not KMIP — it is not a drop-in for KMIP clients.
- ❌ **Not a general-purpose cloud KMS.** No cloud-provider, database, or disk-encryption
  integrations; it is a custody service for a specific hardware-rooted model.
- ❌ **No software key storage.** By design there is no software or file-based KEK in production.
- ⚠️ **Replacement-token restore is not proven end-to-end** — recovering an envelope onto a fresh
  token depends on a physical KEK-replication ceremony that is not yet qualified.

## Quick start

```sh
# Build and test (Go 1.26+)
go build ./...
go test ./...

# Run the daemon (loopback dev mode; serves mTLS once TLS paths are configured)
go run ./cmd/regalia-kms -listen 127.0.0.1:8443
```

The daemon serves mutual TLS when `tls_certificate_path`, `tls_private_key_path`, and
`tls_client_ca_path` are set, and refuses a non-loopback listener without them. Configuration is one
strict JSON object (≤32 KiB); unknown fields, unsafe values, non-loopback plaintext listeners, and
group/world-writable files are rejected. It has **no** fields for PINs, credentials, or key material.
Example configs are in [`config/`](config/).

The YubiKey PIV backend compiles only under `-tags piv` (`go build -tags piv ./...`); the default
build links a stub.

## Repository layout

| Path | What it is |
|---|---|
| `cmd/regalia-kms/` | Daemon entry point |
| `internal/` | Server, operations, backends (PKCS#11 / PIV / OpenPGP), registry, policy, audit, fencing, envelope |
| `adapters/sops/` | SOPS key-service sidecar adapter (separate Go module) |
| `api/` | OpenAPI contract |
| `config/` | Example configs and the custody-manifest JSON schema |
| `tools/` | Developer tooling (mutation-guard enumerator, inventory) |
| `*.md` | Per-component design docs (see below) |

## Documentation

| Doc | Topic |
|---|---|
| [`API.md`](API.md) · [`api/`](api/) | Wire protocol / OpenAPI contract |
| [`IDENTITY.md`](IDENTITY.md) | mTLS client identity and device identity |
| [`POLICY.md`](POLICY.md) · [`config/REGISTRY.md`](config/REGISTRY.md) | Purpose-bound policy and the custody registry |
| [`ENVELOPE.md`](ENVELOPE.md) | Opaque-secret envelope format and rotation |
| [`AUDIT.md`](AUDIT.md) · [`OBSERVABILITY.md`](OBSERVABILITY.md) | Hash-chained audit and metrics |
| [`FENCING.md`](FENCING.md) | Single-signer fencing |
| [`PIN-CUSTODY.md`](PIN-CUSTODY.md) | Unattended PIN handling |
| [`SOPS-TRANSPORT.md`](SOPS-TRANSPORT.md) | SOPS sidecar transport boundary |
| [`COSMOS-SUPPORT.md`](COSMOS-SUPPORT.md) · [`OPENPGP-COMPATIBILITY.md`](OPENPGP-COMPATIBILITY.md) | Cosmos signing; OpenPGP-card compatibility |
| [`TESTING.md`](TESTING.md) | Test tiers and how to run them |

## Security

- **No secrets in the repository.** Secret scanning runs over the whole tree with content-only
  allowlists (never path allowlists), so a real credential committed beside a benign construct is
  still caught. See [`.gitleaks.toml`](.gitleaks.toml).
- **Report vulnerabilities** privately via GitHub Security Advisories, not a public issue.

## Design records

Some code comments and docs cite internal design records (`ADR-0001`, the threat model, requirements)
that live in the operators' private repository and are not part of this release. The in-repo `*.md`
files above are self-contained for understanding and using the code.

## Related

- [regalia-ceremony](https://github.com/Digital-Frontier-LDA/regalia-ceremony) — air-gapped Qubes
  key-ceremony tooling, the Pico HSM staging emulator, and the RP2350 firmware work.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
