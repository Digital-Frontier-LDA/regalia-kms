# Regalia KMS

A hardware-backed key-management service written in Go. Regalia KMS keeps private key
material on dedicated hardware — SmartCard-HSM / PKCS#11 tokens and YubiKey PIV — and exposes
signing, wrapping and opaque-secret release over a mutually authenticated API, so that clients
never receive a PIN, a PKCS#11 module path, a PIV handle, or raw key bytes.

> **Status: pre-production.** The daemon starts fail-closed without configured audit and hardware
> dependencies. The API surface, operation stack, policy/registry model and PKCS#11 backend are
> exercised by an extensive Go test suite; physical hardware qualification is tracked separately.
> Do not rely on it to protect production keys yet.

## What it does

- **Hardware-rooted operations.** Signing, certificate signing, and key wrap/unwrap execute on the
  token. A hardware-held KEK wraps per-secret data keys so that even non-token-native secrets (API
  tokens, passwords, symmetric material) are protected by hardware, with plaintext bounded to
  server memory. See [`ENVELOPE.md`](ENVELOPE.md).
- **Authenticated, policy-gated access.** Callers are identified by their verified mTLS chain; a
  declarative registry and policy decide which principal may perform which operation on which
  object. See [`POLICY.md`](POLICY.md), [`IDENTITY.md`](IDENTITY.md), [`config/REGISTRY.md`](config/REGISTRY.md).
- **Tamper-evident audit.** Every decision is written to a hash-chained journal. See [`AUDIT.md`](AUDIT.md)
  and [`OBSERVABILITY.md`](OBSERVABILITY.md).
- **Single-signer fencing.** Never two simultaneous signers across sites. See [`FENCING.md`](FENCING.md).
- **Backends.** SmartCard-HSM / Nitrokey HSM 2 via PKCS#11, YubiKey PIV (build tag `piv`), and an
  OpenPGP-card compatibility layer. See [`IDENTITY.md`](IDENTITY.md), [`OPENPGP-COMPATIBILITY.md`](OPENPGP-COMPATIBILITY.md).
- **SOPS integration.** A local sidecar adapter lets [SOPS](https://github.com/getsops/sops) use
  the KMS as a key service over a mode-0600 Unix socket. See [`SOPS-TRANSPORT.md`](SOPS-TRANSPORT.md)
  and [`adapters/sops/`](adapters/sops/).
- **Cosmos/Akash signing.** SignDoc binding and digest handling for Cosmos-SDK chains. See
  [`COSMOS-SUPPORT.md`](COSMOS-SUPPORT.md).

## Quick start

```sh
# Build and test (Go 1.26+)
go build ./...
go test ./...

# Run the daemon (loopback development mode; serves mTLS when TLS paths are configured)
go run ./cmd/regalia-kms -listen 127.0.0.1:8443
```

The daemon serves mutual TLS when `tls_certificate_path`, `tls_private_key_path` and
`tls_client_ca_path` are configured, and refuses a non-loopback listener without them. Daemon
configuration is one strict JSON object (≤32 KiB); unknown fields, unsafe values, non-loopback
plaintext listeners, and group/world-writable files are rejected. It intentionally has no fields
for PINs, credentials, or key material. Example configs live in [`config/`](config/).

The YubiKey PIV backend is built only under `-tags piv`; the default build links a stub, so
`go build -tags piv ./...` is required to compile that path.

## Repository layout

| Path | What it is |
|---|---|
| `cmd/regalia-kms/` | Daemon entry point |
| `internal/` | Server, operations, backends, registry, policy, audit, fencing, envelope |
| `adapters/sops/` | SOPS key-service sidecar adapter (separate Go module) |
| `api/` | OpenAPI contract |
| `config/` | Example configs and the custody-manifest JSON schema |
| `tools/` | Developer tooling (guard enumerator, inventory) |
| `*.md` | Component design docs |

## Security

- **No secrets in the repository.** Secret scanning runs over the whole tree; the policy is
  content-only allowlists (never path allowlists) so a real credential committed beside a benign
  construct is still caught. See [`.gitleaks.toml`](.gitleaks.toml).
- **Report vulnerabilities** privately via GitHub Security Advisories rather than a public issue.

## Design records

Some code comments and docs cite internal design records (e.g. `ADR-0001`, the threat model, and
requirements documents) that are part of the operators' private repository and not included in this
open-source release. The in-repo `*.md` files above are self-contained for understanding and using
the code.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
