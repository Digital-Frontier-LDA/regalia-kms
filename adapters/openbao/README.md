# OpenBao seal proof of concept

Tracks #120, #121 and #123. This is an isolated development experiment, not a
supported production plugin. It uses the official OpenBao Wrapper/plugin SDK
and the existing Regalia HTTP wrap/unwrap contract; it adds no daemon endpoint.

## Contract

Each payload gets a new random 32-byte data key and a 12-byte AES-256-GCM nonce.
Regalia wraps only that data key. The caller's AAD digest is appended to the
configured binding path, so Regalia's key-wrap frame authenticates the context.
Local AEAD additionally binds the format version, object ID, repository, path,
environment, purpose and caller AAD. Neither plaintext nor an unwrapped data key
is stored by the plugin. Mutable byte buffers are cleared after use; Go and the
SDK do not guarantee removal of every runtime copy.

The BlobInfo ciphertext contains a strict versioned JSON frame; IV and KeyInfo
must agree with the supported format. KeyId identifies the configured logical
object, **not an immutable hardware generation**. Rotation, historical KEK
routing and production ciphertext migration are deliberately unqualified.
The PoC permits development bindings only and rejects unsupported key IDs,
oversized inputs, alternate formats and configuration changes after setup.
It never discovers credentials from environment variables or retries a KMS
operation automatically. Network errors are redacted. KMS requests use fresh
request IDs/nonces, direct TLS 1.3 mutual authentication, a pinned CA and bounded
timeouts, reusing the existing SOPS transport/client.

## Scope of evidence

The integration fixture uses Regalia's real HTTP authentication, registry, RBAC,
purpose policy, durable replay state and audit coordinator, with a software RSA
provider standing in for the hardware. The deployed KMS executable, fencing,
hardware key attributes and physical recovery are not exercised. Its software
provider is test-only and is never linked into the plugin executable.

Initial target: OpenBao 2.7.1, wrapping SDK 2.9.0, plugin SDK 2.4.0.
External Keys, PKI, Transit, namespace grants, upgrades and production deployment
remain separate qualification work.

Upstream contracts:

- https://openbao.org/docs/configuration/seal/
- https://openbao.org/docs/configuration/plugin/
- https://github.com/openbao/go-kms-wrapping/tree/v2.9.0
