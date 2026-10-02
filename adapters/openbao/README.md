# OpenBao seal proof of concept

Tracks #120, #121 and #123. This is an isolated development experiment, not a
supported production plugin. It uses the official OpenBao Wrapper/plugin SDK
and existing Regalia HTTP operations; it adds no daemon endpoint. Default frame
1 uses raw wrap/unwrap. Opt-in frame 2 uses generation-aware seal-envelope and
release-secret; see [the versioned seal contract](VERSIONED-SEAL.md).
The accepted production design was documented separately in merged #134;
[the experiment's differences](VERSIONED-SEAL.md#relationship-to-the-accepted-design)
remain alignment work for #121. This PoC does not replace that contract.

## Contract

In default frame 1, each payload gets a new random 32-byte data key and a
12-byte AES-256-GCM nonce.
Regalia wraps only that data key. The caller's AAD digest is appended to the
configured binding path, so Regalia's key-wrap frame authenticates the context.
Local AEAD additionally binds the format version, object ID, repository, path,
environment, purpose and caller AAD. Neither plaintext nor an unwrapped data key
is stored by the plugin. Mutable byte buffers are cleared after use; Go and the
SDK do not guarantee removal of every runtime copy.

The BlobInfo ciphertext contains a strict versioned JSON frame; IV and KeyInfo
must agree with the supported format. KeyId identifies the configured logical
object, **not an immutable hardware generation**. Frame 1 has no historical KEK
routing. Frame 2 includes the configured generation in KeyId and authenticates
it in both envelopes; its explicit historical allowlist is also subject to the
KMS registry's generation states. Hardware immutability and production
ciphertext migration remain unqualified.
The PoC permits development bindings only and rejects unsupported key IDs,
oversized inputs, alternate formats and configuration changes after setup.
It never discovers credentials from environment variables or retries a KMS
operation automatically. Network errors are redacted. KMS requests use fresh
request IDs/nonces, direct TLS 1.3 mutual authentication, a pinned CA and bounded
timeouts, reusing the existing SOPS transport/client.

The plugin field is `kms_purpose`, because OpenBao consumes the reserved seal
field `purpose` before forwarding configuration to the plugin. Unknown plugin
fields fail configuration. Plugin registration is declarative and checksum-bound,
so it is available before OpenBao unseals. The fixture uses single-node Raft,
independently issued synthetic mTLS identities, and an HTTP API bound to loopback
only. This HTTP listener configuration is for disposable tests only.

## Scope of evidence

The integration fixture uses Regalia's real HTTP authentication, registry, RBAC,
purpose policy, durable replay state and audit coordinator, with a software RSA
provider standing in for the hardware. The deployed KMS executable, fencing,
hardware key attributes and physical recovery are not exercised. Its software
provider is test-only and is never linked into the plugin executable.
Listener recovery reuses the fixture's in-memory RSA key; it does not prove KMS
process recovery, custody persistence or recovery with missing historical keys.
OpenBao's plugin manager may respawn/retry a crashed plugin; ambiguous-operation
reconciliation across that boundary remains unqualified.

The recovery drill takes a real Raft snapshot, stops the source process and
restores through the normal snapshot endpoint onto separately initialized, empty
storage with a different node ID and newly issued mTLS credentials. It verifies
the source token/data replace the target's initialization state, then restarts
and checks authorized access and unauthorized-identity refusal. A separate KMS
fixture with a different RSA key but the same logical object ID cannot restore
that snapshot; its original target state remains usable. No force-restore
endpoint is used. This proves a single-version software restore with the same
original KMS key, not historical KEK routing, key rotation, recovery shares,
hardware recovery or multi-node disaster recovery.

The separate frame-2 drill initializes under synthetic generation g1, promotes
g2 while retaining g1, verifies OpenBao rewraps stored keys and restarts with no
plugin access to g1, then restores a pre-promotion snapshot using g1. Revoking
g1 leaves current storage usable but makes that old snapshot unrestorable.
Recovery-key authorization is checked after promotion without the predecessor.
These are single-node software fixtures, not a hardware rotation procedure or
an automatic migration from frame 1.

Initial target: OpenBao 2.7.1, wrapping SDK 2.9.0, plugin SDK 2.4.0.
External Keys, PKI, Transit, namespace grants, upgrades and production deployment
remain separate qualification work.

## Run

Use Go 1.26.6 or newer, and a checkout containing the sibling SOPS and root
modules (the replacements in go.mod are intentionally local for this PoC).

```sh
cd adapters/openbao
go test -race ./...
go vet ./...

# Requires the official 2.7.1 release binary, checked against its release checksum.
OPENBAO_POC_BAO=/absolute/path/to/bao OPENBAO_POC_REQUIRE_E2E=1 \
  go test -race -count=1 -run TestOpenBao271 -v -timeout 4m
```

The default tests skip the real-server drill if the executable is absent;
`OPENBAO_POC_REQUIRE_E2E=1` makes absence a failure. The real-server test builds
and executes the plugin separately, initializes OpenBao, stores synthetic KV
data, observes a periodic seal health check, seals/restarts, checks reads during
a KMS listener outage, refuses offline and unauthorized restarts, then restores
authorized access and checks that plaintext and the root token are absent from
Raft storage and captured logs. It also exercises fresh-node snapshot restore,
restored-node identity enforcement and rejection with different KMS key material.
The generation drill is also mandatory when the real-server executable is set.
All fixture identities/state are temporary.
`OPENBAO_POC_KEEP_FAILURE=1` optionally retains **synthetic** private debug
artifacts on failure; remove the reported directory after inspection.

Pinned release archive hashes:

| Archive | SHA-256 |
| --- | --- |
| openbao_2.7.1_linux_amd64.tar.gz | `0e2f1ce10d124e03112b50dd2fbec6b78003783253bc3a91587938f39d1e2243` |
| openbao_2.7.1_darwin_arm64.tar.gz | `15625b5f69aee5bb4578b4e76e856a2141647342b0f8e5969a8875b44e0fbf91` |

These were checked against the official v2.7.1 release's checksums.txt. CI pins
the Linux archive and requires the real-server test; a unit-test pass alone is
not compatibility evidence.

Upstream contracts:

- https://openbao.org/docs/configuration/seal/
- https://openbao.org/docs/configuration/plugins/
- https://openbao.org/docs/commands/operator/raft/
- https://github.com/openbao/openbao/blob/v2.7.1/website/content/docs/api/system/storage/raft.mdx
- https://github.com/openbao/go-kms-wrapping/tree/v2.9.0
