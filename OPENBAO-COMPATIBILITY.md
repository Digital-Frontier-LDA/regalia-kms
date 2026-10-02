# OpenBao compatibility contract

Contract version **1 (draft)**, for #120. It says what `openbao-plugin-kms-regalia` will support,
against which upstream versions, and through which existing KMS operations. Nothing here is built
yet: #121 implements auto-unseal, #122 External Keys, and #123 gates every claim below on a real
OpenBao server. Until #123 passes for a row, that row is a design target and not a support claim.

OpenBao owns application authentication, authorization, namespaces, KV, leases and the PKI and
Transit workflows. Regalia stays the custody boundary: it holds the keys and decides whether its
one service caller may use them. The plugin is a client of the KMS API in [`API.md`](API.md) and
gets nothing a client does not get: no PIN, no PKCS#11 library, no hardware handle.

## Supported versions

| Component | Version | Source of the pin |
|---|---|---|
| OpenBao server | 2.7.1 | the release tag |
| `github.com/openbao/go-kms-wrapping/v2` | v2.9.0 | OpenBao 2.7.1 `go.mod` |
| `github.com/openbao/go-kms-wrapping/plugin/v2` | v2.4.0 | OpenBao 2.7.1 `go.mod` |
| Plugin protocol | go-plugin gRPC, plugin set 1, handshake `OPENBAO_KMS_PLUGIN` | `plugin/plugin.go` at v2.4.0 |
| Regalia KMS API | `/v1` | [`API.md`](API.md) |
| `openbao-plugin-kms-regalia` | 0.x, unreleased | #121 |

Version policy:
- The plugin builds against **released** SDK tags only, pinned in its `go.mod`, never a commit.
- A new OpenBao or SDK version is supported when #123's real-server suite passes on it and a row is
  added here. Passing on 2.7.1 says nothing about 2.6 or 2.8.
- A change to the blob format or to a mapping below takes a new contract version. A plugin must keep
  decrypting every blob format an earlier released plugin wrote.
- **This is not Vault compatibility.** External Keys are OpenBao's redesign of Vault Enterprise
  Managed Keys and the two APIs differ. No Vault version is claimed.

## What the plugin serves

The SDK lets one binary serve two interfaces (`ServeOpts.WrapperFactoryFunc` and
`ServeOpts.KMSFactoryFunc`). They are separate features with separate keys, identities and grants.

| Interface | OpenBao feature | Status in contract 1 |
|---|---|---|
| `wrapping.Wrapper` | Auto-unseal (`seal` stanza) | Supported, #121 |
| `kms.KMS` / `kms.Key`: `Sign`, `Verify`, `ExportPublic` | External Keys for PKI and Transit signing | Supported with the limits below, #122 |
| `kms.Key`: `Encrypt`, `Decrypt` | Transit encryption with an external key | **Not supported**: returns `kms.ErrNotImplemented` |
| `wrapping.KeyExporter` | Exporting the seal key | **Never**: the KMS has no export |
| SSH engine with external keys | | **Not claimed**: no upstream support to test against |

## Auto-unseal: the `Wrapper` mapping

OpenBao 2.7.1 calls `Encrypt` and `Decrypt` on arbitrary small plaintexts (the stored keys, the
recovery key, a one-byte probe at start, and a random health-check value), with no AAD and no key
ID. That is **not** the KMS's `wrap`, which takes a data key and nothing else. The plugin therefore
does envelope encryption itself and uses the envelope pair the KMS already serves:

| `Wrapper` method | What the plugin does | KMS operation |
|---|---|---|
| `Type` | Returns a constant, `regalia`. | none |
| `SetConfig` | Validates the configuration (below) and builds the mTLS client. No KMS call. | none |
| `Encrypt(plaintext)` | Generates a 32-byte data key and a 12-byte nonce, encrypts with AES-256-GCM, sends ciphertext, nonce and data key. Zeroes the data key. | `seal-envelope` |
| `Decrypt(blob)` | Sends the envelope and returns the plaintext. | `release-secret` |
| `KeyId` | Returns `<object_id>@<kek_version>` from the last envelope the KMS produced. | none |

Why this pair and not `wrap`/`unwrap`:
- **Rotation.** `release-secret` routes on the KEK generation the envelope names and opens envelopes
  sealed under a `retired` generation ([`ENVELOPE.md`](ENVELOPE.md)). `unwrap` serves only the active
  binding, so after a KEK rotation it could no longer open what an earlier generation wrapped, and
  OpenBao would not unseal.
- **Binding.** The envelope's context is derived by the KMS from the authorized route (object,
  purpose, environment). A caller cannot choose it.
- **No new server operation** is needed.

Blob format, contract 1:
- `BlobInfo.Ciphertext` is the envelope document exactly as `seal-envelope` returned it
  (`regalia-envelope-v2`). `BlobInfo.Iv` is empty.
- `BlobInfo.KeyInfo.KeyId` is `<object_id>@<kek_version>`, copied from the envelope's own KEK
  reference. It is informational: `Decrypt` trusts the envelope, not this field.
- OpenBao re-encrypts its stored keys when `KeyId` differs from the stored blob's, which is how a
  KEK rotation reaches OpenBao's storage without a manual step.

Limits and refusals:
- Plaintext is at most **32 KiB**. `release-secret` accepts an envelope of at most 64 KiB; the cap
  leaves room for base64 and metadata. Larger input is refused before any KMS call.
- A non-empty `WithAad` is **refused**. `release-secret` rejects caller-chosen context, and silently
  dropping AAD would turn an authenticated encryption into an unauthenticated one. OpenBao 2.7.1's
  seal passes none.
- A `WithKeyId` that names another object is refused. The plugin serves the one object it was
  configured with.
- Unknown KEK generation, tampered envelope, wrong object or wrong identity all fail closed with the
  KMS's own refusal; the plugin adds no fallback and caches no plaintext.

The plaintext passes through the KMS on `release-secret`, and the data key passes through on
`seal-envelope`, both under mTLS. That is the existing envelope contract, not a new exposure: the
party that can unwrap the data key can always read what it protects.

### Key and backend for the seal

- The seal object is an `opaque` object with `seal-envelope` and `release-secret`, whose KEK is a
  non-exportable RSA key (`kek_algorithm` `rsa2048`, `rsa3072` or `rsa4096`) on `nitrokey-pkcs11`.
- `yubikey-openpgp` is served for Ed25519 signing only and cannot hold a seal KEK.
- One seal object per OpenBao cluster and environment. It is used for nothing else.

## External Keys: the `kms.KMS` / `kms.Key` mapping

| SDK call | What the plugin does | KMS operation |
|---|---|---|
| `KMS.Open` | Validates provider configuration and builds the mTLS client. Ignores `AllowEnvironment`: it never reads the environment. | none |
| `KMS.GetKey` | Validates the key mapping (object, purpose, algorithm, pinned public key). No KMS call. | none |
| `Key.Sign`, `Prehashed: true` | Sends the digest (ECDSA) or the PKCS #1 `DigestInfo` (RSA) with content type `application/vnd.regalia.digest`. Verifies the result against the pinned public key before returning it. | `sign` |
| `Key.Sign`, `Prehashed: false` | ECDSA and RSA: hashes locally with the hash in `SignerOpts`, then as above. Ed25519: sends the message. | `sign` |
| `Key.Verify` | Verifies locally against the pinned public key. Returns `kms.ErrInvalidSignature` on a bad signature. | none |
| `Key.ExportPublic` | Returns the pinned public key. | none |
| `Key.Encrypt`, `Key.Decrypt` | Returns `kms.ErrNotImplemented`. | none |
| `KMS.Close` | Closes idle connections. | none |

Signature encoding. The KMS returns what the token produced: `r‖s` for ECDSA, the PKCS #1 v1.5
signature for RSA, `R‖S` for Ed25519. The SDK expects standard-library encodings, so the plugin
converts ECDSA to ASN.1 DER and passes RSA and Ed25519 through.

| Algorithm | `Sign` | Notes |
|---|---|---|
| ECDSA P-256 / SHA-256 | Supported | payload 32 bytes |
| ECDSA P-384 / SHA-384 | Supported | payload 48 bytes |
| RSA 2048, 3072, 4096, PKCS #1 v1.5 with SHA-256/384/512 | Supported | payload is the `DigestInfo` |
| RSA-PSS (`*rsa.PSSOptions`) | **Refused** | the KMS signs with `CKM_RSA_PKCS` only |
| Ed25519 | Transit signing only, message ≤ 1024 bytes | measured limit of the applet through OpenSC; an Ed25519 **PKI issuer is not supported**, because a certificate's to-be-signed bytes are not bounded |
| ECDSA or RSA with a hash that does not match the key's policy | **Refused** | one key, one hash |

A key mapping names **one immutable generation**: the object and the SHA-256 of its public key. If
the key behind the object changes, every signature fails the pinned-key check and the mapping must
be replaced deliberately. Deleting a mapping or a config in OpenBao deletes nothing in the KMS.

### PKI is `sign`, not `certificate-sign`

OpenBao's PKI engine builds the certificate itself and asks its signer for a signature over a
digest. That maps to `sign`. It does **not** map to `certificate-sign`, which takes a CSR and issues
from a profile the KMS chooses.

The consequence is a trust-boundary fact, not an implementation detail: with a digest, the KMS
cannot see what is being signed. For a CA key reachable through this plugin, **OpenBao decides what
that CA signs**, and the KMS's purpose policy can bound only who asks, how often, and the payload
size. So:
- A CA key exposed to OpenBao is an **intermediate** created for that purpose, constrained by the
  certificate that the ceremony issued for it (path length, name constraints, lifetime). Those
  constraints are what holds if OpenBao is compromised.
- Root keys and keys with their own purpose policy are never mapped. In particular a release-signing
  key is **not** an External Key: that would bypass the approval it requires.
- Public ACME issuance stays outside the KMS and outside this plugin
  ([`CERTIFICATES.md`](CERTIFICATES.md)). The internal ACME flow in #122 is OpenBao's PKI engine
  using an intermediate mapped as above.

Transit: an `external-key` Transit key signs and verifies through the mapping above. A normal Transit
key stays a software key inside OpenBao and is not hardware-backed because this plugin is installed.

## Two layers of authorization

| Question | Who decides | Evidence |
|---|---|---|
| May this user or token use this PKI or Transit mount? | OpenBao ACL policies | OpenBao audit device |
| May this mount use this external key? | OpenBao grants on `/sys/external-keys/.../grants`, per namespace | OpenBao audit device |
| May this OpenBao cluster use this KMS object, for this purpose, in this environment? | KMS RBAC and purpose policy, on the plugin's mTLS identity | KMS audit journal |

The KMS sees one caller: the plugin's certificate. It cannot tell which OpenBao user or mount caused
a request and does not try. `context.subject` may carry the namespace and mount for correlation; it
is recorded, never authorized on. No header or field from OpenBao substitutes for either layer.

Identities and keys are separated by use:

| Use | Principal (example) | Object | Operations |
|---|---|---|---|
| Auto-unseal | `spiffe://regalia/workload/openbao-seal-<environment>` | one `opaque` seal object | `seal-envelope`, `release-secret` |
| PKI issuer | `spiffe://regalia/workload/openbao-keys-<environment>` | one intermediate CA key per mapping | `sign` |
| Transit signing | the same, or a second principal per tenant tier | one key per mapping | `sign` |

The seal principal holds no `sign` grant and the keys principal holds no envelope grant. A key has
one purpose and one policy entry per operation; grants are exact, with no wildcards
([`IDENTITY.md`](IDENTITY.md), [`POLICY.md`](POLICY.md)). These policies set
`required_approvals: 0`: a seal cannot wait for a person. That is why a key that does require
approval must not be mapped.

## Configuration

All values below are synthetic.

Declarative registration and seal, in the OpenBao server configuration. A `kms` plugin can only be
declared this way, because it must be available while OpenBao is sealed:

```hcl
plugin "kms" "regalia" {
  command   = "openbao-plugin-kms-regalia"
  version   = "v0.1.0"
  sha256sum = "0000000000000000000000000000000000000000000000000000000000000000"
}

seal "regalia" {
  address     = "https://kms.example.internal:8443"
  server_name = "kms.example.internal"
  ca_path     = "/etc/openbao/kms/ca.pem"
  cert_path   = "/etc/openbao/kms/seal.crt"
  key_path    = "/etc/openbao/kms/seal.key"
  object_id   = "openbao-seal-example"
  purpose     = "openbao-seal"
  environment = "staging"
  timeout     = "10s"
}
```

External Keys, per namespace:

```shell-session
$ bao write sys/external-keys/configs/regalia \
    plugin=regalia address=https://kms.example.internal:8443 \
    server_name=kms.example.internal ca_path=/etc/openbao/kms/ca.pem \
    cert_path=/etc/openbao/kms/keys.crt key_path=/etc/openbao/kms/keys.key \
    environment=staging
$ bao write sys/external-keys/configs/regalia/keys/issuing-ca \
    object_id=example-intermediate-ca purpose=openbao-pki-ca \
    algorithm=p384 public_key_sha256=sha256:0000…0000 public_key=@intermediate.pub.pem
$ bao write sys/external-keys/configs/regalia/keys/issuing-ca/grants/pki
```

Validation, the same for both interfaces:
- Unknown fields are an error (`kms.DecodeConfigMap` with `ErrorUnused`), as are missing ones. There
  are no defaults for `object_id`, `purpose`, `environment`, `ca_path`, `cert_path` or `key_path`.
- `address` must be `https`. The server is verified against `ca_path` only, never the system roots,
  with TLS 1.3.
- **The environment is never read.** `WithDisallowEnvVars` and `AllowEnvironment: false` are the
  only behaviour; setting `AllowEnvironment: true` changes nothing. No well-known file is searched.
- The configuration carries **paths**, not key material. External Keys configuration is stored in
  OpenBao's storage and readable through its API, so a private key or a token must never be a
  field. With no secret field, `Metadata.SensitiveKMSFields` and `SensitiveKeyFields` are empty.
- `public_key` must hash to `public_key_sha256`, and `algorithm` must match the key.
- With `verify=true` (OpenBao's default) the plugin checks configuration and reachability of
  `/v1/health/ready`. It does not sign to verify: a verification must not consume a nonce or a quota.

## Requests, timeouts and retries

Every KMS call carries a fresh `context.nonce`, the same value as `Idempotency-Key`, a new
`X-Request-ID`, and `expires_at` set to now plus the call's remaining deadline, capped by the policy's
`max_future_seconds`.

- **Deadline.** Each call runs under the caller's context and `timeout`. Cancellation closes the
  request. Nothing runs in the background after the caller has given up.
- **Retry only on `retryable: true`** (`BACKEND_UNAVAILABLE`, `DEPENDENCY_UNAVAILABLE`,
  `RESOURCE_EXHAUSTED`), with backoff, inside the same deadline. `DENIED`, `INVALID_ARGUMENT`,
  `NOT_FOUND`, `CONFLICT` and any unknown code are never retried.
- **A retry is a new request with a new nonce.** The KMS keeps a nonce consumed even when the
  hardware result was indeterminate, so resending the same nonce is answered `CONFLICT`. A retry
  therefore may repeat a hardware operation. For `seal-envelope` and `release-secret` that is
  harmless. For `sign` it yields a second valid signature and consumes quota twice; the plugin
  retries `sign` at most once and reports the rest to OpenBao.
- **Fencing is not the plugin's to work around.** If the KMS answers that it is not the active
  signer, the plugin returns the error. It does not try another address.
- **Plugin restart.** The plugin holds no state that matters: no cached plaintext, no cached data
  key, no session. After `ErrPluginShutdown` OpenBao respawns it and the next call starts clean.
- **Seal health check.** OpenBao encrypts and decrypts a random value every 10 minutes per node
  (every minute while unhealthy). Each check is two audited KMS operations; quotas and the audit
  volume must allow for it.

## Errors, logs and memory

- The plugin returns the KMS error **code** and request ID, never a payload, a path's contents, a
  certificate, or backend text. The KMS's `message` is already a fixed string per code.
- `kms.ErrNotImplemented` and `kms.ErrInvalidSignature` are returned as the SDK defines them, so
  OpenBao can tell an unsupported call and a bad signature from an outage.
- Logs carry operation, object ID, code, request ID and duration. Never plaintext, data keys,
  digests, signatures or configuration values.
- Data keys and plaintext buffers are zeroed after use. This is best effort in Go, as it is in the
  daemon. The seal plaintext is OpenBao's own root material, which OpenBao holds in memory anyway.

## Bootstrap and recovery dependencies

- **OpenBao depends on the KMS to unseal. The KMS never depends on OpenBao.** The plugin's client
  certificate and the KMS's own certificates come from the KMS workload CA
  ([`IDENTITY.md`](IDENTITY.md)), never from OpenBao's PKI, and can be issued and rotated while
  every OpenBao node is sealed.
- **After unseal**, KV, auth and software Transit keep working without the KMS. Operations on
  external keys, and the next unseal of any node, need it. #123 measures this instead of assuming it.
- **Recovery keys are not a bypass.** With auto-unseal, OpenBao's recovery key shares authorize
  operations such as generating a root token; they do not decrypt the stored keys. If every
  generation of the seal KEK is gone, the OpenBao data is gone. The seal KEK is therefore backed up
  like every other KEK, through the ceremony, and restored into independently commissioned hardware
  before a token is retired.
- **A second seal path** (Shamir fallback, parallel unseal, seal migration) is not claimed. Any of
  them must be shown on the pinned release in #123 before this document mentions it as available.
- **Restore.** A snapshot restored into fresh nodes needs the plugin's credentials and a KMS that
  still holds the KEK generation the snapshot was sealed under. `retired` generations keep opening;
  there is no state yet for a KEK that must refuse to open.

## Conformance and qualification

Two different claims, kept apart:
- **Software conformance**: #123 runs a real OpenBao 2.7.1 against the daemon on a software token. It
  proves the mapping, the refusals and the recovery behaviour.
- **Hardware qualification**: the production claim needs the physical token, fencing, audit and a
  witnessed recovery, under the existing custody program. A passing CI run is not that.

Examples in this repository are synthetic. Real endpoints, identities, key inventories and
break-glass procedures stay in restricted records.

## What the KMS would have to change

The mapping above needs no new operation. These are the places where the contract meets a limit of
the server today, for a decision on #120 rather than a silent change:

1. **`unwrap` has no generation routing.** This is why the seal uses the envelope pair. Giving
   `wrap`/`unwrap` the same routing would be an alternative; it is not needed.
2. **No served public-key operation.** `PublicKeyResult` is in `api/openapi.json` with no path. The
   plugin pins the public key in the key mapping instead, which is also the stronger check. A served
   operation would only remove a manual step.
3. **Assembling an envelope from outside the module.** `seal-envelope` expects a ciphertext whose
   AEAD binds what `internal/envelope` binds, and the plugin is its own Go module. Either that
   construction is published byte-exactly in `ENVELOPE.md` with a test vector, as the approval
   binding is in `API.md`, or it moves to an importable package. #121 needs one of the two.
4. **`api/openapi.json` omits `application/vnd.regalia.digest`** from `SignRequest.content_type`,
   while the example policy, the hardened-serve test and `regalia-sign` use it. The plugin depends on
   it, so the published contract should list it.
5. **`API.md`'s error table omits `CANCELED`, `DEADLINE_EXCEEDED` and `INVALID_OPERATION`**, which
   the OpenAPI document lists. The plugin treats them as non-retryable unless flagged otherwise.
6. **No RSA-PSS, no general encrypt/decrypt, Ed25519 messages bounded by the applet.** Each is an
   explicit refusal above. Serving any of them is a new reviewed operation, not a plugin option.
7. **Policy shape for the seal object.** It needs `seal-envelope` and `release-secret` on one object.
   #121 confirms the policy and manifest loaders accept that as two exact entries.
