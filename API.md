# Regalia KMS operation API (v1)

The contract clients depend on. It is deliberately **purpose-shaped, not device-shaped**: a caller
names an object and supplies context, and the server decides which device, slot, mechanism and
parameters serve it. Nothing here lets a caller select hardware or an algorithm.

**No operation exports a private key, a recovery source, a token credential, or an unwrapped
key-encryption key.** There is no endpoint for it and no request field that could ask for one.

## Versioning

The version is in the path: `/v1/operations/...`. Within `v1`:

- **New operations may be added.** A client that does not call them is unaffected.
- **New OPTIONAL response fields may be added.** Clients must ignore unknown response fields.
- **Request documents are closed.** Unknown request fields are rejected rather than ignored, so a
  typo in a security-relevant field is an error instead of a silently dropped instruction.
- **Error codes may be added.** Clients must treat an unrecognised code as non-retryable unless the
  `retryable` flag says otherwise — the flag, not the code, is the retry contract.
- **Nothing is removed or narrowed in place.** A breaking change takes a new path prefix.

## Operations

| path | payload | returns |
|---|---|---|
| `POST /v1/operations/sign` | `payload_base64`, digest or message, ≤ 1 MiB, `content_type` required | signature |
| `POST /v1/operations/wrap` | `plaintext_data_key_base64` ≤ 4 KiB, `format: regalia-envelope-v2` | wrapped data key |
| `POST /v1/operations/unwrap` | `wrapped_data_key_base64` ≤ 48 KiB, `format: regalia-envelope-v2` or `sops-pgp` | data key |
| `POST /v1/operations/certificate-sign` | `payload_base64`, PKCS#10 CSR in DER, ≤ 8 KiB | certificate (`application/pkix-cert`) |
| `POST /v1/operations/key-agreement` | `payload_base64`, peer public key in PKIX DER, ≤ 4 KiB | derived key, 32 bytes |
| `POST /v1/operations/release-secret` | `payload_base64`, envelope, ≤ 64 KiB, `format: regalia-envelope-v2` | secret plaintext |
| `POST /v1/operations/seal-envelope` | `ciphertext_base64` ≤ 1 MiB+tag, `nonce_base64` (12 B), `data_key_base64` (32 B), `format: regalia-envelope-v2` | the envelope document |

`GET /v1/health/live` and `GET /v1/health/ready` are the only unauthenticated routes, and disclose
no device, key, policy, topology or dependency detail.

`GET /v1/metrics` serves the operational metrics described by OBSERVABILITY.md in Prometheus text
format. It is authenticated like every operation and additionally authorized per identity: the
caller's SPIFFE identity must be listed in `metrics_reader_principals`, because even label-free
aggregate rates reveal the business rhythm of what is being signed. An empty list refuses everyone.

FIDO2 `authenticate` is **not** part of this API: human administrator authentication is outside the
cryptographic-operation surface.

## Request

```json
{
  "object_id": "production-sops",
  "context": {
    "environment": "production",
    "purpose": "sops-data-key",
    "expires_at": "2026-09-04T12:00:30Z",
    "nonce": "0123456789abcdef",
    "subject": "optional, ≤ 256 bytes"
  },
  "format": "regalia-envelope-v2",
  "content_type": "application/vnd.regalia.digest",
  "payload_base64": "..."
}
```

Required headers: `Content-Type: application/json`, `X-Request-ID` (UUID), `Idempotency-Key`.

Optional header: `X-Verified-Approvals`, base64 of a JSON array of approvals, for policies
that set `required_approvals`. Each entry is

```json
{
  "approver_id":    "spiffe://regalia/approver/treasury",
  "nonce":          "<must equal context.nonce>",
  "expires_at":     "<RFC3339Nano, must not be later than context.expires_at>",
  "payload_digest": "<sha256 hex of the request payload>",
  "signature":      "<base64 ed25519 signature over the canonical binding>"
}
```

The canonical binding is what the approver signs. It is a version line terminated by `\n`,
then six **length-prefixed records** in this order:

```
regalia-approval-v2
<len>:<object_id>
<len>:<context.purpose>
<len>:<context.environment>
<len>:<context.nonce>
<len>:<context.expires_at, RFC3339Nano UTC>
<len>:<sha256 hex of the payload>
```

Each record is `<len>`, a colon, exactly `<len>` bytes of field, then one `\n` — including the
last record. For `object_id: "signing-key-1"` the record is `13:signing-key-1`.

> **Parse by length, never by line.** A record is *usually* a line, but that is a coincidence of
> the values this daemon accepts, not a property of the format. A field may contain `\n`, and the
> length prefix exists precisely so that such a field stays unambiguous — see the note below on
> what the v1 format got wrong. A parser that splits on `\n` reads a field containing a newline
> as two records and produces a different signed binding, whose approvals are not rejected: they
> silently never count. **Read `<len>`, consume exactly that many bytes, then expect one `\n`.**

`<len>` is the number of **bytes in the field's UTF-8 encoding**, written in decimal with no
padding. It counts the field value only — **not** the `<len>:` prefix, and **not** the `\n`
that terminates the line. Counting UTF-16 code units, Unicode code points, or including the
newline produces different signed bytes, and an approval signed over them is not an error:
it simply never counts.

### Test vector

Verify against this before relying on an implementation. For the request

```
object_id:           signing-key-1
context.purpose:     release-signing
context.environment: production
context.nonce:       nonce-aaaa-bbbb-cccc
context.expires_at:  2026-01-02T15:04:05Z
payload:             the bytes being signed
```

the canonical binding is exactly these bytes (`\n` shown as line breaks, and the final line
also ends with `\n`):

```
regalia-approval-v2
13:signing-key-1
15:release-signing
10:production
20:nonce-aaaa-bbbb-cccc
20:2026-01-02T15:04:05Z
64:850578896d7e7f0c6b2d8c93a22f456a12545aec94b1cbbd3770e39f7582c59c
```

`payload_digest` is `850578896d7e7f0c6b2d8c93a22f456a12545aec94b1cbbd3770e39f7582c59c`.

Signed with a throwaway ed25519 pair whose seed is the 32 bytes `00 01 02 … 1f`. **It is a
documentation vector and nothing else** — never configure it as an approver.

| | |
|---|---|
| public key | `A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=` |
| signature | `wO20bUHZh99VG+VzFp2M/+fz+8a7tYcynVUKzi4dAas6B2+mnzeI8jI0pHIZxSLyywcWo/zbOGoOCpidSo2CAg==` |

`TestTheCanonicalBindingIsTheBytesAPIMdPublishes` asserts these same bytes and verifies this
signature, so the daemon cannot drift from this vector without a test failing.

**The length prefix is load-bearing, and `v1` did not have it.** v1 joined the fields with
`\n` and nothing else, which is ambiguous: `{object_id: "prod-signer", purpose: "release\nescrow"}`
and `{object_id: "prod-signer\nrelease", purpose: "escrow"}` serialize to the same bytes, so one
approver's signature over the first counts, unmodified, on the second. The length prefix makes
the framing self-delimiting — shifting a byte across a field boundary changes a declared length —
so the binding is unambiguous on its own terms rather than relying on request validation to keep
newlines out of the fields.

The header carries **evidence, not claims**. Every signature is verified against an
operator-managed key set before the approver is counted, so naming an approver achieves
nothing. An entry that fails any check — unknown approver, wrong nonce, an expiry later
than the request's, a digest over different bytes, a signature that does not verify — is
**not an error**. It is simply not counted, and the policy then denies on the count if it
is short. This is deliberate: rejecting the whole request on bad evidence would let anyone
who can reach the endpoint turn a properly approved request into a denial by appending
one piece of junk.

Duplicates count once. Two signatures from one key satisfy `required_approvals: 1` and
never `2`.

If no approver key set is configured, nothing is ever counted and any policy with
`required_approvals > 0` denies every request. Configure `approver_keys_path` (see
`config/approver-keys.example.json`) to enable dual control.

**The idempotency key must equal `context.nonce`.** The nonce is the durable replay record, so a
client cannot retry under a new key and have the request treated as new.

Each operation accepts exactly one payload field and rejects the others: a `sign` request carrying a
`wrapped_data_key_base64` is an error, not a request with an ignored field.

`envelope_aad_base64` binds a `wrap`, `unwrap` or `key-agreement` result to a caller-supplied
context. `release-secret` **rejects** it: the binding context there is derived from the authorized
route, so there is nothing for the client to select. A context the caller chooses proves only that
the caller knows what it chose.

## Errors

```json
{"request_id": "...", "code": "DENIED", "message": "...", "retryable": false}
```

| code | status | retryable | meaning |
|---|---|---|---|
| `UNAUTHENTICATED` | 401 | no | no verified client identity |
| `DENIED` | 403 | no | RBAC, routing or purpose policy refused |
| `NOT_FOUND` | 404 | no | no such object in the registry |
| `INVALID_ARGUMENT` | 400 | no | malformed, oversized, or wrong fields for the operation |
| `CONFLICT` | 409 | no | replayed nonce |
| `RESOURCE_EXHAUSTED` | 429 | yes | quota or concurrency limit |
| `BACKEND_UNAVAILABLE` | 503 | yes | the assigned token is absent or failing |
| `DEPENDENCY_UNAVAILABLE` | 503 | yes | policy state, audit or another required dependency |
| `INTERNAL` | 500 | no | a fault the caller cannot act on |

`message` is a fixed string per code. It never carries payload, key material, device identity,
policy contents or backend error text — an error is not a channel.

The distinction that matters operationally: **`DENIED` and `INVALID_ARGUMENT` will never succeed on
retry**, while `BACKEND_UNAVAILABLE`, `DEPENDENCY_UNAVAILABLE` and `RESOURCE_EXHAUSTED` may. A
client that retries the first pair is retrying something that cannot change.

## What a client must not build on

- **Response ordering or timing.** Both vary with hardware and policy state.
- **Absence of an error field.** New optional fields may appear.
- **A specific `message` string.** Match on `code`.
- **Reaching a device directly.** Clients receive no token PIN, PKCS#11 configuration, PIV handle,
  OpenPGP card access or local decrypt identity; those paths are removed, not merely discouraged.
