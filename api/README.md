# KMS API v1 contract

`openapi.json` is the contract for the centralized boundary accepted in
`doc/ADR-0001-CENTRALIZED-KMS.md`. It is intentionally small and purpose-shaped. A caller chooses a
logical object and purpose; it never chooses hardware, reader, slot or cryptographic mechanism.

## Authentication and disclosure

Mutual TLS is required globally. Liveness and readiness opt out and return only `ok` or
`unavailable`; they never reveal devices, keys, sites, policy versions or dependency failures.
Client certificates map to workload principals under issue #2. Authentication does not make any
request field trustworthy—authorization and semantic policy still run server-side.

## Idempotency

Every POST requires both `X-Request-ID` and `Idempotency-Key`:

- The request ID correlates the response and audit event.
- The header must exactly equal `context.nonce`; a mismatch is invalid input. This prevents a caller
  from presenting a cosmetic idempotency key while changing the value reserved by replay policy.
- The nonce is scoped by durable policy state and is reserved atomically before hardware use.
- Any repeat returns `CONFLICT`; the KMS deliberately provides at-most-once hardware execution and
  does not retain plaintext unwrap results merely to replay an HTTP response.
- An indeterminate hardware result consumes the nonce and is never retried automatically. The
  caller must reconcile under a new, explicitly authorized request.

The durable idempotency record must be written before hardware use. Its unavailable or rolled-back
state makes the operation unavailable rather than best-effort.

## Operation semantics

- `sign` accepts complete bounded payload bytes and an allowlisted content type. Purpose policy may
  require canonical parsing and may reject opaque input for a high-risk key.
- `unwrap` accepts a wrapped data key, not an arbitrary ciphertext stream. The `sops-pgp` format is
  the centralized SOPS integration point.
- `wrap` accepts only a bounded data key and returns a context-bound `regalia-envelope-v2` key-wrap
  frame; it is the encryption half
  required by the SOPS key-service adapter, not a generic bulk-encryption oracle.
- `releaseSecret` releases a hardware-enveloped consumable value and requires `Cache-Control:
  no-store` on success.
- `getPublicKey` is authenticated because object existence and naming are operational metadata,
  even though the returned key is public.

The contract has no generic object listing, administrative mutation, raw decrypt, client-selected
mechanism, or key-export operation. Administrative APIs, if ever required, need a separate ADR and
threat-model update.

## Error contract

Errors contain only request ID, stable code, safe message, and explicit retryability. They do not
contain middleware stderr, device details, policy internals, peer certificates, payloads or nested
debug data. `NOT_FOUND` may be used instead of `DENIED` where revealing object existence would cross
an authorization boundary.

Validate the contract with:

```sh
python3 -m json.tool api/openapi.json >/dev/null
python3 -m unittest kms.tests.test_openapi_contract
```
