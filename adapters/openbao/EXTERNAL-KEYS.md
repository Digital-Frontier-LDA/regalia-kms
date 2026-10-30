# Development External Keys for Transit

The native binary serves `kms.KMS` independently of its seal Wrapper, using the
official v2.4.0 plugin SDK. OpenBao owns namespaces, ACLs and mount grants;
Regalia owns custody, exact service grants, replay state and its audit journal.
This implements the Transit portion of #122; it does not support PKI issuers.

Provider fields, all required: `address`, `server_name`, `ca_path`, `cert_path`,
`key_path`, `environment`, `timeout`. The TLS and file checks match the native
seal. Only `development` is accepted. Provider `Open` performs a bounded,
read-only mTLS `GET /v1/health/ready`; it never signs to verify configuration.
`AllowEnvironment` never permits ambient configuration. `Close` cancels active
calls, prevents new operations and closes idle connections.

Each immutable key mapping requires `object_id`, `purpose`, `usage=signing`,
`algorithm`, `hash_algorithm`, `public_key` (one PUBLIC KEY PEM/SPKI block) and
`public_key_sha256` (SHA-256 of DER SPKI, `sha256:` plus 64 lowercase hex digits).
Unknown, missing and non-string values fail configuration. `GetKey` makes no
KMS call. `ExportPublic` returns an independent public-key value so callers
cannot mutate the verification pin. Deleting a mapping deletes no custody key.

| Mapping algorithm | Mapping hash | KMS input | Returned signature |
| --- | --- | --- | --- |
| p256 | sha256 | SHA-256 digest | Fixed-width r/s converted to ASN.1 DER |
| p384 | sha384 | SHA-384 digest | Fixed-width r/s converted to ASN.1 DER |
| rsa2048/rsa3072/rsa4096 | sha256/sha384/sha512 | RFC 8017 DigestInfo | PKCS #1 v1.5 signature |
| ed25519 | none | Raw message, 1–1024 bytes | Pure Ed25519 signature |

ECDSA/RSA raw input is hashed locally, with a 1 MiB input cap. Prehashed input
must have the exact configured digest length. Pure Ed25519 ignores the SDK's
Prehashed flag and treats the bytes as the message. Ed25519ph, Ed25519 contexts,
RSA-PSS, mismatched hashes and malformed signatures are refused. Every returned
signature must verify against the mapping's pinned public key before delivery.
`Verify` runs locally and returns `kms.ErrInvalidSignature` for a bad signature.
`Encrypt`/`Decrypt` return `kms.ErrNotImplemented`.

Only validated transient KMS errors with `retryable=true` permit a signing
retry, **at most one** inside the existing deadline, with a fresh request ID and
nonce. An indeterminate operation can therefore consume quota twice and produce
two valid signatures. Network/lost-response ambiguity itself is never retried.
Errors/logs contain codes and correlation metadata, never digests or signatures.

## Synthetic setup

Register the checksum-bound native binary in the server configuration as
`regalia`. Use a dedicated Transit service certificate with exact `sign` grants,
separate from the seal identity. The fields below are synthetic; obtain the
actual public-key pin from the approved commissioning record.

```sh
bao write sys/external-keys/configs/regalia \
  plugin=regalia address=https://kms.example.internal:8443 \
  server_name=kms.example.internal ca_path=/etc/openbao/kms/ca.pem \
  cert_path=/etc/openbao/kms/keys.crt key_path=/etc/openbao/kms/keys.key \
  environment=development timeout=10s
bao write sys/external-keys/configs/regalia/keys/signing \
  object_id=example-transit-key purpose=openbao-transit usage=signing \
  algorithm=p256 hash_algorithm=sha256 \
  public_key=@public.pem public_key_sha256="sha256:<approved-spki-sha256>"
bao write sys/external-keys/configs/regalia/keys/signing/grants/transit
bao write transit/keys/signing type=external-key external_key_ref=regalia:signing
bao write transit/sign/signing input=AQ== \
  hash_algorithm=sha2-256 signature_algorithm=pkcs1v15
```

The Transit mount must already exist. OpenBao 2.7.1 defaults every external key
to RSA-PSS options, including ECDSA/Ed25519, so the explicit signature option is
required for both sign and verify. Use `hash_algorithm=sha2-384` for p384,
the matching SHA-2 choice for RSA, and `none` for Ed25519. These requirements are
verified against the
[released dispatch](https://github.com/openbao/openbao/blob/v2.7.1/sdk/helper/keysutil/policy.go).

## Evidence and remaining gates

`TestOpenBao271ExternalTransitSigningAndGrants` uses the real pinned server,
separate SDK subprocess and Regalia's HTTP/auth/registry/purpose/replay/audit
stack with test-only software keys. It exercises all six algorithms, raw and
prehashed calls, valid/invalid verification, default config verification without
signing, exact mount grants, cross-namespace refusal, grant revocation, mapping
deletion and disable/remount refusal. The fixture readiness response is a
read-only test shim; actual daemon readiness and physical custody require the
[hardware record](HARDWARE-QUALIFICATION.md).

CA mappings are refused, including prehashed or raw signing. #122 still needs
server-side inspected certificate/CRL payloads, issuing profiles and negative
tests, a reviewed CA payload digest audit field and daily signature counts.
There is no digest-only CA fallback. No internal ACME, OCSP or production PKI
support is claimed. Public ACME continues at the ingress.
