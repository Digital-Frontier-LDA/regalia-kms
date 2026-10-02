# Versioned seal experiment

Tracks #120/#121/#123. This is a draft, development-only contract alongside
the existing raw-wrap format. It changes no daemon endpoint or SOPS contract.

## Relationship to the accepted design

The project's accepted design is
[OPENBAO-COMPATIBILITY.md](https://github.com/Digital-Frontier-LDA/regalia-kms/blob/main/OPENBAO-COMPATIBILITY.md),
introduced by merged #134. Issue #120 is completed. This separate experiment
does **not** replace that design or qualify its full production mapping.
Both use generation-aware seal-envelope/release-secret, and this fixture proves
OpenBao's rewrap and historical recovery behavior. These differences remain:

| Area | This development experiment | Accepted plugin design |
| --- | --- | --- |
| Type | regalia-poc | regalia |
| Blob | Outer local AEAD + inner envelope protecting its data key; non-empty IV | Native Regalia envelope directly in Ciphertext; empty IV |
| KeyId | Configured current generation, checked against every server write | object@generation from the last server-produced envelope |
| Metadata | Outer KeyInfo/frame/inner generation must agree | Native envelope is authoritative; KeyInfo is informational |
| AAD | Additional repository/path/caller AAD authenticated locally | Non-empty caller AAD refused |
| Payload | 1 MiB outer bound; only 32-byte outer key sent as inner secret | 32 KiB seal plaintext bound to fit release-secret |
| Promotion | Explicit coordinated registry/configuration changes | Server-selected generation drives KeyId and rewrap |

Configuration names, typed provider errors/retries and production environment
policy also need alignment in #121. OpenBao consumes reserved `purpose` before
forwarding seal fields, so the accepted example needs a plugin-specific purpose
field proven on 2.7.1. No experimental blob is a previously released production
format. Passing these fixtures is behavioral evidence for #123, not full
conformance to every row of the accepted contract.

Setting `key_version` opts into outer frame version 2. Its SDK KeyId is
`regalia-poc-v2:<object_id>:<key_version>`. `historical_key_versions` is an
explicit comma-separated allowlist of at most 16 other generations. Empty,
duplicate, malformed or current-generation entries are refused. No configuration
is discovered from the environment. Without either field, frame 1 is unchanged.
Frame 2 never silently falls back to frame 1.

## Development capability matrix

| Contract | Exercised behavior / limit |
| --- | --- |
| Versions | OpenBao 2.7.1, wrapping SDK 2.9.0, plugin SDK 2.4.0 |
| Wrapper Encrypt/Decrypt | Local AES-256-GCM; at most 1 MiB payload and 1 MiB caller AAD; empty payload supported |
| KMS cryptography | Fixture RSA-2048 with Regalia's framed RSA-OAEP primitive; each wrapped data key is 32 bytes |
| KeyId | Configured current ID; frame 2 includes generation; actual server generation checked on every write |
| WithKeyId | Encrypt accepts current only; Decrypt accepts the blob's explicitly allowed ID only |
| Historical reads | At most 16 explicit predecessor generations; KMS retention/revocation checked independently |
| Authentication | TLS 1.3, pinned CA and protected mTLS files issued before OpenBao unseal |
| Configuration | Development only; set once; no ambient discovery; 1 s–1 min timeout |
| Retry/error behavior | No adapter retry; fresh request identities; redacted errors; upstream plugin-manager retries unqualified |
| KMS/kms.Key interfaces | Not implemented: no External Keys factory, signer, PKI or Transit capability |
| Physical/HA/upgrade | Not qualified; one software fixture version and single-node Raft |

`KeyId` is configuration metadata, not a live registry discovery API. A mismatch
is refused when encrypting; operators must coordinate configuration and registry
promotion. OpenBao uses the changed ID to rewrap its stored/recovery keys.

The adapter encrypts a seal payload locally as before. It protects that 32-byte
data key inside a second, small Regalia secret envelope, using the existing
`seal-envelope` and `release-secret` APIs and the official envelope package.
The server reconstructs object/purpose/environment binding and supplies the KEK
generation. New writes are accepted only when that generation matches configured
`key_version`; an unexpected concurrent registry promotion fails the operation.
Historical reads select only an explicitly allowed generation and verify that
the outer KeyInfo, frame KeyId and inner envelope generation agree. The outer
AEAD binds generation, repository, path and caller AAD. Those additional fields
are adapter-enforced context, not additional server-side mount authorization.

The KMS registry independently grants or denies each generation. `retired`
preserves historical unwrap; `revoked` refuses it. Generation names must never
be reused for different material. Hardware commissioning and public-key identity
pins remain separate qualification obligations; a version string alone does not
prove immutable custody. No credential, hardware handle or private KEK is sent
to OpenBao. The KMS sees local ephemeral data keys, as in the raw-wrap format.

Promotion requires both the registry and plugin configuration to agree on the
new write generation, while retained generations remain explicitly allowed.
This is a restart/configuration-driven experiment, not live reconfiguration or
a production rotation procedure. OpenBao's internal key rotation, seal migration,
and KMS KEK promotion are different operations. Old snapshots require the
generations that protected them even if current storage has been rewrapped.
Revocation is deliberately irreversible in production; test reversals are
synthetic fault injection. Recovery shares cannot substitute for missing keys.

Acceptance for this slice: retain raw-format tests; real HTTP tests for old/new
generation decrypt, changed KeyId, option/AAD/metadata tampering, server promotion
mismatch and revoked/unknown generations; real OpenBao startup after promotion
with a retained generation, and old-snapshot recovery using its original generation.
No support claim is made for physical hardware, multi-node failover, upgrades,
External Keys, PKI, Transit, or migration from frame 1 to frame 2.
