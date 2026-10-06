# Server-owned X.509 signing policy slice

This change implements the daemon enforcement work tracked in #122, on top of
the isolated software experiment in PR #407. The normal OpenBao provider still
refuses CA mappings. No production adoption, hardware qualification or public
ACME service is enabled by this slice.

## Objective and boundary

An authorized OpenBao workload submits complete unhashed certificate/CRL TBS
bytes. The daemon independently decides whether its configured CA object may
sign those exact bytes. OpenBao roles and client assertions cannot substitute
for the daemon profile. Invalid input or a semantic refusal reaches no signing
backend. The existing mTLS, RBAC, registry, approvals, admission, durable state,
audit and bounded executor remain in the path.

The initial opt-in profile is restricted to development policies, P-256/SHA-256,
DNS-only non-CA server leaves and bounded issuer CRLs. It binds a public issuer
certificate, profile ID, explicit DNS suffixes, artifact lifetimes and independent
daily leaf/CRL counts in the server policy file. Profile compilation freezes its
contents. The issuer must be a P-256 intermediate with path length zero; the
selected binding's enforced `public_key_sha256` must equal its SPKI fingerprint.
The older advisory `public_fingerprint` field is not sufficient.

The policy JSON uses an `x509` object with `id`, base64-encoded public
`issuer_der`, `dns_suffixes`, `max_leaf_validity_seconds`,
`max_crl_validity_seconds`, `leaf_per_day` and `crl_per_day`. Lifetime bounds
are checked as integers before duration conversion and must be 1–86,400 seconds.
Unknown nested fields are rejected. The owning policy must use environment
`development`, operation `sign`, algorithm `p256`, a payload cap of at most
32 KiB and only the TBS content type. Actual issuer certificates and deployment
names belong in private configuration, not example issue comments.

## Execution contract

1. Authenticate, authorize and route the request through the existing API.
2. Own a bounded copy of the TBS payload; parse every supported DER field.
   Malformed/ignored nested data returns nonretryable `INVALID_ARGUMENT`.
3. Enforce the server profile: issuer/key identity, DNS suffix boundaries,
   leaf privilege/usages and validity, and CRL validity/serial/extension limits.
   Semantic refusals return nonretryable `DENIED`.
4. Derive the artifact kind and SHA-256 from inspected bytes. Atomically reserve
   its nonce and one leaf or CRL count in the existing fsynced journal.
5. Record and acknowledge authorization audit before executing the backend.
6. Hash the owned TBS once, then send the digest to the existing P-256 backend.
   Record the terminal outcome against the same intent and request ID.

Profiles accept only `sign` with `application/vnd.regalia.x509-tbs`, no opaque
digest fallback, AAD or alternate format. Other operations on the same profiled
CA object must not provide a signing bypass. The normal production adapter
remains disabled for CA use until separate qualification.

## Durable counts and intent

`x509-leaf` and `x509-crl` are separate count buckets. Full and delta CRLs share
the bounded CRL reserve. Count identity is stable for the CA object across
profile/policy revisions, workload identity changes and material rotation.
Reservations remain spent after audit failure, backend failure, cancellation or
lost response. Exhausted X.509 daily counts return nonretryable
`RESOURCE_EXHAUSTED`; generic existing quota semantics remain unchanged.

An optional X.509 quota namespace and signing intent are hash-bound in policy
reservations. Committed day progression is reconstructed on reopen, and stale
days refuse without spending a nonce or count. The intent contains only the
profile ID, TBS digest, artifact kind and intended public-key fingerprint.
Audit events include the same optional metadata with `omitempty`, preserving
historical non-X.509 journal hashes. Neither journal records payloads, names,
certificates, private keys or signatures.

Consumed nonce identity remains stable across profile and policy revisions,
within each CA object and principal. Daily counts are shared across principals.
Deploy a collector supporting these optional fields before enabling a profile:
older collectors reject unknown JSON fields and would prevent acknowledged
signing. Historical events without the fields retain their original encoding.
Compatibility is new readers consuming historical events. After new intent
records are written, older daemon and collector binaries cannot reopen those
journals because they reject unknown fields. Retain compatible binaries for
recovery; stripping fields or truncating a journal is not a rollback procedure.
Downgrade of intent-bearing state remains a separate qualification gate.

Existing high-water checks refuse a shortened journal with its retained newer
mark. Existing writer locking prevents two writers on one journal; epoch checks
refuse superseded epochs seen in that journal. These facts do not qualify
rollback of both journal and mark, trusted wall-clock time, distributed state
replication, physical custody or multi-site token fencing. Off-host evidence
and witnessed hardware recovery remain under #123.

The CRL profile constrains signing authority; it does not reconstruct historical
revocations or enforce monotonically increasing CRL numbers. Reconciliation of
OpenBao state against independently retained audit evidence remains an adoption
gate, especially after restoring an older OpenBao snapshot.

## Components and verification

- `internal/policy/x509*.go`: strict parser, frozen profile and profile tests.
- `internal/policy/policy.go`, `load.go`, `state.go`: policy binding, durable
  counts, stable count identity, intent and day reconstruction.
- `internal/operations`: parser boundary, ordered decisions, hashing and audit.
- `internal/audit`: compatible optional intent fields and validation.
- `adapters/openbao`: the real OpenBao fixture uses daemon enforcement with a
  digest-only software signing backend; the experimental provider stays separate.

Use the pinned Go 1.26.6 native Linux toolchain. Focused checks:

```sh
go test -race -count=1 ./internal/policy ./internal/operations ./internal/audit
go vet ./internal/policy ./internal/operations ./internal/audit
```

The native AMD64/ARM64 conformance workflow must continue passing all eight real
OpenBao drills. Add parser fuzzing and real API refusal tests. Tests must prove
valid leaf/CRL signatures, denial before signing, issuer pinning, profile freeze,
independent bounded counts, restart/revision/concurrency/clock behavior, retained
high-water refusal, epoch refusal and ambiguous-result reservation retention.

Implementation order is parser/profile, policy reservation integration, ordered
coordinator/audit integration, then real-server verification. Every completed
increment is tested and committed. Hardware qualification and deployment remain
separate; #122/#123 acceptance criteria are not closed by software evidence.
