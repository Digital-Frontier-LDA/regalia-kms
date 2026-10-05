# Inspected PKI and internal ACME software PoC

This experiment addresses the PKI/internal ACME proof in existing issue #122.
It is layered on the native seal/Transit work in draft PR #137. It adds no
production CA capability: the normal `NewExternal` factory still refuses every
`x509-ca` mapping, and the package builder does not ship the experiment binary.

## What runs end to end

The checksum-pinned OpenBao 2.7.1 server loads a separate SDK plugin subprocess,
`openbao-plugin-kms-regalia-pki-poc`. Its External Keys provider forwards complete,
unhashed DER signing input over mTLS to a development Regalia fixture. That
fixture uses the real HTTP handler, workload authentication, exact RBAC grants,
registry routing, content/purpose policy, replay state, audit journal and executor.
Only the token backend and readiness shim are test implementations.

The backend's inspector lives exclusively in `_test.go` files. It checks the
input before signing with an in-memory P-256 intermediate key. A distinct
synthetic offline root signs the constrained intermediate; OpenBao imports only
the certificates and references the externally held key. The offline root key
is never mapped or imported. The workload mTLS CA is independent of this issuing
chain, so issuing a server certificate does not grant KMS service authority.

`TestOpenBao271PKIInspectedIssuanceAndCRL` exercises:

- Mapping/configuration verification without a signing call, a required exact
  PKI mount grant, refusal from other mounts/namespaces, and refusal after
  revoking that grant.
- Leaf issuance through the external intermediate, chain/name verification
  against the pinned root, and a SHA-256 match between the returned artifact's
  full TBS bytes and the fixture's inspected signing input.
- Leaf revocation, CRL rebuild, verification of the CRL signature and revoked
  serial, and the same full-byte evidence for CRLs after exhausting the separate
  leaf issuance budget. CRL signing has its own bounded reserve.
- Role-restricted internal ACME using a real RFC 8555 client, required EAB,
  DNS-01 ownership verification through an authoritative loopback DNS fixture,
  issuance and an immediate second order with a fresh client key and serial.
  Missing EAB is refused; unpublished DNS ownership produces a verification
  error and prevents order finalization before a KMS call.
- An actual HTTPS application that presents each ACME-issued certificate in
  sequence. Fresh TLS handshakes verify the expected serial, hostname and chain.
- Permissive OpenBao roles attempting forbidden names and excessive lifetimes.
  Both reach the KMS inspector and are refused without a signature. Subordinate
  CA issuance is also refused.

The focused KMS tests additionally exercise prehashed/opaque-digest refusals,
wrong workload identity, CA privilege escalation, unknown extensions, trailing
DER, mismatched signer options, and exhaustion of each fixture signing budget.
Concurrent callers cannot exceed either budget; invalid input and unauthorized
workloads consume neither. A clock rollback refuses stale-day requests without
refilling either budget. These counters remain a software fixture.

Failure-injection tests exercise lost and truncated responses, a reused HTTP/1
connection closing after signing, a backend error after signing, and a recovered
provider panic after signing. The experimental CA client makes one attempt,
disables HTTP transport replay for its signing request, and marks API errors
nonretryable. Each ambiguous call retains its consumed leaf reservation. These
tests use real coordinator audit events: server signing success does not prove
that a client received the signature.

## Narrow synthetic profile

The experiment accepts only development mappings for `poc-pki-ca`, purpose
`openbao-pki-poc`, usage `x509-ca`, P-256 and SHA-256. Input is bounded to 32 KiB,
must be unhashed, and uses `application/vnd.regalia.x509-tbs`.

Leaf certificates must be v3, contain only DNS SANs at or below `svc.poc.invalid`, have
a matching CN as their sole subject attribute, use a P-256 leaf key, and contain
exactly digitalSignature and serverAuth usages. Basic constraints must assert a
non-CA leaf. Issuer/authority-key identity is pinned, validity is bounded to ten
minutes, and unknown extensions are refused even when noncritical.

CRLs must be v2 with the pinned issuer/authority-key identity, bounded validity,
number and entry count, positive unique revoked serials and no entry extensions.
Only authorityKeyIdentifier, cRLNumber and a strictly parsed critical delta-CRL
indicator are permitted. OpenBao 2.7.1 rebuilds an empty delta CRL as part of
its CRL workflow even with delta publication disabled; its base number must be
nonnegative, bounded and less than the new CRL number. There is no digest-only,
CSR, OCSP or arbitrary-signing fallback.

Strict raw-field checks supplement the standard X.509 parser, which can ignore
some nested fields. The fixture refuses leftover data in certificate validity,
subject attributes, SPKI, extension wrappers and known extension values, and in
CRL revoked entries. Authority key identifiers contain only the pinned key ID;
leaf basic constraints and key usage have the exact supported encodings.

Everything listens on loopback with ephemeral ports. ACME HTTP targets are
restricted to the synthetic OpenBao listener and require no Bao root token;
admin configuration and EAB provisioning use the fixture's initialization token.
Leaf private keys belong to the synthetic ACME application and remain in memory.
No public DNS, Let's Encrypt account, live deployment or customer credential is
used. Public ACME remains an ingress responsibility.

## Run and interpret the proof

Use the development conformance workflow's pinned OpenBao download/checksum and
native Linux Go toolchain. From `adapters/openbao`:

```sh
OPENBAO_POC_BAO=/path/to/checksum-verified/bao \
OPENBAO_POC_REQUIRE_E2E=1 \
go test -race -count=1 -v -timeout 4m \
  -run '^TestOpenBao271PKI|^TestPKIPoC|^TestPOC' .
```

The native amd64/arm64 matrix also runs this drill with the complete existing
suite; missing real-server fixtures are failures. The earlier native-plugin
fixture remains required for the separate upgrade/rollback drill.

Both native CI jobs also fuzz each inspector for 20,000 executions with two
workers. Seeds cover valid certificate/CRL structures, cross-kind input,
truncation, trailing DER, indefinite-length BER, duplicate certificate
extensions, structured oversized input and nested DER leftovers in otherwise
valid certificate/CRL structures. Accepted input must preserve its
complete bounded TBS bytes, remain specific to its artifact type and reject
appended bytes. Run the same checks locally:

```sh
go test -run '^$' -fuzz '^FuzzPOCCertificateInspection$' -fuzztime=20000x -fuzzminimizetime=0x -parallel=2 .
go test -run '^$' -fuzz '^FuzzPOCCRLInspection$' -fuzztime=20000x -fuzzminimizetime=0x -parallel=2 .
```

The predictable public key used to format stable fuzz seeds is never provisioned
into the running fixture. A passing bounded fuzz run is additional parser
evidence; it does not establish complete parser correctness.

This proves that the pinned upstream PKI/ACME workflow can preserve inspectable
signing bytes through this adapter and produce usable certificates. Renewal here
means a second successful order and application certificate rotation; it does
not exercise a renewal scheduler or waiting until expiry.

## Production work still required under #122

The inspector is a deliberately narrow software fixture, not a reviewed
server-owned issuing profile or parser. The generic daemon API is unchanged and
does not implement this inspection. It must not be paired with a generic
production signing backend as a substitute for certificate policy.

Fixture payload-digest records and separate daily leaf/CRL caps are in memory.
Full and delta CRLs share the bounded CRL reserve. The monotonic day guard
prevents a stale timestamp from refilling these counters; restart, trusted time,
snapshot recovery and distributed fencing remain unproved. These are not
production audit schema fields or durable quota reservations.

The backend manager still collapses inspection failures into
`BACKEND_UNAVAILABLE`. The experimental CA client now sends one attempt, but
proper nonretryable profile-denial errors need a separately reviewed server
change. Server-owned inspection should run at the coordinator policy boundary,
derive certificate/CRL counts from inspected bytes and reserve those counts
before hardware execution. Existing durable policy reservations and their
journal, rollback detection and fencing should be extended for this purpose.
Arbitrary provider errors must remain sanitized backend failures. Reservations
must stay spent when signing or response delivery is ambiguous.

Quota identity must remain stable across immutable profile revisions and caller
identity changes: the current generic quota key includes the policy ID, so a
profile-version change must not silently replenish issuance or CRL capacity.
Required production regressions include restart with exhausted counters, stale
snapshot/high-water refusal, fenced competing writers, audit failure after
reservation, ambiguous signature completion and bounded revocation capacity.

Production support still requires reviewed certificate/CRL parsing and immutable
profiles, durable count limits and digest audit records, distributed fencing,
physical nonexportability/recovery evidence, deployed-daemon readiness, an OCSP
decision, and independent trust provisioning. A green software PoC does not close
#122/#123 or qualify production PKI or another OpenBao/SDK version.

Upstream references:
[External Keys](https://openbao.org/docs/concepts/external-keys/),
[pinned PKI/ACME API and required headers](https://github.com/openbao/openbao/blob/v2.7.1/website/content/docs/api/secret/pki.mdx),
[pinned RFC 8555 client](https://pkg.go.dev/golang.org/x/crypto@v0.56.0/acme).
