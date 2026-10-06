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

The coordinator parses complete signing input with the daemon implementation in
`internal/policy`, evaluates a frozen server-owned issuing profile, and durably
reserves a leaf or CRL count before hardware execution. It hashes the approved
bytes once and sends only the SHA-256 digest to a software P-256 token. This
token has no certificate parser, issuing policy or quota counter. A distinct
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
  full TBS bytes, the actual digest-only token call, and the correlated daemon
  authorization/success intent in verified audit and policy journals.
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
DER, mismatched signer options, and exhaustion of each durable signing budget.
Concurrent API callers cannot exceed either budget; invalid input and unauthorized
workloads consume neither. Separate core policy tests exercise restart, stale
snapshots, clock rollback and fencing. Explicitly named legacy software clock
and mutex tests retain the earlier in-memory experiment for comparison; they
are independent of enforcement in the running PKI fixture.

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
some nested fields. The daemon parser refuses leftover data in certificate validity,
subject attributes, SPKI, extension wrappers and known extension values, and in
CRL revoked entries. Authority key identifiers contain only the pinned key ID;
leaf basic constraints and key usage have the supported encodings. The pinned
intermediate must have path length zero, exact certificate/CRL signing usages,
a nonempty subject key identity, and critical positive DNS-only name constraints.
The profile's explicit DNS suffixes must stay within those issuer constraints.

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

Both native CI jobs fuzz the daemon parser and both earlier fixture inspectors
for 20,000 executions per target with two workers. Seeds cover valid certificate/CRL structures, cross-kind input,
truncation, trailing DER, indefinite-length BER, duplicate certificate
extensions, structured oversized input and nested DER leftovers in otherwise
valid certificate/CRL structures. Accepted input must preserve its
complete bounded TBS bytes, remain specific to its artifact type and reject
appended bytes. Run the same checks locally:

```sh
# From the repository root, fuzz the server-owned parser:
go test -run '^$' -fuzz '^FuzzParseX509TBS$' -fuzztime=20000x -fuzzminimizetime=0x -parallel=2 ./internal/policy

# From adapters/openbao, retain the earlier inspector comparison:
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

## Development enforcement and remaining adoption gates

The running fixture now uses the daemon's server-owned parser, immutable profile,
nonretryable semantic refusals, durable quota reservations and verified audit
intent. These checks happen before the digest-only token is invoked. Unknown
extensions, unsafe certificate semantics and out-of-scope names cannot be rescued
by a permissive OpenBao role. Quota refusals also occur before hardware execution.

Full and delta CRLs share a separate bounded reserve. Counts belong to the CA
object, so a policy/profile version change, caller change or same-object issuer
rotation does not create a fresh budget. The core policy tests exercise persisted
counts after restart, stale day refusal, journal high-water rejection, competing
writers, fencing epochs and ambiguous reservations. The OpenBao drill checks
verified durable intent and usable revocation after exhausting leaf issuance.
The separate [process recovery drill](PKI-RECOVERY.md) now tests the shipping
daemon and collector across SIGKILL/restart with a disposable SoftHSM token.
The real Bao PKI drill also reconciles genuine certificates/ACME artifacts and
the current CRL against an independent mTLS collector's authenticated head.
Unavailable historical artifacts remain indeterminate, including superseded
CRLs. Neither drill qualifies external fencing or physical hardware recovery.

Arbitrary provider errors remain sanitized backend failures. The experimental CA
client sends one attempt, disables HTTP replay and does not return retryable CA
errors. Lost responses and backend failures retain their durable reservations;
a server success event does not prove that the client received its signature.

See [the server-owned policy and journal contract](X509-POLICY.md) for the
configuration schema, pinning requirements, durable namespace and upgrade gates.
Collectors and verifiers must support the optional audit intent fields before the
first such event. Older readers cannot safely replay X.509 intent journals; journal
rollback and downgrade require explicit qualification.

The normal plugin factory still refuses CA mappings, the package builder excludes
the experimental binary, and X.509 profiles are limited to development policies.
The legacy test-only inspectors are retained as comparison tests and provide no
authority to the new digest-only backend.

Production adoption still requires review of the narrow profile/parser, a supported
release and collector migration, independent trust provisioning, physical
nonexportability/recovery evidence, production topology and fencing qualification,
off-host audit reconciliation, deployed-daemon readiness and recovery, and an OCSP
or revocation-consumer decision. CRL number history and delta-base reconciliation
are not enforced by this initial profile. A green software PoC does not close
#122/#123 or qualify production PKI or another OpenBao/SDK version.

Upstream references:
[External Keys](https://openbao.org/docs/concepts/external-keys/),
[pinned PKI/ACME API and required headers](https://github.com/openbao/openbao/blob/v2.7.1/website/content/docs/api/secret/pki.mdx),
[pinned RFC 8555 client](https://pkg.go.dev/golang.org/x/crypto@v0.56.0/acme).
