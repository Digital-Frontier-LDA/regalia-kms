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
  serial, and the same full-byte evidence for CRLs.
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
DER, mismatched signer options, and exhaustion of the fixture signing budget.

## Narrow synthetic profile

The experiment accepts only development mappings for `poc-pki-ca`, purpose
`openbao-pki-poc`, usage `x509-ca`, P-256 and SHA-256. Input is bounded to 32 KiB,
must be unhashed, and uses `application/vnd.regalia.x509-tbs`.

Leaf certificates must be v3, contain only DNS SANs below `svc.poc.invalid`, have
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

This proves that the pinned upstream PKI/ACME workflow can preserve inspectable
signing bytes through this adapter and produce usable certificates. Renewal here
means a second successful order and application certificate rotation; it does
not exercise a renewal scheduler or waiting until expiry.

## Production work still required under #122

The inspector is a deliberately narrow software fixture, not a reviewed
server-owned issuing profile or parser. The generic daemon API is unchanged and
does not implement this inspection. It must not be paired with a generic
production signing backend as a substitute for certificate policy.

Fixture payload-digest records and the shared daily signature cap are in memory.
They are not production audit schema fields or durable, fenced quota reservations.
The backend manager currently collapses inspection failures into
`BACKEND_UNAVAILABLE`; the existing adapter may retry once with a fresh nonce,
producing two refused attempts. Tests assert that neither attempt signs. Proper
nonretryable profile-denial errors need a separately reviewed server change.

Production support still requires reviewed certificate/CRL parsing and immutable
profiles, durable count limits and digest audit records, distributed fencing,
physical nonexportability/recovery evidence, deployed-daemon readiness, an OCSP
decision, and independent trust provisioning. A green software PoC does not close
#122/#123 or qualify production PKI or another OpenBao/SDK version.

Upstream references:
[External Keys](https://openbao.org/docs/concepts/external-keys/),
[pinned PKI/ACME API and required headers](https://github.com/openbao/openbao/blob/v2.7.1/website/content/docs/api/secret/pki.mdx),
[pinned RFC 8555 client](https://pkg.go.dev/golang.org/x/crypto@v0.56.0/acme).
