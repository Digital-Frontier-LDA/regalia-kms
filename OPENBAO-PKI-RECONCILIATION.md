# Development PKI artifact reconciliation

`regalia-x509-reconcile` compares certificates and CRLs with a collector's
independently retained signing-intent stream. It runs offline, writes a JSON
report containing counts, and cannot sign or repair state.

Build from the repository root:

```sh
go build -o regalia-x509-reconcile ./cmd/regalia-x509-reconcile
```

Export one complete collector stream from genesis through an agreed committed
head. Select the expected stream by its authenticated daemon identity and site
on the collector. Obtain its sequence/hash through a trusted collector channel;
retain that anchor separately from the export. The command cannot authenticate
how those files or anchors were obtained. Hashes alone do not establish origin.

Supply the trusted public issuer certificate, expected SPKI SHA-256 pin, profile,
CA object and purpose from the approved deployment contract. Do not derive those
expectations from the artifact being investigated. Run against a consistent,
immutable collector snapshot; an export still receiving writes is unsuitable.

```sh
./regalia-x509-reconcile \
  -audit-stream collector-export.jsonl \
  -expected-sequence 12 \
  -expected-hash "$COLLECTOR_HEAD_HASH" \
  -issuer issuing-ca.pem \
  -key-fingerprint "$ISSUER_SPKI_SHA256" \
  -profile synthetic-profile-v1 \
  -object synthetic-ca \
  -purpose synthetic-pki \
  -artifact leaf.pem \
  -artifact full-crl.pem
```

These names describe disposable fixtures. Never publish deployment identity,
configuration, raw exports, private keys or certificate inventories in public
issues. Input files must be regular files; issuer/artifacts accept DER or a
single certificate/CRL PEM block. Private keys and PEM bundles are refused.
The command bounds each file and the number of artifacts.

The verifier checks the collector chain and its exact expected head, issuer
signatures, full signed TBS digests and complete signing intent. Authorization
and terminal events must agree on request identity and intent, in order. A valid
signature alone does not demonstrate an audited or permitted issuance.

- Exit **0**: the supplied artifacts and selected signing requests reconcile.
- Exit **1**: evidence needs review: an artifact is unattested, requests remain
  indeterminate, or correlation conflicts exist. Inspect the count-only report.
- Exit **2**: the inputs, collector anchor or cryptographic checks were refused.

Missing artifacts are **indeterminate**. A signer may have completed a legitimate
request whose response was lost; CRLs may also have been superseded. Neither is
proof of malicious issuance. Do not automatically retry signing, restore quota
or delete history in response to this report. Capture missing evidence and
investigate under the existing recovery procedure.

This command verifies evidence for the development PoC. It does not re-evaluate
historical policy, prove trusted time, qualify physical key custody, reconcile
distributed quotas or prove CRL numbering/revocation history. It cannot uniquely
join a request to a policy reservation: that journal currently carries intent
digests without a unique request identifier. A consistent result applies only
to the selected issuer/profile/object/purpose and supplied collector snapshot.
