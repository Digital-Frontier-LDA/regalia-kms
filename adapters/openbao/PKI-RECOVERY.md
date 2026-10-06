# Development PKI recovery qualification

## Objective

Give operators reviewable software evidence that a terminated signing process
cannot restore spent certificate/CRL quota, and that certificates and CRLs can
be reconciled against an independently retained collector stream. This slice
extends draft PR #527 under existing issues #122 and #123.

## Contract and boundaries

- Exercise real policy, file state, audit recorder, coordinator and authenticated
  HTTP requests across separate operating-system processes. Use the shipping
  daemon and collector with a disposable
  SoftHSM token and a test-only mTLS acknowledgement barrier. No software backend
  or bypass was added to the production daemon. Lab runtime admission and synthetic
  secure-channel evidence remain explicit fixture limitations.
- Kill only disposable local test processes. Test a spent reservation while the
  authorization ACK is held, after terminal success but before delivery, and restart with identical
  persisted state. Replay stays refused, and fresh requests cannot exceed the
  original daily cap. Leaf and CRL reserves remain independent.
- Reconcile a collector export from genesis to an independently authenticated
  expected sequence/hash. A self-consistent hash chain alone is not provenance.
  Verify issuer signatures and full TBS SHA-256, expected issuer public-key pin,
  profile, object and purpose. Correlate authorization/terminal events by request
  ID and complete intent, in order; ambiguous or missing evidence is refused.
- An audited signature without an available artifact is indeterminate: a response
  may have been lost legitimately. Never describe it as proof of unauthorized
  issuance. An artifact without matching evidence is unattested. Do not claim
  unique request-to-policy-reservation correlation from the existing digest join.
- Bound exported journals and artifact input. Reports carry counts and generic
  findings, without certificate names, private keys, tokens or raw audit records.
- No production profile, public ACME integration, live deployment, merge, physical
  HSM ceremony, distributed-quota proof or automatic recovery is authorized here.
  SIGKILL qualifies process termination, not host power loss or storage failure.

## Components and verification

1. Bounded offline reconciliation (`internal/audit/x509_reconcile.go`) and a
   runnable operator command (`cmd/regalia-x509-reconcile`), with synthetic
   certificate/CRL tests: wrong issuer, changed TBS, missing/contradictory intent,
   duplicate certificate serials/artifacts, truncation/rewritten chains, and lost response.
2. Deterministic collector acknowledgement barriers around durable authorization
   and terminal success (`e2e/openbao-pki-recovery.sh`); restart exercises the
   shipping processes, on-disk journals, mTLS HTTP behavior and SoftHSM signing.
   The collector runs as a separate loopback process on the same host. The
   authorization barrier checks the coordinator's acknowledgement ordering; it
   does not independently count token signing calls. Host compromise resistance
   and a physical token's signature counter remain separate qualification work.
3. Integrate reconciliation into real OpenBao issuance/revocation evidence and
   native CI. Maintain normal plugin PKI refusal and exclude experimental tools
   from production plugin packaging.
4. Independent security review, bounded-input tests, Linux race/vet checks, real
   OpenBao conformance, sanitized issue evidence and a stacked draft PR.

Use repository Go conventions and table-driven behavioral tests. Run focused
`go test -race -count=1` and `go vet` for changed packages on Linux; run the pinned
OpenBao drill from `adapters/openbao` with `OPENBAO_POC_REQUIRE_E2E=1`.
Hardware-dependent code must use the existing disposable SoftHSM CI provisioning.
Record actual commands and proof limitations alongside final validation evidence.

The offline command's collection/provenance instructions and exit codes are in
[the operator guide](../../OPENBAO-PKI-RECONCILIATION.md). It accepts a maximum
64 MiB export, 256 artifacts and 64 KiB per artifact. The collector's authenticated
head must be nonempty and must match the complete exported stream.
