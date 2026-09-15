# KMS workload identity and certificate lifecycle

Non-health KMS requests require a verified client certificate and an exact deny-by-default RBAC
grant. Workload identity is the certificate's single URI SAN under `spiffe://regalia/`. Common Name,
DNS SAN, source address, Proxmox VM identity, and forwarded headers never establish a principal.

The TLS layer uses TLS 1.3 and verifies any presented client chain. Health endpoints may complete a
server-authenticated TLS handshake without a client certificate; authentication middleware rejects
every other path unless Go's TLS verifier produced a verified chain. Server certificates accept a
`crypto.Signer`, allowing the private key operation to remain on the HSM or unattended YubiKey.
Do not add a convenience PEM-key fallback.

## Issue, rotate, and revoke

1. Issue from a dedicated workload CA using a short lifetime, one Regalia URI SAN, ClientAuth EKU,
   and no reusable human identity. Record the serial, URI, owner, environment and expiry off-host.
2. Add exact object, operation and environment grants in an `rbac.example.json`-shaped policy.
   Wildcards, duplicate principals, unknown fields and implicit defaults are rejected.
3. Deploy a replacement certificate within the configured clock-skew overlap. Both old and new
   serials may map to the same URI during this bounded window; tests cover this behavior.
4. After cutover, add the old serial to the signed revocation input and reload. Revocation wins over
   an otherwise valid chain. A stale or unavailable revocation source must fail readiness closed.
5. Reconcile the RBAC content digest and certificate event through the off-host audit system.

Clock synchronization is a security dependency. The validator tolerates at most the configured
small skew (one minute in the initial wiring); certificates outside it fail generically. Denials do
not emit peer addresses, subjects, SANs, serials or verifier errors to clients. Issue #9 owns their
redacted off-host audit representation.
