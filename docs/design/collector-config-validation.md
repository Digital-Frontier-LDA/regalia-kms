# Shared offline collector validation (dx7.9 C1)

The collector configuration gate will reuse the endpoint validation already provided by
`regalia-audit-ship check`. `internal/audit.LoadCollectorEndpoint` now provides that existing
validation with explicit paths and time. It checks the HTTPS origin, site, current client
certificate/key pair, usable collector CA and at least one correctly encoded receipt public key.
The CLI retains its flags, error semantics and explicit `-probe` behavior.

Loading validates one service role's supplied files without contacting the collector. It does
not establish reachability, authenticate a response, attest another service's credentials, or
authorize a request. The caller must provide stable configuration files and revalidate when
they change or their validity interval ends. The returned material is not a persistent fact
or an ownership/permission attestation.

Single-node configuredness enforcement is now in place (regalia-kms-dx7.9, PA decision D2): under a
single-node admission with no audit collector configured, the daemon refuses every stateful operation
(wrap, key-agreement, release-secret, seal-envelope) with `collector-not-configured` (503, retryable)
before any policy or opstate reservation — the refusal is in the coordinator, before the spend.
Stateless operations (sign, unwrap, certificate-sign) keep serving. A collector that is configured
but unreachable does not refuse: the shipper retries, and the outage is an alert, not a refusal.
Existing synchronous audit acknowledgement, backlog readiness and startup continuity checks remain in
force. Collector downtime is not an additional offline configuration failure; those separate controls
may still refuse an operation.

Direct loader tests cover offline behavior and invalid configuration. Existing CLI check, probe
and conformance tests retain the command contract. This extraction alone does not complete dx7.9.
