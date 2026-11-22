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

Single-node configuredness enforcement remains open: both daemon and node shipper configuration
need a common contract that preserves private-key separation, and the request check must happen
before policy reservation. Existing synchronous audit acknowledgement, backlog readiness and
startup continuity checks remain in force. Collector downtime is not an additional offline
configuration failure; those separate controls may still refuse an operation.

Direct loader tests cover offline behavior and invalid configuration. Existing CLI check, probe
and conformance tests retain the command contract. This extraction alone does not complete dx7.9.
