# KMS audit contract

Every authenticated allow and deny must produce an `audit.Event`. The fixed schema records sequence,
UTC time, correlation/request ID, workload principal, decision, logical object, purpose, operation,
commissioned device ID, outcome, latency, registry digest and policy digest. It has no payload,
signature, plaintext, PIN, key, middleware-error or arbitrary-details field. Suspicious private-key
markers and control characters in metadata are rejected before persistence.

Events are serialized in deterministic field order and linked by SHA-256 over the complete event and
previous hash. The local mode-0600 append-only buffer is `fsync`ed before delivery, and that buffer
is the shipping queue: a background shipper replays the tail past the collector-acknowledged head,
attempting only the head event so the off-host copy is always a prefix of the chain, and persisting
each acknowledged head to a `.shipped` sidecar. Requiring remote acknowledgement still makes
collector failure fail a high-risk operation closed, but the failed event is retained and retried
with exponential backoff until the collector recovers; every retry carries the same
`Idempotency-Key`, so an acknowledgement lost in transit never double-applies. A restart resumes
from the `.shipped` mark, and a journal that ends before it — or disagrees with it — is refused as
missing collector-acknowledged events, a second truncation tripwire independent of the high-water
sidecar. Sink readiness/send panics are contained as unavailability.

Readiness reports the shipping position, not only collector health: while more than 4096 recorded
events await acknowledgement (`maxAuditBacklog`) the service is unready even when the collector
answers its health check, so a shipping outage surfaces as a stopped pipeline instead of a quietly
incomplete off-host copy.

The concrete HTTPS sink accepts only an `https://` origin, refuses redirects, bounds response
bodies, and requires the collector to acknowledge the exact chained hash. Its production client is
built with `audit.NewMTLSHTTPClient`: TLS 1.3, explicit roots and server name, a hardware-capable
`crypto.Signer` client identity, and no environment-derived proxy. Supplying a generic default
HTTP client is permitted only in unit tests.

The hash chain detects reordering, deletion and alteration relative to a head already held off-host.
It does not stop a fully compromised local host from rewriting an unexported chain. Production
shipping must therefore persist every acknowledged head in separately administered append-only
storage within the operation deadline. A future hardware signature checkpoint may strengthen this,
but must not put a second signing operation on every latency-sensitive request without measurement.

On startup, verify the complete local chain before appending. Alert on sequence gaps, conflicting
hashes for one sequence, registry/policy digest changes outside a deployment window, repeated denies,
and collector acknowledgement latency. Never repair or truncate a corrupt chain in place; quarantine
it, reconcile against the off-host copy, and open a fresh explicitly linked segment through an
incident-approved procedure.
