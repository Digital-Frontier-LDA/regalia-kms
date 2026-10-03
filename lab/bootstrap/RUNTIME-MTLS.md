# External runtime mTLS experiment

`internal/auth/mtls_live_lease_test.go` uses actual TCP/TLS 1.3 connections and the
repository's `ServerTLSConfig`, `Authenticator` and file-backed revocation list.
Its external HTTP gateway is a test fixture using production middleware; the
protected handler counts admitted requests. Every certificate/key is disposable
software material.

The test demonstrates:

- A valid node certificate reaches the handler.
- A new connection genuinely resumes its TLS session while still valid.
- After real certificate expiry, an existing connection receives HTTP 401.
- Both fresh and cached-session reconnects with the expired identity fail.
- A renewed node identity reaches the handler.
- Revocation rejects an existing connection and a genuinely resumed session.
- Loss of the revocation source keeps the existing connection unauthorized.
- Rejected requests never reach the protected handler.

The gateway checks authorization per request. TLS connection establishment and
session caching alone cannot determine continuing membership. This complements
the software cluster's independent verification of short-lived signed lease
responses, including a real SoftHSM signature obtained by bypassing local lease
checks and then rejected by the client.

Limits: the short real-time test explicitly uses zero certificate clock skew.
The daemon's current default permits one minute; production expiry bounds must
account for that value. This test does not join the lab's Python lease protocol
to this Go gateway, deploy a production gateway, qualify HTTP/2 streams, or prove
that a compromised node closes its own HSM sessions. External trust enforcement
and local cooperative logout remain separate controls.
