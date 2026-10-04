# The external audit collector

Every node keeps its audit trails on its own disk, and each trail is shipped, line by line as it is written, to an
**audit collector outside the three servers**: a service the owner chooses (#351; owner's decision of 2026-10-04).
A compromised server can then still lie about what it does next, but it cannot erase or rewrite what it has
already recorded: the collector holds a copy, chained, and refuses anything that does not continue it.

This document is the contract that service must meet. `regalia-audit-ship conformance` checks a candidate against
it (section 5), and CI checks this repository's own `regalia-audit-collector` against the same contract, as the
reference implementation. The monitoring service has its companion document, `MONITORING.md`, with the same
sections (#364).

## 1. What the external service must provide

**Transport.** HTTPS over mutual TLS 1.3, at one origin, `https://host[:port]`, with no path.
- Its server certificate chains to a CA the owner gives the nodes (`collector-ca.pem`).
- The hand-off: the owner gives the service the CA the nodes' client certificates come from. It verifies each
  node's client certificate against it, and refuses a connection without one before any request is read.
- A client is identified by the SHA-256 of its certificate's DER ("identity"). Streams are keyed by identity plus
  the `X-Regalia-Site` header: `<site>.<trail>`, matching `[A-Za-z0-9._-]{1,64}`.

**Endpoints.** These are the only ones a node uses (`internal/audit/httpsink.go`):

| Request | Answer | Meaning |
|---|---|---|
| `HEAD /v1/health/ready` | `204` | ready to commit |
| `POST /v1/events` (one event, JSON, ≤ 64 KiB, `X-Regalia-Site`) | `204` with `X-Regalia-Audit-Hash: <the event's hash>` | committed **durably** before the answer |
| `GET /v1/stream-position` (`X-Regalia-Site`) | `200 {"sequence": n, "hash": "sha256:…"}` | the committed head of the caller's own stream |
| `GET /v1/receipt?sequence=n` (`X-Regalia-Site`) | `200 {"sequence", "event_hash", "line_sha256", "line_chain", "signature"}` | a signed receipt (below) |
| `POST /v1/alarms` (`{"sequence", "hash", "reason"}`) | `204` | a node reports its own trail no longer holds what was committed |
| `POST /v1/handover` | `204` | a node's client certificate rotated; its streams continue under the new one (#291) |

**The chain rules, which are the point of the service.**
- An event's `hash` must bind its content, and its `previous_hash` must be the committed hash before it.
- **The same event sent again** at a committed sequence is acknowledged, not appended: the node's ack was lost
  and it retries.
- **A different event at a committed sequence** (a rewrite) is refused, as is **an event out of order** (a gap).
  Each refusal is an alarm the service keeps, and the head does not move.
- It never deletes or rewrites what it committed. There is no endpoint that returns events, only positions.

**Signed receipts.** Each receipt is Ed25519 over the bytes `ReceiptPreimage`, one field a line:

    regalia.collector.receipt/v1
    <identity>
    <site>
    <sequence>
    <event hash>
    <line sha256>
    <line chain>

- `line chain` is the running digest of every trail line up to this one: `LineChain`, SHA-256 over the previous
  digest's 32 bytes and the line hash's 32 bytes, from 32 zero bytes.
- A receipt is given only for the caller's own stream, and only for a position it holds.
- Its signing key is the service's alone. Its public key, 64 hex, is pinned on every node. The pin is a set, so
  the key can rotate: pin the new key beside the old, then drop the old.

## 2. What each node gives it

- One stream per trail: `<site>.sync`, `<site>.admission`, `<site>.enrol`, `<site>.time` and the operator tools'
  trails (deploy/baremetal/trails.py's registry). Each is shipped by its own `regalia-audit-ship@<trail>`.
- Each trail line is sent as one event, whose detail names the line's SHA-256 (format `regalia.trail/…`). Content
  that carries a key, or is too long, is withheld and only its hash is sent (`internal/audit/trail.go`).
- About one request per new line, a position read every pass (30 s), and a receipt request per archive before it
  is pruned.
- An alarm when a node finds its own trail cut short, rewritten or removed. That shipper then stops (exit 3) and
  is not restarted until an operator looks.

## 3. Configuration on the node

All of it lives under `/etc/regalia/audit-ship/` and `/etc/regalia/audit-ship.env`. No collector host is built in.

| File | Holds |
|---|---|
| `/etc/regalia/audit-ship.env` | `COLLECTOR=https://host[:port]`, `SITE=<site>` |
| `client.crt`, `client.key` | this node's client certificate and key (0640 root:regalia-audit-ship) |
| `collector-ca.pem` | the CA the collector's server certificate must chain to |
| `collector-receipt.pub` | the pinned receipt key(s), one 64-hex Ed25519 public key a line, `#` comments |

- Before every start, each `regalia-audit-ship@<trail>` runs `regalia-audit-ship check`. That validates all of
  it together: the https origin (no path, query, fragment or user), the site, the certificate and key as a pair
  valid now, a usable CA, and at least one well-formed receipt key. A broken configuration fails the start by
  name.
- `regalia-audit-ship check … -probe -trail sync` also reaches the collector, read-only (readiness and each named
  stream's head), and says which step failed: unreachable, a certificate not from the CA given, or this client
  refused.

## 4. Failure behaviour and alerts

- **Unreachable.** The shipper retries each pass. The trail's writer is never slowed or blocked: the shipper only
  reads the trail file, and a trail rotates into archives (bounded) that are pruned only with a receipt.
- **Alerts** (`deploy/monitoring/regalia-node.rules.yml`), from the shipper's metrics:
  - `RegaliaAuditTrailBehind`: lines not committed for 15 minutes.
  - `RegaliaAuditTrailNeverShipped`: a backlog that has never shipped.
  - `RegaliaAuditTrailTampered`: a trail that no longer holds what was committed. This pages.
  - `RegaliaAuditShipMetricsStale`: the shipper itself not running.
- **No receipt, no prune.** An archive is removed only with the collector's signed receipt for its last line,
  verified against the pinned key(s), for this node's identity and stream, and with the line chain recomputed
  over the archive (`trails.py prune`). A collector that is down or does not sign means trails grow; nothing is
  lost.

## 5. How to check a candidate service

From a node, or a machine with a node's client certificate, run this against the candidate before pinning it:

    regalia-audit-ship conformance -collector https://candidate:8443 -site sitea \
        -tls-cert client.crt -tls-key client.key -server-ca candidate-ca.pem -receipt-keys candidate-receipt.pub

It runs the contract's rules through the shippers' own client, on a fresh stream of its own
(`<site>.conformance-<random>`), and exits 0 only when every one holds:
- readiness over mutual TLS;
- a fresh stream at 0;
- three chained events committed and acknowledged, and the head reported;
- the same event re-sent is acknowledged;
- a rewrite and a gap are each refused, and the head does not move;
- a receipt signed by a pinned key over exactly the identity, stream, event, line and line chain;
- no receipt for a position it does not hold;
- a client with no certificate is refused;
- an alarm is taken.

It writes three synthetic lines and one alarm to that stream, and nothing of a real trail. CI runs it against
`regalia-audit-collector` (`e2e/audit-ship-systemd.py`, step 5; `internal/audit/conformance_test.go`).

## 6. What it never receives

- No key, PIN, share or credential: not a node's, not the root's.
- No trail content that carries a key or exceeds the bound: only its hash.
- No KMS request payloads.

What it holds lets it prove what a node recorded, in order. It cannot be used to act on a node, and it gets no
endpoint on the nodes.
