# KMS observability contract

The daemon serves its operational state at `GET /v1/metrics` in Prometheus text exposition format
(`text/plain; version=0.0.4`). This document is the contract for what is exposed, why it is safe to
expose, and the condition under which each series should wake someone up. Alertmanager rule files are
deployment-side and land separately; the conditions below are their source.

## Authorization is part of the design

The endpoint sits behind the same mTLS authenticator as every operation, but authentication is not
enough: the caller's SPIFFE identity must be listed in `metrics_reader_principals`. The empty list
refuses everyone. Plaintext loopback carries no identity, so in development mode the route is still
registered and still answers — with a refusal. The endpoint is unscrapable there, not absent, and
the difference matters: anyone reading "absent" could conclude development mode is safe to bind to
a non-loopback interface.

Why authorization rather than mere authentication: even with no request-derived labels, aggregate
per-route rates reveal the business rhythm of what is being signed — release cadence, signing
volume, outage shape. A valid workload certificate proves you may call the KMS, not that you may
observe it.

## The oracle rule

Label values come only from static, configuration-known enumerations:

- route paths from the API contract (`api.OperationPaths()`),
- device ids from the custody manifest,
- fixed enums decided in code (`decision`, `outcome`, `reason`).

Never from request data. A counter labelled by object id, principal or purpose would leak what is
being signed and by whom to anyone who can scrape. Cardinality is bounded by construction: every
label's value set is enumerated in code or config, and request paths outside the API contract land
in the fixed `unknown` bucket.

Deliberately NOT exposed: per-object quota gauges (object-id oracle), per-principal counters
(principal oracle), audit event content (the journal is the audit surface; authorized readers go
there), and fencing failure detail (static reason strings exist only at evaluation time; the epoch
journal on disk carries them).

## Staleness is a first-class signal

Every cached or passively-evaluated gauge ships with the timestamp of the reading. A gauge without
its age reads as current forever, and a stuck reading is a blind spot, not a healthy subsystem:
"PIN retries 3" measured an hour ago while the card sits at 1 is worse than no number. Alert
conditions below therefore pair value with freshness.

## The series and their alert conditions

| Series | Type | Labels | Alert condition |
| --- | --- | --- | --- |
| `regalia_audit_shipping_configured` | gauge | — | none (context for the next three) |
| `regalia_audit_backlog_events` | gauge | — | `> 0` for 5m: warn. `> 4096` (`maxAuditBacklog`): page — readiness is already false; this says why |
| `regalia_audit_oldest_unshipped_age_seconds` | gauge | — | `> 300`: page. The off-host tamper-evident copy is falling behind |
| `regalia_audit_shipped_sequence` | gauge | — | `rate == 0` while `backlog > 0` for 5m: page (shipper stuck) |
| `regalia_audit_verify_outcome` | gauge | `outcome` | `{outcome="chain-broken"} == 1`: page security — the journal on disk no longer matches what was written. `{outcome="unreadable"} == 1` for 2m: page operations — the verifier cannot read what it audits. `{outcome="unknown"} == 1`: page — an outcome outside the enum is a wiring bug, and the trail's state is being misreported |
| `regalia_audit_verify_last_run_seconds` | gauge | — | `time() - value > 120` (twice the 60s interval): page — the verifier has stopped asking. Startup verification seeds it, so a never-started loop reads as stale from boot, not absent |
| `regalia_fencing_evaluated` | gauge | — | `== 0` for 5m: page — fencing is configured and the lease has never been evaluated, so this site's role is unknown rather than passive |
| `regalia_fencing_lease_held` | gauge | — | `== 0` for 2m on the intended-active site: page. (On the passive site `0` is normal — the rule carries the site's role.) Absent until the first evaluation, so this cannot fire on a restart — `regalia_fencing_evaluated` covers that state |
| `regalia_fencing_lease_epoch` | gauge | — | change outside a planned failover: investigate — two sites believing they are active is the state fencing exists to prevent |
| `regalia_fencing_last_check_seconds` | gauge | — | `time() - value > 120`: page — the lease evaluation itself has stopped; held/lost is now a stale claim |
| `regalia_backend_quarantined` | gauge | `device`, `reason` | nonzero: page. A key's custody is degraded; the reason says which way |
| `regalia_token_pin_retries_remaining` | gauge | `device` | `<= 2`: page — a lockout bricks the token. Under-reported by design (PKCS#11 flags are coarse) |
| `regalia_token_pin_retries_updated_at_seconds` | gauge | `device` | `time() - value > 900` while the daemon serves traffic: page — the reading is stale |
| `regalia_policy_quota_rejections_total` | counter | — | any increase sustained over 1h: investigate — a workload hit its cap, or something is retrying into one |
| `regalia_ready` | gauge | — | `== 0` for 2m: page |
| `regalia_readiness_transitions_total` | counter | — | `> 3` in 10m: investigate — the service is flapping |
| `regalia_readiness_last_check_seconds` | gauge | — | `time() - value > 120`: the LB stopped asking, which is itself odd |
| `regalia_http_router_decisions_total` | counter | `decision` | `rejected` climbing while clients are correctly configured: a path nothing serves — the #72 signature. Distinguish from `regalia_http_requests_total`: routed-but-never-handled means unreachable feature; rejected means not part of the API |
| `regalia_http_requests_total` | counter | `route`, `outcome` | `5xx` on any route for 5m: investigate. A configured route with zero handler entries while its `operations` decision count climbs: unreachable feature |
| `regalia_http_unauthenticated_total` | counter | — | sustained increase: probing, or a client's certificate expired unnoticed |

Absent series are meaningful: a nil source removes the series rather than reporting zero, so
"not configured" never reads as a healthy zero. Counters that do exist report zero from startup,
because a counter that only appears on its first event cannot be alerted on.
