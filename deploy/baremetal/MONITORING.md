# Monitoring: the contract with the external service (#351)

The owner decided (2026-10-04, ADR-0002 D28.6, #351) that monitoring is an **external service** the owner
chooses: no Prometheus or Alertmanager runs on the KMS servers. Each server exposes its metrics; the
outside service scrapes them, evaluates the alert rules shipped here, and tells the owner. This page is what
that service must provide and what it gets. It reads alike with `AUDIT-COLLECTOR.md` (regalia-kms-1e, being
written for #351), the same contract for the audit collector.

## 1. What the external service must provide

- **Scraping over mutual TLS 1.3**, from fixed addresses, with a client certificate issued by the
  **monitoring CA** (for node_exporter) and a KMS workload certificate whose identity is listed in the
  daemon's `metrics_reader_principals` (for the KMS daemon's own metrics). Plain HTTP is never answered.
- **The alert rules, loaded as files:** `deploy/monitoring/regalia-node.rules.yml` (the node's services:
  time, heartbeat, leases, audit shipping, the metrics files themselves) and
  `deploy/monitoring/regalia-kms.rules.yml` (the KMS daemon: [OBSERVABILITY.md](../../OBSERVABILITY.md) is
  their contract), plus `deploy/monitoring/regalia-single-node.rules.yml` (availability and topology
  metadata across both scrape jobs). All three are standard Prometheus rule files. Route `critical` to
  the pager, `warning` for investigation within hours, and `info` without paging.
- **Delivery to the owner** of every firing alert, through a channel the owner chooses (mail, a push
  service). The channel carries the alert's name, its labels and its summary, nothing else (section 6).
- **Its own availability**, watched independently from the KMS servers. Only a running monitoring service
  can detect and report a failed scrape.

## 2. What each node gives it

| endpoint | where | what |
|---|---|---|
| node_exporter | `https://<host_ipv4>:9100/metrics` | the host's own series, and the textfile series every Regalia service writes (`deploy/baremetal/metrics.py`'s registry, `METRICS`: time, heartbeat, unlock refusals, lease, audit shipping) |
| the KMS daemon | `https://<host_ipv4>:<kms_port>/v1/metrics` | the daemon's operational series ([OBSERVABILITY.md](../../OBSERVABILITY.md)) |

Scrape both endpoints every 15 to 60 s and evaluate rules on a comparable interval. Also send a separate
**`GET /v1/health/ready`** probe over HTTPS to the daemon every 30 to 60 s so readiness is reevaluated well
inside the 120 s evidence window. Readiness returns 200 or 503 and does not require a KMS client identity.
Validate the server's TLS certificate. The metrics endpoint does require an allowlisted workload identity.
Scraping `/v1/metrics` reads the recorded readiness result; it does not run the readiness checks. See
[API.md](../../API.md) for the health and metrics routes.

`regalia_topology_nodes` in sync's `membership.prom` reports the designed cluster size from the verified
membership manifest. It is one for a single-node topology, three for legacy manifests, and the declared size for
a v5 multi-node topology. Retired entries and revocation do not change the genesis-fixed size. This gauge
describes the topology of the last verified manifest. Use external target metadata to detect an outage when
the target's live samples are unavailable.

**The scrape job is `regalia-node`.** Configure `job_name: regalia-node` for node_exporter.
**The daemon scrape job is `regalia-kms`.** Configure `job_name: regalia-kms` with
`metrics_path: /v1/metrics` for the daemon. Use `scheme: https` and the respective TLS configuration on
each job. Use these exact names and keep one cluster per rule evaluation environment. Fleet comparisons
group on `job`, so combining multiple clusters under the name would skew those comparisons.

As a commissioning prerequisite, register **both** endpoints for every node in persistent external scrape
inventory. Set the target label `topology_profile` to the fixed value `single-node` or `multi-node` on both jobs.
Set `honor_labels: false` on both jobs so an endpoint cannot override inventory labels. Keep both targets
registered during reboots, failed scrapes and outages, including before their first successful scrape. A
profile is an external label for monitoring, not an admission decision. The two endpoints can have different
`instance` values. Keep each `job`, `instance` pair unique so that no other endpoint supplies its health evidence.

The rule tests hold job matchers to these names. New registrations require the profile label on both jobs. Older
unlabeled targets keep the legacy multi-node alert behavior while the metadata warning is active.

## 3. Configuration on the node

Everything comes from the node's validated site configuration (`/etc/regalia/site.json`,
`deploy/baremetal/sitecfg.py`), so the firewall, the exporter and this contract cannot disagree:

- **`monitoring_cidrs`**: the external service's scraping addresses. `firewall.py` opens TCP 9100 from them
  only, and the KMS port from them and `client_cidrs`; nothing else reaches either.
- **node_exporter**: Debian's `prometheus-node-exporter` (1.9 or later). `/etc/default/prometheus-node-exporter`
  takes the line `python3 -Es -m deploy.baremetal.metrics node-exporter-args /etc/regalia/site.json` prints:
  it listens on `host_ipv4:9100` only, with `--web.config.file=/etc/regalia/node-exporter/web.yml`, and reads
  `/run/regalia-metrics/*`. Its drop-in `units/prometheus-node-exporter.service.d/regalia.conf` gives it the
  `regalia-metrics` group, its only way to read the textfiles.
- **`/etc/regalia/node-exporter/`**: `web.yml` from `deploy/baremetal/node-exporter/web.yml` (mutual TLS 1.3,
  `RequireAndVerifyClientCert`); `server.pem` and `server.key`, this node's certificate; `monitoring-ca.pem`,
  the CA whose certificates the service presents. **The hand-off:** the owner gives the service a client
  certificate from that CA, and installs the CA on each node; the service trusts each node's server
  certificate through the CA that issued it.
- **The KMS daemon**: the service's workload identity listed in `metrics_reader_principals` (the empty list
  refuses everyone).

## 4. Failure behaviour and alerts

- **A registered single-node endpoint** raises `RegaliaSingleNodeDown` (critical) at the first rule
  evaluation that observes a failed scrape or cannot confirm health from a successful scrape. For
  node_exporter, health needs `regalia_admission_serving == 1` and the mtime of `lease.prom` (typically
  `/run/regalia-metrics/admission/lease.prom`). For the daemon, health needs `regalia_ready == 1` and
  `regalia_readiness_last_check_seconds`. Each timestamp must be no more than 120 s old and must not be in
  the future. A false or missing signal is enough to page. The alert can identify an endpoint that has never
  responded or has stayed down past scrape lookback. Its latency includes the scrape/probe and evaluation
  schedules; the rule adds no delay. A failed scrape means service is unavailable or unconfirmed to the
  monitor. Investigate the endpoint, network and TLS as well as the machine.
- **Topology metadata** warns after five minutes for missing or invalid profiles on either job, or for
  missing or conflicting live topology on a successfully scraped exporter with valid metadata. The external
  inventory profile excludes single-node targets from both sides of the fleet comparisons and from survivor
  and recovery-key alerts. Sync's own topology gauge cannot exempt a target or remove a comparison reference;
  in particular, it cannot silence the root-produced anchor alert. Missing inventory labels retain legacy
  coverage. Correct registration is a commissioning requirement; repair metadata when the consistency warning
  fires. Live size one emits informational `RegaliaOwnerAssistedReboot`: an owner must be present on each boot.
  It does not page or change which other alerts apply.
- **Other targets** that cannot be scraped still raise `RegaliaNodeExporterDown` (critical, after 2 minutes).
  The delayed `RegaliaNotServing` and `RegaliaNotReady` rules also retain legacy coverage. The three shared
  alerts exclude explicitly registered single-node targets, which have the earlier composite page.
- **A writer that stopped** leaves its file to age: `RegaliaNodeMetricsStale` (2 minutes),
  `RegaliaAuditShipMetricsStale` (5 minutes for a shipper's).
- **A writer that never wrote** (after a boot, `/run` is empty) leaves no series at all, which no value rule
  can see: `RegaliaAuthtimeMetricsMissing`, `RegaliaHeartbeatMetricsMissing` and `RegaliaLeaseMetricsMissing`
  fire when a scraped node has no such file for 5 minutes; `RegaliaAuditShipMetricsMissing` when it lacks the
  shipper's file of any trail in `trails.py`'s registry (an instance never enabled, or refused its trail's path).
- **A file node_exporter cannot read** drops its series: `RegaliaNodeTextfileUnreadable`.
- **Limits.** No rule can detect an endpoint omitted from scrape inventory, and an offline monitoring service
  cannot send a page. Collector configuration enforcement and comparison against the collector's observed
  epoch remain separate work (regalia-kms-dx7.9).
- On the node, nothing waits for the service: the metrics are written whether or not anyone scrapes them,
  and no node behaviour depends on monitoring.

## 5. How to check a candidate service

- **The rules evaluate as intended:** the node, daemon and single-node firing tests use `promtool test rules`
  to exercise faults and healthy controls. Validate that the service loads all three files, sees both
  persistent target entries, and regularly probes `/v1/health/ready`.
- **The scrape path:** from one of the service's addresses, a request to `https://<host_ipv4>:9100/metrics`
  with its client certificate is answered; the same request without a certificate, or with one from another
  CA, is refused; and from any address outside `monitoring_cidrs` the port does not answer at all
  (`e2e/baremetal-firewall-netns.sh` holds the firewall side by behaviour).
- **Delivery:** fire a test alert (a rule with `expr: vector(1)`) and confirm the owner receives it, with
  nothing in it beyond its name, labels and summary.
- *Not built:* a single conformance command, like the audit collector's `regalia-audit-ship conformance`,
  that runs these checks against a candidate. Until then they are the three steps above.

## 6. What it never receives

- **No key, PIN, share or credential** of any kind: none is in any series, and none can be (the registry
  refuses a series it does not list, `metrics.render`).
- **No audit content:** the trails go to the audit collector, never to monitoring. A metric counts (lines
  committed, refusals by cause); it never carries what a line said.
- **No free text in a label:** every label value comes from an enumeration fixed in code or configuration
  (`metrics.py`'s registry for the node, the oracle rule in [OBSERVABILITY.md](../../OBSERVABILITY.md) for the
  daemon); a reason becomes a `cause` enum, and the reason itself goes to the trail.
- **No object, principal or request detail** from the KMS daemon ([OBSERVABILITY.md](../../OBSERVABILITY.md),
  "the oracle rule").
