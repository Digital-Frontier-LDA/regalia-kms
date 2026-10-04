# Monitoring: the contract with the external service (#351)

The owner decided (2026-10-04, ADR-0002 D28.6, #351) that monitoring is an **external service** the owner
chooses: no Prometheus or Alertmanager runs on the three KMS servers. Each server exposes its metrics; the
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
  their contract). Both are standard Prometheus rule files; any service that evaluates PromQL rules can load
  them. Severity: `critical` pages, `warning` is looked at within hours.
- **Delivery to the owner** of every firing alert, through a channel the owner chooses (mail, a push
  service). The channel carries the alert's name, its labels and its summary, nothing else (section 6).
- **Its own availability**, watched from outside the three servers: if the service stops, nothing on the
  servers notices. A scrape that fails is itself an alert (`RegaliaNodeExporterDown`), but only a running
  service raises it.

## 2. What each node gives it

| endpoint | where | what |
|---|---|---|
| node_exporter | `https://<host_ipv4>:9100/metrics` | the host's own series, and the textfile series every Regalia service writes (`deploy/baremetal/metrics.py`'s registry, `METRICS`: time, heartbeat, unlock refusals, lease, audit shipping) |
| the KMS daemon | `https://<host_ipv4>:<kms_port>/v1/metrics` | the daemon's operational series ([OBSERVABILITY.md](../../OBSERVABILITY.md)) |

A scrape interval of 15 to 60 s suits both. The textfiles are written at their writers' own pace (every 5 to
60 s); the rules carry their own staleness checks (`RegaliaNodeMetricsStale`, `RegaliaAuditShipMetricsStale`),
so a scrape interval does not hide a writer that stopped.

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

- **A node that cannot be scraped** raises `RegaliaNodeExporterDown` (critical, after 2 minutes).
- **A writer that stopped** leaves its file to age: `RegaliaNodeMetricsStale` (2 minutes),
  `RegaliaAuditShipMetricsStale` (5 minutes for a shipper's).
- **A writer that never wrote** (after a boot, `/run` is empty) leaves no series at all, which no value rule
  can see: `RegaliaAuthtimeMetricsMissing`, `RegaliaHeartbeatMetricsMissing` and `RegaliaLeaseMetricsMissing`
  fire when a scraped node has no such file for 5 minutes.
- **A file node_exporter cannot read** drops its series: `RegaliaNodeTextfileUnreadable`.
- **Silence is not health.** The rules above make a missing signal an alert; the one thing they cannot see is
  the service itself having stopped (section 1).
- On the node, nothing waits for the service: the metrics are written whether or not anyone scrapes them,
  and no node behaviour depends on monitoring.

## 5. How to check a candidate service

- **The rules evaluate as intended:** `tests/test_node_alert_firing.py` and `tests/test_alert_firing.py` drive a
  fault at every rule under `promtool test rules` and require each to fire, and to stay silent when healthy.
  A service that loads Prometheus rule files evaluates them the same way.
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
