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
**The collector scrape job is `regalia-collector`.** Configure `job_name: regalia-collector` with
`metrics_path: /metrics` for the audit collector's own witness (regalia-kms-dx7.9, D1=A): the off-host
reference the single-node behind rules compare a node against. It is scraped on the owner's monitoring
service (not the node), and a `metric_relabel_configs` rule copies each series' `site` label onto
`instance` so the reference carries the node's instance under the collector's job (section 4.1).

As a commissioning prerequisite, register **both** endpoints for every node in persistent external scrape
inventory. Set the target label `topology_profile` to the fixed value `single-node` or `multi-node` on both jobs.
Set `honor_labels: false` on both jobs so an endpoint cannot override inventory labels. Keep both targets
registered during reboots, failed scrapes and outages, including before their first successful scrape. A
profile is an external label for monitoring, not an admission decision. Keep each `job`, `instance` pair unique
so that no other endpoint supplies its health evidence.

**The node's `instance` is the shipper's site.** The single-node behind rules compare a node's epoch series
against the collector's witness on `instance` (the fleet rules join on `job`, which may differ; the behind rules
do not). So the `regalia-node` target's `instance` label must be set, in the inventory, to the node's shipper site
(the same value the collector's stream site carries, `nodea` for node-a) — not left at Prometheus's default of the
scrape address (`192.0.2.10:9100`). The collector's `metric_relabel_configs` (section 4.1) maps its `site` label to
that same `instance` and drops `site`, so both sides of the comparison carry one shared `instance` and nothing else
the join does not ignore. A target whose `instance` is the bare address never matches its own witness: the behind
rules stay silent for it and `RegaliaCollectorEpochMissing` fires.

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
  fires. Live size one on a single-node target emits informational `RegaliaNextBootNeedsOwner` (renamed from
  `RegaliaOwnerAssistedReboot`, regalia-kms-dx7.9): an owner must be present on each boot. It does not page or
  change which other alerts apply.
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
  cannot send a page.
- On the node, nothing waits for the service: the metrics are written whether or not anyone scrapes them,
  and no node behaviour depends on monitoring.

### 4.1 The single-node rule set (regalia-kms-dx7.9)

`deploy/monitoring/regalia-single-node.rules.yml` is the set of alerts that watches a one-node installation.
Every rule in it matches on the external inventory label `topology_profile="single-node"`, set on both scrape
jobs by the service's inventory; the fleet rules in `regalia-node.rules.yml` carry the mirror exclusion
(`topology_profile!="single-node"`), so a target is watched by exactly one set. The cross-profile matrix in
`tests/test_single_node_alert_firing.py` holds the two files to each other: every rule here is faulted on a
multi-node fixture and must stay silent, and every multi-node-only rule is faulted on a single-node fixture and
must stay silent.

The rules:

| alert | severity | what it is |
|---|---|---|
| `RegaliaSingleNodeDown` | critical | the composite page for a one-node installation: either endpoint not scraped, or a successful scrape that cannot confirm health (no fresh `regalia_admission_serving`/`lease.prom` mtime for the node, no fresh `regalia_ready`/`regalia_readiness_last_check_seconds` for the daemon). |
| `RegaliaTopologyProfileInvalid` | warning | the `topology_profile` inventory label is missing or not `single-node`/`multi-node` on either job, for five minutes. |
| `RegaliaTopologyMetricMissing` | warning | a scraped target with valid metadata has no `regalia_topology_nodes` series (the verified-topology gauge is absent), for five minutes. |
| `RegaliaTopologyProfileMismatch` | warning | the verified `regalia_topology_nodes` disagrees with the external inventory profile (single-node target reports a size other than one, or a multi-node target reports size one or less), for five minutes. |
| `RegaliaMembershipBehindCollector` | warning | the node's `regalia_membership_epoch` is older than the highest epoch the audit collector already committed in its sync trail (the off-host witness, D1=A), for thirty minutes. The reference is the collector's, not the node's own telemetry: a rolled-back or withholding node cannot supply its own floor. |
| `RegaliaAnchorBehindCollector` | warning | the same, from the collector's `esp-advances` witness: the node's TPM anchor lags what it has already shipped, for thirty minutes. |
| `RegaliaCollectorEpochMissing` | warning | the blind state of the two comparisons above: a scraped single-node target whose collector reference is absent (collector not configured, its scrape job missing, or no witness committed yet) has no right-hand side and the behind rules silently cannot fire. Warns after fifteen minutes. |
| `RegaliaNextBootCannotRender` | warning | `regalia_esp_boot_renderable == 0` under single-node: the chain on the ESP leaves the initrd nothing to render, and there is no peer to ask, so the next boot cannot be unlocked without the owner's recovery path. |
| `RegaliaNextBootNeedsOwner` | info | renamed from `RegaliaOwnerAssistedReboot` (design 4.5): `regalia_topology_nodes == 1` under single-node. Owner presence is required at each boot, including the next reboot. |
| `RegaliaRestorePending` | critical | the boot guard (regalia-kms-dx7.26) seen from monitoring: `regalia_restore_pending == 1` means `/etc/regalia/restore-pending` holds etcd and the daemon SKIPPED at every boot (a replacement disk awaiting its restore). The page names the cause. |
| `RegaliaRestoreMetricsMissing` | warning | a scraped single-node target has no `pending.prom` textfile: the restore-pending marker's state is not watched (the writer died before its first write, or the file is unreadable), for five minutes. |

**The collector's reference (D1=A).** `regalia_collector_witnessed_membership_epoch` and
`regalia_collector_witnessed_anchor_epoch` are scraped from the audit collector's own `/metrics` endpoint, on
the collector's mTLS listener (the same listener and client CA the sink's protocol uses — one door, not a
second). The endpoint emits ONE series per node: the membership series (from the node's sync trail) and the
anchor series (from its esp-advances trail) share the label `site` = the node's own site (the stream's site
minus its trail suffix), so a node's two gauges agree on identity and a node the collector has not seen gets
no series. The scrape job `regalia-collector` adds its own `job`, copies `site` onto `instance`, and drops `site`
(`metric_relabel_configs` — series labels are rewritten only there; `relabel_configs` rewrites target
metadata, which a scraped series no longer has), so the reference carries the node's `instance` under the
collector's job and no label the node's own series lack. The node's `instance` is set to the shipper's site in the
inventory (section 2), so the two sides agree on it. The behind rules compare on the full label set minus `job` and
`topology_profile` (the two labels the sides carry differently), so one-to-one on `instance`: a node is judged
against its own off-host witness, and another node's witness cannot be its floor. While the collector is not
configured or not scraping, the comparisons have no right-hand side and stay silent: that blind state is
`RegaliaCollectorEpochMissing`. The monitoring service must configure the scrape job:

```yaml
- job_name: regalia-collector
  metrics_path: /metrics
  scheme: https
  # mTLS: the service's client certificate, issued by the collector's client CA (the same CA the
  # sink's clients are). The collector's listener is RequireAndVerifyClientCert; a scrape with no
  # chain-verified certificate never reaches a handler.
  # Copy the collector's site label onto the node's instance so the behind rules' one-to-one
  # match on instance works, then drop the site label: the node's own epoch series carry no
  # site, and the rules' ignoring(job, topology_profile) join requires the sides to agree on
  # every other label, so a leftover site would keep the operands apart (the behind alerts stay
  # silent, and the missing-reference warning fires on every node). Distinct nodes keep distinct
  # instance values. This is metric_relabel_configs (series labels, post-scrape): relabel_configs
  # only rewrites target metadata at discovery time and cannot touch a label the endpoint emits.
  metric_relabel_configs:
    - source_labels: [site]
      target_label: instance
      action: replace
    - regex: site
      action: labeldrop
```

**The restore-pending metric.** `regalia_restore_pending` (0 or 1) is written by `deploy/baremetal/metrics.py`
into the node_exporter textfile directory (`/run/regalia-metrics/restore/pending.prom`). It is 1 while
`/etc/regalia/restore-pending` exists (the boot guard of regalia-kms-dx7.26 holds etcd and the daemon SKIPPED
at every boot) and 0 otherwise. `deploy/baremetal/restore.py` updates it at `mark_pending` and `clear_pending`;
`deploy/baremetal/node.py` publishes it on every sync.

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
