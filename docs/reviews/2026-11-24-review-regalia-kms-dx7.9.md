# Review: regalia-kms-dx7.9 (Single-node 9: monitoring and audit for one node)

- Run: review 5f0e68b1
- Head reviewed: b571a934 (branch bead/regalia-kms-dx7.9, PR #783), against origin/main f86b76a6, which is an ancestor
- Diff: 5 commits, 26 files, +1208/-40
- Result: **fixes needed (NEXT: feedback)**

## Findings, most severe first

### 1. CRITICAL (fails open): the collector's `/metrics` always reports epoch 0, so both BehindCollector rules can never fire
`internal/audit/collector.go:419-445` (`committedEvents`) reads `stream.file`. That handle is opened
`os.O_WRONLY|os.O_APPEND` in both places a stream is opened: `loadStream` (collector.go:250) and
`createStreamLocked` (collector.go:662). Every read fails with EBADF. `committedEvents` then returns nil,
`witnessedEpochs` returns (0, 0), and the endpoint serves
`regalia_collector_witnessed_membership_epoch{...} 0` for every stream.

- The input that breaks it: any committed sync ALLOW line. Probe on heavy-pool-h4i (scratch commit, not
  pushed): commit one `sync` ALLOW line at epoch 7, then scrape.
  - At b571a934: `Read on stream.file -> ... bad file descriptor`, and the scrape reads
    `regalia_collector_witnessed_membership_epoch{site="nodea.sync"} 0`. FAIL, want 7.
  - Control, with only the open flag changed to `O_RDWR`: the scrape reads `... 7`. PASS. So the
    read handle is the only cause.
- Why it is fail-open: a 0 reference is never greater than a node's epoch, so
  `RegaliaMembershipBehindCollector` and `RegaliaAnchorBehindCollector` (regalia-single-node.rules.yml:101,112)
  stay silent forever. The series is present, so `RegaliaCollectorEpochMissing` does not report the blind state
  either. The comment at collector.go:417 says a read failure yields a floor and never an invented value, but 0
  is exactly that kind of value.
- Not caught by the tests: `TestTheMetricsEndpointServesTheWitnessedEpochs`
  (cmd/regalia-audit-collector/main_test.go:159) scrapes an EMPTY collector and asserts only the two `# HELP`
  lines (:195-196). It passes with this bug, and it would also pass if `witnessedEpochs` returned a constant.
  No test commits a line and checks the value.
- Fix:
  - Open a separate read-only handle per scrape: `os.Open(c.streamPath(...))`, reading up to the size taken
    under `c.mu`.
  - On a read error, omit the stream's series (or fail the scrape), so the blind-state rule fires and the
    endpoint does not report 0.
  - Add a test that commits sync and esp-advances ALLOW lines and asserts both values, before and after a
    reload.

### 2. HIGH (fails open, and noisy): the witness series can never join a node's series in production
- `internal/audit/collector.go:355-356` labels each series `site=<stream site>`. The stream's site is
  `<site>.<trail>` (cmd/regalia-audit-ship/main.go:89,123: "the stream is <site>.<trail>"), so a node
  produces one series per trail: `a.sync`, `a.esp-advances`, `a.admission` and so on.
  - Each of those streams emits BOTH gauges. The sync stream reports anchor 0, the esp-advances stream reports
    membership 0, and every other trail reports 0 for both.
- The documented scrape job (deploy/baremetal/MONITORING.md:167-168) uses `relabel_configs` with
  `source_labels: [__meta_label_site]`. That relabels TARGET labels before the scrape. It cannot read or
  rewrite a label in the scraped series, and service discovery does not set `__meta_label_site`. So
  `instance` stays the collector's own address, and `site` stays on the series.
- The rules join with `ignoring(job, topology_profile)` (rules :102, :113, :128), which needs every OTHER
  label to be equal. The extra `site` label alone defeats the join, and so does an instance that is not the
  node's.
- Proven with promtool 3.1.0 on heavy-pool-h4i, using the real rule file: the node is at epoch 3 and the
  witness at 9 for 45 minutes.
  - Scenario A, the endpoint's output as scraped under the documented job:
    `{job="regalia-collector",instance="<collector>",site="a.sync"}`. BehindCollector gives `got:[]`.
  - Scenario B, the best case where an operator uses `metric_relabel_configs` to copy site to instance:
    `instance="a.sync"`. Still `got:[]`.
- Consequences:
  - BehindCollector cannot fire, independently of finding 1.
  - `RegaliaCollectorEpochMissing` (:125-128) fires permanently for every single-node target, even with a
    healthy collector.
  - If the labels were mapped one-to-one, the duplicate per-trail series would make the comparison a
    many-to-one match error.
- Not caught by the tests: tests/test_single_node_alert_firing.py:39 hand-builds
  `COLLECTOR = {"job": "regalia-collector", "instance": "a:9100"}`, a shape the endpoint never produces.
  The 131 promtool scenarios prove the rules against a fixture, not against the producer.
- Fix:
  - Emit one series per NODE: strip `.<trail>` and take the membership value only from the sync stream and the
    anchor value only from the esp-advances stream.
  - Put it under a label the rules join on explicitly, for example `on(instance)` after a documented
    `metric_relabel_configs` that maps the node's site to its scrape instance, or a shared `node` label.
  - Add a test that feeds the endpoint's real output, run through the documented relabeling, into promtool.

### 3. HIGH (AC2 and D2 not met): `sign`, `unwrap` and `certificate-sign` reserve policy state and are still served
- D2 is "every route that reserves policy or opstate state ... is refused". `internal/api/handler.go:161-170`
  declares sign, unwrap and certificate-sign stateless ("reserve no policy or opstate state").
- That is not what the policy engine does. `internal/policy/policy.go:333-343` calls `engine.state.Reserve`
  on EVERY allowed evaluation, with the spend-once `Nonce`, the `DailyCaps` amounts and, for a Cosmos
  transaction, `Sequence`/`SequenceKey`.
- A Cosmos transaction is signed through the `sign` operation (internal/operations/coordinator.go:387-399:
  "before policy reserves a sequence").
- The input: on a single-node host with no `audit_sink_url`, POST /v1/operations/sign with content type
  `application/vnd.cosmos.tx+protobuf`. It is served. It reserves a Cosmos account sequence, and a nonce and
  quota, with no off-host record. A replayed disk then replays that sequence: the hazard the refusal exists for.
- handler.go's own comment lists "a Cosmos sequence" as stateful. AUDIT-COLLECTOR.md:118 says "stateful
  operations spend a nonce". Sign and unwrap spend one too.
- `TestEveryOperationTheDaemonNamesStatelessIsServedUnderTheRefusal` (collector_required_test.go:132) pins
  this wrong set in place.
- Fix: refuse every operation that reaches `policy.Evaluate` under ModeSingle with no sink. Or, if the PA wants
  plain signing and decryption kept, at least refuse `sign` carrying a Cosmos transaction and record the PA's
  ruling that a nonce or quota reservation is acceptable without the collector. As written, the D2 text and the
  code disagree, so this needs either a code change or a PA ruling. It is not a test-only issue.

### 4. LOW: data race and unbounded memory in the scrape path
- `MetricsHandler` copies the stream map under `c.mu`, then reads `stream.size` and seeks or reads the
  shared `stream.file` without the lock (collector.go:419-445). `appendLocked` updates `size` under
  `c.mu` (:706), so this is a data race.
- Two concurrent scrapes share one file offset.
- `committedEvents` holds every event of a stream in memory on every scrape, which grows with the trail.
- The fix in finding 1 (a fresh handle, size read under the lock, a streaming scan) removes all three.

### 5. NIT: the doc comments do not match the code
- collector.go:321 says the gauges are "labeled by the client's instance and job". They are labeled by `site`.
- collector.go:330 says "Both are 0 (absent)". They are present, with value 0.

## Acceptance criteria, one line each
- **AC1 (alert tests, cross-profile): PARTIAL.**
  - Met: the matrix and the firing cases exist and fail without the change. The earlier check (cd7e4587) showed
    the reverted tree red and mutants M1, M3-M6 red. The check after it (b353c12d) showed M2 and M7 red. This
    review ran its own mutant R1 (the `topology_profile!="single-node"` exclusion dropped from
    RegaliaAnchorBehindFleet): FAILED (failures=1), against a baseline of 7 tests OK.
  - Not met: the two BehindCollector rules are proven only against a hand-made fixture. Against what the
    endpoint really emits they cannot fire (findings 1 and 2).
- **AC2 (stateful refused with no collector, an outage only alerts): PARTIAL.**
  - Met: wrap, key-agreement, release-secret and seal-envelope are refused before any reservation, following
    the live admission. CI ran the tests green. The earlier checks showed mutants G1-G4 red. A configured but
    failing sink still serves (TestASingleNodeWithACollectorServesAStatefulOperation).
  - Not met: sign (including Cosmos transactions), unwrap and certificate-sign still reserve policy state and
    are served (finding 3).
- **AC3 (MONITORING.md documents the single-node set): PASS** for the table and the doc test (mutant M6 was
  red in cd7e4587). The scrape-job snippet it documents is wrong (finding 2).

## Proof that the relied-on tests fail without the change
- Python and promtool: the reverted-tree run in cd7e4587 (failures=8, errors=5), M1-M7 in cd7e4587 and
  b353c12d, and R1 here (red).
- Go: G1-G4 in cd7e4587 and b353c12d. The CI build-test job at b571a934 shows all 53 packages ok.
- A test that does NOT fail without the behaviour it claims:
  `TestTheMetricsEndpointServesTheWitnessedEpochs`. It is green while the endpoint always serves 0
  (finding 1).

## Public interface changes (who calls them)
- **Alerts:**
  - `RegaliaOwnerAssistedReboot` was removed and is now `RegaliaNextBootNeedsOwner`, keyed on the inventory
    label. The caller is the owner's alert routing; the PA says nothing routes on it yet. Asked for (D3).
  - Seven new single-node alerts. Asked for.
- **Audit collector:**
  - New `GET /metrics` on the sink's mTLS listener. It exports
    `regalia_collector_witnessed_{membership,anchor}_epoch{site}`. The caller is the monitoring service's
    `regalia-collector` scrape job, which lives outside the repo. Asked for (D1=A).
  - **Flagged:** this label contract does not work as documented (finding 2).
  - The collector binary now mounts `Handler()` under "/v1/". Every existing route is under /v1/
    (collector.go:300-311), so no client breaks.
- **Go API (all additive):**
  - `admission.Status.Mode` and `(*Gate).Mode(ctx)`.
  - `operations.ModeAdmission`, `(*Coordinator).SetSingleNodeCollectorRequirement` and
    `SetStatelessOperations`.
  - `api.StatelessOperations()`.
  - Callers: cmd/regalia-kms/main.go and the tests only.
- **Daemon behaviour:**
  - New audit outcome `collector-not-configured` (503 DEPENDENCY_UNAVAILABLE, retryable).
  - A single node with no sink now refuses four operations. Asked for (AC2).
  - e2e/one-node.py configures a sink, so it is unaffected.
- **Node:**
  - metrics.py adds the writer `restore`, the file `pending.prom` and the metric `regalia_restore_pending`
    (additive).
  - regalia-sync.service ReadWritePaths gains `-/run/regalia-metrics/restore`, and tmpfiles adds that
    directory (2750 regalia-sync:regalia-metrics). The sandbox widening is narrow and tied to the new writer.
  - test_scrape_job_contract now allows the `regalia-collector` job.

## Checked and fine
- The restore-pending gauge. regalia-sync has no restore-pending condition, so it runs on a held host and
  publishes 1 at start. restore.py mark and clear update the gauge. RestoreMetricsMissing covers a file that is
  missing.
- The live-admission read of the mode, and the ordering of the not-admitted check before the collector check.
- No ekroots or PINS changes. No non-loopback addresses in the diff. No gate touched.

NEXT: feedback
