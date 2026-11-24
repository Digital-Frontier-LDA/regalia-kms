# Review: regalia-kms-dx7.8 (single-node rolling update and site advance as planned outages)

- Date: 2026-11-24, review run 5e2c8bd6
- Branch: bead/regalia-kms-dx7.8 at ab17192e (PR #779); merge-base with origin/main f86b76a6
- Diff: 12 files, +876/-58 (KERNEL-UPDATE.md, deploy/baremetal/{README.md,owner.py,ownerunlock.py,rollout.py,update.py},
  docs/design/single-node.md, e2e/one-node.py, 4 test modules)
- Verdict: **fixes needed (NEXT: feedback)**. AC2 is not met: the documented evidence path is refused every time
  (finding 1), and under an unphased measurement set the owner's unlock record alone passes retire (finding 2,
  fails open).

## How this was checked

- Targeted suites at head: `python3 -m unittest tests.test_baremetal_rollout tests.test_baremetal_rollout_cli
  tests.test_baremetal_update tests.test_baremetal_owner_unlock.AttestBooted` -> Ran 129 tests, OK (skipped=1).
- Probe tests (scratch, run against this worktree and against an export of f86b76a6), output quoted below.
- 15 mutants on an export of HEAD (`git archive HEAD`), each applied alone, the named tests run, then reverted.
- Callers of every changed signature found with rg (outside tests/).

## Findings (most severe first)

### 1. HIGH: `update quote-for-owner` evidence is always refused by `owner.py attest-booted` (AC2, the runbook path)

- deploy/baremetal/update.py:374 builds the evidence as `dict(host.quote(nonce, manifest), phase="system")`.
- deploy/baremetal/ownerunlock.py:245 reads `phase`, then ownerunlock.py:251 passes the **same dict, with the
  `phase` key still in it**, to `lease.reattest`.
- deploy/baremetal/lease.py:416 checks exact keys (`EVIDENCE_KEYS` plus an optional `pcr_values`), so it refuses.
- Probe: evidence shaped as quote-for-owner prints it (AttestBooted.evidence(..., phase="system")), passed to
  `ownerunlock.attest_booted`:
  `REFUSED: attestation evidence fields mismatch: missing=[] unknown=['phase']`
- Effect: KERNEL-UPDATE.md step 3 (node quote, then `attest-booted --evidence`) can never write the retire
  evidence. Under a per-phase set the retire is unreachable (it fails closed). Under an unphased set the only owner
  record that exists is the unlock's, which finding 2 then counts. The previous STAGE-CHECK's "runnable end to end"
  is not true.
- Why the tests miss it: tests/test_baremetal_owner_unlock.py:376 `evidence(..., phase=None)` defaults to no
  phase, and every AttestBooted test that expects success uses that default. The update tests stop at FakeHost.quote
  and never feed its output to `attest_booted`. Mutant M9 (drop the initrd check) surfaced the same error
  text, `unknown=['phase']`.
- Fix direction: strip `phase` (a node claim, which only selects the early refusal) before `lease.reattest`. Add a
  test that feeds `update.quote_for_owner`'s exact output through `attest_booted` to a passing `retire_ready`.

### 2. HIGH (fails open): under an unphased set, the owner's UNLOCK record alone passes retire (AC2)

- deploy/baremetal/attest.py:625: `seen_phase = phase if "phases" in matched[0] else None`. The owner's unlock
  (ownerunlock.may_unlock, phase="initrd") of a node on an unphased set records `"phase": None`.
- deploy/baremetal/rollout.py:170-172 `_up`: `"initrd"` returns False, but `None` on a set without "phases" returns
  True. So the unlock record counts as "up on the target".
- Nothing restricts the single-node profile to per-phase sets: rg for phases/UKI in membership.py and
  docs/design/single-node.md finds nothing, while the same pattern matches in attest.py. attest.py:49-50
  documents unphased sets as valid ("a host that does not boot a UKI").
- Probe (AttestBooted fixtures, unphased doc; only `ownerunlock.may_unlock` was run, no attest-booted):
  ```
  P1 owner-unlock record: {'epoch': 1, 'label': 'current', 'phase': None}
  P1 set is per phase: False
  P1 retire_ready on the unlock record alone -> {'a': ['owner']}
  ```
  This is the case AC2 forbids: an initrd that asked for its disk and may never have come up.
- Why the tests miss it: tests/test_baremetal_rollout.py:970/992 and test_baremetal_rollout_cli.py:570 build a
  record `("image-2", "initrd")` by hand on an unphased set, which the verifier never writes there. The
  realistic `phase: None` record is not tested. The `_up` docstring itself says "the no-phase case under
  single-node is one its witness does not write", and the owner's unlock does write it.
- Fix direction: under SINGLE_NODE, count only `phase == "system"` (attest_booted always stamps it), whatever the
  set's shape. Add a test with the record `may_unlock` actually writes.

### 3. MEDIUM (regression): a manifest failure in apply/promote/quote-for-owner is no longer on the update trail

- deploy/baremetal/update.py:195-196, 301-302, 352-353 now call `membership.profile(host.manifest())` while
  building `event`, **before** the `try` that records a DENY. update.py:56 and :130 promise "Every exit is on the
  update trail".
- Probe (`host.manifest` raises Refused("the chain does not verify from the root key"), then `update.apply`):
  - base f86b76a6: `[{'event': 'update-apply', ..., 'outcome': 'DENY', 'reason': 'the chain does not verify from the root key'}]`
  - head ab17192e: `[]`
- The refusal still raises (no action is taken), but an unverifiable chain, the case an auditor most needs, now
  leaves no record. It also verifies the chain twice per run.
- Fix direction: set topology inside the `try` from the `manifest` already read there.

### 4. MEDIUM: the documented nonce timing cannot work (AC4 runbook, owner.py)

- deploy/baremetal/owner.py:454 (`--nonce` help): "the owner's tool does this **before the node boots the new
  image**". A nonce lives NONCE_TTL = 120 s (attest.py:99). A server reboot, the owner's unlock and the hand carry
  take longer, so verify refuses with "the nonce expired" (attest.py:589).
- The nonce comes from the same verifier (attest.json) that `owner.py unlock` issues nonces from, and
  MAX_OUTSTANDING = 8 per node (attest.py:100, 557-559) evicts the oldest. Unlock retries in the same window can
  evict it.
- KERNEL-UPDATE.md:168 still says only "the host prints it for the owner's tool". It names neither
  `owner.py attest-booted --nonce` nor `update quote-for-owner --nonce`, nor that the owner must issue the nonce
  after the host is up and carry the evidence back within 120 s.

### 5. LOW: the runbook's promote row names a flag promote does not have, and the promote trail says planned_outage false

- KERNEL-UPDATE.md:152 says "(the self-issued one, `--planned-outage`)". `--planned-outage` is added only to
  `apply`'s parser (update.py:554, under `if name == "apply"`), so `update promote --planned-outage` is an argparse
  error.
- update.py:597 calls `promote(host, args.esp, ask, record)` without planned_outage, so a single-node promote
  records `"planned_outage": false`. KERNEL-UPDATE.md:150 says the trail records `planned_outage: true` "on every
  event".

### 6. LOW: the single-node may-reboot text drops two operator warnings

- rollout.py:607 returns early with a template that omits "TIME IS THE SYSTEM CLOCK, not authenticated" (no
  --now) and "the manifest was NOT checked against this host's TPM epoch counter" (no --tpm-index). The
  multi-node text prints both. update.py:251 (DEADLINE text) still says "its peers unlock it" under single-node.

### 7. NIT: three new checks are redundant (their mutants survive the suite)

- M5 rollout.py:555 (`_states` owner-only) is covered by `_witnesses`.
- M15 rollout.py:324/366 (the `peer in witnesses` filter) is covered by `_witnesses`.
- M7 (apply skipping `fresh_leases` under single-node) is a no-op, because `authorizers()` is already empty with one
  node.
- None is wrong. The first two are defence in depth, but no test pins them.

## Acceptance criteria, one line each

- AC1 (may_reboot single-node passes only with ACTIVE, two sets, --planned-outage; trail records it): **PASS**.
  rollout.py may_reboot plus SingleNodeReboot; apply trail keys in update SingleNode. Mutants M1, M2 and M6 are
  caught. (The promote event's planned_outage=false is finding 5.)
- AC2 (retire refused until the owner tool has seen the node boot on the target; the node's own state never
  evidence): **FAIL**. The own-state rule holds (M3 caught). But the boot evidence the tool chain produces is always
  refused (finding 1), and under an unphased set an unlock-only owner record passes (finding 2).
- AC3 (site advance PCR 12 judged by owner.py unlock, test): **PASS**. AttestBooted.test_a_site_advance... runs
  (not skipped). Mutant M11 (the verifier ignores the PCR digest) makes it fail. No production change, as planned.
- AC4 (KERNEL-UPDATE.md single-node runbook): **PARTIAL**. The section exists (KERNEL-UPDATE.md:140ff), but
  step 3 omits the commands and gives no workable nonce timing (finding 4), and the promote row names a
  non-existent flag (finding 5).

## Mutant controls (export of HEAD, each alone, then reverted; unmutated control green)

| # | Mutant | Tests run | Result |
|---|---|---|---|
| M1 | single-node: drop the planned_outage requirement (rollout.py) | rollout SingleNodeReboot, rollout_cli SingleNode, update SingleNode | FAILED (failures=3) "Refused not raised" |
| M2 | multi-node: drop the --planned-outage refusal | same | FAILED (failures=3) "'--planned-outage is a single-node decision' not found" |
| M3 | _witnesses: drop the owner-only rule | rollout SingleNodeRetire, rollout_cli SingleNode | FAILED (failures=2) |
| M4 | _up: drop initrd -> False | rollout (all), rollout_cli SingleNode | FAILED (failures=3) |
| M5 | _states: drop the CLI owner-only check | rollout_cli SingleNode | **OK (survives)**: redundant with _witnesses |
| M6 | apply: drop the planned_outage/topology trail keys | update SingleNode | FAILED (failures=1, errors=1) KeyError 'planned_outage' |
| M7 | apply: ask peers under single-node | update SingleNode | **OK (survives)**: no-op, authorizers() empty |
| M8 | promote: peers instead of the self-lease | update SingleNode | FAILED (errors=1) |
| M9 | attest_booted: drop the initrd-phase refusal | owner_unlock AttestBooted | FAILED, and the message exposed finding 1 ("unknown=['phase']") |
| M10 | attest_booted: drop the no-phase -> "system" stamp | owner_unlock AttestBooted | FAILED (2) phase None != 'system' |
| M11 | attest.verify: ignore the PCR digest | AttestBooted site-advance test | FAILED "'PCR 12 is' not found" |
| M12 | quote_for_owner: drop the self-lease check | update SingleNode | FAILED "Refused not raised" |
| M13 | quote_for_owner: drop the single-node check | update SingleNode | FAILED "Refused not raised" |
| M14 | owner.py attest-booted: separate state file | owner_unlock AttestBooted | FAILED (errors=1) |
| M15 | retire_ready/stranded: drop the `peer in witnesses` filter | rollout SingleNodeRetire, rollout_cli SingleNode | **OK (survives)**: redundant with _witnesses |

## Public interface changes (who calls them)

| Change | Callers outside tests | Asked by the bead? |
|---|---|---|
| `rollout.may_reboot(..., planned_outage=False, run=...)`: new kwarg before `run` | update.py:226/265, rollout.py:601, e2e/rolling-threenode.py:111. All pass `run=` by keyword, so none breaks | yes |
| may_reboot result: new key `planned_outage` (both profiles); `seconds` is None and `authorizers` [] under single-node | update.apply (handles it), rollout may-reboot JSON | yes |
| `rollout may-reboot` CLI: `--planned-outage` added; `--attest-state` no longer argparse-required (still required in code under multi-node); JSON adds `topology` and `planned_outage` | operators (KERNEL-UPDATE.md) | yes |
| `rollout retire-ready` / `propose`: `--state owner=FILE` under single-node; `_states(items, profile=None)` | rollout.py only | yes |
| `_witnesses` / `retire_ready` / `stranded`: owner-only under single-node; new "no witness has verified" text | rollout.py, manifest.py:469 via check_lockout (signature unchanged) | yes |
| `_up`: an "initrd" record never counts, also for unphased sets | rollout only; the verifier never writes "initrd" for unphased sets, so there is no multi-node effect | yes (but see finding 2) |
| `update.apply(..., planned_outage=False, say=print)`: new kwarg before `say` | update.main (positional only up to deadline_minutes) | yes |
| `update.promote(..., say=print, planned_outage=False)` | update.main (never passes it, finding 5) | yes |
| update trail: `planned_outage` and `topology` on update-apply/update-promote; new event `update-quote-for-owner` | only update.py reads these events (rg) | yes (keys added, none renamed) |
| new `update quote-for-owner --nonce` CLI, `update.quote_for_owner`, `Host.quote` | operators | yes (plan B) |
| new `owner.py attest-booted --nonce / --evidence --session`, `ownerunlock.attest_booted` | operators | yes (plan C) |
| owner attest.json measurement record: `phase: "system"` stamped by attest_booted | rollout retire_ready/stranded | yes |

No unasked interface change was found. Finding 3 is a behaviour regression in the trail, not a signature change.
