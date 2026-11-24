# Review: regalia-kms-dx7.7 (PR #778), run 80ad5a94

Reviewed head `638a9ae3` (bead/regalia-kms-dx7.7, base `3c7439f4`) against the bead's AC1–AC4.
Own test runs: local venv (Python 3.14, `cryptography`), 49 new tests + 4 mutant controls.

## Verdict

**No findings requiring fixes. NEXT: dod.** All four acceptance criteria are met and proven. The
Sentinel advisories are answered below.

## Acceptance criteria

- **AC1** (single-node re-anchor and crash-window recover succeed from the owner chain; refused when the
  collector reports a higher epoch): **PASS.** `convergence.agreed` and `convergence.recover` accept
  `owner_chain` as a source under a single-node tip; `reanchor.plan` and `reanchor.reanchor` take
  `owner_chain`; `recover.apply` wires `--owner-chain` through main → apply → hand_over → handed →
  restore. `verify_owner` under `single_node=True` refuses a statement with `collector_epoch > tip epoch`.
  Proven: 9 `OwnerChain` tests, 5 `SingleNodeCommand` tests, 5 `OwnerChainReanchor` tests, 1 mutant
  (collector-above-tip → red).

- **AC2** (multi-node still requires two node sources or one plus the owner, unchanged): **PASS.**
  The `owner_chain` path is gated on `membership.profile(tip) == SINGLE_NODE` in `convergence.agreed`
  (`convergence.py:170-173`); under a multi-node tip the owner chain is refused before any
  `may_authorize` check. Existing multi-node suites pass unmodified (182 tests, 12 pre-existing
  `reanchor.Command` environment failures identical on base). Proven: 2 mutant tests
  (`test_agreed_refuses_owner_chain_under_multi_node`,
  `test_recover_owner_chain_refused_under_multi_node`) red against a mutant that drops the profile
  guard; `test_multi_node_refuses_owner_chain` (reanchor); `test_verify_owner_under_multi_node_accepts_v1`.

- **AC3** (recount takes its floor from the owner statement/collector under single-node): **PASS.**
  `recount.plan` takes `owner_statement` (a floor source: its `collector_sequence`) and `signer`
  (the node's beat signing counter, a liveness floor). Under single-node with neither a verified
  heartbeat nor the statement, the recount is refused. Proven: 5 `SingleNodeRecount` tests,
  2 `CommandLine` tests (command-level `--owner-statement`), 1 mutant (drop
  `floor.append(st["collector_sequence"])` → red on 2 tests).

- **AC4** (MEMBERSHIP-RECOVERY.md gains a single-node section): **PASS.**
  `deploy/baremetal/MEMBERSHIP-RECOVERY.md:259-317` adds a "## Single node (docs/design/single-node.md 4.7)"
  section with the three commands, what the path loses per design 4.7, and a "What is tested" list
  naming every new test class. Absent at the base (grep on `3c7439f4` returns nothing).

## Sentinel advisories

1. **recover.py:342 — "onesource vs ownerchain phrase."**
   The phrase at `recover.py:370-375` has two branches:
   - `owner_chain is not None and one_source is not None` →
     `"recover %s to epoch %d %s from %s collector at epoch %d"` (names "owner-chain" and the collector's epoch).
   - otherwise →
     `"recover %s to epoch %d %s from %s%s"` (the existing multi-node / one-source phrase).

   The two branches are disjoint: the `owner_chain is not None` path requires `not peers`
   (`recover.py:359`), and the one-source path requires `len(peers) == 1`. The phrase is correct for
   each path. The `owner_chain` path always has `one_source` (main requires `--owner-statement` when
   `--owner-chain` is given, `recover.py:439-441`), so the first branch is always taken when
   `owner_chain` is non-None. No mixed phrase is possible.

2. **convergence.py:158 — "profile-check order."**
   The profile is read at `convergence.py:170-171` **after** chain verification, conflict detection,
   and the `anchored` check, but **before** the `may_authorize` check. This ordering is correct:
   - The profile must be read from the **newest verified manifest** (`last[longest]`), not the disk's.
     Reading it earlier (before verification) would judge a chain the node may not trust.
   - The `may_authorize` check is skipped for `__owner__` and runs for every other source. The
     profile check gates whether the owner chain is accepted at all, so it must run before the
     `may_authorize` loop (a multi-node tip with an owner chain should refuse, not pass
     `may_authorize` and then refuse at the profile).
   - A comment at `convergence.py:168-169` documents this: "read the profile BEFORE any may-require:
     it must not be a bare TypeError from a v5 topology this code does not know."

   No reordering is needed.

## Findings

No findings requiring fixes. The 12 `tests.test_baremetal_reanchor.Command` failures are pre-existing
environment failures (identical on a clean tree at `3c7439f4`: "Ran 37 tests … FAILED (failures=12)"),
caused by `/var` not being a real directory in the local test environment. All 49 new tests pass.

## Public interface changes

| Change | Callers | Asked for by the bead? |
|--------|---------|----------------------|
| `convergence.agreed(root_key, sources, minimum, anchored, owner_chain=None)` | `convergence.recover`, `reanchor.plan` | Yes (plan item a) |
| `convergence.recover(store, sources, minimum=None, owner_chain=None)` | `recover.restore` | Yes (plan item a) |
| `recover.statement(purpose, node_id, tip, session, expires, collector_epoch=None, collector_sequence=None)` | `owner.sign_recovery` | Yes (plan item b) |
| `recover.verify_owner(tip, signed, purpose, node_id, session, now, single_node=False)` | `recover.owner_check`, `recount.main` | Yes (plan item b) |
| `recover.witness_sequence(export, receipt, keys, identity, stream)` | `owner.sign_recovery` (future) | Yes (plan item b) |
| `recover.apply(config_path, peers, one_source=None, typed=None, run=…, now=None, owner_chain=None, boot_id=None)` | `recover.main` | Yes (plan item b) |
| `reanchor.plan(store, sources, node_id, owner=None, owner_chain=None)` | `reanchor.reanchor`, `reanchor.main` | Yes (plan item c) |
| `reanchor.reanchor(store, sources, node_id, typed, sink, owner=None, owner_chain=None, prepare=None, before_anchor=None)` | `reanchor.main` | Yes (plan item c) |
| `recount.plan(counter, manifest, documents, prior=0, owner_statement=None, signer=None)` | `recount.recount`, `recount.main` | Yes (plan item e) |
| `recount.recount(counter, manifest, documents, typed, sink, floor_path, owner_statement=None, signer=None)` | `recount.main` | Yes (plan item e) |
| `owner.sign_recovery(…, collector_sequence=None)` | CLI (`owner.py sign-recovery`) | Yes (plan item d) |
| Statement v2 format: `collector_epoch` (recover/reanchor), `collector_epoch` + `collector_sequence` (recount) | `verify_owner`, `message`, `statement` | Yes (plan item b) |

All new parameters are keyword-only with defaults (`None`/`False`), so existing callers are unaffected.
The v2 statement format is a new prefix (`regalia-<purpose>/v2\0`); v1 statements are still accepted
under multi-node.

## Mutant controls

All 4 mutants named in the plan turn their tests red:

1. Drop `collector_epoch <= tip epoch` in `verify_owner` →
   `test_verify_owner_under_single_node_refuses_collector_above_tip` RED.
2. Drop the profile guard in `agreed` →
   `test_agreed_refuses_owner_chain_under_multi_node` +
   `test_recover_owner_chain_refused_under_multi_node` RED.
3. Drop the v2-required check in `verify_owner` →
   `test_verify_owner_under_single_node_requires_v2` RED.
4. Drop `floor.append(st["collector_sequence"])` in `recount.plan` →
   `test_owner_statement_is_a_floor_source_under_single_node` +
   `test_floor_is_max_of_all_sources` RED.
