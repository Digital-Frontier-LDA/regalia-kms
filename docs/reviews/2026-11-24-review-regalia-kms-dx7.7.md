# Review: regalia-kms-dx7.7 (PR #778), run defcc750

Reviewed head `c2483f75` (bead/regalia-kms-dx7.7; merge-base with origin/main `f86b76a6`, up to date) against
the bead's AC1–AC4. This run replaces the verdict of review run 80ad5a94 ("no findings, NEXT: dod"), which the
check run b4a5ac8d failed. It fixes what that check named: the two missed findings are checked and
reproduced here, red controls are added for the tests that had none, and the interface list now covers the CLI and
data formats. All test runs are on heavy (`heavy run --host heavy-pool-h4i-2`), runs
20261124T115421-Jonathans-MacBook-Pro-51732 (mutants M-A..M-F, probes 1 and 2) and
20261124T115448-Jonathans-MacBook-Pro-57640 (probe 3). The output is in the bead notes.

## Verdict

**3 findings need fixes (2 important, 1 medium) and there are 2 nits. NEXT: feedback.**

## Findings (most severe first)

### 1. IMPORTANT: AC2 regression. A source named `__owner__` skips the may-authorize check under any tip
- `deploy/baremetal/convergence.py:177`: `if source == "__owner__": continue` keys the owner exemption on the
  dict KEY, not on `owner_chain` having been given. When `owner_chain is None`, `all_sources = dict(sources)`
  (:146), so a caller's own `"__owner__"` key is exempt from `membership.may(..., "authorize")`, under a
  multi-node tip too. The plan said the owner chain is a separate argument "so a node can never be named owner";
  this re-opens that.
- It is reachable from a command: `reanchor.py:492` takes `--peer NODE=CHAIN.json` with only
  `require(sep and node_id and path)`, no node-ID pattern. So `reanchor --peer __owner__=X.json --peer b=Y.json`
  gives plan() 2 "node" sources, one of them unauthorized (any root-verified chain, for example a copy of b's).
  `recover.py` main is not affected: its --peer name must match `[a-z0-9][a-z0-9-]{0,31}`.
- Shown on heavy (PROBE 1): with the multi-node fixture `agreed(ROOT, {name: b_chain, "b": b_chain}, 2, 1)`,
  `z` -> REFUSED "'z' is not a source this chain trusts", `__owner__` -> ACCEPTED as 2 sources, profile multi-node.
  At origin/main the loop has no exemption.
- The test misses it: `test_a_node_named_owner_gains_nothing` tries only "owner" and "z". Mutant M-D (exempt
  "owner" as well) turns it red, so the test guards the name it tries and not the name the code actually exempts.
- Fix: exempt the owner chain by identity, never by a name in the sources namespace (keep it out of `all_sources`,
  or refuse any sources key that is not a node ID in `agreed()` and in reanchor main). Add a test that
  `{"__owner__": chain, "b": chain}` under multi-node is refused, with a mutant control.

### 2. IMPORTANT: AC3 is unusable end to end. Nothing produces the recount statement that `recount --owner-statement` needs
- `deploy/baremetal/owner.py:412`: `sign-recovery --purpose` has `choices=("recover", "reanchor")`, although
  `recover.py:50` PURPOSES now includes "recount". PROBE 2 on heavy: `owner sign-recovery --purpose recount` exits 2,
  "invalid choice: 'recount' (choose from recover, reanchor)".
- `owner.py:603-605`: main never passes `collector_sequence`, so even with the choice added, a single-node recount
  is always refused at `owner.py:177-180`.
- `recover.witness_sequence` (`recover.py:189`) has no caller and no test. Mutant M-F (it returns 0) leaves the
  recover, owner and recount suites green: "Ran 77 tests ... OK".
- `sign_recovery` takes `collector_sequence` as a bare integer and never derives it from, or checks it against, the
  `--witness` exports, so the value is not witnessed. Plan item d said "signing the witnessed heartbeat sequence".
- `MEMBERSHIP-RECOVERY.md:274` documents `recount --owner-statement` but names no command that makes the statement.
- Fix: add "recount" to the --purpose choices. Under single-node, compute
  `collector_sequence = max(witness_sequence(*w) for w in witnesses)` inside sign_recovery from the same witnesses,
  never as a free argument. Test witness_sequence (positive, receipt mismatch, no beat-propose) and the
  sign-recovery recount command end to end, add a mutant that drops the derivation, and document the owner
  command in the Single node section.

### 3. MEDIUM: `recover apply --owner-chain` under a multi-node tip with a v1 statement crashes with KeyError, and the refusal is not recorded
- `recover.py:363` runs owner_check with `single_node=False` under a multi-node tip, which accepts a v1 statement
  (the kind `sign-recovery` writes for multi-node). Then `recover.py:370-372` builds the phrase from
  `one_source["statement"]["collector_epoch"]`, which raises KeyError. KeyError is outside `except Refused`
  (`:377`), so the refusal is never handed to regalia-sync for the trail. recover's contract is that every
  decision is a line in the sync trail. main prints `REFUSED: 'collector_epoch'`.
- PROBE 3 on heavy, a SingleNodeCommand fixture with a multi-node owner chain and a v1 statement: "raised KeyError:
  'collector_epoch'", trail outcomes `[]`.
- `test_apply_owner_chain_refused_under_multi_node_tip` passes a v2 statement with owner_check patched, so it never
  reaches this path. The plan said to refuse --owner-chain under multi-node up front.
- Fix: in apply(), `require(is_single, ...)` right after verify_chain of the owner chain (a Refused, recorded),
  then test with a v1 statement and assert a recorded DENY.

### Nits
- `owner.py:609` still prints "give it to the node (recover apply --one-source --owner-statement)" under
  single-node, where the command is `recover apply --owner-chain --owner-statement` (or reanchor/recount).
- The previous report claimed "all new parameters are keyword-only". They are positional-or-keyword with defaults,
  for example `convergence.py:130`. Existing callers are not affected.

## Acceptance criteria (one line each)
- **AC1** (single-node re-anchor and crash-window recover from the owner chain; refused when the collector is higher):
  PASS. convergence.agreed/recover take owner_chain under a SINGLE_NODE tip (min 1), reanchor.plan --owner-chain,
  recover apply --owner-chain. The node refuses `collector_epoch > tip` (recover.py verify_owner), and the owner's
  tool refuses `seen > tip` and, under single-node, no witness (owner.py:173).
- **AC2** (multi-node unchanged): **FAIL**. Findings 1 (the `__owner__` quorum bypass, a regression from origin/main)
  and 3 (unrecorded KeyError instead of a recorded refusal).
- **AC3** (recount floor from owner statement/collector under single-node): **PARTIAL**. recount.plan/main take the
  statement as a floor source (plus the signing-counter liveness floor), but no tool can produce the statement and
  its sequence is not witnessed (finding 2).
- **AC4** (MEMBERSHIP-RECOVERY.md single-node section): PASS. `MEMBERSHIP-RECOVERY.md:259` "## Single node", absent at
  the base. It needs the owner recount command once finding 2 is fixed.

## Red controls (each relied-on test shown to FAIL without the fix)
Baseline on heavy: the 7 new test classes (OwnerChain, OwnerChainReanchor, SingleNodeRecovery, SingleNodeRecount,
recount CommandLine, SingleNodeCommand, SingleNodeStatement) give "Ran 49 tests ... OK".
- M-A reanchor.plan passes `owner_chain=None` to agreed -> OwnerChainReanchor red (failures=2, errors=2).
- M-B convergence.recover drops the owner-chain minimum of 1 -> `test_recover_owner_chain_crash_window_minimum_one` red.
- M-C sign_recovery no longer requires a witness under single-node -> `test_single_node_requires_witness` red.
- M-D the may-authorize exemption also covers "owner" -> `test_a_node_named_owner_gains_nothing` red (it does not
  cover "__owner__": finding 1).
- M-E recount drops the signing-counter liveness floor -> `test_liveness_floor_must_not_go_below_signing_counter` red.
- M-F witness_sequence returns 0 -> **green** (77 tests OK). Nothing tests it (finding 2).
- Earlier controls, still valid: collector-above-tip, profile guard and v2-required (runs 80ad5a94, a6ed1bf7,
  5a012adf); recount floor-source; the recover main --owner-statement gate and the recount node=None fix (5a012adf).

## Public interface changes (who calls each, and whether the bead asked for it)
| Change | Callers | Asked? |
|---|---|---|
| `convergence.agreed(..., owner_chain=None)`, `convergence.recover(..., owner_chain=None)` | reanchor.plan; recover.restore | yes (a). The `"__owner__"` key is a new reserved name in the sources mapping, which is **finding 1** |
| `recover.PURPOSES` gains "recount"; `PREFIX` split into `PREFIX_V1`/`PREFIX_V2`; `STATEMENT_KEYS` renamed `STATEMENT_KEYS_V1` (+V2, V2_RECOUNT) | message/statement/verify_owner; owner.sign_recovery | yes (b). The rename removes `recover.PREFIX`/`STATEMENT_KEYS` (`grep` finds no other caller in the repo). "recount" has no producer, which is **finding 2** |
| Statement v2 format: prefix `regalia-<purpose>/v2\0`, `collector_epoch` (+`collector_sequence` for recount); the node requires v2 under single-node | owner.sign_recovery (writer); verify_owner via owner_check and recount.main (readers) | yes (b, d) |
| `recover.statement(..., collector_epoch=None, collector_sequence=None)`, `verify_owner(..., single_node=False)`, `witness_sequence(...)` (new) | owner.sign_recovery; owner_check, recount.main; **none** | yes (b). witness_sequence has no caller: **finding 2** |
| `recover.apply(..., owner_chain=None, boot_id=None)`; `owner_check`'s returned check takes `single_node`; the hand-over JSON gains `owner_chain`; the `recover` trail event's `sources` is `["owner-chain"]` on that path | recover.main; recover.handed (regalia-sync _restore) | yes (b) |
| `reanchor.plan/reanchor(..., owner_chain=None)`; `_owner_check(..., boot_id=None)`; planned/trail `sources` gets "owner-chain" | reanchor.main | yes (c) |
| `recount.plan/recount(..., owner_statement=None, signer=None)`; the recount trail event gains `owner_sequence` | recount.main | yes (e). `owner_sequence` is a new trail field that no reader uses yet |
| `owner.sign_recovery(..., collector_sequence=None)`; under a single-node tip it refuses with no --witness (the "no collector" escape is gone), changes the typed line (no " no collector") and writes v2 | owner.py main (sign-recovery) | yes (d). main never passes collector_sequence: **finding 2** |
| CLI: `recover apply --owner-chain` (and --owner-statement without --one-source), `reanchor --owner-chain`, `recount --owner-statement` | operators; MEMBERSHIP-RECOVERY.md | yes (b, c, e) |
| recount main under a single-node manifest now always reads the beat signing counter (`nv_signing`, recount.py:305), with or without --owner-statement | operators | yes (plan: liveness floor). A single-node recount now needs that counter to read |

## Sentinel advisories
Both answers in run 80ad5a94 hold. The two phrase branches in recover.py are disjoint. In convergence.py the
profile is read after verification and the CONFLICT check and before the may-authorize loop. That order is right,
but the may-authorize loop's name-based skip is finding 1.
