# Policy spend journal: anchored to the audit collector (DRAFT, for owner review before any push)

Status: draft design note for epic #40 gap `.1.2` (threat model T09). Implemented on a local branch only.
The council approved option (C) of the proposal recorded on that bead. Option (A), a TPM NV counter, is
follow-up `.1.6`.

## The gap

The policy spend journal (`internal/policy/state.go`) records every nonce and quota reservation. Three local
checks hold it today:

- its hash chain from genesis catches an edit;
- the `.high-water` mark catches truncation and an equal-length rewrite;
- the fencing epoch catches a stale leader (#428).

All three live on the disk the journal lives on. A journal and its mark restored together from one earlier
backup agree with each other, so they pass every one of them, and every nonce and quota unit spent since that
backup becomes spendable again.

## The anchor

The audit trail already has an off-host memory that the host cannot rewrite: the collector commits each
event's hash before it acknowledges it, and `audit.ReconcileContinuity` refuses a journal that disagrees with
the collector's committed head at startup.

1. Every allowed operation writes an `authorized` audit record with `requireRemote = true`, after policy has
   reserved and before the card is touched. That record now also carries the policy journal's head:
   `policy_sequence` and `policy_hash`, read from `FileState.Head()`, which advances only after the append is
   synced.
2. At startup, after `ReconcileContinuity`, `operations.ReconcilePolicyState` reads the policy position from
   the last event the collector committed that carries one (`audit.AcknowledgedPolicyPosition`). It then
   requires the journal to reach that reservation with the same hash (`FileState.RequireAcknowledged`).

A journal restored to before an operation the collector acknowledged is therefore refused, and so is one
replaced by a different journal of the same length.

## States at startup, each its own error, each failing closed

| State | Error | Daemon |
|---|---|---|
| Journal reaches the acknowledged reservation with the same hash | none | serves |
| Journal ends before the acknowledged reservation (restored together with its mark, or wiped) | `policy.ErrBehindCollector` | refuses to start |
| Journal holds the acknowledged reservation with another hash (replaced or rewritten) | `policy.ErrDivergedFromCollector` | refuses to start |
| Collector does not answer, or answers in a shape it never emits | `audit.ErrCollectorUnreachable` | refuses to start |
| Collector holds no position (fresh stream, or only events from before these fields) | none | serves |

`audit.ReconcileContinuity` now returns `audit.ErrCollectorUnreachable` for the same condition, and it runs
first, so an operator sees one name for it whichever check reaches it.

## Availability trade-off: a collector outage becomes a KMS outage at startup

**This is the cost the owner is asked to accept.** A daemon that cannot reach its collector at startup does not
start. That is already true of `ReconcileContinuity` on a host configured with a sink, so this change adds a
second reason, not a new class of outage. The policy check runs only at startup; a running daemon is not
stopped by it.

While running, every allowed operation already waits for the collector to acknowledge its authorized record,
so a collector outage already stops allowed operations; this change does not alter that. The trade-off is
deliberate: a host that could start whenever the collector is down could be rolled back by first taking the
collector down.

## Operator recovery

- **Collector unreachable at open (`audit.ErrCollectorUnreachable`).** Restore reachability: the network path,
  the collector process, the mTLS client certificate and its validity window, and the site header. Then
  restart the daemon. There is deliberately no flag that skips the check: such a flag would be the rollback's
  bypass.
- **Journal behind or diverged (`ErrBehindCollector`, `ErrDivergedFromCollector`).** This is an incident, not
  an outage: the policy journal on this host is older than, or different from, what the site already
  acknowledged. Find the newer journal (the copy that was replaced) and put it back with its mark, then
  restart. Do not delete the journal to get a fresh start: a wiped journal is refused the same way.
- **Collector permanently lost.** There is no procedure yet, and none exists today for the audit journal
  either: `ReconcileContinuity` already refuses a stream the collector no longer holds. This is open for the
  council (see the `.1.2` bead).

## Residuals

- **A journal-only host** (no sink configured) has no off-host memory, and both checks accept it, as before.
- **Reservations whose authorized record was never acknowledged** (the sink failed after the reservation) can
  be restored away. Those operations were never served, because the authorized record fails closed before the
  card, so no output was released twice. Their nonces become reusable.
- **A host attacker who also controls the collector**, or who can restore the collector's state with the
  journal, defeats this anchor. Option (A), a TPM NV counter (`.1.6`), is the defence-in-depth for that case.

## Compatibility

- **Hashed bytes.** `policy_sequence` and `policy_hash` are `omitempty`, so an event without them marshals to
  the bytes it always did, and existing journals keep verifying (`TestAnEventWithoutAPolicyPositionKeepsItsBytes`).
- **Upgrade order: collector first.** The collector decodes events with `DisallowUnknownFields`, so a collector
  older than this change refuses an authorized record that carries the new fields.
- **No new device writes.** This adds no TPM writes and no new state file.

## Tests

`internal/operations/policy_anchor_test.go` drives the real coordinator, a real `policy.FileState`, a real
`audit.Recorder` and a collector double that commits what it acknowledges. It has rows for:

- an intact reopen (the control: served);
- a journal and mark restored together (`ErrBehindCollector`);
- a wiped journal with the collector ahead (`ErrBehindCollector`);
- a replaced journal (`ErrDivergedFromCollector`);
- a collector unreachable at open (`audit.ErrCollectorUnreachable`, from both checks).

It also pins that only the authorized record carries the head. `internal/audit/policy_position_test.go` pins
the field rules.
