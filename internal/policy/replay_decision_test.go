package policy

// GUARD COVERAGE, THE CASE-CLAUSE ROUND (#237).
//
// guardenum's header used to assert that an `if` condition and a boolean `return`
// were "the only places these operands occur, and there is no sixth to discover
// later". A case clause of a tag-less switch is a seventh, and the tool did not
// enumerate it, so every round that reported this package swept measured a
// denominator that omitted those sites. Re-derived with the corrected tool: 24
// operands across 20 case sites in 7 files, none of them touched before.
//
// Swept one operand-direction each, narrowing an || leaf and widening an && leaf:
// 22 killed, 2 survivors. This file pins the reachable one.
//
// THOSE THREE FIGURES ARE THE DAY THEY WERE TAKEN, NOT THE PRESENT TENSE, and the
// paragraph above did not say so. Re-derived 2026-09-09 over every non-test .go
// file under kms/, with the same tool: 39 operands across 33 case sites in 11
// files. The tree gained four files' worth of this shape in between, so a reader
// taking 24/20/7 as current is short by more than a third. The count is left
// where it is as the record of what that change measured; what it now carries is
// the date, which is the only thing that makes a count in a comment checkable.
//
// The other is audit.go:304 -- `case statErr != nil:` in the shipped-versus-mark
// classification -- and it is unreachable by any fixture rather than untested:
// readMark refuses every non-NOT-EXIST failure while reading the mark's CONTENTS,
// one call before its EXISTENCE is classified, and the first classification's own
// default arm returns on that same class before this second switch is reached.
// Reaching it would need the stat class to change between two stats of one path.
// Per TESTING.md §17 the guarantee is pinned where it IS enforced, in
// internal/audit's TestAnUnreadableHighWaterMarkIsRefusedRatherThanReadAsGenesis
// -- which had no detecting test either, and whose absence let an unreadable mark
// be read as genesis over a journal truncated to nothing.

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// A SPENT NONCE MUST COME BACK AS A REPLAY, NOT AS "TRY AGAIN LATER".
//
// The operand `case errors.Is(err, ErrReplay):` in Evaluate is the only place a
// state-layer replay becomes a policy verdict, and it was invisible to the guard
// enumerator until #237: a case clause of a tag-less switch is a boolean branch
// with neither an `if` nor a `return` keyword, so every round that swept this
// package enumerated its targets without it. It survived neutralisation.
//
// Both layers on either side of it were already pinned. FileState.Reserve
// returning ErrReplay for a reused nonce is asserted in state_test.go and, across
// a reopen, in durability_test.go. The mapping from policy.CodeReplay to CONFLICT
// / 409 / not-retryable is asserted in operations. What nothing asserted is the
// join: that the engine turns the first into the second.
//
// Measured with the operand neutralised as (false && errors.Is(err, ErrReplay)):
// the switch falls through to its default arm, and a replayed nonce is returned
// as CodeStateUnavailable with rule "durable-state". Downstream in
// operations.coordinator that is DEPENDENCY_UNAVAILABLE, HTTP 503, and
// RETRYABLE=TRUE. So a request whose nonce is already spent is answered with an
// explicit invitation to send it again, and the audit reason recorded for it
// names a durable-state failure rather than a replay -- an attacker retrying a
// captured request is logged as infrastructure trouble on a host whose
// infrastructure is fine. The request is still refused, which is why nothing
// noticed; what is lost is the diagnosis and the retry contract.
//
// The state here is a real FileState rather than a fake returning ErrReplay,
// because the property under test is the JOIN: a fake handed the error models the
// answer instead of producing it, and would pass against an engine wired to a
// state that never detects replay at all.
func TestASpentNonceIsRefusedAsAReplayRatherThanAsUnavailableState(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	defer state.Close()
	engine, err := New([]Policy{basePolicy()}, state, func() time.Time { return now })
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	// ONE request value, evaluated twice. Building it twice from baseRequest
	// would make "the second call is a replay" depend on that helper returning
	// a constant nonce, which is true today and is not the property under test:
	// if it ever generated a fresh one, this test would report "a reused nonce
	// was ALLOWED" about a nonce that was never reused, and blame the engine for
	// the fixture. Capturing it once makes the replay hold by construction.
	request := baseRequest(now)

	// The first evaluation must be ALLOWED. Without this the second could be
	// refused for any of the reasons that precede the reservation -- purpose,
	// window, approvals -- and the test would go green on a refusal that has
	// nothing to do with replay.
	first := engine.Evaluate(context.Background(), request)
	if !first.Allowed {
		t.Fatalf("the first evaluation was refused (%#v), so the nonce was never spent and the "+
			"second evaluation below is not a replay at all", first)
	}

	// The same request again: same nonce, same principal, same object.
	replay := engine.Evaluate(context.Background(), request)
	if replay.Allowed {
		t.Fatalf("a reused nonce was ALLOWED (%#v)", replay)
	}
	if replay.Code != CodeReplay || replay.Rule != "replay" {
		t.Fatalf("a reused nonce came back as code %q rule %q, want %q / %q.\n"+
			"CodeStateUnavailable is what this becomes when the replay arm stops firing, and it "+
			"is not a synonym: operations maps it to DEPENDENCY_UNAVAILABLE, HTTP 503, "+
			"retryable=true, so the caller is told to send the spent nonce again, and the audit "+
			"reason recorded for a replay attempt names a durable-state failure on a host whose "+
			"durable state is working",
			replay.Code, replay.Rule, CodeReplay, "replay")
	}
	if replay.PolicyID != first.PolicyID {
		t.Fatalf("replay decision names policy %q, the allow named %q — a refusal an operator "+
			"cannot trace to a policy is a refusal they cannot act on",
			replay.PolicyID, first.PolicyID)
	}
}
