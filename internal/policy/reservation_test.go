package policy

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openState(t *testing.T) *FileState {
	t.Helper()
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

// The replay nonce and the quota counter are both keyed by concatenating identity fields. If two
// different identities could produce the same key, the consequences run in both directions: a
// principal's nonce would read as already used by someone else (a denial of service on a request
// that was never made), and two objects would draw down one quota (a cap that is silently half
// what the manifest says).
//
// The separator is what prevents it, and these pairs are built to concatenate identically without
// one — the same property ReleaseContext needs in the envelope package, at a different layer.

func boundaryPair() (Reservation, Reservation) {
	first := Reservation{
		PolicyID: "cosmos", ObjectID: "hotwallet",
		Principal: "spiffe://regalia/workload/tx", Nonce: "nonce_000000000001", UTCDate: "2026-09-05",
		Amounts: map[string]uint64{"uatom": 10}, DailyCaps: map[string]uint64{"uatom": 100},
	}
	second := first
	// "cosmos"+"hotwallet" and "cosmosh"+"otwallet" are the same string once the separator between
	// them is gone. Checked below rather than trusted: an earlier version of this pair kept a
	// hyphen on one side only, so the concatenations differed and both mutations passed.
	second.PolicyID, second.ObjectID = "cosmosh", "otwallet"
	return first, second
}

// requireCollidingPair fails if the fixtures do not actually concatenate alike. Without this the
// separator mutations pass for the most boring reason there is: the inputs were never ambiguous.
func requireCollidingPair(t *testing.T, first, second Reservation) {
	t.Helper()
	if first.PolicyID+first.ObjectID != second.PolicyID+second.ObjectID {
		t.Fatalf("the fixtures do not collide without a separator: %q vs %q — this test proves nothing about the separator",
			first.PolicyID+first.ObjectID, second.PolicyID+second.ObjectID)
	}
	if first.PolicyID == second.PolicyID && first.ObjectID == second.ObjectID {
		t.Fatal("the fixtures are the same identity, so a refusal would be an honest replay")
	}
}

func TestTwoIdentitiesThatConcatenateAlikeAreNotOneNonce(t *testing.T) {
	state := openState(t)
	first, second := boundaryPair()
	requireCollidingPair(t, first, second)

	if err := state.Reserve(context.Background(), first); err != nil {
		t.Fatalf("first reservation failed: %v", err)
	}
	// Same nonce string, different identity. It must not read as a replay of the first.
	if err := state.Reserve(context.Background(), second); err != nil {
		t.Fatalf("a different identity using the same nonce was refused as %v: the two keys collide, so one principal's request blocks another's", err)
	}
}

func TestTwoIdentitiesThatConcatenateAlikeDoNotShareAQuota(t *testing.T) {
	state := openState(t)
	first, second := boundaryPair()
	requireCollidingPair(t, first, second)
	first.Amounts = map[string]uint64{"uatom": 100}
	first.DailyCaps = map[string]uint64{"uatom": 100}
	second.Amounts = map[string]uint64{"uatom": 100}
	second.DailyCaps = map[string]uint64{"uatom": 100}

	if err := state.Reserve(context.Background(), first); err != nil {
		t.Fatalf("first reservation failed: %v", err)
	}
	// The first spent its whole cap. If the counters collided, the second would be refused for
	// spending a budget that is not its own.
	if err := state.Reserve(context.Background(), second); err != nil {
		t.Fatalf("a second identity was refused with %v after the first spent ITS cap: the quota counters collide, so the manifest's cap is silently shared", err)
	}
}

// TestTheQuotaBoundsAreExactlyWhatTheCapSays. `current > cap-amount` is unsigned arithmetic on the
// edge, which is where an off-by-one becomes either a cap that refuses its own last unit or one
// that admits an extra.
func TestTheQuotaBoundsAreExactlyWhatTheCapSays(t *testing.T) {
	state := openState(t)
	fill := reservation("nonce_000000000001", "2026-09-05", 900, 1000)
	if err := state.Reserve(context.Background(), fill); err != nil {
		t.Fatal(err)
	}

	// The last unit of the cap must be spendable: a cap of 1000 that refuses the 1000th is a cap
	// of 999 wearing the wrong label.
	if err := state.Reserve(context.Background(), reservation("nonce_000000000002", "2026-09-05", 100, 1000)); err != nil {
		t.Fatalf("the exact remaining balance was refused: %v", err)
	}
	// And nothing beyond it.
	if err := state.Reserve(context.Background(), reservation("nonce_000000000003", "2026-09-05", 1, 1000)); !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit for one unit past a spent cap", err)
	}
}

func TestASingleReservationLargerThanTheCapIsRefused(t *testing.T) {
	state := openState(t)
	if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-05", 1001, 1000)); err == nil {
		t.Fatal("a reservation larger than its own daily cap was accepted")
	}
}

// TestAReservationMustIdentifyItself walks the identity and date rules. Each is refused before any
// journal write, so a malformed reservation cannot consume a sequence number.
func TestAReservationMustIdentifyItself(t *testing.T) {
	for name, mutate := range map[string]struct {
		apply func(*Reservation)
		wants string
	}{
		"no policy":                   {func(r *Reservation) { r.PolicyID = "" }, "identity"},
		"no object":                   {func(r *Reservation) { r.ObjectID = "" }, "identity"},
		"no principal":                {func(r *Reservation) { r.Principal = "" }, "identity"},
		"a nonce off the pattern":     {func(r *Reservation) { r.Nonce = "short" }, "identity"},
		"no nonce":                    {func(r *Reservation) { r.Nonce = "" }, "identity"},
		"a date that is not one":      {func(r *Reservation) { r.UTCDate = "yesterday" }, "date"},
		"a date with no day":          {func(r *Reservation) { r.UTCDate = "2026-09" }, "date"},
		"an unpadded date":            {func(r *Reservation) { r.UTCDate = "2026-9-5" }, "date"},
		"a day that does not exist":   {func(r *Reservation) { r.UTCDate = "2026-02-30" }, "date"},
		"a leap day in a common year": {func(r *Reservation) { r.UTCDate = "2026-02-29" }, "date"},
		"surrounding whitespace":      {func(r *Reservation) { r.UTCDate = " 2026-09-05" }, "date"},
		"an empty denomination":       {func(r *Reservation) { r.Amounts = map[string]uint64{"": 1}; r.DailyCaps = map[string]uint64{"": 10} }, "amount"},
		"a zero amount":               {func(r *Reservation) { r.Amounts = map[string]uint64{"uatom": 0} }, "amount"},
		"a denomination with no cap":  {func(r *Reservation) { r.Amounts = map[string]uint64{"unknown": 1} }, "amount"},
	} {
		t.Run(name, func(t *testing.T) {
			state := openState(t)
			request := reservation("nonce_000000000001", "2026-09-05", 10, 100)
			mutate.apply(&request)

			err := state.Reserve(context.Background(), request)
			if err == nil {
				t.Fatalf("Reserve accepted a reservation with %s", name)
			}
			if !strings.Contains(err.Error(), mutate.wants) {
				t.Fatalf("%s: error = %q, want it to mention %q — refused by a different rule leaves this one unproven", name, err, mutate.wants)
			}
		})
	}
}

// TestACancelledContextReservesNothing. Reserve is called on the request path, so a client that
// hangs up must not leave a nonce spent — the retry would then be refused as a replay of a request
// that never completed.
func TestACancelledContextReservesNothing(t *testing.T) {
	state := openState(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	request := reservation("nonce_000000000001", "2026-09-05", 10, 100)

	if err := state.Reserve(cancelled, request); err == nil {
		t.Fatal("Reserve accepted a cancelled context")
	}
	if err := state.Reserve(context.Background(), request); err != nil {
		t.Fatalf("the same reservation was refused afterwards with %v: the cancelled attempt spent the nonce, so an honest retry now reads as a replay", err)
	}
}

// TestAClosedStateRefusesEverything. Shutdown must not leave a window where reservations are
// accepted into memory and never journalled.
func TestAClosedStateRefusesEverything(t *testing.T) {
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-05", 10, 100)); err == nil {
		t.Fatal("a closed policy state accepted a reservation")
	}
	if state.Ready(context.Background()) {
		t.Fatal("a closed policy state reports itself ready, so readiness would not drop on shutdown")
	}
}

// TestAJournalWriteFailureLatchesTheStateClosed.
//
// The in-memory totals are only as good as the journal behind them. If an append fails and the
// state kept serving, quota and replay would be enforced from memory alone until the next restart
// — at which point the journal would be missing everything since the failure, and the caps would
// silently reset. Failing closed is the only safe direction, and it must LATCH: the next call must
// fail too, not retry into the same broken file.
func TestAJournalWriteFailureLatchesTheStateClosed(t *testing.T) {
	state := openState(t)
	if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-05", 10, 100)); err != nil {
		t.Fatal(err)
	}
	// The handle is closed underneath, which is what a write failure looks like from here.
	if err := state.file.Close(); err != nil {
		t.Fatal(err)
	}

	if err := state.Reserve(context.Background(), reservation("nonce_000000000002", "2026-09-05", 10, 100)); err == nil {
		t.Fatal("a reservation was accepted after the journal became unwritable")
	}
	if !state.failed {
		t.Fatal("the state did not latch failed, so the next reservation would retry into the same broken journal")
	}
	if err := state.Reserve(context.Background(), reservation("nonce_000000000003", "2026-09-05", 10, 100)); err == nil {
		t.Fatal("a second reservation was accepted after the failure: the state is enforcing quota from memory with nothing durable behind it")
	}
	if state.Ready(context.Background()) {
		t.Fatal("a failed policy state reports itself ready, so readiness would not drop")
	}
}

// TestTheDateRoundTripCheckIsUnreachableAndWhyItStays.
//
// validateReservation refuses a date whose Format does not reproduce the input. That branch cannot
// be reached: time.Parse with the layout "2006-01-02" is strict about width and range, so every
// non-canonical spelling fails at the Parse instead — unpadded months and days, out-of-range days,
// a leap day in a common year, surrounding whitespace. Measured, not assumed; the list below is the
// evidence, and the round-trip check is defence in depth against the layout being loosened.
//
// Pinned because the alternative is a reader concluding the round-trip is what catches these and
// removing the Parse error check as redundant. It is the third guard of this shape found today —
// envelope.Peek's missing-version branch and RouteForUnwrap's empty version are the others — so the
// pattern is worth naming: a check whose precondition is already enforced upstream is not wrong,
// but the test has to say where the work is actually done.
func TestTheDateRoundTripCheckIsUnreachableAndWhyItStays(t *testing.T) {
	for _, value := range []string{
		"2026-9-5", "2026-1-01", "2026-01-1", "2026-02-30", "2026-02-29",
		"2026-13-01", "2026-00-01", "2026-01-00", " 2026-01-02", "2026-01-02 ",
	} {
		parsed, err := time.Parse(utcDateLayout, value)
		if err != nil {
			continue
		}
		if parsed.Format(utcDateLayout) != value {
			t.Fatalf("%q parses and round-trips differently, so the round-trip check IS reachable — the comment calling it unreachable is now wrong", value)
		}
		t.Fatalf("%q parses at all, which this list did not expect", value)
	}
}

// TestTheDateTheEngineProducesIsOneTheValidatorAccepts.
//
// Two places speak about the quota bucket's date: Engine.Evaluate formats it, and
// validateReservation parses it back. They were separate literals, so nothing stopped one changing
// without the other — and the failure that produces is total rather than partial. Every reservation
// would be refused as an invalid date, so every quota-bearing operation would stop, with a message
// blaming the caller's date rather than the two halves disagreeing.
//
// THE DATE MUST COME FROM THE ENGINE, not from formatting the clock in the test. Written the second
// way first, this passed with the producer's layout reverted to its own literal: formatting with
// utcDateLayout and then validating with utcDateLayout tests the constant against itself and can
// never see the two ends diverge.
func TestTheDateTheEngineProducesIsOneTheValidatorAccepts(t *testing.T) {
	// Instants where a lax layout and a strict one disagree: single-digit month, single-digit day,
	// both, and neither.
	for _, moment := range []time.Time{
		time.Date(2026, 9, 5, 13, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 5, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 9, 25, 23, 59, 59, 0, time.UTC),
		time.Date(2026, 12, 25, 12, 0, 0, 0, time.UTC),
	} {
		t.Run(moment.Format(time.RFC3339), func(t *testing.T) {
			captured := &reservationState{}
			engine, err := New([]Policy{basePolicy()}, captured, func() time.Time { return moment })
			if err != nil {
				t.Fatal(err)
			}

			decision := engine.Evaluate(context.Background(), baseRequest(moment))
			if !decision.Allowed {
				t.Fatalf("the fixture request was not allowed (%s), so no reservation was produced to check", decision.Code)
			}
			if len(captured.reservations) != 1 {
				t.Fatalf("the engine made %d reservations, want exactly 1", len(captured.reservations))
			}

			produced := captured.reservations[0]
			if err := validateReservation(produced); err != nil {
				t.Fatalf("the engine produced UTCDate %q and the validator refuses it (%v): the producer and the "+
					"validator disagree, so every quota-bearing operation would stop with an error blaming the date",
					produced.UTCDate, err)
			}
		})
	}
}
