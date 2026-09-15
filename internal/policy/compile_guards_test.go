package policy

// FOUR COMPILE-TIME VALIDATORS WITH NO DETECTOR, all found the same way: they are guards whose
// condition spans more than one line, and every mutation sweep in this campaign enumerated only
// single-line `if ... {`, so none of them was ever reached. Defeating any operand of any of the
// four left this package green.
//
// No repo-wide census here on purpose: a count of how many such guards exist, or how many lack a
// detector, is true on the day it is measured and read as current forever after. To get the
// current answer, enumerate `if` lines whose condition is left open by a trailing && or || and
// defeat each whole guard in turn. policy.go has a fifth such guard, the binding-mismatch check
// in Evaluate; that one is covered, by TestEvaluateRejectsMismatchesBeforeState.
//
// Each row provokes exactly ONE operand of one guard and asserts a substring of the MESSAGE.
// These guards sit in sequence and several fixtures satisfy more than one of them — an empty
// ChainIDs list trips the must-be-explicit guard before the duplicate check is reached — so
// `err != nil` would let any of them rot behind a neighbour.
//
// Two rows set a SECOND field, and in both cases the second field is there to silence a sibling
// refuser so the operand under test is the only thing that can fire — it is the isolation, not
// an extra violation, and removing it would make the row pass while proving nothing. Each says
// at the row which refuser it silences.

import (
	"strings"
	"testing"
	"time"
)

// requireBaseCompiles is the known-good half every table below needs (TESTING.md §18). Without
// it each table is equally consistent with a New() that refuses everything — and three of these
// four guards emit their message from a single `return`, so "refused with the right message" and
// "refuses every input with the right message" are the same observation. It runs AFTER the rows
// in each test so a broken fixture cannot stop the rows from reporting first.
func requireBaseCompiles(t *testing.T) {
	t.Helper()
	if err := compileErr(t, func(*Policy) {}); err != nil {
		t.Fatalf("the unmodified base policy was refused (%v) — every row in this test would pass against a New() that refuses everything, and none of them would be evidence", err)
	}
}

func compileErr(t *testing.T, mutate func(*Policy)) error {
	t.Helper()
	policy := basePolicy()
	mutate(&policy)
	_, err := New([]Policy{policy}, &reportingState{ready: true}, func() time.Time {
		return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	})
	return err
}

func TestAPolicyMissingAnyRequiredFieldIsRefused(t *testing.T) {
	for _, row := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"no id", func(p *Policy) { p.ID = "" }},
		{"no object id", func(p *Policy) { p.ObjectID = "" }},
		{"no purpose", func(p *Policy) { p.Purpose = "" }},
		{"no environment", func(p *Policy) { p.Environment = "" }},
		{"no operation", func(p *Policy) { p.Operation = "" }},
		{"no algorithm", func(p *Policy) { p.Algorithm = "" }},
		{"a zero payload bound", func(p *Policy) { p.MaxPayloadBytes = 0 }},
		{"a non-positive future bound", func(p *Policy) { p.MaxFuture = 0 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := compileErr(t, row.mutate)
			if err == nil {
				t.Fatal("a policy compiled with a required field empty or unsafe — every request it admits would be authorised against a rule that names nothing")
			}
			if !strings.Contains(err.Error(), "empty or unsafe required field") {
				t.Fatalf("refused by a different rule: %v", err)
			}
		})
	}
	requireBaseCompiles(t)
}

func TestPolicyListsMustBeNonEmptyUniqueAndConsistent(t *testing.T) {
	for _, row := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"no content types", func(p *Policy) {
			// Cosmos is cleared deliberately. On a Cosmos policy the canonical-protobuf rule refuses an
			// empty list a few lines later, so this guard would only be supplying the diagnosis; on a
			// plain policy it is the sole refuser, and defeating it compiles a policy that accepts
			// EVERY content type.
			p.Cosmos = nil
			p.ContentTypes = nil
		}},
		{"a duplicated content type", func(p *Policy) {
			// Written out rather than repeating p.ContentTypes[0]: indexing panics if the shared
			// fixture ever loses its content types, and the panic would land here rather than in
			// the control that exists to catch exactly that. The value must stay the canonical
			// Cosmos type — an arbitrary duplicate would be refused by the canonical-protobuf rule
			// instead of by the duplicate operand under test.
			p.ContentTypes = []string{"application/vnd.cosmos.tx+protobuf", "application/vnd.cosmos.tx+protobuf"}
		}},
		{"a duplicated approver", func(p *Policy) {
			// Three entries collapsing to two, with a threshold the SET still satisfies. Repeating one
			// approver and raising the threshold to match the slice would ALSO trip the
			// more-approvals-than-approvers operand of this same guard, which refuses with the same
			// message — the row would pass while proving nothing about the duplicate check.
			p.Approvers = []string{"spiffe://regalia/approver/treasury", "spiffe://regalia/approver/risk", "spiffe://regalia/approver/risk"}
			p.RequiredApprovals = 2
		}},
		{"more approvals required than approvers exist", func(p *Policy) { p.RequiredApprovals = len(p.Approvers) + 1 }},
		{"a negative approval count", func(p *Policy) { p.RequiredApprovals = -1 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := compileErr(t, row.mutate)
			if err == nil {
				t.Fatal("a policy compiled with an empty, duplicated or inconsistent list — an empty content-type list accepts every payload shape, and a duplicated approver silently lowers the real approval threshold")
			}
			if !strings.Contains(err.Error(), "empty, duplicated or inconsistent") {
				t.Fatalf("refused by a different rule: %v", err)
			}
		})
	}
	requireBaseCompiles(t)
}

func TestCosmosDimensionsMustBeExplicit(t *testing.T) {
	for _, row := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"no chain ids", func(p *Policy) { p.Cosmos.ChainIDs = nil }},
		{"no account numbers", func(p *Policy) { p.Cosmos.AccountNumbers = nil }},
		{"no message types", func(p *Policy) { p.Cosmos.MessageTypes = nil }},
		{"no destinations", func(p *Policy) { p.Cosmos.Destinations = nil }},
		// The two cap rows pin the DIAGNOSIS, not the refusal, and cannot be made to pin the refusal:
		// emptying one cap map leaves the denomination-count rule or the per-denomination loop to
		// refuse a few lines later, and emptying both just moves the kill to the other operand here.
		// Measured 2026-09-07 by defeating each operand alone: "Cosmos daily and transaction
		// denominations must match" and "Cosmos denomination caps are incomplete or inconsistent"
		// respectively. What these rows hold is that an operator reading the failure is told the
		// dimension was left empty, rather than being sent to a consistency rule about a map they
		// never filled in.
		{"no per-transaction cap", func(p *Policy) { p.Cosmos.MaxPerTransaction = nil }},
		{"no per-day cap", func(p *Policy) { p.Cosmos.MaxPerDay = nil }},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := compileErr(t, row.mutate)
			if err == nil {
				t.Fatal("a Cosmos policy compiled with an empty dimension — an unset dimension is not a wildcard, and treating it as one authorises everything in it")
			}
			if !strings.Contains(err.Error(), "dimensions must be explicit") {
				t.Fatalf("refused by a different rule: %v", err)
			}
		})
	}
	requireBaseCompiles(t)
}

func TestCosmosDimensionsMustNotContainDuplicates(t *testing.T) {
	// Each fixture is NON-EMPTY with a repeat: an empty list would be caught by the
	// must-be-explicit guard immediately above this one, and the row would prove nothing.
	for _, row := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"a duplicated chain id", func(p *Policy) { p.Cosmos.ChainIDs = []string{"cosmoshub-4", "cosmoshub-4"} }},
		{"a duplicated account number", func(p *Policy) { p.Cosmos.AccountNumbers = []uint64{42, 42} }},
		{"a duplicated message type", func(p *Policy) {
			p.Cosmos.MessageTypes = []string{"/cosmos.bank.v1beta1.MsgSend", "/cosmos.bank.v1beta1.MsgSend"}
		}},
		{"a duplicated destination", func(p *Policy) {
			p.Cosmos.Destinations = []string{"cosmos1destination", "cosmos1destination"}
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := compileErr(t, row.mutate)
			if err == nil {
				t.Fatal("a Cosmos policy compiled with a duplicated dimension entry — the declared breadth and the enforced breadth would differ silently")
			}
			if !strings.Contains(err.Error(), "must not contain duplicates") {
				t.Fatalf("refused by a different rule: %v — an empty list would be caught by the explicit-dimensions guard first, which is why every fixture here is non-empty", err)
			}
		})
	}
	requireBaseCompiles(t)
}

// TestACosmosPolicyWithoutCanonicalProtobufIsRefused is the sole-detector for the second of the
// two if-init operands in the Cosmos content-type guard at policy.go:172-177. Mutation sweeping
// for this campaign never reached it because the single-line regex was anchored on `if` and the
// operand is the post-semicolon cond of an `if _, canonical := ...; !canonical {`. Without this
// test a non-canonical Cosmos policy would compile: every MsgSend then refused at the wire while
// the policy author believed the route authorised the shape, and the policy-level reason would be
// the unprovoked "binding-mismatch" returned by Evaluate.
func TestACosmosPolicyWithoutCanonicalProtobufIsRefused(t *testing.T) {
	err := compileErr(t, func(p *Policy) {
		// Silence the sibling operand (octet-stream refusal at policy.go:172) by picking a
		// content-type that is neither the forbidden generic blob nor the required canonical
		// protobuf. With this content-type only the !canonical branch can fire.
		p.ContentTypes = []string{"application/x-other"}
	})
	if err == nil {
		t.Fatal("a Cosmos policy without the canonical protobuf content-type compiled — the route author would believe the shape is authorised while every MsgSend is refused at the wire")
	}
	if !strings.Contains(err.Error(), "requires canonical protobuf") {
		t.Fatalf("refused by a different rule: %v", err)
	}
	requireBaseCompiles(t)
}

// TestACosmosPolicyWithPerDayDenominationsNotMatchingPerTransactionIsRefused is the sole-detector
// for policy.go:196. The two-map-length-mismatch check sits AFTER the per-denom cap loop and
// trips only when one map has a denom the other does not. The mutation sweep that produced the
// 36-survivor list counted it as a survivor because the existing TestCosmosDimensionsMustBeExplicit
// only exercises single-denom cases: its fixtures never add a denom to one map without also
// adding it to the other. Without this row a daily-cap list could declare uosmo while the
// per-transaction list does not, and the missing-denom operand of the cap loop (line 192)
// refuses only at request time, not at policy load — so a real wire request is the first
// observation of a mis-declared policy.
func TestACosmosPolicyWithPerDayDenominationsNotMatchingPerTransactionIsRefused(t *testing.T) {
	err := compileErr(t, func(p *Policy) {
		// Add a denom to the DAILY map only. The cap loop at policy.go:190 iterates the
		// per-transaction map, so the inner !exists and dailyCap<transactionCap operands are
		// unreachable from this fixture; the mismatch check at line 196 is the only guard
		// that can fire.
		p.Cosmos.MaxPerDay = map[string]uint64{"uatom": 5_000_000, "uosmo": 7_000_000}
	})
	if err == nil {
		t.Fatal("a Cosmos policy with per-day denominations not matching per-transaction compiled — the daily map names coins the per-transaction caps do not, and only a request-time refusal would surface the gap")
	}
	if !strings.Contains(err.Error(), "daily and transaction denominations must match") {
		t.Fatalf("refused by a different rule: %v", err)
	}
	requireBaseCompiles(t)
}

// TestACosmosPolicyWithADailyCapLessThanItsTransactionCapIsRefused is the sole-detector for the
// dailyCap<transactionCap operand of policy.go:192. The other three operands of that line share
// the same message and the same return; the existing TestCosmosDimensionsMustBeExplicit covers
// them by leaving daily==transaction, which makes this inequality the one the existing tests do
// not provoke. Without this row a policy could declare a 500_000-atom daily cap and a 1_000_000-
// atom per-transaction cap, both for the same denom, and the request-time guard would refuse
// every transaction while the policy author believes the broader number authorises it.
func TestACosmosPolicyWithADailyCapLessThanItsTransactionCapIsRefused(t *testing.T) {
	err := compileErr(t, func(p *Policy) {
		// Keep the denom in both maps so the !exists sibling is silenced. The remaining
		// operands are denom=="" (silenced because uatom is non-empty), transactionCap==0
		// (silenced because 1_000_000 is non-zero), and dailyCap<transactionCap (fires here).
		p.Cosmos.MaxPerDay = map[string]uint64{"uatom": 500_000}
	})
	if err == nil {
		t.Fatal("a Cosmos policy with a daily cap below its transaction cap compiled — the per-transaction figure would authorise sums the daily figure then refuses, so the larger number is a lie from the policy author's perspective")
	}
	if !strings.Contains(err.Error(), "denomination caps are incomplete or inconsistent") {
		t.Fatalf("refused by a different rule: %v", err)
	}
	requireBaseCompiles(t)
}

// TestNewRejectsANilClock is the sole-detector for the now==nil operand of the engine constructor
// guard at policy.go:146. The guard is `len(policies) == 0 || state == nil || now == nil`, three
// operands sharing one message and one return; no test exercises now==nil directly —
// readiness_test.go covers len(policies)==0 by passing nil policies, and state==nil is covered by
// TestNewRejectsANilState below.
//
// TWO CORRECTIONS TO WHAT THIS COMMENT USED TO SAY, both measured rather than reasoned.
//
// It claimed state==nil was "unreachable from the public path because reportingState is the only
// State implementation in this package". State is an INTERFACE and New is exported, so any caller
// outside the package can pass nil — and TestNewRejectsANilState twenty lines below does exactly
// that. The comment contradicted the test underneath it. What is true is narrower and not
// interesting: this package constructs only one implementation of its own.
//
// It also claimed a nil clock would "silently return a zero time". It does not. Measured with the
// operand neutralised and engine.now() called directly:
//
//	RESULT: PANIC -> runtime error: invalid memory address or nil pointer dereference
//
// policy.go:243 calls engine.now().UTC() on every Evaluate, so a nil clock is a crash on the first
// request, not a quiet freshness refusal. That is a worse consequence than the comment described,
// which matters: a reader deciding whether this guard earns its place was being told the failure
// mode is benign.
func TestNewRejectsANilClock(t *testing.T) {
	policy := basePolicy()
	if _, err := New([]Policy{policy}, &reportingState{ready: true}, nil); err == nil {
		t.Fatal("an engine built with a nil clock — every reservation would then read time.Now() through a nil function pointer, which is recoverable from inside the package but a panic waiting to happen for any caller passing nil")
	} else if !strings.Contains(err.Error(), "clock") {
		t.Fatalf("refused by a different rule: %v", err)
	}
	// §18 control. The assertion above is equally consistent with a New() that refuses every
	// input — including one broken by a later change — so we run a fully-valid New() in the
	// same test to distinguish "it refused this" from "it refuses". The argument mutated by the
	// assertion is the third (clock); the control exercises the first (policy) and second (state)
	// with their canonical values and supplies a non-nil clock, which is the production path
	// compileErr uses for the table-driven tests above.
	requireBaseCompiles(t)
}

// TestNewRejectsANilState is the sole-detector for the state==nil operand of the engine constructor
// guard at policy.go:146. The sibling len(policies)==0 is covered by readiness_test.go:55-66 and
// the sibling now==nil is covered by TestNewRejectsANilClock above; this row isolates the third
// operand by passing a non-empty policy list and a non-nil clock alongside a nil State.
//
// A nil State is reachable from any caller, because State is an interface and New is exported —
// this test is itself such a caller. Without the guard it would panic on first Reserve rather than
// be refused at construction, which is the difference between a startup error an operator can read
// and a crash on the first request that reaches the engine.
func TestNewRejectsANilState(t *testing.T) {
	policy := basePolicy()
	if _, err := New([]Policy{policy}, nil, func() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) }); err == nil {
		t.Fatal("an engine built with a nil state — Reserve would dereference a nil State interface on every call, which the type system cannot catch because State is an interface")
	} else if !strings.Contains(err.Error(), "state") {
		t.Fatalf("refused by a different rule: %v", err)
	}
	// §18 control — same reasoning as TestNewRejectsANilClock: the assertion above is consistent
	// with a New() that refuses every input, so we run a fully-valid New() in the same test to
	// prove the assertion is targeted. The argument mutated by the assertion is the second
	// (state); the control exercises the first and third with their canonical values.
	requireBaseCompiles(t)
}
