package auth

// GrantedObjects' ordering was ASSERTED but only PROBABILISTICALLY detected, and the #237
// sweep of this package found it by recording the wrong verdict.
//
// rbac.go:80 `granted[i].Operation != granted[j].Operation` is the operation tiebreak in
// GrantedObjects' comparator. Deleting it leaves entries that share an ObjectID ordered by
// whatever sequence they arrived in — and they arrive from a Go map, whose iteration order is
// randomised per run. sort.Slice is not stable, so the result varies run to run.
//
// TestGrantedObjectsReportsEveryTripleOnce does assert the operation order, and it catches the
// deletion MOST of the time. Measured, 20 runs against the mutation:
//
//	detected 18/20   missed 2/20
//
// The sweep runs each mutation ONCE, so it drew a miss and recorded the operand as a survivor.
// The verdict was wrong and the assertion was real — the defect is that the assertion's
// detection is a coin weighted 9:1 rather than a decision.
//
// A test that fails only sometimes is not a detector of the thing it names. It is also the
// worst shape to debug from later: the operand reads as covered, the sweep reads as a false
// positive, and the truth is in neither ledger.
//
// This file makes the detection deterministic by sampling instead of asserting once. Each
// LoadPolicy repopulates the maps, so every iteration is an independent draw from the same
// randomisation; requiring the exact sequence on all of them turns a 0.9 detector into
// 1 - 0.1^N. The property under test is the one the comparator's comment already claims:
// "an order that changed run to run would make its output undiffable".

import (
	"strings"
	"testing"
)

// twoObjectsTwoOperations yields four triples that share a principal, so the ObjectID and
// Operation comparisons are the only ones that order them. The principal tiebreak below them
// cannot mask a missing operation tiebreak here, which is what makes the fixture isolating.
const twoObjectsTwoOperations = `{
  "schema_version": 1,
  "principals": [{
    "uri": "spiffe://regalia/workload/sops-prod",
    "grants": [{
      "objects": ["beta-object", "alpha-object"],
      "operations": ["wrap", "unwrap"],
      "environments": ["production"]
    }]
  }]
}`

// TestGrantedObjectsOrderIsTheSameOnEveryLoad covers rbac.go:80.
//
// Falsifier: `(false && (granted[i].Operation != granted[j].Operation))`. A single run detects
// that about nine times in ten; thirty runs detect it every time this test has been executed.
func TestGrantedObjectsOrderIsTheSameOnEveryLoad(t *testing.T) {
	want := []string{
		"alpha-object/unwrap",
		"alpha-object/wrap",
		"beta-object/unwrap",
		"beta-object/wrap",
	}
	// Thirty independent draws. Each LoadPolicy rebuilds the maps this list is generated from,
	// so the iteration order feeding the sort is re-randomised every time; one load asserted
	// once is a single sample of a distribution, which is what made the existing assertion a
	// 9-in-10 detector rather than a decision.
	const loads = 30
	for attempt := 0; attempt < loads; attempt++ {
		policy, err := LoadPolicy(strings.NewReader(twoObjectsTwoOperations))
		if err != nil {
			t.Fatal(err)
		}
		granted := policy.GrantedObjects()
		if len(granted) != len(want) {
			t.Fatalf("load %d: got %d entries, want %d: %+v", attempt, len(granted), len(want), granted)
		}
		for index, expected := range want {
			actual := granted[index].ObjectID + "/" + granted[index].Operation
			if actual != expected {
				t.Fatalf("load %d, position %d: got %q, want %q — GrantedObjects is ordered by "+
					"object then operation, and preflight prints this list, so an order that "+
					"varies between runs makes its output undiffable\nfull result: %+v",
					attempt, index, actual, expected, granted)
			}
		}
	}
}

// TestGrantedObjectsOrdersByPrincipalWhenObjectAndOperationMatch covers the tiebreak BELOW the
// operation comparison, and is the reason the operation tiebreak cannot simply be deleted in
// favour of it.
//
// Two principals granted the same operation on the same object differ only in principal. If
// the operation comparison is forced to decide every same-object pair — the TRUE direction of
// rbac.go:80 — this comparison never runs and equal operations return false instead of
// ordering by principal.
func TestGrantedObjectsOrdersByPrincipalWhenObjectAndOperationMatch(t *testing.T) {
	const twoPrincipals = `{
  "schema_version": 1,
  "principals": [
    {"uri": "spiffe://regalia/workload/zulu",  "grants": [{"objects": ["shared"], "operations": ["wrap"], "environments": ["production"]}]},
    {"uri": "spiffe://regalia/workload/alpha", "grants": [{"objects": ["shared"], "operations": ["wrap"], "environments": ["production"]}]}
  ]
}`
	const loads = 30
	for attempt := 0; attempt < loads; attempt++ {
		policy, err := LoadPolicy(strings.NewReader(twoPrincipals))
		if err != nil {
			t.Fatal(err)
		}
		granted := policy.GrantedObjects()
		if len(granted) != 2 {
			t.Fatalf("load %d: got %d entries, want 2: %+v", attempt, len(granted), granted)
		}
		if !strings.HasSuffix(granted[0].Principal, "/alpha") || !strings.HasSuffix(granted[1].Principal, "/zulu") {
			t.Fatalf("load %d: two grants differing only by principal came back as %q then %q, "+
				"want alpha before zulu", attempt, granted[0].Principal, granted[1].Principal)
		}
	}
}
