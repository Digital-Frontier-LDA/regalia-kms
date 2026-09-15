package approval

// APPROVAL IS THE ONE PACKAGE OF THE FOUR IN THIS SWEEP THAT WAS ALREADY SATURATED, and this
// file closes the single thing that was not — a contract no OPERAND could reach.
//
// The #237 sweep of this package measured 18 sites / 25 operands / 50 operand-directions with
// three surviving directions, and all three were already recorded in
// guard_coverage_round3_test.go as impossible to make the sole refuser. I re-measured rather
// than inheriting, and the measurements agree:
//
//	`header == ""`                        neutralised alone: green. An empty header decodes to
//	                                      no bytes and the JSON decode of nothing refuses at the
//	                                      next guard, so the outcome is identical either way.
//	`err != nil` and
//	`len(signature) != SignatureSize`     neutralised TOGETHER, which is the only way to test the
//	                                      claim, since each is otherwise the other's sibling:
//	                                      green. ed25519.Verify refuses a signature that is not
//	                                      SignatureSize bytes, so the pair is a cheaper path to
//	                                      an answer the primitive already gives.
//
// So the operand ledger for this package is closed with nothing to fix. What the operand
// ledger cannot see is Verify's LAST STATEMENT, which is not a boolean decision and therefore
// not a site:
//
//	sortStrings(verified)
//	return verified
//
// Delete the sort and every guard in the package still fires, every refusal still refuses, and
// the whole dependent suite stays green — MEASURED across all ten packages that can reach this
// code. The doc comment on Verify promises "a deterministic order" and nothing checked it.

import (
	"crypto/ed25519"
	"testing"
)

// TestVerifyReturnsApproversInAnOrderTheHeaderCannotChoose pins `sortStrings(verified)`.
//
// WHY THE ORDER IS NOT COSMETIC. Without the sort, the returned order is the order the
// approvals appeared in the header — which is a client-supplied, attacker-controlled field.
// Verify's output is what a decision is recorded against, so an attacker who cannot change
// WHO approved can still change how the approval is rendered in an audit trail, and two
// audit records of the same two-of-two approval no longer compare equal. A deterministic
// order is what makes a decision reproducible from its inputs.
//
// The two headers below carry the SAME evidence in opposite orders, so the only thing that
// can differ between the results is the ordering.
func TestVerifyReturnsApproversInAnOrderTheHeaderCannotChoose(t *testing.T) {
	// Ids chosen so that the sorted order is NOT the order either header presents them in:
	// sorted is [alice, bob, carol], the first header is carol,alice,bob and the second is
	// bob,carol,alice. A rotation rather than a reversal, so a result that merely reversed
	// the input would not pass by accident.
	type signer struct {
		id      string
		private ed25519.PrivateKey
		public  ed25519.PublicKey
	}
	target := binding()
	keys := map[string]ed25519.PublicKey{}
	signers := map[string]signer{}
	for _, id := range []string{"alice", "bob", "carol"} {
		name, private, public := approver(t, "spiffe://regalia/approver/"+id)
		keys[name] = public
		signers[id] = signer{id: name, private: private, public: public}
	}
	set := NewKeySet(keys)

	approvalFor := func(short string) Approval {
		return sign(t, signers[short].id, signers[short].private, target, target)
	}
	want := []string{
		"spiffe://regalia/approver/alice",
		"spiffe://regalia/approver/bob",
		"spiffe://regalia/approver/carol",
	}

	for _, presentation := range [][]string{
		{"carol", "alice", "bob"},
		{"bob", "carol", "alice"},
	} {
		approvals := make([]Approval, 0, len(presentation))
		for _, short := range presentation {
			approvals = append(approvals, approvalFor(short))
		}
		got := set.Verify(header(t, approvals...), target)

		if len(got) != len(want) {
			t.Fatalf("presentation %v verified %v, want all three approvers — the fixture must count "+
				"everybody, or an ordering assertion is being made about the wrong list", presentation, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("presented as %v, Verify returned %v, want %v — the order follows the header, "+
					"which is a client-supplied field, so the same two-of-two approval renders "+
					"differently in the audit trail depending on how the caller happened to arrange it",
					presentation, got, want)
			}
		}
	}
}
