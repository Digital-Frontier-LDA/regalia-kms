package policy

import (
	"context"
	"testing"
	"time"
)

// THE COSMOS-ACCOUNT PROFILE (#432, d9's hole 3): the SignDoc must carry exactly the chain, account number and
// sequence the chain said just before signing, every message's signer is the fetched account, and no sequence
// high-water is reserved (the chain arbitrates).
func TestACosmosAccountKeySignsOnlyWhatTheChainSays(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := &reservationState{}
	engine, err := New([]Policy{basePolicy()}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	facts := func() *CosmosChainFacts {
		return &CosmosChainFacts{ChainID: "cosmoshub-4", Address: "cosmos1source", AccountNumber: 42, Sequence: 7}
	}
	request := func(n int) Request {
		r := baseRequest(now)
		r.Nonce = "nonce_0123456789abcd" + string(rune('a'+n/10)) + string(rune('a'+n%10))
		r.SigningProfile, r.CosmosChain = ProfileCosmosAccount, facts()
		return r
	}
	allowed := request(0)
	if d := engine.Evaluate(context.Background(), allowed); !d.Allowed {
		t.Fatalf("what the chain says was refused: %#v", d)
	}
	if got := state.reservations[0]; got.Sequence != nil || got.SequenceKey != "" {
		t.Fatalf("a cosmos-account key reserved a sequence high-water: %+v", got)
	}
	// the same sequence again is the chain's to arbitrate, not this KMS's: allowed (another nonce)
	if d := engine.Evaluate(context.Background(), request(1)); !d.Allowed {
		t.Fatalf("a repeated sequence was refused by the KMS: %#v", d)
	}
	for i, c := range []struct {
		change func(*Request)
		rule   string
	}{
		{func(r *Request) { r.CosmosChain = nil }, "cosmos-chain-unknown"},
		{func(r *Request) { r.CosmosChain.ChainID = "cosmoshub-5" }, "cosmos-chain-id-mismatch"},
		{func(r *Request) { r.CosmosChain.AccountNumber = 43 }, "cosmos-account-number-mismatch"},
		{func(r *Request) { r.CosmosChain.Sequence = 8 }, "cosmos-sequence-mismatch"},
		{func(r *Request) { r.CosmosChain.Sequence = 6 }, "cosmos-sequence-mismatch"},
		{func(r *Request) { r.CosmosChain.Address = "cosmos1other" }, "cosmos-signer-mismatch"},
		{func(r *Request) { r.SigningProfile = "cosmos-validator" }, "cosmos-profile-unknown"},
	} {
		r := request(10 + i)
		c.change(&r)
		if d := engine.Evaluate(context.Background(), r); d.Allowed || d.Rule != c.rule || d.Code != CodeDenied {
			t.Errorf("%s: %#v", c.rule, d)
		}
	}
	// without a profile (no fetch), the KMS's own sequence journal still decides, as before
	legacy := baseRequest(now)
	legacy.Nonce = "nonce_0123456789abcdzz"
	if d := engine.Evaluate(context.Background(), legacy); !d.Allowed {
		t.Fatal(d)
	}
	if last := state.reservations[len(state.reservations)-1]; last.Sequence == nil || *last.Sequence != 7 {
		t.Fatalf("a key with no profile lost its sequence reservation: %+v", last)
	}
}
