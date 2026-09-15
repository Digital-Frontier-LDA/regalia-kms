package policy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type reservationState struct {
	err          error
	reservations []Reservation
}

func (state *reservationState) Reserve(_ context.Context, reservation Reservation) error {
	if state.err != nil {
		return state.err
	}
	state.reservations = append(state.reservations, reservation)
	return nil
}

func basePolicy() Policy {
	return Policy{
		ID: "cosmos-hot-wallet", ObjectID: "production-wallet-signer", Purpose: "cosmos-transaction",
		Environment: "production", Operation: "sign", Algorithm: "secp256k1",
		ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"}, MaxPayloadBytes: 100_000,
		MaxFuture: 5 * time.Minute, RequiredApprovals: 1, Approvers: []string{"spiffe://regalia/approver/treasury"},
		Cosmos: &CosmosPolicy{
			ChainIDs: []string{"cosmoshub-4"}, AccountNumbers: []uint64{42},
			MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"},
			Sources:      []string{"cosmos1source"}, Destinations: []string{"cosmos1destination"}, MaxPerTransaction: map[string]uint64{"uatom": 1_000_000},
			MaxGasLimit: 500_000, MaxFee: map[string]uint64{"uatom": 10_000},
			MaxPerDay: map[string]uint64{"uatom": 5_000_000},
		},
	}
}

func baseRequest(now time.Time) Request {
	return Request{
		RequestID: "018f0000-0000-7000-8000-000000000001", Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID: "production-wallet-signer", Purpose: "cosmos-transaction", Environment: "production",
		Operation: "sign", Algorithm: "secp256k1", ContentType: "application/vnd.cosmos.tx+protobuf",
		PayloadBytes: 512, ExpiresAt: now.Add(time.Minute), Nonce: "nonce_0123456789abcdef",
		VerifiedApprovers: []string{"spiffe://regalia/approver/treasury"},
		Cosmos: &CosmosTransaction{
			ChainID: "cosmoshub-4", AccountNumber: 42, Sequence: 7, GasLimit: 200_000,
			Fee:      []Coin{{Denom: "uatom", Amount: 1_000}},
			Messages: []CosmosMessage{{Type: "/cosmos.bank.v1beta1.MsgSend", Source: "cosmos1source", Destination: "cosmos1destination", Amounts: []Coin{{Denom: "uatom", Amount: 900_000}}}},
		},
	}
}

func TestEvaluateRejectsOutOfOrderCosmosSequenceBeforeHardwareReservation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	engine, err := New([]Policy{basePolicy()}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first := baseRequest(now)
	if decision := engine.Evaluate(context.Background(), first); !decision.Allowed {
		t.Fatalf("baseline Cosmos sequence was refused: %#v", decision)
	}
	second := baseRequest(now)
	second.RequestID = "018f0000-0000-7000-8000-000000000002"
	second.Nonce = "nonce_0123456789abcde2"
	second.Cosmos.Sequence = 9
	decision := engine.Evaluate(context.Background(), second)
	if decision.Allowed || decision.Rule != "sequence" || decision.Code != CodeDenied {
		t.Fatalf("DEFECT: out-of-order Cosmos sequence produced %#v; expected a sequence denial", decision)
	}
}

func TestEvaluateRejectsCosmosFeeAndGasOutsidePolicy(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*CosmosTransaction){
		"gas limit": func(tx *CosmosTransaction) { tx.GasLimit = 500_001 },
		"fee cap":   func(tx *CosmosTransaction) { tx.Fee[0].Amount = 10_001 },
	} {
		t.Run(name, func(t *testing.T) {
			engine, err := New([]Policy{basePolicy()}, &reservationState{}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			request := baseRequest(now)
			mutate(request.Cosmos)
			decision := engine.Evaluate(context.Background(), request)
			if decision.Allowed || decision.Rule != "cosmos" {
				t.Fatalf("DEFECT: %s outside policy produced %#v; expected Cosmos policy refusal", name, decision)
			}
		})
	}
}

func TestEvaluateAcceptsInclusiveCosmosGasAndFeeCaps(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	configured := basePolicy()
	configured.Cosmos.MaxGasLimit = 200_000
	configured.Cosmos.MaxFee["uatom"] = 1_000
	state := &reservationState{}
	engine, err := New([]Policy{configured}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := baseRequest(now)
	if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
		t.Fatalf("DEFECT: values exactly at the declared gas and fee caps were refused: %#v", decision)
	}
}

func TestEvaluateAllowsMsgDelegateOnlyWhenExplicitlyAllowlisted(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	configured := basePolicy()
	configured.Cosmos.MessageTypes = []string{"/cosmos.staking.v1beta1.MsgDelegate"}
	configured.Cosmos.Sources = []string{"akash1source"}
	configured.Cosmos.Destinations = []string{"akashvaloper1validator"}
	state := &reservationState{}
	engine, err := New([]Policy{configured}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := baseRequest(now)
	request.Cosmos = &CosmosTransaction{
		ChainID: "cosmoshub-4", AccountNumber: 42, Sequence: 7, GasLimit: 200_000,
		Fee:      []Coin{{Denom: "uatom", Amount: 1_000}},
		Messages: []CosmosMessage{{Type: "/cosmos.staking.v1beta1.MsgDelegate", Source: "akash1source", Destination: "akashvaloper1validator", Amounts: []Coin{{Denom: "uatom", Amount: 900_000}}}},
	}
	if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
		t.Fatalf("explicitly allowlisted MsgDelegate was refused: %#v", decision)
	}
}

func TestFileStateSequencesAreScopedToChainAndAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	reserve := func(key string, nonce string, sequence uint64) error {
		return state.Reserve(context.Background(), Reservation{
			PolicyID: "wallet", ObjectID: "wallet", Principal: "test", Nonce: nonce,
			UTCDate: "2026-09-12", Sequence: &sequence, SequenceKey: key,
		})
	}
	if err := reserve("akashnet-2\x0042", "nonce_sequence_0001", 7); err != nil {
		t.Fatal(err)
	}
	if err := reserve("akashnet-2\x0043", "nonce_sequence_0002", 7); err != nil {
		t.Fatalf("DEFECT: a distinct Cosmos account was treated as sharing account 42's sequence: %v", err)
	}
}

func TestCosmosSequenceReservationsFollowActivePassiveEpochs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cosmos-failover.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = state.Close() }()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	engine, err := New([]Policy{basePolicy()}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	epoch := uint64(1)
	engine.SetEpochSource(func() uint64 { return epoch })

	first := baseRequest(now)
	if decision := engine.Evaluate(context.Background(), first); !decision.Allowed {
		t.Fatalf("active site refused the initial Cosmos reservation: %#v", decision)
	}

	// Promotion changes the fencing epoch and the Cosmos account sequence together. The promoted
	// site must be able to continue with sequence 8, while an old leader holding epoch 1 must not
	// spend sequence 9 after the promotion.
	epoch = 2
	promoted := baseRequest(now)
	promoted.RequestID = "018f0000-0000-7000-8000-000000000002"
	promoted.Nonce = "nonce_0123456789abcde2"
	promoted.Cosmos.Sequence = 8
	if decision := engine.Evaluate(context.Background(), promoted); !decision.Allowed {
		t.Fatalf("promoted site refused the next Cosmos sequence: %#v", decision)
	}

	epoch = 1
	stale := baseRequest(now)
	stale.RequestID = "018f0000-0000-7000-8000-000000000003"
	stale.Nonce = "nonce_0123456789abcde3"
	stale.Cosmos.Sequence = 9
	decision := engine.Evaluate(context.Background(), stale)
	if decision.Allowed || decision.Code != CodeDenied || decision.Rule != "epoch" {
		t.Fatalf("DEFECT: stale Cosmos leader decision = %#v; want an epoch denial before hardware", decision)
	}
}

func TestCosmosSequenceStateSurvivesSignerRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	sequence := uint64(7)
	reservation := Reservation{PolicyID: "wallet", ObjectID: "wallet", Principal: "spiffe://regalia/test", Nonce: "nonce_restart_0001", UTCDate: "2026-09-12", Sequence: &sequence, SequenceKey: "akashnet-2\x0042"}
	if err := state.Reserve(context.Background(), reservation); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	sequence = 8
	reservation.Nonce = "nonce_restart_0002"
	if err := reopened.Reserve(context.Background(), reservation); err != nil {
		t.Fatalf("next sequence was not accepted after restart: %v", err)
	}
	sequence = 7
	reservation.Nonce = "nonce_restart_0003"
	if err := reopened.Reserve(context.Background(), reservation); !errors.Is(err, ErrSequence) {
		t.Fatalf("DEFECT: failover/restart accepted a reused Cosmos sequence: %v", err)
	}
}

func TestEvaluateAllowsExactPolicyAndReservesReplayAndQuota(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := &reservationState{}
	engine, err := New([]Policy{basePolicy()}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(context.Background(), baseRequest(now))
	if !decision.Allowed || decision.Code != CodeAllowed || decision.PolicyID != "cosmos-hot-wallet" {
		t.Fatalf("decision = %#v", decision)
	}
	if len(state.reservations) != 1 || state.reservations[0].Amounts["uatom"] != 900_000 {
		t.Fatalf("reservations = %#v", state.reservations)
	}
}

func TestEvaluateRejectsMismatchesBeforeState(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	tests := map[string]func(*Request){
		"unknown object":    func(r *Request) { r.ObjectID = "unknown-key" },
		"wrong purpose":     func(r *Request) { r.Purpose = "release-artifact" },
		"wrong environment": func(r *Request) { r.Environment = "staging" },
		"wrong operation":   func(r *Request) { r.Operation = "unwrap" },
		"wrong algorithm":   func(r *Request) { r.Algorithm = "ed25519" },
		"unknown content":   func(r *Request) { r.ContentType = "application/octet-stream" },
		"oversized":         func(r *Request) { r.PayloadBytes = 100_001 },
		"expired":           func(r *Request) { r.ExpiresAt = now.Add(-time.Nanosecond) },
		"too far future":    func(r *Request) { r.ExpiresAt = now.Add(6 * time.Minute) },
		"missing approval":  func(r *Request) { r.VerifiedApprovers = nil },
		"unapproved source": func(r *Request) { r.Cosmos.Messages[0].Source = "cosmos1attacker" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			state := &reservationState{}
			engine, err := New([]Policy{basePolicy()}, state, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			request := baseRequest(now)
			mutate(&request)
			decision := engine.Evaluate(context.Background(), request)
			if decision.Allowed || len(state.reservations) != 0 {
				t.Fatalf("decision/state = %#v/%#v", decision, state.reservations)
			}
		})
	}
}

func TestCosmosPolicyRejectsEveryControlledDimension(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	tests := map[string]func(*CosmosTransaction){
		"chain":             func(tx *CosmosTransaction) { tx.ChainID = "evil-1" },
		"account":           func(tx *CosmosTransaction) { tx.AccountNumber = 43 },
		"message":           func(tx *CosmosTransaction) { tx.Messages[0].Type = "/cosmos.staking.v1beta1.MsgDelegate" },
		"destination":       func(tx *CosmosTransaction) { tx.Messages[0].Destination = "cosmos1attacker" },
		"denomination":      func(tx *CosmosTransaction) { tx.Messages[0].Amounts[0].Denom = "uunknown" },
		"transaction limit": func(tx *CosmosTransaction) { tx.Messages[0].Amounts[0].Amount = 1_000_001 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			state := &reservationState{}
			engine, _ := New([]Policy{basePolicy()}, state, func() time.Time { return now })
			request := baseRequest(now)
			mutate(request.Cosmos)
			decision := engine.Evaluate(context.Background(), request)
			if decision.Allowed || decision.Code != CodeDenied || len(state.reservations) != 0 {
				t.Fatalf("decision/state = %#v/%#v", decision, state.reservations)
			}
		})
	}
}

func TestReplayQuotaStateFailureFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := &reservationState{err: errors.New("state unavailable")}
	engine, _ := New([]Policy{basePolicy()}, state, func() time.Time { return now })
	decision := engine.Evaluate(context.Background(), baseRequest(now))
	if decision.Allowed || decision.Code != CodeStateUnavailable {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestNewRejectsDuplicateAndUnsafePolicy(t *testing.T) {
	policy := basePolicy()
	if _, err := New([]Policy{policy, policy}, &reservationState{}, time.Now); err == nil {
		t.Fatal("duplicate policy accepted")
	}
	policy.ContentTypes = append(policy.ContentTypes, "application/octet-stream")
	if _, err := New([]Policy{policy}, &reservationState{}, time.Now); err == nil {
		t.Fatal("generic content type accepted for Cosmos policy")
	}
}

func TestOneObjectCanHaveDistinctWrapAndUnwrapPolicies(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	wrap := Policy{ID: "sops-wrap", ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Operation: "wrap", Algorithm: "rsa2048", ContentTypes: []string{"application/vnd.regalia.data-key"}, MaxPayloadBytes: 4096, MaxFuture: time.Minute}
	unwrap := wrap
	unwrap.ID, unwrap.Operation = "sops-unwrap", "unwrap"
	engine, err := New([]Policy{wrap, unwrap}, &reservationState{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for index, operation := range []string{"wrap", "unwrap"} {
		request := Request{RequestID: "018f0000-0000-7000-8000-000000000001", Principal: "spiffe://regalia/workload/sops", ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Operation: operation, Algorithm: "rsa2048", ContentType: "application/vnd.regalia.data-key", PayloadBytes: 32, ExpiresAt: now.Add(time.Minute), Nonce: "nonce_0123456789abcde" + string(rune('a'+index))}
		if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
			t.Fatalf("%s decision = %#v", operation, decision)
		}
	}
}
