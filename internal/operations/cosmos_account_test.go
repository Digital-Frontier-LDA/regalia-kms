package operations

import (
	"context"

	"encoding/hex"
	"errors"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/cosmosrpc"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type fakeChain struct {
	mu      sync.Mutex
	account cosmosrpc.Account
	err     error
	asked   []string
	gate    chan struct{} // when set, Account waits on it: a request held inside the chain's answer
	inside  chan struct{}
}

func (c *fakeChain) Account(_ context.Context, chainID, address string) (cosmosrpc.Account, error) {
	c.mu.Lock()
	c.asked = append(c.asked, chainID+"/"+address)
	gate, inside := c.gate, c.inside
	c.mu.Unlock()
	if inside != nil {
		inside <- struct{}{}
	}
	if gate != nil {
		<-gate
	}
	return c.account, c.err
}

type cosmosAccountFixture struct {
	says    cosmosrpc.Account
	chainID string
	source  string
	build   func(chain *fakeChain, configured bool) (*Coordinator, *fakeAudit, *fakeHardware)
	request func() api.Request
}

func newCosmosAccountFixture(t *testing.T) cosmosAccountFixture {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "signdoc-akashnet2-msgsend.hex"))
	if err != nil {
		t.Fatal(err)
	}
	signDoc, _ := hex.DecodeString(strings.TrimSpace(string(encoded)))
	transaction, err := policy.ParseCosmosSignDoc(signDoc)
	if err != nil {
		t.Fatal(err)
	}
	message, fee := transaction.Messages[0], transaction.Fee[0]
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	f := cosmosAccountFixture{says: cosmosrpc.Account{Address: message.Source, AccountNumber: transaction.AccountNumber, Sequence: transaction.Sequence},
		chainID: transaction.ChainID, source: message.Source}
	f.build = func(chain *fakeChain, configured bool) (*Coordinator, *fakeAudit, *fakeHardware) {
		engine, err := policy.New([]policy.Policy{{
			ID: "wallet", ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
			Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"},
			MaxPayloadBytes: 10000, MaxFuture: time.Minute, Cosmos: &policy.CosmosPolicy{ChainIDs: []string{transaction.ChainID},
				AccountNumbers: []uint64{transaction.AccountNumber}, MessageTypes: []string{message.Type}, Sources: []string{message.Source},
				Destinations: []string{message.Destination}, MaxGasLimit: transaction.GasLimit, MaxFee: map[string]uint64{fee.Denom: fee.Amount},
				MaxPerTransaction: map[string]uint64{message.Amounts[0].Denom: message.Amounts[0].Amount},
				MaxPerDay:         map[string]uint64{message.Amounts[0].Denom: 10 * message.Amounts[0].Amount}},
		}}, bridgeReservationState{}, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
			Algorithm: "secp256k1", PolicyID: "wallet", Binding: registry.Binding{DeviceID: "hsm-1"}, SigningProfile: registry.ProfileCosmosAccount}}
		recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte("signature")}
		coordinator, err := New(fakeAuthorizer{allowed: true, digest: "sha256:rbac"}, router, engine, recorder, directRunner{}, hardware, "sha256:policy", nil, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		if configured {
			coordinator.SetChain(chain)
		}
		return coordinator, recorder, hardware
	}
	f.request = func() api.Request {
		request := operationRequest()
		request.Operation, request.Format, request.ContentType, request.Data = "sign", "", "application/vnd.cosmos.tx+protobuf", signDoc
		request.Context.ExpiresAt = now.Add(30 * time.Second)
		return request
	}
	return f
}

// A COSMOS-ACCOUNT KEY SIGNS ONLY WHAT THE CHAIN SAYS (#432). The coordinator asks the chain for the signer's
// account just before policy, and policy requires the SignDoc to carry exactly that; an unreachable chain or no
// chain configured is a refusal that never reaches the token.
func TestACosmosAccountKeyAsksTheChainBeforeSigning(t *testing.T) {
	f := newCosmosAccountFixture(t)
	says := f.says
	run := func(chain *fakeChain, configured bool) (*fakeAudit, *fakeHardware, error) {
		coordinator, recorder, hardware := f.build(chain, configured)
		_, err := coordinator.Execute(context.Background(), f.request())
		return recorder, hardware, err
	}
	outcome := func(recorder *fakeAudit) string { return recorder.drafts[len(recorder.drafts)-1].Outcome }

	chain := &fakeChain{account: says}
	recorder, hardware, err := run(chain, true)
	if err != nil || hardware.calls != 1 || outcome(recorder) != "success" {
		t.Fatalf("what the chain says was not signed: %v (token %d, %s)", err, hardware.calls, outcome(recorder))
	}
	if len(chain.asked) != 1 || chain.asked[0] != f.chainID+"/"+f.source {
		t.Fatalf("the chain was asked %v", chain.asked)
	}
	for _, c := range []struct {
		name       string
		chain      *fakeChain
		configured bool
		outcome    string
	}{
		{"the chain says another sequence", &fakeChain{account: cosmosrpc.Account{Address: says.Address, AccountNumber: says.AccountNumber, Sequence: says.Sequence + 1}}, true, "policy-DENIED:cosmos-sequence-mismatch"},
		{"the chain says another account number", &fakeChain{account: cosmosrpc.Account{Address: says.Address, AccountNumber: says.AccountNumber + 1, Sequence: says.Sequence}}, true, "policy-DENIED:cosmos-account-number-mismatch"},
		{"the chain does not answer", &fakeChain{err: errors.New("timeout")}, true, "cosmos-chain-unavailable"},
		{"no chain is configured", &fakeChain{}, false, "cosmos-chain-unconfigured"},
	} {
		t.Run(c.name, func(t *testing.T) {
			recorder, hardware, err := run(c.chain, c.configured)
			if err == nil || hardware.calls != 0 || outcome(recorder) != c.outcome {
				t.Fatalf("err %v, token %d, outcome %q (want %q)", err, hardware.calls, outcome(recorder), c.outcome)
			}
		})
	}
}

// One server serialises a cosmos-account key's requests from the chain's answer to the result: while one request
// is inside the chain's answer, a second for the same key does not ask the chain at all.
func TestOneKeysCosmosRequestsAreSerialisedOnAServer(t *testing.T) {
	f := newCosmosAccountFixture(t)
	chain := &fakeChain{account: f.says, gate: make(chan struct{}), inside: make(chan struct{}, 2)}
	coordinator, _, _ := f.build(chain, true)
	results := make(chan error, 2)
	go func() { _, err := coordinator.Execute(context.Background(), f.request()); results <- err }()
	<-chain.inside // the first is inside the chain's answer
	second := f.request()
	second.RequestID, second.Context.Nonce = "018f0000-0000-7000-8000-000000000002", "018f0000000070008000000000000002"
	go func() { _, err := coordinator.Execute(context.Background(), second); results <- err }()
	select {
	case <-chain.inside:
		t.Fatal("a second request for the same key asked the chain while the first was still inside its answer")
	case <-time.After(100 * time.Millisecond):
	}
	close(chain.gate) // the first finishes; the second may now ask
	<-chain.inside
	for i := 0; i < 2; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}
