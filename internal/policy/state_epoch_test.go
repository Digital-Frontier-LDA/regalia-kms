package policy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE EPOCH RULES OF THE SPEND JOURNAL (#428).
//
// The quota was already durable, atomic, and single-writer; the arm it did not cover was
// leadership: an active/passive failover hands the lease to a new epoch while the journal
// holds the old leader's spends, and a stale leader that keeps signing must not keep
// spending from a budget a newer leader owns. Three rules, each with its own test:
//
//   - an epoch BELOW the journal's maximum is a replaced leader — refused;
//   - an epoch EQUAL to the maximum is the same leader continuing — allowed (the normal case);
//   - epoch 0 after any fenced reservation is the fence disappearing while the budget it
//     protected stays — refused.
//
// And one compatibility rule: epoch-0 journals are the pre-#428 format, so an unfenced
// deployment's existing journal must open, verify, and extend unchanged.

func TestTheSpendJournalRefusesAStaleLeader(t *testing.T) {
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	current := reservation("nonce_000000000001", "2026-09-13", 100, 1_000)
	current.Epoch = 5
	if err := state.Reserve(context.Background(), current); err != nil {
		t.Fatal(err)
	}

	stale := reservation("nonce_000000000002", "2026-09-13", 100, 1_000)
	stale.Epoch = 4
	if err := state.Reserve(context.Background(), stale); !errors.Is(err, ErrEpoch) {
		t.Fatalf("a reservation from the REPLACED epoch was accepted or misclassified: %v", err)
	}

	// The same leader continuing is the normal case and must keep working.
	same := reservation("nonce_000000000003", "2026-09-13", 100, 1_000)
	same.Epoch = 5
	if err := state.Reserve(context.Background(), same); err != nil {
		t.Fatalf("the CURRENT leader's next reservation was refused: %v", err)
	}

	// And a NEWER epoch is a promotion — the whole point of the rule.
	promoted := reservation("nonce_000000000004", "2026-09-13", 100, 1_000)
	promoted.Epoch = 6
	if err := state.Reserve(context.Background(), promoted); err != nil {
		t.Fatalf("the PROMOTED leader's reservation was refused: %v", err)
	}
}

func TestTheSpendJournalRefusesLosingTheFenceWithoutLosingTheJournal(t *testing.T) {
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	fenced := reservation("nonce_000000000001", "2026-09-13", 100, 1_000)
	fenced.Epoch = 5
	if err := state.Reserve(context.Background(), fenced); err != nil {
		t.Fatal(err)
	}
	// Epoch 0 is what the daemon stamps when its lease is unheld or unreadable. After a
	// fenced reservation exists, that state must refuse rather than spend unfenced: it
	// is exactly the moment the fence stopped protecting a budget it already guarded.
	unfenced := reservation("nonce_000000000002", "2026-09-13", 100, 1_000)
	if err := state.Reserve(context.Background(), unfenced); !errors.Is(err, ErrEpoch) {
		t.Fatalf("an unfenced reservation against fenced history was accepted: %v", err)
	}
}

func TestTheEpochRuleSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	current := reservation("nonce_000000000001", "2026-09-13", 100, 1_000)
	current.Epoch = 7
	if err := state.Reserve(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stale := reservation("nonce_000000000002", "2026-09-13", 100, 1_000)
	stale.Epoch = 6
	if err := reopened.Reserve(context.Background(), stale); !errors.Is(err, ErrEpoch) {
		t.Fatalf("the stale leader was accepted after a restart — the epoch high-water must be as durable as the quota: %v", err)
	}
	// The stale leader must not have consumed quota on its way to the refusal.
	ok := reservation("nonce_000000000003", "2026-09-13", 901, 1_000)
	ok.Epoch = 7
	if err := reopened.Reserve(context.Background(), ok); !errors.Is(err, ErrLimit) {
		t.Fatalf("the refused reservation changed the quota picture: %v", err)
	}
}

func TestAPreEpochJournalStillOpensVerifiesAndExtends(t *testing.T) {
	// THE OMITMPTY COMPATIBILITY CLAIM, measured rather than asserted: a journal written
	// entirely before epochs existed must open, verify, and extend — the epoch field is
	// part of the hashed bytes, so an unfenced reservation marshalling with an explicit
	// zero would break every existing journal at the next open (the RBACDigest lesson).
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	legacy := reservation("nonce_000000000001", "2026-09-13", 100, 1_000)
	if err := state.Reserve(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "epoch") {
		t.Fatalf("an unfenced reservation marshalled an epoch field — pre-#428 journals would stop verifying:\n%s", contents)
	}

	reopened, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("a legacy journal no longer opens: %v", err)
	}
	defer reopened.Close()
	summary, err := VerifyState(path)
	if err != nil || summary.HeadEpoch != 0 {
		t.Fatalf("a legacy journal no longer verifies: (%+v, %v)", summary, err)
	}
	next := reservation("nonce_000000000002", "2026-09-13", 100, 1_000)
	if err := reopened.Reserve(context.Background(), next); err != nil {
		t.Fatalf("a legacy journal no longer extends: %v", err)
	}
}

func TestAnEpochRewriteWithRecordedHashesPreservedIsRefused(t *testing.T) {
	// THE CONTENT-REWRITE DISCIPLINE applied to the new field: rewrite a committed
	// reservation's epoch, leave every recorded hash byte-identical, and the journal must
	// refuse to reopen. A tamper test that only writes garbage is refused by the JSON
	// parser and proves nothing about the chain.
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	current := reservation("nonce_000000000001", "2026-09-13", 100, 1_000)
	current.Epoch = 6
	if err := state.Reserve(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(contents), `"epoch":6`, `"epoch":1`, 1)
	if rewritten == string(contents) {
		t.Fatal("the rewrite fixture did not change the journal")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileState(path); err == nil {
		t.Fatal("a journal whose epoch was rewritten with hashes preserved reopened — the chain must bind the epoch")
	}
}

func TestVerifyStateReportsTheHeadEpoch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	first := reservation("nonce_000000000001", "2026-09-13", 100, 1_000)
	first.Epoch = 3
	if err := state.Reserve(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := reservation("nonce_000000000002", "2026-09-13", 100, 1_000)
	second.Epoch = 9
	if err := state.Reserve(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err := VerifyState(path)
	if err != nil {
		t.Fatal(err)
	}
	if summary.HeadEpoch != 9 {
		t.Fatalf("head epoch = %d, want the MAXIMUM recorded (9), not the last — the promoted site checks its copy against exactly this value", summary.HeadEpoch)
	}
}

// The engine stamps the epoch it holds NOW, per reservation: failover under a running
// daemon must put the NEW epoch on the first reservation after promotion, not the one
// captured at startup.
func TestTheEngineStampsTheEpochItHoldsAtReserveTime(t *testing.T) {
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	// A non-Cosmos policy keeps these tests on the epoch rule alone: no amounts are
	// reserved, so quota cannot mask the classification under test.
	base := Policy{ObjectID: "production-wallet-signer", Purpose: "release", Environment: "production", Algorithm: "ecdsa", Operation: "sign", ID: "wallet-sign", ContentTypes: []string{"application/octet-stream"}, MaxPayloadBytes: 4096, MaxFuture: time.Minute}
	engine, err := New([]Policy{base}, state, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	epoch := uint64(5)
	engine.SetEpochSource(func() uint64 { return epoch })

	request := Request{ObjectID: "production-wallet-signer", Purpose: "release", Environment: "production", Operation: "sign", Principal: "spiffe://regalia/workload/tx-signer",
		RequestID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", Nonce: "nonce_000000000001",
		ContentType: "application/octet-stream", Algorithm: "ecdsa", PayloadBytes: 1,
		ExpiresAt: time.Now().Add(30 * time.Second)}
	if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
		t.Fatalf("the fenced first reservation was refused: %+v", decision)
	}

	// Promotion mid-run: the source now reports the new epoch, and the NEXT reservation
	// carries it — which is also what the journal's monotonic rule needs to accept it.
	epoch = 6
	request.Nonce = "nonce_000000000002"
	if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
		t.Fatalf("the promoted leader's reservation was refused: %+v", decision)
	}
	events, err := readState(state.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Reservation.Epoch != 5 || events[1].Reservation.Epoch != 6 {
		t.Fatalf("the journal did not record the per-reservation epochs: %+v", events)
	}
}

// And the DENIED mapping: a stale leader's operation fails closed at the POLICY layer with
// its own rule name, distinguishable from quota and replay in an operator's metrics.
func TestAStaleLeaderIsDeniedUnderTheEpochRule(t *testing.T) {
	state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	// A non-Cosmos policy keeps these tests on the epoch rule alone: no amounts are
	// reserved, so quota cannot mask the classification under test.
	base := Policy{ObjectID: "production-wallet-signer", Purpose: "release", Environment: "production", Algorithm: "ecdsa", Operation: "sign", ID: "wallet-sign", ContentTypes: []string{"application/octet-stream"}, MaxPayloadBytes: 4096, MaxFuture: time.Minute}
	engine, err := New([]Policy{base}, state, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	epoch := uint64(9)
	engine.SetEpochSource(func() uint64 { return epoch })
	request := Request{ObjectID: "production-wallet-signer", Purpose: "release", Environment: "production", Operation: "sign", Principal: "spiffe://regalia/workload/tx-signer",
		RequestID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", Nonce: "nonce_000000000001",
		ContentType: "application/octet-stream", Algorithm: "ecdsa", PayloadBytes: 1,
		ExpiresAt: time.Now().Add(30 * time.Second)}
	if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
		t.Fatalf("fixture reservation refused: %+v", decision)
	}

	// The site is promoted away from; its source still reports the old epoch.
	epoch = 8
	request.Nonce = "nonce_000000000002"
	decision := engine.Evaluate(context.Background(), request)
	if decision.Allowed || decision.Code != CodeDenied || decision.Rule != "epoch" {
		t.Fatalf("the stale leader's decision = %+v, want DENIED under the epoch rule", decision)
	}
}
