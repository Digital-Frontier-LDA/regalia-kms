package operations

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/approval"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// DUAL CONTROL, END TO END, THROUGH THE REAL POLICY ENGINE.
//
// The unit tests in internal/approval prove the verifier. These prove the wiring: that
// what the verifier returns is what policy.Engine counts, and that the journal records the
// same set the decision was made on. A verifier nobody consults is the defect this issue
// was filed about, one layer down.

const approvalsObject = "production-wallet-signer"

func approvalsPolicy(required int, approvers []string) policy.Policy {
	return policy.Policy{
		ID: "cosmos-hot-wallet", ObjectID: approvalsObject, Purpose: "cosmos-transaction",
		Environment: "production", Operation: "sign", Algorithm: "secp256k1",
		ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"}, MaxPayloadBytes: 100_000,
		MaxFuture: 5 * time.Minute, RequiredApprovals: required, Approvers: approvers,
		Cosmos: &policy.CosmosPolicy{
			ChainIDs: []string{"cosmoshub-4"}, AccountNumbers: []uint64{42},
			MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"},
			Sources:      []string{"cosmos1source"}, Destinations: []string{"cosmos1dest"}, MaxPerTransaction: map[string]uint64{"uatom": 1_000_000},
			MaxGasLimit: 500_000, MaxFee: map[string]uint64{"uatom": 10_000},
			MaxPerDay: map[string]uint64{"uatom": 5_000_000},
		},
	}
}

func approvalsRequest(now time.Time, header string) api.Request {
	return api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000009",
		Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID:  approvalsObject, Operation: "sign",
		Context: api.OperationContext{
			Environment: "production", Purpose: "cosmos-transaction",
			ExpiresAt: now.Add(time.Minute), Nonce: "nonce_0123456789abcd1",
		},
		ContentType: "application/vnd.cosmos.tx+protobuf",
		Data:        bridgeCosmosSignDoc(),
		Approvals:   header,
	}
}

func approvalsBinding(now time.Time) approval.Binding {
	return approval.Binding{
		ObjectID: approvalsObject, Purpose: "cosmos-transaction", Environment: "production",
		Nonce: "nonce_0123456789abcd1", ExpiresAt: now.Add(time.Minute), Payload: bridgeCosmosSignDoc(),
	}
}

func approvalsHeader(t *testing.T, binding approval.Binding, signers map[string]ed25519.PrivateKey, ids ...string) string {
	t.Helper()
	list := make([]approval.Approval, 0, len(ids))
	for _, id := range ids {
		list = append(list, approval.Approval{
			ApproverID: id, Nonce: binding.Nonce,
			ExpiresAt:     binding.ExpiresAt.UTC().Format(time.RFC3339Nano),
			PayloadDigest: binding.PayloadDigest(),
			Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(signers[id], binding.CanonicalBytes())),
		})
	}
	encoded, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func approvalsHarness(t *testing.T, now time.Time, required int, keys *approval.KeySet, approvers []string) (*Coordinator, *fakeAudit, *fakeHardware) {
	t.Helper()
	engine, err := policy.New([]policy.Policy{approvalsPolicy(required, approvers)}, bridgeReservationState{}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	router := &fakeRouter{route: registry.Route{
		ObjectID: approvalsObject, Purpose: "cosmos-transaction", Environment: "production",
		Algorithm: "secp256k1", PolicyID: "cosmos-hot-wallet",
		Binding: registry.Binding{DeviceID: "hsm-1"},
	}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("signature")}
	coordinator, err := New(fakeAuthorizer{allowed: true, digest: "sha256:rbac"}, router, engine,
		recorder, directRunner{}, hardware, "sha256:policy", keys, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, recorder, hardware
}

func twoApprovers(t *testing.T) (*approval.KeySet, map[string]ed25519.PrivateKey, []string) {
	t.Helper()
	ids := []string{"spiffe://regalia/approver/treasury", "spiffe://regalia/approver/security"}
	public := map[string]ed25519.PublicKey{}
	private := map[string]ed25519.PrivateKey{}
	for _, id := range ids {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		public[id], private[id] = pub, priv
	}
	return approval.NewKeySet(public), private, ids
}

// Two verified signatures satisfy required_approvals: 2, the operation runs, and the
// journal names both. Without this the negative tests could all pass on a verifier that
// returns nothing at all, which is the posture this issue exists to replace.
func TestTwoVerifiedApprovalsAuthorizeAndAreRecorded(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	keys, signers, ids := twoApprovers(t)
	coordinator, recorder, hardware := approvalsHarness(t, now, 2, keys, ids)

	header := approvalsHeader(t, approvalsBinding(now), signers, ids...)
	if _, err := coordinator.Execute(context.Background(), approvalsRequest(now, header)); err != nil {
		t.Fatalf("two verified approvals were refused: %v — required_approvals is still unsatisfiable", err)
	}
	if hardware.calls != 1 {
		t.Fatalf("hardware calls = %d, want 1", hardware.calls)
	}
	if len(recorder.drafts) == 0 {
		t.Fatal("nothing was audited")
	}
	last := recorder.drafts[len(recorder.drafts)-1]
	if len(last.VerifiedApprovers) != 2 {
		t.Fatalf("DEFECT: audit recorded %v, want both approvers — the journal cannot answer "+
			"'who signed off on this?' and a dual-control decision is unauditable after the fact",
			last.VerifiedApprovers)
	}
}

// The withdrawn design, exercised through the whole stack: the client names both
// approvers, from the policy's own list, and signs nothing.
func TestNamedApproversWithoutEvidenceAreDeniedEndToEnd(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	keys, _, ids := twoApprovers(t)
	coordinator, recorder, hardware := approvalsHarness(t, now, 2, keys, ids)

	claimed := make([]approval.Approval, 0, len(ids))
	for _, id := range ids {
		claimed = append(claimed, approval.Approval{
			ApproverID: id, Nonce: "nonce_0123456789abcd1",
			ExpiresAt:     now.Add(time.Minute).UTC().Format(time.RFC3339Nano),
			PayloadDigest: approvalsBinding(now).PayloadDigest(),
		})
	}
	encoded, err := json.Marshal(claimed)
	if err != nil {
		t.Fatal(err)
	}
	header := base64.StdEncoding.EncodeToString(encoded)

	_, err = coordinator.Execute(context.Background(), approvalsRequest(now, header))
	if err == nil {
		t.Fatal("DEFECT: a client satisfied required_approvals by naming approvers with no " +
			"signatures — VerifiedApprovers is being filled from a client assertion")
	}
	failure, ok := err.(*api.Failure)
	if !ok || failure.Code != "DENIED" || failure.Status != 403 {
		t.Fatalf("failure = %#v, want DENIED/403", err)
	}
	if hardware.calls != 0 {
		t.Errorf("hardware was called %d times on an unapproved request", hardware.calls)
	}
	if len(recorder.drafts) == 0 || len(recorder.drafts[len(recorder.drafts)-1].VerifiedApprovers) != 0 {
		t.Errorf("the denial recorded approvers it never verified: %v", recorder.drafts)
	}
}

// One person cannot be two. This is the case a naive dedup-free implementation gets wrong
// and the one that makes dual control worth having.
func TestOneApproverSigningTwiceDoesNotSatisfyTwo(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	keys, signers, ids := twoApprovers(t)
	coordinator, _, hardware := approvalsHarness(t, now, 2, keys, ids)

	doubled := approvalsHeader(t, approvalsBinding(now), signers, ids[0], ids[0])
	_, err := coordinator.Execute(context.Background(), approvalsRequest(now, doubled))
	if err == nil {
		t.Fatal("DEFECT: one approver signing twice satisfied required_approvals: 2 — " +
			"dual control can be satisfied by a single person")
	}
	if hardware.calls != 0 {
		t.Errorf("hardware was called %d times", hardware.calls)
	}
	// The control: the same coordinator with two distinct approvers must allow, or the
	// assertion above passes because nothing can ever be approved.
	both := approvalsHeader(t, approvalsBinding(now), signers, ids...)
	if _, err := coordinator.Execute(context.Background(), approvalsRequest(now, both)); err != nil {
		t.Fatalf("two distinct approvers were refused (%v): the case above would prove nothing", err)
	}
}
