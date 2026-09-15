package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// --- SignDoc encoder helpers (duplicated from policy/cosmos_test.go so the
//     operations package can build a canonical SignDoc fixture for the bridging
//     tests without reaching into policy test-only symbols). ---

func bridgeEncodeTag(fieldNumber, wireType uint64) []byte {
	return bridgeEncodeVarint((fieldNumber << 3) | wireType)
}

func bridgeEncodeVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func bridgeEncodeLengthDelimited(fieldNumber uint64, body []byte) []byte {
	return append(bridgeEncodeTag(fieldNumber, 2), append(bridgeEncodeVarint(uint64(len(body))), body...)...)
}

func bridgeEncodeString(fieldNumber uint64, value string) []byte {
	return bridgeEncodeLengthDelimited(fieldNumber, []byte(value))
}

func bridgeEncodeTopVarint(fieldNumber, value uint64) []byte {
	return append(bridgeEncodeTag(fieldNumber, 0), bridgeEncodeVarint(value)...)
}

func bridgeEncodeAny(typeURL string, inner []byte) []byte {
	var buf bytes.Buffer
	buf.Write(bridgeEncodeString(1, typeURL))
	buf.Write(bridgeEncodeLengthDelimited(2, inner))
	return buf.Bytes()
}

func bridgeEncodeMsgSend(from, to, denom string, amount uint64) []byte {
	var coin bytes.Buffer
	coin.Write(bridgeEncodeString(1, denom))
	// A DECIMAL STRING, as the upstream protos encode it. This was a varint, and it is the THIRD
	// copy of that assumption in the repository -- the decoder required it, the policy package's
	// test encoder produced it, and so did this one. Three agreeing halves and no cosmos node
	// among them. See kms/internal/policy/testdata for bytes from the generated encoder.
	coin.Write(bridgeEncodeString(2, strconv.FormatUint(amount, 10)))
	var buf bytes.Buffer
	buf.Write(bridgeEncodeString(1, from))
	buf.Write(bridgeEncodeString(2, to))
	buf.Write(bridgeEncodeLengthDelimited(3, coin.Bytes()))
	return buf.Bytes()
}

func bridgeEncodeTxBody(messages [][2][]byte) []byte {
	var buf bytes.Buffer
	for _, pair := range messages {
		buf.Write(bridgeEncodeLengthDelimited(1, bridgeEncodeAny(string(pair[0]), pair[1])))
	}
	return buf.Bytes()
}

func bridgeEncodeAuthInfo() []byte {
	single := bridgeEncodeTopVarint(1, 1)
	modeInfo := bridgeEncodeLengthDelimited(1, single)
	signer := append(bridgeEncodeLengthDelimited(2, modeInfo), bridgeEncodeTopVarint(3, 7)...)
	coin := append(bridgeEncodeString(1, "uatom"), bridgeEncodeString(2, "1000")...)
	fee := append(bridgeEncodeLengthDelimited(1, coin), bridgeEncodeTopVarint(2, 200000)...)
	return append(bridgeEncodeLengthDelimited(1, signer), bridgeEncodeLengthDelimited(2, fee)...)
}

func bridgeEncodeSignDoc(chainID string, accountNumber uint64, txBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write(bridgeEncodeLengthDelimited(1, txBody))
	buf.Write(bridgeEncodeLengthDelimited(2, bridgeEncodeAuthInfo()))
	buf.Write(bridgeEncodeString(3, chainID))
	buf.Write(bridgeEncodeTopVarint(4, accountNumber))
	return buf.Bytes()
}

func bridgeCosmosSignDoc() []byte {
	msg := bridgeEncodeMsgSend("cosmos1source", "cosmos1dest", "uatom", 900_000)
	body := bridgeEncodeTxBody([][2][]byte{{[]byte("/cosmos.bank.v1beta1.MsgSend"), msg}})
	return bridgeEncodeSignDoc("cosmoshub-4", 42, body)
}

// bridgeCoordinator builds a coordinator whose policy decision always allows.
// The test asserts on the captured policy.Request, not the decision.
func bridgeCoordinator(t *testing.T) (*Coordinator, *fakePolicy, *fakeRouter) {
	t.Helper()
	router := &fakeRouter{route: registry.Route{
		ObjectID: "production-wallet-signer", Purpose: "cosmos-transaction",
		Environment: "production", Algorithm: "secp256k1", PolicyID: "cosmos-hot-wallet",
		Binding: registry.Binding{DeviceID: "hsm-1"},
	}}
	semantic := &fakePolicy{decision: policy.Decision{
		Allowed: true, Code: policy.CodeAllowed, PolicyID: "cosmos-hot-wallet", Rule: "allow",
	}}
	hardware := &fakeHardware{output: []byte("signature")}
	coordinator, coordErr := New(
		fakeAuthorizer{allowed: true}, router, semantic,
		&fakeAudit{}, directRunner{}, hardware,
		"sha256:policy", nil, time.Now,
	)
	if coordErr != nil {
		t.Fatal(coordErr)
	}
	return coordinator, semantic, router
}

// --- Cosmos bridging tests ---

// TestCoordinatorBridgesCosmosSignDocIntoPolicyRequest asserts that the
// canonical Cosmos SignDoc payload sent as request.Data is parsed at the
// trusted boundary and the resulting CosmosTransaction is forwarded to the
// policy engine. Without the fix, policy.Request.Cosmos is nil and any policy
// with a Cosmos block denies the request — even for a transaction that
// matches every allowlisted dimension.
func TestCoordinatorBridgesCosmosSignDocIntoPolicyRequest(t *testing.T) {
	coordinator, semantic, _ := bridgeCoordinator(t)

	request := api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000001", Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID: "production-wallet-signer", Operation: "sign",
		Context: api.OperationContext{
			Environment: "production", Purpose: "cosmos-transaction",
			ExpiresAt: time.Now().Add(time.Minute), Nonce: "nonce_0123456789abcdef",
		},
		ContentType: "application/vnd.cosmos.tx+protobuf",
		Data:        bridgeCosmosSignDoc(),
	}
	if _, err := coordinator.Execute(context.Background(), request); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if semantic.calls != 1 {
		t.Fatalf("policy calls = %d, want 1", semantic.calls)
	}
	got := semantic.lastRequest.Cosmos
	if got == nil {
		t.Fatalf("DEFECT: coordinator did not populate policy.Request.Cosmos from the canonical SignDoc; got nil")
	}
	if got.ChainID != "cosmoshub-4" {
		t.Errorf("ChainID = %q, want cosmoshub-4", got.ChainID)
	}
	if got.AccountNumber != 42 {
		t.Errorf("AccountNumber = %d, want 42", got.AccountNumber)
	}
	if got.Sequence != 7 || got.GasLimit != 200000 || len(got.Fee) != 1 || got.Fee[0].Amount != 1000 {
		t.Fatalf("AuthInfo = sequence %d gas %d fee %#v, want 7/200000/1000", got.Sequence, got.GasLimit, got.Fee)
	}
	if len(got.Messages) != 1 || got.Messages[0].Destination != "cosmos1dest" {
		t.Fatalf("Messages = %#v, want one MsgSend to cosmos1dest", got.Messages)
	}
	if got.Messages[0].Type != "/cosmos.bank.v1beta1.MsgSend" {
		t.Errorf("Message.Type = %q, want /cosmos.bank.v1beta1.MsgSend", got.Messages[0].Type)
	}
	amounts := got.Messages[0].Amounts
	if len(amounts) != 1 || amounts[0].Denom != "uatom" || amounts[0].Amount != 900_000 {
		t.Errorf("Message.Amounts = %#v, want [{uatom 900000}]", amounts)
	}
}

func TestCoordinatorHashesCanonicalCosmosSignDocBeforeHardware(t *testing.T) {
	coordinator, _, _ := bridgeCoordinator(t)
	request := api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000002", Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID: "production-wallet-signer", Operation: "sign",
		Context:     api.OperationContext{Environment: "production", Purpose: "cosmos-transaction", ExpiresAt: time.Now().Add(time.Minute), Nonce: "nonce_0123456789abcde2"},
		ContentType: "application/vnd.cosmos.tx+protobuf", Data: bridgeCosmosSignDoc(),
	}
	hardware := coordinator.hardware.(*fakeHardware)
	if _, err := coordinator.Execute(context.Background(), request); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	want := sha256.Sum256(request.Data)
	if string(hardware.data) != string(want[:]) {
		t.Fatalf("DEFECT: hardware received %x, want SHA-256 SignDoc digest %x", hardware.data, want)
	}
}

// TestCoordinatorDoesNotPopulateCosmosForNonCosmosRequests ensures the parser
// is only invoked when the request carries the canonical content type.
func TestCoordinatorDoesNotPopulateCosmosForNonCosmosRequests(t *testing.T) {
	coordinator, semantic, _ := bridgeCoordinator(t)

	request := api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000002", Principal: "spiffe://regalia/workload/sops",
		ObjectID: "production-sops", Operation: "unwrap",
		Context: api.OperationContext{
			Environment: "production", Purpose: "sops-data-key",
			ExpiresAt: time.Now().Add(time.Minute), Nonce: "nonce_abcdef0123456789",
		},
		Format: "regalia-envelope-v2", Data: []byte("wrapped-key"),
	}
	if _, err := coordinator.Execute(context.Background(), request); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if semantic.lastRequest.Cosmos != nil {
		t.Fatalf("policy.Request.Cosmos = %#v, want nil for non-Cosmos content type", semantic.lastRequest.Cosmos)
	}
}

// TestCoordinatorMalformedCosmosSignDocDeniesBeforePolicyAndHardware asserts
// the parser's failure mode: a SignDoc the parser cannot decode must be
// DENIED, not silently treated as "no Cosmos constraints apply" and passed
// through to the device. Without the parser call, the bytes flow past the
// policy layer and only fail at the device boundary, which is exactly the
// digest-oracle posture the policy engine exists to prevent.
func TestCoordinatorMalformedCosmosSignDocDeniesBeforePolicyAndHardware(t *testing.T) {
	coordinator, semantic, _ := bridgeCoordinator(t)
	hardware := &fakeHardware{output: []byte("must-not-escape")}
	coordinator.hardware = hardware

	request := api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000003", Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID: "production-wallet-signer", Operation: "sign",
		Context: api.OperationContext{
			Environment: "production", Purpose: "cosmos-transaction",
			ExpiresAt: time.Now().Add(time.Minute), Nonce: "nonce_0123456789abcd0",
		},
		ContentType: "application/vnd.cosmos.tx+protobuf",
		Data:        []byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x7f}, // truncated length prefix
	}
	_, err := coordinator.Execute(context.Background(), request)
	if err == nil {
		t.Fatal("expected malformed-SignDoc error, got nil")
	}
	failure, ok := err.(*api.Failure)
	if !ok {
		t.Fatalf("error type %T, want *api.Failure", err)
	}
	if failure.Code != "INVALID_ARGUMENT" || failure.Status != 400 {
		t.Fatalf("failure = %#v, want INVALID_ARGUMENT/400", failure)
	}
	if semantic.calls != 0 {
		t.Errorf("policy was evaluated %d times; parser failure must short-circuit before policy", semantic.calls)
	}
	if hardware.calls != 0 {
		t.Errorf("hardware was called %d times; malformed SignDoc must never reach the device", hardware.calls)
	}
}

// TestCoordinatorMalformedCosmosSignDocDeniesEvenWithoutCosmosPolicy asserts
// the parser's failure mode when the policy engine has no Cosmos block at
// all: the parser must still deny, never fall through to "no Cosmos
// constraints apply". This is the exact scenario a digest-oracle attacker
// would probe: a permissive policy plus bytes that look almost-but-not-quite
// like a SignDoc.
func TestCoordinatorMalformedCosmosSignDocDeniesEvenWithoutCosmosPolicy(t *testing.T) {
	router := &fakeRouter{route: registry.Route{
		ObjectID: "production-wallet-signer", Purpose: "cosmos-transaction",
		Environment: "production", Algorithm: "secp256k1", PolicyID: "permissive-signer",
		Binding: registry.Binding{DeviceID: "hsm-1"},
	}}
	semantic := &fakePolicy{decision: policy.Decision{
		Allowed: true, Code: policy.CodeAllowed, PolicyID: "permissive-signer", Rule: "allow",
	}}
	hardware := &fakeHardware{output: []byte("must-not-escape")}
	coordinator, coordErr := New(
		fakeAuthorizer{allowed: true}, router, semantic,
		&fakeAudit{}, directRunner{}, hardware,
		"sha256:policy", nil, time.Now,
	)
	if coordErr != nil {
		t.Fatal(coordErr)
	}

	request := api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000004", Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID: "production-wallet-signer", Operation: "sign",
		Context: api.OperationContext{
			Environment: "production", Purpose: "cosmos-transaction",
			ExpiresAt: time.Now().Add(time.Minute), Nonce: "nonce_abcdef0123456789",
		},
		ContentType: "application/vnd.cosmos.tx+protobuf",
		Data:        []byte("not a protobuf sign doc at all"),
	}
	_, err := coordinator.Execute(context.Background(), request)
	if err == nil {
		t.Fatal("expected malformed-SignDoc error even with permissive policy; got nil")
	}
	failure, ok := err.(*api.Failure)
	if !ok {
		t.Fatalf("error type %T, want *api.Failure", err)
	}
	if failure.Code != "INVALID_ARGUMENT" {
		t.Fatalf("failure.Code = %q, want INVALID_ARGUMENT — a permissive policy must not allow unparsed SignDocs", failure.Code)
	}
	if semantic.calls != 0 {
		t.Errorf("policy was evaluated %d times; parser failure must short-circuit before policy", semantic.calls)
	}
	if hardware.calls != 0 {
		t.Errorf("hardware was called %d times; malformed SignDoc must never reach the device", hardware.calls)
	}
}

// --- Approvals regression: pin the fail-closed posture. ---
//
// The coordinator does not bridge any client-supplied approver set into
// policy.Request.VerifiedApprovers. RequiredApprovals therefore stays
// unsatisfiable from the network, and any policy with RequiredApprovals > 0
// denies every request — even a fully-formed Cosmos SignDoc that matches
// every other dimension. This is deliberate: a client cannot self-attest its
// own approvals. See the filed approvals-verification issue for the design
// that will close this gap without re-introducing the bypass.

type bridgeReservationState struct{}

func (bridgeReservationState) Reserve(_ context.Context, _ policy.Reservation) error { return nil }

// TestCoordinatorApprovalsCannotBeSatisfiedByClientClaims wires a real
// policy.Engine with a policy that requires one approved approver. The
// request matches every dimension (correct object, purpose, environment,
// algorithm, content type, valid Cosmos SignDoc, fresh expiry, valid
// nonce). It must still be denied with the "approval" rule because no
// server-side approver verification has happened.
//
// This test pins the fail-closed posture. Re-introducing a client-side
// approver bridge (e.g. an X-Verified-Approvers header forwarded as-is to
// policy.Request.VerifiedApprovers) would convert this test from PASS into
// the very bypass it exists to prevent.
func TestCoordinatorApprovalsCannotBeSatisfiedByClientClaims(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	cosmosPolicy := policy.Policy{
		ID: "cosmos-hot-wallet", ObjectID: "production-wallet-signer", Purpose: "cosmos-transaction",
		Environment: "production", Operation: "sign", Algorithm: "secp256k1",
		ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"}, MaxPayloadBytes: 100_000,
		MaxFuture: 5 * time.Minute, RequiredApprovals: 1,
		Approvers: []string{"spiffe://regalia/approver/treasury"},
		Cosmos: &policy.CosmosPolicy{
			ChainIDs: []string{"cosmoshub-4"}, AccountNumbers: []uint64{42},
			MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"},
			Sources:      []string{"cosmos1source"}, Destinations: []string{"cosmos1dest"}, MaxPerTransaction: map[string]uint64{"uatom": 1_000_000},
			MaxGasLimit: 500_000, MaxFee: map[string]uint64{"uatom": 10_000},
			MaxPerDay: map[string]uint64{"uatom": 5_000_000},
		},
	}
	engine, err := policy.New([]policy.Policy{cosmosPolicy}, bridgeReservationState{}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	router := &fakeRouter{route: registry.Route{
		ObjectID: "production-wallet-signer", Purpose: "cosmos-transaction",
		Environment: "production", Algorithm: "secp256k1", PolicyID: "cosmos-hot-wallet",
		Binding: registry.Binding{DeviceID: "hsm-1"},
	}}
	hardware := &fakeHardware{output: []byte("must-not-escape")}
	coordinator, coordErr := New(
		fakeAuthorizer{allowed: true}, router, engine,
		&fakeAudit{}, directRunner{}, hardware,
		"sha256:policy", nil, func() time.Time { return now },
	)
	if coordErr != nil {
		t.Fatal(coordErr)
	}

	request := api.Request{
		RequestID: "018f0000-0000-7000-8000-000000000005",
		Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID:  "production-wallet-signer", Operation: "sign",
		Context: api.OperationContext{
			Environment: "production", Purpose: "cosmos-transaction",
			ExpiresAt: now.Add(time.Minute), Nonce: "nonce_0123456789abcd1",
		},
		ContentType: "application/vnd.cosmos.tx+protobuf",
		Data:        bridgeCosmosSignDoc(),
	}
	_, err = coordinator.Execute(context.Background(), request)
	if err == nil {
		t.Fatal("approval-bearing policy must deny every request until server-side approver verification is wired; got nil error")
	}
	failure, ok := err.(*api.Failure)
	if !ok {
		t.Fatalf("error type %T, want *api.Failure", err)
	}
	if failure.Code != "DENIED" || failure.Status != 403 {
		t.Fatalf("failure = %#v, want DENIED/403 — client cannot satisfy RequiredApprovals", failure)
	}
	if hardware.calls != 0 {
		t.Errorf("hardware was called %d times; approval-failed requests must never reach the device", hardware.calls)
	}
}
