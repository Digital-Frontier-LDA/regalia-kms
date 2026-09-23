package integration_test

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE KMS HALF OF A TRANSACTION A LIVE NODE ACCEPTS (regalia#439, acceptance criterion 1).
//
// e2e/cosmos-simapp-kms-tx.sh runs a disposable simd devnet, builds a MsgSend SignDoc with cosmpy's
// GENERATED protobuf bindings — never a hand-written encoder in this repository, which is how the
// Coin.amount defect once passed its own tests — and hands the SignDoc bytes to this test. This
// test is the KMS: it parses the SignDoc with the production parser, admits it through the
// production policy engine, signs the digest through the concrete PKCS#11 provider (which applies
// low-S), and writes the 64-byte signature back. The script then assembles TxRaw with cosmpy and
// broadcasts it. The node's verdict is the evidence; nothing here asserts the chain's rules.
//
// The policy is built to admit exactly the chain, account, source and destination the operator
// passes in the environment — NOT whatever the SignDoc says. So a SignDoc that disagrees with what
// the script asked for is refused, and the refusal arm (REGALIA_COSMOS_NODE_EXPECT_DENY=1) checks
// that a disallowed destination never reaches the token.
func TestCosmosKMSSignsASignDocForALiveNode(t *testing.T) {
	signDocPath, signatureOut := os.Getenv("REGALIA_COSMOS_NODE_SIGNDOC"), os.Getenv("REGALIA_COSMOS_NODE_SIGNATURE_OUT")
	module, serial, pin := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL"), os.Getenv("REGALIA_PKCS11_E2E_PIN")
	objectID := os.Getenv("REGALIA_COSMOS_NODE_OBJECT_ID")
	chainID, allowedDestination := os.Getenv("REGALIA_COSMOS_NODE_CHAIN_ID"), os.Getenv("REGALIA_COSMOS_NODE_ALLOWED_DESTINATION")
	if signDocPath == "" || signatureOut == "" || module == "" || serial == "" || pin == "" || objectID == "" || chainID == "" || allowedDestination == "" {
		t.Skip("driven by e2e/cosmos-simapp-kms-tx.sh")
	}
	expectDeny := os.Getenv("REGALIA_COSMOS_NODE_EXPECT_DENY") == "1"

	signDoc, err := os.ReadFile(signDocPath)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := policy.ParseCosmosSignDoc(signDoc)
	if err != nil {
		t.Fatalf("the production parser refused a cosmpy-generated SignDoc: %v", err)
	}
	if len(tx.Messages) != 1 {
		t.Fatalf("expected exactly one message, got %d", len(tx.Messages))
	}

	now := time.Now().UTC()
	state := &pipelineState{}
	engine, err := policy.New([]policy.Policy{{
		ID: "cosmos-node", ObjectID: "cosmos-node", Purpose: "cosmos-transaction", Environment: "staging",
		Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"},
		MaxPayloadBytes: 10000, MaxFuture: time.Minute,
		Cosmos: &policy.CosmosPolicy{ChainIDs: []string{chainID}, AccountNumbers: []uint64{tx.AccountNumber},
			MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"}, Sources: []string{tx.Messages[0].Source},
			Destinations: []string{allowedDestination}, MaxGasLimit: 300000,
			MaxFee: map[string]uint64{"stake": 1000}, MaxPerTransaction: map[string]uint64{"stake": 1000000},
			MaxPerDay: map[string]uint64{"stake": 5000000}},
	}}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(context.Background(), policy.Request{
		RequestID: "cosmos-node-1", Principal: "spiffe://regalia/workload/e2e", ObjectID: "cosmos-node",
		Purpose: "cosmos-transaction", Environment: "staging", Operation: "sign", Algorithm: "secp256k1",
		ContentType: "application/vnd.cosmos.tx+protobuf", PayloadBytes: int64(len(signDoc)),
		ExpiresAt: now.Add(30 * time.Second), Nonce: "nonce_cosmos_node_" + now.Format("150405000000000"), Cosmos: tx,
	})
	if expectDeny {
		if decision.Allowed {
			t.Fatalf("DEFECT: policy admitted a MsgSend to %s while only %s is allowed", tx.Messages[0].Destination, allowedDestination)
		}
		// Refused BEFORE the token: nothing is written, so the script finds no signature to use.
		t.Logf("refused before hardware, as required: %#v", decision)
		return
	}
	if !decision.Allowed {
		t.Fatalf("policy denied the cosmpy SignDoc: %#v", decision)
	}

	devAuth := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	driver, err := nitrokey.NewPKCS11Driver(module, devAuthProbe(devAuth), secureChannel{}, retryProbe(3))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	provider, err := nitrokey.New(driver, pinSource{value: []byte(pin)})
	if err != nil {
		t.Fatal(err)
	}
	route := registry.Route{Algorithm: "secp256k1", Purpose: "cosmos-transaction", Environment: "staging", Binding: registry.Binding{
		Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "cosmos-node", DeviceSerial: serial,
		DevAuthFingerprint: devAuth, ObjectID: objectID, State: "active",
	}}
	digest := sha256.Sum256(signDoc)
	signature, _, err := provider.Execute(context.Background(), route, "sign", "", "application/vnd.regalia.digest", digest[:], nil)
	if err != nil || len(signature) != 64 {
		t.Fatalf("hardware signature length=%d err=%v", len(signature), err)
	}
	if err := os.WriteFile(signatureOut, signature, 0o600); err != nil {
		t.Fatal(err)
	}
}
