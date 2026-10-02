package integration_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strconv"
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
// The policy is built from what the OPERATOR passes in the environment — chain, account number,
// source, destination and every cap — never from the SignDoc. So a SignDoc that disagrees with what
// the script asked for is refused, and the refusal arms check the reason.
//
// REGALIA_COSMOS_NODE_EXPECT_REFUSAL names the refusal an arm expects: "signdoc" (the parser refuses
// the bytes) or a policy decision rule ("cosmos-destination", "sequence", "quota", "epoch", …). The test passes only
// on EXACTLY that refusal, and a refused request never reaches the token: nothing is written, so the
// script finds no signature to broadcast.
//
// REGALIA_COSMOS_NODE_POLICY_STATE is the production durable journal (policy.FileState). The script
// keeps one path across its arms, so the account sequence, the daily quota and the fencing epoch
// carry from one request to the next exactly as they do in the daemon.
func TestCosmosKMSSignsASignDocForALiveNode(t *testing.T) {
	env := func(name string) string { return os.Getenv("REGALIA_COSMOS_NODE_" + name) }
	signDocPath, signatureOut, statePath := env("SIGNDOC"), env("SIGNATURE_OUT"), env("POLICY_STATE")
	module, serial, pin := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL"), os.Getenv("REGALIA_PKCS11_E2E_PIN")
	objectID, chainID, source, allowedDestination := env("OBJECT_ID"), env("CHAIN_ID"), env("SOURCE"), env("ALLOWED_DESTINATION")
	required := []string{signDocPath, signatureOut, statePath, module, serial, pin, objectID, chainID, source, allowedDestination,
		env("ACCOUNT_NUMBER"), env("MAX_GAS"), env("MAX_FEE"), env("MAX_PER_TX"), env("MAX_PER_DAY"), env("NOW")}
	for _, value := range required {
		if value == "" {
			t.Skip("driven by e2e/cosmos-simapp-kms-tx.sh")
		}
	}
	number := func(name string) uint64 {
		value, err := strconv.ParseUint(env(name), 10, 64)
		if err != nil {
			t.Fatalf("REGALIA_COSMOS_NODE_%s: %v", name, err)
		}
		return value
	}
	expectRefusal := env("EXPECT_REFUSAL")

	signDoc, err := os.ReadFile(signDocPath)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := policy.ParseCosmosSignDoc(signDoc)
	if expectRefusal == "signdoc" {
		if !errors.Is(err, policy.ErrCosmosSignDoc) {
			t.Fatalf("DEFECT: the parser did not refuse this SignDoc as malformed: tx=%#v err=%v", tx, err)
		}
		t.Logf("refused by the parser, before policy and hardware: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("the production parser refused a cosmpy-generated SignDoc: %v", err)
	}

	// ONE CLOCK FOR THE WHOLE RUN: the script fixes it, so a run that straddles midnight UTC cannot
	// split its daily quota across two days and pass the quota arm for the wrong reason.
	now := time.Unix(int64(number("NOW")), 0).UTC()
	state, err := policy.OpenFileState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	engine, err := policy.New([]policy.Policy{{
		ID: "cosmos-node", ObjectID: "cosmos-node", Purpose: "cosmos-transaction", Environment: "staging",
		Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"},
		MaxPayloadBytes: 10000, MaxFuture: time.Minute,
		Cosmos: &policy.CosmosPolicy{ChainIDs: []string{chainID}, AccountNumbers: []uint64{number("ACCOUNT_NUMBER")},
			MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"}, Sources: []string{source},
			Destinations: []string{allowedDestination}, MaxGasLimit: number("MAX_GAS"),
			MaxFee: map[string]uint64{"stake": number("MAX_FEE")}, MaxPerTransaction: map[string]uint64{"stake": number("MAX_PER_TX")},
			MaxPerDay: map[string]uint64{"stake": number("MAX_PER_DAY")}},
	}}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if env("EPOCH") != "" {
		epoch := number("EPOCH")
		engine.SetEpochSource(func() uint64 { return epoch })
	}
	decision := engine.Evaluate(context.Background(), policy.Request{
		RequestID: "cosmos-node-1", Principal: "spiffe://regalia/workload/e2e", ObjectID: "cosmos-node",
		Purpose: "cosmos-transaction", Environment: "staging", Operation: "sign", Algorithm: "secp256k1",
		ContentType: "application/vnd.cosmos.tx+protobuf", PayloadBytes: int64(len(signDoc)),
		ExpiresAt: now.Add(30 * time.Second), Nonce: "nonce_cosmos_node_" + strconv.FormatInt(time.Now().UnixNano(), 10), Cosmos: tx,
	})
	if expectRefusal != "" {
		if decision.Allowed || decision.Rule != expectRefusal {
			t.Fatalf("DEFECT: expected the policy to refuse with rule %q, got %#v", expectRefusal, decision)
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
