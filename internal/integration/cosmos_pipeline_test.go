package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// This is the software half of the production pipeline: generated SignDoc -> parser -> policy
// reservation -> digest -> signer -> verification. The hardware-tagged integration tests replace
// the signer with PKCS#11; keeping this test independent makes the policy boundary falsifiable on
// every platform while making the hardware dependency explicit.
func TestCosmosPolicyToSignerToVerification(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "signdoc-akashnet2-msgsend.hex"))
	if err != nil {
		t.Fatal(err)
	}
	signDoc, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := policy.ParseCosmosSignDoc(signDoc)
	if err != nil {
		t.Fatalf("generated SignDoc refused: %v", err)
	}
	state := &pipelineState{}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	engine, err := policy.New([]policy.Policy{{
		ID: "wallet", ObjectID: "wallet", Purpose: "cosmos-transaction", Environment: "staging",
		Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"},
		MaxPayloadBytes: 10000, MaxFuture: time.Minute, Cosmos: &policy.CosmosPolicy{
			ChainIDs: []string{"akashnet-2"}, AccountNumbers: []uint64{42},
			MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"}, Sources: []string{tx.Messages[0].Source},
			Destinations: []string{tx.Messages[0].Destination}, MaxGasLimit: 300000,
			MaxFee: map[string]uint64{"uakt": 10000}, MaxPerTransaction: map[string]uint64{"uakt": 1000000},
			MaxPerDay: map[string]uint64{"uakt": 5000000},
		},
	}}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(context.Background(), policy.Request{
		RequestID: "cosmos-pipeline-1", Principal: "spiffe://regalia/workload/test", ObjectID: "wallet",
		Purpose: "cosmos-transaction", Environment: "staging", Operation: "sign", Algorithm: "secp256k1",
		ContentType: "application/vnd.cosmos.tx+protobuf", PayloadBytes: int64(len(signDoc)),
		ExpiresAt: now.Add(30 * time.Second), Nonce: "nonce_cosmos_pipeline_1", Cosmos: tx,
	})
	if !decision.Allowed {
		t.Fatalf("policy denied generated transaction: %#v", decision)
	}
	digest := sha256.Sum256(signDoc)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], signature) {
		t.Fatal("DEFECT: signature over the policy-approved canonical SignDoc digest did not verify")
	}
	if state.last.Nonce != "nonce_cosmos_pipeline_1" {
		t.Fatalf("policy reservation was not committed: %#v", state.last)
	}
}

// TestCosmosPolicyToConcretePKCS11 verifies the complete software-to-token seam. It is skipped
// unless the disposable SoftHSM harness (or an explicitly approved staging module) supplies all
// selectors and its ephemeral PIN. The policy decision happens before the token is opened.
func TestCosmosPolicyToConcretePKCS11(t *testing.T) {
	module, serial, pin, tokenLabel := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL"), os.Getenv("REGALIA_PKCS11_E2E_PIN"), os.Getenv("REGALIA_PKCS11_E2E_TOKEN_LABEL")
	if module == "" || serial == "" || pin == "" || tokenLabel == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE, REGALIA_PKCS11_E2E_SERIAL, REGALIA_PKCS11_E2E_PIN, and REGALIA_PKCS11_E2E_TOKEN_LABEL")
	}
	raw, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "signdoc-akashnet2-msgsend.hex"))
	if err != nil {
		t.Fatal(err)
	}
	signDoc, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := policy.ParseCosmosSignDoc(signDoc)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	state := &pipelineState{}
	engine, err := policy.New([]policy.Policy{{
		ID: "cosmos-hardware", ObjectID: "cosmos-hardware", Purpose: "cosmos-transaction", Environment: "staging",
		Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"},
		MaxPayloadBytes: 10000, MaxFuture: time.Minute,
		Cosmos: &policy.CosmosPolicy{ChainIDs: []string{"akashnet-2"}, AccountNumbers: []uint64{42},
			MessageTypes: []string{"/cosmos.bank.v1beta1.MsgSend"}, Sources: []string{tx.Messages[0].Source},
			Destinations: []string{tx.Messages[0].Destination}, MaxGasLimit: 300000,
			MaxFee: map[string]uint64{"uakt": 10000}, MaxPerTransaction: map[string]uint64{"uakt": 1000000},
			MaxPerDay: map[string]uint64{"uakt": 5000000}},
	}}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Evaluate(context.Background(), policy.Request{
		RequestID: "cosmos-hardware-1", Principal: "spiffe://regalia/workload/test", ObjectID: "cosmos-hardware",
		Purpose: "cosmos-transaction", Environment: "staging", Operation: "sign", Algorithm: "secp256k1",
		ContentType: "application/vnd.cosmos.tx+protobuf", PayloadBytes: int64(len(signDoc)),
		ExpiresAt: now.Add(30 * time.Second), Nonce: "nonce_cosmos_hardware_1", Cosmos: tx,
	})
	if !decision.Allowed {
		t.Fatalf("policy denied generated SignDoc before hardware: %#v", decision)
	}
	if state.last.Nonce != "nonce_cosmos_hardware_1" {
		t.Fatalf("policy reservation was not committed before hardware signing: %#v", state.last)
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
		Site: "e2e", Backend: "nitrokey-pkcs11", DeviceID: "cosmos-hardware", DeviceSerial: serial,
		DevAuthFingerprint: devAuth, ObjectID: "01", State: "active",
	}}
	digest := sha256.Sum256(signDoc)
	signature, _, err := provider.Execute(context.Background(), route, "sign", "", "application/vnd.regalia.digest", digest[:], nil)
	if err != nil || len(signature) != 64 {
		t.Fatalf("hardware signature length=%d err=%v", len(signature), err)
	}
	publicDER, _, err := provider.Execute(context.Background(), route, "public-key", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(publicDER) == 0 {
		t.Fatal("token returned an empty public key")
	}
	stateDir := t.TempDir()
	digestPath, signaturePath := filepath.Join(stateDir, "digest.bin"), filepath.Join(stateDir, "signature.raw")
	if err := os.WriteFile(digestPath, digest[:], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	verify := exec.Command("pkcs11-tool", "--module", module, "--token-label", tokenLabel, "--login", "--pin", "env:PKCS11_PIN", "--verify", "--mechanism", "ECDSA", "--id", "01", "--input-file", digestPath, "--signature-file", signaturePath)
	verify.Env = append(os.Environ(), "PKCS11_PIN="+pin)
	if output, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("DEFECT: policy-approved concrete PKCS#11 signature did not verify: %v (%s)", err, output)
	}
}

type pipelineState struct{ last policy.Reservation }

func (s *pipelineState) Reserve(_ context.Context, reservation policy.Reservation) error {
	s.last = reservation
	return nil
}
