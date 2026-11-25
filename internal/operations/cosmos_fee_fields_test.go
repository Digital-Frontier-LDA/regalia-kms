package operations

import (
	"context"
	"strconv"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// THE AUDIT TRAIL OF A FEE THE POLICY COULD NOT SEE (regalia-kms-bim).
//
// The audit record carries no fee field: what it says about a Cosmos transaction is its outcome,
// and the fee the policy judged is policy.Request.Cosmos.Fee, built from the parsed SignDoc. Before
// this fix a SignDoc with a Fee.payer, a Fee.granter (another account pays) was parsed with those
// values dropped, judged on the fee alone, and audited "success". Here the policy is a fake that
// ALLOWS EVERYTHING, so the only thing that can stop these documents is the parser: each is audited
// policy-cosmos-malformed, never reaches policy, and never reaches the token. The control proves the
// harness signs a clean document, and that the fee handed to policy is the fee the chain charges.

func feeFieldsCosmosSignDoc(feeExtra, tip []byte, coins ...[2]string) []byte {
	var fee []byte
	for _, coin := range coins {
		fee = append(fee, bridgeEncodeLengthDelimited(1, append(bridgeEncodeString(1, coin[0]), bridgeEncodeString(2, coin[1])...))...)
	}
	fee = append(append(fee, bridgeEncodeTopVarint(2, 200000)...), feeExtra...)
	modeInfo := bridgeEncodeLengthDelimited(1, bridgeEncodeTopVarint(1, 1))
	signer := append(bridgeEncodeLengthDelimited(2, modeInfo), bridgeEncodeTopVarint(3, 7)...)
	auth := append(bridgeEncodeLengthDelimited(1, signer), bridgeEncodeLengthDelimited(2, fee)...)
	if tip != nil {
		auth = append(auth, bridgeEncodeLengthDelimited(3, tip)...)
	}
	msg := bridgeEncodeMsgSend("cosmos1source", "cosmos1dest", "uatom", 900_000)
	var out []byte
	out = append(out, bridgeEncodeLengthDelimited(1, bridgeEncodeTxBody([][2][]byte{{[]byte("/cosmos.bank.v1beta1.MsgSend"), msg}}))...)
	out = append(out, bridgeEncodeLengthDelimited(2, auth)...)
	out = append(out, bridgeEncodeString(3, "cosmoshub-4")...)
	return append(out, bridgeEncodeTopVarint(4, 42)...)
}

func feeFieldsRequest(data []byte, sequence int) api.Request {
	return api.Request{
		RequestID: "018f0000-0000-7000-8000-00000000b1" + strconv.Itoa(10+sequence), Principal: "spiffe://regalia/workload/tx-signer",
		ObjectID: "production-wallet-signer", Operation: "sign",
		Context: api.OperationContext{
			Environment: "production", Purpose: "cosmos-transaction",
			ExpiresAt: time.Now().Add(time.Minute), Nonce: "nonce_feefields_" + strconv.Itoa(1000+sequence),
		},
		ContentType: "application/vnd.cosmos.tx+protobuf", Data: data,
	}
}

func TestAFeeThePolicyCannotSeeIsAuditedAsRefusedBeforePolicyAndToken(t *testing.T) {
	uatom := [2]string{"uatom", "1000"}
	tip := append(bridgeEncodeLengthDelimited(1, append(bridgeEncodeString(1, "uatom"), bridgeEncodeString(2, "9500")...)),
		bridgeEncodeString(2, "cosmos1source")...)
	for index, test := range []struct {
		name string
		data []byte
	}{
		{"a Fee.payer", feeFieldsCosmosSignDoc(bridgeEncodeString(3, "cosmos1someoneelse"), nil, uatom)},
		{"a Fee.granter", feeFieldsCosmosSignDoc(bridgeEncodeString(4, "cosmos1granter"), nil, uatom)},
		{"an AuthInfo.tip", feeFieldsCosmosSignDoc(nil, tip, uatom)},
	} {
		t.Run(test.name, func(t *testing.T) {
			coordinator, semantic, _ := bridgeCoordinator(t)
			recorder, hardware := coordinator.audit.(*fakeAudit), coordinator.hardware.(*fakeHardware)
			_, err := coordinator.Execute(context.Background(), feeFieldsRequest(test.data, index))
			failure, ok := err.(*api.Failure)
			if !ok || failure.Status != 400 || failure.Code != "INVALID_ARGUMENT" {
				t.Fatalf("DEFECT: %s was not refused as malformed: err=%v, policy calls %d, token calls %d, audit %v",
					test.name, err, semantic.calls, hardware.calls, outcomes(recorder))
			}
			if semantic.calls != 0 || hardware.calls != 0 {
				t.Fatalf("DEFECT: %s reached policy (%d calls) or the token (%d calls)", test.name, semantic.calls, hardware.calls)
			}
			if got := outcomes(recorder); len(got) != 1 || got[0] != "policy-cosmos-malformed" {
				t.Fatalf("DEFECT: %s was audited as %v, want exactly [policy-cosmos-malformed]", test.name, got)
			}
		})
	}

	// THE CONTROL: no payer, granter or tip, and a fee the chain charges in two entries (1000 + 2500
	// uatom). Signed, audited success, and the fee handed to policy is both entries.
	coordinator, semantic, _ := bridgeCoordinator(t)
	recorder := coordinator.audit.(*fakeAudit)
	if _, err := coordinator.Execute(context.Background(), feeFieldsRequest(feeFieldsCosmosSignDoc(nil, nil, uatom, [2]string{"uatom", "2500"}), 9)); err != nil {
		t.Fatalf("the clean SignDoc was not signed (%v, audit %v): the refusals above prove nothing", err, outcomes(recorder))
	}
	if got := outcomes(recorder); len(got) == 0 || got[len(got)-1] != "success" {
		t.Fatalf("the clean SignDoc was audited as %v, want the last outcome to be success", got)
	}
	fee := semantic.lastRequest.Cosmos.Fee
	want := []policy.Coin{{Denom: "uatom", Amount: 1000}, {Denom: "uatom", Amount: 2500}}
	if len(fee) != len(want) || fee[0] != want[0] || fee[1] != want[1] {
		t.Fatalf("DEFECT: policy judged the fee %#v; the chain charges %#v", fee, want)
	}
}
