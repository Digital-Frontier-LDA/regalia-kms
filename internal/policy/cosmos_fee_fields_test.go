package policy

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
)

// WHO PAYS, AND HOW MUCH, IS WHAT THE FEE CAP APPROVED (regalia-kms-bim).
//
// parseFee accepted Fee fields 3 and 4 and dropped their values, so the policy judged a fee
// without knowing who paid it. The fields, from cosmos-sdk proto/cosmos/tx/v1beta1/tx.proto:
//
//	message AuthInfo { repeated SignerInfo signer_infos = 1; Fee fee = 2; Tip tip = 3; }
//	message Fee      { repeated Coin amount = 1; uint64 gas_limit = 2; string payer = 3; string granter = 4; }
//	message Tip      { repeated Coin amount = 1; string tipper = 2; }   // v0.46, deprecated since
//
// The spec scenarios below call Fee field 3 "tip" and field 4 "fee payer"; the proto says payer
// and granter, and the tip is AuthInfo field 3. The scenarios' claim -- Fee field 3 and 4 are
// refused before policy, in any form -- is what these tests hold, under the proto's names.
//
// Every SignDoc here goes through the same two steps the coordinator runs, ParseCosmosSignDoc and
// then Evaluate, so "refused" means the pair never admits it, wherever the refusal happens.

// feeFieldsCoin is a cosmos.base.v1beta1.Coin with its decimal-string amount.
func feeFieldsCoin(denom string, amount uint64) []byte {
	return append(encodeString(1, denom), encodeString(2, strconv.FormatUint(amount, 10))...)
}

// feeFieldsFee is a Fee carrying the given amount coins, gas 200000, and then `extra` verbatim.
func feeFieldsFee(coins [][]byte, extra []byte) []byte {
	var fee []byte
	for _, coin := range coins {
		fee = append(fee, encodeLengthDelimited(1, coin)...)
	}
	fee = append(fee, encodeTopVarint(2, 200_000)...)
	return append(fee, extra...)
}

// feeFieldsTip is an AuthInfo.tip: Tip{amount = [coin], tipper}.
func feeFieldsTip(denom string, amount uint64, tipper string) []byte {
	return append(encodeLengthDelimited(1, feeFieldsCoin(denom, amount)), encodeString(2, tipper)...)
}

// feeFieldsSignDoc is the canonical MsgSend SignDoc (900000 uatom, cosmos1source to cosmos1dest,
// sequence 7) around the given Fee and, when tip is non-nil, an AuthInfo.tip.
func feeFieldsSignDoc(fee, tip []byte) []byte {
	modeInfo := encodeLengthDelimited(1, encodeTopVarint(1, 1))
	signer := append(encodeLengthDelimited(2, modeInfo), encodeTopVarint(3, 7)...)
	auth := append(encodeLengthDelimited(1, signer), encodeLengthDelimited(2, fee)...)
	if tip != nil {
		auth = append(auth, encodeLengthDelimited(3, tip)...)
	}
	return signDocWithAuth(auth)
}

// feeFieldsPolicy admits the canonical MsgSend with a uatom fee up to maxFee. uakt is a second
// fully-capped denomination, fee cap included, so a refusal of a uakt tip below can only be the
// tip's refusal and never "unknown denomination".
func feeFieldsPolicy(maxFee uint64) Policy {
	configured := basePolicy()
	configured.Cosmos.Destinations = []string{"cosmos1dest"}
	configured.Cosmos.MaxFee = map[string]uint64{"uatom": maxFee, "uakt": 10_000}
	configured.Cosmos.MaxPerTransaction = map[string]uint64{"uatom": 1_000_000, "uakt": 1_000_000}
	configured.Cosmos.MaxPerDay = map[string]uint64{"uatom": 5_000_000, "uakt": 5_000_000}
	return configured
}

// feeFieldsPipeline parses signDoc and, if it parses, evaluates it under feeFieldsPolicy(maxFee).
// It returns the parsed transaction, the decision (zero when the parse refused), the reservations
// the state recorded, and the parse error.
func feeFieldsPipeline(t *testing.T, signDoc []byte, maxFee uint64) (*CosmosTransaction, Decision, []Reservation, error) {
	t.Helper()
	transaction, err := ParseCosmosSignDoc(signDoc)
	if err != nil {
		if transaction != nil || !errors.Is(err, ErrCosmosSignDoc) {
			t.Fatalf("a refusal must be an ErrCosmosSignDoc with no transaction: %#v, %v", transaction, err)
		}
		return nil, Decision{}, nil, err
	}
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := &reservationState{}
	engine, engineErr := New([]Policy{feeFieldsPolicy(maxFee)}, state, func() time.Time { return now })
	if engineErr != nil {
		t.Fatal(engineErr)
	}
	request := baseRequest(now)
	request.Cosmos = transaction
	return transaction, engine.Evaluate(context.Background(), request), state.reservations, nil
}

// feeFieldsAdmitted is true when the pipeline signed: the parse accepted and the policy allowed.
func feeFieldsAdmitted(parseErr error, decision Decision) bool {
	return parseErr == nil && decision.Allowed
}

var feeFieldsUatomFee = [][]byte{feeFieldsCoin("uatom", 1_000)}

// THE CONTROL every refusal below is measured against: the same SignDoc with no payer, granter or
// tip is admitted under the same policy, so each refusal is the extra field's and nothing else's.
func TestCosmosFeeFieldsControlIsAdmitted(t *testing.T) {
	_, decision, reservations, err := feeFieldsPipeline(t, feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, nil), nil), 10_000)
	if !feeFieldsAdmitted(err, decision) || len(reservations) != 1 {
		t.Fatalf("the clean SignDoc was not admitted (parse %v, decision %#v, reservations %d): every refusal in this file proves nothing",
			err, decision, len(reservations))
	}
}

// A TIP THAT TAKES THE TOTAL OVER MaxFee. The fee alone (1000) is under the cap (10000); fee plus
// tip (1000 + 9500) is over it. Evaluated on the fee alone, it was within policy.
func TestCosmosTipThatPushesFeeOverTheCapIsRefused(t *testing.T) {
	signDoc := feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, nil), feeFieldsTip("uatom", 9_500, "cosmos1source"))
	if _, decision, _, err := feeFieldsPipeline(t, signDoc, 10_000); feeFieldsAdmitted(err, decision) {
		t.Fatal("DEFECT: a 9500 uatom tip on a 1000 uatom fee was signed under a 10000 uatom fee cap: " +
			"the policy judged the fee without the tip")
	}
}

// A TIP IN ANOTHER DENOMINATION, small and from the signer. Even a parser that summed a tip into
// the fee per denomination would admit this one (uakt has its own cap, and 100 is under it); the
// signer did not approve a second payment in a second coin.
func TestCosmosTipInAForeignDenominationIsRefused(t *testing.T) {
	signDoc := feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, nil), feeFieldsTip("uakt", 100, "cosmos1source"))
	if _, decision, _, err := feeFieldsPipeline(t, signDoc, 10_000); feeFieldsAdmitted(err, decision) {
		t.Fatal("DEFECT: a uakt tip on a uatom fee was signed")
	}
}

// A TIP WHOSE TIPPER IS NOT THE SIGNER, small, in the fee's denomination, under the cap even
// summed. Who pays is not the signer, which is not what was approved.
func TestCosmosTipFromAnotherTipperIsRefused(t *testing.T) {
	signDoc := feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, nil), feeFieldsTip("uatom", 100, "cosmos1someoneelse"))
	if _, decision, _, err := feeFieldsPipeline(t, signDoc, 10_000); feeFieldsAdmitted(err, decision) {
		t.Fatal("DEFECT: a tip from another account was signed")
	}
}

// ANY TIP IS REFUSED, BY NAME, IN THE PARSER: even one in the fee's denomination, from the signer,
// that fits under the cap summed. The design is refuse-outright (cosmos.go parseAuthInfo), and the
// error names the field so an operator reading the refusal is sent to the tip and not to "field 3".
func TestParseAuthInfoRefusesAnyTipByName(t *testing.T) {
	signDoc := feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, nil), feeFieldsTip("uatom", 1, "cosmos1source"))
	_, decision, _, err := feeFieldsPipeline(t, signDoc, 10_000)
	if err == nil {
		t.Fatalf("DEFECT: a SignDoc with an AuthInfo.tip parsed (decision %#v); it must be refused before policy", decision)
	}
	if !strings.Contains(err.Error(), "AuthInfo.tip not allowed") {
		t.Fatalf("a tip was refused as %q; the refusal must name AuthInfo.tip", err)
	}
}

// spec: cosmos-authinfo-parser/tip-field-present
//
// Fee field 3 is Fee.payer in the proto; the scenario calls it the tip. Refused before policy,
// whether it names another account or is present and empty.
func TestParseFeeRefusesPayerInAnyForm(t *testing.T) {
	for name, payer := range map[string]string{"another account": "cosmos1someoneelse", "the signer": "cosmos1source", "present and empty": ""} {
		t.Run(name, func(t *testing.T) {
			signDoc := feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, encodeString(3, payer)), nil)
			_, decision, reservations, err := feeFieldsPipeline(t, signDoc, 10_000)
			if err == nil {
				t.Fatalf("DEFECT: a Fee.payer of %q parsed and reached policy (decision %#v, reservations %d)", payer, decision, len(reservations))
			}
			if !strings.Contains(err.Error(), "Fee.payer not allowed") {
				t.Fatalf("a Fee.payer was refused as %q; the refusal must name Fee.payer", err)
			}
		})
	}
}

// spec: cosmos-authinfo-parser/fee-payer-field-present
//
// Fee field 4 is Fee.granter in the proto; the scenario calls it the fee payer. A granter makes
// another account's x/feegrant allowance pay. Refused before policy, in any form.
func TestParseFeeRefusesGranterInAnyForm(t *testing.T) {
	for name, granter := range map[string]string{"another account": "cosmos1granter", "present and empty": ""} {
		t.Run(name, func(t *testing.T) {
			signDoc := feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, encodeString(4, granter)), nil)
			_, decision, reservations, err := feeFieldsPipeline(t, signDoc, 10_000)
			if err == nil {
				t.Fatalf("DEFECT: a Fee.granter of %q parsed and reached policy (decision %#v, reservations %d)", granter, decision, len(reservations))
			}
			if !strings.Contains(err.Error(), "Fee.granter not allowed") {
				t.Fatalf("a Fee.granter was refused as %q; the refusal must name Fee.granter", err)
			}
		})
	}
}

// Fee field 3 or 4 on a varint wire (not what any encoder writes for a string) is still refused:
// the wire check used to be the arm's only refusal, and removing the arm must not open it.
func TestParseFeeRefusesPayerAndGranterOnAnyWire(t *testing.T) {
	for _, tag := range []uint64{3, 4} {
		signDoc := feeFieldsSignDoc(feeFieldsFee(feeFieldsUatomFee, encodeTopVarint(tag, 1)), nil)
		if _, decision, _, err := feeFieldsPipeline(t, signDoc, 10_000); feeFieldsAdmitted(err, decision) {
			t.Fatalf("DEFECT: Fee field %d on wire 0 was signed", tag)
		}
	}
}

// THE FEE POLICY JUDGES IS THE FEE THE CHAIN CHARGES. Two same-denomination amount entries (the
// chain charges their sum, 3500) on a document with no payer, granter or tip, which is now the only
// fee shape that parses: the parsed fee carries both entries, a cap of exactly the sum admits it
// and reserves, and a cap one below refuses it under cosmos-fee. A parser that kept less of the fee
// than the chain charges admits the second.
func TestCosmosFeeThePolicyJudgesIsTheFeeTheChainCharges(t *testing.T) {
	coins := [][]byte{feeFieldsCoin("uatom", 1_000), feeFieldsCoin("uatom", 2_500)}
	signDoc := feeFieldsSignDoc(feeFieldsFee(coins, nil), nil)

	transaction, decision, reservations, err := feeFieldsPipeline(t, signDoc, 3_500)
	if !feeFieldsAdmitted(err, decision) || len(reservations) != 1 {
		t.Fatalf("a 3500 uatom fee under a 3500 cap was not admitted (parse %v, decision %#v, reservations %d)", err, decision, len(reservations))
	}
	var charged uint64
	for _, coin := range transaction.Fee {
		if coin.Denom != "uatom" {
			t.Fatalf("parsed fee %#v carries a denomination the wire did not", transaction.Fee)
		}
		charged += coin.Amount
	}
	if len(transaction.Fee) != 2 || charged != 3_500 {
		t.Fatalf("DEFECT: the parsed fee is %#v (%d uatom); the chain charges 3500 uatom in two entries", transaction.Fee, charged)
	}

	_, decision, reservations, err = feeFieldsPipeline(t, signDoc, 3_499)
	if feeFieldsAdmitted(err, decision) || decision.Rule != RuleCosmosFee || len(reservations) != 0 {
		t.Fatalf("DEFECT: a 3500 uatom fee under a 3499 cap gave parse %v, decision %#v, reservations %d; want a cosmos-fee denial and nothing reserved",
			err, decision, len(reservations))
	}
}
