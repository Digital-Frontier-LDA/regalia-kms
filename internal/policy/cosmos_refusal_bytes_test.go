package policy

import (
	"errors"
	"strings"
	"testing"
)

// These tests send the exact bytes the parser's refusals are written for. They were
// missing before the spectrace join key existed: the spec scenarios
// (fee-payer-field-present, repeated-amount-entries-for-one-denomination) described
// behavior the parser implemented, but no test exercised it, so the join key reported
// them as orphans. Each test below closes one by driving the path with its bytes.
//
// Two siblings are NOT here: tip-field-present and unsupported-sign-mode-is-refused
// (the direct_secp256r1 arm). Their byte-level tests fail on this tree, because the
// parser here accepts a Fee tip (field 3) and ModeInfo arm 3. The refusals they need are
// pending work, not in this change, so those scenarios stay unclaimed rather than
// claimed by a failing test.

// feeWith builds an AuthInfo whose Fee carries the given extra fee fields
// (each a raw encoded field at the Fee level) in addition to a valid amount and
// gas limit, so the SignDoc is complete except for the offending field.
func feeWith(t *testing.T, extraFields ...[]byte) []byte {
	t.Helper()
	// A valid Fee: amount (Coin uatom/1000) + gas_limit (200000).
	coin := append(encodeString(1, "uatom"), encodeString(2, "1000")...)
	fee := append(encodeLengthDelimited(1, coin), encodeTopVarint(2, 200000)...)
	for _, extra := range extraFields {
		fee = append(fee, extra...)
	}
	modeInfo := encodeLengthDelimited(1, encodeTopVarint(1, 1))
	signer := append(encodeLengthDelimited(2, modeInfo), encodeTopVarint(3, 7)...)
	return append(encodeLengthDelimited(1, signer), encodeLengthDelimited(2, fee)...)
}

// signDocWithAuth builds a complete SignDoc around the given AuthInfo bytes.
func signDocWithAuth(auth []byte) []byte {
	var buf []byte
	buf = append(buf, encodeLengthDelimited(1, canonicalMsgSendTxBody())...)
	buf = append(buf, encodeLengthDelimited(2, auth)...)
	buf = append(buf, encodeString(3, "cosmoshub-4")...)
	buf = append(buf, encodeTopVarint(4, 42)...)
	return buf
}

// spec: cosmos-authinfo-parser/fee-payer-field-present
func TestParseFeeRefusesFeePayerField(t *testing.T) {
	// Fee field 4 (payer) is a varint account number.
	payer := encodeTopVarint(4, 5)
	_, err := ParseCosmosSignDoc(signDocWithAuth(feeWith(t, payer)))
	if err == nil {
		t.Fatal("expected a SignDoc carrying a Fee payer (field 4) to be refused")
	}
	if !errors.Is(err, ErrCosmosSignDoc) {
		t.Fatalf("error %v does not wrap ErrCosmosSignDoc", err)
	}
	if !strings.Contains(err.Error(), "Fee.field 4") {
		t.Fatalf("error %q does not name the refused fee field", err.Error())
	}
}

// spec: cosmos-authinfo-parser/repeated-amount-entries-for-one-denomination
func TestParseFeeSumsRepeatedAmountEntriesForOneDenomination(t *testing.T) {
	// Two Coin entries with the same denomination must be summed, not refused.
	// This is the carve-out the structural-invariants requirement calls out: a
	// repeated length-delimited Fee.amount is legitimate and summed.
	coinA := append(encodeString(1, "uatom"), encodeString(2, "1000")...)
	coinB := append(encodeString(1, "uatom"), encodeString(2, "2500")...)
	fee := []byte{}
	fee = append(fee, encodeLengthDelimited(1, coinA)...)
	fee = append(fee, encodeLengthDelimited(1, coinB)...) // same field number, repeated
	fee = append(fee, encodeTopVarint(2, 200000)...)
	modeInfo := encodeLengthDelimited(1, encodeTopVarint(1, 1))
	signer := append(encodeLengthDelimited(2, modeInfo), encodeTopVarint(3, 7)...)
	auth := append(encodeLengthDelimited(1, signer), encodeLengthDelimited(2, fee)...)

	got, err := ParseCosmosSignDoc(signDocWithAuth(auth))
	if err != nil {
		t.Fatalf("expected repeated same-denomination Fee.amount to be accepted, got: %v", err)
	}
	// The parser keeps the entries (the policy layer sums per denomination, per
	// the spec), so assert BOTH same-denom entries survived the walk — proving
	// the repeat was not refused — and that their amounts are the two values.
	var uatom []uint64
	for _, c := range got.Fee {
		if c.Denom == "uatom" {
			uatom = append(uatom, c.Amount)
		}
	}
	if len(uatom) != 2 || (uatom[0]+uatom[1]) != 3500 {
		t.Fatalf("parsed Fee uatom entries = %v, want two entries summing to 3500", uatom)
	}
}
