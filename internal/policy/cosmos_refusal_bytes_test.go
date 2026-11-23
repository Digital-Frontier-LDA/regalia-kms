package policy

import (
	"testing"
)

// This test sends the exact bytes the parser's fee summing is written for. It was missing
// before the spectrace join key existed: repeated-amount-entries-for-one-denomination described
// behavior the parser implemented, but no test exercised it, so the join key reported it as an
// orphan.
//
// Three siblings are NOT here: tip-field-present, unsupported-sign-mode-is-refused (the
// direct_secp256r1 arm) and fee-payer-field-present. On this tree the parser accepts ModeInfo
// arm 3 and a length-delimited Fee field 3 or 4 (cosmos-sdk tx.proto: Fee.payer = 3,
// Fee.granter = 4), so a test that claimed those refusals would either fail or pass only on a
// malformed-wire fixture. Those
// refusals are pending work, and the scenarios stay unclaimed rather than claimed by a test
// that does not exercise them.

// signDocWithAuth builds a complete SignDoc around the given AuthInfo bytes.
func signDocWithAuth(auth []byte) []byte {
	var buf []byte
	buf = append(buf, encodeLengthDelimited(1, canonicalMsgSendTxBody())...)
	buf = append(buf, encodeLengthDelimited(2, auth)...)
	buf = append(buf, encodeString(3, "cosmoshub-4")...)
	buf = append(buf, encodeTopVarint(4, 42)...)
	return buf
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
