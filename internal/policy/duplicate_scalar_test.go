package policy

import (
	"errors"
	"strings"
	"testing"
)

// A REPEATED SCALAR IS REFUSED, NOT RESOLVED.
//
// These were last-wins in silence. Measured before the guards:
//
//	amount 999999 then amount 1 -> 1
//	amount 1 then amount 999999 -> 999999
//	denom "uakt" then "uusd"    -> "uusd"
//
// The middle one is the shape that matters: the policy compares the decoded amount against a spend
// cap and writes it into the audit record, so a transaction carrying a large amount followed by a
// small one is authorised, capped and recorded as the small one. Proto3 says last wins for scalars,
// so a conforming decoder would agree — but agreeing with one implementation's tolerance of
// non-canonical input is a weaker guarantee than refusing it, and every other party that reads
// these bytes (the chain, a relayer, an approver's display) has to make the same choice for the
// agreement to hold. Nothing canonical emits a repeated scalar, so refusing costs nothing.
func TestARepeatedScalarIsRefusedRatherThanResolved(t *testing.T) {
	// Amounts are LENGTH-DELIMITED STRINGS (#199). Built as varints, every case below would be
	// refused by the wire-type check before the duplicate check was reached — green, and proving
	// nothing about duplication.
	uakt := append([]byte{0x0a, 0x04}, []byte("uakt")...)
	amount := func(text string) []byte { return encodeString(2, text) }
	for _, repeated := range []struct {
		what  string
		bytes []byte
	}{
		{"amount twice, large then small", concat(uakt, amount("999999"), amount("1"))},
		{"amount twice, small then large", concat(uakt, amount("1"), amount("999999"))},
		{"denom twice", concat(uakt, []byte{0x0a, 0x04}, []byte("uusd"), amount("1"))},
	} {
		t.Run(repeated.what, func(t *testing.T) {
			denom, amount, err := decodeCoin(repeated.bytes)
			if err == nil {
				t.Fatalf("decoded a Coin with %s as %q/%d instead of refusing it", repeated.what, denom, amount)
			}
			if !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("error %v does not wrap ErrCosmosSignDoc", err)
			}
		})
	}
}

// A REPEATED to_address IS THE SAME DEFECT ON THE FIELD THAT DECIDES WHERE THE MONEY GOES.
func TestARepeatedDestinationIsRefused(t *testing.T) {
	coin := encodeLengthDelimited(3, coinBytes("uakt", "1"))
	body := concat(
		[]byte{0x0a, 0x04}, []byte("from"),
		[]byte{0x12, 0x04}, []byte("dst1"),
		[]byte{0x12, 0x04}, []byte("dst2"),
		coin,
	)
	if _, _, _, err := decodeMsgSend(body); err == nil {
		t.Fatal("a MsgSend naming two destinations was accepted; the policy would authorise one of them")
	}
}

// THE CONTROL, AND IT IS NOT DECORATION. Coin is a genuinely REPEATED field of MsgSend, so a guard
// written one field too wide would refuse every multi-denomination send — and that refusal is
// fail-closed, which nothing else here would notice.
//
// ITS OWN FIXTURE WAS ONE COIN AWAY FROM STOPPING BEING A CONTROL. The lengths were hand-rolled as
// a single byte, correct only below 128, so the first Coin to exceed that would have produced
// malformed bytes and a refusal indistinguishable from the guard being too wide — in the test whose
// entire job is telling those two apart. It would have failed for the reason it exists to rule out.
// Now through encodeLengthDelimited, and TestAMultiCoinSendSurvivesACoinPast127Bytes below is the
// case that observes it.
func TestASingleScalarAndRepeatedCoinsStillDecode(t *testing.T) {
	one := coinBytes("uakt", "1")
	two := coinBytes("uusd", "2")
	body := concat(
		[]byte{0x0a, 0x04}, []byte("from"),
		[]byte{0x12, 0x04}, []byte("dst1"),
		encodeLengthDelimited(3, one),
		encodeLengthDelimited(3, two),
	)
	_, destination, amounts, err := decodeMsgSend(body)
	if err != nil {
		t.Fatalf("a MsgSend with two coins was refused: %v", err)
	}
	if destination != "dst1" || len(amounts) != 2 {
		t.Fatalf("destination=%q amounts=%v, want dst1 and two coins", destination, amounts)
	}
	if amounts[0].Denom != "uakt" || amounts[0].Amount != 1 || amounts[1].Denom != "uusd" || amounts[1].Amount != 2 {
		t.Fatalf("coins decoded as %v", amounts)
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// A MULTI-COIN SEND WITH ONE LONG COIN, which is the case the control above could not have carried.
//
// Above 127 bytes a protobuf length is a two-byte varint. With hand-rolled single-byte lengths this
// decodes as garbage or not at all, and the failure looks exactly like the over-wide guard the
// control exists to rule out — same symptom, opposite cause.
func TestAMultiCoinSendSurvivesACoinPast127Bytes(t *testing.T) {
	long := strings.Repeat("d", 200)
	body := concat(
		encodeString(1, "from"),
		encodeString(2, "dst1"),
		encodeLengthDelimited(3, coinBytes(long, "1")),
		encodeLengthDelimited(3, coinBytes("uusd", "2")),
	)
	_, destination, amounts, err := decodeMsgSend(body)
	if err != nil {
		t.Fatalf("DEFECT: a MsgSend whose first coin exceeds 127 bytes was refused (%v). If this is "+
			"a length written as one byte, the refusal is the fixture's and not the decoder's — and "+
			"it is indistinguishable from the over-wide guard the control above rules out", err)
	}
	if destination != "dst1" || len(amounts) != 2 {
		t.Fatalf("destination=%q amounts=%v", destination, amounts)
	}
	if amounts[0].Denom != long || amounts[1].Denom != "uusd" {
		t.Fatalf("coins decoded as %d-byte denom and %q", len(amounts[0].Denom), amounts[1].Denom)
	}
}
