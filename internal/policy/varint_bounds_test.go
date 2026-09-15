package policy

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// A VARINT THAT DOES NOT FIT MUST BE REFUSED, NOT TRUNCATED.
//
// The decoder's output is compared against a spend cap. Silently dropping the bits that do not fit
// means the policy authorises a small number for bytes that a decoder handling them correctly reads
// as an enormous one — and there is no correct value to report, because the bytes do not fit the
// type. Measured before the guard existed:
//
//	2^64 + 5 -> 5, no error
//	2^64     -> 0, no error
//
// The eleven-byte case was already refused; the tenth byte was not, and it is the one an encoder
// actually produces for a value just past the range.
func TestAVarintTooLargeForItsTypeIsRefusedRatherThanTruncated(t *testing.T) {
	for _, oversized := range []struct {
		what  string
		bytes []byte
	}{
		// Built by hand because encodeVarint cannot represent them: that is the point.
		{"2^64", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}},
		{"2^64 + 5", []byte{0x85, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}},
		{"tenth byte fully set", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f}},
		{"eleven bytes", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}},
	} {
		t.Run(oversized.what, func(t *testing.T) {
			value, _, err := decodeVarint(oversized.bytes)
			if err == nil {
				t.Fatalf("decoded %s as %d instead of refusing it: the bytes do not fit a uint64, so "+
					"any value reported here disagrees with a decoder that handles them", oversized.what, value)
			}
			if !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("error %v does not wrap ErrCosmosSignDoc, so callers cannot classify it", err)
			}
		})
	}
}

// THE CONTROL, AND IT IS NOT DECORATION. A guard on the tenth byte is one comparison away from
// rejecting the largest legal value, whose tenth byte is 0x01 — and a decoder that refuses
// MaxUint64 fails closed, so nothing else in the suite would notice.
func TestTheLargestRepresentableVarintStillDecodes(t *testing.T) {
	for _, legal := range []uint64{0, 1, 127, 128, math.MaxUint32, math.MaxUint64 - 1, math.MaxUint64} {
		encoded := encodeVarint(legal)
		value, consumed, err := decodeVarint(encoded)
		if err != nil {
			t.Fatalf("decodeVarint(%d) = error %v, want the value back", legal, err)
		}
		if value != legal {
			t.Fatalf("decodeVarint(%d) = %d", legal, value)
		}
		if consumed != len(encoded) {
			t.Fatalf("decodeVarint(%d) consumed %d of %d bytes", legal, consumed, len(encoded))
		}
	}
}

// A refusal deep inside a message must surface as a refusal of the message, not as a coin the
// policy then reasons about. This is the path that matters: an amount that does not fit reaches a
// spend cap.
//
// REWRITTEN FOR THE STRING FRAMING (#199), AND THE PREMISE CHANGED WITH IT. Coin.amount is a
// decimal string, not a varint, so an oversized amount is no longer decodeVarint's overflow guard
// firing — it is decodeCoinAmount refusing a value larger than any uint64 cap can express. The
// guard #198 added is not dead: it still protects account_number and every other varint field. It
// is simply no longer on this path, and a test that kept encoding a varint here would have been
// asserting against a framing no cosmos encoder produces.
func TestAnOversizedCoinAmountIsRefusedByTheDecoder(t *testing.T) {
	// 2^64, one past the largest expressible cap, as the wire actually carries it.
	oversized := coinBytes("uakt", "18446744073709551616")
	if _, _, err := decodeCoin(oversized); err == nil {
		t.Fatal("a Coin whose amount does not fit a uint64 was accepted; the policy would cap a truncated value")
	}
	// The control: the same Coin with an amount that does fit must still decode, or the case above
	// is satisfied by decodeCoin refusing everything.
	denom, amount, err := decodeCoin(coinBytes("uakt", "1234"))
	if err != nil || denom != "uakt" || amount != 1234 {
		t.Fatalf("decodeCoin(sound) = %q/%d/%v, want uakt/1234/nil", denom, amount, err)
	}
}

// coinBytes builds a cosmos.base.v1beta1.Coin the way the upstream encoder does: both fields
// length-delimited. Shared by the tests that were written against the varint framing.
//
// It writes lengths through encodeString rather than as a single byte. The hand-rolled version was
// correct only for values under 128 bytes -- above that, a protobuf length is itself a varint, so it
// would have produced malformed bytes while the comment claimed it matched the upstream encoder. No
// current fixture is that long, which is exactly why it would have gone unnoticed until one was.
func coinBytes(denom, amount string) []byte {
	return append(encodeString(1, denom), encodeString(2, amount)...)
}

// THE TWO REFUSALS MEAN DIFFERENT THINGS AND MUST KEEP SAYING SO.
//
// Only the payload bits of the tenth byte can overflow, so only they are checked. Testing the whole
// byte would classify a tenth byte of 0x80 — a continuation bit over a payload of zero, which fits
// — as "exceeds 64 bits", when what is actually wrong with that input is that it ends mid-varint.
// The refusal is right either way; the diagnosis is not, and an operator reading "exceeds 64 bits"
// for a truncated buffer goes looking for a number that was never there.
func TestTheOverflowAndTruncationRefusalsAreNotConfused(t *testing.T) {
	truncated := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}
	_, _, err := decodeVarint(truncated)
	if err == nil {
		t.Fatal("a buffer ending mid-varint was accepted")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("a truncated varint was reported as %q, want the truncation refusal", err)
	}

	overflowing := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}
	_, _, err = decodeVarint(overflowing)
	if err == nil {
		t.Fatal("a varint above uint64 was accepted")
	}
	if !strings.Contains(err.Error(), "exceeds 64 bits") {
		t.Fatalf("an oversized varint was reported as %q, want the overflow refusal", err)
	}
}
