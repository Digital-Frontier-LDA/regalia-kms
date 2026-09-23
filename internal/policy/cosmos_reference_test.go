package policy

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readReferenceHex(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reference fixture %s is missing: %v", name, err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("reference fixture %s is not hexadecimal: %v", name, err)
	}
	return decoded
}

func TestParseSignDocAcceptsGeneratedCosmosSDKFixture(t *testing.T) {
	raw := readReferenceHex(t, "signdoc-akashnet2-msgsend.hex")
	got, err := ParseCosmosSignDoc(raw)
	if err != nil {
		t.Fatalf("DEFECT: a complete SignDoc produced by generated Cosmos protobuf bindings was refused: %v", err)
	}
	if got.ChainID != "akashnet-2" || got.AccountNumber != 42 || got.Sequence != 7 || got.GasLimit != 200000 {
		t.Fatalf("parsed SignDoc identity = chain %q account %d sequence %d gas %d, want akashnet-2/42/7/200000", got.ChainID, got.AccountNumber, got.Sequence, got.GasLimit)
	}
	if len(got.Fee) != 1 || got.Fee[0].Denom != "uakt" || got.Fee[0].Amount != 1000 {
		t.Fatalf("parsed SignDoc fee = %#v, want one uakt fee of 1000", got.Fee)
	}
	if len(got.Messages) != 1 || got.Messages[0].Type != "/cosmos.bank.v1beta1.MsgSend" {
		t.Fatalf("parsed SignDoc messages = %#v, want one generated MsgSend", got.Messages)
	}
	if got.Messages[0].Source != "akash1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" {
		t.Fatalf("parsed MsgSend source = %q, want generated source address", got.Messages[0].Source)
	}
}

func TestParseSignDocAcceptsGeneratedMsgDelegateFixture(t *testing.T) {
	raw := readReferenceHex(t, "signdoc-akashnet2-msgdelegate.hex")
	got, err := ParseCosmosSignDoc(raw)
	if err != nil {
		t.Fatalf("DEFECT: generated MsgDelegate SignDoc was refused: %v", err)
	}
	if len(got.Messages) != 1 || got.Messages[0].Type != "/cosmos.staking.v1beta1.MsgDelegate" {
		t.Fatalf("messages = %#v, want one MsgDelegate", got.Messages)
	}
	message := got.Messages[0]
	wantValidator := "akashvaloper1" + strings.Repeat("v", 41)
	if message.Source != "akash1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" ||
		message.Destination != wantValidator ||
		len(message.Amounts) != 1 || message.Amounts[0].Denom != "uakt" || message.Amounts[0].Amount != 1_000_000 {
		t.Fatalf("MsgDelegate = %#v, want generated delegator, validator, and amount", message)
	}
}

func TestDecodeMsgDelegateRejectsDuplicateAndMissingFields(t *testing.T) {
	coin := append(encodeString(1, "uakt"), encodeString(2, "1")...)
	valid := append(encodeString(1, "akash1source"), encodeString(2, "akashvaloper1validator")...)
	valid = append(valid, encodeLengthDelimited(3, coin)...)

	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "duplicate delegator",
			input: append(append([]byte(nil), valid...), encodeString(1, "akash1other")...),
			want:  "delegator_address appears twice",
		},
		{
			name:  "missing validator",
			input: append(encodeString(1, "akash1source"), encodeLengthDelimited(3, coin)...),
			want:  "missing delegator, validator or amount",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := decodeMsgDelegate(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("DEFECT: malformed MsgDelegate was not refused by its own guard: err=%v, want %q", err, tc.want)
			}
		})
	}
}

// THE DOC COMMENT CLAIMED cosmos-sdk v1beta1 CONFORMANCE AND NOTHING CHECKED IT.
//
// decodeCoin required a varint for Coin.amount, so it refused every genuine MsgSend. The suite was
// green because the only thing exercising the claim was encodeMsgSend in this package's own tests,
// which encodes the amount as a varint too: the fixture and the decoder shared one assumption and
// agreed with each other about a wire format neither matched. Two halves wrong together.
//
// A second hand-written encoder would have been the same assumption a third time. testdata holds
// bytes produced by the GENERATED upstream bindings, which is the only artifact that turns the
// claim into something this test can fail on.
//
// Settled from the generated descriptor:
//
//	cosmos.base.v1beta1.Coin
//	  field 1 denom  -> TYPE_STRING (wire 2)
//	  field 2 amount -> TYPE_STRING (wire 2)
func TestDecodeMsgSendAcceptsBytesTheUpstreamEncoderProduced(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "msgsend-uakt-1000000.bin"))
	if err != nil {
		t.Fatalf("the reference fixture is missing (%v): without it this package only checks its "+
			"own encoder against its own decoder, which is the state that hid the defect", err)
	}
	if len(raw) != 109 {
		t.Fatalf("the fixture is %d bytes, not the recorded 109: it was regenerated with different "+
			"inputs, and the expectations below describe the old ones", len(raw))
	}

	_, destination, amounts, err := decodeMsgSend(raw)
	if err != nil {
		t.Fatalf("DEFECT: a MsgSend produced by the upstream cosmos encoder was refused: %v", err)
	}
	if destination != "akash1vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" {
		t.Fatalf("to_address = %q", destination)
	}
	if len(amounts) != 1 || amounts[0].Denom != "uakt" || amounts[0].Amount != 1_000_000 {
		t.Fatalf("amounts = %#v, want one uakt coin of 1000000", amounts)
	}
}

// A VARINT AMOUNT IS THE OLD ASSUMPTION AND MUST NOW BE REFUSED.
//
// The control for the test above: without it, a decoder that accepted both framings would pass
// there and still be wrong, and the package's own encoder would keep producing documents no
// cosmos node emits.
func TestCoinAmountEncodedAsAVarintIsRefused(t *testing.T) {
	// Coin{denom: "uakt", amount: <varint 1000000>} — field 2 with wire type 0.
	varintCoin := []byte{0x0a, 0x04, 'u', 'a', 'k', 't', 0x10, 0xc0, 0x84, 0x3d}
	_, _, err := decodeCoin(varintCoin)
	if err == nil {
		t.Fatal("DEFECT: a Coin whose amount is a varint was accepted — that is the framing this " +
			"decoder used to require and no cosmos encoder produces")
	}
	if !strings.Contains(err.Error(), "wire 0 not allowed") {
		t.Fatalf("the refusal does not name the wire type: %v", err)
	}
}

func TestCoinAmountStringsAreCheckedForWhatTheyAre(t *testing.T) {
	// The control first: a plain amount must decode, or every refusal below is satisfied by a
	// function that refuses everything.
	if amount, err := decodeCoinAmount("1000000"); err != nil || amount != 1_000_000 {
		t.Fatalf("a valid amount was refused (%v, %d): the cases below would prove nothing", err, amount)
	}

	for _, refused := range []struct{ text, because string }{
		{"", "an empty amount is not zero, it is a field somebody started and did not finish"},
		{"-1", "Cosmos Int is non-negative; a sign is a document no encoder produces"},
		{"1.5", "amounts are integers in base units; a decimal point means the units are wrong"},
		{"1e6", "an exponent is a spelling no encoder emits and a value a reader may disagree about"},
		{"01", "two spellings of one value hash differently and mean the same thing"},
		{" 1", "surrounding whitespace is not part of the number"},
		{"18446744073709551616", "2^64 — larger than any uint64 cap can express, so the cap refuses it"},
	} {
		t.Run(refused.text, func(t *testing.T) {
			if _, err := decodeCoinAmount(refused.text); err == nil {
				t.Fatalf("DEFECT: %q was accepted — %s", refused.text, refused.because)
			}
		})
	}

	// THE TWO REFUSALS MUST NOT ARRIVE AS THE SAME KIND OF SENTENCE. "not a number" and "larger
	// than any cap can express" send an operator to different places: one is a malformed document,
	// the other is the cap doing its job on a well-formed one.
	//
	// Comparing the two messages for equality CANNOT FAIL, and this assertion did exactly that
	// until falsification caught it: both embed the offending text, so `banana` and
	// `18446744073709551616` produce different strings however wrongly they are classified. The
	// digit check is redundant with ParseUint for accept/reject — everything it catches ParseUint
	// also refuses — so its whole value is which of these two sentences you get, and an assertion
	// that cannot distinguish them leaves the guard unpinned.
	_, malformed := decodeCoinAmount("banana")
	_, oversized := decodeCoinAmount("18446744073709551616")
	if strings.Contains(malformed.Error(), "cap") {
		t.Fatalf("DEFECT: a malformed amount is reported as exceeding the cap (%v) — that sends an "+
			"operator to raise a limit for a document that is not a number", malformed)
	}
	if !strings.Contains(oversized.Error(), "cap") {
		t.Fatalf("DEFECT: an amount beyond every expressible cap is reported as malformed (%v) — "+
			"that sends an operator to inspect an encoder that produced a valid integer", oversized)
	}
}

// A REPEATED AMOUNT IS DIAGNOSED AS REPEATED, WHATEVER THE SECOND COPY CONTAINS.
//
// #198 added the duplicate refusal and #199 changed the parse; rebasing one onto the other left the
// duplicate check AFTER the parse, and git merged that without a conflict. A Coin carrying a valid
// amount followed by a malformed one then reported "not a decimal integer" — true of the second
// copy, and the wrong description of the document, which is a repeated field.
//
// Both orderings refuse, so nothing in either test suite noticed: the only observable difference is
// which sentence an operator reads, and that is the whole value of having two sentences.
func TestARepeatedAmountIsReportedAsRepeatedEvenWhenTheSecondCopyIsMalformed(t *testing.T) {
	uakt := append([]byte{0x0a, 0x04}, []byte("uakt")...)
	amount := func(text string) []byte { return encodeString(2, text) }
	coin := append(append(append([]byte{}, uakt...), amount("1000000")...), amount("banana")...)

	_, _, err := decodeCoin(coin)
	if err == nil {
		t.Fatal("a Coin with two amounts was accepted")
	}
	if !strings.Contains(err.Error(), "appears twice") {
		t.Fatalf("DEFECT: a repeated amount was reported as %v. The document's defect is that the "+
			"field repeats; the second copy being malformed is a consequence, and naming it sends "+
			"an operator to inspect an encoder rather than to reject a non-canonical document", err)
	}
}

// AN AMOUNT CONTAINING INVALID UTF-8 IS REFUSED, AND THE MESSAGE SHOWS THE BYTES THAT ARRIVED.
//
// THIS DOES NOT DISTINGUISH BYTE ITERATION FROM RUNE ITERATION, and saying so is the point.
// decodeCoinAmount indexes bytes because a protobuf string is raw bytes on the wire; review asked
// for that and it is right in principle. It is also, measured, unobservable here: ranging over
// runes yields U+FFFD for an invalid byte, which is outside '0'..'9' and refused just the same, and
// the message formats the ORIGINAL string with %q either way — so the quoted text is accurate under
// both. Restoring the rune loop leaves this test green.
//
// Recorded rather than dressed up. A test named for a distinction it cannot make would be worse
// than none: the next reader would take the byte indexing as load-bearing and defended, and it is
// only the first. What this pins is the behaviour a reader depends on — refusal, and a message they
// can match against a hex dump of the document.
func TestAnInvalidUTF8AmountIsRefusedAndShownRaw(t *testing.T) {
	_, err := decodeCoinAmount("10\x80")
	if err == nil {
		t.Fatal("invalid UTF-8 in an amount was accepted")
	}
	if strings.ContainsRune(err.Error(), '\uFFFD') {
		t.Fatalf("DEFECT: the refusal quotes a U+FFFD replacement rather than the byte that "+
			"arrived (%v) — an operator matching this against the document would not find it", err)
	}
	if !strings.Contains(err.Error(), `\x80`) {
		t.Fatalf("the refusal does not show the offending byte: %v", err)
	}
}

// A LENGTH ABOVE 127 IS ITSELF A VARINT, and no other fixture here is long enough to notice.
//
// coinBytes hand-rolled its lengths as a single byte, which is correct only under 128 and silently
// malformed above it — while its comment claimed it matched the upstream encoder. Nothing was long
// enough to catch that, which is precisely why it would have surfaced later, in whichever fixture
// first crossed the boundary, as an unexplained decode failure.
func TestACoinWithALongFieldIsStillFramedCorrectly(t *testing.T) {
	long := strings.Repeat("d", 200)
	denom, amount, err := decodeCoin(coinBytes(long, "1000000"))
	if err != nil {
		t.Fatalf("DEFECT: a Coin whose denom exceeds 127 bytes did not decode (%v) — its length "+
			"needs a two-byte varint and was written as one byte", err)
	}
	if denom != long || amount != 1_000_000 {
		t.Fatalf("decoded denom of %d bytes and amount %d", len(denom), amount)
	}
}

// PROTO3 DOES NOT ENCODE A ZERO SCALAR. An account's first transaction has sequence 0, and a genesis
// account can have account_number 0, so a genuine SignDoc for either carries NO such field at all —
// and the chain, which rebuilds the SignDoc from its own state, reads the absence as 0. The parser
// required both to be present, so the KMS refused to sign the first transaction of every account it
// would ever hold. Found by e2e/cosmos-simapp-kms-tx.sh against a live simd node (regalia#439): the
// first cosmpy SignDoc it built was refused. The fixture is cosmpy-generated, like its siblings.
func TestParseSignDocAcceptsAccountZeroAndSequenceZero(t *testing.T) {
	raw := readReferenceHex(t, "signdoc-akashnet2-msgsend-account0-sequence0.hex")
	got, err := ParseCosmosSignDoc(raw)
	if err != nil {
		t.Fatalf("DEFECT: a generated SignDoc for account 0 at sequence 0 was refused: %v", err)
	}
	if got.ChainID != "akashnet-2" || got.AccountNumber != 0 || got.Sequence != 0 || got.GasLimit != 200000 {
		t.Fatalf("parsed = chain %q account %d sequence %d gas %d, want akashnet-2/0/0/200000", got.ChainID, got.AccountNumber, got.Sequence, got.GasLimit)
	}
	if len(got.Messages) != 1 || got.Messages[0].Destination != "akash1vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" {
		t.Fatalf("messages = %#v", got.Messages)
	}
}
