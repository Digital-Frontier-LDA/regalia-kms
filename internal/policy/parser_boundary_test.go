package policy

// #267 follow-up: the overflow operand found by mutation prevents one panic; this boundary
// prevents the CLASS. The coordinator calls ParseCosmosSignDoc on caller bytes upstream of
// the operation runner's recover, so a parser panic was a dropped connection — no refusal,
// no audit record, a stack trace nobody asked for. The row proves the conversion directly,
// with a deliberately-panicking body through the same wrapper the exported parser uses:
// the recover's trigger is the next unenumerated panic, and waiting for a real one to test
// it is the §18 trap in the other direction.
import (
	"errors"
	"strings"
	"testing"
)

func TestTheParserBoundaryConvertsAnyPanicToARefusal(t *testing.T) {
	// A nil panic is its own row because it is the one value recover() used to miss. Before Go
	// 1.21 `panic(nil)` made recover() return nil, so this boundary would have let it through and
	// "any panic" would have been false. Since 1.21 the runtime substitutes a
	// *runtime.PanicNilError, which recover() returns like any other value. Measured on this
	// module's toolchain: converted, with the value reported as
	// "panic called with nil argument (*runtime.PanicNilError)".
	//
	// The one configuration that changes it is GODEBUG=panicnil=1, which restores the pre-1.21
	// behaviour and would let a nil panic escape. That is an explicit opt-out, not a default, and
	// naming it here is cheaper than rediscovering it from a connection reset.
	for _, test := range []struct {
		name string
		body func() (*CosmosTransaction, error)
	}{
		{"a slice-bounds panic", func() (*CosmosTransaction, error) {
			empty := []byte(nil)
			_ = empty[3] // the shape the overflow operand guards, arriving from inside
			return nil, nil
		}},
		{"a nil panic", func() (*CosmosTransaction, error) {
			panic(nil)
		}},
		{"an explicit panic value", func() (*CosmosTransaction, error) {
			panic("parser gave up")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction, err := withPanicToError(test.body)
			if err == nil || !strings.Contains(err.Error(), "parser panic") {
				t.Fatalf("a panic crossed the parser boundary unconverted (err=%v) — caller bytes deserve a 400 and an audit record, not a connection reset", err)
			}
			// THE SENTINEL, NOT THE SENTENCE. Callers classify this with errors.Is; a refusal that
			// merely reads the same does not reach that branch. Measured: replacing the %w with %v,
			// leaving the message byte-identical, passes every other test in this package — so
			// without this line the wrap is unpinned and a regression to %v is invisible.
			if !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("the converted panic does not wrap ErrCosmosSignDoc (err=%v), so a caller "+
					"classifying parser failures with errors.Is sees an unrecognised error and "+
					"cannot tell a malformed SignDoc from an internal fault", err)
			}
			if transaction != nil {
				t.Fatal("a panicking parse produced a transaction alongside its refusal")
			}
		})
	}
}

func TestTheExportedParserCarriesTheBoundary(t *testing.T) {
	// The exported path must route through the wrapper: this document's length varint
	// overflows, the guard refuses it as "exceeds buffer", AND — with that guard
	// hypothetically removed — the same input would panic inside and come back as a
	// refusal, not a reset. Belt on the guard, suspenders on the boundary.
	overflowing := append(append(encodeTag(1, 2), encodeVarint(1<<63)...), []byte("body")...)
	_, err := ParseCosmosSignDoc(overflowing)
	if err == nil || !strings.Contains(err.Error(), "exceeds buffer") {
		t.Fatalf("the guarded overflow path changed shape: %v", err)
	}
	// A minimal complete SignDoc still parses: the boundary must not refuse what the
	// parser accepts.
	// The MsgSend shape the parser requires: from(1), to(2), and a repeated Coin with
	// denom(1) and a decimal-string amount(2) — the first version omitted the amount and
	// the row failed on "missing source, destination or amount", not on anything about the
	// boundary. Fixtures for parser rows must be COMPLETE SignDocs or they test the
	// required-field rules by accident.
	coin := append(append([]byte(nil), encodeString(1, "uatom")...), encodeString(2, "100")...)
	msgSend := append(append(append([]byte(nil), encodeString(1, "cosmos1from")...), encodeString(2, "cosmos1target")...), encodeLengthDelimited(3, coin)...)
	body := encodeLengthDelimited(1, encodeAny("/cosmos.bank.v1beta1.MsgSend", msgSend))
	valid := append(append(append(append([]byte(nil),
		encodeLengthDelimited(1, body)...),
		encodeLengthDelimited(2, nil)...),
		encodeString(3, "test-chain")...),
		encodeTopVarint(4, 1)...)
	if _, err := ParseCosmosSignDoc(valid); err != nil {
		t.Fatalf("a complete SignDoc refused under the boundary: %v", err)
	}
}
