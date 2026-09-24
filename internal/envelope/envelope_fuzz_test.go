package envelope

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

// FuzzParseAcceptsOnlyWhatItCanReproduce: Parse reads client-supplied envelopes before anything is
// verified (the AEAD needs a data key the card has not released yet). Two properties:
//
//   - every refusal is exactly ErrInvalidEnvelope, so a malformed envelope cannot steer the caller
//     into a different error path or leak parser detail;
//   - anything Parse ACCEPTS, Marshal reproduces and Parse reads back as the same envelope. An
//     accepted envelope that does not survive its own round trip is one whose meaning depends on
//     which reader looks at it, and that is the ambiguity an envelope format exists to remove.
func FuzzParseAcceptsOnlyWhatItCanReproduce(f *testing.F) {
	t := &testing.T{}
	_, sealed := sealedFixture(t, "1", time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC))
	f.Add(sealed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":2}{"version":2}`))
	f.Add([]byte("null"))
	f.Fuzz(func(t *testing.T, input []byte) {
		parsed, err := Parse(input)
		if err != nil {
			if !errors.Is(err, ErrInvalidEnvelope) || err.Error() != ErrInvalidEnvelope.Error() {
				t.Fatalf("refusal is not exactly ErrInvalidEnvelope: %v", err)
			}
			return
		}
		again, err := parsed.Marshal()
		if err != nil {
			t.Fatalf("Parse accepted an envelope Marshal refuses: %v", err)
		}
		reparsed, err := Parse(again)
		if err != nil {
			t.Fatalf("the re-marshalled envelope does not parse: %v", err)
		}
		if !reflect.DeepEqual(parsed, reparsed) {
			t.Fatal("the envelope changed across Marshal and Parse")
		}
	})
}
