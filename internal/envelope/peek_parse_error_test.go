package envelope

// PEEK HAS TWO REFUSALS AND NEITHER CAN FAIL ALONE, so the message is the only thing that
// distinguishes them and the only thing a test can pin.
//
//	the propagation  -- `if err != nil` on Parse's return, at the top of Peek
//	the backstop     -- `if parsed.KEK.Version == ""` below it, unreachable in normal operation
//	                    because Parse already runs validateKeyRef, whose keyVersionPattern rejects
//	                    "" (measured)
//
// Defeating either one still refuses, which is why a test asserting only "Peek refused" would pin
// nothing. Measured on garbage input:
//
//	baseline               err=invalid secret envelope
//	defeat the propagation err=invalid secret envelope: envelope names no KEK version  <- backstop
//	defeat both            err=<nil>, KEK={Backend: ID: Version:}                      <- success
//
// The last row is what the pair prevents: Coordinator.Execute passes Peek's KeyRef straight into
// RouteForUnwrap, so a success here routes an unwrap on an empty KEK version.
//
// This test asserts the FIRST message, so it fails alone when the propagation is defeated and
// stays green when the backstop is — which is correct, since no input Parse admits can reach it.

import (
	"errors"
	"strings"
	"testing"
)

func TestPeekPropagatesParsesRefusalRatherThanItsBackstop(t *testing.T) {
	// ANCHOR: a well-formed envelope must Peek cleanly, or an always-refusing Peek would satisfy
	// the row below.
	objectID := "deployment-api-token"
	binding := ReleaseContext(objectID, "deploy", "production")
	kek := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}
	good, _ := envelopeSealedUnder(t, 32, objectID, binding, kek)
	encoded, err := good.Marshal()
	if err != nil {
		t.Fatalf("anchor envelope did not marshal: %v — the row below would prove nothing", err)
	}
	if ref, _, err := Peek(encoded); err != nil || ref.Version != "1" {
		t.Fatalf("anchor: Peek = (%+v, %v), want version 1 and no error", ref, err)
	}

	// GATE: garbage must be refused BY PARSE, not by the KEK-version backstop. Both refuse; only
	// the message says which, and a backstop firing means the propagation above it stopped working.
	_, _, peekErr := Peek([]byte("not-an-envelope-at-all"))
	if !errors.Is(peekErr, ErrInvalidEnvelope) {
		t.Fatalf("Peek(garbage) = %v, want ErrInvalidEnvelope — with both refusals defeated this returns nil and an empty KeyRef, which Coordinator.Execute feeds to RouteForUnwrap", peekErr)
	}
	if strings.Contains(peekErr.Error(), "names no KEK version") {
		t.Fatalf("Peek(garbage) was refused by the KEK-version backstop (%v), not by Parse — the error propagation at the top of Peek has stopped working, and the backstop is masking it", peekErr)
	}
}
