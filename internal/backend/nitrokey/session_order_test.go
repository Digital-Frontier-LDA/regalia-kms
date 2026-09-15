package nitrokey

import (
	"context"
	"slices"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE PIN MUST NOT CROSS THE CHANNEL BEFORE THE CHANNEL IS ATTESTED.
//
// Execute does three things before it will use a key: it pins the token's identity, it establishes
// secure messaging, and it logs in with the PIN. The order is the whole control. Identity after
// login means the PIN went to whatever card was in the slot; secure messaging after login means it
// crossed a channel nobody had attested.
//
// Both are currently correct. Nothing asserted it.
// TestExecutePinsIdentityEstablishesSecureMessagingAndZeroesPIN checks that `secure` and `logged` are both true, which is satisfied by any ordering —
// a refactor could swap them and every existing test would still pass, on a mistake whose whole
// consequence is invisible from the outside.
//
// A boolean says a step happened. Only a sequence says it happened first.
func TestExecuteAttestsTheChannelAndPinsIdentityBeforePresentingThePIN(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context")); err != nil {
		t.Fatal(err)
	}

	at := func(name string) int { return slices.Index(session.order, name) }
	for _, name := range []string{"Identity", "EstablishSecureChannel", "Login", "Unwrap"} {
		if at(name) < 0 {
			t.Fatalf("%s was never called; the sequence was %v", name, session.order)
		}
	}
	if at("Identity") > at("Login") {
		t.Fatalf("the PIN was presented before the token's identity was pinned, so it went to whatever card was in the slot: %v", session.order)
	}
	if at("EstablishSecureChannel") > at("Login") {
		t.Fatalf("the PIN was presented before secure messaging was established, so it crossed a channel nobody had attested: %v", session.order)
	}
	if at("Login") > at("Unwrap") {
		t.Fatalf("the key was used before login: %v", session.order)
	}
}

// A CARD THAT CANNOT ATTEST ITS CHANNEL MUST NOT SEE THE PIN AT ALL.
//
// Failing closed is not enough on its own: if the refusal came after the login, the PIN would
// already have been sent over the channel the refusal says was never proven.
func TestAFailedSecureChannelStopsBeforeTheLogin(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, secureErr: true}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context")); err == nil {
		t.Fatal("an operation succeeded despite secure messaging failing to establish")
	}
	if slices.Contains(session.order, "Login") {
		t.Fatalf("the PIN was presented after secure messaging failed: it crossed a channel the KMS had just refused to trust (%v)", session.order)
	}
	if session.loginCalls != 0 {
		t.Fatalf("Login was called %d times after a secure-channel failure", session.loginCalls)
	}
}
