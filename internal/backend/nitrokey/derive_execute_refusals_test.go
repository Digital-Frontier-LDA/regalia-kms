package nitrokey

// Round two of #237 on this package, second pass: the survivors in functions that ARE called.
//
// The first pass closed wrapAES and unwrapAES, which no test called at all. These two are the
// harder shape and the majority one everywhere measured so far — 98 of 132 survivors here, 89
// of 124 in cmd/regalia-kms: the function is exercised, and the FIXTURES do not discriminate.
// Derive() is driven by 7 tests and Execute() by 35, and ten operands between them survived in
// BOTH directions regardless.
//
// THE ISOLATING FIXTURES ARE THE WHOLE WORK HERE. Three of these guards have the shape
// `err != nil || len(x) == 0 || ...`, where a stub that fails empty-handed lets a length clause
// refuse the same input and the error operand is never the sole refuser. This package already
// knew that — fakePIN, fakeSession.PINRetries and fakeSession.PublicKey each carry a comment
// saying they return a value ALONGSIDE the error for exactly this reason — and I still missed
// it in wrapAES on the previous pass. Written first here rather than discovered in
// falsification.

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/miekg/pkcs11"
)

// deriveStub drives Derive() through the cryptoki seam.
type deriveStub struct {
	*fakeCryptoki
	findErr   error
	deriveErr error
	attrs     []*pkcs11.Attribute
	attrErr   error
	attrsSet  bool
}

func (stub *deriveStub) FindObjects(handle pkcs11.SessionHandle, count int) ([]pkcs11.ObjectHandle, bool, error) {
	if stub.findErr != nil {
		return nil, false, stub.findErr
	}
	return stub.fakeCryptoki.FindObjects(handle, count)
}

func (stub *deriveStub) DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if stub.deriveErr != nil {
		return 0, stub.deriveErr
	}
	return 41, nil
}

func (stub *deriveStub) GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if stub.attrsSet || stub.attrErr != nil {
		return stub.attrs, stub.attrErr
	}
	return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, bytes.Repeat([]byte{7}, 32))}, nil
}

func deriveSession(stub *deriveStub) *pkcs11Session {
	stub.fakeCryptoki = &fakeCryptoki{objectHandle: 9}
	return &pkcs11Session{module: stub, loggedIn: true}
}

// TestKeyAgreementRefusesAndTheFailingStepIsIsolated covers pkcs11_driver.go:698 (findObject),
// :704 (DeriveKey) and :712 operands 0, 1 and 2 (the attribute read).
//
// All five survived in both directions despite Derive() being called by seven tests: every
// existing fixture drives the SUCCESS path, so no arm of any refusal was exercised.
//
// :712's three operands share one message, so they are separated by fixture, and the first row
// is the isolating one — an error returned ALONGSIDE a populated attribute, which is the only
// input `err != nil` refuses alone. A stub that failed empty-handed would let `len(values) == 0`
// refuse the same input and the mutation would survive.
//
// Falsifier: `(false && (err != nil))` at each site, and the length clauses likewise.
func TestKeyAgreementRefusesAndTheFailingStepIsIsolated(t *testing.T) {
	boom := errors.New("token said no")
	populated := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte("something"))}
	peer := peerKey(t)
	for _, row := range []struct {
		name string
		stub *deriveStub
	}{
		{"the private key cannot be found", &deriveStub{findErr: boom}},
		{"the derive call fails", &deriveStub{deriveErr: boom}},
		{"reading the derived value fails WITH a value present", &deriveStub{attrErr: boom, attrs: populated, attrsSet: true}},
		{"the token returns no attributes", &deriveStub{attrs: nil, attrsSet: true}},
		{"the token returns an attribute with no value", &deriveStub{attrs: []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)}, attrsSet: true}},
	} {
		t.Run(row.name, func(t *testing.T) {
			session := deriveSession(row.stub)
			out, err := session.Derive(context.Background(), kekObjectID, "p256", peer)
			if err == nil {
				t.Fatalf("Derive accepted and returned %d bytes", len(out))
			}
			if out != nil {
				t.Fatalf("a refused key agreement returned %d bytes — this path returns a SHARED "+
					"SECRET, so handing back a slice alongside an error is the wrong shape", len(out))
			}
		})
	}
}

// TestDeriveReturnsTheDerivedValueWhenTheTokenAnswers is the control for the table above.
//
// Every row there asserts a refusal, so a Derive that refused unconditionally would pass all
// five. This is the arm that fails if the stub — or the guard set — starts refusing everything.
func TestDeriveReturnsTheDerivedValueWhenTheTokenAnswers(t *testing.T) {
	session := deriveSession(&deriveStub{})
	out, err := session.Derive(context.Background(), kekObjectID, "p256", peerKey(t))
	if err != nil {
		t.Fatalf("Derive refused a healthy token: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("derived %d bytes, want 32", len(out))
	}
}

func retryProvider(t *testing.T, session *fakeSession) *Provider {
	t.Helper()
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func unwrapWith(provider *Provider, format string) ([]byte, string, error) {
	return provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"unwrap", format, "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
}

// TestARetryReadingIsRecordedOnlyWhenTheCardAnswered covers provider.go:181 (`retryErr == nil`),
// in both directions.
//
// The reading feeds the operator's view of how much PIN budget a card has left. Recording one
// when the read FAILED would publish a number the card never gave — and the value returned
// alongside the error is whatever the fake was configured with, so the reading would look
// plausible. Not recording one when the read SUCCEEDED loses the signal entirely.
//
// Falsifier: `(false && (retryErr == nil))` stops every reading; `(true || (retryErr == nil))`
// records one from a failed read.
func TestARetryReadingIsRecordedOnlyWhenTheCardAnswered(t *testing.T) {
	t.Run("a healthy read is recorded", func(t *testing.T) {
		session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, retries: 3, retriesSet: true}
		provider := retryProvider(t, session)
		if _, _, err := unwrapWith(provider, "regalia-envelope-v2"); err != nil {
			t.Fatalf("unwrap: %v", err)
		}
		provider.mu.Lock()
		reading, ok := provider.pinReadings[binding().DeviceID]
		provider.mu.Unlock()
		if !ok {
			t.Fatal("no PIN-retry reading was recorded for a card that answered")
		}
		if reading.retries != 3 {
			t.Fatalf("recorded %d retries, want 3", reading.retries)
		}
	})
	t.Run("a failed read is not recorded", func(t *testing.T) {
		session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint,
			retries: 3, retriesSet: true, retriesErr: errors.New("card said no")}
		provider := retryProvider(t, session)
		if _, _, err := unwrapWith(provider, "regalia-envelope-v2"); err == nil {
			t.Fatal("a card whose retry budget could not be read was served")
		}
		provider.mu.Lock()
		_, ok := provider.pinReadings[binding().DeviceID]
		provider.mu.Unlock()
		if ok {
			t.Fatal("a PIN-retry reading was recorded from a read that FAILED — the number " +
				"published to the operator was never given by the card")
		}
	})
}

// TestOnlyASpentBudgetBlocksThePIN covers provider.go:185 (`retryErr == nil`), in both
// directions.
//
// blockPIN quarantines the device permanently — quarantine latches, and the first reason wins.
// A card that merely failed to REPORT its budget has not spent it, and latching one out of
// service on a transient read failure is an outage the operator has to clear by hand.
//
// Falsifier: `(false && (retryErr == nil))` stops a genuinely spent card from being blocked;
// `(true || (retryErr == nil))` blocks a card whose budget was never read.
func TestOnlyASpentBudgetBlocksThePIN(t *testing.T) {
	t.Run("a spent budget blocks", func(t *testing.T) {
		session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, retries: 1, retriesSet: true}
		provider := retryProvider(t, session)
		if _, _, err := unwrapWith(provider, "regalia-envelope-v2"); err == nil {
			t.Fatal("a card with one retry left was served")
		}
		provider.mu.Lock()
		reason, blocked := provider.blocked[binding().DeviceID]
		provider.mu.Unlock()
		if !blocked {
			t.Fatal("a card down to its last PIN retry was not quarantined")
		}
		if reason != "pin-budget-spent" {
			t.Fatalf("quarantined as %q, want pin-budget-spent", reason)
		}
	})
	t.Run("an unreadable budget does not block", func(t *testing.T) {
		session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint,
			retries: 5, retriesSet: true, retriesErr: errors.New("card said no")}
		provider := retryProvider(t, session)
		if _, _, err := unwrapWith(provider, "regalia-envelope-v2"); err == nil {
			t.Fatal("a card whose retry budget could not be read was served")
		}
		provider.mu.Lock()
		reason, blocked := provider.blocked[binding().DeviceID]
		provider.mu.Unlock()
		if blocked {
			t.Fatalf("a card was latched out of service as %q because its budget could not be "+
				"READ — a transient read failure is not a spent budget, and quarantine does not "+
				"clear itself", reason)
		}
	})
}

// releasingPIN is the first pinReleaser double in this package. provider.go:196 asserts the
// source to that interface and nothing implemented it, so both operands of the release guard
// were unreachable by every fixture that existed.
type releasingPIN struct {
	fakePIN
	releaseErr error
	released   int
}

func (source *releasingPIN) Release(pin []byte) error {
	source.released++
	return source.releaseErr
}

// TestAPINThatCannotBeReleasedFailsTheOperation covers provider.go:197 (`releaseErr != nil`).
//
// The release runs in a deferred function AFTER the operation succeeded, and it rewrites the
// named return values. If releasing the PIN fails, the custody of that PIN is in doubt, and
// handing back a data key obtained under it would be acting on a credential the provider can no
// longer account for. The guard turns a successful operation into ErrUnavailable and zeroes the
// output.
//
// Falsifier: `(false && (releaseErr != nil))`. The unwrap then succeeds and returns the data
// key despite the PIN never being released.
func TestAPINThatCannotBeReleasedFailsTheOperation(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, retries: 3, retriesSet: true}
	source := &releasingPIN{fakePIN: fakePIN{value: []byte("123456")}, releaseErr: errors.New("cannot release")}
	provider, err := New(&fakeDriver{session: session}, source)
	if err != nil {
		t.Fatal(err)
	}
	out, _, execErr := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
	if source.released == 0 {
		t.Fatal("Release was never called, so this test is not exercising the release guard")
	}
	if execErr == nil {
		t.Fatalf("the operation succeeded and returned %d bytes although the PIN could not be "+
			"released — the data key was obtained under a credential the provider cannot account for", len(out))
	}
	if !errors.Is(execErr, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", execErr)
	}
	if len(out) != 0 {
		t.Fatalf("a failed release returned %d bytes; the guard must zero the output", len(out))
	}
}

// TestUnwrapAcceptsBothDeclaredFormats covers provider.go:251 operand 1
// (`format != "sops-pgp"`).
//
// The guard is `format != "regalia-envelope-v2" && format != "sops-pgp"`, so deleting the
// second operand narrows what unwrap accepts to one format. Every existing fixture passes
// "regalia-envelope-v2", which leaves the sops-pgp arm undriven in both directions: nothing
// proved it was accepted, and nothing would notice if it stopped being.
//
// Falsifier: `(true || (format != "sops-pgp"))` makes the conjunction false and admits ANY
// format; `(false && (format != "sops-pgp"))` narrows it and this test's sops-pgp row fails.
func TestUnwrapAcceptsBothDeclaredFormats(t *testing.T) {
	for _, format := range []string{"regalia-envelope-v2", "sops-pgp"} {
		t.Run(format, func(t *testing.T) {
			session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, retries: 3, retriesSet: true}
			provider := retryProvider(t, session)
			out, _, err := unwrapWith(provider, format)
			if err != nil {
				t.Fatalf("unwrap refused the declared format %q: %v", format, err)
			}
			if len(out) == 0 {
				t.Fatalf("unwrap of %q returned nothing", format)
			}
		})
	}
	t.Run("an undeclared format is still refused", func(t *testing.T) {
		session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, retries: 3, retriesSet: true}
		provider := retryProvider(t, session)
		if _, _, err := unwrapWith(provider, "pgp-armored"); err == nil {
			t.Fatal("an undeclared format was accepted — without this row the test above would " +
				"pass with the format check deleted entirely")
		}
	})
}

// TestAPublicKeyOperationRefusesAnEmptyAnswer covers provider.go:150 operand 1
// (`len(output) == 0`).
//
// A card that answers the public-key request successfully with no bytes is the state this
// clause exists for. It was unreachable until fakeSession gained publicKeyEmpty: the fake
// substituted []byte("public") whenever no key was configured, so every fixture produced a
// non-empty answer and the operand survived in both directions.
//
// Falsifier: `(false && (len(output) == 0))`. Execute then returns an empty slice and
// "application/pkix" as a successful public-key read.
func TestAPublicKeyOperationRefusesAnEmptyAnswer(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, publicKeyEmpty: true}
	provider := retryProvider(t, session)
	out, outputType, err := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()}, "public-key", "", "", nil, nil)
	if err == nil {
		t.Fatalf("an empty public key was returned as %q with %d bytes", outputType, len(out))
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

// TestAPublicKeyOperationReturnsTheKeyWhenTheCardAnswers is the success arm for
// provider.go:150, and it is not decoration.
//
// The refusal test above pins the FALSE direction — the operand deleted, an empty answer
// accepted. It cannot see the TRUE direction, where the guard fires unconditionally and every
// public-key request is refused, because nothing in this package performed a public-key read
// that was expected to SUCCEED. Measured: `(true || (len(output) == 0))` survived the whole
// suite until this test existed.
//
// A table of refusals with no success arm cannot distinguish "refuses the right inputs" from
// "refuses everything".
func TestAPublicKeyOperationReturnsTheKeyWhenTheCardAnswers(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint,
		publicKey: []byte("a real public key")}
	provider := retryProvider(t, session)
	out, outputType, err := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()}, "public-key", "", "", nil, nil)
	if err != nil {
		t.Fatalf("a public-key read from a healthy card was refused: %v", err)
	}
	if !bytes.Equal(out, []byte("a real public key")) {
		t.Fatalf("returned %q, want the card's key", out)
	}
	if outputType != "application/pkix" {
		t.Fatalf("outputType = %q, want application/pkix", outputType)
	}
}

// TestAPINThatReleasesCleanlyLeavesTheOperationAlone is the success arm for provider.go:197,
// for the same reason.
//
// The failing-release test pins the FALSE direction. Nothing pinned the TRUE direction —
// the guard firing on a release that SUCCEEDED — because releasingPIN was the first
// pinReleaser in this package and it only ever failed. Measured:
// `(true || (releaseErr != nil))` survived until this test existed, and under it every
// operation performed with a releasing PIN source returns ErrUnavailable.
func TestAPINThatReleasesCleanlyLeavesTheOperationAlone(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, retries: 3, retriesSet: true}
	source := &releasingPIN{fakePIN: fakePIN{value: []byte("123456")}}
	provider, err := New(&fakeDriver{session: session}, source)
	if err != nil {
		t.Fatal(err)
	}
	out, _, execErr := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context"))
	if execErr != nil {
		t.Fatalf("an operation whose PIN released cleanly was refused: %v", execErr)
	}
	if source.released == 0 {
		t.Fatal("Release was never called, so this test does not exercise the release guard")
	}
	if len(out) == 0 {
		t.Fatal("the operation returned nothing")
	}
}
