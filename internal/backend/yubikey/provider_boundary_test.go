package yubikey

// DELIBERATELY UNTAGGED.
//
// provider.go carries no build constraint, and four of this package's seven test
// files do. A test written behind `//go:build piv` for a file that compiles
// without it is a test a plain `go test ./...` cannot see — which is exactly how
// this package became the largest unswept surface in #237: every sweep that ran
// without `-tags piv` compiled nothing here and read the resulting silence as
// "no mutation was detected". These tests exercise provider.go alone, so they
// belong on the untagged side where both builds run them.
//
// Each test below names the operand it was measured against. Every one was
// falsified: the named operand was neutralised (or forced) in a scratch copy of
// provider.go, the suite re-run, and the test confirmed as the failure that
// names the defect. Where it was not the SOLE failure that is stated.

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// boundarySession is a card whose every answer AND every failure is set
// independently, including the combinations the existing fixtures cannot
// express: an answer returned ALONGSIDE an error.
//
// That pairing is the point. riggedSession.PublicKey returns the error with a
// nil key, so `err != nil` and `len(output) == 0` fire on the same input and
// neither operand is ever the sole refuser. A fake that cannot pair a value
// with an error cannot measure the error operand at all.
type boundarySession struct {
	serial, pinPolicy, touchPolicy string

	identityErr, policiesErr, retriesErr error
	loginErr, closeErr                   error

	retries    int
	retriesSet bool

	publicKey []byte
	publicErr error

	signValue []byte
	signErr   error
	signSet   bool

	unwrapFrame []byte
	unwrapErr   error

	panicOnSign bool

	signed, closed bool
	loginCalls     int
}

func (s *boundarySession) Identity(context.Context) (string, error) {
	return s.serial, s.identityErr
}

func (s *boundarySession) Policies(context.Context, string) (string, string, error) {
	return s.pinPolicy, s.touchPolicy, s.policiesErr
}

func (s *boundarySession) PINRetries(context.Context) (int, error) {
	if !s.retriesSet {
		return 3, s.retriesErr
	}
	return s.retries, s.retriesErr
}

func (s *boundarySession) Login(_ context.Context, _ []byte) error {
	s.loginCalls++
	return s.loginErr
}

func (s *boundarySession) Sign(context.Context, string, string, []byte) ([]byte, error) {
	s.signed = true
	if s.panicOnSign {
		panic("the card driver faulted mid-signature")
	}
	if s.signSet {
		return append([]byte(nil), s.signValue...), s.signErr
	}
	return []byte("signature"), nil
}

func (s *boundarySession) Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	if s.unwrapErr != nil {
		return nil, s.unwrapErr
	}
	return append([]byte(nil), s.unwrapFrame...), nil
}

func (s *boundarySession) PublicKey(context.Context, string) ([]byte, error) {
	return append([]byte(nil), s.publicKey...), s.publicErr
}

func (s *boundarySession) Close() error { s.closed = true; return s.closeErr }

type boundaryDriver struct {
	session Session
	openErr error
}

func (d *boundaryDriver) Open(context.Context, string) (Session, error) {
	return d.session, d.openErr
}
func (*boundaryDriver) Ready(context.Context) bool { return true }

func boundaryCard() *boundarySession {
	return &boundarySession{serial: "12345678", pinPolicy: "once", touchPolicy: "never", publicKey: []byte("public")}
}

// providerOver builds a Provider over one session, failing the test rather than
// returning an error, so no case below can silently run against a nil provider.
func providerOver(t *testing.T, session Session, openErr error, pins PINSource) *Provider {
	t.Helper()
	made, err := New(&boundaryDriver{session: session, openErr: openErr}, pins)
	if err != nil {
		t.Fatal(err)
	}
	return made
}

func sixDigitPIN() *fakePIN { return &fakePIN{value: []byte("123456")} }

// signOnce runs the sign operation and reports whether a panic escaped Execute.
// Execute promises to convert a faulting driver into a refusal; observing that
// requires catching the panic here rather than letting it take the binary down,
// which would report as every test in the package failing at once.
func signOnce(provider *Provider, route registry.Route) (output []byte, err error, escaped any) {
	func() {
		defer func() { escaped = recover() }()
		output, _, err = provider.Execute(context.Background(), route, "sign", "", "application/octet-stream", []byte("payload"), nil)
	}()
	return output, err, escaped
}

// ----------------------------------------------------------------------------
// provider.go:43 op0 `driver == nil`, op1 `pins == nil`
// ----------------------------------------------------------------------------

// NEITHER CONSTRUCTOR ARGUMENT HAD A TEST THAT SUPPLIED IT AS NIL.
//
// Every existing caller of New in this package passes both, so both operands
// survived neutralisation. A Provider built over a nil driver does not fail at
// construction — it fails at the first Open, inside a deferred cleanup, on a
// nil interface, which is a crash rather than a refusal.
//
// Falsifier: provider.go:43 op0 -> `(false && driver == nil)`. New(nil, pins)
// then returns a Provider and a nil error. Sole failure. Likewise op1.
func TestNewRefusesAMissingDriverOrPINSource(t *testing.T) {
	if _, err := New(nil, sixDigitPIN()); err == nil {
		t.Error("New accepted a nil driver: the Provider it returns cannot open a card, and the absence " +
			"surfaces as a nil-interface call inside Execute's deferred cleanup rather than as a refusal here")
	}
	if _, err := New(&boundaryDriver{session: boundaryCard()}, nil); err == nil {
		t.Error("New accepted a nil PIN source: every operation that needs a PIN would call PIN on nil")
	}
	// Control: the refusals above prove nothing if New refuses everything.
	if _, err := New(&boundaryDriver{session: boundaryCard()}, sixDigitPIN()); err != nil {
		t.Fatalf("New refused a driver and a PIN source that are both present: %v", err)
	}
}

// ----------------------------------------------------------------------------
// provider.go:51 op6 `binding.PINPolicy != "always"`
// ----------------------------------------------------------------------------

// A REFUSAL-DIRECTION GAP: THE POLICY THE SUITE NEVER ACCEPTS.
//
// Execute admits exactly two PIN policies. Every existing fixture uses "once",
// and the only "always" in the suite is a card DISAGREEING with a binding that
// says "once". So the operand that admits "always" could be turned into a
// refusal and the whole suite stayed green: a commissioned YubiKey whose slot
// is PINPolicyAlways would stop being servable, and no negative test notices,
// because losing access to a key looks like every other refusal.
//
// Falsifier: provider.go:51 op6 -> `(true || binding.PINPolicy != "always")`,
// which collapses the pair to `!= "once"`. Sole failure.
func TestABindingWithPINPolicyAlwaysIsServed(t *testing.T) {
	session := boundaryCard()
	session.pinPolicy = "always"
	provider := providerOver(t, session, nil, sixDigitPIN())

	always := route()
	always.Binding.PINPolicy = "always"

	output, err, escaped := signOnce(provider, always)
	if escaped != nil {
		t.Fatalf("panic: %v", escaped)
	}
	if err != nil {
		t.Fatalf("a binding declaring PINPolicy \"always\", confirmed by the card, was refused: %v — "+
			"\"always\" is one of the two policies this backend admits, and refusing it takes a "+
			"commissioned key out of service without any negative test going red", err)
	}
	if string(output) != "signature" {
		t.Fatalf("output = %q, want the card's signature", output)
	}
}

// ----------------------------------------------------------------------------
// provider.go:59 op1 `session == nil`
// ----------------------------------------------------------------------------

// Healthy has a case for a driver that returns neither a session nor an error;
// Execute did not, so the operand survived. Without it the nil session reaches
// Identity, and the deferred cleanup then calls Close on the same nil — a panic
// raised inside a deferred function that has already spent its recover.
//
// Falsifier: provider.go:59 op1 -> `(false && session == nil)`. This test is
// the failure; the panic escapes Execute, so it is caught here rather than
// aborting the binary and reporting as a package-wide failure.
func TestExecuteRefusesADriverThatReturnsNoSessionAndNoError(t *testing.T) {
	provider := providerOver(t, nil, nil, sixDigitPIN())

	output, err, escaped := signOnce(provider, route())
	if escaped != nil {
		t.Fatalf("a driver returning no session and no error was carried into the operation and panicked (%v) — "+
			"the nil check is what stops the deref, and its absence is a crash, not a refusal", escaped)
	}
	if err == nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable for a driver that opened nothing", err)
	}
	if len(output) != 0 {
		t.Fatalf("output = %q, want nothing", output)
	}
}

// ----------------------------------------------------------------------------
// provider.go:63 op0 `recover() != nil`
// ----------------------------------------------------------------------------

// A FAULTING CARD DRIVER MUST BE A REFUSAL, NOT A DEAD DAEMON.
//
// Nothing in the suite made a session panic, so the deferred recover was
// unmeasured. It is the boundary between "one operation failed" and "the
// process serving every other key went down".
//
// Falsifier: provider.go:63 op0 -> `(false && recover() != nil)`, which does
// not merely skip the body — short-circuiting means recover() is never CALLED,
// so the panic propagates out of Execute. Sole failure.
func TestAPanickingCardSessionBecomesARefusal(t *testing.T) {
	session := boundaryCard()
	session.panicOnSign = true
	provider := providerOver(t, session, nil, sixDigitPIN())

	output, err, escaped := signOnce(provider, route())
	if escaped != nil {
		t.Fatalf("a panic from the card session escaped Execute (%v) — the deferred recover is what turns a "+
			"faulting driver into one refused operation instead of taking down the daemon serving every other key", escaped)
	}
	if !session.signed {
		t.Fatal("the fixture never reached Sign, so nothing panicked and this proves nothing about recovery")
	}
	if err == nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable after a recovered panic", err)
	}
	if len(output) != 0 {
		t.Fatalf("output = %q, want nothing", output)
	}
}

// ----------------------------------------------------------------------------
// provider.go:73 op0, :77 op0, :77 op1
// ----------------------------------------------------------------------------

// THE CARD-DISAGREEMENT CHECKS EXIST TWICE AND WERE TESTED ONCE.
//
// Healthy has a case for each of these; Execute has the identical three
// comparisons and had cases for only the serial and the touch policy. The
// remaining three operands survived on the Execute path — which is the path
// that actually uses the key.
//
// Each case is the sole refuser of its own input: the other two comparisons
// agree in every row, so the refusal is attributable to the named one.
func TestExecuteRefusesACardThatDisagreesWithItsBinding(t *testing.T) {
	for name, test := range map[string]struct {
		apply  func(*boundarySession)
		reason string
	}{
		// :73 op0 — Identity errors while returning the RIGHT serial, so the
		// sibling `serial != binding.DeviceSerial` agrees and this operand is
		// the only thing that can refuse.
		"the serial cannot be read": {
			apply:  func(s *boundarySession) { s.identityErr = errors.New("card stopped answering") },
			reason: "a card that will not state its serial has not been identified, and an unidentified card is not the commissioned one",
		},
		// :77 op0 — Policies errors while returning matching policies.
		"the slot policy cannot be read": {
			apply:  func(s *boundarySession) { s.policiesErr = errors.New("slot unreadable") },
			reason: "an unreadable slot policy is not a policy of \"never\"; this backend's whole contract is that no operation requests presence",
		},
		// :77 op1 — the card reports a PIN policy the manifest did not declare.
		"a PIN policy the manifest did not declare": {
			apply:  func(s *boundarySession) { s.pinPolicy = "always" },
			reason: "the manifest declares \"once\" and the card says \"always\"; the manifest is the record the fleet is audited against",
		},
	} {
		t.Run(name, func(t *testing.T) {
			session := boundaryCard()
			test.apply(session)
			provider := providerOver(t, session, nil, sixDigitPIN())

			output, err, escaped := signOnce(provider, route())
			if escaped != nil {
				t.Fatalf("panic: %v", escaped)
			}
			if err == nil || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("%s was served (err=%v, output=%q): %s", name, err, output, test.reason)
			}
			if session.signed {
				t.Fatalf("%s reached the signing call — the disagreement must stop the operation before the key is used, "+
					"not merely change what is returned afterwards", name)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// provider.go:82 op0 and :93 op0 — `err != nil` from PublicKey
// ----------------------------------------------------------------------------

// AN ANSWER RETURNED ALONGSIDE AN ERROR, WHICH NO EXISTING FIXTURE COULD BUILD.
//
// riggedSession.PublicKey returns `append(nil, s.publicKey...), s.publicErr`
// and every fixture that sets publicErr leaves publicKey nil. So on the
// public-key arm the sibling `len(output) == 0` refused the same input, and on
// the wrap arm keywrap.RSAOAEP refused the nil key one line further down. Both
// error operands were masked by a neighbour refusing the same fixture, and the
// suite could not tell the difference.
//
// A card that returns a well-formed key AND an error separates them: with the
// error operand neutralised, the public-key arm hands back a key the card
// disowned, and the wrap arm wraps a data key TO it.
//
// Falsifiers: :82 op0 -> `(false && err != nil)` (sole failure, subtest
// "public-key"); :93 op0 -> `(false && publicErr != nil)` (sole failure,
// subtest "wrap").
func TestACardKeyReturnedWithAnErrorIsNotUsed(t *testing.T) {
	publicKey := boundaryRSAPublicKey(t)

	t.Run("public-key", func(t *testing.T) {
		session := boundaryCard()
		session.publicKey = publicKey
		session.publicErr = errors.New("slot read failed")
		provider := providerOver(t, session, nil, sixDigitPIN())

		output, contentType, err := provider.Execute(context.Background(), route(), "public-key", "", "", nil, nil)
		if err == nil {
			t.Fatalf("a key the card returned WITH an error was published as %q (%d bytes) — it parses and it is "+
				"well-formed, so nothing downstream would question it, and a certificate would be issued over a key "+
				"the card did not vouch for", contentType, len(output))
		}
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})

	t.Run("wrap", func(t *testing.T) {
		session := boundaryCard()
		session.publicKey = publicKey
		session.publicErr = errors.New("slot read failed")
		provider := providerOver(t, session, nil, sixDigitPIN())
		wrapRoute := route()
		wrapRoute.Algorithm = "rsa2048"

		output, _, err := provider.Execute(context.Background(), wrapRoute, "wrap", "regalia-envelope-v2", "", []byte("data-key"), []byte("aad"))
		if err == nil {
			t.Fatalf("a data key was wrapped to a card key returned WITH an error (%d bytes) — the key is "+
				"parseable, so RSAOAEP succeeds and the failure never surfaces; only this guard stands between "+
				"an unreliable slot read and an envelope nobody can open", len(output))
		}
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})
}

// cardPublicMaterialPKIX is a fixed, PKIX-encoded RSA-2048 PUBLIC modulus and
// exponent, base64 of the DER. Public by construction: no private half exists
// anywhere, here or in the generator that produced it, so there is nothing to
// keep out of the tree.
//
// FIXED RATHER THAN GENERATED PER RUN. What these cases need is a key that
// keywrap.RSAOAEP can parse and wrap to; which key that is does not matter, and
// generating a 2048-bit one per run costs a second of test time and makes the
// fixture different on every execution. A fixture that changes between runs
// cannot be reasoned about when a case fails only sometimes.
const cardPublicMaterialPKIX = "" +
	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqaGB9q1GhWII6ze60SLumzVJ9N04DNE/" +
	"382Pv30y98wyTgc1IjNg8R8AaKraldSvE6TcvLurTllAD42QxsxqNrgUpWSrdMhcdnBOVwCZdfum" +
	"zDoVcsQF6feRj3ynuUogXqo1GRLy0d52eJU51dZ+/Ruzpe1qeAhiFN0epc4+9RPfviIjUQnUWwZS" +
	"g/XNQWgIdNR7EkW6p3qiO4SeaG/3HoOo4hsmAl57Cnn3JSH14qPWwdiAv/UP94CoGMiBhXUiPZem" +
	"jVTPAnuazDHrzyaDO87vFjAlvaaMVqm/GzyZ4t2xtYrtqL7M1Ug0APgQXzRjrnLclfqVaZwJXNiQ" +
	"cMJSFwIDAQAB"

// boundaryRSAPublicKey decodes the fixture and PARSES it, so a corrupted
// literal fails here rather than surfacing as a wrap that refuses for a reason
// the test would then attribute to the guard under measurement.
func boundaryRSAPublicKey(t *testing.T) []byte {
	t.Helper()
	encoded, err := base64.StdEncoding.DecodeString(cardPublicMaterialPKIX)
	if err != nil {
		t.Fatalf("the card material fixture is not valid base64: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		t.Fatalf("the card material fixture does not parse as PKIX: %v — every case below would then refuse "+
			"for a reason that is not the operand under measurement", err)
	}
	public, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("the card material fixture parsed as %T, want an RSA public key", parsed)
	}
	if bits := public.N.BitLen(); bits != 2048 {
		t.Fatalf("the card material fixture is %d bits, want 2048: the wrap arm below asserts an RSA-2048 "+
			"output length", bits)
	}
	return encoded
}

// ----------------------------------------------------------------------------
// provider.go:104 op0 `retryErr != nil` and :105 op0 `retryErr == nil`
// ----------------------------------------------------------------------------

// THE LATCH MUST FIRE ON A SPENT BUDGET AND MUST NOT FIRE ON A FAILED READ.
//
// provider.go:105 was the only operand in this package that survived in BOTH
// directions, and it is the one whose two failure modes point opposite ways:
//
//	never latch   a card down to its last retry is tried again and again until
//	              the PIN blocks permanently and the key needs an operator with
//	              the PUK
//	always latch  a transient failure to READ the retry count takes a healthy
//	              device out of the fleet until an operator clears it by hand
//
// The second is the refusal-direction defect this sweep was told to look for:
// every negative test stays green, because the daemon merely refuses more.
//
// The latch is not visible in Execute's return value — both cases give
// ErrUnavailable — so it is read from pinBlocked directly, which is what makes
// this a per-operand discriminator rather than "something refused".
//
// Falsifiers, each the sole failure:
//
//	:104 op0 -> `(false && retryErr != nil)`  subtest "unreadable" reaches Sign
//	:105 op0 -> `(false && retryErr == nil)`  subtest "one retry left" is not latched
//	:105 op0 -> `(true  || retryErr == nil)`  subtest "unreadable" is latched
func TestThePINLatchDistinguishesASpentBudgetFromAnUnreadableOne(t *testing.T) {
	// THE LATCH IS READ FOR THE DEVICE THE OPERATION ACTUALLY USED, taken from
	// the same route the call was made with rather than spelled out again. A
	// literal here would keep passing if route()'s DeviceID changed — it would
	// simply start asserting about a device this test never touches, and the
	// "not latched" case would then be satisfied by a key that was never a
	// candidate for latching.
	t.Run("one retry left", func(t *testing.T) {
		session := boundaryCard()
		session.retries, session.retriesSet = 1, true
		provider := providerOver(t, session, nil, sixDigitPIN())
		operation := route()

		if _, err, _ := signOnce(provider, operation); err == nil {
			t.Fatal("a card down to its last retry was used")
		}
		if session.signed {
			t.Fatal("the last retry was spent on a signature")
		}
		if !provider.pinBlocked(operation.Binding.DeviceID) {
			t.Fatalf("the card %q reported one retry left and was not latched — the retry budget is spent by "+
				"ATTEMPTS, so a device that is merely refused each time is retried until the PIN blocks and "+
				"only a PUK recovers it", operation.Binding.DeviceID)
		}
	})

	t.Run("the retry count is unreadable", func(t *testing.T) {
		session := boundaryCard()
		session.retriesErr = errors.New("card stopped answering")
		provider := providerOver(t, session, nil, sixDigitPIN())
		operation := route()

		if _, err, _ := signOnce(provider, operation); err == nil {
			t.Fatal("an operation went ahead without knowing how many PIN retries remained")
		}
		if session.loginCalls != 0 {
			t.Fatalf("the PIN was presented %d times without a readable retry budget — that is how a budget is "+
				"spent blind", session.loginCalls)
		}
		if provider.pinBlocked(operation.Binding.DeviceID) {
			t.Fatalf("the card %q had a retry count that could not be READ and was latched out of the fleet — "+
				"the latch is sticky and needs an operator to clear, so treating a failed read as a spent budget "+
				"turns a transient fault into a manual recovery for a device that may be perfectly healthy",
				operation.Binding.DeviceID)
		}
	})
}

// ----------------------------------------------------------------------------
// provider.go:111 op0 `err != nil` from the PIN source
// ----------------------------------------------------------------------------

// fakePIN never fails, so this operand had no fixture. And a PIN source that
// fails by returning NOTHING would not measure it either: `len(pin) < 6`
// refuses an empty slice on its own. Only a source that returns a
// correctly-shaped PIN alongside an error leaves this operand as the sole
// refuser.
//
// Falsifier: :111 op0 -> `(false && err != nil)`. The PIN is presented to the
// card and a retry is spent on custody material the source disowned. Sole
// failure.
type failingPIN struct{ value []byte }

func (source *failingPIN) PIN(context.Context, string) ([]byte, error) {
	return append([]byte(nil), source.value...), errors.New("custody store unavailable")
}

func TestAPINReturnedWithAnErrorIsNeverPresentedToTheCard(t *testing.T) {
	session := boundaryCard()
	provider := providerOver(t, session, nil, &failingPIN{value: []byte("123456")})

	output, err, escaped := signOnce(provider, route())
	if escaped != nil {
		t.Fatalf("panic: %v", escaped)
	}
	if err == nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable when the PIN source failed", err)
	}
	if session.loginCalls != 0 {
		t.Fatalf("a PIN the source returned WITH an error was presented to the card (%d logins) — it is the right "+
			"LENGTH, so the length guard passes it through, and a retry is spent from a budget of three on material "+
			"the custody store said it could not vouch for", session.loginCalls)
	}
	if len(output) != 0 {
		t.Fatalf("output = %q, want nothing", output)
	}
}

// ----------------------------------------------------------------------------
// provider.go:117 op0 `releaseErr != nil`, forced direction
// ----------------------------------------------------------------------------

// THE SUITE HAD A PIN SOURCE THAT CANNOT RELEASE AND NONE THAT CAN.
//
// fakePIN is not a pinReleaser at all, so the type assertion fails and the body
// never runs; unreleasablePIN always errors. Forcing this operand true — every
// release treated as failed — left the whole suite green, which means nothing
// asserted that a SUCCESSFUL release lets the result through. Another
// refusal-direction gap: the daemon would discard every signature it produced.
//
// Falsifier: :117 op0 -> `(true || releaseErr != nil)`. Sole failure.
type releasingPIN struct {
	value    []byte
	released int
}

func (source *releasingPIN) PIN(context.Context, string) ([]byte, error) {
	return append([]byte(nil), source.value...), nil
}
func (source *releasingPIN) Release([]byte) error { source.released++; return nil }

func TestASuccessfulPINReleaseDoesNotDiscardTheResult(t *testing.T) {
	session := boundaryCard()
	pins := &releasingPIN{value: []byte("123456")}
	provider := providerOver(t, session, nil, pins)

	output, err, escaped := signOnce(provider, route())
	if escaped != nil {
		t.Fatalf("panic: %v", escaped)
	}
	if pins.released != 1 {
		t.Fatalf("Release was called %d times, want 1 — this test measures what a SUCCESSFUL release does, so a "+
			"fixture the provider never releases to measures nothing", pins.released)
	}
	if err != nil {
		t.Fatalf("a signature was discarded after the PIN was released cleanly: %v — the release path exists to "+
			"catch custody material the source would not take back, and turning every release into a failure means "+
			"the daemon produces signatures and throws all of them away", err)
	}
	if string(output) != "signature" {
		t.Fatalf("output = %q, want the card's signature", output)
	}
}

// ----------------------------------------------------------------------------
// provider.go:132 op1 `format != "sops-pgp"`
// ----------------------------------------------------------------------------

// THE SECOND ALLOWED UNWRAP FORMAT HAD NO TEST THAT USED IT.
//
// TestUnwrapRefusesAFormatOutsideTheAllowlist pins the refusal of a third
// format and the acceptance of regalia-envelope-v2. sops-pgp is named in the
// source and nowhere in the suite, so collapsing the pair to a single allowed
// format left everything green — and the SOPS path, which is the reason this
// operand exists, would refuse every artifact.
//
// Falsifier: :132 op1 -> `(true || format != "sops-pgp")`. Sole failure.
func TestUnwrapAcceptsTheSOPSPGPFormat(t *testing.T) {
	aad := []byte("aad-for-the-sops-pgp-format-test")
	plaintext := []byte("decrypted-data-key-32-bytes-long")
	session := boundaryCard()
	session.unwrapFrame = boundaryV2Frame(aad, plaintext)
	provider := providerOver(t, session, nil, sixDigitPIN())

	unwrapRoute := route()
	unwrapRoute.Algorithm = "rsa2048"

	output, contentType, err := provider.Execute(context.Background(), unwrapRoute, "unwrap", "sops-pgp", "", []byte("ciphertext"), aad)
	if err != nil {
		t.Fatalf("unwrap refused format \"sops-pgp\": %v — it is one of the two formats this arm admits, and "+
			"refusing it means every SOPS artifact bound to a YubiKey stops opening while every negative test "+
			"in this package stays green", err)
	}
	if !bytes.Equal(output, plaintext) {
		t.Fatalf("output = %q, want the frame's declared plaintext %q", output, plaintext)
	}
	if contentType != "application/octet-stream" {
		t.Fatalf("content type = %q", contentType)
	}
}

// boundaryV2Frame builds the frame keywrap.OpenFrame reads: magic, the digest
// of the label, a big-endian length, then the plaintext.
func boundaryV2Frame(aad, plaintext []byte) []byte {
	digest := sha256.Sum256(aad)
	frame := make([]byte, 0, 4+sha256.Size+4+len(plaintext))
	frame = append(frame, 'R', 'G', 'K', 2)
	frame = append(frame, digest[:]...)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(plaintext)))
	frame = append(frame, length[:]...)
	return append(frame, plaintext...)
}

// ----------------------------------------------------------------------------
// provider.go:145 op0 `err != nil`, op1 `len(output) == 0`
// ----------------------------------------------------------------------------

// THE FINAL BACKSTOP, WHOSE TWO OPERANDS MASKED EACH OTHER.
//
// Every fixture in the suite made Sign return bytes with a nil error or nothing
// with an error, so the two operands always agreed and neither was ever the
// sole refuser. Splitting them needs a card that returns bytes WITH an error,
// and one that returns nothing WITHOUT one.
//
// Falsifiers, each the sole failure: :145 op0 -> `(false && err != nil)` for
// "bytes with an error"; :145 op1 -> `(false && len(output) == 0)` for
// "nothing without an error".
func TestAFailedOrEmptySignatureIsNotReturned(t *testing.T) {
	t.Run("bytes returned with an error", func(t *testing.T) {
		session := boundaryCard()
		session.signValue, session.signErr, session.signSet = []byte("partial-signature"), errors.New("card faulted mid-sign"), true
		provider := providerOver(t, session, nil, sixDigitPIN())

		output, err, _ := signOnce(provider, route())
		if err == nil {
			t.Fatalf("a signature the card returned WITH an error was handed back: %q — it is non-empty, so the "+
				"length half of this guard passes it, and a caller cannot tell a partial signature from a whole one", output)
		}
		if len(output) != 0 {
			t.Fatalf("output = %q, want nothing", output)
		}
	})

	t.Run("nothing returned without an error", func(t *testing.T) {
		session := boundaryCard()
		session.signValue, session.signErr, session.signSet = nil, nil, true
		provider := providerOver(t, session, nil, sixDigitPIN())

		output, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
		if err == nil {
			t.Fatalf("an empty signature was returned as a success (%d bytes) — nothing errored, so the error half "+
				"of this guard passes it, and an empty signature verifies against nothing while looking like a "+
				"completed operation", len(output))
		}
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	})
}

// ----------------------------------------------------------------------------
// provider.go:165 op0 `err != nil` in Healthy
// ----------------------------------------------------------------------------

// Healthy's "the card cannot be opened" case passes a nil session with the
// error, so the sibling `session == nil` refused the same input and the error
// operand was never measured. A driver that returns a usable session ALONGSIDE
// an error separates them.
//
// Falsifier: :165 op0 -> `(false && err != nil)`. Sole failure.
func TestHealthyRefusesAnOpenThatReturnsSessionAndError(t *testing.T) {
	session := boundaryCard()
	session.retries, session.retriesSet = 3, true
	provider := providerOver(t, session, errors.New("device busy"), sixDigitPIN())

	if provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("a card whose Open reported an error was reported healthy because the session it also returned " +
			"answered every probe — readiness is what decides whether the load balancer sends this device traffic")
	}

	// Control: the same session with no Open error IS healthy, so the refusal
	// above is attributable to the error and not to the fixture.
	if !providerOver(t, session, nil, sixDigitPIN()).Healthy(context.Background(), route().Binding) {
		t.Fatal("the same session without an Open error was also reported unhealthy — the fixture is not what " +
			"this test thinks it is and the refusal above proves nothing")
	}
}

// ----------------------------------------------------------------------------
// provider.go:181 op1 `provider.driver != nil` in Ready
// ----------------------------------------------------------------------------

// A BOUND NAMED ON ONE SIDE ONLY, INSIDE A SINGLE TEST.
//
// TestReadyRequiresADriverAPINSourceAndAReadyDriver isolates the PIN source
// (driver present, pins nil) but never isolates the driver: its no-driver case
// is `&Provider{}`, where pins is nil too, so the pins operand refuses the same
// input and the driver operand is never the sole refuser.
//
// Falsifier: :181 op1 -> `(true || provider.driver != nil)`. Ready then calls
// Ready on a nil driver interface, which panics; the panic is caught here so
// the failure is one named test rather than an aborted binary.
func TestReadyRefusesAProviderWithAPINSourceAndNoDriver(t *testing.T) {
	provider := &Provider{pins: sixDigitPIN()}

	var escaped any
	var ready bool
	func() {
		defer func() { escaped = recover() }()
		ready = provider.Ready(context.Background())
	}()

	if escaped != nil {
		t.Fatalf("Ready called through a nil driver and panicked (%v) — the nil check is what stops the call, "+
			"and readiness is probed by /v1/health/ready, so its absence is a crash on a health endpoint", escaped)
	}
	if ready {
		t.Fatal("a provider with a PIN source and no driver reported ready")
	}
}
