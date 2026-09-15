package certs

// THE ENTRY GUARDS NOTHING CALLED (#237 sweep). Every operand pinned here survived because
// the suite only ever reaches these functions through a well-formed fixture: a real issuer,
// a real card, a real signer-opts. The guards decide what happens when one of those is
// absent, and absent is the one shape no test constructed.
//
// FOUR OF THE FIVE ARE THE ONLY THING BETWEEN THE CALL AND A NIL DEREFERENCE, so the
// mutant does not return a wrong answer -- it takes the process down. That is why each
// case below catches the panic and reports it as the failure rather than letting it
// propagate: an unrecovered panic aborts the whole test binary, which truncates the failing
// set and makes the mutation look like it killed more than it did.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// errNoisyToken is a fault a real token can report while still answering with a key.
var errNoisyToken = errors.New("pkcs11: CKR_DEVICE_ERROR")

// noisyCard answers exactly like fakeCard but can return a key AND an error from the same
// public-key call.
//
// fakeCard cannot express that: its publicErr path returns a nil key alongside the error, so
// the two operands of `err != nil || len(publicKey) == 0` always fire together and neither can
// be shown to matter on its own. One fixture, two operands, pins neither.
type noisyCard struct {
	inner     *fakeCard
	publicErr error
}

func (card *noisyCard) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) ([]byte, string, error) {
	key, mediaType, err := card.inner.Execute(ctx, route, operation, format, contentType, data, aad)
	if operation == "public-key" && card.publicErr != nil {
		return key, mediaType, card.publicErr
	}
	return key, mediaType, err
}

// callCatchingPanic runs call and reports a panic as a value rather than letting it escape.
//
// It returns the panic instead of failing here so the CALLER names what was being protected;
// a shared helper saying "it panicked" would print the same sentence for five different
// defects.
func callCatchingPanic(call func() error) (err error, panicked any) {
	defer func() { panicked = recover() }()
	err = call()
	return err, nil
}

// TestNewIssuerRequiresAClock pins issuer.go's `now == nil`.
//
// TestIssuerRefusesIncompleteConfiguration is the test named for this property and covers
// the other three operands of the same condition -- backend, certificate, and both profile
// clauses -- but never passes a nil clock. MEASURED WITH THE OPERAND NEUTRALISED: NewIssuer
// returns a usable *Issuer, and the nil func value is not reached until a certificate-sign
// arrives in production, where `issuer.now()` takes the daemon down mid-request.
func TestNewIssuerRequiresAClock(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, caKey, time.Now().Add(time.Hour))
	card := &fakeCard{key: caKey, t: t}

	if issuer, err := NewIssuer(card, ca, staging(), nil); err == nil {
		t.Fatalf("NewIssuer accepted a nil clock and returned %#v — the absent func is not reached "+
			"until the first certificate-sign, so the daemon starts, reports itself configured, and "+
			"panics on the first request that uses it", issuer)
	}

	// THE CONTROL: the same arguments with a real clock still build, so the refusal above is
	// about the clock and not about a constructor that has started refusing everything.
	if _, err := NewIssuer(card, ca, staging(), time.Now); err != nil {
		t.Fatalf("control: a fully configured issuer was refused: %v", err)
	}
}

// TestANilIssuerAndANilBackendAreRefusedRatherThanDereferenced pins BOTH operands of
// issuer.go's `issuer == nil || issuer.inner == nil`.
//
// The two are separate deployment states and neither is reached by any existing test:
//
//	issuer == nil        a coordinator holding an *Issuer it never assigned
//	issuer.inner == nil  an Issuer value built without going through the constructors,
//	                     which is what a zero value in a struct literal produces
//
// MEASURED, each with its own operand neutralised: both panic with a nil dereference —
// the first on `issuer.inner`, the second on `issuer.inner.Execute`. ErrUnavailable is a
// refusal the coordinator classifies and fails over from; a panic is not.
func TestANilIssuerAndANilBackendAreRefusedRatherThanDereferenced(t *testing.T) {
	for _, test := range []struct {
		name   string
		issuer *Issuer
		what   string
	}{
		{"a nil issuer", nil, "issuer == nil"},
		{"an issuer with no backend", &Issuer{}, "issuer.inner == nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			// A passthrough operation, so the certificate-sign branch is not what answers:
			// this is the entry guard, and it must hold for every operation.
			err, panicked := callCatchingPanic(func() error {
				_, _, err := test.issuer.Execute(t.Context(), registry.Route{}, "unwrap", "", "", []byte("x"), nil)
				return err
			})
			if panicked != nil {
				t.Fatalf("Execute on %s panicked (%v) — `%s` is the only thing between the "+
					"coordinator's call and a nil dereference, and a panic is not a refusal it "+
					"can classify or fail over from", test.name, panicked, test.what)
			}
			if err == nil {
				t.Fatalf("Execute on %s returned no error", test.name)
			}
		})
	}

	// THE CONTROL: a properly built issuer still forwards the same operation, so the
	// refusals above are not an Execute that refuses everything.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewPassthrough(&fakeCard{key: caKey, t: t})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.Execute(t.Context(), registry.Route{}, "unwrap", "", "", []byte("x"), nil); err != nil {
		t.Fatalf("control: a real issuer refused a passthrough operation: %v", err)
	}
}

// TestATokenErrorIsNotOverriddenByTheKeyItAlsoReturned pins issuer.go's `err != nil` on the
// public-key call.
//
// TestIssuerDistinguishesHardwareFailureFromABadRequest exercises this line with
// `card.publicErr` set, and does not pin it: that fake returns a nil key ALONGSIDE its
// error, so the sibling operand `len(publicKey) == 0` refuses the request either way and
// the test stays green with the error check gone.
//
// A real token need not be so tidy. MEASURED WITH THE OPERAND NEUTRALISED and a card that
// returns a key AND an error: the issuer ignores the error, parses the key, matches it
// against the CA certificate and ISSUES A CERTIFICATE — a signature produced on a token
// that has just reported a fault.
func TestATokenErrorIsNotOverriddenByTheKeyItAlsoReturned(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The card answers public-key with the RIGHT key and a fault at the same time. That is the
	// one combination the existing fake cannot express, and the only one that isolates this
	// operand from its sibling.
	card := &noisyCard{inner: &fakeCard{key: caKey, t: t}, publicErr: errNoisyToken}
	issuer, err := NewIssuer(card, ca, staging(), time.Now)
	if err != nil {
		t.Fatal(err)
	}

	certificate, _, err := issuer.Execute(t.Context(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", newCSR(t, "api.staging.internal", nil, subjectKey), nil)
	if len(certificate) != 0 {
		t.Fatalf("the token reported a fault on the public-key call and a %d-byte certificate was "+
			"issued anyway — the error was discarded because the key that came back with it looked "+
			"usable", len(certificate))
	}
	if err == nil {
		t.Fatal("a token fault on the public-key call produced no error")
	}

	// THE CONTROL: the same card without the fault issues, so the refusal above is
	// attributable to the error and not to the fixture.
	card.publicErr = nil
	control, _, err := issuer.Execute(t.Context(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", newCSR(t, "api.staging.internal", nil, subjectKey), nil)
	if err != nil || len(control) == 0 {
		t.Fatalf("control: a healthy token produced no certificate (%v) — every assertion above "+
			"would pass against an issuer that refuses everything", err)
	}
}

// TestTheTokensSigningFaultReachesTheCallerRatherThanBeingRelabelled pins issuer.go's
// `signErr != nil` inside the CardSigner closure.
//
// `fakeCard` has carried a `signErr` field since it was written and NO TEST HAS EVER SET IT.
// That is why the operand survived: the sign path is only ever driven by a card that works.
//
// MEASURED WITH THE OPERAND NEUTRALISED: the request is still refused, so `err != nil` sees
// nothing. What changes is which layer is blamed. The closure discards the token's error and
// returns a nil signature; CardSigner then finds zero bytes where a raw r||s pair should be
// and reports "card returned a malformed raw ECDSA signature". An operator reading that goes
// looking at the card's key material and its PKCS#11 encoding, when the card in fact said it
// had been removed. This is the same defect TestAnEmptyCardSignatureIsReportedAsMalformedRatherThanAsZero
// exists to prevent one layer down, arriving one layer up.
func TestTheTokensSigningFaultReachesTheCallerRatherThanBeingRelabelled(t *testing.T) {
	issuer, card, _ := issuerFixture(t)
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := newCSR(t, "api.staging.internal", nil, subjectKey)
	card.signErr = errors.New("pkcs11: CKR_DEVICE_REMOVED")

	certificate, _, err := issuer.Execute(t.Context(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", csr, nil)
	if len(certificate) != 0 {
		t.Fatalf("the card refused to sign and %d bytes of certificate came back", len(certificate))
	}
	if err == nil {
		t.Fatal("the card refused to sign and no error came back")
	}
	if !strings.Contains(err.Error(), "CKR_DEVICE_REMOVED") {
		t.Fatalf("the card said %q and the caller was told %q — the token's own fault was dropped "+
			"and the nil signature it left behind was relabelled by the encoding rules one layer "+
			"down, which sends an operator to the card's key material instead of to a card that "+
			"is not there", card.signErr, err)
	}

	// THE CONTROL: the same card without the fault still issues, so the refusal above is
	// attributable to signErr and not to the fixture.
	card.signErr = nil
	control, _, err := issuer.Execute(t.Context(), registry.Route{Algorithm: "p256"},
		"certificate-sign", "", "", csr, nil)
	if err != nil || len(control) == 0 {
		t.Fatalf("control: a healthy card produced no certificate: %v", err)
	}
}

// TestASigningFailureIsAnErrorRatherThanAnEmptyCertificate pins issue.go's `err != nil` on
// x509.CreateCertificate.
//
// MEASURED WITH THE OPERAND NEUTRALISED: Issue returns (nil, nil) — no certificate and no
// error. Every caller in this repository checks the error first, so a signing failure
// becomes a SUCCESS carrying zero bytes; Issuer.Execute would hand the coordinator an empty
// body with content type application/pkix-cert.
//
// Nothing else covers it. Issuer.Execute refuses a mismatched key before reaching Issue
// (TestAnIssuerKeyMismatchIsUnavailableRatherThanAnOpaqueX509Failure pins that guard), so
// Issue itself is never called with a signer crypto/x509 will reject. This calls it directly.
func TestASigningFailureIsAnErrorRatherThanAnEmptyCertificate(t *testing.T) {
	ca, matching, subjectKey := issuanceFixture(t)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// A perfectly functional card holding a key that is not the one the CA certificate names.
	// crypto/x509 refuses to sign with it; the operand decides whether we notice.
	mismatched := &CardSigner{PublicKey: stranger.Public(), Sign_: emulateCard(t, stranger)}
	csr := newCSR(t, "api.staging.internal", nil, subjectKey)

	der, err := Issue(ca, mismatched, csr, staging(), time.Now())
	if err == nil {
		t.Fatalf("Issue returned no error and %d bytes of certificate after crypto/x509 refused to "+
			"sign — every caller checks the error first, so a signing failure is delivered as a "+
			"successful issuance of nothing", len(der))
	}
	if len(der) != 0 {
		t.Fatalf("Issue returned both an error and %d bytes", len(der))
	}
	requireRefusal(t, err, "certificate signing failed")

	// THE CONTROL: the matching signer over the same CSR still produces a certificate.
	control, err := Issue(ca, matching, csr, staging(), time.Now())
	if err != nil || len(control) == 0 {
		t.Fatalf("control: the matching signer produced no certificate: %v", err)
	}
}

// TestTheCardSignerRefusesANilReceiverAndAbsentOptions pins signer.go's `signer == nil` and
// `opts == nil`.
//
// crypto.Signer is an interface, so both states are reachable from ordinary code: a nil
// *CardSigner stored in one, and a caller passing no SignerOpts. MEASURED, each operand
// neutralised on its own: the first dereferences `signer.Sign_` and the second calls
// `opts.HashFunc()` on a nil interface. Both panic.
//
// TestTheCardSignerRefusesAnythingButASHA256Digest covers the OTHER operand of the second
// condition -- a non-SHA-256 hash -- and always passes a real opts value.
func TestTheCardSignerRefusesANilReceiverAndAbsentOptions(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("tbs"))
	working := &CardSigner{PublicKey: key.Public(), Sign_: emulateCard(t, key)}

	// EVERY call goes through callCatchingPanic, including the message assertions. A Sign that
	// escapes with a live panic aborts the whole test BINARY, and a mutation run that aborts
	// reports a failing set that is only a lower bound — so the mutant this test exists to
	// detect would also hide how much else detected it.
	for _, test := range []struct {
		name   string
		signer *CardSigner
		opts   crypto.SignerOpts
		what   string
		wants  string
	}{
		{"a nil card signer", nil, crypto.SHA256, "signer == nil", "card signer is not configured"},
		{"no signer options", working, nil, "opts == nil", "only SHA-256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err, panicked := callCatchingPanic(func() error {
				_, err := test.signer.Sign(rand.Reader, digest[:], test.opts)
				return err
			})
			if panicked != nil {
				t.Fatalf("Sign with %s panicked (%v) — `%s` is the only thing in front of the "+
					"dereference, and crypto.Signer is an interface any caller may hold", test.name, panicked, test.what)
			}
			// The message too, so a refusal by the WRONG rule is still visible on a path where
			// several refusals share one condition.
			if err == nil || !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("Sign with %s was refused with %v, want a message containing %q", test.name, err, test.wants)
			}
		})
	}

	// THE CONTROL: the same signer with real options still signs.
	if _, err := working.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("control: a well-formed Sign call was refused: %v", err)
	}
}

// MEASURED AND DELIBERATELY NOT TESTED — the four survivors this file does not close.
//
// Where the claim is about a PAIR, the pair was neutralised together, because a masking claim
// cannot be tested one operand at a time: each survives only because the other still stands.
//
//	issue.go, Issue, `err != nil` on rand.Int
//	  UNREACHABLE BY ANY FIXTURE. rand.Int returns an error only when its bound is
//	  non-positive or its reader fails; the bound here is a literal 1<<127 and the reader is
//	  crypto/rand.Reader, which the standard library no longer allows to fail. No input to
//	  this package makes the branch run.
//
//	issuer.go, Execute, `len(publicKey) == 0` and `err != nil` on ParsePKIXPublicKey
//	  CANNOT BE THE SOLE REFUSER. Masked by `!matchesIssuerCertificate(parsed, ...)` two lines
//	  down, and this is measured rather than argued:
//
//	      both neutralised together            green
//	      both PLUS matchesIssuerCertificate   RED — TestAnIssuerKeyMismatchIsUnavailableRatherThanAnOpaqueX509Failure
//
//	  The differential is the point. The pair going green shows the two are redundant for
//	  every fixture that exists; the third mutation going red shows a mutation on this path
//	  CAN be detected, so the green above is a measurement and not a silent instrument. An
//	  empty or unparseable key leaves `parsed == nil`, and Equal(nil) is false for every
//	  standard-library key type, so the request is refused with the same ErrUnavailable.
//
//	issuer.go, matchesIssuerCertificate, `!ok`
//	  NOT REACHABLE FROM PRODUCTION. The assertion is to `interface{ Equal(crypto.PublicKey) bool }`,
//	  and every key type x509.ParseCertificate can produce — RSA, ECDSA, Ed25519, ECDH —
//	  implements it, so `ok` is always true. A test could force it only by hand-building an
//	  x509.Certificate around a key type of its own, which no certificate parse produces.
//	  Worth keeping rather than deleting: with the operand neutralised, that hypothetical
//	  value reaches `comparable.Equal(candidate)` on a nil interface, so the guard is what
//	  stands between a hand-built certificate and a panic. Recorded, not pinned — a test for
//	  it would assert on a state the daemon cannot construct.
