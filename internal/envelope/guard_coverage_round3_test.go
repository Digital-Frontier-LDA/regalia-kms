package envelope

// ROUND 3 of the #237 mutation sweep over this package: 42 guard sites, 73 leaf operands,
// enumerated with tools/guardenum (go/ast) and neutralised one operand at a time against
// internal/envelope plus every package whose test closure reaches it (internal/operations,
// internal/secrets, internal/integration, cmd/regalia-kms).
//
// Sixteen operands survived. Five of them a fixture can reach, and each test below closes
// exactly one; each was falsified by re-applying its own mutation and confirming this test was
// the SOLE failure across all five packages. Re-running the sweep afterwards moved the tally
// from 54 killed / 16 survivors to 59 killed / 11 survivors, which is the only evidence that
// these five tests are gates rather than documentation.
//
// THE ELEVEN THAT REMAIN, and why each is not a gap. A survivor is an UNTESTED operand, never
// a defect; the question for each is whether a fixture could distinguish its presence at all.
//
//	Seal:68[4]   createdAt.IsZero()        The first of two refusals for the same property.
//	SealAssembled:150[5]                   validateEnvelopeMetadata:336[3] checks it again on
//	                                       the very next statement and IS killed, so no input
//	                                       reaches a different outcome. Named in envelope.go's
//	                                       own comment and pinned at the metadata layer by
//	                                       TestParseRefusesAnEnvelopeNamingACreatedAtBeforeTheClockStarted.
//
//	Seal:84[0]   err != nil (newAEAD)      Dead: all four call sites pin len(dataKey) == 32
//	SealAssembled:171[0]                   before calling, and aes.NewCipher cannot fail on a
//	Open:234[0]                            32-byte key. newAEAD never returns an error here.
//	Rewrap:285[0]
//
//	newAEAD:368[0] err != nil              Reachable only by calling the unexported helper
//	                                       directly with a key length no caller can produce.
//	                                       Measured with the operand gone: newAEAD(17-byte key)
//	                                       PANICS with a nil pointer dereference inside
//	                                       cipher.NewGCM rather than admitting anything. A test
//	                                       there would be a panic detector, not a refusal gate,
//	                                       and would make every future sweep of this operand
//	                                       report PANIC — a truncated, lower-bound failing set —
//	                                       in place of a clean verdict.
//
//	Parse:188[0] len(encoded) == 0         Measured with the operand gone: Parse(nil) and
//	                                       Parse([]byte{}) still return ErrInvalidEnvelope,
//	                                       because the json decoder answers io.EOF and
//	                                       Parse:194 refuses on it. Same error, same boundary.
//
//	Parse:188[1]  len(encoded) > cap       Resource bounds, not validity bounds. The largest
//	Marshal:212[1] len(encoded) > cap      envelope validateEnvelope admits encodes to roughly
//	                                       1.49 MB against a 2 MB cap, so nothing that reaches
//	                                       Marshal can exceed it, and an oversized input to
//	                                       Parse is refused downstream anyway — measured:
//	                                       Parse(2097153 junk bytes) with the operand gone still
//	                                       returns ErrInvalidEnvelope. What the guards buy is
//	                                       the work NOT done before that refusal, which no
//	                                       behavioural assertion can observe. The Marshal side
//	                                       is already recorded in
//	                                       TestMarshalReturnsNoBytesWhenTheEnvelopeCannotBeEncoded.
//
//	Peek:261[0]  parsed.KEK.Version == ""  Unreachable: Parse runs first and validateKeyRef
//	                                       refuses an empty Version, so Peek never sees one.
//	                                       Already argued and pinned where the guarantee lives,
//	                                       by TestAnEnvelopeWithNoKEKVersionCannotBeParsedAtAll.
//
// Every test here is anchor + gate: the anchor is a control that must pass, so a validator
// that refused everything could not satisfy the gate, and the gate names the measured
// consequence of the operand's absence rather than restating the source line.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// round3Device is the fixture backend for this file: a real AES-GCM wrap under a known key,
// so a wrap that succeeds proves the whole path ran rather than that a stub said yes.
func round3Device(t *testing.T) (*fakeHardware, KeyRef) {
	t.Helper()
	device := hardware("nitrokey-pkcs11", map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)})
	return device, KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"}
}

// TestSealRefusesAnEmptySecretTheSameWaySealAssembledDoes closes the `len(plaintext) == 0`
// operand of Seal's entry guard.
//
// The rule was asserted on one side only. seal_assembled_test.go's boundary test opens with
// "Seal in this package refuses len(plaintext) == 0; SealAssembled must agree" and then pins
// only SealAssembled's 17-byte ciphertext floor. Nothing called Seal with an empty secret, so
// the operand the comment cites as the authority was itself untested.
//
// Measured with that operand neutralised, and this is why reading the code does not find it:
// nothing looks broken downstream. Seal returns err = nil and a STRUCTURALLY VALID envelope --
// a 12-byte nonce, a 60-byte wrapped data key, and a 16-byte ciphertext that is exactly a GCM
// tag over zero bytes. 16 is the syntactic floor validateEnvelope deliberately keeps (see the
// SIXTEEN IS DELIBERATE comment in envelope.go), so the token marshals, Parses clean, and
// Opens to a zero-length secret. The KMS spends a hardware wrap on nothing and hands the
// operator a token that behaves like a real one until something tries to use the secret.
//
// Isolation: the other four operands of that guard cannot fire on this input -- an empty
// plaintext is not over MaxPlaintextBytes, the binding context is well under the cap, random
// is rand.Reader, and createdAt is a real time. The empty-plaintext operand is the only
// refuser Seal has for this call.
func TestSealRefusesAnEmptySecretTheSameWaySealAssembledDoes(t *testing.T) {
	device, kek := round3Device(t)
	objectID := "deployment-api-token"
	bindingContext := ReleaseContext(objectID, "deploy", "production")
	createdAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	// ANCHOR: one byte of plaintext must seal, and must produce the 17-byte ciphertext that
	// SealAssembled's floor accepts. Without this a Seal that refused everything would satisfy
	// the gate below, and the two entry points would agree only by both being broken.
	anchor, err := Seal(context.Background(), device, kek, objectID, bindingContext,
		[]byte("x"), rand.Reader, createdAt)
	if err != nil {
		t.Fatalf("anchor: Seal of a one-byte secret = %v, want nil — the gate below would prove nothing", err)
	}
	if len(anchor.Ciphertext) != 17 {
		t.Fatalf("anchor: a one-byte secret produced %d ciphertext bytes, want 17 (1 plaintext + 16 tag) — "+
			"the fixture is not sitting on the boundary this test claims", len(anchor.Ciphertext))
	}

	// GATE: the empty secret. Nothing else in Seal refuses it.
	sealed, err := Seal(context.Background(), device, kek, objectID, bindingContext,
		[]byte{}, rand.Reader, createdAt)
	if !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Seal of an empty secret = %v, want ErrInvalidEnvelope — SealAssembled refuses the "+
			"equivalent 16-byte ciphertext, and the two seal entry points must agree about whether an "+
			"empty secret is sealable", err)
	}
	// Errorf above, then this: with the operand gone BOTH halves are wrong, and the returned
	// envelope is the half that names the failure mode. A Fatalf would hide it.
	if len(sealed.Ciphertext) != 0 || len(sealed.WrappedDataKey) != 0 {
		t.Errorf("Seal returned an envelope alongside its refusal: %d ciphertext bytes, %d wrapped-key bytes. "+
			"A 16-byte ciphertext is a GCM tag over nothing, it clears validateEnvelope's 16-byte syntactic "+
			"floor, and the resulting token Parses and Opens to a zero-length secret",
			len(sealed.Ciphertext), len(sealed.WrappedDataKey))
	}
	if device.calls != 1 {
		t.Errorf("the backend was asked to wrap %d times, want 1 (the anchor only) — an empty secret must "+
			"not spend a hardware wrap", device.calls)
	}
}

// TestMarshalWillNotEmitATokenParseWouldRefuse closes the `err != nil` operand on Marshal's
// validateEnvelope call.
//
// TestMarshalReturnsNoBytesWhenTheEnvelopeCannotBeEncoded pins Marshal's OTHER refusal, the
// json.Marshal result guard, using an envelope that is valid but carries a year-10000
// timestamp. That fixture passes validateEnvelope by construction, so it says nothing about
// what happens when validateEnvelope refuses -- which is this operand.
//
// Measured with it neutralised: Envelope{}.Marshal() returns err = nil and 218 bytes of
// {"version":0,...,"ciphertext_base64":null}. coordinator.seal writes Marshal's return value
// out as the sealed secret, so the failure mode is a well-formed-looking JSON token on disk
// that this package's own Parse then refuses -- a writer and a reader that disagree, with the
// disagreement discovered at release time rather than at seal time.
//
// Isolation: each row is invalid in exactly one way and encodes without complaint, so
// validateEnvelope is the only refuser Marshal has for it. The json.Marshal guard cannot fire
// on any of them.
func TestMarshalWillNotEmitATokenParseWouldRefuse(t *testing.T) {
	device, kek := round3Device(t)
	objectID := "deployment-api-token"
	bindingContext := ReleaseContext(objectID, "deploy", "production")
	createdAt := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	valid, err := Seal(context.Background(), device, kek, objectID, bindingContext,
		[]byte("top-secret-value"), rand.Reader, createdAt)
	if err != nil {
		t.Fatal(err)
	}

	// ANCHOR: the well-formed envelope must marshal to a token that Parses back. Without it a
	// Marshal that refused everything would satisfy every row below.
	encoded, err := valid.Marshal()
	if err != nil {
		t.Fatalf("anchor: Marshal of a sealed envelope = %v, want nil", err)
	}
	if _, err := Parse(encoded); err != nil {
		t.Fatalf("anchor: Parse of the token Marshal just produced = %v, want nil", err)
	}

	broken := map[string]func(Envelope) Envelope{
		"the zero envelope": func(Envelope) Envelope { return Envelope{} },
		"a nonce GCM cannot use": func(e Envelope) Envelope {
			e.Nonce = e.Nonce[:11]
			return e
		},
		"a wrapped data key the card never returned": func(e Envelope) Envelope {
			e.WrappedDataKey = nil
			return e
		},
		"a context digest that is not a digest": func(e Envelope) Envelope {
			e.ContextDigest = "sha256:not-a-digest"
			return e
		},
	}
	for name, break_ := range broken {
		t.Run(name, func(t *testing.T) {
			subject := break_(valid.Clone())
			// The fixture must be one Parse refuses, or the row asserts nothing about Marshal.
			if blob, err := json.Marshal(subject); err != nil {
				t.Fatalf("fixture does not encode (%v) — this row would exercise Marshal's "+
					"json guard, not its validation guard", err)
			} else if _, err := Parse(blob); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("fixture Parses cleanly (%v) — it is not an invalid envelope and the row "+
					"proves nothing", err)
			}

			emitted, err := subject.Marshal()
			if !errors.Is(err, ErrInvalidEnvelope) {
				t.Errorf("Marshal = %v, want ErrInvalidEnvelope", err)
			}
			if len(emitted) != 0 {
				t.Errorf("Marshal emitted %d bytes for an envelope Parse refuses: %q. coordinator.seal "+
					"writes this value out as the sealed secret, so the writer and the reader would "+
					"disagree and the disagreement would surface at release time", len(emitted), emitted)
			}
		})
	}
}

// TestAContextDigestMustNameSHA256AndNotJustAnyAlgorithm closes the
// `envelope.ContextDigest[:7] != "sha256:"` operand.
//
// This is the other half of the bound TestAContextDigestMustBeHexNotJustTheRightShape names.
// That test defeats the hex decode with "sha256:" + 64 'z'. The prefix comparison beside it
// had no such fixture, and the two are independent: a digest can be the right length and
// perfectly valid hex while naming a different algorithm.
//
// Measured with the prefix operand neutralised, on "sha512:" + 64 hex characters:
//
//	validateEnvelopeMetadata -> <nil>
//	Parse                    -> <nil>
//
// Both accept it. contextDigest only ever produces "sha256:", so an accepted "sha512:" digest
// can never equal a digest this package computes -- the envelope is one no bindingContext can
// open, and Open/Rewrap answer ErrInvalidEnvelope from the constant-time comparison instead of
// from the parser. The prefix is also what makes the field self-describing: dropping it lets a
// stored envelope claim an algorithm the code does not implement, and nothing at the parse
// boundary contradicts the claim.
//
// Isolation: the fixture is exactly 71 characters (so the length operand beside it passes) and
// its last 64 characters decode as hex (so the hex check below it passes). The prefix
// comparison is the only refuser left.
func TestAContextDigestMustNameSHA256AndNotJustAnyAlgorithm(t *testing.T) {
	objectID := "deployment-api-token"
	realDigest := contextDigest(ReleaseContext(objectID, "deploy", "production"))

	// ANCHOR: the genuine digest must pass, or a validator refusing every digest would satisfy
	// the gate below.
	if err := validateEnvelopeMetadata(digestFixture(t, realDigest), nil); err != nil {
		t.Fatalf("anchor: validateEnvelopeMetadata(real digest) = %v, want nil", err)
	}

	// The fixture: same length, same hex body, different algorithm name.
	wrongAlgorithm := "sha512:" + realDigest[len("sha256:"):]
	if len(wrongAlgorithm) != len(realDigest) {
		t.Fatalf("fixture is %d characters against a real digest's %d — the length operand would "+
			"refuse it and the prefix comparison would never be reached", len(wrongAlgorithm), len(realDigest))
	}
	if strings.HasPrefix(wrongAlgorithm, "sha256:") {
		t.Fatal("fixture still names sha256 — it is not a counterexample to anything")
	}

	// GATE, at the validator and at the boundary that calls it.
	subject := digestFixture(t, wrongAlgorithm)
	if err := validateEnvelopeMetadata(subject, nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("validateEnvelopeMetadata(%q) = %v, want ErrInvalidEnvelope — the body is valid hex of "+
			"the right length, so only the prefix comparison stands between this and an accepted envelope",
			wrongAlgorithm, err)
	}
	blob, err := json.Marshal(subject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(blob); !errors.Is(err, ErrInvalidEnvelope) {
		t.Errorf("Parse(envelope naming a %q digest) = %v, want ErrInvalidEnvelope — contextDigest only "+
			"ever produces \"sha256:\", so an accepted envelope of this shape is one no binding context "+
			"can ever open", wrongAlgorithm[:7], err)
	}
}

// TestTheKEKIDIsBoundedByTheSamePatternTheObjectIDIs closes the
// `!objectIDPattern.MatchString(ref.ID)` operand of validateKeyRef.
//
// The identical pattern check on envelope.ObjectID, one guard up in
// validateEnvelopeMetadata, is killed by the committed tests. The KEK's own ID was not: the
// bound was pinned on one side and not the other, and the untested side is the field the
// registry looks up to decide WHICH key object on WHICH card to reach.
//
// Measured with the operand neutralised, every one of these validates and Parses clean:
//
//	""                     -> validateKeyRef <nil>, Parse <nil>
//	"x"                    -> validateKeyRef <nil>, Parse <nil>
//	"../../../etc/passwd"  -> validateKeyRef <nil>, Parse <nil>
//	"COMPANY-KEK"          -> validateKeyRef <nil>, Parse <nil>
//
// Isolation: every row keeps Version "1" (which keyVersionPattern accepts) and Backend
// "nitrokey-pkcs11" (which hardwareBackend accepts), so the ID pattern is the only operand of
// that guard that can refuse the row. wrapper is nil, so the backend-agreement guard below it
// cannot fire either.
func TestTheKEKIDIsBoundedByTheSamePatternTheObjectIDIs(t *testing.T) {
	objectID := "deployment-api-token"
	digest := contextDigest(ReleaseContext(objectID, "deploy", "production"))

	// ANCHOR: a well-formed KEK ID must be accepted, at the validator and through Parse.
	good := KeyRef{Backend: "nitrokey-pkcs11", ID: "company-kek", Version: "1"}
	if err := validateKeyRef(good, nil); err != nil {
		t.Fatalf("anchor: validateKeyRef(%q) = %v, want nil — a validator refusing every ID would "+
			"satisfy every row below", good.ID, err)
	}
	anchorEnvelope := digestFixture(t, digest)
	anchorEnvelope.KEK = good
	blob, err := json.Marshal(anchorEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(blob); err != nil {
		t.Fatalf("anchor: Parse of an envelope naming KEK id %q = %v, want nil", good.ID, err)
	}

	rejected := map[string]string{
		"empty":                     "",
		"one character":             "x",
		"two characters":            "ab",
		"path traversal":            "../../../etc/passwd",
		"uppercase":                 "COMPANY-KEK",
		"leading hyphen":            "-company-kek",
		"a NUL inside the id":       "company\x00kek",
		"sixty-four characters":     strings.Repeat("a", 64),
		"whitespace around a valid": " company-kek ",
	}
	for name, id := range rejected {
		t.Run(name, func(t *testing.T) {
			ref := KeyRef{Backend: "nitrokey-pkcs11", ID: id, Version: "1"}
			if err := validateKeyRef(ref, nil); !errors.Is(err, ErrInvalidEnvelope) {
				t.Errorf("validateKeyRef(id=%q) = %v, want ErrInvalidEnvelope — the KEK id is what the "+
					"registry resolves to a card and a key object, and objectIDPattern is the only thing "+
					"bounding it", id, err)
			}
			subject := digestFixture(t, digest)
			subject.KEK = ref
			encoded, err := json.Marshal(subject)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Parse(encoded); !errors.Is(err, ErrInvalidEnvelope) {
				t.Errorf("Parse(envelope naming KEK id %q) = %v, want ErrInvalidEnvelope", id, err)
			}
		})
	}
}

// TestEveryBackendTheRegistryRoutesToIsABackendAnEnvelopeMayName closes the
// `value == "yubikey-openpgp"` operand of hardwareBackend.
//
// Its two siblings are killed by the committed tests; the third arm was not. The one place
// "yubikey-openpgp" appears in this package's tests is seal_assembled_test.go, where it is the
// MISMATCHED backend in a KeyRef-versus-wrapper disagreement -- a fixture that expects a
// refusal, and therefore one that stays green when the arm stops recognising the value at all.
// That is why the operand survived a sweep of a package whose backend list looks exhaustively
// tested.
//
// The direction of the defect is refusal, not admission: with the arm gone,
// hardwareBackend("yubikey-openpgp") returns false and Parse answers ErrInvalidEnvelope for a
// legitimately routable envelope. registry.go carries capability entries for yubikey-openpgp
// and routes to it, and RUNBOOK-DISASTER-RECOVERY records yubikey-openpgp objects as carrying
// hardware custody, so envelopes naming it exist and must open. A KMS that refuses to parse
// them loses the secrets rather than leaking them -- which is the failure a refusal-side sweep
// is least likely to notice, because every negative test still passes.
//
// Isolation: each accepted row keeps a valid ID and Version, so hardwareBackend is the only
// operand of validateKeyRef that decides it.
func TestEveryBackendTheRegistryRoutesToIsABackendAnEnvelopeMayName(t *testing.T) {
	objectID := "deployment-api-token"
	digest := contextDigest(ReleaseContext(objectID, "deploy", "production"))

	parseWithBackend := func(t *testing.T, backend string) error {
		t.Helper()
		subject := digestFixture(t, digest)
		subject.KEK = KeyRef{Backend: backend, ID: "company-kek", Version: "1"}
		encoded, err := json.Marshal(subject)
		if err != nil {
			t.Fatal(err)
		}
		_, parseErr := Parse(encoded)
		return parseErr
	}

	// ANCHOR: something must still be refused, or a hardwareBackend that answered true for
	// every string would satisfy the accepted rows below.
	for _, backend := range []string{"", "software", "vault-transit", "nitrokey", "yubikey"} {
		if !errors.Is(parseWithBackend(t, backend), ErrInvalidEnvelope) {
			t.Fatalf("anchor: Parse accepted backend %q — hardwareBackend is not discriminating and the "+
				"accepted rows below would prove nothing", backend)
		}
		if hardwareBackend(backend) {
			t.Fatalf("anchor: hardwareBackend(%q) = true, want false", backend)
		}
	}

	// GATE: all three hardware backends. The registry routes to each of them, so each must
	// survive a round trip through this package.
	for _, backend := range []string{"nitrokey-pkcs11", "yubikey-piv", "yubikey-openpgp"} {
		t.Run(backend, func(t *testing.T) {
			if !hardwareBackend(backend) {
				t.Errorf("hardwareBackend(%q) = false — the registry has a capability entry for this "+
					"backend and routes bindings to it", backend)
			}
			if err := parseWithBackend(t, backend); err != nil {
				t.Errorf("Parse(envelope naming backend %q) = %v, want nil — envelopes sealed against "+
					"this backend already exist and a refusal here loses them", backend, err)
			}
		})
	}
}
