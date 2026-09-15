package openpgp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp"
)

// A REFUSED ROUTE NEVER REACHES THE CARD.
//
// This is the difference between a limit and a preference. A limit enforced after the card is open
// has already opened the card: it has selected a reader, presented a PIN or woken a token for an
// operation policy says may not happen, and on a card with a signature counter that is not a
// no-op. The driver here fails the test if anything calls Open, so the ordering is asserted rather
// than read off the source.
//
// Every row is a refusal from a different rule, so this doubles as the census: if a rule is added
// that fires after Open, it belongs above the Open call or in this list as a known exception.
//
// Falsifier: move the provider.driver.Open call above the Admit call in Execute. Every row fails,
// and nothing else in the package does.
func TestARefusedRouteNeverReachesTheCard(t *testing.T) {

	type refusal struct {
		name      string
		operation string
		format    string
		algorithm string
		object    string
		touch     string
		pin       string
		backend   string
		day       int
		want      error
	}
	base := refusal{operation: "sign", format: "", algorithm: "rsa2048", object: "approved-object",
		touch: "never", pin: "once", backend: openpgp.BackendName, day: 1}

	cases := []refusal{}
	for _, operation := range []string{"wrap", "seal-envelope", "certificate-sign", "key-agreement", "release-secret"} {
		row := base
		row.name = "operation not on this applet: " + operation
		row.operation = operation
		row.want = openpgp.ErrOperationNotOnThisApplet
		cases = append(cases, row)
	}
	unadvertised := base
	unadvertised.name = "algorithm the matrix does not advertise"
	unadvertised.algorithm = "p256"
	unadvertised.want = openpgp.ErrNotAdvertised
	cases = append(cases, unadvertised)

	unapproved := base
	unapproved.name = "no recorded approval for a pair a supported backend serves"
	unapproved.object = "object-with-no-exception"
	unapproved.want = openpgp.ErrExceptionRequired
	cases = append(cases, unapproved)

	expired := base
	expired.name = "approval expired"
	expired.day = 31
	expired.want = openpgp.ErrExceptionExpired
	cases = append(cases, expired)

	wrongBackend := base
	wrongBackend.name = "route names another backend"
	wrongBackend.backend = "nitrokey-pkcs11"
	wrongBackend.want = openpgp.ErrNotThisBackend
	cases = append(cases, wrongBackend)

	touchy := base
	touchy.name = "binding asks for touch"
	touchy.touch = "always"
	touchy.want = openpgp.ErrInteractionRequired
	cases = append(cases, touchy)

	newMaterial := base
	newMaterial.name = "unwrap presents a regalia envelope rather than legacy material"
	newMaterial.operation = "unwrap"
	newMaterial.algorithm = "cv25519"
	newMaterial.object = "unavoidable-object"
	newMaterial.format = "regalia-envelope-v2"
	newMaterial.want = openpgp.ErrLegacyMaterialRequired
	cases = append(cases, newMaterial)

	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			scoped, err := openpgp.New(forbiddenDriver{t: t}, admissionFor(t, row.day, "approved-object"))
			if err != nil {
				t.Fatalf("building the provider: %v", err)
			}
			route := legacyRoute(row.object, row.algorithm)
			route.Binding.Backend = row.backend
			route.Binding.TouchPolicy = row.touch
			route.Binding.PINPolicy = row.pin
			output, outputType, err := scoped.Execute(context.Background(), route, row.operation,
				row.format, "application/octet-stream", []byte("payload"), nil)
			if !errors.Is(err, row.want) {
				t.Fatalf("Execute = %v, want %v", err, row.want)
			}
			if output != nil || outputType != "" {
				t.Errorf("a refusal returned output %q of type %q; a refused operation produces nothing", output, outputType)
			}
		})
	}
}

// THE ADMITTED PATH REACHES THE CARD AND RETURNS WHAT THE CARD PRODUCED.
//
// Every refusal test above passes just as well against an Execute that refuses everything. This is
// the arm that says the adapter still works, and it is in its own test so a failure here reads as
// "the admitted path broke" rather than as one more refusal.
func TestTheAdmittedPathReachesTheCard(t *testing.T) {
	t.Run("sign", func(t *testing.T) {
		card := unattendedCard()
		provider := providerWith(t, card, admissionFor(t, 1, "approved-object"))
		output, outputType, err := provider.Execute(context.Background(),
			legacyRoute("approved-object", "ed25519"), "sign", "", "application/octet-stream", []byte("digest"), nil)
		if err != nil {
			t.Fatalf("Execute = %v, want the signature", err)
		}
		if string(output) != "signature-bytes" {
			t.Errorf("output = %q, want the card's signature", output)
		}
		if outputType != "application/octet-stream" {
			t.Errorf("outputType = %q, want the requested content type passed through", outputType)
		}
		if !called(card, "sign:ed25519") {
			t.Errorf("the card was asked for %v, not a signature over ed25519", card.calls)
		}
		if !called(card, "close") {
			t.Error("the card was not closed")
		}
	})
	t.Run("unwrap", func(t *testing.T) {
		card := unattendedCard()
		provider := providerWith(t, card, admissionFor(t, 1, "unavoidable-object"))
		output, outputType, err := provider.Execute(context.Background(),
			legacyRoute("unavoidable-object", "cv25519"), "unwrap", "sops-pgp", "application/octet-stream", []byte("wrapped"), nil)
		if err != nil {
			t.Fatalf("Execute = %v, want the recovered data key", err)
		}
		if string(output) != "recovered-data-key" {
			t.Errorf("output = %q, want the card's plaintext", output)
		}
		if outputType != "application/octet-stream" {
			t.Errorf("outputType = %q, want application/octet-stream", outputType)
		}
		if !called(card, "decipher:cv25519") {
			t.Errorf("the card was asked for %v, not a decipher over cv25519", card.calls)
		}
	})
}

// PW1 IS NOT PIV'S PIN, AND THE MANIFEST CANNOT SEE THE DIFFERENCE.
//
// A binding may say pin_policy: once — which registry.validateBinding accepts — while the card
// resets PW1 after every signature. The deployment is then not the one that was reviewed. The
// state applies to PSO:CDS alone, so the same card that cannot sign unattended can still decrypt
// unattended, and a per-card check would refuse a perfectly usable decryption key.
//
// All three arms are here on purpose: the refusal, the same card succeeding at the operation the
// flag does not govern, and the same card succeeding at signing once the binding stops claiming
// something the card does not do.
//
// Falsifier: delete the SignaturePINValidForMultipleSignatures check in unattended() and the first
// arm fails alone. Widen it to both slots and the second fails alone.
func TestAPinOnceBindingIsRefusedOnACardThatResetsPW1AfterOneSignature(t *testing.T) {
	forced := func() *fakeCard {
		card := unattendedCard()
		card.status.SignaturePINValidForMultipleSignatures = false
		return card
	}

	t.Run("signing is refused", func(t *testing.T) {
		provider := providerWith(t, forced(), admissionFor(t, 1, "approved-object"))
		_, _, err := provider.Execute(context.Background(),
			legacyRoute("approved-object", "ed25519"), "sign", "", "application/octet-stream", []byte("digest"), nil)
		if !errors.Is(err, openpgp.ErrCardContradictsBinding) {
			t.Fatalf("Execute = %v, want ErrCardContradictsBinding: the binding promised the PIN holds and the card resets it", err)
		}
	})
	t.Run("decryption on the same card is unaffected", func(t *testing.T) {
		provider := providerWith(t, forced(), admissionFor(t, 1, "unavoidable-object"))
		if _, _, err := provider.Execute(context.Background(),
			legacyRoute("unavoidable-object", "cv25519"), "unwrap", "sops-pgp", "application/octet-stream", []byte("wrapped"), nil); err != nil {
			t.Fatalf("Execute = %v, want the data key: PW1's multiple-signature state governs PSO:CDS, not PSO:DEC", err)
		}
	})
	t.Run("pin_policy always claims nothing the card contradicts", func(t *testing.T) {
		route := legacyRoute("approved-object", "ed25519")
		route.Binding.PINPolicy = "always"
		provider := providerWith(t, forced(), admissionFor(t, 1, "approved-object"))
		if _, _, err := provider.Execute(context.Background(), route, "sign", "", "application/octet-stream", []byte("digest"), nil); err != nil {
			t.Fatalf("Execute = %v, want the signature: pin_policy=always makes no claim the card can contradict", err)
		}
	})
}

// THE USER INTERACTION FLAG REFUSES THE SLOT IT GUARDS AND ONLY THAT SLOT.
//
// Both directions, because a check written against one slot and applied to both looks correct from
// either single-slot test. A card may carry a touch-gated signature key beside an untouched
// decryption key, and refusing the whole card for that would strand the migration this backend
// exists to serve.
func TestTouchOnTheCardRefusesTheSlotItGuardsAndNotTheOther(t *testing.T) {
	sign := func(t *testing.T, card *fakeCard) error {
		t.Helper()
		provider := providerWith(t, card, admissionFor(t, 1, "approved-object"))
		_, _, err := provider.Execute(context.Background(),
			legacyRoute("approved-object", "ed25519"), "sign", "", "application/octet-stream", []byte("digest"), nil)
		return err
	}
	unwrap := func(t *testing.T, card *fakeCard) error {
		t.Helper()
		provider := providerWith(t, card, admissionFor(t, 1, "unavoidable-object"))
		_, _, err := provider.Execute(context.Background(),
			legacyRoute("unavoidable-object", "cv25519"), "unwrap", "sops-pgp", "application/octet-stream", []byte("wrapped"), nil)
		return err
	}

	t.Run("touch on the signature key", func(t *testing.T) {
		card := unattendedCard()
		card.status.TouchRequiredForSignature = true
		if err := sign(t, card); !errors.Is(err, openpgp.ErrInteractionRequired) {
			t.Errorf("sign = %v, want ErrInteractionRequired", err)
		}
		other := unattendedCard()
		other.status.TouchRequiredForSignature = true
		if err := unwrap(t, other); err != nil {
			t.Errorf("unwrap = %v, want the data key: the flag is set on the other key", err)
		}
	})
	t.Run("touch on the decryption key", func(t *testing.T) {
		card := unattendedCard()
		card.status.TouchRequiredForDecryption = true
		if err := unwrap(t, card); !errors.Is(err, openpgp.ErrInteractionRequired) {
			t.Errorf("unwrap = %v, want ErrInteractionRequired", err)
		}
		other := unattendedCard()
		other.status.TouchRequiredForDecryption = true
		if err := sign(t, other); err != nil {
			t.Errorf("sign = %v, want the signature: the flag is set on the other key", err)
		}
	})
}

// THE CARD IN THE SLOT MUST BE THE CARD THE MANIFEST PINNED.
func TestTheCardSerialMustMatchThePinnedSerial(t *testing.T) {
	card := unattendedCard()
	card.status.Serial = "99999999"
	provider := providerWith(t, card, admissionFor(t, 1, "approved-object"))
	_, _, err := provider.Execute(context.Background(),
		legacyRoute("approved-object", "ed25519"), "sign", "", "application/octet-stream", []byte("digest"), nil)
	if !errors.Is(err, openpgp.ErrCardContradictsBinding) {
		t.Fatalf("Execute = %v, want ErrCardContradictsBinding", err)
	}
}

// UNWRAP OPENS LEGACY MATERIAL AND NOTHING ELSE.
//
// sops-pgp is the centralized SOPS integration point (api/README.md) and the reason this backend
// exists. regalia-envelope-v2 is what /v1/operations/wrap produces, and this adapter refuses wrap —
// so no regalia envelope can have been created against this applet, and one presented here is
// either a manifest error or an attempt to move new material onto the card being retired.
func TestUnwrapOpensLegacyMaterialOnly(t *testing.T) {
	for _, row := range []struct {
		format string
		admit  bool
	}{
		{"sops-pgp", true},
		{"regalia-envelope-v2", false},
		{"", false},
		{"application/octet-stream", false},
	} {
		t.Run("format="+row.format, func(t *testing.T) {
			provider := providerWith(t, unattendedCard(), admissionFor(t, 1, "unavoidable-object"))
			_, _, err := provider.Execute(context.Background(),
				legacyRoute("unavoidable-object", "cv25519"), "unwrap", row.format, "application/octet-stream", []byte("wrapped"), nil)
			switch {
			case row.admit && err != nil:
				t.Errorf("format %q = %v, want the data key", row.format, err)
			case !row.admit && !errors.Is(err, openpgp.ErrLegacyMaterialRequired):
				t.Errorf("format %q = %v, want ErrLegacyMaterialRequired", row.format, err)
			}
		})
	}
	// The format rule is for unwrap. Signing has no wrapped material and the yubikey and nitrokey
	// providers both ignore format for it; asserting that here stops a later "tighten the format
	// check" from silently refusing every signature.
	provider := providerWith(t, unattendedCard(), admissionFor(t, 1, "approved-object"))
	if _, _, err := provider.Execute(context.Background(),
		legacyRoute("approved-object", "ed25519"), "sign", "regalia-envelope-v2", "application/octet-stream", []byte("digest"), nil); err != nil {
		t.Errorf("sign with a format set = %v, want the signature: format describes wrapped material and signing has none", err)
	}
}

// A HARDWARE FAILURE IS REPORTED AS UNAVAILABLE, NOT AS A LIMIT.
//
// A caller that cannot tell the two apart reports a policy decision as an outage, which sends an
// operator to the bench for a config problem — or the reverse, which sends them to the config for
// a dead card.
func TestAHardwareFailureIsNotReportedAsALimit(t *testing.T) {
	for _, row := range []struct {
		name   string
		break_ func(*fakeCard, *fakeDriver)
	}{
		{"the card cannot be opened", func(_ *fakeCard, driver *fakeDriver) { driver.openErr = errors.New("no reader") }},
		{"status fails", func(card *fakeCard, _ *fakeDriver) { card.statusErr = errors.New("apdu error") }},
		{"the operation fails", func(card *fakeCard, _ *fakeDriver) { card.signErr = errors.New("apdu error") }},
		{"the card returns nothing", func(card *fakeCard, _ *fakeDriver) { card.signature = nil }},
		{"close fails", func(card *fakeCard, _ *fakeDriver) { card.closeErr = errors.New("reader vanished") }},
	} {
		t.Run(row.name, func(t *testing.T) {
			card := unattendedCard()
			driver := &fakeDriver{card: card}
			row.break_(card, driver)
			provider, err := openpgp.New(driver, admissionFor(t, 1, "approved-object"))
			if err != nil {
				t.Fatalf("building the provider: %v", err)
			}
			_, _, err = provider.Execute(context.Background(),
				legacyRoute("approved-object", "ed25519"), "sign", "", "application/octet-stream", []byte("digest"), nil)
			if !errors.Is(err, openpgp.ErrUnavailable) {
				t.Fatalf("Execute = %v, want ErrUnavailable", err)
			}
			if errors.Is(err, openpgp.ErrRefused) {
				t.Error("a hardware failure was reported as a refusal; an operator would go and read config")
			}
		})
	}
}

// A PROVIDER WITHOUT AN ADMISSION LAYER IS THE UNCONSTRAINED BACKEND THIS ISSUE EXISTS TO PREVENT.
//
// Reached by passing nil, which is why it is refused at construction rather than treated as "no
// exceptions configured". NewAdmission(nil, clock) already expresses that, at a call site somebody
// had to write.
func TestAProviderCannotBeBuiltWithoutItsLimits(t *testing.T) {
	if _, err := openpgp.New(&fakeDriver{card: unattendedCard()}, nil); err == nil {
		t.Error("a provider was built with no admission layer; every route would reach the card")
	}
	if _, err := openpgp.New(nil, admissionFor(t, 1)); err == nil {
		t.Error("a provider was built with no driver")
	}
}

// READINESS AND HEALTH ANSWER FALSE RATHER THAN PANICKING ON A ZERO PROVIDER.
func TestAZeroProviderIsNotReadyAndNotHealthy(t *testing.T) {
	var provider *openpgp.Provider
	if provider.Ready(context.Background()) {
		t.Error("a nil provider reported ready")
	}
	if provider.Healthy(context.Background(), legacyRoute("o", "ed25519").Binding) {
		t.Error("a nil provider reported healthy")
	}
	if _, _, err := provider.Execute(context.Background(), legacyRoute("o", "ed25519"), "sign", "", "", nil, nil); !errors.Is(err, openpgp.ErrUnavailable) {
		t.Errorf("a nil provider answered %v, want ErrUnavailable", err)
	}
}

// HEALTH IS FALSE WHEN EITHER KEY CANNOT BE USED UNATTENDED.
//
// Healthy is asked before an operation is chosen, so it has to answer for both slots the binding
// could reach. Reporting healthy and refusing at the operation is the worse of the two, because
// readiness is what an operator watches.
func TestHealthIsFalseWhenEitherKeyNeedsAHuman(t *testing.T) {
	binding := legacyRoute("approved-object", "ed25519").Binding
	healthy := providerWith(t, unattendedCard(), admissionFor(t, 1, "approved-object"))
	if !healthy.Healthy(context.Background(), binding) {
		t.Fatal("a card that honours the binding reported unhealthy; every row below would pass vacuously")
	}
	for _, row := range []struct {
		name   string
		break_ func(*fakeCard)
	}{
		{"touch on the signature key", func(card *fakeCard) { card.status.TouchRequiredForSignature = true }},
		{"touch on the decryption key", func(card *fakeCard) { card.status.TouchRequiredForDecryption = true }},
		{"PW1 resets after one signature", func(card *fakeCard) { card.status.SignaturePINValidForMultipleSignatures = false }},
		{"a different card is present", func(card *fakeCard) { card.status.Serial = "99999999" }},
	} {
		t.Run(row.name, func(t *testing.T) {
			card := unattendedCard()
			row.break_(card)
			if providerWith(t, card, admissionFor(t, 1, "approved-object")).Healthy(context.Background(), binding) {
				t.Error("reported healthy; readiness would say the card is usable unattended and the operation would refuse")
			}
		})
	}
	other := binding
	other.Backend = "nitrokey-pkcs11"
	if healthy.Healthy(context.Background(), other) {
		t.Error("reported healthy for another backend's binding")
	}
}

func called(card *fakeCard, want string) bool {
	for _, call := range card.calls {
		if call == want {
			return true
		}
	}
	return false
}
