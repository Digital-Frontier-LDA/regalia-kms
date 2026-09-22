package nitrokey

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

// attributeStub is a cryptoki that answers object lookups and returns a fixed attribute list.
//
// The embedded nil interface is deliberate: any method these tests do not stub panics rather than
// returning a usable zero value, so a guard that starts calling something new fails loudly here
// instead of quietly passing against a fake that invented an answer.
type attributeStub struct {
	cryptoki
	values []*pkcs11.Attribute
	getErr error
	// The token this stub claims to be. AssertKEKGeneratedOnToken asks, because CKA_LOCAL means
	// something different on an SC-HSM behind OpenSC — it tracks the certificate there, not the
	// key's origin (regalia#447). The embedded nil interface panicked when it was first asked.
	model        string
	manufacturer string
}

func (stub *attributeStub) GetTokenInfo(uint) (pkcs11.TokenInfo, error) {
	return pkcs11.TokenInfo{Model: stub.model, ManufacturerID: stub.manufacturer}, nil
}

func (*attributeStub) FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error { return nil }

func (*attributeStub) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	return []pkcs11.ObjectHandle{1}, false, nil
}

func (*attributeStub) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }

func (stub *attributeStub) GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return stub.values, stub.getErr
}

func boolAttribute(kind uint, value bool) *pkcs11.Attribute {
	raw := byte(0)
	if value {
		raw = 1
	}
	return &pkcs11.Attribute{Type: kind, Value: []byte{raw}}
}

func stubSession(values []*pkcs11.Attribute) *pkcs11Session {
	return &pkcs11Session{module: &attributeStub{values: values}, loggedIn: true}
}

// A TOKEN THAT DOES NOT PUBLISH THE ATTRIBUTE HAS NOT SAID THE KEY IS BAD.
//
// Both refusals are correct — an unprovable KEK must not be used. What must not happen is the
// refusal being dressed as a verdict: reported as ErrKEKNotTokenGenerated or ErrKEKExportable it
// reaches the operator as "kek-not-token-generated" / "kek-exportable" and sends them to
// re-provision a key that may be perfectly good. Refusing and diagnosing are separable, and only
// the refusal is automatic.
//
// This is the branch that could not be reached through SoftHSM, which returns all three attributes
// for every key the e2e provisions. It is reachable here because cryptoki is an interface.
func TestAnAbsentAttributeRefusesWithoutClaimingAVerdict(t *testing.T) {
	for _, absent := range []struct {
		what       string
		values     []*pkcs11.Attribute
		call       func(*pkcs11Session) error
		definitive error
	}{
		{
			"CKA_LOCAL missing",
			nil,
			func(s *pkcs11Session) error { return s.AssertKEKGeneratedOnToken(context.Background(), "02") },
			ErrKEKNotTokenGenerated,
		},
		{
			"CKA_EXTRACTABLE missing, CKA_SENSITIVE present",
			[]*pkcs11.Attribute{boolAttribute(pkcs11.CKA_SENSITIVE, true)},
			func(s *pkcs11Session) error { return s.AssertKEKNonExportable(context.Background(), "02") },
			ErrKEKExportable,
		},
		{
			"CKA_SENSITIVE missing, CKA_EXTRACTABLE present",
			[]*pkcs11.Attribute{boolAttribute(pkcs11.CKA_EXTRACTABLE, false)},
			func(s *pkcs11Session) error { return s.AssertKEKNonExportable(context.Background(), "02") },
			ErrKEKExportable,
		},
	} {
		t.Run(absent.what, func(t *testing.T) {
			err := absent.call(stubSession(absent.values))
			if err == nil {
				t.Fatal("used a KEK whose attributes the token did not supply")
			}
			if errors.Is(err, absent.definitive) {
				t.Fatalf("an unsupplied attribute was reported as %v, a verdict the token never gave", absent.definitive)
			}
		})
	}
}

// The controls. Without these the cases above are satisfied by a guard that refuses everything,
// and by one that reports every refusal as non-definitive including the real ones.
func TestPresentAttributesGiveDefinitiveAnswers(t *testing.T) {
	good := stubSession([]*pkcs11.Attribute{boolAttribute(pkcs11.CKA_LOCAL, true)})
	if err := good.AssertKEKGeneratedOnToken(context.Background(), "02"); err != nil {
		t.Fatalf("a token-generated KEK was refused: %v", err)
	}
	notLocal := stubSession([]*pkcs11.Attribute{boolAttribute(pkcs11.CKA_LOCAL, false)})
	if err := notLocal.AssertKEKGeneratedOnToken(context.Background(), "02"); !errors.Is(err, ErrKEKNotTokenGenerated) {
		t.Fatalf("CKA_LOCAL=false gave %v, want ErrKEKNotTokenGenerated", err)
	}

	sound := stubSession([]*pkcs11.Attribute{
		boolAttribute(pkcs11.CKA_SENSITIVE, true), boolAttribute(pkcs11.CKA_EXTRACTABLE, false),
	})
	if err := sound.AssertKEKNonExportable(context.Background(), "02"); err != nil {
		t.Fatalf("a non-exportable KEK was refused: %v", err)
	}
	// Sensitive AND extractable: the shape of the imported e2e key, and the reason checking
	// CKA_SENSITIVE alone is not enough.
	leaky := stubSession([]*pkcs11.Attribute{
		boolAttribute(pkcs11.CKA_SENSITIVE, true), boolAttribute(pkcs11.CKA_EXTRACTABLE, true),
	})
	if err := leaky.AssertKEKNonExportable(context.Background(), "02"); !errors.Is(err, ErrKEKExportable) {
		t.Fatalf("a sensitive-but-extractable KEK gave %v, want ErrKEKExportable", err)
	}
}

// A LOOKUP WITH NO CLASSES IS A PROGRAMMER ERROR, NOT AN EMPTY RESULT.
//
// Without the guard the loop never runs, lastErr stays nil, and the zero handle goes back as a
// success — so a caller that forgot its classes would hand handle 0 to GetAttributeValue and the
// guards would draw a conclusion about a key they never looked at. Handle 0 is not an object.
func TestAKEKLookupWithNoClassesIsRefused(t *testing.T) {
	session := stubSession([]*pkcs11.Attribute{boolAttribute(pkcs11.CKA_LOCAL, true)})
	handle, err := session.findKEKObject("02")
	if err == nil {
		t.Fatalf("findKEKObject with no classes returned handle %d and no error", handle)
	}
	// The control: the same session with a class does find the object, so the refusal above is
	// the missing class rather than the stub failing to answer at all.
	if _, err := session.findKEKObject("02", pkcs11.CKO_PUBLIC_KEY); err != nil {
		t.Fatalf("findKEKObject with a class failed: %v — the case above proves nothing", err)
	}
}

// TestSCHSMProvenanceIsReportedAsUndeterminable pins the measurement in regalia#447: on an SC-HSM
// behind OpenSC, CKA_LOCAL on the public object tracks whether a CERTIFICATE exists for that id,
// not where the private key came from.
//
// Measured on ESP41D722E2, 2026-09-22, with one imported key and one generated on the card:
//
//	akash-funding   (imported,  has a certificate)  CKA_LOCAL = true
//	pico-generated  (generated, no certificate)     CKA_LOCAL = false
//
// then writing a certificate for the GENERATED key and touching nothing else:
//
//	cert-for-generated                              CKA_LOCAL = true   <- was false
//
// That inverts this guard rather than blunting it. The ceremony's importer ALWAYS writes a
// certificate — gnupg-pkcs11-scd and `ssh-keygen -D` cannot see a key without one — so a
// CKA_LOCAL=true reading on such a token is exactly what an IMPORTED key looks like.
func TestSCHSMProvenanceIsReportedAsUndeterminable(t *testing.T) {
	for _, token := range []struct{ name, model, manufacturer string }{
		{"nitrokey hsm 2", "PKCS#15 emulated", "www.CardContact.de"},
		{"pico hsm", "PKCS#15 emulated", "Pol Henarejos"},
	} {
		t.Run(token.name, func(t *testing.T) {
			// CKA_LOCAL true — which on this token class means "there is a certificate", and is
			// precisely the reading an imported ceremony key produces.
			stub := &attributeStub{
				values:       []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LOCAL, true)},
				model:        token.model,
				manufacturer: token.manufacturer,
			}
			session := &pkcs11Session{module: stub}
			err := session.AssertKEKGeneratedOnToken(context.Background(), "01")
			if err == nil {
				t.Fatal("a CKA_LOCAL=true reading was accepted as proof the key was generated on " +
					"the token; on this token class that reading only means a certificate exists")
			}
			if !errors.Is(err, ErrKEKProvenanceUndeterminable) {
				t.Fatalf("err = %v, want ErrKEKProvenanceUndeterminable", err)
			}
			if errors.Is(err, ErrKEKNotTokenGenerated) {
				t.Fatal("reported as 'not generated on this token', which claims to know where the " +
					"key came from — the whole point is that this token cannot say")
			}
		})
	}
}

// A token whose CKA_LOCAL has NOT been measured to mean something else keeps the ordinary meaning.
// SoftHSM is where the attribute was verified, and the guard's worked example depends on it.
func TestAnOrdinaryTokenKeepsTheAttributesMeaning(t *testing.T) {
	generated := &attributeStub{
		values:       []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LOCAL, true)},
		model:        "SoftHSM v2",
		manufacturer: "SoftHSM project",
	}
	if err := (&pkcs11Session{module: generated}).AssertKEKGeneratedOnToken(context.Background(), "01"); err != nil {
		t.Fatalf("a locally generated SoftHSM key was refused: %v", err)
	}
	imported := &attributeStub{
		values:       []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LOCAL, false)},
		model:        "SoftHSM v2",
		manufacturer: "SoftHSM project",
	}
	err := (&pkcs11Session{module: imported}).AssertKEKGeneratedOnToken(context.Background(), "01")
	if !errors.Is(err, ErrKEKNotTokenGenerated) {
		t.Fatalf("err = %v, want ErrKEKNotTokenGenerated for an imported SoftHSM key", err)
	}
}

// The signature is the PKCS#15 EMULATION, not a product name: a token that merely mentions one of
// these manufacturers without being the emulated profile is not in the measured class.
func TestTheDeviceClassIsIdentifiedByTheEmulationNotTheName(t *testing.T) {
	stub := &attributeStub{
		values:       []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LOCAL, false)},
		model:        "Some Other Applet",
		manufacturer: "www.CardContact.de",
	}
	err := (&pkcs11Session{module: stub}).AssertKEKGeneratedOnToken(context.Background(), "01")
	if !errors.Is(err, ErrKEKNotTokenGenerated) {
		t.Fatalf("err = %v; a non-emulated token keeps the attribute's ordinary meaning", err)
	}
}
