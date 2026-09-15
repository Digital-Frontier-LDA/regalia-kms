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
