package nitrokey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

// pairedCardModule models an SC-HSM the way a COMMISSIONED one actually enumerates: one private
// key, one public key, and one certificate — the imported key's own — all sharing a CKA_ID. That
// is what DENK0404144 reported on 2026-09-21 after an import:
//
//	Private Key Object; EC      label: akash-funding
//	Certificate Object; X.509   label: akash-funding   ID: 02
//	Public Key Object; EC
//
// Its device-authentication certificate is a CVC in EF 2F02 and is NOT a PKCS#11 object, on this
// card or on a Pico. So the single certificate a probe finds here belongs to a KEY.
type pairedCardModule struct {
	certs     map[pkcs11.ObjectHandle][]byte // handle -> CKA_VALUE
	certIDs   map[pkcs11.ObjectHandle][]byte // handle -> CKA_ID
	keyIDs    [][]byte                       // CKA_ID of every key object
	lastClass uint
	findErr   error // fails EVERY FindObjects
	certErr   error // fails only the certificate lookup
	keyIDErr  bool  // the CKA_ID of key objects cannot be read
}

func (m *pairedCardModule) GetSlotList(bool) ([]uint, error) { return []uint{0}, nil }
func (m *pairedCardModule) GetTokenInfo(uint) (pkcs11.TokenInfo, error) {
	return pkcs11.TokenInfo{SerialNumber: "SERIAL-1", Flags: pkcs11.CKF_TOKEN_INITIALIZED}, nil
}
func (m *pairedCardModule) OpenSession(uint, uint) (pkcs11.SessionHandle, error) { return 1, nil }
func (m *pairedCardModule) CloseSession(pkcs11.SessionHandle) error              { return nil }
func (m *pairedCardModule) Login(pkcs11.SessionHandle, uint, string) error       { return nil }
func (m *pairedCardModule) Logout(pkcs11.SessionHandle) error                    { return nil }

func (m *pairedCardModule) FindObjectsInit(_ pkcs11.SessionHandle, template []*pkcs11.Attribute) error {
	m.lastClass = 0
	for _, attribute := range template {
		if attribute != nil && attribute.Type == pkcs11.CKA_CLASS && len(attribute.Value) > 0 {
			m.lastClass = nativeUint(attribute.Value)
		}
	}
	return nil
}

func (m *pairedCardModule) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	if m.findErr != nil {
		return nil, false, m.findErr
	}
	if m.certErr != nil && m.lastClass == pkcs11.CKO_CERTIFICATE {
		return nil, false, m.certErr
	}
	switch m.lastClass {
	case pkcs11.CKO_CERTIFICATE:
		out := make([]pkcs11.ObjectHandle, 0, len(m.certs))
		for handle := range m.certs {
			out = append(out, handle)
		}
		return out, false, nil
	case pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY:
		out := make([]pkcs11.ObjectHandle, 0, len(m.keyIDs))
		for i := range m.keyIDs {
			out = append(out, pkcs11.ObjectHandle(1000+i))
		}
		return out, false, nil
	}
	return nil, false, nil
}

func (m *pairedCardModule) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }

func (m *pairedCardModule) GetAttributeValue(_ pkcs11.SessionHandle, object pkcs11.ObjectHandle,
	template []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	out := make([]*pkcs11.Attribute, 0, len(template))
	for _, attribute := range template {
		switch {
		case attribute.Type == pkcs11.CKA_VALUE:
			value, ok := m.certs[object]
			if !ok {
				return nil, errors.New("no value")
			}
			out = append(out, pkcs11.NewAttribute(pkcs11.CKA_VALUE, value))
		case attribute.Type == pkcs11.CKA_ID:
			if id, ok := m.certIDs[object]; ok {
				out = append(out, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
				continue
			}
			if index := int(object) - 1000; index >= 0 && index < len(m.keyIDs) {
				if m.keyIDErr {
					return nil, errors.New("key id unreadable")
				}
				out = append(out, pkcs11.NewAttribute(pkcs11.CKA_ID, m.keyIDs[index]))
				continue
			}
			return nil, errors.New("no id")
		}
	}
	return out, nil
}

func (m *pairedCardModule) SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	return nil
}
func (m *pairedCardModule) Sign(pkcs11.SessionHandle, []byte) ([]byte, error) { return nil, nil }
func (m *pairedCardModule) DecryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	return nil
}
func (m *pairedCardModule) Decrypt(pkcs11.SessionHandle, []byte) ([]byte, error) { return nil, nil }
func (m *pairedCardModule) DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, nil
}
func (m *pairedCardModule) UnwrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []byte, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, nil
}
func (m *pairedCardModule) WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error) {
	return nil, nil
}
func (m *pairedCardModule) CreateObject(pkcs11.SessionHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, nil
}
func (m *pairedCardModule) DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error { return nil }

// THE DEFECT. A commissioned SC-HSM carries exactly one CKO_CERTIFICATE and it belongs to the
// imported KEY. Hashing it as the device identity is wrong in two directions at once: rotating the
// key changes the "device identity" so the same card is refused as a different one, and two cards
// holding the same imported key and certificate produce the SAME identity, so the probe cannot
// tell them apart — which is the entire job of the identity boundary.
func TestAKeyCertificateIsNotADeviceIdentity(t *testing.T) {
	module := &pairedCardModule{
		certs:   map[pkcs11.ObjectHandle][]byte{7: []byte("the imported key's certificate")},
		certIDs: map[pkcs11.ObjectHandle][]byte{7: {0x02}},
		keyIDs:  [][]byte{{0x02}},
	}
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1")
	if err == nil {
		t.Fatalf("a KEY certificate was accepted as the device identity (fingerprint %q); two cards "+
			"holding the same imported key would be indistinguishable", fingerprint)
	}
	if !errors.Is(err, ErrNoDeviceCertificate) {
		t.Fatalf("err = %v, want ErrNoDeviceCertificate so a caller can fall back to EF 2F02 "+
			"rather than treat this as the wrong device", err)
	}
}

// An UNPAIRED certificate is the one that could be a device certificate, and it must still work.
func TestAnUnpairedCertificateIsStillTheDeviceIdentity(t *testing.T) {
	module := &pairedCardModule{
		certs:   map[pkcs11.ObjectHandle][]byte{7: []byte("C.DevAut")},
		certIDs: map[pkcs11.ObjectHandle][]byte{7: {0xFF}},
		keyIDs:  [][]byte{{0x02}},
	}
	probes, _ := NewTokenProbes(module)
	fingerprint, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1")
	if err != nil {
		t.Fatalf("an unpaired certificate was rejected: %v", err)
	}
	if fingerprint == "" {
		t.Fatal("no fingerprint returned")
	}
}

// A card carrying a device certificate AND a key certificate must resolve to the device one, not
// refuse as "ambiguous": two certificates is the normal state of a commissioned card that also
// exposes its identity.
func TestAKeyCertificateBesideADeviceCertificateIsNotAmbiguous(t *testing.T) {
	module := &pairedCardModule{
		certs: map[pkcs11.ObjectHandle][]byte{
			7: []byte("C.DevAut"),
			8: []byte("the imported key's certificate"),
		},
		certIDs: map[pkcs11.ObjectHandle][]byte{7: {0xFF}, 8: {0x02}},
		keyIDs:  [][]byte{{0x02}},
	}
	probes, _ := NewTokenProbes(module)
	fingerprint, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1")
	if err != nil {
		t.Fatalf("a device certificate beside a key certificate was refused: %v", err)
	}
	digest := sha256.Sum256([]byte("C.DevAut"))
	sum := "sha256:" + hex.EncodeToString(digest[:])
	if fingerprint != sum {
		t.Fatalf("hashed the wrong certificate: got %s want %s", fingerprint, sum)
	}
}

// Two UNPAIRED certificates really are ambiguous and must still refuse.
func TestTwoUnpairedCertificatesRemainAmbiguous(t *testing.T) {
	module := &pairedCardModule{
		certs:   map[pkcs11.ObjectHandle][]byte{7: []byte("one"), 8: []byte("two")},
		certIDs: map[pkcs11.ObjectHandle][]byte{7: {0xFE}, 8: {0xFF}},
		keyIDs:  [][]byte{{0x02}},
	}
	probes, _ := NewTokenProbes(module)
	if _, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1"); err == nil {
		t.Fatal("two unpaired certificates were not treated as ambiguous")
	}
}

// A card with no certificate at all — a blank or freshly initialised SC-HSM, which is what
// ESP41D722E2 and DENK0404144 both report — must say so in a way a caller can act on.
func TestNoCertificateIsTypedSoACallerCanFallBack(t *testing.T) {
	module := &pairedCardModule{certs: map[pkcs11.ObjectHandle][]byte{}}
	probes, _ := NewTokenProbes(module)
	_, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1")
	if !errors.Is(err, ErrNoDeviceCertificate) {
		t.Fatalf("err = %v, want ErrNoDeviceCertificate", err)
	}
}

// A FAILED LOOKUP IS NOT AN ABSENT CERTIFICATE. Returning ErrNoDeviceCertificate for a read error
// would invite a caller to fall back to another identity source on a card it could not read at
// all, which is how an unreadable device becomes an accepted one.
func TestALookupFailureIsNotReportedAsAbsence(t *testing.T) {
	module := &pairedCardModule{certs: map[pkcs11.ObjectHandle][]byte{}, findErr: errors.New("boom")}
	probes, _ := NewTokenProbes(module)
	_, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1")
	if err == nil {
		t.Fatal("a failed lookup was not an error")
	}
	if errors.Is(err, ErrNoDeviceCertificate) {
		t.Fatal("a failed lookup was reported as an ABSENT certificate; a caller would fall back " +
			"to another identity source on a card it cannot read")
	}
}

// A CERTIFICATE LOOKUP THAT FAILS IS NOT AN EMPTY TOKEN. The previous row could not tell these
// apart, because failing every FindObjects also failed the KEY lookup and the error came from
// there. This fails only the certificate query, so the certificate path is the one under test.
func TestOnlyTheCertificateLookupFailingIsStillNotAbsence(t *testing.T) {
	module := &pairedCardModule{
		certs:   map[pkcs11.ObjectHandle][]byte{},
		keyIDs:  [][]byte{{0x02}},
		certErr: errors.New("C_FindObjects failed"),
	}
	probes, _ := NewTokenProbes(module)
	_, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1")
	if err == nil {
		t.Fatal("a failed certificate lookup was not an error")
	}
	if errors.Is(err, ErrNoDeviceCertificate) {
		t.Fatal("a failed certificate lookup was reported as an ABSENT certificate; a caller " +
			"would fall back to EF 2F02 on a card whose objects it could not enumerate")
	}
}

// A KEY WHOSE CKA_ID CANNOT BE READ cannot be matched against, so every certificate would look
// unpaired — including the key's own. Skipping such a key silently is how the defect this whole
// file exists for comes back on a card with one unreadable object.
func TestAnUnreadableKeyIDRefusesRatherThanGuessing(t *testing.T) {
	module := &pairedCardModule{
		certs:    map[pkcs11.ObjectHandle][]byte{7: []byte("the imported key's certificate")},
		certIDs:  map[pkcs11.ObjectHandle][]byte{7: {0x02}},
		keyIDs:   [][]byte{{0x02}},
		keyIDErr: true,
	}
	probes, _ := NewTokenProbes(module)
	fingerprint, err := probes.Fingerprint(context.Background(), "hsm-sitea", "SERIAL-1")
	if err == nil {
		t.Fatalf("an unreadable key id let a KEY certificate through as the device identity (%q)",
			fingerprint)
	}
	if errors.Is(err, ErrNoDeviceCertificate) {
		t.Fatal("reported as an absent certificate; this is a card that could not be read, not " +
			"one that exposes none")
	}
}
