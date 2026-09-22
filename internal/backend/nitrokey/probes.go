package nitrokey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// TokenProbes implements DevAuthProbe and PINRetryProbe over PKCS#11.
//
// Only the parts PKCS#11 can actually answer are implemented here. Secure messaging is NOT among
// them — PKCS#11 has no concept of it — which is why SecureChannel stays a separate collaborator
// that must be satisfied some other way rather than quietly stubbed here.
type TokenProbes struct{ module cryptoki }

func NewTokenProbes(module cryptoki) (*TokenProbes, error) {
	if module == nil {
		return nil, errors.New("PKCS#11 module is required")
	}
	return &TokenProbes{module: module}, nil
}

// slotFor resolves a commissioned serial to exactly one slot, refusing when zero or several match.
// Two tokens reporting the same serial is not something to disambiguate by position.
func (probes *TokenProbes) slotFor(serial string) (uint, error) {
	slots, err := probes.module.GetSlotList(true)
	if err != nil {
		return 0, errors.New("PKCS#11 enumeration failed")
	}
	var selected uint
	matches := 0
	for _, slot := range slots {
		info, infoErr := probes.module.GetTokenInfo(slot)
		if infoErr == nil && strings.TrimSpace(info.SerialNumber) == serial {
			selected, matches = slot, matches+1
		}
	}
	if matches != 1 {
		return 0, errors.New("commissioned PKCS#11 device is unavailable")
	}
	return selected, nil
}

// Remaining reports the user-PIN attempts left, derived from the token flags.
//
// PKCS#11 does not expose an exact counter — only three coarse states — so this DELIBERATELY
// UNDER-REPORTS: a token that is merely "count low" is reported as 2 even if the card would say 3.
// Under-reporting is the safe direction here, because the provider refuses to attempt a login when
// the remaining count is low, so an error can only ever stop work early, never spend a retry the
// caller thought it had.
func (probes *TokenProbes) Remaining(ctx context.Context, _, serial string) (int, error) {
	if probes == nil || probes.module == nil {
		return 0, errors.New("PKCS#11 module is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	slot, err := probes.slotFor(serial)
	if err != nil {
		return 0, err
	}
	info, err := probes.module.GetTokenInfo(slot)
	if err != nil {
		return 0, errors.New("PKCS#11 token info unavailable")
	}
	switch {
	case info.Flags&pkcs11.CKF_USER_PIN_LOCKED != 0:
		return 0, nil
	case info.Flags&pkcs11.CKF_USER_PIN_FINAL_TRY != 0:
		return 1, nil
	case info.Flags&pkcs11.CKF_USER_PIN_COUNT_LOW != 0:
		return 2, nil
	}
	return 3, nil
}

// Fingerprint returns sha256:<hex> over the DER of the device-authentication certificate the token
// holds, so a substituted device is detected before any private-key use.
//
// It reads the certificate object rather than trusting a label: the value hashed is the one the
// card actually presents.
func (probes *TokenProbes) Fingerprint(ctx context.Context, _, serial string) (string, error) {
	if probes == nil || probes.module == nil {
		return "", errors.New("PKCS#11 module is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	slot, err := probes.slotFor(serial)
	if err != nil {
		return "", err
	}
	handle, err := probes.module.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return "", errors.New("PKCS#11 session unavailable")
	}
	defer func() { _ = probes.module.CloseSession(handle) }()

	// A KEY'S CERTIFICATE IS NOT A DEVICE IDENTITY, and this used to hash whichever single
	// CKO_CERTIFICATE it found. A COMMISSIONED SC-HSM carries exactly one, and it belongs to the
	// imported key — measured on DENK0404144 on 2026-09-21, where the only certificate object was
	// CN=cosmos-staging-qual, written beside the key minutes earlier.
	//
	// Hashing that is wrong in two directions at once. Rotating the key changes the "device
	// identity", so the same physical card is refused as a different one. Worse, two cards holding
	// the same imported key and certificate produce the SAME identity, so the probe cannot tell
	// them apart — which is the entire job of the boundary this probe implements.
	//
	// A key's certificate is distinguishable: it shares its CKA_ID with a key object. Only an
	// UNPAIRED certificate can be a device certificate.
	certificates, err := probes.certificateHandles(handle)
	if err != nil {
		return "", err
	}
	keyIDs, err := probes.keyIDs(handle)
	if err != nil {
		return "", err
	}
	var unpaired []pkcs11.ObjectHandle
	for _, object := range certificates {
		id, idErr := probes.objectID(handle, object)
		if idErr != nil {
			// A certificate whose CKA_ID cannot be read cannot be shown to belong to a key, and
			// assuming it does not would let exactly the object this guard excludes back in.
			return "", errors.New("certificate identifier is unreadable")
		}
		if !containsID(keyIDs, id) {
			unpaired = append(unpaired, object)
		}
	}
	if len(unpaired) == 0 {
		// TYPED, so a caller can fall back to the CVC in EF 2F02 — which is where an SC-HSM's
		// device certificate actually lives, on a Nitrokey HSM 2 and on a Pico alike — instead of
		// concluding it is holding the wrong device. Distinct from every read failure above.
		return "", fmt.Errorf("%w: this token exposes none as a PKCS#11 object (an SC-HSM keeps it "+
			"in EF 2F02, which PKCS#11 does not surface)", ErrNoDeviceCertificate)
	}
	// More than one UNPAIRED certificate means the identity is ambiguous; hashing the first would
	// pin whichever the middleware happened to enumerate first.
	if len(unpaired) != 1 {
		return "", errors.New("device certificate is ambiguous")
	}
	values, err := probes.module.GetAttributeValue(handle, unpaired[0],
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil || len(values) == 0 || len(values[0].Value) == 0 {
		return "", errors.New("device certificate is unreadable")
	}
	sum := sha256.Sum256(values[0].Value)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ErrNoDeviceCertificate reports that the token exposes no device certificate as a PKCS#11
// object. It is a statement about the MIDDLEWARE's view, not about the device: an SC-HSM's
// C.DevAut is a card-verifiable certificate in EF 2F02 and OpenSC's PKCS#15 emulation does not
// surface it. Callers that can read EF 2F02 should do so on this error; callers that cannot must
// still refuse, because an identity that cannot be established is not an identity.
var ErrNoDeviceCertificate = errors.New("no device certificate is exposed through PKCS#11")

// certificateHandles lists every CKO_CERTIFICATE on the token. The cap is deliberately generous:
// the previous code asked for 2 in order to detect ambiguity, which also meant it could not see a
// device certificate sitting behind two key certificates.
func (probes *TokenProbes) certificateHandles(handle pkcs11.SessionHandle) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)}
	if err := probes.module.FindObjectsInit(handle, template); err != nil {
		return nil, errors.New("PKCS#11 certificate lookup failed")
	}
	objects, _, findErr := probes.module.FindObjects(handle, 64)
	_ = probes.module.FindObjectsFinal(handle)
	if findErr != nil {
		// NOT an absence. Reporting a read error as "no certificate" would invite a caller to
		// fall back to another identity source on a card it could not read at all.
		return nil, errors.New("PKCS#11 certificate lookup failed")
	}
	return objects, nil
}

// keyIDs collects the CKA_ID of every key object, public and private. A certificate sharing one
// belongs to that key.
func (probes *TokenProbes) keyIDs(handle pkcs11.SessionHandle) ([][]byte, error) {
	var ids [][]byte
	for _, class := range []uint{pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_PUBLIC_KEY} {
		template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}
		if err := probes.module.FindObjectsInit(handle, template); err != nil {
			return nil, errors.New("PKCS#11 key lookup failed")
		}
		objects, _, findErr := probes.module.FindObjects(handle, 64)
		_ = probes.module.FindObjectsFinal(handle)
		if findErr != nil {
			return nil, errors.New("PKCS#11 key lookup failed")
		}
		for _, object := range objects {
			id, err := probes.objectID(handle, object)
			if err != nil {
				// A key whose id cannot be read cannot be matched against, so a certificate that
				// belongs to it would look unpaired. Refuse rather than guess.
				return nil, errors.New("key identifier is unreadable")
			}
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (probes *TokenProbes) objectID(handle pkcs11.SessionHandle, object pkcs11.ObjectHandle) ([]byte, error) {
	values, err := probes.module.GetAttributeValue(handle, object,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil)})
	if err != nil || len(values) == 0 {
		return nil, errors.New("attribute unavailable")
	}
	return values[0].Value, nil
}

func containsID(ids [][]byte, want []byte) bool {
	for _, id := range ids {
		if bytes.Equal(id, want) {
			return true
		}
	}
	return false
}

// NewPKCS11DriverWithProbes builds the module once and derives the identity and retry probes from
// it, so a caller cannot accidentally point them at a different module than the driver uses.
//
// SecureChannel stays a parameter: PKCS#11 cannot answer it, so it must come from somewhere that
// can, and making it explicit keeps that visible at the call site.
func NewPKCS11DriverWithProbes(modulePath string, secure SecureChannel) (*PKCS11Driver, error) {
	if secure == nil {
		return nil, errors.New("a secure-channel implementation is required")
	}
	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, errors.New("PKCS#11 module unavailable")
	}
	if err := module.Initialize(); err != nil {
		module.Destroy()
		return nil, errors.New("PKCS#11 initialization failed")
	}
	probes, err := NewTokenProbes(module)
	if err != nil {
		module.Finalize()
		module.Destroy()
		return nil, err
	}
	return newPKCS11Driver(module, probes, secure, probes, func() error {
		err := module.Finalize()
		module.Destroy()
		return err
	})
}
