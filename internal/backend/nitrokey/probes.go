package nitrokey

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE)}
	if err := probes.module.FindObjectsInit(handle, template); err != nil {
		return "", errors.New("PKCS#11 certificate lookup failed")
	}
	objects, _, findErr := probes.module.FindObjects(handle, 2)
	_ = probes.module.FindObjectsFinal(handle)
	if findErr != nil || len(objects) == 0 {
		return "", errors.New("device certificate is not present")
	}
	// More than one device certificate means the identity is ambiguous; hashing the first would
	// pin whichever the middleware happened to enumerate first.
	if len(objects) != 1 {
		return "", errors.New("device certificate is ambiguous")
	}
	values, err := probes.module.GetAttributeValue(handle, objects[0],
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil || len(values) == 0 || len(values[0].Value) == 0 {
		return "", errors.New("device certificate is unreadable")
	}
	sum := sha256.Sum256(values[0].Value)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
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
