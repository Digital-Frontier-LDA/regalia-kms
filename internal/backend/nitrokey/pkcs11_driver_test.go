package nitrokey

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/miekg/pkcs11"
)

func (module *fakeCryptoki) DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, errors.New("derive not supported by this fake")
}
func (module *fakeCryptoki) UnwrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []byte, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, errors.New("unwrap not supported by this fake")
}
func (module *fakeCryptoki) WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error) {
	return nil, errors.New("wrap not supported by this fake")
}
func (module *fakeCryptoki) CreateObject(pkcs11.SessionHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, errors.New("create not supported by this fake")
}
func (module *fakeCryptoki) DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error {
	return nil
}

type fakeCryptoki struct {
	serial       string
	loginPIN     string
	signature    []byte
	plaintext    []byte
	closed       bool
	loggedOut    bool
	findClass    uint
	mechanism    uint
	objectHandle pkcs11.ObjectHandle
}

func (fake *fakeCryptoki) GetSlotList(bool) ([]uint, error) { return []uint{7}, nil }
func (fake *fakeCryptoki) GetTokenInfo(uint) (pkcs11.TokenInfo, error) {
	return pkcs11.TokenInfo{SerialNumber: fake.serial}, nil
}
func (*fakeCryptoki) OpenSession(uint, uint) (pkcs11.SessionHandle, error) { return 11, nil }
func (fake *fakeCryptoki) CloseSession(pkcs11.SessionHandle) error         { fake.closed = true; return nil }
func (fake *fakeCryptoki) Login(_ pkcs11.SessionHandle, _ uint, pin string) error {
	fake.loginPIN = pin
	return nil
}
func (fake *fakeCryptoki) Logout(pkcs11.SessionHandle) error { fake.loggedOut = true; return nil }
func (fake *fakeCryptoki) FindObjectsInit(_ pkcs11.SessionHandle, attrs []*pkcs11.Attribute) error {
	for _, attribute := range attrs {
		if attribute.Type == pkcs11.CKA_CLASS {
			fake.findClass = bytesToUint(attribute.Value)
		}
	}
	return nil
}
func (fake *fakeCryptoki) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	return []pkcs11.ObjectHandle{fake.objectHandle}, false, nil
}
func (*fakeCryptoki) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }
func (fake *fakeCryptoki) SignInit(_ pkcs11.SessionHandle, mechanisms []*pkcs11.Mechanism, _ pkcs11.ObjectHandle) error {
	fake.mechanism = mechanisms[0].Mechanism
	return nil
}
func (fake *fakeCryptoki) Sign(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return append([]byte(nil), fake.signature...), nil
}
func (fake *fakeCryptoki) DecryptInit(_ pkcs11.SessionHandle, mechanisms []*pkcs11.Mechanism, _ pkcs11.ObjectHandle) error {
	fake.mechanism = mechanisms[0].Mechanism
	return nil
}
func (fake *fakeCryptoki) Decrypt(pkcs11.SessionHandle, []byte) ([]byte, error) {
	return append([]byte(nil), fake.plaintext...), nil
}
func (*fakeCryptoki) GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	return nil, errors.New("not implemented")
}

type fixedDevAuth string

func (value fixedDevAuth) Fingerprint(context.Context, string, string) (string, error) {
	return string(value), nil
}

type recordingSecureChannel struct{ calls int }

func (channel *recordingSecureChannel) Establish(context.Context, string, string) error {
	channel.calls++
	return nil
}

type fixedRetries int

func (retries fixedRetries) Remaining(context.Context, string, string) (int, error) {
	return int(retries), nil
}

func TestPKCS11DriverSelectsPinnedSerialAndExecutesPrivateOperations(t *testing.T) {
	module := &fakeCryptoki{serial: "SERIAL-1", objectHandle: 42, signature: []byte("sig"), plaintext: []byte("plain")}
	secure := &recordingSecureChannel{}
	driver, err := newPKCS11Driver(module, fixedDevAuth("sha256:abc"), secure, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	session, err := driver.Open(context.Background(), registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: "SERIAL-1"})
	if err != nil {
		t.Fatal(err)
	}
	serial, devAuth, err := session.Identity(context.Background())
	if err != nil || serial != "SERIAL-1" || devAuth != "sha256:abc" {
		t.Fatalf("identity = %q %q, %v", serial, devAuth, err)
	}
	if err := session.EstablishSecureChannel(context.Background()); err != nil || secure.calls != 1 {
		t.Fatalf("secure channel = %v calls=%d", err, secure.calls)
	}
	pin := []byte("123456")
	if err := session.Login(context.Background(), pin); err != nil {
		t.Fatal(err)
	}
	if result, err := session.Sign(context.Background(), "01", "secp256k1", []byte("digest")); err != nil || string(result) != "sig" || module.mechanism != pkcs11.CKM_ECDSA {
		t.Fatalf("sign = %q %v mechanism=%x", result, err, module.mechanism)
	}
	if result, err := session.Unwrap(context.Background(), "01", "rsa2048", []byte("wrapped"), []byte("context")); err != nil || string(result) != "plain" || module.mechanism != pkcs11.CKM_RSA_PKCS_OAEP {
		t.Fatalf("unwrap = %q %v mechanism=%x", result, err, module.mechanism)
	}
	if err := session.Close(); err != nil || !module.closed || !module.loggedOut {
		t.Fatalf("close = %v closed=%v logout=%v", err, module.closed, module.loggedOut)
	}
	if module.loginPIN != "123456" || module.findClass != pkcs11.CKO_PRIVATE_KEY {
		t.Fatalf("login/find mismatch: pin=%q class=%d", module.loginPIN, module.findClass)
	}
}

func TestPKCS11DriverFailsClosedOnUnknownOrDuplicateDevice(t *testing.T) {
	module := &fakeCryptoki{serial: "SERIAL-1"}
	driver, err := newPKCS11Driver(module, fixedDevAuth("sha256:abc"), &recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Open(context.Background(), registry.Binding{}); err == nil {
		t.Fatal("unknown device was accepted")
	}
	if _, err := driver.Open(context.Background(), registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: "SERIAL-2"}); err == nil {
		t.Fatal("substituted serial was accepted")
	}
}

func bytesToUint(value []byte) uint {
	var result uint
	for index := len(value) - 1; index >= 0; index-- {
		result = result<<8 | uint(value[index])
	}
	return result
}
