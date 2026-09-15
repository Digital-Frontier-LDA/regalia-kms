package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

type fakeHardware struct {
	backend string
	keys    map[string][]byte
	calls   int
}

func (hardware *fakeHardware) Backend() string { return hardware.backend }

func (hardware *fakeHardware) WrapKey(_ context.Context, ref KeyRef, plaintext, binding []byte) ([]byte, error) {
	hardware.calls++
	return fakeCrypt(hardware.keys[ref.ID+":"+ref.Version], plaintext, binding, true)
}

func (hardware *fakeHardware) UnwrapKey(_ context.Context, ref KeyRef, wrapped, binding []byte) ([]byte, error) {
	hardware.calls++
	return fakeCrypt(hardware.keys[ref.ID+":"+ref.Version], wrapped, binding, false)
}

func fakeCrypt(key, input, aad []byte, seal bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if seal {
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}
		return append(nonce, aead.Seal(nil, nonce, input, aad)...), nil
	}
	if len(input) < len(nonce) {
		return nil, errors.New("wrapped key truncated")
	}
	return aead.Open(nil, input[:len(nonce)], input[len(nonce):], aad)
}

func hardware(backend string, keys map[string][]byte) *fakeHardware {
	return &fakeHardware{backend: backend, keys: keys}
}

func TestSealParseAndOpenUsesContextAndZeroizesCallbackBuffer(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	created := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	envelope, err := Seal(context.Background(), device, KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"},
		"deployment-api-token", []byte("repository=infra/path=prod.yaml"), []byte("top-secret-value"), rand.Reader, created)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var observed []byte
	err = parsed.Open(context.Background(), device, []byte("repository=infra/path=prod.yaml"), func(plaintext []byte) error {
		if string(plaintext) != "top-secret-value" {
			t.Fatalf("plaintext = %q", plaintext)
		}
		observed = plaintext
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(observed, make([]byte, len(observed))) {
		t.Fatalf("callback plaintext was not zeroized: %x", observed)
	}
}

func TestOpenRejectsWrongContextAndCorruptionWithoutPlaintext(t *testing.T) {
	device := hardware("nitrokey-pkcs11", map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32)})
	original, err := Seal(context.Background(), device, KeyRef{Backend: device.Backend(), ID: "company-kek", Version: "1"},
		"deployment-api-token", []byte("right-context"), []byte("secret"), rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Envelope, *[]byte){
		"wrong context": func(_ *Envelope, contextValue *[]byte) { *contextValue = []byte("wrong-context") },
		"ciphertext":    func(value *Envelope, _ *[]byte) { value.Ciphertext[0] ^= 1 },
		"wrapped key":   func(value *Envelope, _ *[]byte) { value.WrappedDataKey[0] ^= 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := original.Clone()
			contextValue := []byte("right-context")
			mutate(&value, &contextValue)
			called := false
			if err := value.Open(context.Background(), device, contextValue, func([]byte) error { called = true; return nil }); err == nil || called {
				t.Fatalf("Open() error=%v called=%v", err, called)
			}
		})
	}
}

func TestRewrapRotatesKEKWithoutChangingCiphertextAndRestoredTokenCanOpen(t *testing.T) {
	keys := map[string][]byte{"company-kek:1": bytes.Repeat([]byte{1}, 32), "company-kek:2": bytes.Repeat([]byte{2}, 32)}
	originalDevice := hardware("nitrokey-pkcs11", keys)
	value, err := Seal(context.Background(), originalDevice, KeyRef{Backend: originalDevice.Backend(), ID: "company-kek", Version: "1"},
		"deployment-api-token", []byte("prod-context"), []byte("secret"), rand.Reader, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	originalCiphertext := append([]byte(nil), value.Ciphertext...)
	if err := value.Rewrap(context.Background(), originalDevice, originalDevice, KeyRef{Backend: originalDevice.Backend(), ID: "company-kek", Version: "2"}, []byte("prod-context")); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value.Ciphertext, originalCiphertext) || value.KEK.Version != "2" {
		t.Fatal("rewrap changed content ciphertext or failed to rotate KEK")
	}
	restoredToken := hardware("nitrokey-pkcs11", map[string][]byte{"company-kek:2": append([]byte(nil), keys["company-kek:2"]...)})
	if err := value.Open(context.Background(), restoredToken, []byte("prod-context"), func(plaintext []byte) error {
		if string(plaintext) != "secret" {
			t.Fatalf("plaintext = %q", plaintext)
		}
		return nil
	}); err != nil {
		t.Fatalf("restored token Open() error = %v", err)
	}
}

func TestSealRejectsSoftwareBackendAndOversizedPlaintextBeforeBackend(t *testing.T) {
	device := hardware("software", map[string][]byte{"kek:1": bytes.Repeat([]byte{1}, 32)})
	if _, err := Seal(context.Background(), device, KeyRef{Backend: "software", ID: "kek", Version: "1"}, "secret-id", nil, []byte("secret"), rand.Reader, time.Now()); err == nil {
		t.Fatal("software backend accepted")
	}
	device.backend = "nitrokey-pkcs11"
	if _, err := Seal(context.Background(), device, KeyRef{Backend: device.backend, ID: "kek", Version: "1"}, "secret-id", nil, make([]byte, MaxPlaintextBytes+1), rand.Reader, time.Now()); err == nil {
		t.Fatal("oversized plaintext accepted")
	}
	if device.calls != 0 {
		t.Fatalf("backend called %d times", device.calls)
	}
}
