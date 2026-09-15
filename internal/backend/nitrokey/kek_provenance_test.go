package nitrokey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// wrappableKey is a real PKIX RSA public key. The default fake returns a stub that cannot be
// parsed, so a wrap attempt fails before reaching any guard — which would make every refusal
// below unattributable.
func wrappableKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A KEK IS ONLY HARDWARE-ROOTED IF THE TOKEN SAYS SO.
//
// #6 requires that "production KEKs are non-exportable hardware keys and no software fallback
// exists". Nothing asked the token. Measured against SoftHSM before these guards existed: an RSA
// key generated with openssl on the host and imported with CKA_EXTRACTABLE set wrapped a data key
// in 256 bytes, indistinguishable at every layer above from the on-token key.
//
// These cases pin the wiring — that a refusal from the driver stops the operation and latches the
// device with a distinguishable reason. That the driver reads the right PKCS#11 attributes is a
// separate question, answered against a real module in internal/integration.
func kekProvider(t *testing.T, session *fakeSession) *Provider {
	t.Helper()
	session.serial, session.devaut = "serial-1", binding().DevAuthFingerprint
	if session.publicKey == nil {
		session.publicKey = wrappableKey(t)
	}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	return provider
}

func wrap(provider *Provider) error {
	_, _, err := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"wrap", "regalia-envelope-v2", "application/vnd.regalia.data-key",
		[]byte("data-key"), []byte("aad"))
	return err
}

func unwrap(provider *Provider) error {
	_, _, err := provider.Execute(context.Background(),
		registry.Route{Algorithm: "rsa2048", Binding: binding()},
		"unwrap", "regalia-envelope-v2", "application/vnd.regalia.data-key",
		[]byte("wrapped"), []byte("aad"))
	return err
}

func TestWrappingToAKEKTheTokenDidNotGenerateIsRefusedAndLatched(t *testing.T) {
	// The control: the same call on a correctly provisioned token must succeed, or a refusal
	// below would prove only that wrap is broken.
	if err := wrap(kekProvider(t, &fakeSession{})); err != nil {
		t.Fatalf("wrap on a well-provisioned token was refused: %v", err)
	}

	provider := kekProvider(t, &fakeSession{notTokenGenerated: ErrKEKNotTokenGenerated})
	if err := wrap(provider); err == nil {
		t.Fatal("sealed to a KEK the token did not generate")
	}
	reason, latched := provider.QuarantineReason(binding().DeviceID)
	if !latched || reason != "kek-not-token-generated" {
		t.Fatalf("quarantine = %q/%v, want kek-not-token-generated", reason, latched)
	}
}

func TestReleasingUnderAnExportableKEKIsRefusedAndLatched(t *testing.T) {
	if err := unwrap(kekProvider(t, &fakeSession{})); err != nil {
		t.Fatalf("unwrap on a well-provisioned token was refused: %v", err)
	}

	provider := kekProvider(t, &fakeSession{exportable: ErrKEKExportable})
	if err := unwrap(provider); err == nil {
		t.Fatal("released a secret under a KEK whose private half the token will hand out")
	}
	reason, latched := provider.QuarantineReason(binding().DeviceID)
	if !latched || reason != "kek-exportable" {
		t.Fatalf("quarantine = %q/%v, want kek-exportable", reason, latched)
	}
}

// A READ FAILURE IS NOT A VERDICT, AND MUST NOT BE LATCHED AS ONE.
//
// Both outcomes refuse and both latch — "cannot prove this KEK is hardware-rooted" is not a safer
// state than "provably is not". What must differ is the diagnosis. Reporting an attribute read
// that failed as "kek-exportable" sends an operator to re-provision a key that may be perfectly
// good, which is the same argument that keeps the two definitive reasons apart.
func TestAnUnreadableKEKAttributeIsNotReportedAsAVerdict(t *testing.T) {
	for _, unreadable := range []struct {
		what    string
		session *fakeSession
		run     func(*Provider) error
	}{
		{"wrap", &fakeSession{notTokenGenerated: errors.New("PKCS#11 key attributes unavailable")}, wrap},
		{"unwrap", &fakeSession{exportable: errors.New("PKCS#11 key attributes unavailable")}, unwrap},
	} {
		t.Run(unreadable.what, func(t *testing.T) {
			provider := kekProvider(t, unreadable.session)
			if err := unreadable.run(provider); err == nil {
				t.Fatal("proceeded with a KEK whose provenance could not be read")
			}
			reason, latched := provider.QuarantineReason(binding().DeviceID)
			if !latched || reason != "kek-provenance-unreadable" {
				t.Fatalf("quarantine = %q/%v, want kek-provenance-unreadable — a failed read was reported as a verdict", reason, latched)
			}
		})
	}
}

// NO "THE TWO REASONS ARE DISTINGUISHABLE" CASE, DELIBERATELY. It reads like the useful third
// assertion — an operator told "kek-exportable" re-provisions with a non-extractable key, while
// "kek-not-token-generated" means asking where the key came from, so collapsing them sends one to
// the wrong remedy. But the two cases above already require those exact strings, and no mutation
// can make a third case fail while both of them pass: collapsing the reasons to either existing
// value, or to a new one, reddens them first. Measured, not assumed — a case that cannot fail
// alone is TESTING.md 17, and it belongs deleted rather than documented as covered.
