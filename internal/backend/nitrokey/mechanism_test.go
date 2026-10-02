package nitrokey

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE TOKEN SAYS WHAT IT CAN DO (regalia#541).
//
// The capability matrix advertises ed25519/sign and aes-256/unwrap for the PKCS#11 backend. Neither
// SmartCard-HSM on the bench lists an EdDSA or AES mechanism. The list below is the one measured on
// Nitrokey HSM 2 DENK0404144 (applet 4.1) and on a Pico HSM (firmware 6.6) through OpenSC 0.26.1,
// reduced to the mechanisms this driver uses.
var smartCardHSMMechanisms = []uint{pkcs11.CKM_ECDSA, pkcs11.CKM_RSA_PKCS, pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.CKM_ECDH1_DERIVE}

func TestRequiredMechanismIsTheOneTheOperationIsSentWith(t *testing.T) {
	for _, test := range []struct {
		operation, algorithm string
		mechanism            uint
		needed               bool
	}{
		{"sign", "p256", pkcs11.CKM_ECDSA, true},
		{"sign", "p384", pkcs11.CKM_ECDSA, true},
		{"sign", "secp256k1", pkcs11.CKM_ECDSA, true},
		{"sign", "ed25519", ckmEdDSA, true},
		{"sign", "rsa3072", pkcs11.CKM_RSA_PKCS, true},
		{"unwrap", "rsa2048", pkcs11.CKM_RSA_PKCS_OAEP, true},
		{"unwrap", "rsa4096", pkcs11.CKM_RSA_PKCS_OAEP, true},
		{"unwrap", "aes-256", pkcs11.CKM_AES_KEY_WRAP_PAD, true},
		{"key-agreement", "p256", pkcs11.CKM_ECDH1_DERIVE, true},
		{"key-agreement", "p384", pkcs11.CKM_ECDH1_DERIVE, true},
		// Nothing is sent to the token with a mechanism for these, so there is nothing to ask for.
		{"public-key", "p384", 0, false},
		{"wrap", "rsa3072", 0, false},
		// An algorithm the driver has no mechanism for is the operation's own path to refuse.
		{"sign", "opaque", 0, false},
		{"unwrap", "p256", 0, false},
		{"key-agreement", "rsa2048", 0, false},
	} {
		mechanism, needed := requiredMechanism(test.operation, test.algorithm)
		if mechanism != test.mechanism || needed != test.needed {
			t.Errorf("%s/%s: (%#x, %v), want (%#x, %v)", test.algorithm, test.operation, mechanism, needed, test.mechanism, test.needed)
		}
	}
}

func mechanismSession(t *testing.T, module *fakeCryptoki) Session {
	t.Helper()
	module.serial = "serial-1"
	driver, err := newPKCS11Driver(module, fixedDevAuth("sha256:abc"), &recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	session, err := driver.Open(context.Background(), registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm", DeviceSerial: "serial-1"})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestOffersMechanismAnswersFromTheTokensOwnList(t *testing.T) {
	ctx := context.Background()
	session := mechanismSession(t, &fakeCryptoki{mechanisms: smartCardHSMMechanisms})
	for _, offered := range [][2]string{{"sign", "p384"}, {"sign", "secp256k1"}, {"sign", "rsa3072"}, {"unwrap", "rsa2048"}, {"key-agreement", "p256"}, {"public-key", "ed25519"}} {
		if err := session.OffersMechanism(ctx, offered[0], offered[1]); err != nil {
			t.Errorf("%s/%s was refused on a token that offers it: %v", offered[1], offered[0], err)
		}
	}
	// The two promises the matrix makes and a SmartCard-HSM does not keep.
	for _, missing := range [][2]string{{"sign", "ed25519"}, {"unwrap", "aes-256"}} {
		if err := session.OffersMechanism(ctx, missing[0], missing[1]); !errors.Is(err, ErrMechanismNotOffered) {
			t.Errorf("%s/%s on a SmartCard-HSM: %v, want ErrMechanismNotOffered", missing[1], missing[0], err)
		}
	}
	// A token that does list EdDSA is believed too: the YubiKey's OpenPGP applet does.
	applet := mechanismSession(t, &fakeCryptoki{mechanisms: []uint{ckmEdDSA}})
	if err := applet.OffersMechanism(ctx, "sign", "ed25519"); err != nil {
		t.Errorf("ed25519/sign was refused on a token that lists EdDSA: %v", err)
	}
	if err := applet.OffersMechanism(ctx, "sign", "p384"); !errors.Is(err, ErrMechanismNotOffered) {
		t.Errorf("p384/sign on a token that lists EdDSA alone: %v, want ErrMechanismNotOffered", err)
	}
}

// "Could not ask" is not "the token said no", and neither is "yes".
func TestAMechanismListThatCannotBeReadIsNeitherAnswer(t *testing.T) {
	session := mechanismSession(t, &fakeCryptoki{mechanismErr: pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)})
	err := session.OffersMechanism(context.Background(), "sign", "p384")
	if err == nil || errors.Is(err, ErrMechanismNotOffered) {
		t.Fatalf("an unreadable mechanism list answered %v", err)
	}
	// A list with nothing in it was not read: a token that offered no mechanism at all would be
	// refused for every object at startup on the strength of it.
	err = mechanismSession(t, &fakeCryptoki{mechanisms: []uint{}}).OffersMechanism(context.Background(), "sign", "p384")
	if err == nil || errors.Is(err, ErrMechanismNotOffered) {
		t.Fatalf("an empty mechanism list answered %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := mechanismSession(t, &fakeCryptoki{}).OffersMechanism(cancelled, "sign", "p384"); err == nil {
		t.Fatal("a cancelled context got an answer")
	}
}

// The provider asks before it fetches the PIN, refuses on any answer but yes, and does not latch
// the device: one mis-bound object must not take the token's other keys out of service.
func TestAnOperationTheTokenCannotDoIsRefusedBeforeThePINAndDoesNotLatchTheDevice(t *testing.T) {
	for name, answer := range map[string]error{"the token does not offer it": ErrMechanismNotOffered, "the list could not be read": errors.New("unreadable")} {
		session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, mechanismErr: answer}
		pins := &fakePIN{value: []byte("123456")}
		provider, err := New(&fakeDriver{session: session}, pins)
		if err != nil {
			t.Fatal(err)
		}
		result, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "ed25519", Binding: binding()}, "sign", "", "application/vnd.regalia.digest", []byte("digest"), nil)
		if !errors.Is(err, ErrUnavailable) || result != nil {
			t.Fatalf("%s: result=%q err=%v", name, result, err)
		}
		if session.logged || session.loginCalls != 0 || len(session.pin) != 0 {
			t.Fatalf("%s: the PIN was presented (logged=%v, calls=%d)", name, session.logged, session.loginCalls)
		}
		// Not fetched either, and the retry counter not read: the question comes first, and it is
		// asked about this operation on this key.
		if pins.calls != 0 {
			t.Fatalf("%s: the PIN was fetched %d times for an operation the token cannot do", name, pins.calls)
		}
		if len(session.mechanismAsked) != 1 || session.mechanismAsked[0] != "sign/ed25519" {
			t.Fatalf("%s: the token was asked %v, want [sign/ed25519]", name, session.mechanismAsked)
		}
		for _, step := range session.order {
			if step == "PINRetries" || step == "Login" {
				t.Fatalf("%s: %s was reached: %v", name, step, session.order)
			}
		}
		if reason, latched := provider.QuarantineReason(binding().DeviceID); latched {
			t.Fatalf("%s: the device was latched (%s)", name, reason)
		}
		if !session.closed {
			t.Fatalf("%s: the session was left open", name)
		}
	}
	// The control: with the mechanism offered, the same request logs in and signs.
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if _, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "p384", Binding: binding()}, "sign", "", "application/vnd.regalia.digest", []byte("digest"), nil); err != nil || !session.logged {
		t.Fatalf("the control did not sign: err=%v logged=%v", err, session.logged)
	}
	position := map[string]int{}
	for index, step := range session.order {
		if _, seen := position[step]; !seen {
			position[step] = index + 1
		}
	}
	if position["mechanism"] == 0 || position["PINRetries"] == 0 || position["Login"] == 0 ||
		position["mechanism"] > position["PINRetries"] || position["mechanism"] > position["Login"] {
		t.Fatalf("the token must be asked before the retry counter is read and before login: %v", session.order)
	}
	if len(session.mechanismAsked) != 1 || session.mechanismAsked[0] != "sign/p384" {
		t.Fatalf("the token was asked %v, want [sign/p384]", session.mechanismAsked)
	}
}
