package nitrokey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func TestConcretePKCS11DriverAgainstSoftHSM(t *testing.T) {
	modulePath := os.Getenv("REGALIA_PKCS11_E2E_MODULE")
	serial := os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE and REGALIA_PKCS11_E2E_SERIAL")
	}
	driver, err := NewPKCS11Driver(modulePath, fixedDevAuth("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), &recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	provider, err := New(driver, &fakePIN{value: e2ePKCS11PIN(t)})
	if err != nil {
		t.Fatal(err)
	}
	binding := registry.Binding{
		Backend: "nitrokey-pkcs11", DeviceID: "hsm-e2e", DeviceSerial: serial,
		DevAuthFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ObjectID:           "01", State: "active",
	}
	route := registry.Route{Algorithm: "secp256k1", Binding: binding}
	signature, _, err := provider.Execute(context.Background(), route, "sign", "", "application/vnd.regalia.digest", make([]byte, 32), nil)
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature length=%d err=%v", len(signature), err)
	}
	publicDER, contentType, err := provider.Execute(context.Background(), route, "public-key", "", "", nil, nil)
	if err != nil || contentType != "application/pkix" || len(publicDER) == 0 {
		t.Fatalf("public key length=%d type=%q err=%v", len(publicDER), contentType, err)
	}
	var decoded subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(publicDER, &decoded); err != nil || len(rest) != 0 || !decoded.Algorithm.Algorithm.Equal(oidPublicKeyEC) {
		t.Fatalf("invalid secp256k1 SubjectPublicKeyInfo: rest=%x err=%v", rest, err)
	}

	route.Algorithm = "rsa2048"
	route.Binding.ObjectID = "02"
	aad := []byte(`{"environment":"development","path":"fixture.enc.yaml","purpose":"sops-data-key","repository":"Org/repo"}`)
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	wrapped, contentType, err := provider.Execute(context.Background(), route, "wrap", "regalia-envelope-v2", "", dataKey, aad)
	if err != nil || contentType != "application/vnd.regalia.wrapped-key" || len(wrapped) != 256 {
		t.Fatalf("wrap length=%d type=%q err=%v", len(wrapped), contentType, err)
	}
	unwrapped, contentType, err := provider.Execute(context.Background(), route, "unwrap", "regalia-envelope-v2", "", wrapped, aad)
	if err != nil || contentType != "application/octet-stream" || string(unwrapped) != string(dataKey) {
		session, openErr := driver.Open(context.Background(), route.Binding)
		if openErr == nil {
			_, _, _ = session.Identity(context.Background())
			_ = session.EstablishSecureChannel(context.Background())
			_ = session.Login(context.Background(), e2ePKCS11PIN(t))
			_, openErr = session.Unwrap(context.Background(), "02", "rsa2048", wrapped, aad)
			_ = session.Close()
		}
		t.Fatalf("unwrap = %x type=%q err=%v direct=%v", unwrapped, contentType, err, openErr)
	}
	if value, _, err := provider.Execute(context.Background(), route, "unwrap", "regalia-envelope-v2", "", wrapped, []byte("wrong-context")); err == nil || value != nil {
		t.Fatal("context-transplanted wrapped key was accepted")
	}
}

// #75's OTHER HALF. The matrix entry, the registry test, and the negotiation between the driver
// and the matrix are all visible without a token. The branch this test pins is the one a fake
// cannot model: CKM_AES_KEY_WRAP_PAD against a CKO_SECRET_KEY on a real PKCS#11 module, and the
// round trip that the matrix entry's promise rides on. Without it, the entry would be a promise
// with no measurement, and the next token that fails to honour CKM_AES_KEY_WRAP_PAD would be
// indistinguishable from the one that does.
//
// Object 09 is the sensitive AES-256 KEK provisioned by e2e/softhsm-pkcs11.sh (--sensitive, the
// guard-respecting shape). The test uses session.Wrap / session.Unwrap directly — provider.Execute
// dispatches wrap on algorithm and never reaches driver.Wrap for aes-256 because the matrix lists
// unwrap only. Going through the driver keeps the production surface unwrap-only while letting a
// real token construct a real wrapped frame for the unwrap path to consume.
func TestAES256UnwrapRoundTripsAgainstSoftHSM(t *testing.T) {
	module, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if module == "" || serial == "" {
		t.Skip("set REGALIA_PKCS11_E2E_MODULE and REGALIA_PKCS11_E2E_SERIAL")
	}
	driver, err := NewPKCS11Driver(module, fixedDevAuth("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), &recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	// ONE session, because PKCS#11 login state belongs to the token and not the session: a
	// second Login against the same token returns CKR_USER_ALREADY_LOGGED_IN.
	session, err := driver.Open(context.Background(), registry.Binding{
		Backend: "nitrokey-pkcs11", DeviceID: "softhsm-aes-unwrap", DeviceSerial: serial,
		DevAuthFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ObjectID:           "09", State: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close() }()
	if err := session.Login(context.Background(), e2ePKCS11PIN(t)); err != nil {
		t.Fatal(err)
	}

	aad := []byte(`{"environment":"development","path":"fixture.enc.yaml","purpose":"sops-data-key","repository":"Org/repo"}`)
	dataKey := []byte("0123456789abcdef0123456789abcdef")
	frame, err := buildFrame(aad, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := session.Wrap(context.Background(), "09", "aes-256", frame, aad)
	if err != nil || len(wrapped) == 0 {
		t.Fatalf("session.Wrap(aes-256) length=%d err=%v", len(wrapped), err)
	}
	// THE WRAP LENGTH IS A SEPARATE ASSERTION, NOT A PROPERTY OF ROUND-TRIP EQUALITY.
	//
	// RFC 5649 (AES-KEY-WRAP-PAD) wraps ceil(len/8)*8 input bytes and prepends an 8-byte
	// integrity check value, so the exact wrapped length is derived from the frame length, not
	// guessed from "always a multiple of 8" or "greater than the frame". Catching the exact
	// length matters because the bit-for-bit round trip below would happily pass if the driver
	// wrapped the wrong thing — the raw 32-byte data key (40 wrapped bytes), magic + plaintext
	// with no digest (48 wrapped bytes), or the actual 68-byte frame (80 wrapped bytes) — as long
	// as the same Wrap/Unwrap pair produced the same bytes back. A derived exact assertion is
	// the only thing that distinguishes "wrapped the frame" from "wrapped something of a similar
	// size".
	//
	// For a 32-byte plaintext: 4 (magic) + 32 (sha256) + 4 (length) + 32 (plaintext) = 72-byte
	// frame (where 4 is the new big-endian length field added by the v2 frame layout), 72 is
	// already a multiple of 8 so no RFC 5649 padding is added, and the 8-byte integrity check
	// value makes 80 bytes. The derivation is the shape to keep; hard-coding 80 would break the
	// test if a future SoftHSM (or this driver) ever changed its output for CKM_AES_KEY_WRAP_PAD,
	// and that change is exactly what the assertion is supposed to surface — a token that
	// stopped honouring RFC 5649 would no longer interoperate with the other
	// AES-KEY-WRAP-PAD-compliant sites.
	//
	// The v2 frame happening to be 8-aligned for the 32-byte data key (envelope.go:220
	// enforces 32 bytes in production) means this test no longer exercises the non-stripping
	// SoftHSM 2.6.1 path: that module returns the padded length instead of the original, but
	// with no padding added, 2.6.1 and a compliant module are indistinguishable on this
	// round trip. The non-stripping signal now lives only in keywrap.TestOpenFrameIgnoresTrailingBytes,
	// which hand-appends junk bytes to a v2 frame and asserts OpenFrame still returns the
	// declared plaintext. Defence for a future payload size that breaks the 8-alignment, not
	// live exposure on the current 32-byte payload.
	wantWrapped := 8 + ((len(frame)+7)/8)*8
	if len(wrapped) != wantWrapped {
		t.Fatalf("session.Wrap(aes-256) length=%d, want %d (RFC 5649: 8-byte ICV + ceil(len(frame)/8)*8): the wrap must produce exactly the frame-derivable length, not just any multiple of 8",
			len(wrapped), wantWrapped)
	}

	unwrapped, err := session.Unwrap(context.Background(), "09", "aes-256", wrapped, aad)
	if err != nil {
		t.Fatalf("session.Unwrap(aes-256) err=%v", err)
	}
	defer zero(unwrapped)
	// BIT-FOR-BIT. Anything less than equality here is a failure: a frame that lost a byte is no
	// longer a frame, and the difference would not be visible to any caller that didn't compare.
	if !bytes.Equal(unwrapped, frame) {
		t.Fatalf("unwrapped = %x, want %x", unwrapped, frame)
	}
	// OpenFrame is the real consumer's check: it re-verifies the magic and the SHA256(aad) prefix
	// before handing the data key back. Without it the unwrap path could return ANY 52 bytes and
	// pass — a different AES key, an attacker-substituted value, a byte off in the magic.
	recovered, err := keywrap.OpenFrame(unwrapped, aad)
	if err != nil {
		t.Fatalf("keywrap.OpenFrame: %v", err)
	}
	if !bytes.Equal(recovered, dataKey) {
		t.Fatalf("OpenFrame recovered %x, want %x", recovered, dataKey)
	}
	// Context-transplant: the same wrapped bytes under a different AAD must refuse. The PKCS#11
	// unwrap itself is aad-blind (CKM_AES_KEY_WRAP_PAD takes no AAD parameter), so the binding
	// check lives in keywrap.OpenFrame, which verifies the SHA256(label) prefix. The driver's
	// session.Unwrap returns the frame; OpenFrame is what catches a context-transplanted blob.
	wrongFrame, err := session.Unwrap(context.Background(), "09", "aes-256", wrapped, []byte("wrong-context"))
	if err != nil {
		t.Fatalf("session.Unwrap(aes-256) with transplanted AAD returned err=%v at the PKCS#11 layer; this should succeed and let OpenFrame do the binding check", err)
	}
	defer zero(wrongFrame)
	if _, err := keywrap.OpenFrame(wrongFrame, []byte("wrong-context")); err == nil {
		t.Fatal("a frame bound to one AAD was accepted under a different AAD: the SHA256(label) binding did not hold")
	}
}

// buildFrame assembles a regalia envelope frame in the shape keywrap.OpenFrame expects:
// frameMagic || SHA256(label) || len(4 BE) || plaintext. The test constructs it in-line rather
// than reaching for keywrap.RSAOAEP because RSAOAEP does the AES-side layout AND the OAEP wrap;
// the AES branch in the driver only does the AES side, so the input to session.Wrap is the
// frame, not a plaintext data key. The length field is what makes the frame self-delimiting
// against a non-compliant C_UnwrapKey that does not strip RFC 5649 padding (measured on SoftHSM
// 2.6.1); see keywrap.OpenFrame for the consumer side.
func buildFrame(label, plaintext []byte) ([]byte, error) {
	if len(label) == 0 {
		return nil, errors.New("frame label is required")
	}
	if len(plaintext) == 0 {
		return nil, errors.New("frame plaintext is required: an empty payload would build a frame keywrap.OpenFrame always rejects, and a fixture that cannot construct a valid case would fail the round-trip below silently rather than loudly")
	}
	digest := sha256.Sum256(label)
	out := make([]byte, 0, 4+sha256.Size+4+len(plaintext))
	out = append(out, 'R', 'G', 'K', 2)
	out = append(out, digest[:]...)
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(plaintext)))
	out = append(out, lengthBuf[:]...)
	out = append(out, plaintext...)
	return out, nil
}
