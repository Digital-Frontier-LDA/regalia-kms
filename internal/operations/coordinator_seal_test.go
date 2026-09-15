package operations

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// sealRoute is a route as RouteForSeal returns one: the object is opaque, and the
// KEK identity comes from the binding, never the caller.
func sealRoute() registry.Route {
	return registry.Route{
		ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Algorithm: "opaque", PolicyID: "sops", KEKAlgorithm: "rsa2048", KEKVersion: "k1",
		Binding: registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-1"},
	}
}

// assembleSealInputs plays the client: encrypt locally, then hand the assembled
// parts to the server. The AAD is replicated from the envelope format without API
// help, which is deliberate — the server independently reconstructs it.
func assembleSealInputs(t *testing.T, route registry.Route, plaintext []byte) (ciphertext, nonce, dataKey []byte) {
	t.Helper()
	dataKey = []byte("0123456789abcdef0123456789abcdef")
	nonce = []byte("123456789012")
	aead, err := cipher.NewGCM(mustAES(t, dataKey))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment))
	contentAAD := []byte("regalia-envelope-v2\x00" + route.ObjectID + "\x00AES-256-GCM\x00" + "sha256:" + hex.EncodeToString(digest[:]))
	ciphertext = aead.Seal(nil, nonce, plaintext, contentAAD)
	return ciphertext, nonce, dataKey
}

func mustAES(t *testing.T, key []byte) cipher.Block {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	return block
}

func sealRequest(route registry.Route, ciphertext, nonce, dataKey []byte) api.Request {
	request := operationRequest()
	request.Operation = "seal-envelope"
	request.Format = "regalia-envelope-v2"
	request.Data = nil
	request.SealCiphertext = ciphertext
	request.SealNonce = nonce
	request.SealDataKey = dataKey
	request.ObjectID = route.ObjectID
	return request
}

// openableEnvelope proves the returned envelope opens under the served binding's
// context with a wrapper holding the wrapped key — the whole point of sealing.
type openStub struct{ dataKey []byte }

func (stub openStub) Backend() string { return "nitrokey-pkcs11" }
func (stub openStub) WrapKey(context.Context, envelope.KeyRef, []byte, []byte) ([]byte, error) {
	return nil, errors.New("not used in this test")
}
func (stub openStub) UnwrapKey(context.Context, envelope.KeyRef, []byte, []byte) ([]byte, error) {
	return append([]byte(nil), stub.dataKey...), nil
}

// SEALING IS SERVED, AND WHAT IS SERVED OPENS.
//
// Until now every envelope the KMS could release had to be constructed by hand
// against the Go API: the primitive existed, the registry routed it, and no
// request reached either. The test drives the coordinator end to end and opens
// the result — an envelope that cannot be opened is not a product.
func TestSealEnvelopeProducesAnOpenableEnvelope(t *testing.T) {
	route := sealRoute()
	router := &fakeRouter{route: route}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("wrapped-by-the-card")}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("the secret itself"))
	// SealAssembled zeroes the caller's data key slice; retain a copy before the call.
	retained := append([]byte(nil), dataKey...)
	result, err := coordinator.Execute(context.Background(), sealRequest(route, ciphertext, nonce, dataKey))
	if err != nil {
		t.Fatalf("seal-envelope = %v", err)
	}
	produced, err := envelope.Parse(result.Data)
	if err != nil {
		t.Fatalf("the response is not an envelope: %v", err)
	}
	if produced.KEK.Backend != "nitrokey-pkcs11" || produced.KEK.ID != route.ObjectID || produced.KEK.Version != "k1" {
		t.Fatalf("envelope KEK = %#v, want the route's binding identity — never the caller's", produced.KEK)
	}
	if string(produced.WrappedDataKey) != "wrapped-by-the-card" {
		t.Fatalf("wrapped data key = %q, want the hardware's wrap", produced.WrappedDataKey)
	}
	var opened []byte
	if err := produced.Open(context.Background(), openStub{retained}, envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment), func(plaintext []byte) error {
		opened = append([]byte(nil), plaintext...)
		return nil
	}); err != nil {
		t.Fatalf("the sealed envelope does not open: %v", err)
	}
	if string(opened) != "the secret itself" {
		t.Fatalf("opened %q, want the sealed plaintext", opened)
	}
	// The card was asked to wrap with the KEK's algorithm, once — §3's rule: assert
	// the value the double received, because a double that accepts anything cannot fail.
	if hardware.calls != 1 {
		t.Fatalf("hardware calls = %d, want exactly one wrap", hardware.calls)
	}
	if len(recorder.drafts) != 2 || recorder.drafts[1].Operation != "seal-envelope" {
		t.Fatalf("audit drafts = %#v", recorder.drafts)
	}
}

// RELEASE AND SEAL ARE SEPARATE GRANTS, NOT ONE.
//
// A policy that admits release-secret and says nothing about seal-envelope must
// deny sealing: otherwise the two operations silently collapse into one grant,
// and a read credential can mint envelopes. Checked at the coordinator with the
// operation carried unmapped to the policy engine.
func TestSealEnvelopeDeniedWhenOnlyReleaseIsGranted(t *testing.T) {
	route := sealRoute()
	router := &fakeRouter{route: route}
	semantic := &fakePolicy{decision: policy.Decision{Code: policy.CodeDenied, PolicyID: "sops", Rule: "unknown-object"}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("wrapped")}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("secret"))
	_, err = coordinator.Execute(context.Background(), sealRequest(route, ciphertext, nonce, dataKey))
	var failure *api.Failure
	if !errors.As(err, &failure) || failure.Status != 403 {
		t.Fatalf("seal under a release-only policy = %v, want 403 DENIED", err)
	}
	if hardware.calls != 0 {
		t.Fatal("hardware was reached under a policy that never admitted the operation")
	}
	if semantic.lastRequest.Operation != "seal-envelope" {
		t.Fatalf("the policy engine was asked about %q, not seal-envelope: the operations collapsed somewhere above it", semantic.lastRequest.Operation)
	}
	if len(recorder.drafts) != 1 || recorder.drafts[0].Decision != "deny" || recorder.drafts[0].Operation != "seal-envelope" {
		t.Fatalf("audit drafts = %#v", recorder.drafts)
	}
}

// A TAMPERED BLOB FAILS AS INTEGRITY, NOT AS ANYTHING ELSE.
//
// A wrong-context refusal and a tampered-ciphertext refusal look identical from
// outside unless the status says which: tampering is a 400 (the caller's bytes
// failed the AEAD proof), a deny is a 403, and a backend fault is a 503. Only the
// first proves the integrity check did its job, and it must happen before the
// hardware is asked to wrap anything.
func TestSealEnvelopeRejectsTamperedCiphertextAsIntegrityFailure(t *testing.T) {
	route := sealRoute()
	router := &fakeRouter{route: route}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("wrapped")}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("secret"))
	ciphertext[3] ^= 0xff // tamper after assembly
	_, err = coordinator.Execute(context.Background(), sealRequest(route, ciphertext, nonce, dataKey))
	var failure *api.Failure
	if !errors.As(err, &failure) || failure.Status != 400 || failure.Code != "INVALID_ARGUMENT" {
		t.Fatalf("tampered ciphertext = %v, want 400 INVALID_ARGUMENT — a 403 would mean it failed as authorization, a 503 as a backend fault", err)
	}
	if hardware.calls != 0 {
		t.Fatal("the hardware wrapped a blob whose AEAD tag did not verify: the integrity check must fire first")
	}
}
