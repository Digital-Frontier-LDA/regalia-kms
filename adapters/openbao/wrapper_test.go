package openbaopoc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sops "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

type testKMS struct {
	lastKey []byte
	fail    bool
	short   bool
	calls   int
}

func (k *testKMS) Wrap(ctx context.Context, req sops.Request) ([]byte, error) {
	k.calls++
	k.lastKey = req.Data
	if k.fail {
		return nil, errors.New("provider secret must never escape")
	}
	aead, _ := gcm(bytes.Repeat([]byte{42}, 32))
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	return aead.Seal(nonce, nonce, req.Data, []byte(req.Path)), nil
}
func (k *testKMS) Unwrap(ctx context.Context, req sops.Request) ([]byte, error) {
	k.calls++
	if k.fail {
		return nil, errors.New("provider secret must never escape")
	}
	if k.short {
		return []byte{1}, nil
	}
	if len(req.Data) < 12 {
		return nil, errOperation
	}
	aead, _ := gcm(bytes.Repeat([]byte{42}, 32))
	return aead.Open(nil, req.Data[:12], req.Data[12:], []byte(req.Path))
}
func testWrapper() (*Wrapper, *testKMS) {
	k := &testKMS{}
	return &Wrapper{client: k, binding: binding{"poc-seal-key", "example/poc", "fixtures/seal", "development", "openbao-seal"}, configured: true}, k
}

func TestEnvelopeRoundTripAndDataKeyBoundary(t *testing.T) {
	for _, size := range []int{0, 1, 32, 4096, maxPayload} {
		w, k := testWrapper()
		plain := bytes.Repeat([]byte{99}, size)
		blob, err := w.Encrypt(context.Background(), plain, wrapping.WithAad([]byte("root-key")))
		if err != nil {
			t.Fatal(err)
		}
		if len(k.lastKey) != 32 || !bytes.Equal(k.lastKey, make([]byte, 32)) {
			t.Fatal("data key not limited to 32 bytes and cleared")
		}
		out, err := w.Decrypt(context.Background(), blob, wrapping.WithAad([]byte("root-key")))
		if err != nil || !bytes.Equal(out, plain) {
			t.Fatalf("roundtrip at size %d failed: %v", size, err)
		}
	}
}

func TestEveryAuthenticatedComponentRejectsTampering(t *testing.T) {
	w, _ := testWrapper()
	original, err := w.Encrypt(context.Background(), []byte("secret"), wrapping.WithAad([]byte("root-key")))
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"payload", "wrapped_key", "nonce", "key_id", "version", "frame_key_id", "unknown_field", "duplicate_field", "trailing_json", "aad", "binding"} {
		t.Run(part, func(t *testing.T) {
			blob := proto.Clone(original).(*wrapping.BlobInfo)
			aad := []byte("root-key")
			target, _ := testWrapper()
			var f frame
			_ = json.Unmarshal(blob.Ciphertext, &f)
			switch part {
			case "payload":
				f.Payload[0] ^= 1
			case "wrapped_key":
				f.WrappedKey[len(f.WrappedKey)-1] ^= 1
			case "nonce":
				blob.Iv[0] ^= 1
			case "key_id":
				blob.KeyInfo.KeyId = "another-key"
			case "version":
				f.Version = 2
			case "frame_key_id":
				f.KeyID = "another-key"
			case "aad":
				aad = []byte("different")
			case "binding":
				target.binding.Purpose = "another-purpose"
			}
			blob.Ciphertext, _ = json.Marshal(f)
			if part == "unknown_field" {
				blob.Ciphertext = append(blob.Ciphertext[:len(blob.Ciphertext)-1], []byte(`,"extra":true}`)...)
			}
			if part == "trailing_json" {
				blob.Ciphertext = append(blob.Ciphertext, []byte(` {}`)...)
			}
			if part == "duplicate_field" {
				blob.Ciphertext = append([]byte(`{"version":1,`), blob.Ciphertext[1:]...)
			}
			out, err := target.Decrypt(context.Background(), blob, wrapping.WithAad(aad))
			if err == nil || len(out) != 0 {
				t.Fatal("tampered component released plaintext")
			}
		})
	}
}

func TestRequestsAreFreshAndCiphertextRandomized(t *testing.T) {
	w, _ := testWrapper()
	ctx := context.Background()
	a, err := w.Encrypt(ctx, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := w.Encrypt(ctx, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) || bytes.Equal(a.Iv, b.Iv) {
		t.Fatal("reused key or nonce")
	}
	r1, _ := request(w.binding, "wrap", nil, nil)
	r2, _ := request(w.binding, "wrap", nil, nil)
	if r1.RequestID == r2.RequestID || strings.Compare(r1.IdempotencyKey, r2.IdempotencyKey) == 0 {
		t.Fatal("replayed request identity")
	}
}

func TestNilAndEmptyAADAreEquivalent(t *testing.T) {
	w, _ := testWrapper()
	blob, err := w.Encrypt(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := w.Decrypt(context.Background(), blob, wrapping.WithAad([]byte{}))
	if err != nil || !bytes.Equal(plain, []byte("payload")) {
		t.Fatal("empty AAD differs from nil")
	}
}

func TestFailuresAreBoundedAndRedacted(t *testing.T) {
	w, k := testWrapper()
	ctx := context.Background()
	if _, err := w.Encrypt(ctx, make([]byte, maxPayload+1)); err == nil || k.calls != 0 {
		t.Fatal("oversize reached KMS")
	}
	k.fail = true
	if _, err := w.Encrypt(ctx, []byte("payload")); err != errOperation || k.calls != 1 {
		t.Fatal("backend error escaped or operation retried")
	}
	if !bytes.Equal(k.lastKey, make([]byte, 32)) {
		t.Fatal("failed wrap retained data key")
	}
	k.fail = false
	blob, err := w.Encrypt(ctx, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	k.short = true
	if out, err := w.Decrypt(ctx, blob); err == nil || len(out) != 0 {
		t.Fatal("short data key accepted")
	}
	k.short = false
	if _, err := w.Decrypt(ctx, blob, wrapping.WithKeyId("unknown")); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := w.Decrypt(ctx, nil); err == nil {
		t.Fatal("nil blob accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	before := k.calls
	if _, err := w.Encrypt(cancelled, []byte("payload")); err == nil || k.calls != before {
		t.Fatal("cancelled call reached KMS")
	}
	if _, err := New().Encrypt(ctx, []byte("payload")); err == nil {
		t.Fatal("unconfigured wrapper accepted")
	}
}
