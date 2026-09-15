package sopsadapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops/sopsrpc"
)

// bindingContextKMS is a context-aware KMSClient fake. Wrap records the
// plaintext keyed by the binding-context fields the adapter fills
// (ObjectID, Repository, Path, Environment, Purpose); Unwrap refuses any
// request whose context does not match what was recorded. The synthesized
// ciphertext is a random nonce; the context check uses structural equality
// on the field tuple, not a delimiter-joined string.
//
// This models the real KMS's refusal to decrypt an envelope under a
// purpose/environment it was not wrapped against, which is the property
// envelope.ReleaseContext exists for and the property a migration to a
// context-blind KMS would silently lose. The existing roundTripKMS in
// interop_test.go is context-blind by design (it stores the first wrap's
// data key and returns it on every unwrap) — that is the regression a
// migration would introduce, and these tests pin that it would fail here.
//
// The struct key avoids the `|` delimiter collision from #210
// (CanonicalBytes): safePath does not exclude `|`, so a Path containing
// `|` could produce the same joined-string key as a different (Path,
// Environment) pair. Structural equality on the field tuple cannot
// collide regardless of delimiter content.
type bindingContextKMS struct {
	mu      sync.Mutex
	entries map[string]bindingContextEntry // keyed by ciphertext
}

type bindingContextKey struct {
	ObjectID    string
	Repository  string
	Path        string
	Environment string
	Purpose     string
}

type bindingContextEntry struct {
	context   bindingContextKey
	plaintext []byte
}

func contextKey(request Request) bindingContextKey {
	return bindingContextKey{
		ObjectID:    request.ObjectID,
		Repository:  request.Repository,
		Path:        request.Path,
		Environment: request.Environment,
		Purpose:     request.Purpose,
	}
}

func (client *bindingContextKMS) Wrap(_ context.Context, request Request) ([]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, hex.EncodedLen(len(nonce)))
	hex.Encode(ciphertext, nonce)
	if client.entries == nil {
		client.entries = make(map[string]bindingContextEntry)
	}
	client.entries[string(ciphertext)] = bindingContextEntry{
		context:   contextKey(request),
		plaintext: append([]byte(nil), request.Data...),
	}
	return ciphertext, nil
}

func (client *bindingContextKMS) Unwrap(_ context.Context, request Request) ([]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	entry, ok := client.entries[string(request.Data)]
	if !ok {
		return nil, errors.New("unknown ciphertext")
	}
	if entry.context != contextKey(request) {
		return nil, errors.New("binding context mismatch")
	}
	return append([]byte(nil), entry.plaintext...), nil
}

// TestBindingContextKeyIsCollisionFree pins that two distinct binding
// contexts produce distinct struct keys regardless of delimiter-like
// content in any field. The peer (regalia-12) reported the previous
// `|`-joined encoding was not collision-free: safePath does not exclude
// `|`, so a Path containing `|` could produce the same joined string as
// a different (Path, Environment) pair.
//
// The two contexts below have distinct field values but produce the
// SAME `|`-joined string — they are the falsification inputs for the
// defect class. Under the joined encoding the collision is reachable
// today (it requires only Path to contain `|`, which safePath allows);
// under the struct encoding the fields are structurally distinct and
// the keys cannot be equal.
func TestBindingContextKeyIsCollisionFree(t *testing.T) {
	a := bindingContextKey{
		ObjectID:    "oid",
		Repository:  "repo",
		Path:        "x|staging",
		Environment: "production",
		Purpose:     "p",
	}
	b := bindingContextKey{
		ObjectID:    "oid",
		Repository:  "repo",
		Path:        "x",
		Environment: "staging|production",
		Purpose:     "p",
	}
	if a == b {
		t.Fatalf("bindingContextKey collision: %+v == %+v — the struct key is not collision-free; under a `|`-joined encoding these inputs produce the identical string \"oid|repo|x|staging|production|p\"", a, b)
	}
}

// TestRoundTripEncryptThenDecryptMatchesPlaintext pins that the adapter
// preserves the binding context end-to-end: an Encrypt → Decrypt round
// trip under the same context recovers the original plaintext
// byte-for-byte. A migration to a context-blind KMS would also pass
// this test, which is why TestRoundTripFailsUnderDifferentContext pins
// the failure direction separately.
func TestRoundTripEncryptThenDecryptMatchesPlaintext(t *testing.T) {
	client := &bindingContextKMS{}
	server := New(client)
	key := sopsKey()
	plaintext := []byte("01234567890123456789012345678901") // 32 bytes — the SOPS data-key shape

	encrypted, err := server.Encrypt(context.Background(), &sopsrpc.EncryptRequest{
		Key: key, Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if len(encrypted.Ciphertext) == 0 {
		t.Fatal("Encrypt() returned empty ciphertext")
	}

	decrypted, err := server.Decrypt(context.Background(), &sopsrpc.DecryptRequest{
		Key: key, Ciphertext: encrypted.Ciphertext,
	})
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if !bytes.Equal(decrypted.Plaintext, plaintext) {
		t.Fatalf("Decrypt() = %q, want %q — the binding context did not survive the round trip",
			decrypted.Plaintext, plaintext)
	}
}

// TestRoundTripFailsUnderDifferentContext pins that an envelope produced
// under one purpose does NOT decrypt under another. This is the property
// envelope.ReleaseContext exists for: the real KMS derives the AAD from
// (object_id, purpose, environment), and decrypting under a different
// purpose is structurally invalid. The plain-text content of the
// decryption response is also asserted empty, because a context-blind
// KMS would return a non-nil plaintext with the wrong purpose and
// silently leak the data key — exit-status is not enough.
//
// Falsifications this test is designed to catch:
//   - bindingContextKMS.Unwrap (line 82) drops the entry.context check:
//     Decrypt succeeds and returns the original plaintext under
//     mismatched purpose — the len(plaintext)>0 assertion fires.
//   - The adapter translates the SOPS key's purpose into something
//     other than what the caller supplied: Decrypt succeeds for a
//     different reason (the adapter overrode the purpose to match
//     Wrap's) and the err==nil assertion fires.
//   - The test is removed: nothing catches the regression.
func TestRoundTripFailsUnderDifferentContext(t *testing.T) {
	client := &bindingContextKMS{}
	server := New(client)
	keyA := sopsKey()
	plaintext := []byte("01234567890123456789012345678901")

	encrypted, err := server.Encrypt(context.Background(), &sopsrpc.EncryptRequest{
		Key: keyA, Plaintext: plaintext,
	})
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	keyB := sopsKey()
	keyB.GetKmsKey().Context["purpose"] = "another-purpose"

	decrypted, err := server.Decrypt(context.Background(), &sopsrpc.DecryptRequest{
		Key: keyB, Ciphertext: encrypted.Ciphertext,
	})
	if err == nil {
		t.Fatalf("Decrypt() succeeded under mismatched purpose %q, want error — an envelope produced under %q must not decrypt under a different purpose; this is the property a context-blind KMS migration would silently lose",
			keyB.GetKmsKey().Context["purpose"], keyA.GetKmsKey().Context["purpose"])
	}
	if decrypted != nil && len(decrypted.Plaintext) > 0 {
		t.Fatalf("Decrypt() leaked %d bytes of plaintext under mismatched context: the error path must not return a non-empty data key",
			len(decrypted.Plaintext))
	}
}
