// Package openbaopoc implements a development-only OpenBao seal adapter.
package openbaopoc

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"

	sops "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

const maxPayload = 1 << 20
const maxWrappedKey = 48 << 10

var errConfig = errors.New("invalid Regalia PoC configuration")
var errOperation = errors.New("Regalia PoC operation failed")

type binding struct {
	ObjectID    string `json:"object_id"`
	Repository  string `json:"repository"`
	Path        string `json:"path"`
	Environment string `json:"environment"`
	Purpose     string `json:"purpose"`
	KeyVersion  string `json:"key_version,omitempty"`
}

type frame struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	WrappedKey []byte `json:"wrapped_key"`
	Payload    []byte `json:"payload"`
}

type Wrapper struct {
	mu         sync.RWMutex
	client     sops.KMSClient
	binding    binding
	configured bool
	historical map[string]bool
}

var _ wrapping.Wrapper = (*Wrapper)(nil)

func New() *Wrapper { return &Wrapper{} }

func (*Wrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperType("regalia-poc"), nil
}

func (w *Wrapper) KeyId(ctx context.Context) (string, error) {
	_, b, err := w.snapshot(ctx)
	if err != nil {
		return "", err
	}
	return keyID(b), nil
}

func keyID(b binding) string {
	if b.KeyVersion != "" {
		return "regalia-poc-v2:" + b.ObjectID + ":" + b.KeyVersion
	}
	return "regalia-poc-v1:" + b.ObjectID
}

func frameVersion(b binding) int {
	if b.KeyVersion != "" {
		return 2
	}
	return 1
}

func (w *Wrapper) snapshot(ctx context.Context) (sops.KMSClient, binding, error) {
	if ctx.Err() != nil {
		return nil, binding{}, errOperation
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.configured || w.client == nil {
		return nil, binding{}, errOperation
	}
	return w.client, w.binding, nil
}

func operationOptions(b binding, options []wrapping.Option) (*wrapping.Options, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil || len(opts.WithAad) > maxPayload ||
		(opts.WithKeyId != "" && opts.WithKeyId != keyID(b)) || len(opts.WithConfigMap) != 0 {
		return nil, errOperation
	}
	return opts, nil
}

func request(b binding, operation string, data, aad []byte) (sops.Request, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return sops.Request{}, errOperation
	}
	id[6], id[8] = id[6]&0x0f|0x40, id[8]&0x3f|0x80
	s := hex.EncodeToString(id)
	uuid := s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
	digest := sha256.Sum256(aad)
	return sops.Request{Operation: operation, ObjectID: b.ObjectID, Repository: b.Repository,
		Path: b.Path + "/" + hex.EncodeToString(digest[:]), Environment: b.Environment, Purpose: b.Purpose,
		RequestID: uuid, IdempotencyKey: "openbao-poc-" + s, Data: data}, nil
}

func associatedData(b binding, aad []byte) []byte {
	if len(aad) == 0 {
		aad = nil
	}
	// Struct encoding is canonical for this version; every field is authenticated.
	data, _ := json.Marshal(struct {
		Version int     `json:"version"`
		Binding binding `json:"binding"`
		AAD     []byte  `json:"aad"`
	}{frameVersion(b), b, aad})
	return data
}

func gcm(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errOperation
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errOperation
	}
	return cipher.NewGCM(block)
}

func (w *Wrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	client, b, err := w.snapshot(ctx)
	if err != nil || len(plaintext) > maxPayload {
		return nil, errOperation
	}
	opts, err := operationOptions(b, options)
	if err != nil {
		return nil, errOperation
	}
	dek := make([]byte, 32)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return nil, errOperation
	}
	req, err := request(b, "wrap", dek, opts.WithAad)
	if err != nil {
		return nil, errOperation
	}
	wrapped, err := client.Wrap(ctx, req)
	if err != nil || len(wrapped) == 0 || len(wrapped) > maxWrappedKey {
		return nil, errOperation
	}
	aead, err := gcm(dek)
	if err != nil {
		return nil, errOperation
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errOperation
	}
	sealed := aead.Seal(nil, nonce, plaintext, associatedData(b, opts.WithAad))
	encoded, err := json.Marshal(frame{frameVersion(b), keyID(b), wrapped, sealed})
	if err != nil || ctx.Err() != nil {
		return nil, errOperation
	}
	return &wrapping.BlobInfo{Ciphertext: encoded, Iv: nonce, KeyInfo: &wrapping.KeyInfo{KeyId: keyID(b)}}, nil
}

func (w *Wrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	client, b, err := w.snapshot(ctx)
	if err != nil || blob == nil || blob.KeyInfo == nil ||
		blob.KeyInfo.Mechanism != 0 || len(blob.KeyInfo.WrappedKey) != 0 || len(blob.Iv) != 12 ||
		len(blob.Ciphertext) == 0 || len(blob.Ciphertext) > 2*(maxPayload+maxWrappedKey) {
		return nil, errOperation
	}
	if b, err = w.decryptBinding(b, blob.KeyInfo.KeyId); err != nil {
		return nil, errOperation
	}
	opts, err := operationOptions(b, options)
	if err != nil {
		return nil, errOperation
	}
	decoder := json.NewDecoder(bytes.NewReader(blob.Ciphertext))
	decoder.DisallowUnknownFields()
	var f frame
	if decoder.Decode(&f) != nil {
		return nil, errOperation
	}
	var extra any
	if !errors.Is(decoder.Decode(&extra), io.EOF) || f.Version != frameVersion(b) || f.KeyID != keyID(b) ||
		len(f.WrappedKey) == 0 || len(f.WrappedKey) > maxWrappedKey || len(f.Payload) < 16 || len(f.Payload) > maxPayload+16 {
		return nil, errOperation
	}
	canonical, _ := json.Marshal(f)
	if !bytes.Equal(canonical, blob.Ciphertext) {
		// Refuse duplicate keys and alternate encodings, not merely unknown fields.
		return nil, errOperation
	}
	if b.KeyVersion != "" && !validInnerEnvelope(f.WrappedKey, b) {
		return nil, errOperation
	}
	req, err := request(b, "unwrap", f.WrappedKey, opts.WithAad)
	if err != nil {
		return nil, errOperation
	}
	dek, err := client.Unwrap(ctx, req)
	defer clear(dek)
	if err != nil || len(dek) != 32 {
		return nil, errOperation
	}
	aead, err := gcm(dek)
	if err != nil {
		return nil, errOperation
	}
	plain, err := aead.Open(nil, blob.Iv, f.Payload, associatedData(b, opts.WithAad))
	if err != nil || ctx.Err() != nil {
		clear(plain)
		return nil, errOperation
	}
	return plain, nil
}
