package openbaopoc

import (
	"context"
	"strings"
	"sync"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// NativeWrapper experiments with the accepted seal blob contract. It remains
// development-only; production hardware qualification remains open.
type NativeWrapper struct {
	mu      sync.RWMutex
	client  *versionedClient
	binding binding
	timeout time.Duration
	lastID  string
}

var _ wrapping.Wrapper = (*NativeWrapper)(nil)

func NewNative() *NativeWrapper { return &NativeWrapper{} }

func (*NativeWrapper) Type(context.Context) (wrapping.WrapperType, error) {
	return wrapping.WrapperType("regalia"), nil
}

func (w *NativeWrapper) KeyId(ctx context.Context) (string, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if ctx.Err() != nil || w.client == nil {
		return "", errOperation
	}
	// OpenBao's startup Encrypt probe discovers the generation. Decrypting an
	// older blob must never move the last observed sealing generation backwards.
	return w.lastID, nil
}

func nativeOptions(b binding, options []wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil || len(opts.WithAad) != 0 || len(opts.WithConfigMap) != 0 {
		return errOperation
	}
	if opts.WithKeyId != "" {
		object, version, qualified := strings.Cut(opts.WithKeyId, "@")
		if object != b.ObjectID || (qualified && !generation.MatchString(version)) {
			return errOperation
		}
	}
	return nil
}

func (w *NativeWrapper) snapshot(ctx context.Context) (*versionedClient, binding, time.Duration, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if ctx.Err() != nil || w.client == nil {
		return nil, binding{}, 0, errOperation
	}
	return w.client, w.binding, w.timeout, nil
}

func (w *NativeWrapper) Encrypt(ctx context.Context, plaintext []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	c, b, timeout, err := w.snapshot(ctx)
	if err != nil || len(plaintext) == 0 || len(plaintext) > nativeMaxPlaintext || nativeOptions(b, options) != nil {
		return nil, errOperation
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := request(b, "seal-envelope", plaintext, nil)
	if err != nil {
		return nil, errOperation
	}
	doc, err := c.seal(ctx, req, nativeMaxEnvelope)
	if err != nil {
		return nil, err
	}
	e, err := nativeEnvelope(doc, b)
	if err != nil || len(e.Ciphertext) != len(plaintext)+16 || ctx.Err() != nil {
		return nil, errOperation
	}
	id := e.ObjectID + "@" + e.KEK.Version
	w.mu.Lock()
	w.lastID = id
	w.mu.Unlock()
	return &wrapping.BlobInfo{Ciphertext: doc, KeyInfo: &wrapping.KeyInfo{KeyId: id}}, nil
}

func (w *NativeWrapper) Decrypt(ctx context.Context, blob *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	c, b, timeout, err := w.snapshot(ctx)
	if err != nil || blob == nil || len(blob.Iv) != 0 || nativeOptions(b, options) != nil {
		return nil, errOperation
	}
	e, err := nativeEnvelope(blob.Ciphertext, b)
	if err != nil {
		return nil, errOperation
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := request(b, "release-secret", blob.Ciphertext, nil)
	if err != nil {
		return nil, errOperation
	}
	// KeyInfo is informational. Only the native envelope and KMS registry route
	// the historical generation; no configured generation or allowlist is used.
	plain, err := c.callBounded(ctx, req, "release-secret", versionedRequest{Payload: blob.Ciphertext}, "application/vnd.regalia.secret", nativeMaxPlaintext)
	if err != nil {
		clear(plain)
		return nil, err
	}
	if len(plain) != len(e.Ciphertext)-16 || ctx.Err() != nil {
		clear(plain)
		return nil, errOperation
	}
	return plain, nil
}
