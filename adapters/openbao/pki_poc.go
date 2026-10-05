package openbaopoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// ExternalPKIPoC is served only by the separate PKI experiment executable.
// It forwards full TBS bytes to a development software-token fixture that must
// inspect them before signing. NewExternal still refuses all CA mappings.
// This is not production PKI policy, a hardware provider or a released plugin.
type ExternalPKIPoC struct{ *ExternalKMS }

func NewExternalPKIPoC() *ExternalPKIPoC { return &ExternalPKIPoC{NewExternal()} }

func (p *ExternalPKIPoC) GetKey(ctx context.Context, opts *kms.KeyOptions) (kms.Key, error) {
	if opts == nil || opts.ConfigMap["usage"] != "x509-ca" || opts.ConfigMap["object_id"] != "poc-pki-ca" ||
		opts.ConfigMap["purpose"] != "openbao-pki-poc" || opts.ConfigMap["algorithm"] != "p256" || opts.ConfigMap["hash_algorithm"] != "sha256" {
		return nil, errConfig
	}
	config := kms.ConfigMap{}
	for name, value := range opts.ConfigMap {
		config[name] = value
	}
	config["usage"] = "signing" // Reuse strict SPKI pin/config parsing only.
	key, err := p.ExternalKMS.GetKey(ctx, &kms.KeyOptions{ConfigMap: config})
	if err != nil {
		return nil, err
	}
	return &pkiPOCKey{externalKey: key.(*externalKey)}, nil
}

type pkiPOCKey struct{ *externalKey }

func pkiPOCInput(opts *kms.SignOptions) bool {
	if opts == nil || opts.Prehashed || len(opts.Data) == 0 || len(opts.Data) > 32<<10 {
		return false
	}
	hash, ok := opts.SignerOpts.(crypto.Hash)
	return ok && hash == crypto.SHA256
}

func (k *pkiPOCKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	if !pkiPOCInput(opts) {
		return nil, errOperation
	}
	call, cancel, err := k.provider.keyContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	input := bytes.Clone(opts.Data)
	defer clear(input)
	req, err := request(k.client.binding, "sign", input, nil)
	if err != nil {
		return nil, errOperation
	}
	// CA execution errors can be ambiguous even when the server labels them
	// retryable. This experiment sends one attempt and never advertises a retry.
	sig, err := k.client.nativeAttempt(call, req, "sign", versionedRequest{ContentType: "application/vnd.regalia.x509-tbs", Payload: input}, "application/octet-stream", 4096)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) {
			safe := *apiErr
			safe.Retryable = false
			return nil, &safe
		}
		return nil, err
	}
	defer clear(sig)
	public := k.public.(*ecdsa.PublicKey)
	if len(sig) != 64 {
		return nil, errOperation
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(public.Params().N) >= 0 || s.Cmp(public.Params().N) >= 0 {
		return nil, errOperation
	}
	encoded, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	// Hash only after forwarding the complete input, for local verification.
	h := crypto.SHA256.New()
	h.Write(input)
	if err != nil || !k.verify(h.Sum(nil), encoded) || call.Err() != nil {
		clear(encoded)
		return nil, errOperation
	}
	return encoded, nil
}

func (k *pkiPOCKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	if opts == nil || !pkiPOCInput(&kms.SignOptions{Data: opts.Data, Prehashed: opts.Prehashed, SignerOpts: opts.SignerOpts}) {
		return errOperation
	}
	return k.externalKey.Verify(ctx, opts)
}
