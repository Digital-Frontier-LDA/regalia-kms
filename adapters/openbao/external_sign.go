package openbaopoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

var rsaDigestPrefix = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func (k *externalKey) signingInput(data []byte, prehashed bool, opts crypto.SignerOpts) ([]byte, error) {
	switch o := opts.(type) {
	case crypto.Hash:
	case *ed25519.Options:
		if o == nil {
			return nil, errOperation
		}
	default:
		return nil, errOperation
	}
	if opts == nil || opts.HashFunc() != k.hash || len(data) == 0 || len(data) > 1<<20 {
		return nil, errOperation
	}
	if _, ok := k.public.(ed25519.PublicKey); ok {
		if len(data) > 1024 {
			return nil, errOperation
		}
		switch o := opts.(type) {
		case crypto.Hash:
		case *ed25519.Options:
			if o.Context != "" || o.Hash != 0 {
				return nil, errOperation
			}
		default:
			return nil, errOperation
		}
		// Pure Ed25519 ignores Prehashed per the SDK. The bytes are the message.
		return bytes.Clone(data), nil
	}
	if _, ok := opts.(crypto.Hash); !ok {
		return nil, errOperation
	} // includes RSA-PSS
	if prehashed {
		if len(data) != k.hash.Size() {
			return nil, errOperation
		}
		return bytes.Clone(data), nil
	}
	h := k.hash.New()
	h.Write(data)
	return h.Sum(nil), nil
}

func (k *externalKey) verify(data, sig []byte) bool {
	switch public := k.public.(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(public, data, sig)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(public, k.hash, data, sig) == nil
	case ed25519.PublicKey:
		return ed25519.Verify(public, data, sig)
	}
	return false
}

func (k *externalKey) Sign(ctx context.Context, opts *kms.SignOptions) ([]byte, error) {
	call, cancel, err := k.provider.keyContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if opts == nil {
		return nil, errOperation
	}
	input, err := k.signingInput(opts.Data, opts.Prehashed, opts.SignerOpts)
	if err != nil {
		return nil, err
	}
	defer clear(input)
	payload := input
	if _, ok := k.public.(*rsa.PublicKey); ok {
		payload = append(bytes.Clone(rsaDigestPrefix[k.hash]), input...)
		defer clear(payload)
	}
	req, err := request(k.client.binding, "sign", payload, nil)
	if err != nil {
		return nil, errOperation
	}
	sig, err := k.client.nativeCall(call, req, "sign", versionedRequest{ContentType: "application/vnd.regalia.digest", Payload: payload}, "application/octet-stream", 4096)
	if err != nil {
		return nil, err
	}
	if public, ok := k.public.(*ecdsa.PublicKey); ok {
		width := (public.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*width {
			clear(sig)
			return nil, errOperation
		}
		r, s := new(big.Int).SetBytes(sig[:width]), new(big.Int).SetBytes(sig[width:])
		clear(sig)
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(public.Params().N) >= 0 || s.Cmp(public.Params().N) >= 0 {
			return nil, errOperation
		}
		sig, err = asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			return nil, errOperation
		}
	}
	if !k.verify(input, sig) || call.Err() != nil {
		clear(sig)
		return nil, errOperation
	}
	return sig, nil
}

func (k *externalKey) Verify(ctx context.Context, opts *kms.VerifyOptions) error {
	call, cancel, err := k.provider.keyContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if opts == nil {
		return errOperation
	}
	input, err := k.signingInput(opts.Data, opts.Prehashed, opts.SignerOpts)
	if err != nil {
		return err
	}
	defer clear(input)
	if call.Err() != nil {
		return contextError(call.Err(), "")
	}
	if !k.verify(input, opts.Signature) {
		return kms.ErrInvalidSignature
	}
	return nil
}
