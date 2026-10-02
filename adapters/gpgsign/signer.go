package gpgsign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

// digestInfoPrefix is the DER encoding of DigestInfo up to the digest (RFC 8017 §9.2, note 1). The
// KMS signs an RSA key with CKM_RSA_PKCS, which pads what it is given and does not build this
// structure, so the caller sends DigestInfo. Every result is checked with rsa.VerifyPKCS1v15, which
// builds its own: a wrong byte here fails every signature, it cannot produce a bad one.
var digestInfoPrefix = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// signCall is the KMS operation a Signer drives; *Client.Sign with its target bound.
type signCall func(ctx context.Context, payload []byte, subject string) ([]byte, error)

// Signer signs digests with a key held by the KMS. It knows the key only by its PUBLIC half, which
// the operator pins in the configuration, and it returns no signature that half does not verify:
// a KMS routed to another key, or an answer altered on the way, yields an error and never a
// signature somebody later fails to verify.
type Signer struct {
	public crypto.PublicKey
	hash   crypto.Hash
	call   signCall
}

// NewSigner binds a pinned public key to the KMS object that holds its private half. The key type
// fixes the digest: SHA-256 for P-256, RSA and Ed25519, SHA-384 for P-384. One key, one digest — the purpose
// policy's payload size is exact, and a caller cannot ask for a weaker hash.
func NewSigner(public crypto.PublicKey, client *Client, target Target) (*Signer, error) {
	if client == nil || !target.valid() {
		return nil, errors.New("a signer needs a KMS client and a valid target")
	}
	hash, err := digestFor(public)
	if err != nil {
		return nil, err
	}
	return &Signer{public: public, hash: hash, call: func(ctx context.Context, payload []byte, subject string) ([]byte, error) {
		return client.Sign(ctx, target, payload, subject)
	}}, nil
}

func digestFor(public crypto.PublicKey) (crypto.Hash, error) {
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return crypto.SHA256, nil
		case elliptic.P384():
			return crypto.SHA384, nil
		}
		return 0, errors.New("the release key must be on P-256 or P-384")
	case *rsa.PublicKey:
		switch key.N.BitLen() {
		case 2048, 3072, 4096:
			return crypto.SHA256, nil
		}
		return 0, errors.New("the release key must be RSA-2048, RSA-3072 or RSA-4096")
	case ed25519.PublicKey:
		if len(key) == ed25519.PublicKeySize {
			return crypto.SHA256, nil
		}
		return 0, errors.New("the release key is not a valid Ed25519 public key")
	}
	return 0, errors.New("the release key must be ECDSA (P-256, P-384), RSA or Ed25519")
}

// Public returns the pinned public key.
func (signer *Signer) Public() crypto.PublicKey { return signer.public }

// Hash returns the one digest this key signs.
func (signer *Signer) Hash() crypto.Hash { return signer.hash }

// SignDigest returns a signature over digest in the form crypto.Signer promises: ASN.1 DER for
// ECDSA, the PKCS #1 v1.5 signature for RSA, the 64 bytes R||S for Ed25519. It has already been
// verified against the pinned key.
func (signer *Signer) SignDigest(ctx context.Context, digest []byte, hash crypto.Hash, subject string) ([]byte, error) {
	if hash != signer.hash || len(digest) != hash.Size() {
		return nil, errors.New("this key signs only its own digest algorithm")
	}
	switch key := signer.public.(type) {
	case *ecdsa.PublicKey:
		raw, err := signer.call(ctx, digest, subject)
		if err != nil {
			return nil, err
		}
		// The token returns r||s, each the size of the curve order (CKM_ECDSA).
		size := (key.Curve.Params().N.BitLen() + 7) / 8
		if len(raw) != 2*size {
			return nil, errors.New("the KMS returned a signature of the wrong size for this key")
		}
		r, s := new(big.Int).SetBytes(raw[:size]), new(big.Int).SetBytes(raw[size:])
		if !ecdsa.Verify(key, digest, r, s) {
			return nil, errors.New("the KMS returned a signature the pinned public key does not verify")
		}
		return asn1.Marshal(struct{ R, S *big.Int }{r, s})
	case *rsa.PublicKey:
		payload := append(append([]byte{}, digestInfoPrefix[hash]...), digest...)
		raw, err := signer.call(ctx, payload, subject)
		if err != nil {
			return nil, err
		}
		if rsa.VerifyPKCS1v15(key, hash, digest, raw) != nil {
			return nil, errors.New("the KMS returned a signature the pinned public key does not verify")
		}
		return raw, nil
	case ed25519.PublicKey:
		// In an OpenPGP EdDSA signature the digest IS the message Ed25519 signs. The token signs
		// the bytes it is given (CKM_EDDSA: measured on the YubiKey OpenPGP applet, regalia#541,
		// and on SoftHSM) and returns R||S.
		raw, err := signer.call(ctx, digest, subject)
		if err != nil {
			return nil, err
		}
		if len(raw) != ed25519.SignatureSize {
			return nil, errors.New("the KMS returned a signature of the wrong size for this key")
		}
		if !ed25519.Verify(key, digest, raw) {
			return nil, errors.New("the KMS returned a signature the pinned public key does not verify")
		}
		return raw, nil
	}
	return nil, errors.New("unsupported release key")
}

// bound is a Signer fixed to one operation's context and subject, in the shape go-crypto calls.
//
// It also keeps the error of its last call. go-crypto v1.5.2 loses an RSA signer's error: in
// packet.Signature.Sign the RSA arm declares its own `err`, so a failed signer returns nil there and
// the caller only finds out later, as "need to call Sign before Serialize". The ECDSA arm does not
// have the defect. Reading the error back here makes a KMS refusal a KMS refusal for both.
type bound struct {
	signer  *Signer
	ctx     context.Context
	subject string
	failure error
}

func (operation *bound) Public() crypto.PublicKey { return operation.signer.public }

func (operation *bound) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// PSS is a different signature scheme with the same key. OpenPGP does not use it and the KMS
	// was not asked for it, so an opts value that names it is refused rather than ignored.
	if _, pss := opts.(*rsa.PSSOptions); pss || opts == nil {
		operation.failure = errors.New("only PKCS #1 v1.5 and ECDSA signatures are produced")
		return nil, operation.failure
	}
	signature, err := operation.signer.SignDigest(operation.ctx, digest, opts.HashFunc(), operation.subject)
	operation.failure = err
	return signature, err
}
