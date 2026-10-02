// Package certs turns an on-card signing key into an X.509 issuer.
//
// The private key never leaves the token: Go builds and hashes the TBSCertificate, the card signs
// the digest, and this package adapts the card's output to the encoding X.509 requires. That
// adaptation is the whole reason this file exists — PKCS#11 does not return what x509 expects.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// PKCS#1 v1.5 DigestInfo headers (RFC 8017 section 9.2). CKM_RSA_PKCS
// pads exactly these bytes and the digest; it does not construct this header.
var digestInfoPrefixes = map[crypto.Hash][]byte{
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

// ecdsaSignature is the DER form X.509 requires: SEQUENCE { r INTEGER, s INTEGER }.
type ecdsaSignature struct{ R, S *big.Int }

// CardSign is the hardware call: it receives the bytes to sign and returns the card's raw output.
type CardSign func(payload []byte) ([]byte, error)

// CardSigner adapts an on-card key to crypto.Signer so x509.CreateCertificate can use it.
//
// It exists because the two mechanisms disagree with x509 in opposite directions:
//
//   - CKM_ECDSA returns a RAW signature, r||s at fixed width, while X.509 wants DER.
//   - CKM_RSA_PKCS pads whatever it is handed, while X.509 wants PKCS#1 v1.5 over a DigestInfo.
//
// Getting either wrong yields a certificate that parses and does not verify, which is a
// particularly unhelpful failure to debug in production.
type CardSigner struct {
	PublicKey crypto.PublicKey
	Sign_     CardSign
}

func (signer *CardSigner) Public() crypto.PublicKey { return signer.PublicKey }

func (signer *CardSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if signer == nil || signer.Sign_ == nil || len(digest) == 0 {
		return nil, errors.New("card signer is not configured")
	}
	if opts == nil || digestInfoPrefixes[opts.HashFunc()] == nil {
		return nil, errors.New("only SHA-256, SHA-384 and SHA-512 certificate signatures are supported")
	}
	hash := opts.HashFunc()
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("digest is not a %s digest", hash)
	}

	switch public := signer.PublicKey.(type) {
	case *rsa.PublicKey:
		if public == nil {
			return nil, errors.New("unsupported certificate signing key type")
		}
		if _, pss := opts.(*rsa.PSSOptions); pss {
			return nil, errors.New("card certificate signing uses PKCS#1 v1.5, not RSA-PSS")
		}
		signature, err := signer.Sign_(append(append([]byte{}, digestInfoPrefixes[hash]...), digest...))
		if err != nil {
			return nil, err
		}
		if len(signature) != public.Size() {
			return nil, errors.New("card returned a signature of the wrong length for the key")
		}
		return signature, nil

	case *ecdsa.PublicKey:
		if public == nil {
			return nil, errors.New("unsupported certificate signing key type")
		}
		expected := crypto.Hash(0)
		switch public.Curve {
		case elliptic.P256():
			expected = crypto.SHA256
		case elliptic.P384():
			expected = crypto.SHA384
		default:
			return nil, errors.New("unsupported certificate signing curve")
		}
		if hash != expected {
			return nil, errors.New("certificate digest does not match the signing curve")
		}
		raw, err := signer.Sign_(digest)
		if err != nil {
			return nil, err
		}
		// A raw ECDSA signature is exactly two fixed-width field elements. An odd length means the
		// card returned something else — DER already, or a truncated read — and guessing would
		// produce a plausible-looking certificate, so refuse.
		if len(raw) != 2*((public.Curve.Params().BitSize+7)/8) {
			return nil, errors.New("card returned a malformed raw ECDSA signature")
		}
		half := len(raw) / 2
		r := new(big.Int).SetBytes(raw[:half])
		s := new(big.Int).SetBytes(raw[half:])
		if r.Sign() == 0 || s.Sign() == 0 {
			return nil, errors.New("card returned a zero ECDSA signature component")
		}
		return asn1.Marshal(ecdsaSignature{R: r, S: s})

	default:
		return nil, errors.New("unsupported certificate signing key type")
	}
}
