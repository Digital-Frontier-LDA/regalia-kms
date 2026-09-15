// Package certs turns an on-card signing key into an X.509 issuer.
//
// The private key never leaves the token: Go builds and hashes the TBSCertificate, the card signs
// the digest, and this package adapts the card's output to the encoding X.509 requires. That
// adaptation is the whole reason this file exists — PKCS#11 does not return what x509 expects.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

// digestInfoPrefixSHA256 is the DER header of DigestInfo(SHA-256, digest).
//
// The Nitrokey path signs with CKM_RSA_PKCS, which applies PKCS#1 v1.5 padding to EXACTLY the bytes
// it is given — it does not build a DigestInfo. Handing it a bare digest produces a signature that
// no verifier accepts, so the header is prepended here.
var digestInfoPrefixSHA256 = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
	0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
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
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("only SHA-256 certificate signatures are supported")
	}
	if len(digest) != crypto.SHA256.Size() {
		return nil, errors.New("digest is not a SHA-256 digest")
	}

	switch public := signer.PublicKey.(type) {
	case *rsa.PublicKey:
		signature, err := signer.Sign_(append(append([]byte{}, digestInfoPrefixSHA256...), digest...))
		if err != nil {
			return nil, err
		}
		if len(signature) != public.Size() {
			return nil, errors.New("card returned a signature of the wrong length for the key")
		}
		return signature, nil

	case *ecdsa.PublicKey:
		raw, err := signer.Sign_(digest)
		if err != nil {
			return nil, err
		}
		// A raw ECDSA signature is exactly two fixed-width field elements. An odd length means the
		// card returned something else — DER already, or a truncated read — and guessing would
		// produce a plausible-looking certificate, so refuse.
		if len(raw) == 0 || len(raw)%2 != 0 {
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
