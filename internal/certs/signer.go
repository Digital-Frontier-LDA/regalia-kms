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

// certificateHash is the one hash a CA key signs certificates with, and for an ECDSA key the width
// of one signature component.
//
// THE HASH FOLLOWS THE KEY. P-256 signs over SHA-256 and P-384 over SHA-384: the pairing RFC 5480
// and every public CA use, and the one x509.CreateCertificate chooses for the key when the template
// names no algorithm. This signer used to accept SHA-256 only, so a P-384 CA key, which the
// capability matrix advertises for certificate-sign, could not issue at all (regalia-kms#169).
// RSA stays on SHA-256 at every key size. No other pairing is accepted: a P-384 key asked for a
// SHA-256 signature is refused, not obliged, so the strength of a certificate's signature is
// never less than its key's.
func certificateHash(public crypto.PublicKey) (hash crypto.Hash, width int, ok bool) {
	switch key := public.(type) {
	case *rsa.PublicKey:
		return crypto.SHA256, 0, true
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return crypto.SHA256, 32, true
		case elliptic.P384():
			return crypto.SHA384, 48, true
		}
	}
	return 0, 0, false
}

func (signer *CardSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if signer == nil || signer.Sign_ == nil || len(digest) == 0 {
		return nil, errors.New("card signer is not configured")
	}
	hash, width, ok := certificateHash(signer.PublicKey)
	if !ok {
		return nil, errors.New("unsupported certificate signing key type")
	}
	if opts == nil || opts.HashFunc() != hash {
		return nil, errors.New("the certificate signature hash is not the one this key signs with (SHA-256 for RSA and P-256, SHA-384 for P-384)")
	}
	if len(digest) != hash.Size() {
		return nil, errors.New("the digest is not of the hash this key signs with")
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
		// A raw ECDSA signature is exactly two field elements at the width of the curve order.
		// Any other length means the card returned something else — DER already, a truncated
		// read, a signature made with another key — and guessing would produce a plausible-looking
		// certificate, so refuse.
		if len(raw) != 2*width {
			return nil, errors.New("card returned a malformed raw ECDSA signature")
		}
		half := width
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
