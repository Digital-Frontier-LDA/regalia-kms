package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

// TPM constants, as deploy/baremetal/attest.py names them (TCG TPM 2.0 Library, Part 2).
const (
	tpmGenerated  = 0xFF544347
	stAttestQuote = 0x8018
	algSHA256     = 0x000B
	algNull       = 0x0010
	algECDSA      = 0x0018
	algECC        = 0x0023
	curveP256     = 0x0003
	rhEndorsement = 0x4000000B
	// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | sign, and nothing else
	akAttributes = 0x00050072
)

// reader walks a TPM structure. Every read is bounds-checked; a short structure is an error, never a panic.
type reader struct {
	data []byte
	bad  bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.data) {
		r.bad = true
		return nil
	}
	out := r.data[:n]
	r.data = r.data[n:]
	return out
}

func (r *reader) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.BigEndian.Uint16(b)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *reader) sized() []byte { return r.take(int(r.u16())) }

func (r *reader) done() bool { return !r.bad && len(r.data) == 0 }

func tpmName(publicArea []byte) []byte {
	digest := sha256.Sum256(publicArea)
	return append([]byte{0x00, algSHA256}, digest[:]...)
}

// akIdentity is attest.ak_identity: the Name and the public key of an attestation key, computed from
// its public area. Anything that is not a restricted, TPM-made, sign-only ECDSA P-256/SHA-256 key is
// refused.
func akIdentity(akPublic []byte) ([]byte, *ecdsa.PublicKey, error) {
	outer := &reader{data: akPublic}
	area := outer.sized()
	if !outer.done() {
		return nil, nil, errors.New("the AK public area is malformed")
	}
	r := &reader{data: area}
	ok := r.u16() == algECC && r.u16() == algSHA256 && r.u32() == akAttributes
	ok = ok && len(r.sized()) == 0 // no auth policy
	ok = ok && r.u16() == algNull && r.u16() == algECDSA && r.u16() == algSHA256 && r.u16() == curveP256 && r.u16() == algNull
	x, y := r.sized(), r.sized()
	if !ok || !r.done() || len(x) != 32 || len(y) != 32 {
		return nil, nil, errors.New("the signer is not a restricted ECDSA P-256 attestation key")
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, x...), y...))
	if err != nil { // the point is not on the curve
		return nil, nil, errors.New("the signer's public point is not on P-256")
	}
	return tpmName(area), key, nil
}

// qualifiedName is the AK's Qualified Name under the EK in the endorsement hierarchy: what
// TPMS_ATTEST.qualifiedSigner must be if the signing key is this AK under this EK.
func qualifiedName(ekName, akName []byte) []byte {
	h := func(data []byte) []byte {
		digest := sha256.Sum256(data)
		return append([]byte{0x00, algSHA256}, digest[:]...)
	}
	return h(append(h(append([]byte{0x40, 0x00, 0x00, 0x0B}, ekName...)), akName...))
}

// parseAttest reads the head of a TPMS_ATTEST for a quote: who signed it, and over what.
func parseAttest(attest []byte) (qualifiedSigner, extraData []byte, err error) {
	r := &reader{data: attest}
	if r.u32() != tpmGenerated || r.u16() != stAttestQuote {
		return nil, nil, errors.New("the signed structure is not a TPM quote")
	}
	qualifiedSigner, extraData = r.sized(), r.sized()
	if r.bad {
		return nil, nil, errors.New("the quote is truncated")
	}
	return qualifiedSigner, extraData, nil
}

// verifyPeerSignature is unlock.verify_signature: the response is signed by the AK the boot
// configuration names for the peer, under its EK, as a TPM2_Quote whose qualifying data is the digest
// of exactly this response.
func verifyPeerSignature(signature *peerSignature, peer pin, digest []byte) error {
	akPublic, err1 := lowerHex(signature.AKPublic)
	quote, err2 := lowerHex(signature.Quote)
	sig, err3 := lowerHex(signature.Sig)
	if err1 != nil || err2 != nil || err3 != nil || len(akPublic) > 1024 || len(quote) > 1024 || len(sig) > 256 {
		return errors.New("the response's signature is malformed")
	}
	name, key, err := akIdentity(akPublic)
	if err != nil {
		return err
	}
	if hex.EncodeToString(name) != peer.AKName {
		return errors.New("the response is not signed by the AK recorded for " + peer.NodeID)
	}
	hashed := sha256.Sum256(quote)
	if !ecdsa.VerifyASN1(key, hashed[:], sig) {
		return errors.New("the response's signature does not verify")
	}
	qualifiedSigner, extraData, err := parseAttest(quote)
	if err != nil {
		return err
	}
	ekName, _ := hex.DecodeString(peer.EKName)
	if !bytes.Equal(qualifiedSigner, qualifiedName(ekName, name)) {
		return errors.New("the response is not signed under the EK recorded for " + peer.NodeID)
	}
	if subtle.ConstantTimeCompare(extraData, digest) != 1 {
		return errors.New("the peer's quote is not over this response")
	}
	return nil
}
