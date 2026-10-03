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

	"github.com/google/go-tpm/tpm2"
)

// The structures a peer sends (its attestation key's public area, the TPMS_ATTEST it signed) are parsed
// by go-tpm. What is decided here is only what deploy/baremetal/attest.py decides about them.

// akAttributes: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | sign, and
// nothing else (attest.AK_ATTRIBUTES).
var akAttributes = tpm2.TPMAObject{FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true, UserWithAuth: true,
	Restricted: true, SignEncrypt: true}

var errNotAnAK = errors.New("the signer is not a restricted ECDSA P-256 attestation key")

// akIdentity is attest.ak_identity: the Name and the public key of an attestation key, computed from
// its public area. Anything that is not a restricted, TPM-made, sign-only ECDSA P-256/SHA-256 key is
// refused.
func akIdentity(akPublic []byte) ([]byte, *ecdsa.PublicKey, error) {
	wrapped, err := tpm2.Unmarshal[tpm2.TPM2BPublic](akPublic)
	if err != nil {
		return nil, nil, errors.New("the AK public area is malformed")
	}
	public, err := wrapped.Contents()
	if err != nil {
		return nil, nil, errors.New("the AK public area is malformed")
	}
	// the same bytes back: nothing after the structure, and no second encoding of the same key
	if !bytes.Equal(tpm2.Marshal(tpm2.New2B(*public)), akPublic) {
		return nil, nil, errors.New("the AK public area is malformed")
	}
	if public.Type != tpm2.TPMAlgECC || public.NameAlg != tpm2.TPMAlgSHA256 || public.ObjectAttributes != akAttributes || len(public.AuthPolicy.Buffer) != 0 {
		return nil, nil, errNotAnAK
	}
	parameters, err := public.Parameters.ECCDetail()
	if err != nil || parameters.Symmetric.Algorithm != tpm2.TPMAlgNull || parameters.Scheme.Scheme != tpm2.TPMAlgECDSA ||
		parameters.CurveID != tpm2.TPMECCNistP256 || parameters.KDF.Scheme != tpm2.TPMAlgNull {
		return nil, nil, errNotAnAK
	}
	scheme, err := parameters.Scheme.Details.ECDSA()
	if err != nil || scheme.HashAlg != tpm2.TPMAlgSHA256 {
		return nil, nil, errNotAnAK
	}
	point, err := public.Unique.ECC()
	if err != nil || len(point.X.Buffer) != 32 || len(point.Y.Buffer) != 32 {
		return nil, nil, errNotAnAK
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, point.X.Buffer...), point.Y.Buffer...))
	if err != nil { // the point is not on the curve
		return nil, nil, errors.New("the signer's public point is not on P-256")
	}
	name, err := tpm2.ObjectName(public)
	if err != nil {
		return nil, nil, errNotAnAK
	}
	return name.Buffer, key, nil
}

// qualifiedName is the AK's Qualified Name under the EK in the endorsement hierarchy: what
// TPMS_ATTEST.qualifiedSigner must be if the signing key is this AK under this EK
// (TPM 2.0 Library, Part 1, "Qualified Name": QN = H(QN of the parent || Name), from the hierarchy down).
func qualifiedName(ekName, akName []byte) []byte {
	h := func(data []byte) []byte {
		digest := sha256.Sum256(data)
		return append(binary.BigEndian.AppendUint16(nil, uint16(tpm2.TPMAlgSHA256)), digest[:]...)
	}
	return h(append(h(append(binary.BigEndian.AppendUint32(nil, uint32(tpm2.TPMRHEndorsement)), ekName...)), akName...))
}

// parseAttest reads a TPMS_ATTEST for a quote: who signed it, and over what. It accepts what
// attest.parse_quote accepts and nothing else. go-tpm parses the structure; three things it does not
// check are checked here:
//   - the magic. TPM_GENERATED is what makes a signature by a restricted key mean "the TPM built this":
//     such a key signs caller-supplied data too, as long as it does NOT begin with that value. go-tpm's
//     Unmarshal reads the field and does not compare it (v0.9.8).
//   - the length. Unmarshal accepts bytes after the structure and a structure cut short at a sized
//     field, so the parsed value is marshalled again and must give the same bytes.
//   - one PCR selection, of the SHA-256 bank.
func parseAttest(attest []byte) (qualifiedSigner, extraData []byte, err error) {
	notAQuote := errors.New("the signed structure is not a TPM quote")
	parsed, err := tpm2.Unmarshal[tpm2.TPMSAttest](attest)
	if err != nil || parsed.Magic != tpm2.TPMGeneratedValue || parsed.Type != tpm2.TPMSTAttestQuote {
		return nil, nil, notAQuote
	}
	quote, err := parsed.Attested.Quote()
	if err != nil || len(quote.PCRSelect.PCRSelections) != 1 || quote.PCRSelect.PCRSelections[0].Hash != tpm2.TPMAlgSHA256 {
		return nil, nil, notAQuote
	}
	if !bytes.Equal(tpm2.Marshal(parsed), attest) {
		return nil, nil, notAQuote
	}
	return parsed.QualifiedSigner.Buffer, parsed.ExtraData.Buffer, nil
}

// quotedPCRDigest is the pcrDigest of a quote, once parseAttest has accepted it.
func quotedPCRDigest(attest []byte) ([]byte, error) {
	if _, _, err := parseAttest(attest); err != nil {
		return nil, err
	}
	parsed, _ := tpm2.Unmarshal[tpm2.TPMSAttest](attest)
	quote, _ := parsed.Attested.Quote()
	return quote.PCRDigest.Buffer, nil
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
