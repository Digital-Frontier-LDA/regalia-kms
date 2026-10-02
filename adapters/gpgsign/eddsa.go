package gpgsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgpeddsa "github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ED25519, BY SIGNING TWICE. A RECORDED DEVIATION (regalia#530, decided 2026-10-02).
//
// go-crypto v1.5.2 lets an external crypto.Signer make RSA and ECDSA signatures. For EdDSA it
// accepts only its own private-key type, so a key that lives in the KMS cannot be plugged in. Until
// the library takes an external Ed25519 signer, this file does the following instead:
//
//  1. go-crypto builds the complete signature packet ONCE, signing with a THROWAWAY Ed25519 key.
//     The packet's public key, issuer fingerprint and issuer key ID are the KMS key's: only the
//     private half is a dummy. Everything that is hashed therefore already names the real key.
//  2. The hash object is ours, so the digest go-crypto signs is observed as it is computed.
//  3. The KMS signs that digest. The Signer checks the answer against the pinned public key.
//  4. The throwaway signature's two integers, R and S, are replaced with the KMS's.
//  5. The finished packet is parsed back and verified against the KMS public key before one byte
//     is written (Key.finish). If step 4 were skipped, step 5 fails: the throwaway signature cannot
//     leave.
//
// The deviation from "the library does the encoding" is exactly the two integers in step 4 (mpi,
// below) and the public key's curve, borrowed from a generated key as ecdsaPublicKey does. It is
// removed when go-crypto accepts a crypto.Signer for EdDSA.

// eddsaPublicKey frames a 32-byte Ed25519 public key as an OpenPGP EdDSA key (algorithm 22, the
// format GnuPG 2.4 reads), and returns the throwaway private key that step 1 signs with.
func eddsaPublicKey(created time.Time, key ed25519.PublicKey) (*packet.PublicKey, *pgpeddsa.PrivateKey, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, nil, errors.New("the release key is not a valid Ed25519 public key")
	}
	// The curve is a value of an internal go-crypto package, so it comes from a key the library
	// generates. That key's private half is the throwaway of step 1; its public half is discarded.
	template, err := openpgp.NewEntity("curve template", "", "", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		return nil, nil, fmt.Errorf("prepare the OpenPGP curve: %w", err)
	}
	generated, ok := template.PrimaryKey.PublicKey.(*pgpeddsa.PublicKey)
	throwaway, ok2 := template.PrivateKey.PrivateKey.(*pgpeddsa.PrivateKey)
	if !ok || !ok2 || len(generated.X) != ed25519.PublicKeySize {
		return nil, nil, errors.New("prepare the OpenPGP curve: unexpected key type")
	}
	framed := *generated
	framed.X = append([]byte(nil), key...)
	return packet.NewEdDSAPublicKey(created, &framed), throwaway, nil
}

// capturingHash is a hash whose final value is remembered. go-crypto writes the signature trailer
// into it and calls Sum exactly once; that value is the digest the signature is over.
type capturingHash struct {
	hash.Hash
	digest []byte
	sums   int
}

func (capture *capturingHash) Sum(prefix []byte) []byte {
	out := capture.Hash.Sum(prefix)
	capture.sums++
	capture.digest = append([]byte(nil), out[len(prefix):]...)
	return out
}

// signEdDSA performs steps 1 to 4 on a signature whose hash has been fed. Step 5 is Key.finish.
func (key *Key) signEdDSA(ctx context.Context, signature *packet.Signature, hasher hash.Hash, config *packet.Config, subject string) error {
	capture := &capturingHash{Hash: hasher}
	throwaway := &packet.PrivateKey{PublicKey: *key.public, PrivateKey: key.throwaway}
	if err := signature.Sign(capture, throwaway, config); err != nil {
		return err
	}
	// The digest must be the one this signature's own 16-bit prefix was taken from. If go-crypto
	// ever hashed differently (a second Sum, a salt, another length), stop here.
	if capture.sums != 1 || len(capture.digest) != key.signer.hash.Size() || !bytes.Equal(signature.HashTag[:], capture.digest[:2]) {
		return errors.New("the signature digest could not be captured")
	}
	raw, err := key.signer.SignDigest(ctx, capture.digest, key.signer.hash, subject)
	if err != nil {
		return err
	}
	return edDSASwap(signature, raw)
}

// edDSASwap is step 4. It is a variable so a test can skip it and prove that step 5 then refuses.
var edDSASwap = func(signature *packet.Signature, raw []byte) error {
	if len(raw) != ed25519.SignatureSize {
		return errors.New("an Ed25519 signature is 64 bytes")
	}
	signature.EdDSASigR, signature.EdDSASigS = newMPI(raw[:32]), newMPI(raw[32:])
	return nil
}

// mpi is an OpenPGP multiprecision integer (RFC 9580 §3.2): a two-byte bit count, then the value
// big-endian with no leading zero bytes. It is the one encoding this adapter writes itself, for R
// and S only. go-crypto's own type is in an internal package and has no exported constructor; this
// one satisfies the same interface, and the library still writes the packet around it.
type mpi struct {
	value     []byte
	bitLength uint16
}

func newMPI(value []byte) *mpi {
	for len(value) > 0 && value[0] == 0 {
		value = value[1:]
	}
	result := &mpi{value: append([]byte(nil), value...)}
	if len(value) > 0 {
		bits := uint16(8 * len(value))
		for mask := byte(0x80); mask != 0 && value[0]&mask == 0; mask >>= 1 {
			bits--
		}
		result.bitLength = bits
	}
	return result
}

func (m *mpi) Bytes() []byte     { return m.value }
func (m *mpi) BitLength() uint16 { return m.bitLength }
func (m *mpi) EncodedBytes() []byte {
	return append([]byte{byte(m.bitLength >> 8), byte(m.bitLength)}, m.value...)
}
func (m *mpi) EncodedLength() uint16 { return uint16(2 + len(m.value)) }

// ReadFrom is part of the interface and is never used: these values are only written.
func (m *mpi) ReadFrom(io.Reader) (int64, error) {
	return 0, errors.New("this integer is write-only")
}
