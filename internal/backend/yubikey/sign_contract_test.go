package yubikey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/certs"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

// KNOWN ANSWERS FOR THE ECDSA RE-ENCODING. DER drops leading zero bytes and adds one before a high
// bit; r||s is fixed width. Each row is a way the two differ.
func TestRawECDSAIsRAndSAtTheWidthOfTheCurve(t *testing.T) {
	for name, test := range map[string]struct {
		der, raw string
		width    int
	}{
		"both values full width, high bit clear": {
			"30440220" + "1111111111111111111111111111111111111111111111111111111111111111" + "0220" + "2222222222222222222222222222222222222222222222222222222222222222",
			"1111111111111111111111111111111111111111111111111111111111111111" + "2222222222222222222222222222222222222222222222222222222222222222", 32},
		"high bit set: DER carries a leading zero that the raw form does not": {
			"3046022100" + "ff11111111111111111111111111111111111111111111111111111111111111" + "022100" + "8022222222222222222222222222222222222222222222222222222222222222",
			"ff11111111111111111111111111111111111111111111111111111111111111" + "8022222222222222222222222222222222222222222222222222222222222222", 32},
		"a short value is left-padded": {
			"3024" + "0201" + "07" + "021f" + "33333333333333333333333333333333333333333333333333333333333333",
			"0000000000000000000000000000000000000000000000000000000000000007" + "0033333333333333333333333333333333333333333333333333333333333333", 32},
		"P-384 width": {
			"3006" + "020101" + "020102",
			"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002", 48},
	} {
		raw, ok := rawECDSA(mustHex(t, test.der), test.width)
		if !ok || !bytes.Equal(raw, mustHex(t, test.raw)) {
			t.Errorf("%s: (%x, %v), want %s", name, raw, ok, test.raw)
		}
	}
	good := mustHex(t, "3006020101020102")
	for name, der := range map[string][]byte{
		"nothing":                   nil,
		"bytes after the signature": append(append([]byte{}, good...), 0x00),
		"a truncated signature":     good[:len(good)-1],
		"r is zero":                 mustHex(t, "3006020100020102"),
		"s is negative":             mustHex(t, "30060201010201ff"),
		"already raw, not DER":      bytes.Repeat([]byte{0x11}, 64),
		"one integer, not two":      mustHex(t, "3003020101"),
	} {
		if raw, ok := rawECDSA(der, 32); ok {
			t.Errorf("%s was accepted as a signature: %x", name, raw)
		}
	}
	// A value that fits P-384 does not fit P-256.
	wide, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := rawECDSA(wide, 32); ok {
		t.Error("an r wider than the curve was accepted for P-256")
	}
	if _, ok := rawECDSA(wide, 48); !ok {
		t.Error("the same r was refused for P-384, where it fits")
	}
}

// AN RSA PAYLOAD IS THE DIGESTINFO, EXACTLY. The card library is handed the digest inside it and
// rebuilds the same bytes; anything that is not that DigestInfo is refused, a bare digest included.
func TestAnRSAPayloadMustBeTheDigestInfoForItsHash(t *testing.T) {
	digest := sha256.Sum256([]byte("to be signed"))
	long := sha512.Sum512([]byte("to be signed"))
	for hash, inner := range map[crypto.Hash][]byte{crypto.SHA256: digest[:], crypto.SHA384: long[:48], crypto.SHA512: long[:]} {
		payload := append(append([]byte{}, digestInfoPrefixes[hash]...), inner...)
		named, ok := signingHash("rsa2048", len(payload))
		if !ok || named != hash {
			t.Fatalf("a %d-byte DigestInfo was read as hash %v (%v), want %v", len(payload), named, ok, hash)
		}
		got, ok := cardDigest("rsa2048", payload, named)
		if !ok || !bytes.Equal(got, inner) {
			t.Fatalf("hash %v: the digest inside the DigestInfo was not recovered", hash)
		}
		// The DigestInfo is itself DER: what the library rebuilds must be what was sent.
		var parsed struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		if rest, err := asn1.Unmarshal(payload, &parsed); err != nil || len(rest) != 0 || !bytes.Equal(parsed.Digest, inner) {
			t.Fatalf("hash %v: the prefix table does not encode a DigestInfo: %v", hash, err)
		}
		// One wrong byte in the header, and the same length, is not that DigestInfo.
		tampered := append([]byte{}, payload...)
		tampered[14] ^= 0x01
		if _, ok := cardDigest("rsa2048", tampered, named); ok {
			t.Fatalf("hash %v: a DigestInfo naming another hash was accepted", hash)
		}
	}
	for _, size := range []int{0, 31, 32, 48, 50, 52, 64, 66, 84} {
		if _, ok := signingHash("rsa2048", size); ok {
			t.Errorf("an RSA payload of %d bytes was accepted; a bare digest is not a DigestInfo", size)
		}
	}
	// Other algorithms are sent to the card as they come.
	if got, ok := cardDigest("p256", digest[:], crypto.SHA256); !ok || !bytes.Equal(got, digest[:]) {
		t.Fatal("a P-256 digest was changed on the way to the card")
	}
}

// softCard signs like piv-go does: ECDSA as ASN.1 DER, RSA from a bare digest and a hash.
type softCard struct {
	ecdsaKey *ecdsa.PrivateKey
	rsaKey   *rsa.PrivateKey
}

// sign is pivSession.Sign's body with the card replaced by software keys.
func (card softCard) sign(algorithm string, payload []byte) ([]byte, bool) {
	hash, valid := signingHash(algorithm, len(payload))
	if !valid {
		return nil, false
	}
	input, valid := cardDigest(algorithm, payload, hash)
	if !valid {
		return nil, false
	}
	var value []byte
	var err error
	if algorithm == "rsa2048" {
		value, err = card.rsaKey.Sign(rand.Reader, input, hash)
	} else {
		value, err = card.ecdsaKey.Sign(rand.Reader, input, hash)
	}
	if err != nil {
		return nil, false
	}
	return contractSignature(algorithm, value)
}

// THE CALLERS ACCEPT WHAT THIS BACKEND NOW RETURNS.
//
// certs.CardSigner is the caller that issues certificates from an on-card CA key, written against
// the PKCS#11 backend's answers. x509.CreateCertificate checks the signature it is given, so a
// certificate coming out is the proof that the encoding is the one the caller expects. Before the
// contract was applied, the ECDSA rows failed here and the RSA row was refused at the size gate.
func TestCertificatesCanBeIssuedFromWhatTheBackendReturns(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for algorithm, test := range map[string]struct {
		card   softCard
		public crypto.PublicKey
	}{
		"p256":    {softCard{ecdsaKey: p256}, &p256.PublicKey},
		"rsa2048": {softCard{rsaKey: rsaKey}, &rsaKey.PublicKey},
	} {
		signer := &certs.CardSigner{PublicKey: test.public, Sign_: func(payload []byte) ([]byte, error) {
			signature, ok := test.card.sign(algorithm, payload)
			if !ok {
				return nil, ErrUnavailable
			}
			return signature, nil
		}}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "regalia-kms#162 " + algorithm},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, test.public, signer)
		if err != nil {
			t.Fatalf("%s: a certificate could not be issued from the backend's signature: %v", algorithm, err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if err := certificate.CheckSignatureFrom(certificate); err != nil {
			t.Fatalf("%s: the issued certificate does not verify: %v", algorithm, err)
		}
	}
	// And the form regalia-sign checks: r and s as the two halves of the answer.
	digest := sha256.Sum256([]byte("a release digest"))
	raw, ok := softCard{ecdsaKey: p256}.sign("p256", digest[:])
	if !ok || len(raw) != 64 || !ecdsa.Verify(&p256.PublicKey, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatalf("the P-256 answer is not r||s that verifies: %d bytes, ok=%v", len(raw), ok)
	}
}
