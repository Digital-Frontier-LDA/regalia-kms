package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"testing"
	"time"
)

func TestRSACertificateDigestInfoVerifiesForEachSupportedHash(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, key, time.Now().Add(time.Hour))
	card := &CardSigner{PublicKey: key.Public(), Sign_: emulateCard(t, key)}
	for _, row := range []struct {
		hash      crypto.Hash
		algorithm x509.SignatureAlgorithm
	}{
		{crypto.SHA256, x509.SHA256WithRSA}, {crypto.SHA384, x509.SHA384WithRSA}, {crypto.SHA512, x509.SHA512WithRSA},
	} {
		t.Run(row.hash.String(), func(t *testing.T) {
			template := &x509.Certificate{SerialNumber: ca.SerialNumber, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, SignatureAlgorithm: row.algorithm}
			der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), card)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := leaf.CheckSignatureFrom(ca); err != nil {
				t.Fatal(err)
			}
		})
	}
	calls := 0
	card.Sign_ = func([]byte) ([]byte, error) { calls++; return nil, nil }
	digest := sha256.Sum256([]byte("public fixture"))
	if _, err := card.Sign(rand.Reader, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("accepted RSA-PSS for a PKCS#1 v1.5 mechanism")
	}
	if calls != 0 {
		t.Fatal("unsupported options reached card")
	}
}

func TestECDSADigestMustMatchTheRoutedCurve(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		calls := 0
		card := &CardSigner{PublicKey: key.Public(), Sign_: func([]byte) ([]byte, error) { calls++; return nil, nil }}
		hash := crypto.SHA384
		digest := sha512.Sum384([]byte("public fixture"))
		payload := digest[:]
		if curve == elliptic.P384() {
			hash = crypto.SHA256
			payload = payload[:32]
		}
		if _, err := card.Sign(rand.Reader, payload, hash); err == nil {
			t.Fatal("accepted wrong hash for curve")
		}
		if calls != 0 {
			t.Fatal("wrong curve digest reached card")
		}
	}
}
