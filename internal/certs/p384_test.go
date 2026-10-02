package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"testing"
	"time"
)

func TestP384CAIssuesAVerifiableCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, key, time.Now().Add(365*24*time.Hour))
	var digestSize int
	card := emulateCard(t, key)
	signer := &CardSigner{PublicKey: key.Public(), Sign_: func(digest []byte) ([]byte, error) { digestSize = len(digest); return card(digest) }}
	subject, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, subject), staging(), time.Now())
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
	if leaf.SignatureAlgorithm != x509.ECDSAWithSHA384 || digestSize != crypto.SHA384.Size() {
		t.Fatalf("algorithm %v, card digest size %d", leaf.SignatureAlgorithm, digestSize)
	}
}

func TestP384SignerRejectsTruncatedDigestsAndWrongRawWidth(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum384([]byte("public tbs fixture"))
	calls := 0
	signer := &CardSigner{PublicKey: key.Public(), Sign_: func(payload []byte) ([]byte, error) { calls++; return emulateCard(t, key)(payload) }}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384); err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{32, 47, 49} {
		if _, err := signer.Sign(rand.Reader, make([]byte, size), crypto.SHA384); err == nil {
			t.Fatalf("accepted %d-byte digest", size)
		}
	}
	if calls != 1 {
		t.Fatalf("wrong digest reached card: calls=%d", calls)
	}
	signer.Sign_ = func([]byte) ([]byte, error) { raw := make([]byte, 64); raw[0] = 1; raw[32] = 1; return raw, nil }
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA384); err == nil {
		t.Fatal("accepted a P-256-width raw signature for P-384")
	}
}
