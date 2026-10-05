package openbaopoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

// Stable public structures keep fuzz seeds meaningful across worker processes.
// This deliberately predictable test key formats seeds only; it is never used
// by a running service, exported or provisioned into a token.
func pocFuzzInputs(t testing.TB) (*x509.Certificate, time.Time, []byte, []byte, []byte) {
	t.Helper()
	curve := elliptic.P256()
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: curve.Params().Gx, Y: curve.Params().Gy}, D: big.NewInt(1)}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-fuzz-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	encodeLeaf := func() []byte {
		der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed.RawTBSCertificate
	}
	valid := encodeLeaf()
	leaf.SubjectKeyId = bytes.Repeat([]byte{0x44}, (32<<10)+1)
	oversize := encodeLeaf()
	crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: now}}}
	der, err = x509.CreateRevocationList(rand.Reader, crl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pocInspectCertificate(valid, issuer, now); err != nil {
		t.Fatal("valid certificate fuzz seed was refused")
	}
	if _, err := pocInspectCRL(parsed.RawTBSRevocationList, issuer, now); err != nil {
		t.Fatal("valid CRL fuzz seed was refused")
	}
	return issuer, now, valid, parsed.RawTBSRevocationList, oversize
}

func TestPOCDuplicateExtensionRefused(t *testing.T) {
	issuer, now, cert, _, _ := pocFuzzInputs(t)
	if _, err := pocInspectCertificate(pocDuplicateCertificateExtension(t, cert), issuer, now); !errors.Is(err, errPOCProfile) {
		t.Fatal("duplicate certificate extension accepted")
	}
}

func TestPOCInspectorInputBounds(t *testing.T) {
	issuer, now, _, _, oversize := pocFuzzInputs(t)
	if len(oversize) <= 32<<10 {
		t.Fatal("oversize seed is too small")
	}
	if _, err := pocInspectCertificate(oversize, issuer, now); !errors.Is(err, errPOCProfile) {
		t.Fatal("oversize structured certificate was accepted")
	}
}

func pocFuzzSeeds(f *testing.F, valid, other, oversize []byte) {
	f.Add(valid)
	f.Add(other)
	f.Add(oversize)
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(valid[:len(valid)/2])
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0, 0}) // Indefinite-length BER is not DER.
}

func FuzzPOCCertificateInspection(f *testing.F) {
	issuer, now, valid, crl, oversize := pocFuzzInputs(f)
	pocFuzzSeeds(f, valid, crl, oversize)
	f.Add(pocDuplicateCertificateExtension(f, valid))
	for _, seed := range pocDERRefusalCases {
		if seed.kind == "certificate" {
			f.Add(pocDERRefusalMutation(f, valid, seed.kind, seed.mutation))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := pocInspectCertificate(data, issuer, now)
		if err != nil {
			if !errors.Is(err, errPOCProfile) {
				t.Fatal("unexpected certificate refusal class")
			}
			return
		}
		if len(data) > 32<<10 || cert == nil || !bytes.Equal(cert.RawTBSCertificate, data) {
			t.Fatal("accepted certificate did not preserve bounded full input")
		}
		if cert.VerifyHostname(cert.Subject.CommonName) != nil {
			t.Fatal("accepted certificate subject is not covered by DNS SAN")
		}
		if _, err = pocInspectCertificate(append(bytes.Clone(data), 0), issuer, now); !errors.Is(err, errPOCProfile) {
			t.Fatal("trailing certificate DER accepted")
		}
		if _, err = pocInspectCRL(data, issuer, now); !errors.Is(err, errPOCProfile) {
			t.Fatal("certificate was also accepted as CRL")
		}
	})
}

func FuzzPOCCRLInspection(f *testing.F) {
	issuer, now, cert, valid, oversize := pocFuzzInputs(f)
	pocFuzzSeeds(f, valid, cert, oversize)
	for _, seed := range pocDERRefusalCases {
		if seed.kind == "crl" {
			f.Add(pocDERRefusalMutation(f, valid, seed.kind, seed.mutation))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		crl, err := pocInspectCRL(data, issuer, now)
		if err != nil {
			if !errors.Is(err, errPOCProfile) {
				t.Fatal("unexpected CRL refusal class")
			}
			return
		}
		if len(data) > 32<<10 || crl == nil || !bytes.Equal(crl.RawTBSRevocationList, data) {
			t.Fatal("accepted CRL did not preserve bounded full input")
		}
		if _, err = pocInspectCRL(append(bytes.Clone(data), 0), issuer, now); !errors.Is(err, errPOCProfile) {
			t.Fatal("trailing CRL DER accepted")
		}
		if _, err = pocInspectCertificate(data, issuer, now); !errors.Is(err, errPOCProfile) {
			t.Fatal("CRL was also accepted as certificate")
		}
	})
}

// Duplicate-extension seeds retain otherwise valid certificate DER. Keeping
// this transformation separate makes it reusable for corpus regression cases.
func pocDuplicateCertificateExtension(t testing.TB, data []byte) []byte {
	t.Helper()
	fields, err := pocTBSFields(data)
	if err != nil {
		t.Fatal(err)
	}
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(fields[7].Bytes, &sequence); err != nil || len(rest) != 0 {
		t.Fatal("invalid extension seed")
	}
	var extensions []pkix.Extension
	if rest, err := asn1.Unmarshal(sequence.FullBytes, &extensions); err != nil || len(rest) != 0 || len(extensions) == 0 {
		t.Fatal("invalid extension sequence")
	}
	extensions = append(extensions, extensions[0])
	encoded, err := asn1.Marshal(extensions)
	if err != nil {
		t.Fatal(err)
	}
	fields[7] = asn1.RawValue{Class: 2, Tag: 3, IsCompound: true, Bytes: encoded}
	encoded, err = asn1.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
