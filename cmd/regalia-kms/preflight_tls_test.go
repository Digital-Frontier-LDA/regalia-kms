package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeKeypair emits a self-signed server certificate with the given validity window.
func writeKeypair(t *testing.T, dir string, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kms.test"},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"kms.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	// The same certificate serves as the client trust root for this fixture.
	if err := os.WriteFile(filepath.Join(dir, "clients.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func tlsSettings(t *testing.T, notBefore, notAfter time.Time) (settingsDir string) {
	t.Helper()
	dir := t.TempDir()
	writeKeypair(t, dir, notBefore, notAfter)
	return dir
}

// AN EXPIRED CERTIFICATE IS A SCHEDULED OUTAGE THE FILES PREDICT.
//
// TLS material was on preflight's unchecked list. It should not have been: an expired server
// certificate means the listener refuses every connection, and a certificate whose key does not
// match is a deployment mistake that only surfaces as a handshake failure once traffic arrives.
// Both are answerable without starting anything, and preflight is run precisely when somebody is
// deciding whether to act.
func TestPreflightChecksTLSMaterialAndExpiry(t *testing.T) {
	now := time.Now()

	valid := completeSettings(t)
	dir := tlsSettings(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	valid.ListenAddress = "0.0.0.0:8443"
	valid.TLSCertificatePath = filepath.Join(dir, "server.crt")
	valid.TLSPrivateKeyPath = filepath.Join(dir, "server.key")
	valid.TLSClientCAPath = filepath.Join(dir, "clients.pem")

	_, _, _, _, report, err := preflight(valid)
	if err != nil {
		t.Fatalf("a valid keypair failed preflight: %v", err)
	}
	joined := strings.Join(report.Checked, "\n")
	if !strings.Contains(joined, "private key matches") {
		t.Fatalf("preflight did not report the keypair check: %v", report.Checked)
	}
	// Remaining life, not merely "valid" — the day before expiry and a year out are the same word
	// for very different situations.
	if !strings.Contains(joined, "days remaining") {
		t.Fatalf("preflight reported validity without remaining life: %v", report.Checked)
	}

	expired := valid
	expiredDir := tlsSettings(t, now.Add(-48*time.Hour), now.Add(-time.Hour))
	expired.TLSCertificatePath = filepath.Join(expiredDir, "server.crt")
	expired.TLSPrivateKeyPath = filepath.Join(expiredDir, "server.key")
	expired.TLSClientCAPath = filepath.Join(expiredDir, "clients.pem")
	if _, _, _, _, _, err := preflight(expired); err == nil {
		t.Fatal("preflight accepted an expired server certificate: the listener would refuse every connection and preflight said the configuration was fine")
	} else if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the failure does not say the certificate expired: %v", err)
	}

	// A key that does not match its certificate: the classic deployment mix-up, invisible until a
	// client connects.
	mismatched := valid
	otherDir := tlsSettings(t, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	mismatched.TLSPrivateKeyPath = filepath.Join(otherDir, "server.key")
	if _, _, _, _, _, err := preflight(mismatched); err == nil {
		t.Fatal("preflight accepted a private key that does not match the certificate")
	}
}
