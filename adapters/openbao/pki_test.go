package openbaopoc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fixturePKI struct {
	server         tls.Certificate
	roots          *x509.CertPool
	config         map[string]string
	strangerConfig map[string]string
}

func newFixturePKI(t *testing.T) fixturePKI {
	t.Helper()
	dir := t.TempDir()
	now := time.Now()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-poc-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	serial := int64(1)
	issue := func(name, identity string, server bool) (tls.Certificate, string, string) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			cert.DNSNames = []string{"kms.poc.test"}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			uri, err := url.Parse(identity)
			if err != nil {
				t.Fatal(err)
			}
			cert.URIs = []*url.URL{uri}
			cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		encoded, err := x509.CreateCertificate(rand.Reader, cert, ca, public, key)
		if err != nil {
			t.Fatal(err)
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
		certPath, keyPath := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			t.Fatal(err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPath, keyPath
	}
	server, _, _ := issue("server", "", true)
	_, clientPath, keyPath := issue("client", "spiffe://regalia/workload/openbao-poc", false)
	_, strangerPath, strangerKeyPath := issue("stranger", "spiffe://regalia/workload/unauthorized", false)
	c := map[string]string{"kms_url": "https://127.0.0.1:1", "server_name": "kms.poc.test", "ca_path": caPath, "certificate_path": clientPath, "private_key_path": keyPath, "object_id": "poc-seal-key", "repository": "example/poc", "path": "fixtures/seal", "environment": "development", "kms_purpose": "openbao-seal", "timeout": "2s"}
	stranger := cloneConfig(c)
	stranger["certificate_path"], stranger["private_key_path"] = strangerPath, strangerKeyPath
	return fixturePKI{server, roots, c, stranger}
}

func cloneConfig(c map[string]string) map[string]string {
	copy := make(map[string]string, len(c))
	for k, v := range c {
		copy[k] = v
	}
	return copy
}
