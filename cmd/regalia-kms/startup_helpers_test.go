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

// THE AUDIT SINK'S SERVER NAME IS WHERE "SHIP THE TRAIL OFF-HOST" BECOMES "OVER TLS".
//
// sinkServerName is not a formatting helper: its https check is the only thing standing between a
// misconfigured sink URL and an audit trail shipped in the clear. The whole point of the off-host
// copy is that it survives a host compromise, and a plaintext one is readable by whoever already
// owns the network path.
//
// The hostname-not-host:port detail matters separately. The result is used as the TLS ServerName,
// and a name carrying a port matches no certificate — so a sink on a non-default port would fail
// verification with an error about the certificate rather than about the URL.
func TestSinkServerNameRequiresHTTPSAndReturnsAVerifiableName(t *testing.T) {
	// Subtests rather than sequential assertions: a Fatalf in the first would stop the second
	// from running, so a mutation could be "caught" by a case that was already passing while the
	// case meant to catch it never executed. Each accepted URL now fails on its own.
	//
	// The error is asserted alongside the name in both. A function returning the right hostname
	// AND a non-nil error would satisfy a name-only check, and the caller treats any error as
	// fatal at startup -- so that combination is a daemon that will not boot, under a test
	// saying it should.
	for name, raw := range map[string]string{
		"an explicit port, which must not reach the TLS ServerName": "https://audit.internal:8443/v1/events",
		"the default port":         "https://audit.internal/v1/events",
		"a bare host with no path": "https://audit.internal",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := sinkServerName(raw)
			if err != nil {
				t.Fatalf("%s was refused: %v", name, err)
			}
			if got != "audit.internal" {
				t.Fatalf("server name = %q, want the bare hostname", got)
			}
		})
	}

	for name, raw := range map[string]string{
		"plain http, which ships the trail in the clear": "http://audit.internal/v1/events",
		"no scheme at all":       "audit.internal/v1/events",
		"a scheme nobody serves": "gopher://audit.internal/",
		"empty":                  "",
		"a path with no host":    "https:///v1/events",
		"not a URL":              "://///",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := sinkServerName(raw)
			if err == nil {
				t.Fatalf("%s was accepted, giving server name %q", name, got)
			}
			if got != "" {
				t.Errorf("a refused URL still produced a server name: %q", got)
			}
		})
	}
}

func writePEM(t *testing.T, directory, name, blockType string, der []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A PRIVATE KEY WHERE A CERTIFICATE WAS EXPECTED MUST BE REFUSED, NOT PARSED.
//
// The PEM type is checked rather than the payload alone, and that check is what makes the
// commonest configuration mistake legible. `issuer_certificate_path` pointing at the issuer's
// KEY is a plausible slip -- the two files sit beside each other with similar names -- and
// without the type check the failure would be an ASN.1 parse error deep inside x509, which
// reads as a corrupt certificate rather than as the wrong file.
func TestLoadIssuerCertificateRefusesAnythingThatIsNotACertificatePEM(t *testing.T) {
	directory := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "regalia-issuer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	good := writePEM(t, directory, "issuer.crt", "CERTIFICATE", der)
	loaded, err := loadIssuerCertificate(good)
	if err != nil {
		t.Fatalf("a valid issuer certificate was refused: %v", err)
	}
	if loaded.Subject.CommonName != "regalia-issuer" {
		t.Fatalf("the wrong certificate was loaded: %s", loaded.Subject.CommonName)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the issuer's private key by mistake", func(t *testing.T) {
		path := writePEM(t, t.TempDir(), "issuer.key", "EC PRIVATE KEY", keyDER)
		_, err := loadIssuerCertificate(path)
		if err == nil {
			t.Fatal("a private key was loaded as the issuer certificate")
		}
		if !strings.Contains(err.Error(), "not a PEM certificate") {
			t.Errorf("the error blames the contents rather than the file type: %v", err)
		}
	})

	t.Run("a PEM whose body is not a certificate", func(t *testing.T) {
		path := writePEM(t, t.TempDir(), "bogus.crt", "CERTIFICATE", []byte("not DER"))
		if _, err := loadIssuerCertificate(path); err == nil {
			t.Fatal("a CERTIFICATE block containing junk was accepted")
		}
	})

	t.Run("not PEM at all", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "issuer.crt")
		if err := os.WriteFile(path, []byte("-----BEGIN nonsense"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadIssuerCertificate(path); err == nil {
			t.Fatal("a file that is not PEM was accepted")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadIssuerCertificate(filepath.Join(directory, "absent.crt"))
		if err == nil {
			t.Fatal("a missing issuer certificate was accepted")
		}
		if !strings.Contains(err.Error(), "read issuer certificate") {
			t.Errorf("a missing file does not say so: %v", err)
		}
	})
}
