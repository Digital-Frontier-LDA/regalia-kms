package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
)

type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newAuthority(t *testing.T, name string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca authority) issue(t *testing.T, commonName, uri string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{parsed}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        mustParse(t, der),
	}
}

func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writePair(t *testing.T, dir, name string, cert tls.Certificate) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// THE LISTENER MUST AUTHENTICATE THE CALLER, NOT JUST ENCRYPT.
//
// The daemon previously served plaintext and refused every routable address, because
// auth.Authenticator reads the verified chain from request.TLS — nil over plaintext — so nothing
// could be authenticated at all. This drives the real wiring: load the configured material, wrap
// the listener, and check who gets through.
func TestMutualTLSListenerAuthenticatesCallers(t *testing.T) {
	dir := t.TempDir()
	clientCA := newAuthority(t, "regalia-clients")
	rogueCA := newAuthority(t, "rogue")

	serverCert := clientCA.issue(t, "kms", "", true)
	certPath, keyPath := writePair(t, dir, "server", serverCert)
	rootsPath := filepath.Join(dir, "clients.pem")
	if err := os.WriteFile(rootsPath, clientCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}

	settings := config.Default()
	settings.TLSCertificatePath = certPath
	settings.TLSPrivateKeyPath = keyPath
	settings.TLSClientCAPath = rootsPath

	tlsConfig, err := mutualTLSConfig(settings)
	if err != nil {
		t.Fatalf("mutualTLSConfig: %v", err)
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", tlsConfig.MinVersion)
	}

	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(raw, tlsConfig)
	defer listener.Close()

	// The authenticated boundary: identity is required for anything but health.
	protected := auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).
		Middleware(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusNoContent)
		}))
	server := &http.Server{Handler: protected, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	endpoint := "https://" + raw.Addr().String() + "/v1/operations/sign"
	serverRoots := x509.NewCertPool()
	serverRoots.AppendCertsFromPEM(clientCA.pem)

	call := func(t *testing.T, certs []tls.Certificate) (*http.Response, error) {
		t.Helper()
		client := &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13, RootCAs: serverRoots, Certificates: certs,
			}},
		}
		return client.Get(endpoint)
	}

	t.Run("trusted client certificate is authenticated", func(t *testing.T) {
		trusted := clientCA.issue(t, "sops", "spiffe://regalia/sops", false)
		response, err := call(t, []tls.Certificate{trusted})
		if err != nil {
			t.Fatalf("trusted client rejected: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
		}
	})

	t.Run("certificate from an untrusted authority never reaches the handler", func(t *testing.T) {
		rogue := rogueCA.issue(t, "attacker", "spiffe://regalia/sops", false)
		response, err := call(t, []tls.Certificate{rogue})
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				t.Fatal("a certificate signed by an untrusted authority was authenticated")
			}
			return
		}
	})

	t.Run("no client certificate never reaches the handler", func(t *testing.T) {
		response, err := call(t, nil)
		if err == nil {
			defer response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				t.Fatal("an anonymous caller was authenticated")
			}
		}
	})
}

// A daemon configured for mTLS must not start when the material is unusable: starting without the
// trust roots it was told to use would accept callers it cannot authenticate.
func TestMutualTLSConfigFailsClosedOnUnusableMaterial(t *testing.T) {
	dir := t.TempDir()
	ca := newAuthority(t, "regalia-clients")
	certPath, keyPath := writePair(t, dir, "server", ca.issue(t, "kms", "", true))

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.Default()
	settings.TLSCertificatePath, settings.TLSPrivateKeyPath, settings.TLSClientCAPath = certPath, keyPath, empty
	if _, err := mutualTLSConfig(settings); err == nil {
		t.Fatal("trust roots with no usable certificate were accepted")
	}

	settings.TLSClientCAPath = filepath.Join(dir, "absent.pem")
	if _, err := mutualTLSConfig(settings); err == nil {
		t.Fatal("missing trust roots file was accepted")
	}

	settings.TLSClientCAPath = filepath.Join(dir, "clients.pem")
	_ = os.WriteFile(settings.TLSClientCAPath, ca.pem, 0o600)
	settings.TLSPrivateKeyPath = filepath.Join(dir, "absent.key")
	if _, err := mutualTLSConfig(settings); err == nil {
		t.Fatal("missing private key was accepted")
	}
}
