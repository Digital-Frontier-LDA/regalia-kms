package sopsadapter

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"
)

func TestClientTLSConfigRequiresSignerRootsAndServerIdentity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{{1, 2, 3}}, PrivateKey: key}
	roots := x509.NewCertPool()
	config, err := ClientTLSConfig(cert, roots, "kms.internal.example")
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.ServerName != "kms.internal.example" || config.RootCAs != roots || len(config.Certificates) != 1 {
		t.Fatalf("unsafe TLS config: %#v", config)
	}

	for name, input := range map[string]struct {
		certificate tls.Certificate
		roots       *x509.CertPool
		serverName  string
	}{
		"missing certificate": {roots: roots, serverName: "kms.internal.example"},
		"missing roots":       {certificate: cert, serverName: "kms.internal.example"},
		"missing server name": {certificate: cert, roots: roots},
		"URL as server name":  {certificate: cert, roots: roots, serverName: "https://kms.internal.example"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ClientTLSConfig(input.certificate, input.roots, input.serverName); err == nil {
				t.Fatal("unsafe client TLS configuration accepted")
			}
		})
	}
}

func TestNewMTLSHTTPClientHasBoundedTransportAndNoProxyOrRedirect(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: key}
	client, err := NewMTLSHTTPClient(certificate, x509.NewCertPool(), "kms.internal.example", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil || client.Timeout != 15*time.Second {
		t.Fatalf("unsafe HTTP transport: %#v", client)
	}
	if err := client.CheckRedirect(nil, nil); err != http.ErrUseLastResponse {
		t.Fatalf("redirect policy = %v", err)
	}
	if _, err := NewMTLSHTTPClient(certificate, x509.NewCertPool(), "kms.internal.example", 0); err == nil {
		t.Fatal("unbounded timeout accepted")
	}
}

// Compile-time assertion: ordinary software signers satisfy the same Go
// interface as PKCS#11 signers, while the constructor never accepts key bytes.
var _ crypto.Signer = (*rsa.PrivateKey)(nil)
