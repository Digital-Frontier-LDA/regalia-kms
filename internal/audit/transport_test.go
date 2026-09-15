package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
)

func TestMTLSClientIsPinnedAndDoesNotUseAmbientProxy(t *testing.T) {
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewMTLSHTTPClient(tls.Certificate{Certificate: [][]byte{{1, 2, 3}}, PrivateKey: signer}, x509.NewCertPool(), "audit.internal")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		transport.TLSClientConfig.ServerName != "audit.internal" || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("unsafe transport: %#v", client.Transport)
	}
}

func TestMTLSClientRejectsMissingTrustIdentityAndSigner(t *testing.T) {
	valid := tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))}
	tests := []struct {
		name string
		cert tls.Certificate
		root *x509.CertPool
		host string
	}{
		{"roots", valid, nil, "audit.internal"},
		{"identity", tls.Certificate{}, x509.NewCertPool(), "audit.internal"},
		{"signer", tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: []byte("secret")}, x509.NewCertPool(), "audit.internal"},
		{"server name", valid, x509.NewCertPool(), ""},
		{"URL instead of server name", valid, x509.NewCertPool(), "https://audit.internal"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewMTLSHTTPClient(test.cert, test.root, test.host); err == nil {
				t.Fatal("accepted unsafe transport")
			}
		})
	}
}
