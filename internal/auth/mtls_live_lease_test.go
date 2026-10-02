package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The gateway is outside the node whose short-lived identity it checks. A node
// can retain its private key and keep a TLS connection open; each request still
// has to pass current gateway expiry/revocation policy. All keys are disposable
// software fixtures, and zero skew makes the short real-time expiry test bounded.
func TestExternalMTLSGatewayRefusesExpiredAndRevokedNodesOnLiveConnections(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "lab peer authority"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	serial := int64(1)
	issue := func(server bool, expires time.Time) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			identity, _ := url.Parse("spiffe://regalia/node/a")
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.URIs = []*url.URL{identity}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), rootKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	}
	revocationPath := filepath.Join(t.TempDir(), "revoked")
	if err := os.WriteFile(revocationPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	revocations, err := NewRevocationList(revocationPath)
	if err != nil {
		t.Fatal(err)
	}
	var served atomic.Int64
	middleware := NewAuthenticator("spiffe://regalia/node/", revocations, time.Now, 0)
	gateway := httptest.NewUnstartedServer(middleware.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if Principal(r.Context()) != "spiffe://regalia/node/a" {
			http.Error(w, "wrong node", http.StatusForbidden)
			return
		}
		served.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})))
	gateway.TLS, err = ServerTLSConfig(issue(true, time.Now().Add(time.Hour)), roots)
	if err != nil {
		t.Fatal(err)
	}
	gateway.StartTLS()
	defer gateway.Close()
	client := func(identity tls.Certificate) *http.Client {
		transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{identity}, ClientSessionCache: tls.NewLRUClientSessionCache(4)}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	var lastHandshakeResumed atomic.Bool
	call := func(c *http.Client) (int, bool, error) {
		request, _ := http.NewRequest(http.MethodGet, gateway.URL+"/v1/operations/sign", nil)
		reused := false
		lastHandshakeResumed.Store(false)
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }, TLSHandshakeDone: func(state tls.ConnectionState, err error) { lastHandshakeResumed.Store(err == nil && state.DidResume) }}))
		response, err := c.Do(request)
		if err != nil {
			return 0, reused, err
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		return response.StatusCode, reused, readErr
	}
	short := issue(false, time.Now().Add(4*time.Second))
	node := client(short)
	if status, _, err := call(node); err != nil || status != http.StatusNoContent {
		t.Fatalf("valid node: status %d error %v", status, err)
	}
	node.Transport.(*http.Transport).CloseIdleConnections()
	if status, reused, err := call(node); err != nil || status != http.StatusNoContent || reused || !lastHandshakeResumed.Load() {
		t.Fatalf("valid resumed TLS session: status %d reused %v resumed %v error %v", status, reused, lastHandshakeResumed.Load(), err)
	}
	time.Sleep(time.Until(short.Leaf.NotAfter) + 100*time.Millisecond)
	if status, reused, err := call(node); err != nil || status != http.StatusUnauthorized || !reused {
		t.Fatalf("expired retained connection: status %d reused %v error %v", status, reused, err)
	}
	if _, _, err := call(client(short)); err == nil {
		t.Fatal("expired node established a fresh authenticated TLS connection")
	}
	node.Transport.(*http.Transport).CloseIdleConnections()
	if _, _, err := call(node); err == nil {
		t.Fatal("expired node reused its cached TLS identity to reach the gateway")
	}
	if served.Load() != 2 {
		t.Fatal("expired requests reached protected backend")
	}
	renewed := issue(false, time.Now().Add(time.Hour))
	renewedNode := client(renewed)
	if status, _, err := call(renewedNode); err != nil || status != http.StatusNoContent {
		t.Fatalf("renewed node: status %d error %v", status, err)
	}
	if err := os.WriteFile(revocationPath, []byte(renewed.Leaf.SerialNumber.String()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if status, reused, err := call(renewedNode); err != nil || status != http.StatusUnauthorized || !reused {
		t.Fatalf("revoked retained connection: status %d reused %v error %v", status, reused, err)
	}
	renewedNode.Transport.(*http.Transport).CloseIdleConnections()
	if status, reused, err := call(renewedNode); err != nil || status != http.StatusUnauthorized || reused || !lastHandshakeResumed.Load() {
		t.Fatalf("revoked resumed session: status %d reused %v resumed %v error %v", status, reused, lastHandshakeResumed.Load(), err)
	}
	if served.Load() != 3 {
		t.Fatal("revoked node reached protected backend")
	}
	// Losing the revocation source cannot turn an existing connection into trust.
	if err := os.Remove(revocationPath); err != nil {
		t.Fatal(err)
	}
	if status, reused, err := call(renewedNode); err != nil || status != http.StatusUnauthorized || !reused {
		t.Fatalf("unavailable policy: status %d reused %v error %v", status, reused, err)
	}
}
