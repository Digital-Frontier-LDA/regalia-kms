package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func collectorEndpointFixture(t *testing.T) (CollectorEndpointOptions, time.Time, []byte) {
	t.Helper()
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "offline-test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, contents []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return CollectorEndpointOptions{Collector: "https://collector.invalid:8443", Site: "sitea",
		CertificatePath: write("client.crt", certPEM), PrivateKeyPath: write("client.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})),
		CAPath: write("collector-ca.pem", certPEM), ReceiptKeysPath: write("receipts.pub", []byte("# pinned test receipt\n"+hex.EncodeToString(public)+" # current\n"))}, now, der
}

// Count accepted TCP connections before net/http performs TLS. A failed
// certificate check must remain visible even if no HTTP handler ever runs.
type collectorEndpointConnections struct {
	net.Listener
	accepted atomic.Int64
}

func (listener *collectorEndpointConnections) Accept() (net.Conn, error) {
	connection, err := listener.Listener.Accept()
	if err == nil {
		listener.accepted.Add(1)
	}
	return connection, err
}

func collectorEndpointTestServer(t *testing.T) (*httptest.Server, *collectorEndpointConnections, *atomic.Int64) {
	t.Helper()
	requests := new(atomic.Int64)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	connections := &collectorEndpointConnections{Listener: server.Listener}
	server.Listener = connections
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, connections, requests
}

func TestCollectorEndpointLoadsExistingContractWithoutProbing(t *testing.T) {
	options, now, der := collectorEndpointFixture(t)
	server, connections, requests := collectorEndpointTestServer(t)
	options.Collector = server.URL
	endpoint, err := LoadCollectorEndpoint(options, now)
	if err != nil {
		t.Fatal(err)
	}
	wantIdentity := sha256.Sum256(der)
	if endpoint.Collector != options.Collector || endpoint.Site != options.Site || endpoint.Identity != hex.EncodeToString(wantIdentity[:]) ||
		endpoint.Certificate.PrivateKey == nil || endpoint.Leaf.Subject.CommonName != "offline-test" || endpoint.Roots == nil || len(endpoint.ReceiptKeys) != 1 {
		t.Fatal("validated endpoint lost material required by check/probe/conformance")
	}
	// Close the listener before the final observation. A synchronous TLS probe
	// must be accepted before it can return its handshake error to the loader.
	server.Close()
	if connections.accepted.Load() != 0 {
		t.Fatal("offline validation opened a connection to the collector")
	}
	if requests.Load() != 0 {
		t.Fatal("offline validation contacted the collector HTTP handler")
	}
	// An origin with no reachable listener is still configured: this API does not test liveness.
	options.Collector = "https://127.0.0.1:1"
	if _, err := LoadCollectorEndpoint(options, now); err != nil {
		t.Fatalf("offline origin validation probed liveness: %v", err)
	}
}

func TestCollectorEndpointConnectionWitnessSeesRejectedHandshake(t *testing.T) {
	options, now, _ := collectorEndpointFixture(t)
	server, connections, requests := collectorEndpointTestServer(t)
	options.Collector = server.URL
	endpoint, err := LoadCollectorEndpoint(options, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewMTLSHTTPClient(endpoint.Certificate, endpoint.Roots, parsed.Hostname())
	if err != nil {
		t.Fatal(err)
	}
	client.Timeout = 5 * time.Second
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	server.Close()
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) {
		t.Fatalf("control must exercise a rejected TLS trust check, got %v", err)
	}
	if connections.accepted.Load() == 0 {
		t.Fatal("connection witness missed a rejected TLS handshake")
	}
	if requests.Load() != 0 {
		t.Fatal("rejected handshake reached HTTP handler")
	}
}

func TestCollectorEndpointRefusesMissingFields(t *testing.T) {
	base, now, _ := collectorEndpointFixture(t)
	for _, field := range []string{"collector", "site", "certificate", "key", "ca", "receipts"} {
		t.Run(field, func(t *testing.T) {
			options := base
			switch field {
			case "collector":
				options.Collector = ""
			case "site":
				options.Site = ""
			case "certificate":
				options.CertificatePath = ""
			case "key":
				options.PrivateKeyPath = ""
			case "ca":
				options.CAPath = ""
			case "receipts":
				options.ReceiptKeysPath = ""
			}
			if _, err := LoadCollectorEndpoint(options, now); err == nil || !strings.Contains(err.Error(), "are required") {
				t.Fatalf("missing %s: %v", field, err)
			}
		})
	}
}

func TestCollectorEndpointKeepsOriginAndSiteRefusals(t *testing.T) {
	base, now, _ := collectorEndpointFixture(t)
	for _, origin := range []string{"http://collector.invalid", "https://user@collector.invalid", "https://collector.invalid/path", "https://collector.invalid?q=1", "https://collector.invalid#fragment"} {
		t.Run(origin, func(t *testing.T) {
			o := base
			o.Collector = origin
			if _, err := LoadCollectorEndpoint(o, now); err == nil || !strings.Contains(err.Error(), "collector") {
				t.Fatalf("invalid origin accepted: %v", err)
			}
		})
	}
	for _, site := range []string{"site a", strings.Repeat("a", 63)} {
		o := base
		o.Site = site
		if _, err := LoadCollectorEndpoint(o, now); err == nil || !strings.Contains(err.Error(), "not a site") {
			t.Fatalf("invalid site accepted: %v", err)
		}
	}
}

func TestCollectorEndpointChecksPairAndValidityAtSuppliedTime(t *testing.T) {
	base, now, _ := collectorEndpointFixture(t)
	for _, delta := range []time.Duration{-2 * time.Hour, 2 * time.Hour} {
		if _, err := LoadCollectorEndpoint(base, now.Add(delta)); err == nil || !strings.Contains(err.Error(), "not now") {
			t.Fatalf("invalid certificate time %v: %v", delta, err)
		}
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base.PrivateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCollectorEndpoint(base, now); err == nil || !strings.Contains(err.Error(), "client certificate and key") {
		t.Fatalf("mismatched key pair accepted: %v", err)
	}
}

func TestCollectorEndpointRequiresCAAndReceiptKeys(t *testing.T) {
	for _, tc := range []struct {
		name, body, reason string
		ca                 bool
	}{
		{"ca", "not a CA", "holds no usable certificate", true},
		{"empty receipts", "# none pinned\n", "pins no receipt key", false},
		{"malformed receipts", "not-a-key\n", "is not an Ed25519 public key", false},
		{"uppercase receipts", strings.Repeat("A", 64), "is not an Ed25519 public key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, now, _ := collectorEndpointFixture(t)
			path := o.ReceiptKeysPath
			if tc.ca {
				path = o.CAPath
			}
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCollectorEndpoint(o, now); err == nil || !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("invalid %s accepted: %v", tc.name, err)
			}
		})
	}
}
