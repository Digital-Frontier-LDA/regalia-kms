package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func certificate(t *testing.T, uri string, notBefore, notAfter time.Time, serial int64) *x509.Certificate {
	t.Helper()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if uri != "" {
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		cert.URIs = []*url.URL{parsed}
	}
	return cert
}

func authenticatedRequest(cert *x509.Certificate) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil)
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	return request
}

// writeRevocationFile builds a one-line-per-serial revocation file and returns
// its path. The file is created in t.TempDir() so the test owns it.
func writeRevocationFile(t *testing.T, serials ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revoked.txt")
	if err := os.WriteFile(path, []byte(strings.Join(serials, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newRevocationList is the test-side convenience: build a list from a list of
// serials (no file I/O at the test site, but the list still re-reads the file
// it wrote on every check — same semantics as production).
func newRevocationList(t *testing.T, serials ...string) *RevocationList {
	t.Helper()
	list, err := NewRevocationList(writeRevocationFile(t, serials...))
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestAuthenticateAcceptsOneVerifiedRegaliaURISAN(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	principal, err := authenticator.Authenticate(authenticatedRequest(certificate(t, "spiffe://regalia/workload/sops-prod", now.Add(-time.Hour), now.Add(time.Hour), 1)))
	if err != nil || principal != "spiffe://regalia/workload/sops-prod" {
		t.Fatalf("Authenticate() = %q, %v", principal, err)
	}
}

func TestAuthenticateRejectsUnverifiedMissingAmbiguousExpiredAndRevokedCertificates(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", newRevocationList(t, "5"), func() time.Time { return now }, time.Minute)
	valid := certificate(t, "spiffe://regalia/workload/test", now.Add(-time.Hour), now.Add(time.Hour), 1)
	ambiguous := certificate(t, "spiffe://regalia/workload/test", now.Add(-time.Hour), now.Add(time.Hour), 2)
	second, _ := url.Parse("spiffe://regalia/workload/other")
	ambiguous.URIs = append(ambiguous.URIs, second)
	tests := map[string]*http.Request{
		"no TLS":              httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil),
		"unverified":          func() *http.Request { r := authenticatedRequest(valid); r.TLS.VerifiedChains = nil; return r }(),
		"missing URI":         authenticatedRequest(certificate(t, "", now.Add(-time.Hour), now.Add(time.Hour), 3)),
		"ambiguous URI":       authenticatedRequest(ambiguous),
		"expired beyond skew": authenticatedRequest(certificate(t, "spiffe://regalia/workload/test", now.Add(-2*time.Hour), now.Add(-2*time.Minute), 4)),
		"revoked":             authenticatedRequest(certificate(t, "spiffe://regalia/workload/test", now.Add(-time.Hour), now.Add(time.Hour), 5)),
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := authenticator.Authenticate(request); err == nil || err.Error() != "request authentication failed" {
				t.Fatalf("Authenticate() error = %q", err)
			}
		})
	}
}

func TestAuthenticateRejectsNonCanonicalSPIFFEIdentity(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	identities := []string{
		"spiffe://regalia/workload/sops?role=admin",
		"spiffe://regalia/workload/sops#admin",
		"spiffe://user@regalia/workload/sops",
		"spiffe://regalia.evil/workload/sops",
		"https://regalia/workload/sops",
	}
	for _, identity := range identities {
		if _, err := authenticator.Authenticate(authenticatedRequest(certificate(t, identity, now.Add(-time.Hour), now.Add(time.Hour), 20))); err == nil {
			t.Fatalf("non-canonical identity accepted: %s", identity)
		}
	}
}

func TestMiddlewareRequiresIdentityExceptHealthAndDoesNotLeakPeer(t *testing.T) {
	authenticator := NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute)
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(Principal(request.Context())))
	})
	handler := authenticator.Middleware(next)

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/health/live", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	denied := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil)
	request.RemoteAddr = "super-secret-peer.internal:1234"
	handler.ServeHTTP(denied, request)
	if denied.Code != http.StatusUnauthorized || strings.Contains(denied.Body.String(), "super-secret-peer") {
		t.Fatalf("unsafe denial: status=%d body=%q", denied.Code, denied.Body.String())
	}
}

func TestMiddlewarePassesVerifiedPrincipalInContext(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	handler := authenticator.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(Principal(request.Context())))
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, authenticatedRequest(certificate(t, "spiffe://regalia/workload/release", now.Add(-time.Hour), now.Add(time.Hour), 8)))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "spiffe://regalia/workload/release" {
		t.Fatalf("authenticated response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestCertificateRotationOverlapAndRevocation(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	oldCert := certificate(t, "spiffe://regalia/workload/release", now.Add(-time.Hour), now.Add(5*time.Minute), 10)
	newCert := certificate(t, "spiffe://regalia/workload/release", now.Add(30*time.Second), now.Add(time.Hour), 11)
	overlap := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	for _, cert := range []*x509.Certificate{oldCert, newCert} {
		if _, err := overlap.Authenticate(authenticatedRequest(cert)); err != nil {
			t.Fatalf("rotation overlap rejected serial %s: %v", cert.SerialNumber, err)
		}
	}
	afterCutover := NewAuthenticator("spiffe://regalia/", newRevocationList(t, "10"), func() time.Time { return now }, time.Minute)
	if _, err := afterCutover.Authenticate(authenticatedRequest(oldCert)); err == nil {
		t.Fatal("revoked old certificate accepted")
	}
	if _, err := afterCutover.Authenticate(authenticatedRequest(newCert)); err != nil {
		t.Fatalf("new certificate rejected after cutover: %v", err)
	}
}

func TestServerTLSRequiresTLS13AndVerifiesPresentedClientCertificates(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	config, err := ServerTLSConfig(tls.Certificate{PrivateKey: key}, roots)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.ClientAuth != tls.VerifyClientCertIfGiven || config.ClientCAs != roots {
		t.Fatalf("unsafe TLS config: %#v", config)
	}
}

func issueTestCertificate(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, uri string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "regalia-test"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		parsed, parseErr := url.Parse(uri)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		template.URIs = []*url.URL{parsed}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}
}

func TestLiveTLSHandshakeRequiresTrustedClientForOperation(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "regalia-test-ca"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	serverCertificate := issueTestCertificate(t, ca, caKey, 101, "", true)
	clientCertificate := issueTestCertificate(t, ca, caKey, 102, "spiffe://regalia/workload/sops-prod", false)

	authenticator := NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute)
	server := httptest.NewUnstartedServer(authenticator.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte(Principal(request.Context())))
	})))
	server.TLS, err = ServerTLSConfig(serverCertificate, roots)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()

	client := server.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{clientCertificate}
	response, err := client.Post(server.URL+"/v1/operations/unwrap", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated status = %d", response.StatusCode)
	}

	unauthenticated := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
	}}}
	response, err = unauthenticated.Post(server.URL+"/v1/operations/unwrap", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.StatusCode)
	}
}

func TestPrincipalContextDefaultsEmpty(t *testing.T) {
	if got := Principal(context.Background()); got != "" {
		t.Fatalf("Principal() = %q", got)
	}
}

// A REJECTED REQUEST IS A SECURITY SIGNAL, NOT JUST A 401.
//
// Probing, expired client certificates and revoked-but-retrying callers all die in
// the middleware before any route or handler runs, so nothing downstream can ever
// count them. The hook fires on exactly the rejections — never on health checks,
// never on requests that authenticated.
func TestAuthenticatorReportsUnauthorizedAttempts(t *testing.T) {
	authenticator := NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute)
	var rejected int
	authenticator.OnUnauthorized(func() { rejected++ })
	ok := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { writer.WriteHeader(http.StatusOK) })
	handler := authenticator.Middleware(ok)

	// Health checks are unauthenticated by design; they are not a signal.
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/health/live", nil))
	if rejected != 0 {
		t.Fatalf("health check counted as unauthorized: rejected=%d", rejected)
	}

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil))
	if rejected != 1 {
		t.Fatalf("certificateless operation request: rejected=%d, want 1", rejected)
	}

	cert := certificate(t, "spiffe://regalia/workload/anything", time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 1)
	handler.ServeHTTP(httptest.NewRecorder(), authenticatedRequest(cert))
	if rejected != 1 {
		t.Fatalf("a request that authenticated was counted as rejected: rejected=%d", rejected)
	}
}
