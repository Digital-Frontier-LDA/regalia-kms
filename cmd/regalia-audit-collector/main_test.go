package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

func TestRunRefusesMissingOrPartialConfiguration(t *testing.T) {
	cases := []struct {
		name      string
		arguments []string
		mentions  string
	}{
		{
			name:      "no arguments at all",
			arguments: nil,
			mentions:  "-state",
		},
		{
			name:      "state and listen without TLS material",
			arguments: []string{"-state", t.TempDir(), "-listen", "127.0.0.1:0"},
			mentions:  "-tls-cert",
		},
		{
			name:      "TLS material without a client CA",
			arguments: []string{"-state", t.TempDir(), "-listen", "127.0.0.1:0", "-tls-cert", "cert.pem", "-tls-key", "key.pem"},
			mentions:  "-client-ca",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := run(testCase.arguments, os.Stdout)
			if err == nil {
				t.Fatal("run accepted incomplete configuration")
			}
			if !strings.Contains(err.Error(), testCase.mentions) {
				t.Fatalf("the refusal does not name %q: %v", testCase.mentions, err)
			}
		})
	}
}

func TestRunRefusesStateItCannotServe(t *testing.T) {
	// A FILE where the state directory belongs: OpenCollector must not create streams
	// under someone else's file, and run must fail before the listener binds.
	stateAsFile := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(stateAsFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"-state", stateAsFile, "-listen", "127.0.0.1:0"}, os.Stdout)
	if err == nil {
		t.Fatal("run accepted a state path that is a file")
	}
}

func TestBuildServerRefusesUnusableTLSMaterial(t *testing.T) {
	dir := t.TempDir()
	handler := http.NotFoundHandler()
	if _, err := buildServer("127.0.0.1:0", filepath.Join(dir, "missing.pem"), filepath.Join(dir, "missing.pem"), filepath.Join(dir, "missing.pem"), handler); err == nil {
		t.Fatal("buildServer accepted missing TLS files")
	}
	// A CA file with no certificate in it is not a trust root.
	emptyCA := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(emptyCA, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	authority, _, serverPEM, serverKey := collectorPKIFiles(t, dir)
	if _, err := buildServer("127.0.0.1:0", serverPEM, serverKey, emptyCA, handler); err == nil {
		t.Fatal("buildServer accepted a client CA containing no certificate")
	}
	if _, err := buildServer("127.0.0.1:0", serverPEM, serverKey, authority, handler); err != nil {
		t.Fatalf("buildServer refused a complete configuration: %v", err)
	}
}

// THE LISTENER IS THE FIRST DOOR: an audit client without a chain-verified certificate
// must be refused at the handshake, before any handler runs. The handler-level refusal in
// peerIdentity is the second; a regression in either shows up here as a request that
// succeeds which must not.
func TestTheListenerRefusesClientsWithoutACertificate(t *testing.T) {
	dir := t.TempDir()
	authorityPath, clientTLS, serverPEM, serverKey := collectorPKIFiles(t, dir)

	collector, err := audit.OpenCollector(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	server, err := buildServer("127.0.0.1:0", serverPEM, serverKey, authorityPath, collector.Handler())
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serving := make(chan error, 1)
	go func() { serving <- server.ServeTLS(listener, "", "") }()
	defer server.Close()

	// A TLS client with no certificate: the handshake itself must fail. It still trusts
	// the REAL authority, so the only thing that can fail the handshake is the missing
	// client certificate — refusing on the server's identity would pass for the wrong
	// reason, and skipping verification entirely would disable a control under test.
	plainClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    clientRoots(t, authorityPath),
	}}, Timeout: 5 * time.Second}
	_, err = plainClient.Get("https://" + listener.Addr().String() + "/v1/stream-position")
	if err == nil {
		t.Fatal("a client with no certificate completed a request — the listener does not require client certificates")
	}

	// A TLS client WITH the certificate reaches the handler and gets the protocol's answer.
	authenticated, err := audit.NewMTLSHTTPClient(clientTLS, clientRoots(t, authorityPath), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	response, err := authenticated.Get("https://" + listener.Addr().String() + "/v1/stream-position")
	if err != nil {
		t.Fatalf("an authenticated client could not reach the collector: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("an authenticated client was answered %d", response.StatusCode)
	}
	select {
	case err := <-serving:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("the server stopped on its own: %v", err)
		}
	default:
	}
}

func clientRoots(t *testing.T, authorityPath string) *x509.CertPool {
	t.Helper()
	pemBytes, err := os.ReadFile(authorityPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("the test authority is not a usable certificate")
	}
	return pool
}

// collectorPKIFiles writes a one-test CA, a server keypair for 127.0.0.1, and a client
// keypair, returning the CA path, the client tls.Certificate, and the server PEM paths.
func collectorPKIFiles(t *testing.T, dir string) (authorityPath string, clientTLS tls.Certificate, serverPEM string, serverKey string) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "collector-cmd-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, blockType string, derBytes []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: derBytes}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	authorityPath = write("ca.pem", "CERTIFICATE", caDER)

	issue := func(commonName string, extKeyUsage x509.ExtKeyUsage, forServer bool) (string, string, tls.Certificate) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{extKeyUsage},
		}
		if forServer {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		certPath := write(commonName+"-cert.pem", "CERTIFICATE", der)
		pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		keyPath := write(commonName+"-key.pem", "PRIVATE KEY", pkcs8)
		certificate, err := tls.X509KeyPair(mustRead(t, certPath), mustRead(t, keyPath))
		if err != nil {
			t.Fatal(err)
		}
		return certPath, keyPath, certificate
	}
	serverPEM, serverKey, _ = issue("collector-cmd-server", x509.ExtKeyUsageServerAuth, true)
	_, _, clientTLS = issue("sitea-daemon", x509.ExtKeyUsageClientAuth, false)
	return authorityPath, clientTLS, serverPEM, serverKey
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
