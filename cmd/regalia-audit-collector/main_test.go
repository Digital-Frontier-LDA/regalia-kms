package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
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

// THE METRICS ENDPOINT IS ON THE SAME LISTENER (regalia-kms-dx7.9, D1=A): a client with a
// chain-verified certificate can scrape it, and the two witnessed-epoch gauges are there,
// labeled by the site (the stream's identity — the scrape job relabels site to instance).
func TestTheMetricsEndpointServesTheWitnessedEpochs(t *testing.T) {
	dir := t.TempDir()
	authorityPath, clientTLS, serverPEM, serverKey := collectorPKIFiles(t, dir)

	collector, err := audit.OpenCollector(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	mux := http.NewServeMux()
	mux.Handle("/v1/", collector.Handler())
	mux.Handle("GET /metrics", collector.MetricsHandler())
	server, err := buildServer("127.0.0.1:0", serverPEM, serverKey, authorityPath, mux)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.ServeTLS(listener, "", "") }()

	authenticated, err := audit.NewMTLSHTTPClient(clientTLS, clientRoots(t, authorityPath), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	response, err := authenticated.Get("https://" + listener.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("an authenticated client could not scrape /metrics: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("the metrics endpoint answered %d", response.StatusCode)
	}
	body := mustReadBody(t, response)
	if !strings.Contains(body, "# HELP regalia_collector_witnessed_membership_epoch") ||
		!strings.Contains(body, "# HELP regalia_collector_witnessed_anchor_epoch") {
		t.Fatalf("the metrics endpoint does not name both witnessed-epoch gauges:\n%s", body)
	}
}

// THE WITNESS REPORTS WHAT THE COMMIT PATH COMMITTED, NOT 0 (regalia-kms-dx7.9 review finding 1):
// the collector's stream file is opened write-only for the commit path, and a scrape that read
// through that handle would fail every read and serve epoch 0 for every node — a reference the
// behind rules can never exceed, so both stay silent. This test commits real sync and
// esp-advances lines THROUGH the sink's own POST /v1/events path and scrapes: the values must be
// the epochs the lines carry. The series is ONE PER NODE (finding 2): labeled by the node's site
// (the stream's site minus its .<trail> suffix), the membership value from the node's sync trail,
// the anchor value from its esp-advances trail, and nothing for a node the collector has not seen.
func TestTheMetricsEndpointReportsTheCommittedWitness(t *testing.T) {
	dir := t.TempDir()
	authorityPath, clientTLS, serverPEM, serverKey := collectorPKIFiles(t, dir)

	collector, err := audit.OpenCollector(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	mux := http.NewServeMux()
	mux.Handle("/v1/", collector.Handler())
	mux.Handle("GET /metrics", collector.MetricsHandler())
	server, err := buildServer("127.0.0.1:0", serverPEM, serverKey, authorityPath, mux)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.ServeTLS(listener, "", "") }()

	authenticated, err := audit.NewMTLSHTTPClient(clientTLS, clientRoots(t, authorityPath), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://" + listener.Addr().String() + "/v1/events"

	// One line a trail event, committed exactly the way the shipper commits it: the stream
	// is the shipper's <site>.<trail>, the event's chain position is the stream's, and the line
	// is the shape recover.witness_epoch reads — an ALLOW that names the epoch.
	ship := func(stream, line string, sequence uint64, previousHash string) {
		t.Helper()
		dot := strings.LastIndexByte(stream, '.')
		events, err := audit.TrailEvents(stream[dot+1:], []byte(line+"\n"))
		if err != nil {
			t.Fatalf("the %s line %q does not map: %v", stream, line, err)
		}
		event := events[0]
		event.Sequence = sequence
		event.PreviousHash = previousHash
		event.Hash = audit.EventHashForTest(event)
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Regalia-Site", stream)
		response, err := authenticated.Do(request)
		if err != nil {
			t.Fatalf("commit the %s line: %v", stream, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("commit the %s line: %d %s", stream, response.StatusCode, mustReadBody(t, response))
		}
	}

	// node-a's sync trail: two ALLOW lines, epochs 3 and 7, chained like trails.py writes.
	// The event chain is built over BOTH lines at once (TrailEvents chains them: the second
	// event's previous_hash is the first event's hash), and each is committed one at a time.
	first := `{"at":1790000000,"event":"epoch","prev":"","seq":1,"outcome":"ALLOW","epoch":3}`
	second := `{"at":1790000001,"event":"epoch","prev":"` + hex.EncodeToString(func() []byte {
		sum := sha256.Sum256(append([]byte(first), '\n'))
		return sum[:]
	}()) + `","seq":2,"outcome":"ALLOW","epoch":7}`
	events, err := audit.TrailEvents("sync", []byte(first+"\n"+second+"\n"))
	if err != nil {
		t.Fatalf("the sync trail does not chain: %v", err)
	}
	for i, line := range []string{first, second} {
		_ = line
		event := events[i]
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Regalia-Site", "nodea.sync")
		response, err := authenticated.Do(request)
		if err != nil {
			t.Fatalf("commit the sync line: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("commit the sync line: %d %s", response.StatusCode, mustReadBody(t, response))
		}
	}
	// node-a's esp-advances trail: anchor 5.
	ship("nodea.esp-advances", `{"at":1790000002,"event":"anchor","prev":"","seq":1,"outcome":"ALLOW","epoch":5}`, 1, audit.GenesisHash())

	scrape := func() string {
		t.Helper()
		response, err := authenticated.Get("https://" + listener.Addr().String() + "/metrics")
		if err != nil {
			t.Fatalf("scrape the metrics endpoint: %v", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("the metrics endpoint answered %d", response.StatusCode)
		}
		return mustReadBody(t, response)
	}

	body := scrape()
	for _, want := range []string{
		`regalia_collector_witnessed_membership_epoch{site="nodea"} 7`,
		`regalia_collector_witnessed_anchor_epoch{site="nodea"} 5`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("the scrape does not hold the committed witness %q:\\n%s", want, body)
		}
	}
	if strings.Contains(body, `site="nodeb"`) {
		t.Fatalf("a node the collector has not seen gets a series the endpoint invented:\\n%s", body)
	}

	// A reloaded collector re-reads the committed lines from disk and reports the same witness:
	// the value comes from the file, not from memory the commit path keeps.
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := audit.OpenCollector(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopenedMux := http.NewServeMux()
	reopenedMux.Handle("GET /metrics", reopened.MetricsHandler())
	reopenedServer, err := buildServer("127.0.0.1:0", serverPEM, serverKey, authorityPath, reopenedMux)
	if err != nil {
		t.Fatal(err)
	}
	reopenedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedServer.Close()
	go func() { _ = reopenedServer.ServeTLS(reopenedListener, "", "") }()
	response, err := authenticated.Get("https://" + reopenedListener.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("scrape the reloaded collector: %v", err)
	}
	defer response.Body.Close()
	body = mustReadBody(t, response)
	if !strings.Contains(body, `regalia_collector_witnessed_membership_epoch{site="nodea"} 7`) ||
		!strings.Contains(body, `regalia_collector_witnessed_anchor_epoch{site="nodea"} 5`) {
		t.Fatalf("the reloaded collector does not hold the committed witness:\\n%s", body)
	}
}

// THE WITNESS REPORTS ABSENCE, NOT A FLOOR (regalia-kms-dx7.9 review, round 5): a committed trail
// that holds no ALLOW epoch is not a witnessed epoch-0 — it is the blind state, and a zero series
// would both suppress RegaliaCollectorEpochMissing and give the behind rules a floor to compare
// against. So a node whose sync trail committed but never allowed an epoch gets NO membership
// series (and the anchor is untouched); likewise a negative epoch is not an epoch (it would wrap
// to the top of the uint64 range and stand as a spurious maximum), so a trail of only negative
// epochs also gets no series.
func TestTheMetricsEndpointReportsAbsenceWhenNoEpochWasAllowed(t *testing.T) {
	dir := t.TempDir()
	authorityPath, clientTLS, serverPEM, serverKey := collectorPKIFiles(t, dir)

	collector, err := audit.OpenCollector(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	mux := http.NewServeMux()
	mux.Handle("/v1/", collector.Handler())
	mux.Handle("GET /metrics", collector.MetricsHandler())
	server, err := buildServer("127.0.0.1:0", serverPEM, serverKey, authorityPath, mux)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() { _ = server.ServeTLS(listener, "", "") }()

	authenticated, err := audit.NewMTLSHTTPClient(clientTLS, clientRoots(t, authorityPath), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://" + listener.Addr().String() + "/v1/events"

	ship := func(stream, line string) {
		t.Helper()
		dot := strings.LastIndexByte(stream, '.')
		events, err := audit.TrailEvents(stream[dot+1:], []byte(line+"\n"))
		if err != nil {
			t.Fatalf("the %s line %q does not map: %v", stream, line, err)
		}
		event := events[0]
		event.Sequence = 1
		event.PreviousHash = audit.GenesisHash()
		event.Hash = audit.EventHashForTest(event)
		body, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-Regalia-Site", stream)
		response, err := authenticated.Do(request)
		if err != nil {
			t.Fatalf("commit the %s line: %v", stream, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("commit the %s line: %d %s", stream, response.StatusCode, mustReadBody(t, response))
		}
	}

	// nodeb's sync trail committed but allowed no epoch (a RECORDED line, no epoch at all).
	ship("nodeb.sync", `{"at":1790000010,"event":"epoch","prev":"","seq":1,"outcome":"RECORDED"}`)
	// nodec's sync trail allowed only a negative epoch (not an epoch; would wrap uint64).
	ship("nodec.sync", `{"at":1790000011,"event":"epoch","prev":"","seq":1,"outcome":"ALLOW","epoch":-1}`)

	response, err := authenticated.Get("https://" + listener.Addr().String() + "/metrics")
	if err != nil {
		t.Fatalf("scrape the metrics endpoint: %v", err)
	}
	defer response.Body.Close()
	body := mustReadBody(t, response)
	for _, absent := range []string{
		`regalia_collector_witnessed_membership_epoch{site="nodeb"}`,
		`regalia_collector_witnessed_membership_epoch{site="nodec"}`,
	} {
		if strings.Contains(body, absent) {
			t.Fatalf("the scrape publishes a membership series for a node with no allowed epoch (%q):\\n%s", absent, body)
		}
	}
	// The endpoint still names the gauge (the series is what is absent, not the metric).
	if !strings.Contains(body, "# HELP regalia_collector_witnessed_membership_epoch") {
		t.Fatalf("the gauge is no longer named:\\n%s", body)
	}
}

func mustReadBody(t *testing.T, response *http.Response) string {
	t.Helper()
	contents, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
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

// TestTheOperatorHandover: `regalia-audit-collector handover` (#291) needs its four flags, refuses
// while a collector holds the state, and then records the hand-over a restarted collector applies.
func TestTheOperatorHandover(t *testing.T) {
	selfSigned := func(name string) *x509.Certificate {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
		if err != nil {
			t.Fatal(err)
		}
		certificate, _ := x509.ParseCertificate(der)
		return certificate
	}
	fingerprint := func(c *x509.Certificate) string { sum := sha256.Sum256(c.Raw); return hex.EncodeToString(sum[:]) }
	old, replacement := selfSigned("old"), selfSigned("new")
	stateDir := t.TempDir()
	collector, err := audit.OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	events, _ := audit.TrailEvents("sync", []byte(`{"at":1790000000,"event":"e","prev":"","seq":1}`+"\n"))
	body, _ := json.Marshal(events[0])
	request := httptest.NewRequest("POST", "/v1/events", strings.NewReader(string(body)))
	request.Header.Set("X-Regalia-Site", "sitea.sync")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{old}}
	recorder := httptest.NewRecorder()
	collector.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 204 {
		t.Fatalf("the old certificate's event: %d %s", recorder.Code, recorder.Body.String())
	}
	argv := []string{"handover", "-state", stateDir, "-old", fingerprint(old), "-new", fingerprint(replacement), "-reason", "the old key was lost"}
	if err := run(argv[:len(argv)-2], os.Stderr); err == nil {
		t.Fatal("a hand-over without a reason was taken")
	}
	if err := run(argv, os.Stderr); err == nil || !strings.Contains(err.Error(), "held by another collector") {
		t.Fatalf("a hand-over while a collector holds the state: %v", err)
	}
	collector.Close()
	out, _ := os.CreateTemp(t.TempDir(), "out")
	if err := run(argv, out); err != nil {
		t.Fatal(err)
	}
	reopened, err := audit.OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	request = httptest.NewRequest("GET", "/v1/stream-position", nil)
	request.Header.Set("X-Regalia-Site", "sitea.sync")
	request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{replacement}}
	recorder = httptest.NewRecorder()
	reopened.Handler().ServeHTTP(recorder, request)
	if !strings.Contains(recorder.Body.String(), `"sequence":1`) {
		t.Fatalf("the replacement does not see the old stream: %s", recorder.Body.String())
	}
}
