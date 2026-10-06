package e2e_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

const (
	recoveryObject    = "synthetic-recovery-ca"
	recoveryPurpose   = "synthetic-pki-recovery"
	recoveryPrincipal = "spiffe://regalia/workload/synthetic-recovery"
	recoveryProfile   = "synthetic-recovery-profile"
	recoverySite      = "synthetic-recovery-site"
)

// The shell runner makes these dependencies mandatory. Ordinary unit runs do
// not claim process/hardware evidence when the disposable fixture is absent.
func TestShippingDaemonPKIReservationsSurviveSIGKILL(t *testing.T) {
	if os.Getenv("REGALIA_EXPECT_PKI_RECOVERY") != "1" {
		t.Skip("run e2e/openbao-pki-recovery.sh for the mandatory SoftHSM process drill")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("the mandatory process drill requires Linux")
	}
	for _, tool := range []string{"softhsm2-util", "pkcs11-tool"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal("mandatory recovery dependency missing", tool)
		}
	}
	for _, variable := range []string{"REGALIA_PKI_RECOVERY_KMS", "REGALIA_PKI_RECOVERY_COLLECTOR"} {
		info, err := os.Stat(os.Getenv(variable))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("mandatory recovery executable missing", variable)
		}
	}
	for _, outcome := range []string{"authorized", "success"} {
		t.Run(outcome+"-ack-held", func(t *testing.T) { recoveryScenario(t, outcome) })
	}
}

type recoveryProcess struct {
	command *exec.Cmd
	done    chan error
	log     *os.File
	stopped bool
}

func recoveryStart(t *testing.T, path string, arguments []string, environment []string, logPath string) *recoveryProcess {
	t.Helper()
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal("create private process log", err)
	}
	command := exec.Command(path, arguments...)
	command.Env, command.Stdout, command.Stderr = environment, log, log
	if err := command.Start(); err != nil {
		log.Close()
		t.Fatal("start disposable process", err)
	}
	p := &recoveryProcess{command: command, done: make(chan error, 1), log: log}
	go func() { p.done <- command.Wait() }()
	t.Cleanup(func() {
		if p.stopped {
			_ = log.Close()
			return
		}
		_ = command.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(5 * time.Second):
		}
		_ = log.Close()
	})
	return p
}

func (p *recoveryProcess) kill(t *testing.T) {
	t.Helper()
	if err := p.command.Process.Kill(); err != nil {
		t.Fatal("SIGKILL disposable daemon", err)
	}
	select {
	case err := <-p.done:
		p.stopped = true
		if err == nil || !strings.Contains(err.Error(), "killed") {
			t.Fatal("daemon did not terminate from SIGKILL")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGKILL did not terminate disposable daemon")
	}
}

func recoveryWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal("write private recovery fixture", err)
	}
}

func recoveryJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal("encode recovery fixture", err)
	}
	recoveryWrite(t, path, data)
}

func recoveryKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func recoveryCertificate(t *testing.T, template, parent *x509.Certificate, public any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal("create synthetic public certificate", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func recoveryTLS(t *testing.T, directory string, now time.Time) (*x509.CertPool, tls.Certificate, tls.Certificate, tls.Certificate) {
	t.Helper()
	key := recoveryKey(t)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-workload-root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root = recoveryCertificate(t, root, root, key.Public(), key)
	recoveryWrite(t, filepath.Join(directory, "tls-root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	roots := x509.NewCertPool()
	roots.AddCert(root)
	certificates := make([]tls.Certificate, 0, 3)
	for i, name := range []string{"daemon", "collector", "workload"} {
		identity := recoveryKey(t)
		template := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "synthetic-" + name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		switch name {
		case "daemon":
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		case "collector":
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "workload":
			principal, _ := url.Parse(recoveryPrincipal)
			template.URIs = []*url.URL{principal}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		certificate := recoveryCertificate(t, template, root, identity.Public(), key)
		private, err := x509.MarshalECPrivateKey(identity)
		if err != nil {
			t.Fatal(err)
		}
		certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
		privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private})
		recoveryWrite(t, filepath.Join(directory, name+".pem"), certificatePEM)
		recoveryWrite(t, filepath.Join(directory, name+".key"), privatePEM)
		pair, err := tls.X509KeyPair(certificatePEM, privatePEM)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, pair)
	}
	return roots, certificates[0], certificates[1], certificates[2]
}

func recoveryClient(t *testing.T, roots *x509.CertPool, certificate tls.Certificate) *http.Client {
	t.Helper()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate}}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func recoveryAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func recoveryReady(t *testing.T, client *http.Client, origin string, collector bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		method, expected := http.MethodGet, http.StatusOK
		if collector {
			method, expected = http.MethodHead, http.StatusNoContent
		}
		request, err := http.NewRequest(method, origin+"/v1/health/ready", nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == expected {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("disposable process did not become ready")
}

// The proxy forwards to the shipping collector over mTLS as the exact daemon
// certificate identity. It holds a valid committed ACK, never invents an event
// or substitutes a fake collector. Both listeners are disposable loopback only.
type recoveryACKBarrier struct {
	mu      sync.Mutex
	request string
	outcome string
	held    chan audit.Event
	release chan struct{}
	client  *http.Client
	origin  string
}

func (barrier *recoveryACKBarrier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil || len(body) > 64<<10 {
		http.Error(w, "bounded audit input required", http.StatusBadRequest)
		return
	}
	forward, err := http.NewRequestWithContext(r.Context(), r.Method, barrier.origin+r.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "audit forwarding failed", http.StatusBadGateway)
		return
	}
	forward.Header = r.Header.Clone()
	response, err := barrier.client.Do(forward)
	if err != nil {
		http.Error(w, "audit collector unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	var event audit.Event
	barrier.mu.Lock()
	matched := r.URL.Path == "/v1/events" && json.Unmarshal(body, &event) == nil && event.RequestID == barrier.request && event.Outcome == barrier.outcome && barrier.request != ""
	if matched {
		barrier.request = "" // hold exactly one attempt, including under replay
	}
	barrier.mu.Unlock()
	if matched {
		if response.StatusCode != http.StatusNoContent || response.Header.Get("X-Regalia-Audit-Hash") != event.Hash {
			http.Error(w, "collector did not acknowledge the exact event", http.StatusBadGateway)
			return
		}
		barrier.held <- event
		select {
		case <-barrier.release:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", response.Header.Get("Content-Type"))
	w.Header().Set("X-Regalia-Audit-Hash", response.Header.Get("X-Regalia-Audit-Hash"))
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 64<<10))
}

type recoveryResponse struct {
	status int
	result []byte
	code   string
	retry  bool
	err    error
}

func recoverySign(client *http.Client, origin string, raw []byte, nonce, requestID string) recoveryResponse {
	body, err := json.Marshal(map[string]any{"object_id": recoveryObject, "context": map[string]any{"environment": "development", "purpose": recoveryPurpose, "expires_at": time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339), "nonce": nonce}, "content_type": "application/vnd.regalia.x509-tbs", "payload_base64": raw})
	if err != nil {
		return recoveryResponse{err: err}
	}
	request, err := http.NewRequest(http.MethodPost, origin+"/v1/operations/sign", bytes.NewReader(body))
	if err != nil {
		return recoveryResponse{err: err}
	}
	request.GetBody = nil // a killed signing request is never transport-replayed
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", nonce)
	request.Header.Set("X-Request-ID", requestID)
	response, err := client.Do(request)
	if err != nil {
		return recoveryResponse{err: err}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8<<10+1))
	if err != nil || len(data) > 8<<10 {
		return recoveryResponse{err: io.ErrUnexpectedEOF}
	}
	var result struct {
		Result    []byte `json:"result_base64"`
		Code      string `json:"code"`
		Retryable bool   `json:"retryable"`
	}
	err = json.Unmarshal(data, &result)
	return recoveryResponse{status: response.StatusCode, result: result.Result, code: result.Code, retry: result.Retryable, err: err}
}

func recoveryRefusal(t *testing.T, response recoveryResponse, status int, code string) {
	t.Helper()
	if response.err != nil || response.status != status || response.code != code || response.retry || len(response.result) != 0 {
		t.Fatal("incorrect recovery refusal", response.status, response.code, response.retry, response.err)
	}
}

// Only placeholder signatures use the stand-in key. The TBS issuer name/AKI
// refer to the token-backed intermediate; after the daemon signs, the returned
// signature must verify against that intermediate's actual token public key.
func recoveryInputs(t *testing.T, issuer *x509.Certificate, standIn *ecdsa.PrivateKey, now time.Time) ([]byte, []byte, []byte) {
	t.Helper()
	parent := *issuer
	parent.PublicKey = standIn.Public()
	leafKey := recoveryKey(t)
	leaves := make([][]byte, 0, 2)
	for _, serial := range []int64{10, 11} {
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		leaf := recoveryCertificate(t, template, &parent, leafKey.Public(), standIn)
		leaves = append(leaves, leaf.Raw)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(10), RevocationTime: now}}}, &parent, standIn)
	if err != nil {
		t.Fatal("create synthetic CRL input", err)
	}
	return leaves[0], leaves[1], crl
}

func recoveryTBS(t *testing.T, der []byte) []byte {
	t.Helper()
	var artifact struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &artifact); err != nil || len(rest) != 0 {
		t.Fatal("invalid synthetic signing artifact")
	}
	return artifact.TBS.FullBytes
}

func recoveryArtifact(t *testing.T, der, rawSignature []byte, issuer *x509.Certificate, crl bool) []byte {
	t.Helper()
	if len(rawSignature) != 64 {
		t.Fatal("daemon did not release a P-256 signature")
	}
	var artifact struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &artifact); err != nil || len(rest) != 0 {
		t.Fatal("invalid synthetic artifact")
	}
	signature, err := asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(rawSignature[:32]), new(big.Int).SetBytes(rawSignature[32:])})
	if err != nil {
		t.Fatal(err)
	}
	artifact.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	encoded, err := asn1.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if crl {
		parsed, err := x509.ParseRevocationList(encoded)
		if err != nil || parsed.CheckSignatureFrom(issuer) != nil || len(parsed.RevokedCertificateEntries) != 1 || parsed.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(10)) != 0 {
			t.Fatal("token-signed CRL did not verify or preserve revocation")
		}
	} else {
		parsed, err := x509.ParseCertificate(encoded)
		if err != nil || parsed.CheckSignatureFrom(issuer) != nil || parsed.VerifyHostname("web.svc.poc.invalid") != nil {
			t.Fatal("token-signed leaf did not verify")
		}
	}
	return encoded
}

func recoveryRunTool(t *testing.T, environment []string, name string, arguments ...string) []byte {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Env = environment
	output, err := command.Output()
	if err != nil {
		// Neither argv nor output is printed: initialization argv contains a
		// disposable PIN and token tools may repeat their input on a failure.
		t.Fatal("disposable token provisioning failed", name)
	}
	return output
}

func recoveryToken(t *testing.T, directory string) ([]string, string, string, string, any) {
	t.Helper()
	// Never inherit a physical bench module override. This drill provisions
	// only SoftHSM, even when the caller has hardware-test variables set.
	module := ""
	for _, candidate := range []string{"/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so", "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"} {
		if _, err := os.Stat(candidate); err == nil {
			module = candidate
			break
		}
	}
	if module == "" {
		t.Fatal("mandatory SoftHSM module missing")
	}
	tokens := filepath.Join(directory, "tokens")
	if err := os.Mkdir(tokens, 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(directory, "softhsm2.conf")
	recoveryWrite(t, conf, []byte("directories.tokendir = "+tokens+"\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n"))
	environment := append(os.Environ(), "SOFTHSM2_CONF="+conf)
	credential := make([]byte, 16)
	if _, err := rand.Read(credential); err != nil {
		t.Fatal(err)
	}
	pin := hex.EncodeToString(credential)
	if _, err := rand.Read(credential); err != nil {
		t.Fatal(err)
	}
	soPIN := hex.EncodeToString(credential)
	clear(credential)
	recoveryRunTool(t, environment, "softhsm2-util", "--init-token", "--free", "--label", "synthetic-pki-recovery", "--so-pin", soPIN, "--pin", pin)
	base := []string{"--module", module, "--token-label", "synthetic-pki-recovery"}
	recoveryRunTool(t, append(environment, "REGALIA_RECOVERY_PIN="+pin), "pkcs11-tool", append(base, "--login", "--pin", "env:REGALIA_RECOVERY_PIN", "--keypairgen", "--key-type", "EC:prime256v1", "--usage-sign", "--label", "synthetic-ca", "--id", "01")...)
	publicPath := filepath.Join(directory, "token-public.der")
	recoveryRunTool(t, environment, "pkcs11-tool", append(base, "--read-object", "--type", "pubkey", "--id", "01", "--output-file", publicPath)...)
	if err := os.Chmod(publicPath, 0o600); err != nil {
		t.Fatal(err)
	}
	publicDER, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatal("token public key is not SPKI")
	}
	serial := ""
	for _, line := range strings.Split(string(recoveryRunTool(t, environment, "pkcs11-tool", append(base, "--list-slots")...)), "\n") {
		if before, after, found := strings.Cut(line, ":"); found && strings.TrimSpace(before) == "serial num" {
			serial = strings.TrimSpace(after)
			break
		}
	}
	if serial == "" {
		t.Fatal("disposable token serial unavailable")
	}
	pinPath := filepath.Join(directory, "token.pin")
	recoveryWrite(t, pinPath, []byte(pin))
	digest := sha256.Sum256(publicDER)
	return environment, module, serial, "sha256:" + hex.EncodeToString(digest[:]), public
}

func recoveryScenario(t *testing.T, outcome string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	environment, module, serial, keyPin, public := recoveryToken(t, directory)
	now := time.Now().UTC().Truncate(time.Second)
	roots, daemonCertificate, collectorCertificate, workloadCertificate := recoveryTLS(t, directory, now)
	standIn := recoveryKey(t)
	root := &x509.Certificate{SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "synthetic-offline-issuing-root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root = recoveryCertificate(t, root, root, standIn.Public(), standIn)
	issuer := recoveryCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: "synthetic-token-intermediate"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(40 * time.Minute), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"svc.poc.invalid"}}, root, public, standIn)
	leaf, lostLeaf, crl := recoveryInputs(t, issuer, standIn, now)
	collectorState := filepath.Join(directory, "collector-state")
	if err := os.Mkdir(collectorState, 0o700); err != nil {
		t.Fatal(err)
	}
	collectorAddress := recoveryAddress(t)
	collectorOrigin := "https://" + collectorAddress
	recoveryStart(t, os.Getenv("REGALIA_PKI_RECOVERY_COLLECTOR"), []string{"-state", collectorState, "-listen", collectorAddress, "-tls-cert", filepath.Join(directory, "collector.pem"), "-tls-key", filepath.Join(directory, "collector.key"), "-client-ca", filepath.Join(directory, "tls-root.pem")}, environment, filepath.Join(directory, "collector.log"))
	auditClient := recoveryClient(t, roots, daemonCertificate)
	recoveryReady(t, auditClient, collectorOrigin, true)
	barrier := &recoveryACKBarrier{held: make(chan audit.Event, 1), release: make(chan struct{}), client: auditClient, origin: collectorOrigin}
	proxy := httptest.NewUnstartedServer(barrier)
	proxy.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{collectorCertificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	proxy.StartTLS()
	t.Cleanup(proxy.Close)
	daemonAddress := recoveryAddress(t)
	daemonOrigin := "https://" + daemonAddress
	statePath, auditPath := filepath.Join(directory, "policy-state.jsonl"), filepath.Join(directory, "audit.jsonl")
	recoveryJSON(t, filepath.Join(directory, "secure-channel.json"), map[string]any{"schema_version": 1, "devices": []any{map[string]any{"device_serial": serial, "verified_by": "synthetic-e2e", "verified_at": now.Format(time.RFC3339), "expires_at": now.Add(time.Hour).Format(time.RFC3339), "firmware": "softhsm", "secure_messaging_established": true}}})
	recoveryJSON(t, filepath.Join(directory, "manifest.json"), map[string]any{"schema_version": 1, "manifest_id": "synthetic-recovery", "generated_at": now.Format(time.RFC3339), "objects": []any{map[string]any{"id": recoveryObject, "name": "Synthetic recovery CA", "kind": "asymmetric-key", "classification": "restricted", "environment": "development", "owner": "fixture", "purpose": recoveryPurpose, "custody": "direct-hardware", "algorithm": "p256", "operations": []string{"sign"}, "policy_id": "synthetic-recovery-policy", "bindings": []any{map[string]any{"site": recoverySite, "backend": "nitrokey-pkcs11", "device_id": "synthetic-softhsm", "device_serial": serial, "object_id": "01", "public_key_sha256": keyPin, "public_fingerprint": keyPin, "state": "active"}}, "recovery": map[string]any{}, "rotation": map[string]any{}, "migration": map[string]any{}, "verification": map[string]string{"status": "verified"}}}})
	recoveryJSON(t, filepath.Join(directory, "policy.json"), map[string]any{"schema_version": 1, "policies": []any{map[string]any{"id": "synthetic-recovery-policy", "object_id": recoveryObject, "purpose": recoveryPurpose, "environment": "development", "operation": "sign", "algorithm": "p256", "content_types": []string{"application/vnd.regalia.x509-tbs"}, "max_payload_bytes": 32 << 10, "max_future_seconds": 300, "x509": map[string]any{"id": recoveryProfile, "issuer_der": issuer.Raw, "dns_suffixes": []string{"svc.poc.invalid"}, "max_leaf_validity_seconds": 600, "max_crl_validity_seconds": 3600, "leaf_per_day": 2, "crl_per_day": 1}}}})
	recoveryJSON(t, filepath.Join(directory, "rbac.json"), map[string]any{"schema_version": 1, "principals": []any{map[string]any{"uri": recoveryPrincipal, "grants": []any{map[string]any{"objects": []string{recoveryObject}, "operations": []string{"sign"}, "environments": []string{"development"}}}}}})
	configPath := filepath.Join(directory, "config.json")
	recoveryJSON(t, configPath, map[string]any{"listen_address": daemonAddress, "site": recoverySite, "registry_path": filepath.Join(directory, "manifest.json"), "rbac_policy_path": filepath.Join(directory, "rbac.json"), "policy_path": filepath.Join(directory, "policy.json"), "policy_state_path": statePath, "tls_certificate_path": filepath.Join(directory, "daemon.pem"), "tls_private_key_path": filepath.Join(directory, "daemon.key"), "tls_client_ca_path": filepath.Join(directory, "tls-root.pem"), "pkcs11_module_path": module, "secure_channel_evidence_path": filepath.Join(directory, "secure-channel.json"), "pin_paths": map[string]string{"synthetic-softhsm": filepath.Join(directory, "token.pin")}, "audit_journal_path": auditPath, "audit_sink_url": proxy.URL, "runtime_admission": "disabled-for-lab"})
	daemon := recoveryStart(t, os.Getenv("REGALIA_PKI_RECOVERY_KMS"), []string{"-config", configPath}, environment, filepath.Join(directory, "daemon.log"))
	client := recoveryClient(t, roots, workloadCertificate)
	recoveryReady(t, client, daemonOrigin, false)
	baseline := recoverySign(client, daemonOrigin, recoveryTBS(t, leaf), "synthetic_nonce_baseline", "018f0000-0000-7000-8000-000000000001")
	if baseline.err != nil || baseline.status != http.StatusOK {
		t.Fatal("shipping daemon failed baseline token signing", baseline.status, baseline.code, baseline.err)
	}
	baselineArtifact := recoveryArtifact(t, leaf, baseline.result, issuer, false)
	recoveryWrite(t, filepath.Join(directory, "signed-leaf.der"), baselineArtifact)
	const pendingID = "018f0000-0000-7000-8000-000000000002"
	const pendingNonce = "synthetic_nonce_pending"
	lostTBS := recoveryTBS(t, lostLeaf)
	barrier.mu.Lock()
	barrier.request, barrier.outcome = pendingID, outcome
	barrier.mu.Unlock()
	pending := make(chan recoveryResponse, 1)
	go func() {
		pending <- recoverySign(client, daemonOrigin, lostTBS, pendingNonce, pendingID)
	}()
	var held audit.Event
	select {
	case held = <-barrier.held:
	case response := <-pending:
		t.Fatal("signing returned before the committed ACK barrier", response.status, response.code, response.err)
	case <-time.After(5 * time.Second):
		t.Fatal("shipping daemon did not reach the committed ACK barrier")
	}
	digest := sha256.Sum256(recoveryTBS(t, lostLeaf))
	if held.Outcome != outcome || held.X509ProfileID != recoveryProfile || held.PayloadDigest != "sha256:"+hex.EncodeToString(digest[:]) || held.ArtifactKind != "certificate" || held.KeyFingerprint != keyPin || held.ObjectID != recoveryObject || held.Purpose != recoveryPurpose {
		t.Fatal("held real collector ACK has unrelated signing intent")
	}
	summary, err := policy.VerifyState(statePath)
	if err != nil || summary.Reservations != 2 {
		t.Fatal("pending signing did not durably reserve its count", summary, err)
	}
	daemon.kill(t)
	close(barrier.release)
	select {
	case response := <-pending:
		if response.err == nil || len(response.result) != 0 {
			t.Fatal("SIGKILL released a pending signature")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("killed signing request remained pending")
	}
	// Identical files and token survive; this executes shipping startup preflight,
	// collector continuity reconciliation, state replay, and PKCS#11 readiness.
	recoveryStart(t, os.Getenv("REGALIA_PKI_RECOVERY_KMS"), []string{"-config", configPath}, environment, filepath.Join(directory, "daemon-restarted.log"))
	recoveryReady(t, client, daemonOrigin, false)
	recoveryRefusal(t, recoverySign(client, daemonOrigin, recoveryTBS(t, lostLeaf), pendingNonce, "018f0000-0000-7000-8000-000000000003"), http.StatusConflict, "CONFLICT")
	recoveryRefusal(t, recoverySign(client, daemonOrigin, recoveryTBS(t, lostLeaf), "synthetic_nonce_fresh", "018f0000-0000-7000-8000-000000000004"), http.StatusTooManyRequests, "RESOURCE_EXHAUSTED")
	reservedCRL := recoverySign(client, daemonOrigin, recoveryTBS(t, crl), "synthetic_nonce_crl_first", "018f0000-0000-7000-8000-000000000005")
	if reservedCRL.err != nil || reservedCRL.status != http.StatusOK {
		t.Fatal("retained leaf reservations blocked independent CRL capacity", reservedCRL.status, reservedCRL.code, reservedCRL.err)
	}
	crlArtifact := recoveryArtifact(t, crl, reservedCRL.result, issuer, true)
	recoveryWrite(t, filepath.Join(directory, "signed-crl.der"), crlArtifact)
	recoveryRefusal(t, recoverySign(client, daemonOrigin, recoveryTBS(t, crl), "synthetic_nonce_crl_fresh", "018f0000-0000-7000-8000-000000000006"), http.StatusTooManyRequests, "RESOURCE_EXHAUSTED")
	summary, err = policy.VerifyState(statePath)
	if err != nil || summary.Reservations != 3 {
		t.Fatal("restart reclaimed capacity or recorded denied reservations", summary, err)
	}
	events, err := audit.VerifyIntegrity(auditPath)
	if err != nil {
		t.Fatal("post-restart audit journal does not verify", err)
	}
	authorized, success := 0, 0
	for _, event := range events {
		if event.RequestID == pendingID {
			if event.X509ProfileID != held.X509ProfileID || event.PayloadDigest != held.PayloadDigest || event.ArtifactKind != held.ArtifactKind || event.KeyFingerprint != held.KeyFingerprint {
				t.Fatal("pending request audit lost its original signing intent")
			}
			if event.Outcome == "authorized" {
				authorized++
			}
			if event.Outcome == "success" {
				success++
			}
		}
	}
	expectedSuccess := 0
	if outcome == "success" {
		expectedSuccess = 1
	}
	if authorized != 1 || success != expectedSuccess {
		t.Fatal("restart fabricated or repeated pending signing outcomes", authorized, success)
	}
	// Independently obtain the committed stream head over authenticated mTLS.
	// A valid local hash chain alone is not collector provenance.
	sink, err := audit.NewHTTPSink(collectorOrigin, auditClient, time.Second, recoverySite)
	if err != nil {
		t.Fatal(err)
	}
	var head uint64
	var hash string
	// Denial audit ships asynchronously. Wait for the committed head rather
	// than assuming its ACK raced ahead of the final refusal response.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		head, hash, err = sink.CommittedHead(context.Background(), recoverySite)
		if err == nil && head == uint64(len(events)) && hash == events[len(events)-1].Hash {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || head != uint64(len(events)) || hash != events[len(events)-1].Hash {
		t.Fatal("authenticated collector head differs from durable daemon audit", head, err)
	}
	streams, err := filepath.Glob(filepath.Join(collectorState, "streams", "*", "*.jsonl"))
	if err != nil || len(streams) != 1 {
		t.Fatal("unexpected committed collector stream count")
	}
	committed, err := audit.Verify(streams[0])
	if err != nil || len(committed) != len(events) {
		t.Fatal("real collector stream does not verify or has duplicate replay events", err)
	}
	for i := range committed {
		if committed[i].Hash != events[i].Hash {
			t.Fatal("collector stream differs from daemon history")
		}
	}
	export, err := os.Open(streams[0])
	if err != nil {
		t.Fatal("open private collector export", err)
	}
	defer export.Close()
	report, err := audit.ReconcileX509(export, audit.X509ReconcileConfig{ExpectedSequence: head, ExpectedHash: hash, ProfileID: recoveryProfile, ObjectID: recoveryObject, Purpose: recoveryPurpose, KeyFingerprint: keyPin, IssuerDER: issuer.Raw}, [][]byte{baselineArtifact, crlArtifact})
	if err != nil || report.Status != "indeterminate" || report.MatchedArtifacts != 2 || report.IndeterminateRequests != 1 || report.Conflicts != 0 || report.UnattestedArtifacts != 0 {
		t.Fatal("real recovery evidence misclassified unavailable pending artifact", report, err)
	}
	t.Log("Actual daemon SIGKILL/restart retained two leaf reservations, refused replay and fresh exhausted issuance, preserved one bounded verifiable CRL signature, and reconciled the actual authenticated collector export: two artifacts matched, one pending request indeterminate; software token and test-only ACK proxy, lab admission disabled.")
}
