package integration_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/operations"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE DEPLOYED EXECUTABLE, NOT THE ADAPTER-AS-LIBRARY (#426).
//
// TestSOPSCLIThroughMTLSPolicyAuditAndConcretePKCS11 proves the protocol halves against a
// ServeUnix goroutine — the adapter linked into the test binary. The deployable path is a
// different thing: the regalia-sops-kms PROCESS, launched with -config the way
// deploy/systemd launches it, loading its own identity files, refusing its own
// misconfigurations. This test builds that binary and drives the whole chain — SOPS CLI,
// Unix socket, executable, mTLS, daemon policy stack, concrete SoftHSM backend — plus the
// failure arms the deployment actually meets: a missing identity half, a hostname that is
// not the server's, an untrusting CA, an expired certificate on either end, and a
// wrong-purpose certificate. Every refusal arm also asserts the daemon's audit journal
// saw nothing: refused before any hardware call, not refused by it.
func TestDeployedSOPSSidecarExecutableThroughMTLS(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	sops, lookErr := exec.LookPath("sops")
	if modulePath == "" || serial == "" || lookErr != nil {
		t.Skip("requires the SoftHSM E2E environment and SOPS 3.13.x")
	}
	version, err := exec.Command(sops, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "sops 3.13.") {
		t.Skipf("requires SOPS 3.13.x: %s", version)
	}

	binary := buildSidecarExecutable(t)
	pki := newSidecarPKI(t)
	daemon := newSOPSE2EDaemon(t, modulePath, serial, pki)

	// The happy path: the exact deployment shape — config file, identity files on disk,
	// executable process, SOPS CLI over the socket.
	// Two directories, deliberately: the SIDECAR's (config, identity files, socket — the
	// only files it could ever write) and SOPS's own working files. The nothing-persisted
	// scan below covers the sidecar's directory alone, so a plaintext file SOPS itself
	// wrote cannot both be the input and the finding.
	deployment := shortDeploymentDir(t)
	work := t.TempDir()
	goodConfig := writeSidecarDeployment(t, deployment, sidecarConfig{
		kmsURL: daemon.server.URL, serverName: "kms.e2e.internal",
		ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
	})
	sidecar := launchSidecar(t, binary, goodConfig, filepath.Join(deployment, "sops.sock"))
	socket := "unix://" + filepath.Join(deployment, "sops.sock")
	plain := filepath.Join(work, "plain.yaml")
	if err := os.WriteFile(plain, []byte("secret: executable-e2e-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	encryptedPath := filepath.Join(work, "secrets.enc.yaml")
	encryptOutput, err := exec.Command(sops, "--encrypt", "--enable-local-keyservice=false", "--keyservice", socket,
		"--kms", "arn:aws:kms:regalia:000000000000:key/production-sops",
		"--encryption-context", "repository:regalia-kms/regalia,path:fixtures/secrets.enc.yaml,environment:development,purpose:sops-data-key",
		plain).CombinedOutput()
	if err != nil {
		t.Fatalf("SOPS encrypt through the deployed executable: %v\n%s", err, encryptOutput)
	}
	if err := os.WriteFile(encryptedPath, encryptOutput, 0o600); err != nil {
		t.Fatal(err)
	}
	decrypted, err := exec.Command(sops, "--decrypt", "--enable-local-keyservice=false", "--keyservice", socket, encryptedPath).CombinedOutput()
	if err != nil || string(decrypted) != "secret: executable-e2e-only\n" {
		t.Fatalf("SOPS decrypt through the deployed executable: %v output=%q", err, decrypted)
	}
	sidecar.stop(t)

	events := daemon.sink.snapshot()
	if len(events) != 4 || events[0].Operation != "wrap" || events[1].Outcome != "success" || events[2].Operation != "unwrap" || events[3].Outcome != "success" {
		t.Fatalf("the deployed round trip did not produce the correlated wrap/unwrap pairs: %#v", events)
	}

	// NOTHING PERSISTED (#426 AC3). The sidecar's own directory may hold exactly what the
	// deployment provisioned (config, identity files, socket) — the plaintext document,
	// the unwrapped data key, and any additional private-key material must not appear in
	// any file the sidecar could have written. The plaintext lives in the files SOPS
	// itself wrote (plain.yaml and, encrypted, secrets.enc.yaml) — which is why the scan
	// covers the SIDECAR's directory only.
	provisioned := map[string]bool{
		"config.json": true, "kms-ca.pem": true, "workload.pem": true, "workload-key.pem": true,
	}
	for _, entry := range sidecarArtifacts(t, deployment) {
		if !provisioned[filepath.Base(entry)] {
			t.Fatalf("%s is a file the deployment did not provision — the sidecar wrote state of its own", entry)
		}
		contents, readErr := os.ReadFile(entry)
		if readErr != nil {
			t.Fatalf("scan the sidecar directory: %v", readErr)
		}
		if bytes.Contains(contents, []byte("executable-e2e-only")) {
			t.Fatalf("%s contains the plaintext document — the sidecar persisted secret material", entry)
		}
		if block, _ := pem.Decode(contents); block != nil && block.Type == "PRIVATE KEY" && entry != filepath.Join(deployment, "workload-key.pem") {
			t.Fatalf("%s holds private-key material beyond the provisioned workload key", entry)
		}
	}

	// The refusal arms. Each one runs the same deployment shape with one field broken,
	// requires SOPS to fail, and requires the audit journal to be UNCHANGED — the refusal
	// happened in TLS or in the sidecar's own configuration loading, before any policy
	// decision or hardware call. That is the "before any hardware call" of #426's
	// acceptance criteria, made observable.
	baseline := len(daemon.sink.snapshot())

	t.Run("a missing private key half refuses to start and creates no socket", func(t *testing.T) {
		dir := shortDeploymentDir(t)
		config := writeSidecarDeployment(t, dir, sidecarConfig{
			kmsURL: daemon.server.URL, serverName: "kms.e2e.internal",
			ca: pki.caPEM, certificate: pki.clientPEM, privateKey: []byte("placeholder"),
		})
		// The identity half is removed AFTER writing, so the config itself is well-formed
		// and the refusal is specifically the missing file.
		if err := os.Remove(filepath.Join(dir, "workload-key.pem")); err != nil {
			t.Fatal(err)
		}
		output, err := runSidecarToCompletion(t, binary, config)
		if err == nil {
			t.Fatalf("the sidecar started with half an identity:\n%s", output)
		}
		// The process-level refusal is DELIBERATELY opaque ("errors return no data or
		// backend detail" is the adapter's stated policy; the stage that refused is
		// observable only in-process, which guard_coverage_test.go pins). What the
		// deployment can rely on is: non-zero exit, the one fixed line, and no socket.
		if !strings.Contains(output, "regalia SOPS sidecar unavailable") || strings.Contains(output, "workload identity") {
			t.Fatalf("the refusal leaked or lost its fixed shape: %q", output)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "sops.sock")); statErr == nil {
			t.Fatal("the sidecar created a socket while refusing its own configuration")
		}
	})

	refusedOverTheWire := func(t *testing.T, configPath, socketDir string) {
		t.Helper()
		sidecar := launchSidecar(t, binary, configPath, filepath.Join(socketDir, "sops.sock"))
		defer sidecar.stop(t)
		if output, err := exec.Command(sops, "--encrypt", "--enable-local-keyservice=false", "--keyservice", "unix://"+filepath.Join(socketDir, "sops.sock"),
			"--kms", "arn:aws:kms:regalia:000000000000:key/production-sops",
			"--encryption-context", "repository:regalia-kms/regalia,path:fixtures/secrets.enc.yaml,environment:development,purpose:sops-data-key",
			plain).CombinedOutput(); err == nil {
			t.Fatalf("SOPS succeeded through a deployment that must be refused:\n%s", output)
		}
		if got := len(daemon.sink.snapshot()); got != baseline {
			t.Fatalf("the refusal reached the daemon: %d audit events were recorded (baseline %d) — the deployment was refused by policy or hardware, not before it", got, baseline)
		}
	}

	t.Run("a server name that is not the server's is refused", func(t *testing.T) {
		dir := shortDeploymentDir(t)
		config := writeSidecarDeployment(t, dir, sidecarConfig{
			kmsURL: daemon.server.URL, serverName: "not-the-kms.internal",
			ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
		})
		refusedOverTheWire(t, config, dir)
	})

	t.Run("a CA that did not issue the server is refused", func(t *testing.T) {
		dir := shortDeploymentDir(t)
		config := writeSidecarDeployment(t, dir, sidecarConfig{
			kmsURL: daemon.server.URL, serverName: "kms.e2e.internal",
			ca: pki.otherCAPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
		})
		refusedOverTheWire(t, config, dir)
	})

	t.Run("an expired server certificate is refused", func(t *testing.T) {
		dir := shortDeploymentDir(t)
		expired := httptest.NewUnstartedServer(daemon.handler)
		expired.TLS = serverTLSFor(t, pki.expiredServerCertificate, pki.caPool)
		expired.StartTLS()
		defer expired.Close()
		config := writeSidecarDeployment(t, dir, sidecarConfig{
			kmsURL: expired.URL, serverName: "kms.e2e.internal",
			ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
		})
		refusedOverTheWire(t, config, dir)
	})

	t.Run("a wrong-purpose workload certificate is refused", func(t *testing.T) {
		dir := shortDeploymentDir(t)
		config := writeSidecarDeployment(t, dir, sidecarConfig{
			kmsURL: daemon.server.URL, serverName: "kms.e2e.internal",
			ca: pki.caPEM, certificate: pki.serverCertificatePEM, privateKey: pki.serverCertificateKeyPEM,
		})
		refusedOverTheWire(t, config, dir)
	})

	t.Run("an expired workload certificate is refused", func(t *testing.T) {
		dir := shortDeploymentDir(t)
		config := writeSidecarDeployment(t, dir, sidecarConfig{
			kmsURL: daemon.server.URL, serverName: "kms.e2e.internal",
			ca: pki.caPEM, certificate: pki.expiredClientPEM, privateKey: pki.expiredClientKeyPEM,
		})
		refusedOverTheWire(t, config, dir)
	})
}

// buildSidecarExecutable compiles the deployable binary from the adapter module. The E2E
// exists to prove THAT artifact; linking the adapter into the test binary would prove a
// different one (and is already covered by TestSOPSCLIThroughMTLSPolicyAuditAndConcretePKCS11).
func buildSidecarExecutable(t *testing.T) string {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "..", "kms", "adapters", "sops", "cmd", "regalia-sops-kms"))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "regalia-sops-kms")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = source
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the deployable sidecar: %v\n%s", err, output)
	}
	return binary
}

type sidecarConfig struct {
	kmsURL      string
	serverName  string
	ca          []byte
	certificate []byte
	privateKey  []byte
}

// writeSidecarDeployment materialises the deployment shape: one strict config file plus
// the identity files, with the modes the sidecar's own protected-file reader demands
// (nothing group- or other-writable; the private key readable by its owner alone).
func writeSidecarDeployment(t *testing.T, directory string, cfg sidecarConfig) string {
	t.Helper()
	caPath := filepath.Join(directory, "kms-ca.pem")
	certificatePath := filepath.Join(directory, "workload.pem")
	keyPath := filepath.Join(directory, "workload-key.pem")
	for path, contents := range map[string][]byte{caPath: cfg.ca, certificatePath: cfg.certificate} {
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(keyPath, cfg.privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`{
		"socket_path": %q,
		"kms_url": %q,
		"server_name": %q,
		"ca_path": %q,
		"certificate_path": %q,
		"private_key_path": %q,
		"timeout": "15s"
	}`, filepath.Join(directory, "sops.sock"), strings.TrimSuffix(cfg.kmsURL, "/"), cfg.serverName, caPath, certificatePath, keyPath)
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

// shortDeploymentDir is a SHORT directory for deployments whose socket path must fit a
// unix socket (darwin caps the path at 104 bytes; t.TempDir() embeds the test name and
// overflows that cap, and net.Listen then fails before anything observable happens — the
// trap cmd/regalia-sops-kms/startup_test.go documents).
func shortDeploymentDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "rgl-sops-exec-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

// sidecarProcess owns exactly ONE Wait: the goroutine started at launch. A second Wait
// from the stopping side is a data race on os/exec.Cmd's internal state (found by -race,
// not by reading), so stopping signals and then takes the goroutine's answer.
type sidecarProcess struct {
	command *exec.Cmd
	exited  <-chan error
}

func (process *sidecarProcess) stop(t *testing.T) {
	t.Helper()
	if err := process.command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	_ = <-process.exited
}

func launchSidecar(t *testing.T, binary, configPath, socketPath string) *sidecarProcess {
	t.Helper()
	command := exec.Command(binary, "-config", configPath)
	command.Dir = filepath.Dir(socketPath) // the deployment's WorkingDirectory; anything written to a relative path lands where the scan looks
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	waitForSocket(t, socketPath, exited)
	return &sidecarProcess{command: command, exited: exited}
}

func runSidecarToCompletion(t *testing.T, binary, configPath string) (string, error) {
	t.Helper()
	output, err := exec.Command(binary, "-config", configPath).CombinedOutput()
	return string(output), err
}

// sidecarArtifacts lists the regular files in the sidecar's directory.
func sidecarArtifacts(t *testing.T, directory string) []string {
	t.Helper()
	var paths []string
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			paths = append(paths, filepath.Join(directory, entry.Name()))
		}
	}
	return paths
}

// sopsDaemon is the in-process daemon half shared by both SOPS E2E tests: concrete
// SoftHSM provider behind the registry, RBAC, wrap/unwrap policy, audit journal, and a
// real TLS 1.3 mTLS endpoint whose client root is the test CA. handler is exposed so a
// variant endpoint (an expired certificate) can serve the same policy stack.
type sopsDaemon struct {
	server  *httptest.Server
	handler http.Handler
	sink    *synchronizedAuditSink
	// clientCertificate and roots are the matching workload identity for the daemon's
	// test CA, so a test driving the adapter in-process uses the same trust chain the
	// deployed sidecar's failure arms vary.
	clientCertificate tls.Certificate
	roots             *x509.CertPool
}

func newSOPSE2EDaemon(t *testing.T, modulePath, serial string, pki *sidecarPKI) *sopsDaemon {
	t.Helper()
	principal := "spiffe://regalia/workload/sops-e2e"
	devAuth := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	driver, err := nitrokey.NewPKCS11Driver(modulePath, devAuthProbe(devAuth), secureChannel{}, retryProbe(3))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Close() })
	provider, err := nitrokey.New(driver, pinSource{value: e2ePKCS11PIN(t)})
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider})
	if err != nil {
		t.Fatal(err)
	}
	manifest := fmt.Sprintf(`{"schema_version":1,"manifest_id":"sops-e2e","generated_at":"2026-09-04T12:00:00Z","objects":[{"id":"production-sops","name":"SOPS E2E","kind":"symmetric-key","classification":"restricted","environment":"development","owner":"security","purpose":"sops-data-key","custody":"direct-hardware","algorithm":"rsa2048","operations":["wrap","unwrap"],"policy_id":"sops-policy","bindings":[{"site":"e2e-site","backend":"nitrokey-pkcs11","device_id":"hsm-e2e","device_serial":%q,"devaut_fingerprint":%q,"object_id":"02","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active"}],"recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}]}`, serial, devAuth)
	router, err := registry.Load(bytes.NewBufferString(manifest), "e2e-site", hardware)
	if err != nil {
		t.Fatal(err)
	}
	rbac, err := auth.LoadPolicy(bytes.NewBufferString(fmt.Sprintf(`{"schema_version":1,"principals":[{"uri":%q,"grants":[{"objects":["production-sops"],"operations":["wrap","unwrap"],"environments":["development"]}]}]}`, principal)))
	if err != nil {
		t.Fatal(err)
	}
	state, err := policy.OpenFileState(filepath.Join(t.TempDir(), "policy.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	basePolicy := policy.Policy{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "development", Algorithm: "rsa2048", ContentTypes: []string{"application/vnd.regalia.data-key"}, MaxPayloadBytes: 4096, MaxFuture: 2 * time.Minute}
	wrapPolicy, unwrapPolicy := basePolicy, basePolicy
	wrapPolicy.ID, wrapPolicy.Operation = "sops-wrap", "wrap"
	unwrapPolicy.ID, unwrapPolicy.Operation = "sops-unwrap", "unwrap"
	engine, err := policy.New([]policy.Policy{wrapPolicy, unwrapPolicy}, state, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sink := &synchronizedAuditSink{}
	recorder, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	coordinator, err := operations.New(rbac, router, engine, recorder, executor.New(1, 10*time.Second), hardware, "sha256:sops-e2e", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(api.NewHandler(coordinator))

	tlsConfig, err := auth.ServerTLSConfig(pki.serverCertificate, pki.caPool)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	return &sopsDaemon{server: server, handler: handler, sink: sink, clientCertificate: pki.clientPair, roots: pki.caPool}
}

func serverTLSFor(t *testing.T, certificate tls.Certificate, clientRoots *x509.CertPool) *tls.Config {
	t.Helper()
	config, err := auth.ServerTLSConfig(certificate, clientRoots)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// newSidecarPKI issues the certificate zoo the failure arms need: the good workload
// client, an unrelated CA, an expired server certificate, a server-purpose certificate
// posing as a workload identity, and an expired client certificate — all from the one
// test CA except the unrelated one, which is the point of it.
type sidecarPKI struct {
	caPEM      []byte
	otherCAPEM []byte
	caPool     *x509.CertPool
	// serverCertificate is the daemon's GOOD endpoint certificate (kms.e2e.internal):
	// one CA runs through the whole test, so every arm varies exactly one thing.
	serverCertificate tls.Certificate
	clientPair        tls.Certificate

	clientPEM, clientKeyPEM []byte

	expiredServerCertificate tls.Certificate

	// A certificate carrying the workload URI but the SERVER purpose (ServerAuth EKU,
	// no ClientAuth): chain-valid, identity-shaped, purpose-wrong. Presented as the
	// workload identity it is refused by the purpose check alone — a no-URI certificate
	// would also be refused by the URI-count guard, and the arm would pass for a reason
	// that has nothing to do with purpose.
	serverCertificatePEM, serverCertificateKeyPEM []byte

	expiredClientPEM, expiredClientKeyPEM []byte
}

func newSidecarPKI(t *testing.T) *sidecarPKI {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sidecar-e2e-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "unrelated-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, otherPublic, otherPrivate)
	if err != nil {
		t.Fatal(err)
	}

	identity, _ := url.Parse("spiffe://regalia/workload/sops-e2e")
	serialCounter := int64(10)
	issue := func(asServer, expired, withIdentity bool, dnsName string) (tls.Certificate, []byte, []byte) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serialCounter++
		notAfter := now.Add(time.Hour)
		if expired {
			notAfter = now.Add(-time.Minute)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serialCounter), NotBefore: now.Add(-time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
		if asServer {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			if dnsName != "" {
				template.Subject = pkix.Name{CommonName: dnsName}
				template.DNSNames = []string{dnsName}
			}
			if withIdentity {
				// The purpose-wrong workload shape: the URI is present, only the
				// EXTENDED KEY USAGE is wrong for a client.
				template.URIs = []*url.URL{identity}
			}
		} else {
			template.URIs = []*url.URL{identity}
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certPEM, keyPEM
	}
	clientPair, clientPEM, clientKeyPEM := issue(false, false, false, "")
	goodServer, _, _ := issue(true, false, false, "kms.e2e.internal")
	expiredServer, _, _ := issue(true, true, false, "kms.e2e.internal")
	_, serverPEM, serverKeyPEM := issue(true, false, true, "")
	_, expiredClientPEM, expiredClientKeyPEM := issue(false, true, false, "")

	caPool := x509.NewCertPool()
	caPool.AddCert(ca)
	return &sidecarPKI{
		caPEM:             pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		otherCAPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}),
		caPool:            caPool,
		serverCertificate: goodServer,
		clientPair:        clientPair,
		clientPEM:         clientPEM, clientKeyPEM: clientKeyPEM,
		expiredServerCertificate: expiredServer,
		serverCertificatePEM:     serverPEM, serverCertificateKeyPEM: serverKeyPEM,
		expiredClientPEM: expiredClientPEM, expiredClientKeyPEM: expiredClientKeyPEM,
	}
}
