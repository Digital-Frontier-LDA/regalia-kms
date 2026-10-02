package integration_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

// A RELEASE SIGNED BY THE KMS, CHECKED BY GNUPG (regalia#530).
//
// adapters/gpgsign has its own tests, against a stand-in for the KMS that signs the way the token
// does. That stand-in is this repository's reading of the token. Here nothing stands in: the
// regalia-sign PROCESS, with its configuration and identity files on disk, reaches the daemon's real
// policy stack over mTLS, and the signature is computed by the concrete PKCS#11 driver on a key
// generated inside the (software) token — CKM_ECDSA on P-384, CKM_RSA_PKCS on RSA-3072. GnuPG, with
// nothing but the exported public key, then says whether it is a signature.
//
// The arms after the happy path each break one thing and say where the refusal must come from:
// the policy (and the audit journal records the denial), the client's pinned key (the token signed,
// and the signature is still never written), or TLS (the daemon records nothing).
func TestDeployedRegaliaSignExecutableThroughMTLS(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("requires the SoftHSM E2E environment")
	}
	gpg := requireGPG(t)
	binary := buildRegaliaSign(t)
	pki := newSidecarPKI(t)
	daemon := newReleaseSigningDaemon(t, modulePath, serial, pki)

	for _, key := range []struct{ name, objectID, tokenID string }{
		{"P-384", "release-signing-p384", "0b"},
		{"RSA-3072", "release-signing-rsa", "0c"},
		// Ed25519: neither HSM has it through OpenSC, so this run is what SoftHSM can show — the
		// daemon's CKM_EDDSA path and regalia-sign's sign-twice path (adapters/gpgsign/eddsa.go)
		// meeting on a real PKCS#11 module, judged by GnuPG.
		{"Ed25519", "release-signing-ed25519", "0f"},
	} {
		t.Run(key.name, func(t *testing.T) {
			deployment := t.TempDir()
			config := writeSignDeployment(t, deployment, signConfig{
				kmsURL: daemon.server.URL, serverName: "kms.e2e.internal", ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
				objectID: key.objectID, purpose: "release-artifact", publicKey: tokenPublicKeyPEM(t, modulePath, key.tokenID),
			})
			baseline := len(daemon.sink.snapshot())

			fingerprint := strings.TrimSpace(regaliaSign(t, binary, config, "--fingerprint"))
			if len(fingerprint) != 40 || len(daemon.sink.snapshot()) != baseline {
				t.Fatalf("--fingerprint gave %q and reached the daemon %d times", fingerprint, len(daemon.sink.snapshot())-baseline)
			}
			exported := regaliaSign(t, binary, config, "--export-key")
			sums := filepath.Join(deployment, "SHA256SUMS")
			if err := os.WriteFile(sums, []byte("9f2c…  regalia-kms_1.0.0_linux_amd64.tar.gz\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			regaliaSign(t, binary, config, "--detach", sums)

			home := importIntoThrowawayGnuPG(t, gpg, exported, fingerprint)
			output, err := exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--verify", sums+".asc", sums).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "[GNUPG:] VALIDSIG "+fingerprint) {
				t.Fatalf("GnuPG does not accept the KMS-made signature: %v\n%s", err, output)
			}
			if err := os.WriteFile(sums, []byte("9f2c…  regalia-kms_1.0.1_linux_amd64.tar.gz\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--verify", sums+".asc", sums).CombinedOutput(); err == nil || !strings.Contains(string(output), "[GNUPG:] BADSIG") {
				t.Fatalf("GnuPG accepted the signature over a changed file: %v\n%s", err, output)
			}

			// A cleartext signature, the form an apt repository serves as InRelease: GnuPG accepts
			// it and gives back the text that was signed.
			release := filepath.Join(deployment, "Release")
			releaseText := "Origin: Regalia\nSuite: stable\nSHA256:\n e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 Packages\n"
			if err := os.WriteFile(release, []byte(releaseText), 0o644); err != nil {
				t.Fatal(err)
			}
			inRelease, extracted := filepath.Join(deployment, "InRelease"), filepath.Join(deployment, "Release.extracted")
			regaliaSign(t, binary, config, "--clearsign", release, "--output", inRelease)
			output, err = exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--output", extracted, "--decrypt", inRelease).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "[GNUPG:] VALIDSIG "+fingerprint) {
				t.Fatalf("GnuPG does not accept the KMS-made cleartext signature: %v\n%s", err, output)
			}
			if text, err := os.ReadFile(extracted); err != nil || string(text) != releaseText {
				t.Fatalf("GnuPG extracted a different text (%v): %q", err, text)
			}

			// Three operations reached the token — the key certification, the detached signature
			// and the cleartext one — and each is an authorized/success pair in the audit journal,
			// for this object and nothing else.
			events := daemon.sink.snapshot()[baseline:]
			if len(events) != 6 {
				t.Fatalf("expected 6 audit events for 3 signatures, got %d: %#v", len(events), events)
			}
			for index, event := range events {
				wantOutcome := []string{"authorized", "success"}[index%2]
				if event.Operation != "sign" || event.ObjectID != key.objectID || event.Outcome != wantOutcome {
					t.Fatalf("audit event %d is %s/%s/%s, want sign/%s/%s", index, event.Operation, event.ObjectID, event.Outcome, key.objectID, wantOutcome)
				}
			}
		})
	}

	p384Public := tokenPublicKeyPEM(t, modulePath, "0b")
	good := signConfig{
		kmsURL: daemon.server.URL, serverName: "kms.e2e.internal", ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
		objectID: "release-signing-p384", purpose: "release-artifact", publicKey: p384Public,
	}
	// refused runs --detach from a deployment that must not produce a signature, and returns what
	// the tool said and how many audit events the attempt left.
	refused := func(t *testing.T, cfg signConfig) (string, []audit.Event) {
		t.Helper()
		deployment := t.TempDir()
		config := writeSignDeployment(t, deployment, cfg)
		sums := filepath.Join(deployment, "SHA256SUMS")
		if err := os.WriteFile(sums, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		baseline := len(daemon.sink.snapshot())
		command := exec.Command(binary, "--config", config, "--detach", sums)
		output, err := command.CombinedOutput()
		if err == nil {
			t.Fatalf("regalia-sign succeeded from a deployment that must be refused:\n%s", output)
		}
		if _, statErr := os.Stat(sums + ".asc"); statErr == nil {
			t.Fatal("a signature file was written by a refused run")
		}
		return string(output), daemon.sink.snapshot()[baseline:]
	}

	t.Run("a purpose the policy does not allow is denied by the daemon and audited", func(t *testing.T) {
		cfg := good
		cfg.purpose = "container-image"
		output, events := refused(t, cfg)
		if !strings.Contains(output, "DENIED") {
			t.Fatalf("the tool did not report the KMS's refusal: %q", output)
		}
		if len(events) != 1 || events[0].Decision != "deny" {
			t.Fatalf("expected exactly one deny event, got %#v", events)
		}
	})

	t.Run("an object this identity is not granted is denied before the token", func(t *testing.T) {
		cfg := good
		cfg.objectID = "release-signing-ungranted"
		output, events := refused(t, cfg)
		if !strings.Contains(output, "DENIED") {
			t.Fatalf("the tool did not report the KMS's refusal: %q", output)
		}
		for _, event := range events {
			if event.Decision != "deny" {
				t.Fatalf("an ungranted object produced a non-deny event: %#v", event)
			}
		}
	})

	t.Run("a pinned key the object does not hold: the token signs, and no signature is written", func(t *testing.T) {
		cfg := good
		cfg.objectID = "release-signing-p384b" // a second P-384 key on the token, same policy shape
		output, events := refused(t, cfg)
		if !strings.Contains(output, "pinned public key does not verify") {
			t.Fatalf("the refusal is not the pinned-key check: %q", output)
		}
		// The daemon did its job — this object, this policy, a real signature. The refusal is the
		// client's, and it is the only thing between a registry mistake and a release signed by the
		// wrong key.
		if len(events) != 2 || events[1].Outcome != "success" {
			t.Fatalf("expected the daemon to have signed (2 events), got %#v", events)
		}
	})

	for name, edit := range map[string]func(*signConfig){
		"a server name that is not the server's": func(cfg *signConfig) { cfg.serverName = "not-the-kms.internal" },
		"a CA that did not issue the server":     func(cfg *signConfig) { cfg.ca = pki.otherCAPEM },
		"an expired workload certificate": func(cfg *signConfig) {
			cfg.certificate, cfg.privateKey = pki.expiredClientPEM, pki.expiredClientKeyPEM
		},
		"a wrong-purpose workload certificate": func(cfg *signConfig) {
			cfg.certificate, cfg.privateKey = pki.serverCertificatePEM, pki.serverCertificateKeyPEM
		},
	} {
		t.Run(name+" is refused before any policy decision", func(t *testing.T) {
			cfg := good
			edit(&cfg)
			if _, events := refused(t, cfg); len(events) != 0 {
				t.Fatalf("the refusal reached the daemon's policy: %#v", events)
			}
		})
	}

	t.Run("an expired server certificate is refused", func(t *testing.T) {
		expired := httptest.NewUnstartedServer(daemon.handler)
		expired.TLS = serverTLSFor(t, pki.expiredServerCertificate, pki.caPool)
		expired.StartTLS()
		defer expired.Close()
		cfg := good
		cfg.kmsURL = expired.URL
		if _, events := refused(t, cfg); len(events) != 0 {
			t.Fatalf("the refusal reached the daemon's policy: %#v", events)
		}
	})
}

// requireGPG returns gpg's path, or skips — unless REGALIA_EXPECT_GPG says this job installed it, in
// which case its absence is a FAILURE. Same contract as requireSOPS313.
func requireGPG(t *testing.T) string {
	t.Helper()
	expect := false
	if raw := os.Getenv("REGALIA_EXPECT_GPG"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("REGALIA_EXPECT_GPG=%q is not a boolean (%v)", raw, err)
		}
		expect = parsed
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		if expect {
			t.Fatalf("REGALIA_EXPECT_GPG is set, but gpg is not on PATH: %v", err)
		}
		t.Skipf("gpg is not on PATH: %v", err)
	}
	return gpg
}

// buildRegaliaSign compiles the deployable binary from the adapter module: the artifact a release
// job runs, not the adapter linked into this test.
func buildRegaliaSign(t *testing.T) string {
	t.Helper()
	source, err := filepath.Abs(filepath.Join("..", "..", "adapters", "gpgsign", "cmd", "regalia-sign"))
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "regalia-sign")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = source
	build.Env = append(os.Environ(), "GOWORK=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build regalia-sign: %v\n%s", err, output)
	}
	return binary
}

func regaliaSign(t *testing.T, binary, config string, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	command := exec.Command(binary, append([]string{"--config", config}, args...)...)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("regalia-sign %v: %v\n%s", args, err, stderr.String())
	}
	return stdout.String()
}

// tokenPublicKeyPEM reads a public key off the token, as an operator does when the release key is
// generated: this is the value regalia-sign pins.
func tokenPublicKeyPEM(t *testing.T, modulePath, id string) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "public.der")
	// The SoftHSM battery's token is regalia-kms-e2e. A run on a real token names its own label.
	label := os.Getenv("REGALIA_PKCS11_E2E_TOKEN_LABEL")
	if label == "" {
		label = "regalia-kms-e2e"
	}
	if output, err := exec.Command("pkcs11-tool", "--module", modulePath, "--token-label", label,
		"--read-object", "--type", "pubkey", "--id", id, "--output-file", path).CombinedOutput(); err != nil {
		t.Fatalf("read public key %s off the token: %v\n%s", id, err, output)
	}
	der, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// pkcs11-tool writes an RSA or EC public key as DER and an Ed25519 one already as PEM.
	if block, _ := pem.Decode(der); block != nil && block.Type == "PUBLIC KEY" {
		der = block.Bytes
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Fatalf("public key %s is not PKIX: %v", id, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func importIntoThrowawayGnuPG(t *testing.T, gpg, exportedKey, fingerprint string) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "rgl-sign-e2e-") // short: gpg-agent's socket must fit a unix socket path
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	})
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--import")
	command.Stdin = strings.NewReader(exportedKey)
	output, err := command.CombinedOutput()
	// GnuPG computes the fingerprint itself from the key packet. That it is the one regalia-sign
	// printed is the check that both mean the same key.
	if err != nil || !strings.Contains(string(output), "IMPORT_OK 1 "+fingerprint) {
		t.Fatalf("GnuPG did not import the exported key under fingerprint %s: %v\n%s", fingerprint, err, output)
	}
	return home
}

type signConfig struct {
	kmsURL, serverName          string
	ca, certificate, privateKey []byte
	objectID, purpose           string
	publicKey                   []byte
}

func writeSignDeployment(t *testing.T, directory string, cfg signConfig) string {
	t.Helper()
	write := func(name string, contents []byte, mode os.FileMode) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, contents, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil { // WriteFile's mode is subject to the umask
			t.Fatal(err)
		}
		return path
	}
	config := fmt.Sprintf(`{
		"kms_url": %q, "server_name": %q, "ca_path": %q, "certificate_path": %q, "private_key_path": %q, "timeout": "15s",
		"object_id": %q, "environment": "development", "purpose": %q,
		"public_key_path": %q, "key_created": %q, "user_id": "Regalia Release Signing (e2e) <releases@example.invalid>"
	}`, strings.TrimSuffix(cfg.kmsURL, "/"), cfg.serverName,
		write("kms-ca.pem", cfg.ca, 0o644), write("workload.pem", cfg.certificate, 0o644), write("workload-key.pem", cfg.privateKey, 0o600),
		cfg.objectID, cfg.purpose, write("release-key.pub.pem", cfg.publicKey, 0o644),
		// A day old: GnuPG refuses a key, or a signature, dated after its own clock.
		time.Now().UTC().Add(-24*time.Hour).Format("2006-01-02T15:04:05Z"))
	return write("config.json", []byte(config), 0o600)
}

// newReleaseSigningDaemon is the daemon half: the concrete SoftHSM provider behind the registry,
// RBAC, one sign policy per release object, the audit journal, and a real TLS 1.3 mTLS endpoint.
// The workload identity is the one newSidecarPKI issues.
func newReleaseSigningDaemon(t *testing.T, modulePath, serial string, pki *sidecarPKI) *sopsDaemon {
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
	// Three granted objects and one that is registered but granted to nobody. The DigestInfo an RSA
	// key signs is 19 bytes of prefix and a 32-byte SHA-256 digest; a P-384 key signs a 48-byte
	// SHA-384 digest. Each policy allows exactly that and nothing longer.
	objects := []struct {
		id, algorithm, tokenID string
		payload                int64
	}{
		{"release-signing-p384", "p384", "0b", 48},
		{"release-signing-rsa", "rsa3072", "0c", 51},
		{"release-signing-ed25519", "ed25519", "0f", 32},
		{"release-signing-p384b", "p384", "0d", 48},
		{"release-signing-ungranted", "p384", "0e", 48},
	}
	var manifestObjects, granted []string
	var policies []policy.Policy
	for _, object := range objects {
		manifestObjects = append(manifestObjects, fmt.Sprintf(`{"id":%q,"name":"Release signing E2E","kind":"asymmetric-key","classification":"restricted","environment":"development","owner":"security","purpose":"release-artifact","custody":"direct-hardware","algorithm":%q,"operations":["sign"],"policy_id":%q,"bindings":[{"site":"e2e-site","backend":"nitrokey-pkcs11","device_id":"hsm-e2e","device_serial":%q,"devaut_fingerprint":%q,"object_id":%q,"public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active"}],"recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}`,
			object.id, object.algorithm, object.id+"-policy", serial, devAuth, object.tokenID))
		if object.id != "release-signing-ungranted" {
			granted = append(granted, strconv.Quote(object.id))
		}
		policies = append(policies, policy.Policy{
			ID: object.id + "-policy", ObjectID: object.id, Purpose: "release-artifact", Environment: "development",
			Operation: "sign", Algorithm: object.algorithm, ContentTypes: []string{"application/vnd.regalia.digest"},
			MaxPayloadBytes: object.payload, MaxFuture: 2 * time.Minute,
		})
	}
	manifest := fmt.Sprintf(`{"schema_version":1,"manifest_id":"release-e2e","generated_at":"2026-10-02T00:00:00Z","objects":[%s]}`, strings.Join(manifestObjects, ","))
	router, err := registry.Load(bytes.NewBufferString(manifest), "e2e-site", hardware)
	if err != nil {
		t.Fatal(err)
	}
	rbac, err := auth.LoadPolicy(bytes.NewBufferString(fmt.Sprintf(`{"schema_version":1,"principals":[{"uri":%q,"grants":[{"objects":[%s],"operations":["sign"],"environments":["development"]}]}]}`, principal, strings.Join(granted, ","))))
	if err != nil {
		t.Fatal(err)
	}
	state, err := policy.OpenFileState(filepath.Join(t.TempDir(), "policy.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	engine, err := policy.New(policies, state, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sink := &synchronizedAuditSink{}
	recorder, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	coordinator, err := operations.New(rbac, router, engine, recorder, executor.New(1, 10*time.Second), hardware, "sha256:release-e2e", nil, time.Now)
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
