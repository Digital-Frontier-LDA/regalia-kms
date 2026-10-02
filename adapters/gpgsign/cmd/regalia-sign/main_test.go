package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign"
)

// A signature dated after GnuPG's own clock is refused, so the tool's clock in these tests is the
// real one, and the key is a day old.
var keyCreated = time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Second)

const testUserID = "Regalia Release Signing (test) <releases@example.invalid>"

// deployment is the shape regalia-sign runs in: a configuration file, the pinned public key, a
// workload identity on disk, and a KMS that demands that identity over TLS 1.3.
type deployment struct {
	t          *testing.T
	directory  string
	configPath string
	server     *httptest.Server
	key        crypto.Signer // *ecdsa.PrivateKey (P-384) or ed25519.PrivateKey

	mu       sync.Mutex
	requests int
	refuse   string // when set, the KMS answers with this error code
	// approver, when set, is the one key whose approval this KMS's policy requires: a request
	// without that key's signature over its own binding is DENIED, as the daemon would deny it.
	approver ed25519.PublicKey
}

const releaseApprover = "spiffe://regalia/approver/release"

// approved verifies the evidence the way internal/approval does: against the binding of the request
// that actually arrived, never against anything the evidence says about itself.
func (d *deployment) approved(header, objectID, purpose, environment, nonce, expiresAt string, payload []byte) bool {
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return false
	}
	var approvals []gpgsign.Approval
	if json.Unmarshal(decoded, &approvals) != nil {
		return false
	}
	digest := sha256.Sum256(payload)
	binding, err := gpgsign.Pending{Version: 1, ObjectID: objectID, Purpose: purpose, Environment: environment, Nonce: nonce,
		ExpiresAt: expiresAt, Created: "2026-01-01T00:00:00Z", PayloadSHA256: hex.EncodeToString(digest[:])}.Binding()
	if err != nil {
		return false
	}
	for _, approval := range approvals {
		signature, err := base64.StdEncoding.DecodeString(approval.Signature)
		if err == nil && approval.ApproverID == releaseApprover && ed25519.Verify(d.approver, binding, signature) {
			return true
		}
	}
	return false
}

func newDeployment(t *testing.T) *deployment {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newDeploymentFor(t, key)
}

// newEd25519Deployment is the same deployment around an Ed25519 release key.
func newEd25519Deployment(t *testing.T) *deployment {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return newDeploymentFor(t, key)
}

func newDeploymentFor(t *testing.T, key crypto.Signer) *deployment {
	t.Helper()
	result := &deployment{t: t, directory: t.TempDir(), key: key}
	caPEM, caPool, issue := testCA(t)
	serverPair, _, _ := issue(true)
	_, clientPEM, clientKeyPEM := issue(false)

	result.server = httptest.NewUnstartedServer(http.HandlerFunc(result.serve))
	result.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverPair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caPool}
	result.server.StartTLS()
	t.Cleanup(result.server.Close)

	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	result.write("kms-ca.pem", caPEM, 0o644)
	result.write("workload.pem", clientPEM, 0o644)
	result.write("workload-key.pem", clientKeyPEM, 0o600)
	result.write("release-key.pub.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	result.configPath = result.writeConfig(nil)
	return result
}

func (d *deployment) write(name string, contents []byte, mode os.FileMode) string {
	d.t.Helper()
	path := filepath.Join(d.directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		d.t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // WriteFile's mode is subject to the umask
		d.t.Fatal(err)
	}
	return path
}

// writeConfig writes a configuration, with edit applied to the default document first.
func (d *deployment) writeConfig(edit func(map[string]any)) string {
	d.t.Helper()
	document := map[string]any{
		"kms_url": d.server.URL, "server_name": "kms.test.internal",
		"ca_path": filepath.Join(d.directory, "kms-ca.pem"), "certificate_path": filepath.Join(d.directory, "workload.pem"),
		"private_key_path": filepath.Join(d.directory, "workload-key.pem"), "timeout": "10s",
		"object_id": "release-signing-key", "environment": "staging", "purpose": "release-artifact",
		"public_key_path": filepath.Join(d.directory, "release-key.pub.pem"),
		"key_created":     keyCreated.Format("2006-01-02T15:04:05Z"), "user_id": testUserID,
	}
	if edit != nil {
		edit(document)
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		d.t.Fatal(err)
	}
	return d.write("config.json", encoded, 0o600)
}

func (d *deployment) serve(writer http.ResponseWriter, request *http.Request) {
	d.mu.Lock()
	d.requests++
	refuse := d.refuse
	d.mu.Unlock()
	var document struct {
		ObjectID string `json:"object_id"`
		Payload  string `json:"payload_base64"`
		Context  struct {
			Environment string `json:"environment"`
			Purpose     string `json:"purpose"`
			ExpiresAt   string `json:"expires_at"`
			Nonce       string `json:"nonce"`
		} `json:"context"`
	}
	_ = json.NewDecoder(request.Body).Decode(&document)
	writer.Header().Set("Content-Type", "application/json")
	if d.approver != nil && refuse == "" {
		payload, _ := base64.StdEncoding.DecodeString(document.Payload)
		if !d.approved(request.Header.Get("X-Verified-Approvals"), document.ObjectID, document.Context.Purpose, document.Context.Environment,
			document.Context.Nonce, document.Context.ExpiresAt, payload) {
			refuse = "DENIED"
		}
	}
	if refuse != "" {
		writer.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(writer).Encode(map[string]any{"request_id": request.Header.Get("X-Request-ID"), "code": refuse, "message": "request failed", "retryable": false})
		return
	}
	digest, _ := base64.StdEncoding.DecodeString(document.Payload)
	var signature []byte
	switch key := d.key.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			d.t.Fatal(err)
		}
		signature = append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...)
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, digest) // CKM_EDDSA: the digest is the message
	}
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"request_id": request.Header.Get("X-Request-ID"), "operation_id": "op-1", "object_id": document.ObjectID,
		"content_type": "application/vnd.regalia.digest", "result_base64": base64.StdEncoding.EncodeToString(signature),
	})
}

func (d *deployment) seen() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.requests
}

// invoke runs the tool in-process and returns its exit code, stdout and stderr.
func (d *deployment) invoke(stdin string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	getenv := func(name string) string {
		if name == "REGALIA_SIGN_CONFIG" {
			return d.configPath
		}
		return ""
	}
	code := run(args, strings.NewReader(stdin), &stdout, &stderr, getenv, time.Now)
	return code, stdout.String(), stderr.String()
}

func testCA(t *testing.T) ([]byte, *x509.CertPool, func(server bool) (tls.Certificate, []byte, []byte)) {
	t.Helper()
	now := time.Now()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "regalia-sign-test-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	serial := int64(10)
	issue := func(server bool) (tls.Certificate, []byte, []byte) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		serial++
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if server {
			template.DNSNames, template.ExtKeyUsage = []string{"kms.test.internal"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
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
		certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
		pair, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return pair, certificatePEM, keyPEM
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pool, issue
}

// requireTool returns a program's path, or skips — unless REGALIA_EXPECT_GPG says this job installed
// GnuPG and git, in which case absence is a FAILURE (the same contract as REGALIA_EXPECT_SOPS).
func requireTool(t *testing.T, name string) string {
	t.Helper()
	expect := false
	if raw := os.Getenv("REGALIA_EXPECT_GPG"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("REGALIA_EXPECT_GPG=%q is not a boolean (%v)", raw, err)
		}
		expect = parsed
	}
	path, err := exec.LookPath(name)
	if err != nil {
		if expect {
			t.Fatalf("REGALIA_EXPECT_GPG is set, but %s is not on PATH: %v", name, err)
		}
		t.Skipf("%s is not on PATH: %v", name, err)
	}
	return path
}

// gnupgHome is a throwaway GnuPG home holding only the exported public key.
func gnupgHome(t *testing.T, gpg, exportedKey string) string {
	t.Helper()
	home, err := os.MkdirTemp("/tmp", "rgl-sign-") // short: gpg-agent's socket must fit a unix socket path
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
	command := exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--import")
	command.Stdin = strings.NewReader(exportedKey)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("gpg --import: %v\n%s", err, output)
	}
	return home
}

func TestDetachWritesASignatureGnuPGAccepts(t *testing.T) {
	d := newDeployment(t)
	code, fingerprint, stderr := d.invoke("", "--fingerprint")
	fingerprint = strings.TrimSpace(fingerprint)
	if code != 0 || len(fingerprint) != 40 || d.seen() != 0 {
		t.Fatalf("--fingerprint: exit %d, %q, %d KMS requests; stderr %q", code, fingerprint, d.seen(), stderr)
	}
	code, exported, stderr := d.invoke("", "--export-key")
	if code != 0 || !strings.HasPrefix(exported, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatalf("--export-key: exit %d, stderr %q", code, stderr)
	}

	sums := d.write("SHA256SUMS", []byte("0f3a…  regalia-kms_1.0.0_linux_amd64.tar.gz\n"), 0o644)
	if code, stdout, stderr := d.invoke("", "--detach", sums); code != 0 || stdout != "" {
		t.Fatalf("--detach: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	signature, err := os.ReadFile(sums + ".asc")
	if err != nil || !bytes.HasPrefix(signature, []byte("-----BEGIN PGP SIGNATURE-----")) {
		t.Fatalf("no armored signature beside the file: %v", err)
	}

	gpg := requireTool(t, "gpg")
	home := gnupgHome(t, gpg, exported)
	output, err := exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--verify", sums+".asc", sums).CombinedOutput()
	if err != nil || !strings.Contains(string(output), "[GNUPG:] VALIDSIG "+fingerprint) {
		t.Fatalf("gpg --verify: %v\n%s", err, output)
	}

	// An existing signature is never replaced.
	if code, _, stderr := d.invoke("", "--detach", sums); code == 0 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("a second --detach replaced the signature: exit %d, stderr %q", code, stderr)
	}
	if after, _ := os.ReadFile(sums + ".asc"); !bytes.Equal(after, signature) {
		t.Fatal("the existing signature file changed")
	}

	// --binary writes .sig; --output names the file; "-" reads stdin and writes stdout.
	if code, _, stderr := d.invoke("", "--detach", sums, "--binary"); code != 0 {
		t.Fatalf("--binary: exit %d, stderr %q", code, stderr)
	}
	if binary, err := os.ReadFile(sums + ".sig"); err != nil || bytes.HasPrefix(binary, []byte("-----")) || len(binary) == 0 {
		t.Fatalf("--binary did not write an unarmored signature: %v", err)
	}
	elsewhere := filepath.Join(d.directory, "elsewhere.asc")
	if code, _, stderr := d.invoke("", "--detach", sums, "--output", elsewhere); code != 0 {
		t.Fatalf("--output: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := d.invoke("from stdin", "--detach", "-"); code != 0 || !strings.HasPrefix(stdout, "-----BEGIN PGP SIGNATURE-----") {
		t.Fatalf("--detach -: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestTheGitFormSignsStdinAndReportsOnTheStatusDescriptor(t *testing.T) {
	d := newDeployment(t)
	_, fingerprint, _ := d.invoke("", "--fingerprint")
	fingerprint = strings.TrimSpace(fingerprint)

	code, stdout, stderr := d.invoke("tree 4b825d…\nauthor A <a@example.invalid> 0 +0000\n\nmessage\n", "--status-fd=2", "-bsau", fingerprint)
	if code != 0 || !strings.HasPrefix(stdout, "-----BEGIN PGP SIGNATURE-----") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	// git accepts the signature only if the status output contains "\n[GNUPG:] SIG_CREATED ".
	if !strings.Contains(stderr, "\n[GNUPG:] SIG_CREATED D 19 9 00 ") || !strings.HasSuffix(strings.TrimSpace(stderr), fingerprint) {
		t.Fatalf("the status lines are not what git looks for: %q", stderr)
	}

	// A key that is not the configured one is refused before the KMS is asked for anything.
	before := d.seen()
	code, stdout, stderr = d.invoke("payload", "--status-fd=2", "-bsau", "0123456789ABCDEF0123456789ABCDEF01234567")
	if code == 0 || stdout != "" || strings.Contains(stderr, "SIG_CREATED") || d.seen() != before {
		t.Fatalf("signed for a key that was not asked for: exit %d, stdout %q, stderr %q, %d new KMS requests", code, stdout, stderr, d.seen()-before)
	}
	// The user ID selects it too, as with gpg.
	if code, _, stderr := d.invoke("payload", "--status-fd=2", "-bsau", "releases@example.invalid"); code != 0 {
		t.Fatalf("the key's own address did not select it: exit %d, stderr %q", code, stderr)
	}
}

// THE REAL THING: git itself, with the built binary as gpg.program, makes a signed commit and a
// signed tag, and git's own verification — which runs GnuPG through that same binary — accepts both.
func TestGitSignsAndVerifiesACommitAndATagThroughTheBinary(t *testing.T) {
	for name, deploy := range map[string]func(*testing.T) *deployment{"P-384": newDeployment, "Ed25519": newEd25519Deployment} {
		t.Run(name, func(t *testing.T) { gitSignsAndVerifies(t, deploy(t)) })
	}
}

func gitSignsAndVerifies(t *testing.T, d *deployment) {
	git, gpg := requireTool(t, "git"), requireTool(t, "gpg")
	binary := filepath.Join(t.TempDir(), "regalia-sign")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build regalia-sign: %v\n%s", err, output)
	}
	tool := func(args ...string) string {
		command := exec.Command(binary, args...)
		command.Env = append(os.Environ(), "REGALIA_SIGN_CONFIG="+d.configPath)
		output, err := command.Output()
		if err != nil {
			t.Fatalf("regalia-sign %v: %v", args, err)
		}
		return string(output)
	}
	fingerprint := strings.TrimSpace(tool("--fingerprint"))
	home := gnupgHome(t, gpg, tool("--export-key"))

	repository := t.TempDir()
	run := func(args ...string) (string, error) {
		command := exec.Command(git, args...)
		command.Dir = repository
		command.Env = append(os.Environ(), "REGALIA_SIGN_CONFIG="+d.configPath, "GNUPGHOME="+home, "REGALIA_SIGN_GPG="+gpg,
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			"GIT_AUTHOR_NAME=Release", "GIT_AUTHOR_EMAIL=releases@example.invalid", "GIT_COMMITTER_NAME=Release", "GIT_COMMITTER_EMAIL=releases@example.invalid")
		output, err := command.CombinedOutput()
		return string(output), err
	}
	must := func(args ...string) string {
		t.Helper()
		output, err := run(args...)
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
		return output
	}
	must("init", "--quiet", "--initial-branch=main")
	must("config", "gpg.program", binary)
	must("config", "user.signingkey", fingerprint)
	if err := os.WriteFile(filepath.Join(repository, "VERSION"), []byte("1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	must("add", "VERSION")
	must("commit", "--quiet", "-S", "-m", "release 1.0.0")
	must("tag", "-s", "v1.0.0", "-m", "release 1.0.0")

	if output := must("verify-commit", "--raw", "HEAD"); !strings.Contains(output, "[GNUPG:] VALIDSIG "+fingerprint) {
		t.Fatalf("git verify-commit did not report a valid signature by %s:\n%s", fingerprint, output)
	}
	if output := must("verify-tag", "--raw", "v1.0.0"); !strings.Contains(output, "[GNUPG:] VALIDSIG "+fingerprint) {
		t.Fatalf("git verify-tag did not report a valid signature by %s:\n%s", fingerprint, output)
	}

	// The negative control: when the KMS refuses, git makes no commit.
	d.mu.Lock()
	d.refuse = "DENIED"
	d.mu.Unlock()
	if err := os.WriteFile(filepath.Join(repository, "VERSION"), []byte("1.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	must("add", "VERSION")
	if output, err := run("commit", "--quiet", "-S", "-m", "release 1.0.1"); err == nil || !strings.Contains(output, "DENIED") {
		t.Fatalf("git committed although the KMS refused to sign: %v\n%s", err, output)
	}
	if head := must("log", "--format=%s", "-1"); strings.TrimSpace(head) != "release 1.0.0" {
		t.Fatalf("HEAD moved to %q after a refused signature", head)
	}
}

// The output appears under its final name whole or not at all, and never over an existing file.
func TestInstallNewIsAtomicAndNeverReplaces(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "InRelease")
	leftovers := func() []string {
		entries, err := os.ReadDir(directory)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, entry := range entries {
			if entry.Name() != "InRelease" {
				names = append(names, entry.Name())
			}
		}
		return names
	}
	if err := installNew(destination, "first\n"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("the installed file is %v (%v), want mode 0644", info, err)
	}
	if err := installNew(destination, "second\n"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("an existing file was not refused: %v", err)
	}
	if contents, _ := os.ReadFile(destination); string(contents) != "first\n" {
		t.Fatalf("the existing file was changed to %q", contents)
	}
	// A dangling symbolic link at the name is an existing name too: nothing is written through it.
	link := filepath.Join(directory, "dangling")
	if err := os.Symlink(filepath.Join(directory, "elsewhere"), link); err != nil {
		t.Fatal(err)
	}
	if err := installNew(link, "through the link\n"); err == nil {
		t.Fatal("a symbolic link at the destination was written through")
	}
	if _, err := os.Stat(filepath.Join(directory, "elsewhere")); err == nil {
		t.Fatal("the link's target was created")
	}
	if err := installNew(filepath.Join(directory, "no-such-directory", "InRelease"), "x"); err == nil {
		t.Fatal("a destination in a missing directory was accepted")
	}
	if names := leftovers(); len(names) != 1 || names[0] != "dangling" {
		t.Fatalf("temporary files were left behind: %v", names)
	}
}

func TestAKMSRefusalWritesNoSignatureAndNamesTheCode(t *testing.T) {
	d := newDeployment(t)
	d.refuse = "DENIED"
	sums := d.write("SHA256SUMS", []byte("x\n"), 0o644)
	code, stdout, stderr := d.invoke("", "--detach", sums)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "DENIED") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, err := os.Stat(sums + ".asc"); err == nil {
		t.Fatal("a signature file exists after the KMS refused")
	}
}

// Every one of these is a deployment that must not sign. Each is refused before the KMS receives a
// request, so the refusal is this tool's own and not the policy's.
func TestAnUnsafeOrWrongDeploymentIsRefusedBeforeTheKMSIsAsked(t *testing.T) {
	cases := map[string]func(d *deployment){
		"a configuration others can write": func(d *deployment) {
			if err := os.Chmod(d.configPath, 0o666); err != nil {
				d.t.Fatal(err)
			}
		},
		"a workload key others can read": func(d *deployment) {
			if err := os.Chmod(filepath.Join(d.directory, "workload-key.pem"), 0o644); err != nil {
				d.t.Fatal(err)
			}
		},
		"a pinned public key others can write": func(d *deployment) {
			if err := os.Chmod(filepath.Join(d.directory, "release-key.pub.pem"), 0o666); err != nil {
				d.t.Fatal(err)
			}
		},
		"a pinned public key reached through a symbolic link": func(d *deployment) {
			real := filepath.Join(d.directory, "release-key.pub.pem")
			link := filepath.Join(d.directory, "link.pem")
			if err := os.Symlink(real, link); err != nil {
				d.t.Fatal(err)
			}
			d.configPath = d.writeConfig(func(document map[string]any) { document["public_key_path"] = link })
		},
		"a private key where the public key should be": func(d *deployment) {
			// Built here rather than written out as a literal: a PEM private-key header in a source
			// file is what a secret scanner exists to find.
			d.write("release-key.pub.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a key")}), 0o644)
		},
		"an unknown configuration field": func(d *deployment) {
			d.configPath = d.writeConfig(func(document map[string]any) { document["slot"] = 2 })
		},
		"a relative path": func(d *deployment) {
			d.configPath = d.writeConfig(func(document map[string]any) { document["ca_path"] = "kms-ca.pem" })
		},
		"a plain-HTTP KMS": func(d *deployment) {
			d.configPath = d.writeConfig(func(document map[string]any) {
				document["kms_url"] = strings.Replace(d.server.URL, "https://", "http://", 1)
			})
		},
		"a creation time that is not exact": func(d *deployment) {
			d.configPath = d.writeConfig(func(document map[string]any) { document["key_created"] = "2026-10-02" })
		},
		"a server name that is not the server's": func(d *deployment) {
			d.configPath = d.writeConfig(func(document map[string]any) { document["server_name"] = "not-the-kms.internal" })
		},
		"a CA that did not issue the server": func(d *deployment) {
			otherCA, _, _ := testCA(d.t)
			d.write("kms-ca.pem", otherCA, 0o644)
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			d := newDeployment(t)
			breakIt(d)
			sums := d.write("SHA256SUMS", []byte("x\n"), 0o644)
			code, stdout, stderr := d.invoke("", "--detach", sums)
			if code == 0 || stdout != "" {
				t.Fatalf("signed from a deployment that must be refused: exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if _, err := os.Stat(sums + ".asc"); err == nil {
				t.Fatal("a signature file was written")
			}
			if d.seen() != 0 {
				t.Fatalf("the KMS received %d requests from a refused deployment", d.seen())
			}
			// A refusal says what is wrong without quoting key material or a certificate.
			if strings.Contains(stderr, "BEGIN") || len(stderr) > 400 {
				t.Fatalf("the refusal is not one short line: %q", stderr)
			}
		})
	}
}

func TestTheCommandLineIsStrict(t *testing.T) {
	good := [][]string{
		{"--detach", "f"}, {"--detach=f", "--output", "o"}, {"--detach", "f", "--binary"}, {"--export-key"}, {"--fingerprint"},
		{"--config", "c", "--fingerprint"}, {"--status-fd=2", "-bsau", "KEY"}, {"-b", "-s", "-a", "-u", "KEY"},
		{"--detach-sign", "--sign", "--armor", "--local-user", "KEY", "--status-fd", "2"}, {"--verify", "sig", "-"},
		{"--keyid-format=long", "--status-fd=1", "--verify", "sig", "-"},
		{"--prepare", "p", "--detach", "f"}, {"--prepare=p", "--valid-for", "5m", "--clearsign", "f"}, {"--prepare", "p", "--export-key"},
		{"--complete", "p", "--approval", "a", "--detach", "f", "--binary"}, {"--complete", "p", "--approval", "a", "--approval", "b", "--clearsign", "f", "--output", "o"},
		{"--complete", "p", "--approval", "a", "--export-key", "--output", "o"},
	}
	for _, args := range good {
		if _, err := parse(args); err != nil {
			t.Errorf("%v refused: %v", args, err)
		}
	}
	bad := [][]string{
		{}, {"--detach"}, {"--detach", "f", "--export-key"}, {"--output", "o"}, {"--binary", "--fingerprint"},
		{"--frobnicate"}, {"file"}, {"-bsa"}, {"-bsua", "KEY"}, {"-bsx", "KEY"}, {"-sau", "KEY"}, {"-bsu", "KEY"},
		{"--status-fd=3", "-bsau", "KEY"}, {"--status-fd=2"}, {"--clearsign"}, {"-bsau"},
		{"--prepare", "p"}, {"--prepare", "p", "--fingerprint"}, {"--prepare", "p", "--complete", "p", "--approval", "a", "--detach", "f"},
		{"--complete", "p", "--detach", "f"}, {"--approval", "a", "--detach", "f"}, {"--valid-for", "5m", "--detach", "f"},
		{"--prepare", "p", "--detach", "f", "--output", "o"}, {"--prepare", "p", "--status-fd=2", "-bsau", "KEY"},
		{"--complete", "p", "--approval", "a"}, {"--export-key", "--output", "o"},
		// An empty value is not an absent option: these would otherwise be the one-step command.
		{"--prepare=", "--detach", "f"}, {"--prepare", "", "--detach", "f"}, {"--complete=", "--detach", "f"}, {"--detach="}, {"--detach", "f", "--output="},
	}
	for _, args := range bad {
		if _, err := parse(args); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	if code, _, stderr := (&deployment{t: t}).invoke("", "--frobnicate"); code != 2 || !strings.Contains(stderr, "usage:") {
		t.Errorf("an unknown option: exit %d, stderr %q", code, stderr)
	}
}

func TestClearsignWritesADocumentBesideTheFileAndNeverABinaryOne(t *testing.T) {
	d := newDeployment(t)
	release := d.write("Release", []byte("Origin: Regalia\nSuite: stable\n"), 0o644)
	if code, stdout, stderr := d.invoke("", "--clearsign", release); code != 0 || stdout != "" {
		t.Fatalf("--clearsign: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	signed, err := os.ReadFile(release + ".asc")
	if err != nil || !bytes.HasPrefix(signed, []byte("-----BEGIN PGP SIGNED MESSAGE-----\n")) || !bytes.Contains(signed, []byte("\nOrigin: Regalia\nSuite: stable\n-----BEGIN PGP SIGNATURE-----\n")) {
		t.Fatalf("no cleartext-signed document beside the file (%v):\n%s", err, signed)
	}
	if code, _, stderr := d.invoke("", "--clearsign", release); code == 0 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("a second --clearsign replaced the document: exit %d, stderr %q", code, stderr)
	}
	inRelease := filepath.Join(d.directory, "InRelease")
	if code, _, stderr := d.invoke("", "--clearsign", release, "--output", inRelease); code != 0 {
		t.Fatalf("--output: exit %d, stderr %q", code, stderr)
	}
	if code, stdout, stderr := d.invoke("Origin: stdin\n", "--clearsign", "-"); code != 0 || !strings.HasPrefix(stdout, "-----BEGIN PGP SIGNED MESSAGE-----") {
		t.Fatalf("--clearsign -: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	before := d.seen()
	for _, args := range [][]string{{"--clearsign", release, "--binary"}, {"--clearsign", release, "--detach", release}} {
		if code, _, _ := d.invoke("", args...); code != 2 || d.seen() != before {
			t.Fatalf("%v: exit %d, %d KMS requests", args, code, d.seen()-before)
		}
	}
}

// THE REAL CONSUMER: apt itself. A flat repository whose InRelease regalia-sign made is accepted by
// `apt-get update` with the exported key as its only trust anchor, and refused once one byte of the
// signed Release text changes. Whatever verifier this apt uses (gpgv before 3.0, sqv after) is the
// one that decides, with apt's own policy on top.
func TestAptAcceptsARepositoryWhoseInReleaseWasSignedThroughTheKMS(t *testing.T) {
	for name, deploy := range map[string]func(*testing.T) *deployment{"P-384": newDeployment, "Ed25519": newEd25519Deployment} {
		t.Run(name, func(t *testing.T) { aptAcceptsTheRepository(t, deploy(t)) })
	}
}

func aptAcceptsTheRepository(t *testing.T, d *deployment) {
	apt, err := exec.LookPath("apt-get")
	if err != nil {
		t.Skip("apt-get is not on PATH: this is not a Debian or Ubuntu system")
	}
	_, exported, stderr := d.invoke("", "--export-key")
	if !strings.HasPrefix(exported, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Fatalf("--export-key: %q", stderr)
	}
	// apt drops privileges to _apt when run as root and must be able to read everything, so the
	// repository lives in a world-readable directory rather than under t.TempDir() (0700 parents).
	root, err := os.MkdirTemp("/tmp", "rgl-apt-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	repository, state := filepath.Join(root, "repo"), filepath.Join(root, "apt")
	for _, directory := range []string{repository, filepath.Join(state, "lists", "partial"), filepath.Join(state, "cache", "archives", "partial")} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	packages := "Package: regalia-example\nVersion: 1.0.0\nArchitecture: all\nMaintainer: Releases <releases@example.invalid>\nFilename: ./regalia-example_1.0.0_all.deb\nSize: 1\nSHA256: 0000000000000000000000000000000000000000000000000000000000000000\nDescription: an example\n\n"
	write(filepath.Join(repository, "Packages"), packages)
	sum := sha256.Sum256([]byte(packages))
	release := fmt.Sprintf("Origin: Regalia\nLabel: Regalia\nSuite: stable\nDate: %s\nSHA256:\n %x %d Packages\n",
		time.Now().UTC().Add(-time.Hour).Format("Mon, 02 Jan 2006 15:04:05 UTC"), sum, len(packages))
	releasePath, inRelease := filepath.Join(repository, "Release"), filepath.Join(repository, "InRelease")
	write(releasePath, release)
	if code, _, stderr := d.invoke("", "--clearsign", releasePath, "--output", inRelease); code != 0 {
		t.Fatalf("--clearsign: exit %d, stderr %q", code, stderr)
	}
	if err := os.Remove(releasePath); err != nil { // only InRelease is served: apt must rely on it
		t.Fatal(err)
	}
	key := filepath.Join(root, "regalia-release.asc")
	write(key, exported)
	sources := filepath.Join(root, "sources.list")
	write(sources, fmt.Sprintf("deb [signed-by=%s] file:%s ./\n", key, repository))
	write(filepath.Join(state, "status"), "")

	update := func() (string, error) {
		// No list from an earlier run may answer for this one.
		_ = os.RemoveAll(filepath.Join(state, "lists"))
		if err := os.MkdirAll(filepath.Join(state, "lists", "partial"), 0o755); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(apt, "update",
			"-o", "Dir::Etc::sourcelist="+sources, "-o", "Dir::Etc::sourceparts=/dev/null",
			"-o", "Dir::Etc::trusted=/dev/null", "-o", "Dir::Etc::trustedparts=/dev/null",
			"-o", "Dir::State::lists="+filepath.Join(state, "lists"), "-o", "Dir::State::status="+filepath.Join(state, "status"),
			"-o", "Dir::Cache="+filepath.Join(state, "cache"), "-o", "Debug::NoLocking=1",
			"-o", "APT::Sandbox::User=", "-o", "APT::Update::Error-Mode=any",
			"-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false")
		command.Env = append(os.Environ(), "LC_ALL=C")
		output, err := command.CombinedOutput()
		return string(output), err
	}

	output, err := update()
	if err != nil {
		t.Fatalf("apt-get update refused the repository: %v\n%s", err, output)
	}
	listed, _ := filepath.Glob(filepath.Join(state, "lists", "*Packages*"))
	if len(listed) == 0 {
		t.Fatalf("apt-get update exited 0 but fetched no Packages index, so it verified nothing:\n%s", output)
	}

	// The control. One changed byte in the signed text, same signature.
	signed, err := os.ReadFile(inRelease)
	if err != nil {
		t.Fatal(err)
	}
	write(inRelease, strings.Replace(string(signed), "Suite: stable", "Suite: sid   ", 1))
	if output, err := update(); err == nil {
		t.Fatalf("apt-get update accepted an InRelease whose text was changed after signing:\n%s", output)
	}
	// And with no key at all the untouched repository is refused too: it was the signature, checked
	// against THIS key, that admitted it.
	write(inRelease, string(signed))
	write(key, "")
	if output, err := update(); err == nil {
		t.Fatalf("apt-get update accepted the repository with an empty keyring:\n%s", output)
	}
}

// UNDER A POLICY THAT REQUIRES APPROVAL the one-step commands are denied, and the two-step form
// produces the same kind of signature: --prepare contacts nobody, the approver signs the record, and
// --complete sends exactly the prepared request. GnuPG judges the result.
func TestPrepareThenCompleteSignsUnderAnApprovalPolicy(t *testing.T) {
	for name, build := range map[string]func(*testing.T) *deployment{"P-384": newDeployment, "Ed25519": newEd25519Deployment} {
		t.Run(name, func(t *testing.T) {
			d := build(t)
			approverPublic, approverPrivate, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			d.approver = approverPublic
			sums := d.write("SHA256SUMS", []byte("0f3a…  regalia-kms_1.0.0_linux_amd64.tar.gz\n"), 0o644)

			// One step: denied, and nothing is written.
			if code, _, stderr := d.invoke("", "--detach", sums); code != 1 || !strings.Contains(stderr, "DENIED") {
				t.Fatalf("an unapproved signature: exit %d, stderr %q", code, stderr)
			}
			if _, err := os.Stat(sums + ".asc"); !os.IsNotExist(err) {
				t.Fatal("a denied request left a signature")
			}

			approve := func(pendingPath string) string {
				t.Helper()
				record, err := os.ReadFile(pendingPath)
				if err != nil {
					t.Fatal(err)
				}
				pending, err := gpgsign.ReadPending(record)
				if err != nil {
					t.Fatal(err)
				}
				approval, err := gpgsign.Approve(pending, releaseApprover, approverPrivate, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				encoded, _ := json.Marshal(approval)
				return d.write(filepath.Base(pendingPath)+".approval", encoded, 0o644)
			}

			// The key export is a signature too (the self-certification), so it takes the same path.
			before := d.seen()
			keyPending := filepath.Join(d.directory, "key.pending")
			if code, _, stderr := d.invoke("", "--prepare", keyPending, "--export-key"); code != 0 || d.seen() != before {
				t.Fatalf("--prepare --export-key: exit %d, %d KMS requests, stderr %q", code, d.seen()-before, stderr)
			}
			code, exported, stderr := d.invoke("", "--complete", keyPending, "--approval", approve(keyPending), "--export-key")
			if code != 0 || !strings.HasPrefix(exported, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
				t.Fatalf("--complete --export-key: exit %d, stderr %q", code, stderr)
			}

			before = d.seen()
			pendingPath := filepath.Join(d.directory, "SHA256SUMS.pending")
			code, stdout, stderr := d.invoke("", "--prepare", pendingPath, "--detach", sums)
			contents, _ := os.ReadFile(sums)
			fileHash := sha256.Sum256(contents)
			if code != 0 || d.seen() != before || !strings.Contains(stdout, "prepared, not signed") || !strings.Contains(stdout, hex.EncodeToString(fileHash[:])) {
				t.Fatalf("--prepare: exit %d, %d KMS requests, stdout %q, stderr %q", code, d.seen()-before, stdout, stderr)
			}
			if _, err := os.Stat(sums + ".asc"); !os.IsNotExist(err) {
				t.Fatal("--prepare wrote a signature")
			}
			// A record is never replaced: preparing twice to one name would leave an approver unsure
			// which request they are approving.
			if code, _, _ := d.invoke("", "--prepare", pendingPath, "--detach", sums); code != 1 {
				t.Fatal("--prepare replaced an existing pending record")
			}
			approvalPath := approve(pendingPath)

			// The wrong kind of signature for this record, and a file that changed since: refused
			// here, with the KMS never asked.
			if code, _, stderr := d.invoke("", "--complete", pendingPath, "--approval", approvalPath, "--clearsign", sums); code != 1 || !strings.Contains(stderr, "pending signature is a detach") {
				t.Fatalf("a clearsign completion of a detach record: exit %d, stderr %q", code, stderr)
			}
			changed := d.write("changed", append(append([]byte(nil), contents...), []byte("deadbeef  extra\n")...), 0o644)
			if code, _, stderr := d.invoke("", "--complete", pendingPath, "--approval", approvalPath, "--detach", changed); code != 1 || !strings.Contains(stderr, "not what was prepared and approved") {
				t.Fatalf("a changed file: exit %d, stderr %q", code, stderr)
			}
			if d.seen() != before {
				t.Fatalf("a refused completion reached the KMS %d times", d.seen()-before)
			}
			// An approval for the other record does not count for this one.
			if code, _, stderr := d.invoke("", "--complete", pendingPath, "--approval", filepath.Join(d.directory, "key.pending.approval"), "--detach", sums); code != 1 || !strings.Contains(stderr, "for another request") {
				t.Fatalf("another record's approval: exit %d, stderr %q", code, stderr)
			}

			if code, stdout, stderr := d.invoke("", "--complete", pendingPath, "--approval", approvalPath, "--detach", sums); code != 0 || stdout != "" {
				t.Fatalf("--complete: exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if d.seen() != before+1 {
				t.Fatalf("--complete made %d KMS requests, want exactly 1", d.seen()-before)
			}
			gpg := requireTool(t, "gpg")
			home := gnupgHome(t, gpg, exported)
			output, err := exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--verify", sums+".asc", sums).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "[GNUPG:] VALIDSIG ") {
				t.Fatalf("gpg --verify of the approved signature: %v\n%s", err, output)
			}
		})
	}
}

// --prepare= (an unset variable in a release script) must not turn into the one-step command.
func TestAnEmptyPrepareValueNeverReachesTheKMS(t *testing.T) {
	d := newDeployment(t)
	sums := d.write("SHA256SUMS", []byte("x\n"), 0o644)
	for _, args := range [][]string{{"--prepare=", "--detach", sums}, {"--prepare", "", "--detach", sums}, {"--complete=", "--approval", "a", "--detach", sums}} {
		if code, _, stderr := d.invoke("", args...); code != 2 || !strings.Contains(stderr, "not empty") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	if _, err := os.Stat(sums + ".asc"); !os.IsNotExist(err) || d.seen() != 0 {
		t.Fatalf("an empty option value signed: %d KMS requests", d.seen())
	}
}

// A cleartext signature verifies over any file with the same canonical text. --complete emits the
// file it is given, so it must be given the exact file that was prepared and approved.
func TestCompleteEmitsOnlyTheExactFileThatWasApproved(t *testing.T) {
	d := newDeployment(t)
	_, approverPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d.approver = approverPrivate.Public().(ed25519.PublicKey)
	release := d.write("Release", []byte("Origin: Regalia\nSuite: stable\n"), 0o644)
	variant := d.write("Release.variant", []byte("Origin: Regalia   \nSuite: stable\n"), 0o644)
	pendingPath := filepath.Join(d.directory, "Release.pending")
	if code, _, stderr := d.invoke("", "--prepare", pendingPath, "--clearsign", release); code != 0 {
		t.Fatalf("--prepare: exit %d, stderr %q", code, stderr)
	}
	record, _ := os.ReadFile(pendingPath)
	pending, err := gpgsign.ReadPending(record)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := gpgsign.Approve(pending, releaseApprover, approverPrivate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(approval)
	approvalPath := d.write("Release.approval", encoded, 0o644)
	before := d.seen()
	out := filepath.Join(d.directory, "InRelease")
	if code, _, stderr := d.invoke("", "--complete", pendingPath, "--approval", approvalPath, "--clearsign", variant, "--output", out); code != 1 || !strings.Contains(stderr, "its SHA-256 is not the record's") {
		t.Fatalf("a file with the same canonical text and other bytes: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) || d.seen() != before {
		t.Fatal("the variant was signed or the KMS was asked")
	}
	if code, _, stderr := d.invoke("", "--complete", pendingPath, "--approval", approvalPath, "--clearsign", release, "--output", out); code != 0 {
		t.Fatalf("the exact file: exit %d, stderr %q", code, stderr)
	}
}
