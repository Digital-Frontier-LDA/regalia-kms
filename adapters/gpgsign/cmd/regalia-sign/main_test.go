package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	key        *ecdsa.PrivateKey

	mu       sync.Mutex
	requests int
	refuse   string // when set, the KMS answers with this error code
}

func newDeployment(t *testing.T) *deployment {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	}
	_ = json.NewDecoder(request.Body).Decode(&document)
	writer.Header().Set("Content-Type", "application/json")
	if refuse != "" {
		writer.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(writer).Encode(map[string]any{"request_id": request.Header.Get("X-Request-ID"), "code": refuse, "message": "request failed", "retryable": false})
		return
	}
	digest, _ := base64.StdEncoding.DecodeString(document.Payload)
	r, s, err := ecdsa.Sign(rand.Reader, d.key, digest)
	if err != nil {
		d.t.Fatal(err)
	}
	signature := append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...)
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
	git, gpg := requireTool(t, "git"), requireTool(t, "gpg")
	d := newDeployment(t)
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
