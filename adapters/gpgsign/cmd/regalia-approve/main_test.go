package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign"
)

// THE TOKEN IS STOOD IN FOR BY THIS TEST BINARY. regalia-approve reaches a hardware key by running
// pkcs11-tool; here the "tool" is the test executable itself, which TestMain turns into a signer
// when stubVariable is set. It reads --input-file and writes --output-file exactly as pkcs11-tool
// does, so what is tested is everything regalia-approve does around the token: the argument vector,
// the files, and above all the check of what comes back. The real pkcs11-tool against a real
// PKCS#11 module is in internal/integration (SoftHSM).
const stubVariable = "REGALIA_APPROVE_TEST_STUB"

func TestMain(m *testing.M) {
	if behaviour := os.Getenv(stubVariable); behaviour != "" {
		os.Exit(stubTool(behaviour, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// stubSeed is the stub token's key. The honest stub signs with it; the others misbehave.
var stubSeed = bytes.Repeat([]byte{0x42}, ed25519.SeedSize)

func stubTool(behaviour string, args []string) int {
	values := map[string]string{}
	for index := 0; index+1 < len(args); index++ {
		if strings.HasPrefix(args[index], "--") {
			values[args[index]] = args[index+1]
		}
	}
	if record := os.Getenv("REGALIA_APPROVE_TEST_ARGV"); record != "" {
		_ = os.WriteFile(record, []byte(strings.Join(args, "\n")), 0o600)
	}
	message, err := os.ReadFile(values["--input-file"])
	if err != nil || values["--mechanism"] != "EDDSA" {
		return 3
	}
	var signature []byte
	switch behaviour {
	case "honest":
		signature = ed25519.Sign(ed25519.NewKeyFromSeed(stubSeed), message)
	case "another-key":
		signature = ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x43}, ed25519.SeedSize)), message)
	case "prehashed":
		// What a device does that signs a hash of the input instead of the input: 64 bytes, by the
		// right key, and not a plain Ed25519 signature over the binding.
		signature, _ = ed25519.NewKeyFromSeed(stubSeed).Sign(nil, message, &ed25519.Options{Context: "not-plain"})
	case "short":
		signature = ed25519.Sign(ed25519.NewKeyFromSeed(stubSeed), message)[:63]
	case "fails":
		return 1
	}
	if os.WriteFile(values["--output-file"], signature, 0o600) != nil {
		return 3
	}
	return 0
}

type bench struct {
	t         *testing.T
	directory string
	release   *ecdsa.PrivateKey
	key       *gpgsign.Key // the preparer's key; its KMS is never reached
	approver  ed25519.PrivateKey
	config    map[string]any
}

const (
	userID     = "Regalia Release Signing (test) <releases@example.invalid>"
	keyCreated = "2026-10-02T00:00:00Z"
	approverID = "spiffe://regalia/approver/release"
)

func (b *bench) write(name string, contents []byte, mode os.FileMode) string {
	b.t.Helper()
	path := filepath.Join(b.directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		b.t.Fatal(err)
	}
	return path
}

func publicPEM(t *testing.T, public any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func newBench(t *testing.T) *bench {
	t.Helper()
	release, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := &bench{t: t, directory: t.TempDir(), release: release, approver: ed25519.NewKeyFromSeed(stubSeed)}
	target := gpgsign.Target{ObjectID: "release-signing-key", Environment: "production", Purpose: "release-signing"}
	// The preparer's side. Its client points nowhere: Prepare must not use it.
	client, err := gpgsign.NewClient("https://kms.invalid", &http.Client{Timeout: time.Second}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gpgsign.NewSigner(release.Public(), client, target)
	if err != nil {
		t.Fatal(err)
	}
	created, _ := time.Parse(time.RFC3339, keyCreated)
	if b.key, err = gpgsign.NewKey(signer, created, userID); err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(b.approver)
	if err != nil {
		t.Fatal(err)
	}
	b.config = map[string]any{
		"approver_id": approverID, "approver_public_key_path": b.write("approver.pub.pem", publicPEM(t, b.approver.Public()), 0o644),
		"key_file":  b.write("approver-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600),
		"object_id": target.ObjectID, "environment": target.Environment, "purpose": target.Purpose,
		"public_key_path": b.write("release.pub.pem", publicPEM(t, release.Public()), 0o644), "key_created": keyCreated, "user_id": userID,
	}
	return b
}

// useToken switches the approver from the key file to the stub token.
func (b *bench) useToken(behaviour string) {
	b.t.Helper()
	executable, err := os.Executable()
	if err != nil {
		b.t.Fatal(err)
	}
	// A copy with exact permissions: the toolchain builds the test binary group-writable under a
	// permissive umask, and a tool others can write is (rightly) not run.
	contents, err := os.ReadFile(executable)
	if err != nil {
		b.t.Fatal(err)
	}
	executable = b.write("pkcs11-tool", contents, 0o755)
	if err := os.Chmod(executable, 0o755); err != nil {
		b.t.Fatal(err)
	}
	delete(b.config, "key_file")
	// The module is only named to the stub, never loaded; any file that passes the same ownership
	// check as the tool will do.
	b.config["pkcs11"] = map[string]string{"tool": executable, "module": b.write("module.so", []byte("not a module"), 0o644), "token_label": "OpenPGP card (User PIN (sig))", "key_id": "01"}
	b.t.Setenv(stubVariable, behaviour)
}

func (b *bench) configPath() string {
	b.t.Helper()
	encoded, err := json.Marshal(b.config)
	if err != nil {
		b.t.Fatal(err)
	}
	path := filepath.Join(b.directory, "approve.json")
	_ = os.Remove(path)
	return b.write("approve.json", encoded, 0o600)
}

// prepare writes a pending record for document, as regalia-sign --prepare does.
func (b *bench) prepare(name string, mode gpgsign.Mode, document []byte) (string, gpgsign.Pending) {
	b.t.Helper()
	pending, err := b.key.Prepare(context.Background(), mode, bytes.NewReader(document), time.Now(), 5*time.Minute)
	if err != nil {
		b.t.Fatal(err)
	}
	if mode != gpgsign.ModeExportKey {
		pending.SetDocument(document)
	}
	encoded, _ := json.Marshal(pending)
	return b.write(name, encoded, 0o644), pending
}

func (b *bench) invoke(environment map[string]string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	config := b.configPath()
	getenv := func(name string) string {
		if name == "REGALIA_APPROVE_CONFIG" {
			return config
		}
		return environment[name]
	}
	code := run(args, strings.NewReader(""), &stdout, &stderr, getenv, time.Now)
	return code, stdout.String(), stderr.String()
}

// counts says whether the approval file is one the KMS would count: the approver's Ed25519
// signature over the binding of the pending request, carrying that request's own fields.
func (b *bench) counts(path string, pending gpgsign.Pending) bool {
	b.t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	approval, err := gpgsign.ReadApproval(contents)
	if err != nil {
		b.t.Fatal(err)
	}
	binding, err := pending.Binding()
	if err != nil {
		b.t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	return err == nil && approval.ApproverID == approverID && approval.Nonce == pending.Nonce && approval.ExpiresAt == pending.ExpiresAt &&
		approval.PayloadDigest == pending.PayloadSHA256 && ed25519.Verify(b.approver.Public().(ed25519.PublicKey), binding, signature)
}

var sums = []byte("0f3a…  regalia-kms_1.0.0_linux_amd64.tar.gz\n")

func TestAnApproverWhoHoldsTheFileApprovesExactlyThatFile(t *testing.T) {
	b := newBench(t)
	file := b.write("SHA256SUMS", sums, 0o644)
	for _, mode := range []gpgsign.Mode{gpgsign.ModeDetach, gpgsign.ModeDetachBinary, gpgsign.ModeClearSign} {
		path, pending := b.prepare("pending-"+string(mode), mode, sums)
		code, stdout, stderr := b.invoke(nil, "--pending", path, "--file", file)
		if code != 0 || !strings.Contains(stdout, "checked against SHA256SUMS, sha256 "+pending.DocumentSHA256) || !strings.Contains(stdout, approverID) {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", mode, code, stdout, stderr)
		}
		if !b.counts(path+".approval", pending) {
			t.Fatalf("%s: the approval is not one the KMS would count", mode)
		}
		// An approval is never replaced.
		if code, _, stderr := b.invoke(nil, "--pending", path, "--file", file); code != 1 || !strings.Contains(stderr, "already exists") {
			t.Fatalf("%s: a second approval to the same name: exit %d, stderr %q", mode, code, stderr)
		}
	}
	// A key export signs no file: it is checked against the pinned key alone.
	path, pending := b.prepare("pending-key", gpgsign.ModeExportKey, nil)
	if code, stdout, stderr := b.invoke(nil, "--pending", path, "--output", filepath.Join(b.directory, "key.approval")); code != 0 || !strings.Contains(stdout, "a key export") {
		t.Fatalf("key export: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if !b.counts(filepath.Join(b.directory, "key.approval"), pending) {
		t.Fatal("the key-export approval is not one the KMS would count")
	}
}

// THE POINT OF THE TOOL. The pending record carries a file hash, but the hash is only what the
// preparer wrote; what the approver signs is the payload digest. Each case below is a record whose
// claims and whose payload disagree, or that is for something this approver does not approve, and
// each must end with no approval file.
func TestNothingIsApprovedThatTheApproverDidNotCheck(t *testing.T) {
	b := newBench(t)
	file := b.write("SHA256SUMS", sums, 0o644)
	other := b.write("OTHER", []byte("deadbeef  backdoored.tar.gz\n"), 0o644)
	rewrite := func(name string, pending gpgsign.Pending) string {
		encoded, _ := json.Marshal(pending)
		return b.write(name, encoded, 0o644)
	}
	_, honest := b.prepare("honest", gpgsign.ModeDetach, sums)
	_, forOther := b.prepare("for-other", gpgsign.ModeDetach, []byte("deadbeef  backdoored.tar.gz\n"))

	// The preparer signs another file and labels it with the good file's hash.
	lying := forOther
	lying.DocumentSHA256 = honest.DocumentSHA256
	otherObject, otherPurpose, otherEnvironment, otherKey := honest, honest, honest, honest
	otherObject.ObjectID, otherPurpose.Purpose, otherEnvironment.Environment = "another-key", "token-signing", "staging"
	otherKey.Fingerprint = strings.Repeat("0", 40)
	laterTime := honest
	laterTime.Created = "2031-01-01T00:00:00Z"
	otherMode := honest
	otherMode.Mode = gpgsign.ModeClearSign
	expired := honest
	expired.ExpiresAt = time.Now().UTC().Add(-time.Second).Truncate(time.Second).Format(time.RFC3339Nano)

	for name, test := range map[string]struct {
		pending gpgsign.Pending
		args    []string
		want    string
	}{
		"a record for another file, labelled with this file's hash": {lying, []string{"--file", file}, "not a signature over this file"},
		"the approver's file is not the one prepared":               {honest, []string{"--file", other}, "not a signature over this file"},
		"another object":         {otherObject, []string{"--file", file}, "another key or target"},
		"another purpose":        {otherPurpose, []string{"--file", file}, "another key or target"},
		"another environment":    {otherEnvironment, []string{"--file", file}, "another key or target"},
		"another key":            {otherKey, []string{"--file", file}, "another key or target"},
		"another object, unseen": {otherObject, []string{"--unseen"}, "another key or target"},
		"another key, unseen":    {otherKey, []string{"--unseen"}, "another key or target"},
		"a creation time other than the one the digest covers": {laterTime, []string{"--file", file}, "not a signature over this file"},
		"another kind of signature than the digest is of":      {otherMode, []string{"--file", file}, "not a signature over this file"},
		"an expired record":             {expired, []string{"--file", file}, "expired"},
		"neither the file nor --unseen": {honest, nil, "pass --file"},
	} {
		t.Run(name, func(t *testing.T) {
			path := rewrite("case.pending", test.pending)
			t.Cleanup(func() { _ = os.Remove(path); _ = os.Remove(path + ".approval") })
			code, _, stderr := b.invoke(nil, append([]string{"--pending", path}, test.args...)...)
			if code != 1 || !strings.Contains(stderr, test.want) {
				t.Fatalf("exit %d, stderr %q, want a refusal containing %q", code, stderr, test.want)
			}
			if _, err := os.Stat(path + ".approval"); !os.IsNotExist(err) {
				t.Fatal("a refused approval was written")
			}
		})
	}

	// --unseen is the stated exception: it approves the record as it stands and says, in the
	// output, that the file was not checked.
	path := rewrite("unseen.pending", lying)
	code, stdout, stderr := b.invoke(nil, "--pending", path, "--unseen")
	if code != 0 || !strings.Contains(stdout, "NOT CHECKED (--unseen)") {
		t.Fatalf("--unseen: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// A HARDWARE APPROVER, AND WHAT COMES BACK FROM IT. The token is asked through pkcs11-tool; whatever
// it returns is an approval only if it is a plain Ed25519 signature by the pinned approver key over
// the binding. A device that signs with another key, signs something derived from the binding, or
// returns a wrong-sized result would produce an approval the KMS silently does not count; it is
// refused here instead.
func TestATokenApproverIsBelievedOnlyWhenItsSignatureVerifies(t *testing.T) {
	for behaviour, want := range map[string]string{
		"honest": "", "another-key": "does not verify against the approver's own key",
		"prehashed": "does not verify against the approver's own key", "short": "did not return an Ed25519 signature", "fails": "the token did not sign",
	} {
		t.Run(behaviour, func(t *testing.T) {
			b := newBench(t)
			b.useToken(behaviour)
			sumsPath := b.write("SHA256SUMS", sums, 0o644)
			path, pending := b.prepare("pending", gpgsign.ModeDetach, sums)
			argv := filepath.Join(b.directory, "argv")
			t.Setenv("REGALIA_APPROVE_TEST_ARGV", argv)
			code, _, stderr := b.invoke(map[string]string{}, "--pending", path, "--file", sumsPath)
			if want == "" {
				if code != 0 || !b.counts(path+".approval", pending) {
					t.Fatalf("an honest token: exit %d, stderr %q", code, stderr)
				}
				// The PIN was not in the environment, so it is not asked for on the command line
				// either: pkcs11-tool prompts. And the binding it was handed is the record's.
				recorded, _ := os.ReadFile(argv)
				if strings.Contains(string(recorded), "--pin") || !strings.Contains(string(recorded), "--token-label\nOpenPGP card (User PIN (sig))") ||
					!strings.Contains(string(recorded), "--id\n01") || !strings.Contains(string(recorded), "--login") {
					t.Fatalf("the token was asked with %q", recorded)
				}
				return
			}
			if code != 1 || !strings.Contains(stderr, want) {
				t.Fatalf("exit %d, stderr %q, want a refusal containing %q", code, stderr, want)
			}
			if _, err := os.Stat(path + ".approval"); !os.IsNotExist(err) {
				t.Fatal("an approval the KMS would not count was written")
			}
		})
	}

	// With the PIN in the environment, pkcs11-tool is told the NAME of the variable. The value is
	// never an argument.
	b := newBench(t)
	b.useToken("honest")
	sumsPath := b.write("SHA256SUMS", sums, 0o644)
	path, _ := b.prepare("pending", gpgsign.ModeDetach, sums)
	argv := filepath.Join(b.directory, "argv")
	t.Setenv("REGALIA_APPROVE_TEST_ARGV", argv)
	if code, _, stderr := b.invoke(map[string]string{pinVariable: "648219"}, "--pending", path, "--file", sumsPath); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	recorded, _ := os.ReadFile(argv)
	if !strings.Contains(string(recorded), "--pin\nenv:"+pinVariable) || strings.Contains(string(recorded), "648219") {
		t.Fatalf("the PIN handling on the command line is wrong: %q", recorded)
	}
}

func TestTheConfigurationAndCommandLineAreStrict(t *testing.T) {
	b := newBench(t)
	file := b.write("SHA256SUMS", sums, 0o644)
	path, _ := b.prepare("pending", gpgsign.ModeDetach, sums)
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherSeed := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x07}, ed25519.SeedSize))
	for name, test := range map[string]struct {
		edit func(map[string]any)
		want string
	}{
		"no approver ID":   {func(c map[string]any) { c["approver_id"] = " " }, "are required"},
		"an unknown field": {func(c map[string]any) { c["touch"] = true }, "not the expected JSON document"},
		"a relative path":  {func(c map[string]any) { c["public_key_path"] = "release.pub.pem" }, "absolute and clean"},
		"both key sources": {func(c map[string]any) {
			c["pkcs11"] = map[string]string{"tool": "/t", "module": "/m", "token_label": "l", "key_id": "01"}
		}, "exactly one of"},
		"no key source": {func(c map[string]any) { delete(c, "key_file") }, "exactly one of"},
		"a relative tool path": {func(c map[string]any) {
			delete(c, "key_file")
			c["pkcs11"] = map[string]string{"tool": "pkcs11-tool", "module": "/m", "token_label": "l", "key_id": "01"}
		}, "pkcs11 needs"},
		"a key ID not in hex": {func(c map[string]any) {
			delete(c, "key_file")
			c["pkcs11"] = map[string]string{"tool": "/t", "module": "/m", "token_label": "l", "key_id": "sig"}
		}, "pkcs11 needs"},
		"an approver key that is not Ed25519": {func(c map[string]any) {
			c["approver_public_key_path"] = b.write("p256.pub.pem", publicPEM(t, ecdsaKey.Public()), 0o644)
		}, "must be Ed25519"},
		"a key file that is not the pinned approver key": {func(c map[string]any) {
			c["approver_public_key_path"] = b.write("other.pub.pem", publicPEM(t, otherSeed.Public()), 0o644)
		}, "is not the Ed25519 private key"},
		"a key file others can read": {func(c map[string]any) {
			contents, _ := os.ReadFile(c["key_file"].(string))
			c["key_file"] = b.write("loose-key.pem", contents, 0o644)
		}, "key file is unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			saved := map[string]any{}
			for key, value := range b.config {
				saved[key] = value
			}
			t.Cleanup(func() { b.config = saved; _ = os.Remove(path + ".approval") })
			test.edit(b.config)
			code, _, stderr := b.invoke(nil, "--pending", path, "--file", file)
			if code != 1 || !strings.Contains(stderr, test.want) {
				t.Fatalf("exit %d, stderr %q, want %q", code, stderr, test.want)
			}
			if _, err := os.Stat(path + ".approval"); !os.IsNotExist(err) {
				t.Fatal("an approval was written under a refused configuration")
			}
		})
	}
	for _, args := range [][]string{{}, {"--file", "f"}, {"--pending"}, {"--pending", "p", "--frobnicate"}, {"--pending", "p", "--file", "f", "--unseen"}, {"p"}} {
		if code, _, stderr := b.invoke(nil, args...); code != 2 || !strings.Contains(stderr, "usage:") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
}

// THE TOOL THAT IS RUN SEES THE PIN AND DRIVES THE KEY. A tool or module that someone other than root
// or the approver could have replaced is not run at all.
func TestAToolOrModuleOthersCanReplaceIsNotRun(t *testing.T) {
	for name, loosen := range map[string]func(b *bench, device map[string]string){
		"a group-writable tool": func(b *bench, device map[string]string) {
			contents, err := os.ReadFile(device["tool"])
			if err != nil {
				b.t.Fatal(err)
			}
			device["tool"] = b.write("loose-tool", contents, 0o755)
			if err := os.Chmod(device["tool"], 0o775); err != nil {
				b.t.Fatal(err)
			}
		},
		"a world-writable module": func(b *bench, device map[string]string) {
			if err := os.Chmod(device["module"], 0o666); err != nil {
				b.t.Fatal(err)
			}
		},
		"a tool that is a directory":   func(b *bench, device map[string]string) { device["tool"] = b.directory },
		"a module that does not exist": func(b *bench, device map[string]string) { device["module"] = filepath.Join(b.directory, "absent.so") },
		"a link to a tool others can write": func(b *bench, device map[string]string) {
			contents, _ := os.ReadFile(device["tool"])
			target := b.write("loose-target", contents, 0o755)
			if err := os.Chmod(target, 0o777); err != nil {
				b.t.Fatal(err)
			}
			device["tool"] = filepath.Join(b.directory, "tool-link")
			if err := os.Symlink(target, device["tool"]); err != nil {
				b.t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBench(t)
			b.useToken("honest")
			sumsPath := b.write("SHA256SUMS", sums, 0o644)
			path, _ := b.prepare("pending", gpgsign.ModeDetach, sums)
			argv := filepath.Join(b.directory, "argv")
			t.Setenv("REGALIA_APPROVE_TEST_ARGV", argv)
			loosen(b, b.config["pkcs11"].(map[string]string))
			code, _, stderr := b.invoke(map[string]string{}, "--pending", path, "--file", sumsPath)
			if code != 1 || !(strings.Contains(stderr, "pkcs11 tool:") || strings.Contains(stderr, "pkcs11 module:")) {
				t.Fatalf("exit %d, stderr %q", code, stderr)
			}
			if _, err := os.Stat(argv); !os.IsNotExist(err) {
				t.Fatal("the tool was run")
			}
			if _, err := os.Stat(path + ".approval"); !os.IsNotExist(err) {
				t.Fatal("an approval was written")
			}
		})
	}
}
