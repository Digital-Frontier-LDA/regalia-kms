package integration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/approval"
)

// A RELEASE SIGNATURE THAT NEEDS AN APPROVAL, WITH NOTHING STANDING IN (regalia#530, ADR-0002 D25).
//
// The adapter's own tests run regalia-sign and regalia-approve against a stand-in KMS that checks
// approvals the way this repository reads API.md, and a stand-in token. Here both are the real thing:
// the daemon's policy engine and internal/approval decide whether the evidence counts, and the
// approver key lives on a PKCS#11 token (SoftHSM) and is reached through OpenSC's pkcs11-tool with
// CKM_EDDSA, the path a YubiKey approver takes. Three processes — prepare, approve, complete — and
// GnuPG judges what comes out.
//
// The two serializations of the approval binding (the daemon's and the adapter's) meet here on live
// requests: if they disagreed by one byte, the daemon would count nobody and deny.
func TestAReleaseSignatureNeedsAHardwareKeyApprovalAtTheRealDaemon(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("requires the SoftHSM E2E environment")
	}
	pin := string(e2ePKCS11PIN(t))
	gpg := requireGPG(t)
	pkcs11Tool, err := exec.LookPath("pkcs11-tool")
	if err != nil {
		t.Fatal("pkcs11-tool is required")
	}
	sign, approve := buildRegaliaSign(t), buildGPGSignCommand(t, "regalia-approve")
	pki := newSidecarPKI(t)

	// The approver's public key, read off the token as an operator does when enrolling an approver,
	// is the ONLY approver the daemon knows.
	approverPEM := tokenPublicKeyPEM(t, modulePath, "10")
	block, _ := pem.Decode(approverPEM)
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	approverPublic, isEd25519 := parsed.(ed25519.PublicKey)
	if err != nil || !isEd25519 {
		t.Fatalf("token key 10 is not an Ed25519 public key: %v", err)
	}
	daemon := newReleaseSigningDaemon(t, modulePath, serial, pki, approval.NewKeySet(map[string]ed25519.PublicKey{releaseApproverID: approverPublic}))

	// The runner's deployment and the approver's are two directories with nothing shared but the
	// release public key: the approver holds no workload identity, the runner no approver key.
	runner, approverHome := t.TempDir(), t.TempDir()
	releasePublic := tokenPublicKeyPEM(t, modulePath, "11")
	config := writeSignDeployment(t, runner, signConfig{
		kmsURL: daemon.server.URL, serverName: "kms.e2e.internal", ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
		objectID: approvedObject, purpose: "release-artifact", publicKey: releasePublic,
	})
	var signConfigDocument map[string]string
	if contents, err := os.ReadFile(config); err != nil || json.Unmarshal(contents, &signConfigDocument) != nil {
		t.Fatalf("read back the runner's configuration: %v", err)
	}
	write := func(directory, name string, contents []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, contents, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	approverConfig := func(name string, source map[string]any, approverKey []byte) string {
		document := map[string]any{
			"approver_id": releaseApproverID, "approver_public_key_path": write(approverHome, name+".approver.pub.pem", approverKey, 0o644),
			"object_id": approvedObject, "environment": "development", "purpose": "release-artifact",
			"public_key_path": write(approverHome, name+".release.pub.pem", releasePublic, 0o644),
			"key_created":     signConfigDocument["key_created"], "user_id": signConfigDocument["user_id"],
		}
		for key, value := range source {
			document[key] = value
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return write(approverHome, name+".json", encoded, 0o600)
	}
	onToken := approverConfig("token", map[string]any{"pkcs11": map[string]string{
		"tool": pkcs11Tool, "module": modulePath, "token_serial": serial, "token_label": "regalia-kms-e2e", "key_id": "10"}}, approverPEM)

	run := func(binary string, environment []string, args ...string) (string, error) {
		command := exec.Command(binary, args...)
		command.Env = append(os.Environ(), environment...)
		output, err := command.CombinedOutput()
		return string(output), err
	}
	must := func(what, binary string, environment []string, args ...string) string {
		t.Helper()
		output, err := run(binary, environment, args...)
		if err != nil {
			t.Fatalf("%s: %v\n%s", what, err, output)
		}
		return output
	}
	tokenPIN := []string{"REGALIA_APPROVE_PIN=" + pin}

	sums := write(runner, "SHA256SUMS", []byte("9f2c…  regalia-kms_1.0.0_linux_amd64.tar.gz\n"), 0o644)
	// The approver's own copy of the file, as it would be after downloading the release candidate.
	approversCopy := write(approverHome, "SHA256SUMS", []byte("9f2c…  regalia-kms_1.0.0_linux_amd64.tar.gz\n"), 0o644)

	t.Run("without an approval the daemon denies, and says so in the audit journal", func(t *testing.T) {
		baseline := len(daemon.sink.snapshot())
		output, err := run(sign, nil, "--config", config, "--detach", sums)
		if err == nil || !strings.Contains(output, "DENIED") {
			t.Fatalf("an unapproved release signature was not denied: %v\n%s", err, output)
		}
		if _, statErr := os.Stat(sums + ".asc"); statErr == nil {
			t.Fatal("a denied request left a signature")
		}
		events := daemon.sink.snapshot()[baseline:]
		if len(events) != 1 || events[0].Decision != "deny" || len(events[0].VerifiedApprovers) != 0 {
			t.Fatalf("expected one deny event naming no approver, got %#v", events)
		}
	})

	// The exported key: its self-certification is a signature by the release key, so it is prepared,
	// approved on the token and completed like any other.
	keyPending := filepath.Join(runner, "key.pending")
	must("prepare the key export", sign, nil, "--config", config, "--prepare", keyPending, "--export-key")
	must("approve the key export", approve, tokenPIN, "--config", onToken, "--pending", keyPending)
	exported := filepath.Join(runner, "release-key.asc")
	must("complete the key export", sign, nil, "--config", config, "--complete", keyPending, "--approval", keyPending+".approval", "--export-key", "--output", exported)
	exportedKey, err := os.ReadFile(exported)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.TrimSpace(must("fingerprint", sign, nil, "--config", config, "--fingerprint"))
	home := importIntoThrowawayGnuPG(t, gpg, string(exportedKey), fingerprint)

	t.Run("prepared by the runner, approved on the token, completed: GnuPG accepts it", func(t *testing.T) {
		baseline := len(daemon.sink.snapshot())
		pending := filepath.Join(runner, "SHA256SUMS.pending")
		must("prepare", sign, nil, "--config", config, "--prepare", pending, "--detach", sums)
		if len(daemon.sink.snapshot()) != baseline {
			t.Fatal("--prepare reached the daemon")
		}
		output := must("approve", approve, tokenPIN, "--config", onToken, "--pending", pending, "--file", approversCopy)
		if !strings.Contains(output, "checked against SHA256SUMS") {
			t.Fatalf("the approver was not shown what was checked:\n%s", output)
		}
		if len(daemon.sink.snapshot()) != baseline {
			t.Fatal("regalia-approve reached the daemon")
		}
		must("complete", sign, nil, "--config", config, "--complete", pending, "--approval", pending+".approval", "--detach", sums)

		verified, err := exec.Command(gpg, "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--verify", sums+".asc", sums).CombinedOutput()
		if err != nil || !strings.Contains(string(verified), "[GNUPG:] VALIDSIG "+fingerprint) {
			t.Fatalf("GnuPG does not accept the approved signature: %v\n%s", err, verified)
		}
		// The journal names who approved: the daemon's own verification, not the client's claim.
		events := daemon.sink.snapshot()[baseline:]
		if len(events) != 2 || events[0].Outcome != "authorized" || events[1].Outcome != "success" {
			t.Fatalf("expected an authorized/success pair, got %#v", events)
		}
		for _, event := range events {
			if event.ObjectID != approvedObject || len(event.VerifiedApprovers) != 1 || event.VerifiedApprovers[0] != releaseApproverID {
				t.Fatalf("the audit event does not name the approver: %#v", event)
			}
		}

		// AN APPROVAL IS SPENT WITH ITS REQUEST. The same record and approval, sent again, is the
		// same nonce: the daemon has reserved it and signs nothing more.
		again := filepath.Join(runner, "again.asc")
		before := len(daemon.sink.snapshot())
		if output, err := run(sign, nil, "--config", config, "--complete", pending, "--approval", pending+".approval", "--detach", sums, "--output", again); err == nil {
			t.Fatalf("a spent approval signed a second time:\n%s", output)
		}
		if _, statErr := os.Stat(again); statErr == nil {
			t.Fatal("a replayed approval wrote a signature")
		}
		for _, event := range daemon.sink.snapshot()[before:] {
			if event.Outcome == "success" {
				t.Fatalf("the token signed for a replayed approval: %#v", event)
			}
		}
	})

	t.Run("an approver the daemon does not know is denied, by the daemon", func(t *testing.T) {
		// A complete, well-formed approval under the right identity, by a key that is not in the
		// daemon's key set. Nothing on the client can tell; the daemon counts nobody.
		_, stranger, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(stranger)
		if err != nil {
			t.Fatal(err)
		}
		public, err := x509.MarshalPKIXPublicKey(stranger.Public())
		if err != nil {
			t.Fatal(err)
		}
		strangerConfig := approverConfig("stranger", map[string]any{
			"key_file": write(approverHome, "stranger-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600),
		}, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))

		other := write(runner, "OTHER", []byte("release notes\n"), 0o644)
		pending := filepath.Join(runner, "OTHER.pending")
		must("prepare", sign, nil, "--config", config, "--prepare", pending, "--detach", other)
		must("approve as a stranger", approve, nil, "--config", strangerConfig, "--pending", pending, "--file", other)
		baseline := len(daemon.sink.snapshot())
		output, err := run(sign, nil, "--config", config, "--complete", pending, "--approval", pending+".approval", "--detach", other)
		if err == nil || !strings.Contains(output, "DENIED") {
			t.Fatalf("an approval by an unknown key was not denied: %v\n%s", err, output)
		}
		if _, statErr := os.Stat(other + ".asc"); statErr == nil {
			t.Fatal("a denied request left a signature")
		}
		events := daemon.sink.snapshot()[baseline:]
		if len(events) != 1 || events[0].Decision != "deny" || len(events[0].VerifiedApprovers) != 0 {
			t.Fatalf("expected one deny event naming no approver, got %#v", events)
		}
	})

	t.Run("the approver's copy differs from what the runner prepared: nothing is approved", func(t *testing.T) {
		tampered := write(runner, "TAMPERED", []byte("deadbeef  backdoored.tar.gz\n"), 0o644)
		pending := filepath.Join(runner, "TAMPERED.pending")
		must("prepare", sign, nil, "--config", config, "--prepare", pending, "--detach", tampered)
		output, err := run(approve, tokenPIN, "--config", onToken, "--pending", pending, "--file", approversCopy)
		if err == nil || !strings.Contains(output, "not a signature over this file") {
			t.Fatalf("the approver approved a file other than their own copy: %v\n%s", err, output)
		}
		if _, statErr := os.Stat(pending + ".approval"); statErr == nil {
			t.Fatal("an approval was written for a file the approver did not hold")
		}
	})

}
