package sopsadapter

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type roundTripKMS struct {
	mu      sync.Mutex
	dataKey []byte
}

func (client *roundTripKMS) Wrap(_ context.Context, request Request) ([]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.dataKey = append([]byte(nil), request.Data...)
	return []byte("regalia-test-envelope"), nil
}

func (client *roundTripKMS) Unwrap(_ context.Context, _ Request) ([]byte, error) {
	client.mu.Lock()
	defer client.mu.Unlock()
	return append([]byte(nil), client.dataKey...), nil
}

func TestSOPS313EncryptDecryptInteroperability(t *testing.T) {
	// A SKIP IS A PASS, and this is the one test whose dependency CI installs on purpose.
	// `.github/workflows/kms.yml` fetches a checksum-pinned SOPS 3.13.3, verifies its SHA-256,
	// puts it on $GITHUB_PATH, and sets REGALIA_EXPECT_SOPS in the same step. A skip while that
	// variable is set does not mean sops is unavailable — it means the interoperability check
	// silently did not run in the job that provisioned it.
	//
	// GATED ON A PURPOSE-NAMED VARIABLE, NOT ON `CI`, and the first version got this wrong.
	// `CI` is set in every job, including local-hsm-e2e, which runs the whole suite in a
	// container that deliberately has no sops — so gating on CI turned that job's correct silent
	// skip into a red. `CI` answers "am I in automation"; the question here is "was this tool
	// provisioned for me", and only the step that installs it can answer that.
	//
	// Deliberately NOT applied to the other skips in this repository. Most turn on running as
	// non-root or on filesystem behaviour, and CI containers run as root, so the same rule there
	// would fail the build for a condition CI genuinely has. The rule is "refuse to skip where
	// the environment is supposed to provide it", not "never skip".
	// A SET-BUT-UNPARSEABLE VALUE IS A TYPO IN THE WORKFLOW, NOT A REQUEST TO SKIP. Ignoring
	// ParseBool's error would let REGALIA_EXPECT_SOPS=yes silently disable this gate, which is
	// the failure the gate exists to prevent, arriving through the gate's own switch.
	expectSOPS := false
	if raw := os.Getenv("REGALIA_EXPECT_SOPS"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("REGALIA_EXPECT_SOPS=%q is not a boolean (%v) — this variable decides whether a missing sops is a skip or a failure, so an unreadable value must not quietly choose skip", raw, err)
		}
		expectSOPS = parsed
	}
	sops, err := exec.LookPath("sops")
	if err != nil {
		if expectSOPS {
			t.Fatalf("REGALIA_EXPECT_SOPS is set but sops is not on PATH: %v — the workflow sets that variable in the same step that installs a checksum-pinned SOPS 3.13.3, so its absence here means the install step and this module's tests are no longer in the same job and the interoperability check has silently stopped running", err)
		}
		t.Skip("sops binary is not installed")
	}
	version, err := exec.Command(sops, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "sops 3.13.") {
		if expectSOPS {
			t.Fatalf("sops on PATH is not 3.13.x (%s, err=%v) — the workflow pins 3.13.3, so a different version here means the pin and this assertion have drifted apart", version, err)
		}
		t.Skipf("requires SOPS 3.13.x: %s", version)
	}
	directory := socketDir(t)
	socket := filepath.Join(directory, "sops.sock")
	ctx, cancel := context.WithCancel(context.Background())
	// defer, because a t.Fatal between here and the explicit cancel below would leave this
	// goroutine running for the rest of the package's test binary, where it can fail an
	// unrelated test that runs afterwards.
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeUnix(ctx, socket, New(&roundTripKMS{})) }()
	for deadline := time.Now().Add(2 * time.Second); ; {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("adapter socket did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	plainPath := filepath.Join(directory, "plain.yaml")
	encryptedPath := filepath.Join(directory, "secrets.enc.yaml")
	if err := os.WriteFile(plainPath, []byte("secret: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyserviceURL := "unix://" + socket
	carrier := "arn:aws:kms:regalia:000000000000:key/production-sops"
	binding := "repository:regalia-kms/infrastructure,path:clusters/prod/secrets.enc.yaml,environment:production,purpose:sops-data-key"
	encrypt := exec.Command(sops, "--encrypt", "--kms", carrier, "--encryption-context", binding,
		"--enable-local-keyservice=false", "--keyservice", keyserviceURL, plainPath)
	encrypted, err := encrypt.CombinedOutput()
	if err != nil {
		t.Fatalf("sops encrypt: %v\n%s", err, encrypted)
	}
	if err := os.WriteFile(encryptedPath, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	decrypt := exec.Command(sops, "--decrypt", "--enable-local-keyservice=false", "--keyservice", keyserviceURL, encryptedPath)
	decrypted, err := decrypt.CombinedOutput()
	if err != nil {
		t.Fatalf("sops decrypt: %v\n%s", err, decrypted)
	}
	if string(decrypted) != "secret: value\n" {
		t.Fatalf("decrypted = %q", decrypted)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeUnix() = %v", err)
	}
}
