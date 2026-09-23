package integration_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	sopsadapter "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

type synchronizedAuditSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (sink *synchronizedAuditSink) Send(_ context.Context, event audit.Event) error {
	sink.mu.Lock()
	sink.events = append(sink.events, event)
	sink.mu.Unlock()
	return nil
}
func (*synchronizedAuditSink) Ready(context.Context) bool { return true }
func (sink *synchronizedAuditSink) snapshot() []audit.Event {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]audit.Event(nil), sink.events...)
}

func TestSOPSCLIThroughMTLSPolicyAuditAndConcretePKCS11(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_PKCS11_E2E_MODULE"), os.Getenv("REGALIA_PKCS11_E2E_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("requires the SoftHSM E2E environment")
	}
	sops := requireSOPS313(t)
	pki := newSidecarPKI(t)
	daemon := newSOPSE2EDaemon(t, modulePath, serial, pki)
	httpClient, err := sopsadapter.NewMTLSHTTPClient(daemon.clientCertificate, daemon.roots, "kms.e2e.internal", 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	directory, err := os.MkdirTemp("/tmp", "regalia-sops-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "sops.sock")
	ctx, cancel := context.WithCancel(context.Background())
	// defer, because a t.Fatal between here and the explicit cancel below would leave this
	// goroutine running for the rest of the package's test binary, where it can fail an
	// unrelated test that runs afterwards.
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- sopsadapter.ServeUnix(ctx, socket, sopsadapter.New(sopsadapter.NewHTTPClient(daemon.server.URL, httpClient, time.Now)))
	}()
	waitForSocket(t, socket, done)
	plainPath := filepath.Join(directory, "plain.yaml")
	encryptedPath := filepath.Join(directory, "secrets.enc.yaml")
	if err := os.WriteFile(plainPath, []byte("secret: local-e2e-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyserviceURL := "unix://" + socket
	carrier := "arn:aws:kms:regalia:000000000000:key/production-sops"
	binding := "repository:regalia-kms/regalia,path:fixtures/secrets.enc.yaml,environment:development,purpose:sops-data-key"
	encrypted, err := exec.Command(sops, "--encrypt", "--kms", carrier, "--encryption-context", binding, "--enable-local-keyservice=false", "--keyservice", keyserviceURL, plainPath).CombinedOutput()
	if err != nil {
		t.Fatalf("SOPS encrypt: %v\n%s", err, encrypted)
	}
	if err := os.WriteFile(encryptedPath, encrypted, 0o600); err != nil {
		t.Fatal(err)
	}
	decrypted, err := exec.Command(sops, "--decrypt", "--enable-local-keyservice=false", "--keyservice", keyserviceURL, encryptedPath).CombinedOutput()
	if err != nil || string(decrypted) != "secret: local-e2e-only\n" {
		t.Fatalf("SOPS decrypt: %v output=%q", err, decrypted)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	events := daemon.sink.snapshot()
	if len(events) != 4 || events[0].Operation != "wrap" || events[1].Outcome != "success" || events[2].Operation != "unwrap" || events[3].Outcome != "success" {
		t.Fatalf("audit events = %#v", events)
	}

	// #24 AC1 asks for a CORRELATED audit event, and operation/outcome alone do not show that.
	// The four assertions above pass unchanged if every event carried one request id, or if wrap
	// and unwrap were recorded under the same one. An audit nobody can tie back to the operation
	// it describes cannot answer "what happened to this secret", which is the only question it
	// exists for, so the correlation is asserted rather than assumed.
	//
	// The coordinator writes two events per operation -- "authorized" before the device is
	// touched and the outcome after -- so a request id is correlated when exactly those two
	// share it and the next operation does not.
	for index, event := range events {
		if event.RequestID == "" {
			t.Errorf("audit event %d (%s/%s) carries no request id: nothing links it to a request",
				index, event.Operation, event.Outcome)
		}
	}
	if events[0].RequestID != events[1].RequestID {
		t.Errorf("the wrap pair was recorded under two request ids (%q then %q): its authorization cannot be tied to its outcome",
			events[0].RequestID, events[1].RequestID)
	}
	if events[2].RequestID != events[3].RequestID {
		t.Errorf("the unwrap pair was recorded under two request ids (%q then %q): its authorization cannot be tied to its outcome",
			events[2].RequestID, events[3].RequestID)
	}
	if events[0].RequestID == events[2].RequestID {
		t.Errorf("wrap and unwrap share request id %q: the journal cannot separate two operations on the same secret",
			events[0].RequestID)
	}

	// The chain is what makes the journal tamper-evident. Correlation is worth little if an event
	// can be dropped or reordered between the two operations without trace, so the sequence and
	// the hash links are checked across the pair rather than within a single record.
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Errorf("audit event %d has sequence %d: the journal is not contiguous", index, event.Sequence)
		}
		if index > 0 && event.PreviousHash != events[index-1].Hash {
			t.Errorf("audit event %d does not link to its predecessor (previous_hash=%q, prior hash=%q)",
				index, event.PreviousHash, events[index-1].Hash)
		}
	}
}

func waitForSocket(t *testing.T, socket string, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("SOPS adapter exited before ready: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("SOPS adapter socket did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
