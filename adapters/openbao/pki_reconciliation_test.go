package openbaopoc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
)

// Observe actual acknowledgements without replacing the collector with the
// in-memory assertions used by the older fixture. The event is recorded by the
// daemon and committed over mTLS before the observer sees it.
type pocCollectorObserver struct {
	sink     audit.Sink
	observer *fixtureAudit
}

func (s *pocCollectorObserver) Send(ctx context.Context, event audit.Event) error {
	if err := s.sink.Send(ctx, event); err != nil {
		return err
	}
	return s.observer.Send(ctx, event)
}

func (s *pocCollectorObserver) Ready(ctx context.Context) bool { return s.sink.Ready(ctx) }

type pocAuditCollector struct {
	sink       *audit.HTTPSink
	exportPath string
}

func newPOCAuditCollector(t *testing.T) *pocAuditCollector {
	t.Helper()
	// This collector uses a distinct synthetic transport authority and state
	// directory. A separate-process deployment is qualified by the daemon recovery
	// test; this arm exercises the actual collector protocol with genuine Bao data.
	pki := newFixturePKI(t)
	stateDir := t.TempDir()
	collector, err := audit.OpenCollector(stateDir)
	if err != nil {
		t.Fatal("open independent audit collector", err)
	}
	t.Cleanup(func() {
		if err := collector.Close(); err != nil {
			t.Error("close audit collector", err)
		}
	})
	server := httptest.NewUnstartedServer(collector.Handler())
	server.TLS, err = auth.ServerTLSConfig(pki.server, pki.roots)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	pair, err := tls.LoadX509KeyPair(pki.caConfig["certificate_path"], pki.caConfig["private_key_path"])
	if err != nil {
		t.Fatal(err)
	}
	client, err := audit.NewMTLSHTTPClient(pair, pki.roots, "kms.poc.test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	sink, err := audit.NewHTTPSink(server.URL, client, 5*time.Second, "poc-site")
	if err != nil {
		t.Fatal(err)
	}
	identity := sha256.Sum256(pair.Certificate[0])
	return &pocAuditCollector{sink: sink, exportPath: filepath.Join(stateDir, "streams", hex.EncodeToString(identity[:]), "site-poc-site.jsonl")}
}

func pocWaitCollectorAudit(t *testing.T, f *signingFixture, start int, match func(audit.Event) bool) bool {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		for _, event := range f.audit.snapshotEvents()[start:] {
			if match(event) {
				return true
			}
		}
		select {
		case <-deadline.C:
			return false
		case <-tick.C:
		}
	}
}

func pocReconcileBaoArtifacts(t *testing.T, f *signingFixture, collector *pocAuditCollector) {
	t.Helper()
	// The expected head comes from the authenticated collector protocol, rather
	// than the untrusted export's own final line or the in-memory event observer.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sequence, head, err := collector.sink.CommittedHead(ctx, "poc-site")
	if err != nil || sequence == 0 || head == "" {
		t.Fatal("collector cannot attest its committed export position", err)
	}
	data, err := os.ReadFile(collector.exportPath)
	if err != nil {
		t.Fatal("read independent collector export", err)
	}
	if _, err := audit.Verify(collector.exportPath); err != nil {
		t.Fatal("independent collector export failed integrity verification", err)
	}
	config := audit.X509ReconcileConfig{
		ExpectedSequence: sequence, ExpectedHash: head,
		ProfileID: f.profile.ID, ObjectID: "poc-pki-ca", Purpose: "openbao-pki-poc",
		KeyFingerprint: f.keyConfig["public_key_sha256"].(string), IssuerDER: f.profile.IssuerDER,
	}
	report, err := audit.ReconcileX509(bytes.NewReader(data), config, f.artifacts)
	if err != nil {
		t.Fatal("real Bao artifacts did not reconcile against collector evidence", err)
	}
	if len(f.artifacts) != 4 || report.Artifacts != 4 || report.MatchedArtifacts != 4 || report.UnattestedArtifacts != 0 || report.Conflicts != 0 {
		t.Fatal("certificate/ACME/CRL artifacts are not all attested by independent evidence", report)
	}
	// Bao signed older CRLs while configuring and rotating the mount. They were
	// legitimately replaced by the current CRL, so incomplete historical inventory
	// is indeterminate and must not be reported as proven unauthorized issuance.
	if report.Status != "indeterminate" || report.IndeterminateRequests == 0 {
		t.Fatal("unavailable older CRLs were not reported as indeterminate", report)
	}
	wrongHead := config
	wrongHead.ExpectedSequence++
	if _, err := audit.ReconcileX509(bytes.NewReader(data), wrongHead, f.artifacts); err == nil {
		t.Fatal("collector export accepted a different authenticated expected head")
	}
	wrongKey := config
	wrongKey.KeyFingerprint = "sha256:" + strings.Repeat("0", 64)
	if _, err := audit.ReconcileX509(bytes.NewReader(data), wrongKey, f.artifacts); err == nil {
		t.Fatal("artifacts accepted against a different independently expected issuer key")
	}
	for _, change := range []struct {
		name  string
		apply func(*audit.X509ReconcileConfig)
	}{
		{"profile", func(c *audit.X509ReconcileConfig) { c.ProfileID = "another-profile" }},
		{"object", func(c *audit.X509ReconcileConfig) { c.ObjectID = "another-object" }},
		{"purpose", func(c *audit.X509ReconcileConfig) { c.Purpose = "another-purpose" }},
	} {
		wrongScope := config
		change.apply(&wrongScope)
		unattested, err := audit.ReconcileX509(bytes.NewReader(data), wrongScope, f.artifacts)
		if err != nil || unattested.MatchedArtifacts != 0 || unattested.UnattestedArtifacts != 4 {
			t.Fatal("artifacts attested to a different configured scope", change.name, unattested, err)
		}
	}
	lastLine := bytes.LastIndex(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) + 1
	if _, err := audit.ReconcileX509(bytes.NewReader(data[:lastLine]), config, f.artifacts); err == nil {
		t.Fatal("truncated collector export accepted")
	}
	withoutArtifacts, err := audit.ReconcileX509(bytes.NewReader(data), config, nil)
	if err != nil || withoutArtifacts.Status != "indeterminate" || withoutArtifacts.IndeterminateRequests < report.IndeterminateRequests+4 {
		t.Fatal("missing legitimate artifacts did not retain uncertainty", withoutArtifacts, err)
	}
	t.Log("Actual Bao certificate, two ACME chains and CRL reconciled to mTLS collector head; unavailable historical CRLs remain indeterminate")
}
