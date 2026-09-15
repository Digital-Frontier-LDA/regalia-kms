package operations

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// RELEASE AND SEAL LOG NOTHING (#6 criterion 3, "never logged").
//
// TestTheRequestPathEmitsNoLogs (internal/integration) holds that request handling emits no log
// records, but it drives only certificate-sign, and its stack wires no releaser and no seal path.
// The #6 acceptance audit inserted `slog.Info("secret released", "value", string(plaintext))` into
// secrets.Releaser's Open callback, and the whole module stayed green (measured on b1219f1).
//
// The handler code these two operations share with certificate-sign is already covered there. What
// is specific to them is the coordinator, the real secrets.Releaser and the seal path, so this test
// drives those: a success and a denial of each, under a handler installed where the daemon logs.
//
// Falsifier: the audit's own mutation, slog.Info of the released plaintext in the Releaser's Open
// callback. It fails this test, naming the record.
func TestReleaseAndSealEmitNoLogs(t *testing.T) {
	captured := &logRecorder{}
	previous := slog.Default()
	slog.SetDefault(slog.New(captured))
	t.Cleanup(func() { slog.SetDefault(previous) })

	// The instrument must be able to see the thing: a package-level slog.Info, written the way the
	// daemon writes one, is observed before its silence is trusted.
	slog.Info("instrument check", "detail", "visible")
	if len(captured.take()) != 1 {
		t.Fatal("the recording handler did not observe a package-level slog.Info, so its silence below would mean nothing")
	}

	// release-secret through a real registry and a real releaser: a success, then a denial.
	if data, _, err := releaseAfter(t, `"envelope_max_age_days":30`, 29*24*time.Hour); err != nil || string(data) != "the secret" {
		t.Fatalf("control failed: the release did not succeed (%q, %v), so a silent log would prove nothing", data, err)
	}
	if _, _, err := releaseAfter(t, `"envelope_max_age_days":30`, 31*24*time.Hour); err == nil {
		t.Fatal("control failed: the expired release was not refused")
	}

	// seal-envelope: a success, then a policy denial.
	route := sealRoute()
	ciphertext, nonce, dataKey := assembleSealInputs(t, route, []byte("the secret itself"))
	sealed, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: route},
		&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
		&fakeAudit{}, directRunner{}, &fakeHardware{output: []byte("wrapped-by-the-card")}, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.Execute(context.Background(), sealRequest(route, ciphertext, nonce, dataKey)); err != nil {
		t.Fatalf("control failed: the seal did not succeed: %v", err)
	}
	ciphertext, nonce, dataKey = assembleSealInputs(t, route, []byte("the secret itself"))
	denied, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: route},
		&fakePolicy{decision: policy.Decision{Allowed: false, Code: policy.CodeDenied, PolicyID: "sops", Rule: "deny"}},
		&fakeAudit{}, directRunner{}, &fakeHardware{output: []byte("wrapped-by-the-card")}, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Execute(context.Background(), sealRequest(route, ciphertext, nonce, dataKey)); err == nil {
		t.Fatal("control failed: the denied seal succeeded")
	}

	if leaked := captured.take(); len(leaked) != 0 {
		t.Fatalf("release-secret or seal-envelope emitted %d log record(s); a released or sealed secret must never reach a log:\n  %s",
			len(leaked), strings.Join(leaked, "\n  "))
	}
}

type logRecorder struct {
	mu      sync.Mutex
	records []string
}

func (recorder *logRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (recorder *logRecorder) Handle(_ context.Context, record slog.Record) error {
	line := record.Message
	record.Attrs(func(attr slog.Attr) bool {
		line += fmt.Sprintf(" %s=%v", attr.Key, attr.Value)
		return true
	})
	recorder.mu.Lock()
	recorder.records = append(recorder.records, line)
	recorder.mu.Unlock()
	return nil
}

func (recorder *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return recorder }
func (recorder *logRecorder) WithGroup(string) slog.Handler      { return recorder }

func (recorder *logRecorder) take() []string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	taken := recorder.records
	recorder.records = nil
	return taken
}
