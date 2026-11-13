package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// A PIN OR PLAINTEXT IN A BACKEND ERROR NEVER REACHES THE AUDIT TRAIL (threat model T16, epic #40
// AC3, gap .1.4).
//
// TestCoordinatorHardwareFailureReturnsNoOutput shows the RESPONSE to a backend error carrying a
// PIN is generic. Nothing showed the same for the audit event: the outcome is the fixed string
// "backend-failed" today, so a PIN stays out, but no test would notice a change that put the
// error's text into the trail -- which is exactly where a diagnostic message tends to be added.
// This test drives the real coordinator into a real audit.Recorder and checks every string field
// of every draft, and the journal's bytes on disk.
type capturingAudit struct {
	inner  *audit.Recorder
	drafts []audit.Draft
}

func (value *capturingAudit) Record(ctx context.Context, draft audit.Draft, requireRemote bool) error {
	value.drafts = append(value.drafts, draft)
	return value.inner.Record(ctx, draft, requireRemote)
}

// ackSink acknowledges every event, as a reachable collector does, and keeps what it was sent: a
// requireRemote record with no sink fails closed before the card is reached.
type ackSink struct {
	mu     sync.Mutex
	events []audit.Event
}

func (sink *ackSink) Send(_ context.Context, event audit.Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	return nil
}
func (*ackSink) Ready(context.Context) bool { return true }

// draftStrings returns every string a draft carries, by field name, so a canary in a field added
// later is checked too.
func draftStrings(draft audit.Draft) map[string]string {
	fields := map[string]string{}
	value := reflect.ValueOf(draft)
	for index := 0; index < value.NumField(); index++ {
		name := value.Type().Field(index).Name
		switch field := value.Field(index); field.Kind() {
		case reflect.String:
			fields[name] = field.String()
		case reflect.Slice:
			if field.Type().Elem().Kind() == reflect.String {
				fields[name] = strings.Join(field.Interface().([]string), "\x00")
			}
		}
	}
	return fields
}

func TestABackendErrorCarryingAPINOrPlaintextNeverReachesTheAuditTrail(t *testing.T) {
	const pin = "PIN-CANARY-739151"
	const plaintext = "PLAINTEXT-CANARY-5f1e"
	canaries := []string{pin, plaintext}
	cause := fmt.Errorf("C_Login with %s failed; buffer was %q", pin, plaintext)
	for _, c := range []struct {
		name string
		err  error
	}{
		{"a plain backend error", cause},
		{"an executor error wrapping it", &executor.Error{Code: executor.CodeTimeout, Cause: cause}},
		{"a wrapped error", fmt.Errorf("token: %w", cause)},
	} {
		t.Run(c.name, func(t *testing.T) {
			sink := &ackSink{}
			path := filepath.Join(t.TempDir(), "audit.journal")
			recorder, err := audit.Open(path, sink)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = recorder.Close() })
			capture := &capturingAudit{inner: recorder}
			router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
			// The card returns bytes AND the error: the coordinator must drop both.
			hardware := &fakeHardware{output: []byte(plaintext), err: c.err}
			coordinator, err := New(fakeAuthorizer{allowed: true}, router, &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}}, capture, directRunner{}, hardware, "sha256:policy", nil, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			result, execErr := coordinator.Execute(context.Background(), operationRequest())
			if execErr == nil || result.Data != nil {
				t.Fatalf("Execute() = %#v, %v; want a failure with no data", result, execErr)
			}

			// The drafts and the caller's error first: a leak that also made the recorder refuse the
			// event must still be named here, not hidden behind a control failing below.
			for _, canary := range canaries {
				for index, draft := range capture.drafts {
					for name, text := range draftStrings(draft) {
						if strings.Contains(text, canary) {
							t.Errorf("DEFECT: audit draft %d field %s carries %q: %q", index, name, canary, text)
						}
					}
				}
				if strings.Contains(execErr.Error(), canary) {
					t.Errorf("DEFECT: the error returned to the caller carries %q", canary)
				}
			}
			if errors.Is(execErr, cause) {
				t.Error("DEFECT: the caller's error still wraps the backend's cause")
			}

			// CONTROL: the failure was recorded, through the real recorder, as the backend failure it
			// is, and reached the journal and the sink. Without it an empty trail would pass every
			// byte check below.
			if hardware.calls != 1 || len(capture.drafts) != 2 || !strings.HasPrefix(capture.drafts[1].Outcome, "backend-failed") {
				t.Fatalf("hardware calls = %d, drafts = %#v; want the authorized record and a backend-failed record", hardware.calls, capture.drafts)
			}
			journal, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(journal, []byte(`"backend-failed`)) {
				t.Fatalf("the journal does not hold the backend-failed event, so its bytes prove nothing:\n%s", journal)
			}
			sink.mu.Lock()
			shipped, _ := json.Marshal(sink.events)
			sent := len(sink.events)
			sink.mu.Unlock()
			if sent != 2 {
				t.Fatalf("the sink acknowledged %d events, want 2: the shipped-bytes check below would prove nothing", sent)
			}
			for _, canary := range canaries {
				if bytes.Contains(journal, []byte(canary)) {
					t.Errorf("DEFECT: the audit journal on disk carries %q", canary)
				}
				if bytes.Contains(shipped, []byte(canary)) {
					t.Errorf("DEFECT: an event sent to the audit sink carries %q", canary)
				}
			}
		})
	}
}
