package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type memorySink struct {
	mu     sync.Mutex
	ready  bool
	err    error
	events []Event
}

func (sink *memorySink) Send(_ context.Context, event Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.err != nil {
		return sink.err
	}
	sink.events = append(sink.events, event)
	return nil
}

func (sink *memorySink) Ready(context.Context) bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return sink.ready
}

func draft(requestID, decision string) Draft {
	return Draft{
		Timestamp: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC), RequestID: requestID,
		Principal: "spiffe://regalia/workload/release", Decision: decision,
		ObjectID: "release-signing-key", Purpose: "release-artifact", Operation: "sign",
		DeviceID: "yubikey-sitea", Outcome: "allowed", LatencyMilliseconds: 12,
		RegistryDigest: "sha256:" + strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		RBACDigest: "sha256:" + strings.Repeat("c", 64),
	}
}

func TestRecorderPersistsOrderedIntegrityChainAndShipsOffHost(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{ready: true}
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	for _, item := range []Draft{draft("018f0000-0000-7000-8000-000000000001", "allow"), draft("018f0000-0000-7000-8000-000000000002", "deny")} {
		if err := recorder.Record(context.Background(), item, true); err != nil {
			t.Fatal(err)
		}
	}
	events, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Sequence != 1 || events[1].Sequence != 2 || events[1].PreviousHash != events[0].Hash {
		t.Fatalf("invalid chain: %#v", events)
	}
	if len(sink.events) != 2 || sink.events[1].Hash != events[1].Hash {
		t.Fatalf("off-host events = %#v", sink.events)
	}
}

func TestVerifyDetectsAlteredAndMissingEvents(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"altered": func(value string) string {
			return strings.Replace(value, `"outcome":"allowed"`, `"outcome":"forged"`, 1)
		},
		"missing": func(value string) string {
			lines := strings.Split(strings.TrimSpace(value), "\n")
			return lines[1] + "\n"
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			recorder, err := Open(path, &memorySink{ready: true})
			if err != nil {
				t.Fatal(err)
			}
			_ = recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), true)
			_ = recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000002", "allow"), true)
			_ = recorder.Close()
			contents, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(mutate(string(contents))), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(path); err == nil {
				t.Fatal("Verify() accepted tampered chain")
			}
		})
	}
}

func TestHighRiskRecordFailsClosedAfterDurableLocalAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink := &memorySink{ready: false, err: errors.New("collector down")}
	recorder, err := Open(path, sink)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	err = recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), true)
	if !errors.Is(err, ErrSinkUnavailable) {
		t.Fatalf("Record() error = %v", err)
	}
	if recorder.Ready(context.Background()) {
		t.Fatal("Ready() = true for failed sink")
	}
	if events, verifyErr := Verify(path); verifyErr != nil || len(events) != 1 {
		t.Fatalf("local durable event missing: events=%d err=%v", len(events), verifyErr)
	}
}

func TestRecordRejectsUnsafeMetadataWithoutPersistingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	item := draft("018f0000-0000-7000-8000-000000000001", "allow")
	item.Outcome = "-----BEGIN PRIVATE KEY-----"
	if err := recorder.Record(context.Background(), item, true); err == nil {
		t.Fatal("Record() accepted private material")
	}
	contents, _ := os.ReadFile(path)
	if len(contents) != 0 {
		t.Fatalf("unsafe metadata persisted: %q", contents)
	}
}

// TestValidateDraftRejectsEmptyRBACDigest pins the missing-field pin at the
// lowest layer. The audit trail is what the operator reads back later; a draft
// without an RBAC digest cannot be tied to the policy under which the decision
// was made, and we want to fail the record rather than ship a digest-less event.
//
// Delete-fix scenario: comment out the RBACDigest check in validateDraft. Record
// succeeds; Verify returns the event with RBACDigest == ""; this test fails
// with the explicit DEFECT message.
func TestValidateDraftRejectsEmptyRBACDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	item := draft("018f0000-0000-7000-8000-000000000001", "allow")
	item.RBACDigest = ""
	if err := recorder.Record(context.Background(), item, true); err == nil {
		t.Fatal("DEFECT: Record() accepted draft with empty RBACDigest — audit chain cannot be tied to a policy")
	} else if !strings.Contains(err.Error(), "incomplete audit metadata") {
		t.Fatalf("err = %q, want it to mention incomplete audit metadata", err)
	}
}

// TestEventCarriesRBACDigestThroughRecordAndVerify covers the round trip:
// draft -> event -> persisted line -> re-parsed event. Every hop must carry
// the digest; if Recorder drops it on any leg, the operator's later review
// cannot answer "which RBAC policy authorized this?".
//
// Delete-fix scenario: zero RBACDigest in Recorder.Record's Event literal.
// The re-parsed event has RBACDigest == ""; this test fails.
func TestEventCarriesRBACDigestThroughRecordAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	want := "sha256:" + strings.Repeat("d", 64)
	item := draft("018f0000-0000-7000-8000-000000000001", "allow")
	item.RBACDigest = want
	if err := recorder.Record(context.Background(), item, true); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	events, err := Verify(path)
	if err != nil || len(events) != 1 {
		t.Fatalf("Verify() = %d events, err=%v", len(events), err)
	}
	if events[0].RBACDigest != want {
		t.Fatalf("DEFECT: re-parsed Event.RBACDigest = %q, want %q — Recorder dropped it on the way to disk", events[0].RBACDigest, want)
	}
}

// TestDenialDraftStillCarriesRBACDigest pins the negative-path invariant:
// the deny path is the audit trail the operator reads FIRST when reviewing
// an incident, and a deny without an RBAC digest is exactly the draft that
// is hardest to defend later.
func TestDenialDraftStillCarriesRBACDigest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	want := "sha256:" + strings.Repeat("e", 64)
	item := draft("018f0000-0000-7000-8000-000000000001", "deny")
	item.RBACDigest = want
	item.Outcome = "rbac-denied"
	if err := recorder.Record(context.Background(), item, true); err != nil {
		t.Fatalf("Record() = %v", err)
	}
	events, err := Verify(path)
	if err != nil {
		t.Fatalf("Verify() returned an error after a denial Record(): %v — journal integrity must survive a negative-path write", err)
	}
	if events[0].Decision != "deny" || events[0].RBACDigest != want {
		t.Fatalf("deny Event = %+v", events[0])
	}
}

// TestVerifyRefusesPreRBACDigestEvents pins the upgrade-day incompatibility
// introduced by adding RBACDigest to Event. Hashes are computed by
// json.Marshal-ing the Event struct, and adding any field changes the byte
// stream — even when the field's value is the empty string. A journal written
// by pre-#61 code therefore fails Verify after this PR lands, because the
// stored hash was computed without "rbac_digest" in the projection and the
// new code recomputes it WITH that key.
//
// Delete-fix scenario: change the Event struct's RBACDigest tag to `json:"rbac_digest,omitempty"`
// AND make audit.Event.RBACDigest hash-stable only when non-empty. With both
// fixes, Verify would accept pre-#61 events. Without both, this test passes
// (Verify still refuses them). Future work — pin the decision deliberately
// rather than discover it during an incident.
func TestVerifyRefusesPreRBACDigestEvents(t *testing.T) {
	// preRBACDigestEvent is the Event struct shape used by audit code before
	// RBACDigest was added. It exists only in this test; the production code
	// uses Event with the field. Mirroring it here lets us write a journal
	// line that pre-#61 code would have produced.
	type preRBACDigestEvent struct {
		Sequence            uint64    `json:"sequence"`
		Timestamp           time.Time `json:"timestamp"`
		RequestID           string    `json:"request_id"`
		Principal           string    `json:"principal"`
		Decision            string    `json:"decision"`
		ObjectID            string    `json:"object_id,omitempty"`
		Purpose             string    `json:"purpose,omitempty"`
		Operation           string    `json:"operation"`
		DeviceID            string    `json:"device_id,omitempty"`
		Outcome             string    `json:"outcome"`
		LatencyMilliseconds int64     `json:"latency_ms"`
		RegistryDigest      string    `json:"registry_digest"`
		PolicyDigest        string    `json:"policy_digest"`
		PreviousHash        string    `json:"previous_hash"`
		Hash                string    `json:"hash"`
	}
	event := preRBACDigestEvent{
		Sequence: 1, Timestamp: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
		RequestID: "018f0000-0000-7000-8000-000000000001",
		Principal: "spiffe://regalia/workload/release", Decision: "allow",
		ObjectID: "release-signing-key", Operation: "sign", DeviceID: "yubikey-sitea",
		Outcome: "success", LatencyMilliseconds: 5,
		RegistryDigest: "sha256:" + strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64),
	}
	// Hash is computed by zeroing Hash, marshaling, sha256'ing, and re-stamping.
	// This is what the old `eventHash(event)` did; doing it the same way here
	// reproduces the bytes-on-disk exactly so the journal line matches what a
	// pre-#61 daemon would have written.
	event.Hash = ""
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	event.Hash = "sha256:" + hex.EncodeToString(sum[:])

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	if events, err := Verify(path); err == nil {
		t.Fatalf("DEFECT: pre-#61 event was accepted by post-#61 Verify — back-compat now exists and this test should be updated to capture it as deliberate rather than compat-by-accident: %+v", events)
	} else if !strings.Contains(err.Error(), "audit chain integrity check failed") {
		t.Fatalf("Verify() returned %q, want the chain-integrity message", err)
	}
}

// ADDING THIS FIELD MUST NOT BREAK EVERY JOURNAL WRITTEN BEFORE IT.
//
// Event hashes are computed over json.Marshal of the struct, so adding a field changes the
// byte stream and every earlier event fails Verify. RBACDigest did exactly that, which
// TestVerifyRefusesPreRBACDigestEvents pins as a deliberate upgrade-day cost.
//
// VerifiedApprovers is omitempty precisely so it does not repeat that. Almost no operation
// carries approvals, so almost every event must marshal to the bytes it did before. This
// asserts the property the comment on the field claims, rather than leaving a compatibility
// guarantee resting on a struct tag nobody exercised.
func TestAnEventWithoutApproversMarshalsWithoutTheField(t *testing.T) {
	var event Event
	event.RequestID = "018f0000-0000-7000-8000-00000000000a"
	event.RegistryDigest, event.PolicyDigest, event.RBACDigest = "sha256:aa", "sha256:bb", "sha256:cc"

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("verified_approvers")) {
		t.Fatalf("DEFECT: an event with no approvals still carries verified_approvers, so every "+
			"journal written before this change now fails Verify:\n%s", encoded)
	}

	event.VerifiedApprovers = []string{"spiffe://regalia/approver/treasury"}
	withApprovers, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(withApprovers, []byte("verified_approvers")) {
		t.Fatal("an event WITH approvals omitted the field: omitempty is dropping real evidence, " +
			"and the check above would then pass for the wrong reason")
	}
}

// #315. A caller counting LOST audit records has to tell "the write failed" from "the write
// succeeded and the collector has not acknowledged it yet". Record returns an error in both cases,
// and its sequence advances only after Write and Sync both succeed — so three of its failure
// returns happen with the event already on disk. Durable is what separates them, and these tests
// exercise the real Record rather than a hand-built error: a coordinator-side test that constructs
// the wrapped error itself cannot notice if Record stops wrapping.

func TestDurableIsTrueWhenTheEventReachedTheJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	// No shipper configured AND requireRemote: Record reaches its post-write return.
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()

	recordErr := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), true)

	if recordErr == nil {
		t.Fatal("Record() must still fail closed for a high-risk operation with no sink")
	}
	// PAIRED. "Durable says true" is worthless without "the event is actually there" — a Durable
	// that returned true unconditionally would satisfy the first half alone.
	if !Durable(recordErr) {
		t.Fatalf("Durable(%v) = false, but the event was written and synced before this return; a "+
			"caller counting dropped records will count one that is on disk and will ship", recordErr)
	}
	events, verifyErr := Verify(path)
	if verifyErr != nil || len(events) != 1 {
		t.Fatalf("the event is not in the journal after a Durable error: events=%d err=%v", len(events), verifyErr)
	}
	// The wrap must not hide the cause the existing callers match on.
	if !errors.Is(recordErr, ErrSinkUnavailable) {
		t.Fatalf("marking the error durable lost ErrSinkUnavailable: %v", recordErr)
	}
}

func TestDurableIsFalseWhenTheWriteItselfFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	if err := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), false); err != nil {
		t.Fatal(err)
	}

	// Close the descriptor WITHOUT setting the closed flag, so Record reaches Write and fails
	// there — the one place the event does not become durable. Setting the flag instead would
	// short-circuit before the write and test a different branch.
	recorder.mu.Lock()
	_ = recorder.file.Close()
	recorder.mu.Unlock()

	recordErr := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000002", "deny"), false)

	if recordErr == nil {
		t.Fatal("Record() succeeded with a closed descriptor")
	}
	if Durable(recordErr) {
		t.Fatalf("Durable(%v) = true for a failed write; a caller counting dropped records would "+
			"exclude a record that genuinely never reached the journal — the exact loss this "+
			"distinction exists to keep visible", recordErr)
	}
	events, verifyErr := Verify(path)
	if verifyErr != nil || len(events) != 1 {
		t.Fatalf("the journal should hold only the first event: events=%d err=%v", len(events), verifyErr)
	}
}

// The SECOND post-write return: a shipper exists, the event is enqueued, and the remote
// acknowledgement does not arrive. Distinct from the no-shipper case above — that one returns the
// sentinel directly, this one returns whatever waitShipped produced — so removing either wrap must
// fail a test, and with only one of these it did not.
func TestDurableIsTrueWhenOnlyTheRemoteAcknowledgementFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: false, err: errors.New("collector down")})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()

	recordErr := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), true)

	if recordErr == nil {
		t.Fatal("Record() must fail closed when a high-risk event cannot be acknowledged")
	}
	if !Durable(recordErr) {
		t.Fatalf("Durable(%v) = false: the event was written, synced and queued — only the "+
			"acknowledgement is missing, and it ships when the collector recovers", recordErr)
	}
	if events, verifyErr := Verify(path); verifyErr != nil || len(events) != 1 {
		t.Fatalf("the queued event is not in the journal: events=%d err=%v", len(events), verifyErr)
	}
}

// The THIRD post-write return, and the last of the three. The event is written and synced, and the
// high-water sidecar write is what fails — so the journal holds the event while Record reports an
// error. Induced by putting a DIRECTORY where the sidecar goes, which fails the write for any uid:
// chmod would not, because root ignores mode bits and CI containers run as root.
func TestDurableIsTrueWhenOnlyTheHighWaterMarkFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, &memorySink{ready: true})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	if err := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000001", "allow"), false); err != nil {
		t.Fatal(err)
	}

	mark := path + highWaterSuffix
	if err := os.RemoveAll(mark); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mark, 0o755); err != nil {
		t.Fatal(err)
	}
	// The control: prove the obstruction actually blocks the write, so a passing test cannot mean
	// "the sidecar wrote fine and Record never errored".
	if err := writeAuditHighWater(path, highWaterMark{Sequence: 99, Hash: "x"}); err == nil {
		t.Fatal("the planted directory did not block the high-water write; this test would pass vacuously")
	}

	recordErr := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000002", "deny"), false)

	if recordErr == nil {
		t.Fatal("Record() ignored a failed high-water write")
	}
	if !Durable(recordErr) {
		t.Fatalf("Durable(%v) = false: the event was written and synced before the sidecar was "+
			"attempted, so it is in the journal and counting it as lost over-reports", recordErr)
	}
	if events, verifyErr := Verify(path); verifyErr != nil || len(events) != 2 {
		t.Fatalf("both events should be in the journal: events=%d err=%v", len(events), verifyErr)
	}
}
