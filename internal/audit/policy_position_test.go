package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// A policy position (epic #40 gap .1.2) is both a sequence and a sha256 hash, or neither: a
// sequence with no hash could not be checked against the journal, and a hash with no sequence names
// no reservation.
func TestAPolicyPositionIsBothFieldsOrNeither(t *testing.T) {
	hash := "sha256:" + strings.Repeat("ab", 32)
	for _, c := range []struct {
		name     string
		sequence uint64
		hash     string
		valid    bool
	}{
		{"control: neither", 0, "", true},
		{"control: both", 7, hash, true},
		{"a sequence without a hash", 7, "", false},
		{"a hash without a sequence", 0, hash, false},
		{"a hash that is not sha256", 7, "md5:" + strings.Repeat("ab", 16), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			draft := validDraft(1)
			draft.PolicySequence, draft.PolicyHash = c.sequence, c.hash
			if err := validateDraft(draft); (err == nil) != c.valid {
				t.Fatalf("validateDraft(sequence %d, hash %q) = %v, want valid=%v", c.sequence, c.hash, err, c.valid)
			}
		})
	}
}

// An event with no position marshals to exactly the bytes it did before the fields existed, so
// every journal written before them still verifies (the RBACDigest lesson; VerifiedApprovers').
func TestAnEventWithoutAPolicyPositionKeepsItsBytes(t *testing.T) {
	encoded, err := json.Marshal(Event{Sequence: 1, Outcome: "authorized"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("policy_sequence")) || bytes.Contains(encoded, []byte("policy_hash")) {
		t.Fatalf("an event without a policy position marshals the new fields: %s", encoded)
	}
}

// committedSink acknowledges every event; CommittedHead reports the first `committed` of them (all
// when committed < 0), as a collector whose durable copy ends there.
type committedSink struct {
	mu        sync.Mutex
	events    []Event
	committed int
}

func (sink *committedSink) Send(_ context.Context, event Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	return nil
}
func (*committedSink) Ready(context.Context) bool { return true }
func (sink *committedSink) CommittedHead(context.Context, string) (uint64, string, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	count := len(sink.events)
	if sink.committed >= 0 && sink.committed < count {
		count = sink.committed
	}
	if count == 0 {
		return 0, "", nil
	}
	return sink.events[count-1].Sequence, sink.events[count-1].Hash, nil
}

// THE GREATEST ACKNOWLEDGED POLICY HEAD WINS, NOT THE LAST ONE (#720 review).
//
// The coordinator reads the policy head when it builds the authorized record, and that read is
// not serialized with Record: A reads head 1, B reserves and records head 2, then A records head
// 1. The collector then holds [2, 1]. Reading the last position would return 1 while 2 is
// acknowledged, and a journal restored to reservation 1 would pass RequireAcknowledged: the
// nonces and quota of reservation 2 would be spendable again.
func TestTheGreatestAcknowledgedPolicyHeadWinsNotTheLast(t *testing.T) {
	positionHash := func(n int) string { return "sha256:" + strings.Repeat(fmt.Sprintf("%02x", n), 32) }
	for _, c := range []struct {
		name      string
		positions []uint64 // the policy sequence each authorized record carries, in append order; 0 = none
		committed int      // how many of them the collector holds durably; -1 = all
		want      uint64
	}{
		{"control: heads in order", []uint64{1, 2}, -1, 2},
		{"heads acknowledged out of order: 2 then 1", []uint64{2, 1}, -1, 2},
		{"out of order around a record without a head", []uint64{3, 0, 1, 2}, -1, 3},
		{"a greater head the collector has not committed is not read", []uint64{1, 3}, 1, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			sink := &committedSink{committed: c.committed}
			recorder, err := Open(path, sink)
			if err != nil {
				t.Fatal(err)
			}
			for index, sequence := range c.positions {
				record := validDraft(index)
				if sequence > 0 {
					record.PolicySequence, record.PolicyHash = sequence, positionHash(int(sequence))
				}
				if err := recorder.Record(context.Background(), record, true); err != nil {
					t.Fatal(err)
				}
			}
			if err := recorder.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := AcknowledgedPolicyPosition(context.Background(), path, sink, "")
			if err != nil {
				t.Fatal(err)
			}
			if got.Sequence != c.want || got.Hash != positionHash(int(c.want)) {
				t.Fatalf("DEFECT: acknowledged heads %v (collector holds %d) gave position %d %q, want %d: the greatest acknowledged head must win",
					c.positions, c.committed, got.Sequence, got.Hash, c.want)
			}
		})
	}
}
