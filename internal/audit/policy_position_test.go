package audit

import (
	"bytes"
	"encoding/json"
	"strings"
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
