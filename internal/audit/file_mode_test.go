package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE DIAGNOSTIC MUST DESCRIBE THE CHECK, NOT A STRICTER ONE.
//
// The guard is `IsRegular() && Perm()&0o077 == 0` -- a regular file whose group and other mode
// bits are clear. Not "no other user can reach it": a POSIX ACL can grant access those bits do
// not show, so that phrasing would overstate the check in the same way the original did.
// It said "must be a mode-0600 regular file", which is a different and narrower claim: 0700
// passes. That reached an operator runbook, where it would have sent someone to "fix" a file
// that was already acceptable, during an incident.
//
// The wording is not the interesting part. A message that overstates its check is a claim
// nothing verifies, and the accepted set is what an operator actually needs, so the set is
// pinned here rather than the sentence.
func TestTheAcceptedFileModesAreTheOnesTheMessageDescribes(t *testing.T) {
	for _, test := range []struct {
		mode     os.FileMode
		accepted bool
		why      string
	}{
		{0o600, true, "the documented mode"},
		{0o700, true, "owner bits are not constrained: the guard is the group and other mode bits"},
		{0o640, false, "group can read"},
		{0o604, false, "other can read"},
		{0o660, false, "group can write"},
		// Refused, but by the open rather than the mode check: the recorder opens O_WRONLY, so a
		// read-only buffer never reaches the guard. Pinned because "no group or other access"
		// reads as though 0400 would be fine, and an operator setting it would find the daemon
		// unable to start with an error about permissions rather than about the mode.
		{0o400, false, "owner cannot write, so the append-only open fails first"},
	} {
		t.Run(test.why, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.jsonl")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			recorder, err := Open(path, nil)
			if err == nil {
				defer recorder.Close()
			}
			if accepted := err == nil; accepted != test.accepted {
				t.Fatalf("mode %04o accepted=%v, want %v (%s): err=%v",
					test.mode.Perm(), accepted, test.accepted, test.why, err)
			}
			if err != nil && strings.Contains(err.Error(), "mode-0600") {
				t.Errorf("the refusal still claims mode-0600 while %04o is accepted: %v", 0o700, err)
			}
		})
	}
}
