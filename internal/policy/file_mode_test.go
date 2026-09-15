package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The audit recorder's guard, one package over, with the same diagnostic and the same original
// overstatement -- so the same regression test, because fixing one occurrence and testing only
// that one leaves the other free to drift back.
//
// The invariant is the group and other MODE BITS being clear. Not "no other user can reach it":
// a POSIX ACL can grant access those bits do not show. The message must not claim more than the
// check performs, which is the whole point of the change this pins.
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
		{0o400, false, "owner cannot write, so the append-only open fails first"},
	} {
		t.Run(test.why, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy-state.jsonl")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			state, err := OpenFileState(path)
			if err == nil {
				defer state.Close()
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

// The mode refusal describes the mode, and nothing else does.
//
// The guard used to read `if err != nil || !info.Mode().IsRegular() || ...`, so a failed Stat
// produced a mode diagnostic and sent whoever read it to check permissions that were never the
// cause. That branch is now split, as audit.Open already had it.
//
// WHAT THIS DOES NOT COVER, STATED BECAUSE THE NAME WOULD OTHERWISE IMPLY IT: the Stat failure
// itself is not exercised. Stat on a descriptor that just opened successfully does not fail in
// any way this test can portably induce, so re-merging the two branches would leave this green.
// What is pinned is the reachable half -- the mode refusal names the mode and is not dressed as
// a stat failure -- and the split is left to review.
func TestTheModeRefusalDescribesTheMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "policy-state.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatalf("a well-formed state file was refused: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	// The reachable half of the claim: the mode diagnostic is only produced by the mode guard,
	// so it names the mode when and only when the mode is what is wrong.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err = OpenFileState(path)
	if err == nil {
		t.Fatal("a group-readable policy state was accepted")
	}
	if !strings.Contains(err.Error(), "permission bits") {
		t.Errorf("the mode refusal does not describe the mode: %v", err)
	}
	if strings.Contains(err.Error(), "stat policy state") {
		t.Errorf("a mode problem was reported as a stat failure: %v", err)
	}
}
