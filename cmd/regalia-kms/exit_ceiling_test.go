// Package main — the entrypoint's failure paths must be OBSERVABLE, not fatal.
//
// WHY THIS FILE EXISTS (#384). Seven paths inside run() ended in os.Exit(1). os.Exit kills the
// TEST BINARY, so a test could observe *that* something went wrong and never *what*: `go test`
// reported the package as failed and named nothing at all. Measured on main.go:100 and main.go:147,
// a mutation on the guard above produced "package FAIL, 0 named failures", which a harness reading
// "exit code non-zero" as a kill records as a detection that does not exist. Fourteen operands of
// the #237 sweep sit behind these paths.
//
// That is distinct from a panic in the way that matters: a panic prints a stack naming the test and
// the line; os.Exit leaves nothing.
//
// Every test here REACHES AN ASSERTION. That is the whole claim — before this change the process
// died first, so the assertion could not run. These tests therefore fail by vanishing (no named
// failure) if the os.Exit calls come back, which is exactly the signature the issue describes.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAFailingSubcommandReturnsInsteadOfKillingTheProcess drives each path that used to call
// os.Exit(1) and asserts the failure can be NAMED. The table is the seven sites; the two that need
// a crafted tree have their own tests below.
func TestAFailingSubcommandReturnsInsteadOfKillingTheProcess(t *testing.T) {
	for _, c := range []struct {
		name  string
		args  []string
		label string // the operator-facing text the runbooks grep for
	}{
		{
			name:  "verify-audit on a missing journal",
			args:  []string{"-verify-audit", "/nonexistent/audit.journal"},
			label: "audit verification FAILED",
		},
		{
			name:  "verify-policy-state on a missing journal",
			args:  []string{"-verify-policy-state", "/nonexistent/policy.journal"},
			label: "policy state verification FAILED",
		},
		{
			name:  "inspect-export on a missing envelope",
			args:  []string{"-inspect-export", "/nonexistent/export.json", "-authority-key-pem", "/nonexistent/authority.pem"},
			label: "export inspection FAILED",
		},
		{
			name:  "scan-tree on a root that cannot be walked",
			args:  []string{"-scan-tree", "/nonexistent/tree"},
			label: "tree scan FAILED",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := driveRun(t, c.args...)
			if err == nil {
				t.Fatalf("run(%v) returned nil — the failure was neither reported nor returned", c.args)
			}
			// The sentinel is what tells main() the operator line is already on stderr, so asserting
			// it pins the contract that keeps the runbooks' quoted output intact.
			if !errors.Is(err, errAlreadyReported) {
				t.Errorf("run(%v) error is not marked already-reported: %v\nmain() would print a second, differently-shaped line and displace the one the runbooks tell operators to read", c.args, err)
			}
			if !strings.Contains(err.Error(), c.label) {
				t.Errorf("run(%v) error does not name %q: %v", c.args, c.label, err)
			}
		})
	}
}

// TestTheOperatorLineSurvivesTheRefactor is the runbook contract, asserted rather than assumed.
// doc/RUNBOOK-KMS-OPERATOR.md quotes `audit verification FAILED: …` inside a fenced block and
// doc/RUNBOOK-DISASTER-RECOVERY.md says to "read the last line, not the exit code alone". Moving
// the text into main()'s slog call would have kept the substring while changing the line, so this
// checks the stream, not the error value.
func TestTheOperatorLineSurvivesTheRefactor(t *testing.T) {
	captured := filepath.Join(t.TempDir(), "stderr")
	file, err := os.Create(captured)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = file
	t.Cleanup(func() { os.Stderr = saved })

	runErr := driveRun(t, "-verify-audit", "/nonexistent/audit.journal")
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stderr = saved
	if runErr == nil {
		t.Fatal("expected a failure")
	}

	written, err := os.ReadFile(captured)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(written), "\n"), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "audit verification FAILED: ") {
		t.Errorf("the LAST stderr line is %q; the runbooks tell operators to read the last line and quote it as `audit verification FAILED: …`", last)
	}
}

// TestScanTreeRefusesWithACountRatherThanExitingSilently covers the one site whose failure is not a
// wrapped error: the per-finding lines are the operator output, and the old code just exited after
// printing them, so nothing could assert that the scan had refused OR how much it found.
func TestScanTreeRefusesWithACountRatherThanExitingSilently(t *testing.T) {
	tree := t.TempDir()
	// A directory named "credentials" is a finding by itself (Shape: credential-directory), so this
	// needs no entropy fixture and cannot drift with the content heuristics.
	if err := os.Mkdir(filepath.Join(tree, "credentials"), 0o700); err != nil {
		t.Fatal(err)
	}

	err := driveRun(t, "-scan-tree", tree)
	if err == nil {
		t.Fatal("a tree holding a credentials directory must not pass the scan")
	}
	if !errors.Is(err, errAlreadyReported) {
		t.Errorf("the refusal is not marked already-reported: %v", err)
	}
	if !strings.Contains(err.Error(), "secret-shaped finding") {
		t.Errorf("the refusal does not say what it found: %v", err)
	}
}

// TestACleanTreePassesSoTheRefusalAboveMeansSomething is the control. Without it the test above
// passes for a scanner that refuses everything, including a tree with nothing in it.
func TestACleanTreePassesSoTheRefusalAboveMeansSomething(t *testing.T) {
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "notes.txt"), []byte("nothing secret here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := driveRun(t, "-scan-tree", tree); err != nil {
		t.Fatalf("a clean tree must pass, else the refusal above proves nothing: %v", err)
	}
}
