package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE STRONGEST INTEGRITY CHECK MUST BE SEEN TO RUN, NOT JUST TO PASS.
//
// `-verify-audit` answers when an operator asks. Between asks, nothing watches:
// a journal corrupted after startup verifies clean at the next startup only if
// anyone restarts. The daemon therefore verifies its own durable journal prefix
// periodically, and the outcome distinguishes "the chain is broken" from "the
// verifier could not run" — a permission error pages operations, a broken chain
// pages security, and neither may look like the other.
func TestPeriodicVerifierDetectsCorruptionBetweenChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"018f0000-0000-7000-8000-00000000000a", "018f0000-0000-7000-8000-00000000000b"} {
		record(t, recorder, id)
	}
	// Open's startup verification seeds the state, so a verifier that never ticks
	// still goes stale rather than absent. The seed covers what startup verified:
	// an empty fresh journal, not the events recorded below.
	boot := recorder.VerifyState()
	if boot.Outcome != VerifyIntact || boot.Events != 0 || boot.At.IsZero() {
		t.Fatalf("startup state = %+v, want intact over the empty fresh journal", boot)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	recorder.StartVerifier(ctx, 10*time.Millisecond)
	defer recorder.Close()

	waitForShip(t, "the verifier never re-ran after startup: a periodic check that does not ask proves nothing", func() bool {
		return recorder.VerifyState().At.After(boot.At)
	})

	// Corrupt the journal between checks: rewrite an outcome field in place.
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	altered := strings.Replace(string(contents), `"outcome":"allowed"`, `"outcome":"forged_"`, 1)
	if altered == string(contents) {
		t.Fatal("the fixture did not alter the journal: the test would pass while checking nothing")
	}
	if err := os.WriteFile(path, []byte(altered), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForShip(t, "an in-place alteration of the journal was never detected: the verifier is not watching", func() bool {
		return recorder.VerifyState().Outcome == VerifyChainBroken
	})
}

// A VERIFIER THAT CANNOT READ IS NOT A BROKEN CHAIN.
//
// Both are failures, but they page different people. The unreadable case also
// covers the verifier never being able to start: no run may masquerade as intact.
func TestVerifierDistinguishesUnreadableFromBroken(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")
	defer recorder.Close()

	// chmod the parent directory: chmod 000 on the FILE does not reliably break
	// os.Stat, but a permissionless directory breaks opening anything under it.
	if err := os.Chmod(directory, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(directory, 0o700) }()

	recorder.VerifyNow(context.Background())
	state := recorder.VerifyState()
	if state.Outcome != VerifyUnreadable {
		t.Fatalf("an unreadable journal reported %q: a permission error must not page as a broken chain", state.Outcome)
	}
}

// A STOPPED VERIFIER MUST GO STALE.
//
// The alert that fires when the check has not run in two intervals exists because
// the verifier stopping silently is the blind spot the loop exists to close. The
// state must keep its last outcome and stop advancing.
func TestStoppedVerifierStopsAdvancing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The recorder needs the same treatment as the context below: a t.Fatal between here and the
	// end of the test would leave it open, and the trailing Close() was on the success path only.
	//
	// BUT THE CLEANUP MUST NOT RUN WHEN THE VERIFIER IS STUCK. Close() waits on the same
	// WaitGroup, unbounded (audit.go:426). If the goroutine is not exiting, a cleanup that closes
	// hangs the package -- turning the bounded failure below into exactly the ten-minute timeout
	// the bound exists to prevent. Measured, with cancellation mutated away: the package timed out
	// at 40s and the 5s message never printed at all, so the failure reported as infrastructure
	// trouble instead of naming the defect. Review caught this; my earlier falsification did not,
	// because it predated the cleanup and I did not re-run it after adding one.
	verifierExited := false
	t.Cleanup(func() {
		if !verifierExited {
			return // Close would block on the goroutine we have just proven is stuck
		}
		_ = recorder.Close()
	})
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")
	boot := recorder.VerifyState()
	ctx, cancel := context.WithCancel(context.Background())
	// defer AND the explicit cancel below: waitForShip can t.Fatal, and without this the
	// verifier goroutine would outlive the test and keep writing for the rest of the package
	// run — a leak that shows up as an unrelated test flaking, which is how this one was found.
	// context.CancelFunc is idempotent, so the deliberate cancel() below still reads as the
	// event the test is about.
	defer cancel()
	recorder.StartVerifier(ctx, 10*time.Millisecond)
	waitForShip(t, "the verifier never re-ran after startup", func() bool {
		return recorder.VerifyState().At.After(boot.At)
	})
	// CANCEL SIGNALS; IT DOES NOT WAIT. The verifier may be inside VerifyNow when the context is
	// cancelled, and that iteration finishes before the loop sees Done and returns. Reading the
	// timestamp immediately after cancel() therefore races the final write: this test failed in
	// CI on 2026-09-06 with the two samples 6.7ms apart, and reproduces locally at roughly one
	// run in three under `go test -race ./...` load while passing 60/60 unloaded.
	//
	// The fix is not a longer sleep. The goroutine signals its own exit through verifyWg, so
	// quiescence is KNOWABLE rather than guessable, and this test is in-package and can wait on
	// it. Bounded, because an unbounded Wait on a loop that ignored cancellation would hang until
	// the package timeout and report as an infrastructure problem instead of naming the defect.
	cancel()
	stopped := make(chan struct{})
	go func() { recorder.verifyWg.Wait(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the verifier goroutine was still running 5s after its context was cancelled — cancellation is not being observed, and a dead verifier would look like a live one")
	}
	verifierExited = true // only now is Close() guaranteed not to block

	// Only now is the last write guaranteed to have landed. Anything that moves the timestamp
	// from here is a writer that outlived cancellation.
	last := recorder.VerifyState().At
	time.Sleep(50 * time.Millisecond)
	if got := recorder.VerifyState().At; !got.Equal(last) {
		t.Fatalf("verify timestamp advanced after the verifier exited: %s -> %s — something is still writing verification state", last, got)
	}
}

// A READ FAILURE IS NOT A BROKEN CHAIN — AND THE WHOLE FEATURE IS THE DISTINCTION.
//
// verifyEvents returns two kinds of error: integrity failures (the bytes are not
// the chain that was written) and I/O failures (the bytes could not be read).
// They page different people: chain-broken means tampering or a daemon bug and is
// a security incident; unreadable means disk or permissions and is operations. A
// verifier that reports "corrupted" for a journal it could not read sends the
// wrong person, and the wrong person concludes there is a security incident.
func TestVerifierClassifiesAReadFailureAsUnreadableNotBroken(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")
	defer recorder.Close()

	// Replace the journal with a directory: opening it succeeds, reading it fails
	// mid-scan. The failure is I/O, and the classification must say so.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	state := recorder.VerifyNow(context.Background())
	if state.Outcome != VerifyUnreadable {
		t.Fatalf("a journal that could not be read reported %q: a disk or permission problem would page as a security incident", state.Outcome)
	}
}

// A DELETED JOURNAL MUST NOT PANIC VERIFYNOW.
//
// os.Open returns *os.File or an error; the if-check at verifier.go:74 catches
// the error and returns before the deferred file.Close runs on a nil *os.File,
// which would panic. The bug at verifier.go:74[0] is exactly that bypass: pass
// the err, proceed to defer file.Close(), panic on close. Measured: with the
// check removed, this test panics inside VerifyNow and the package reports an
// infrastructure failure instead of the missing check.
//
// Deleting the journal makes os.Open fail with ErrNotExist — a path the
// existing permission/chmod tests do not exercise on macOS, where chmod 000 on
// a parent directory does not always stop os.Open on the file.
func TestVerifyNowOnAMissingJournalReturnsUnreadableRatherThanPanicking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")

	if err := os.Remove(path); err != nil {
		t.Fatalf("remove journal: %v", err)
	}

	// No assertion needed; if VerifyNow panics, the test fails. The Outcome
	// assertion pins the contract too — a deletion is an unreadable journal,
	// not a broken chain.
	state := recorder.VerifyNow(context.Background())
	if state.Outcome != VerifyUnreadable {
		t.Fatalf("a deleted journal reported %q: an absent file is operations, not security", state.Outcome)
	}
}

// STARTING THE VERIFIER TWICE MUST BE A NO-OP.
//
// verifier.go:127's guard refuses a second StartVerifier on the same recorder:
// one verifier per recorder. Two loops means two reads on every tick, and the
// loop contexts are siblings — recorder.verifyStop is the second stop, so on
// Close the first loopCtx outlives shutdown and verifyWg.Wait() blocks on the
// leaked goroutine.
//
// The proof has to come via Close(), because both loop contexts derive from
// the parent context — cancelling it exits both, even when two goroutines are
// running, and the bug is invisible at that point. Close() is what calls only
// recorder.verifyStop, so it is where the leak shows. The test asserts
// Close() returns within a bounded time: with the guard intact, both goroutines
// exit together; with the guard bypassed, one leaks and Close() blocks.
func TestStartVerifierTwiceIsANoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	recorder.StartVerifier(ctx, 100*time.Millisecond)
	recorder.StartVerifier(ctx, 100*time.Millisecond)

	// Bounded Close — the test is the wall-clock time. With a single goroutine
	// the verifyWg drains in microseconds; with two, the first loopCtx outlives
	// recorder.verifyStop and verifyWg.Wait() blocks until the test timeout.
	done := make(chan error, 1)
	go func() { done <- recorder.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return 5s after the second StartVerifier — the first verifier loop outlived recorder.verifyStop, which is exactly what the guard at verifier.go:127 is supposed to prevent")
	}
}
