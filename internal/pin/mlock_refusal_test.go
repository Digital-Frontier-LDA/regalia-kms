package pin

// A CREDENTIAL WHOSE PAGES CANNOT BE LOCKED INTO RAM MUST NOT BE RETURNED, and nothing tested it.
// Defeating the Mlock refusal left the whole kms module green — 25 packages, zero failures — while
// PIN handed back the plaintext credential on swappable pages:
//
//	guard intact    PIN -> value=""        err="PIN credential unavailable"
//	guard defeated  PIN -> value="123456"  err=<nil>
//
// Nothing downstream catches it. nitrokey/provider.go and yubikey/provider.go both gate only on
// `err != nil || len(pin) < 6 || len(pin) > 64`, and the defeated case returns err=nil with len=6,
// so the provider accepts a credential the kernel was never asked to pin.
//
// WHY THIS TEST GATES ON GOOS. The guard can only fire where mlock can fail for the buffer PIN
// actually locks, and that is a platform property, not something the test can detect in-process.
// Measured on both:
//
//	linux   RLIMIT_MEMLOCK=0 -> mlock fails, with or without CAP_IPC_LOCK; PIN refuses
//	darwin  RLIMIT_MEMLOCK=0 -> a direct mlock of a fresh page fails, yet PIN's own small buffer
//	                            locks anyway and the guard never fires
//
// So a probe mlock is NOT a usable gate: on darwin it fails while PIN succeeds, which is exactly
// the shape that made the first version of this test report a defect that was not there. The
// probe is kept below as an instrument check on Linux, where it is predictive.
//
// A plain t.Skip there would be a pass, and this repository has already been bitten by that (#277,
// a skipped SOPS interop test that gated nothing until it was made a hard failure under a
// purpose-named variable).
//
// WHAT THE VARIABLE ACTUALLY DOES, precisely, because the first version of this comment overstated
// it: on linux the test always runs, set or not — the measurement says the guard fires there, so
// there is nothing to gate. The variable's single job is to turn the non-linux SKIP into a FAILURE.
// It is set on the linux CI step so that if that step ever stops being linux — a runner change, a
// container swap — the skip is loud instead of silent. It does not decide whether the check runs;
// it decides whether NOT running is allowed to pass.

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// expectMlockEnforced marks an environment as one where this test must not be skipped. It has no
// effect on linux, where the test runs regardless; it converts the non-linux skip into a failure.
const expectMlockEnforced = "REGALIA_EXPECT_MLOCK_ENFORCED"

func TestACredentialWhosePagesCannotBeLockedIsRefused(t *testing.T) {
	expected := false
	if raw := os.Getenv(expectMlockEnforced); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("%s=%q is not a boolean — an unparseable value must not read as \"not expected\"", expectMlockEnforced, raw)
		}
		expected = parsed
	}

	if runtime.GOOS != "linux" {
		if expected {
			t.Fatalf("%s is set but GOOS is %s, where PIN's buffer locks even at RLIMIT_MEMLOCK=0 and the "+
				"guard cannot fire — the check that was expected to run did not", expectMlockEnforced, runtime.GOOS)
		}
		t.Skipf("GOOS is %s, where PIN's buffer locks even at RLIMIT_MEMLOCK=0, so this test would pass "+
			"without exercising the guard; set %s=1 on linux to require it", runtime.GOOS, expectMlockEnforced)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("123456"), 0o400); err != nil {
		t.Fatal(err)
	}
	source, err := NewLockedFileSource(map[string]string{"hsm": path})
	if err != nil {
		t.Fatal(err)
	}

	// ANCHOR, before touching any limit: this credential must be served. Without it a refusal
	// below could come from the fixture's shape — mode, owner, length, content — rather than from
	// the locking failure this test names.
	value, err := source.PIN(context.Background(), "hsm")
	if err != nil || string(value) != "123456" {
		t.Fatalf("anchor: PIN over a well-formed credential = (%q, %v), want the credential and no error", value, err)
	}
	// Release it. PIN returns LOCKED pages holding plaintext, and leaving them locked would
	// outlive this test in the package's process — and would change the very thing measured
	// below, since already-locked pages are charged against RLIMIT_MEMLOCK.
	if err := source.Release(value); err != nil {
		t.Fatalf("anchor: releasing the credential failed: %v", err)
	}

	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Fatalf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: limit.Max}); err != nil {
		t.Fatalf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}
	defer func() {
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			t.Errorf("could not restore RLIMIT_MEMLOCK: %v — later tests in this process run under a lowered limit", err)
		}
	}()

	// PROVE THE INSTRUMENT. On Linux a refusal below means nothing unless the lowered limit
	// actually reached the kernel.
	//
	// The probe is two pages wide and every page is written before the call, for two reasons.
	// mlock accounts by PAGE, not by byte, so a short slice makes the charge depend on where
	// the allocator happened to place it — it can land inside a page the process has already
	// locked, and then a success would say nothing about the limit. Two pages guarantee at
	// least one page belongs to no one else, and touching them faults them in so the kernel
	// must account for resident pages rather than for a mapping it may defer.
	pageSize := os.Getpagesize()
	probe := make([]byte, 2*pageSize)
	for i := 0; i < len(probe); i += pageSize {
		probe[i] = 1
	}
	if err := unix.Mlock(probe); err == nil {
		// Undo it first: the failure below aborts the test, and locked pages would outlive it
		// in this process and be charged against every later RLIMIT_MEMLOCK measurement.
		if err := unix.Munlock(probe); err != nil {
			t.Errorf("could not unlock the probe: %v — %d bytes stay locked for the rest of this process", err, len(probe))
		}
		t.Fatalf("mlock of %d bytes still succeeds at RLIMIT_MEMLOCK=0 on %s — the limit did not "+
			"reach the kernel, so any refusal below would be for another reason", len(probe), runtime.GOOS)
	}

	// GATE.
	value, err = source.PIN(context.Background(), "hsm")
	if err == nil {
		t.Fatalf("PIN returned %q with no error although its pages could not be locked — the credential "+
			"is plaintext on swappable memory, and both providers accept it because they check only "+
			"length and error", value)
	}
	// The consequence above is what a mutation should print, so it stays as its own branch.
	// This adds the contract every other refusal in the package is held to: the uniform
	// message, so the error cannot say WHICH check failed and map the host's credential
	// layout, and a nil value rather than a merely empty one.
	//
	// TestEveryRefusalUsesTheSameWords cannot cover this path — it enumerates six cases and
	// this refusal needs a lowered RLIMIT_MEMLOCK — so without this call the mlock path was
	// one of only two refusals in the package outside that contract.
	requireRefused(t, value, err, "a credential whose pages cannot be locked")
}
