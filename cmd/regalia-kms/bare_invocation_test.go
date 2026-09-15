package main

// #275: `regalia-kms` with no arguments panicked with a nil dereference and exited 2.
//
// keyRegistry is nil-checked at main.go's "KMS registry loaded" log and then dereferenced
// unconditionally by fenceRunner, which takes keyRegistry.Digest(). A bare invocation reaches
// that call with nil, and the process dies with a SIGSEGV stack trace —
// the worst possible answer to the simplest possible invocation, because a crash on startup
// reads as a broken build rather than a missing argument.
//
// Found by DEV5 while building #256's runbook-command check, and NOT by that check: nothing
// in any runbook teaches a bare `regalia-kms`, so the corpus it walks could never contain
// this invocation. Worth stating, because "the new check would have caught it" is the
// comfortable reading and it is false.
//
// This drives run() directly rather than building a subprocess. run() declares its flags on
// the default flag.CommandLine, so swapping that and os.Args exercises the real entry point
// at unit-test speed; both are restored, because a test that leaves the global flag set
// replaced would break every test that runs after it.

import (
	"flag"
	"os"
	"strings"
	"testing"
)

func TestABareInvocationIsRefusedRatherThanPanicking(t *testing.T) {
	// A temp working directory, so a run that gets further than expected cannot write into the
	// repository — and so the emptiness assertion below means something.
	directory := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	savedArgs, savedFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = savedArgs, savedFlags })
	os.Args = []string{"regalia-kms"}
	flag.CommandLine = flag.NewFlagSet("regalia-kms", flag.ContinueOnError)

	// A panic here is the defect: recovering and reporting it beats the test binary dying with
	// the process, which would take every other test in this package with it.
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("a bare invocation panicked: %v — an operator who types the binary's name with no arguments must get a sentence, not a stack trace", recovered)
		}
	}()

	runErr := run()
	if runErr == nil {
		t.Fatal("a bare invocation was accepted — the daemon has no custody manifest and cannot serve, so this must refuse")
	}
	if !strings.Contains(runErr.Error(), "no custody manifest is configured") {
		t.Fatalf("refused, but not by the missing-manifest guard: %v — any other refusal means this test is not checking what it names", runErr)
	}

	// NOTHING WAS CREATED. The refusal has to land before the daemon starts opening journals,
	// or a bare invocation would leave state behind in whatever directory it was run from.
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("a refused bare invocation left %v behind — the refusal must precede any side effect", names)
	}
}
