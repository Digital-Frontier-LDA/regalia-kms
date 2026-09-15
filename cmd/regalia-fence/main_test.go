package main

import (
	"errors"
	"flag"
	"os"
	"strings"
	"testing"
)

// -h IS A REQUEST, NOT A FAILURE.
//
// flag.ContinueOnError reports a help request as an error, and main treated every error the
// same way: usage to stdout, then an error prefix on stderr, then exit 1. To a person that
// reads as a broken tool; to a script it is a failed step. For the binary an operator
// reaches for during a failover, at the moment they are least inclined to give it the
// benefit of the doubt, that matters more than it looks.
func TestHelpIsNotAnError(t *testing.T) {
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	if got := run([]string{"-h"}, devnull); !errors.Is(got, flag.ErrHelp) {
		t.Fatalf("run(-h) returned %v, want flag.ErrHelp — main cannot tell a help request "+
			"apart from a failure unless run reports it distinctly", got)
	}

	// The control: a genuine error must still be a genuine error, or the fix above turns
	// every failure into a silent success.
	missing := run([]string{"-site", "sitea"}, devnull)
	if missing == nil || errors.Is(missing, flag.ErrHelp) {
		t.Fatalf("run with missing required flags returned %v — a real failure must not be "+
			"mistaken for a help request", missing)
	}
	if !strings.Contains(missing.Error(), "required") {
		t.Errorf("the error does not say what is missing: %v", missing)
	}
}
