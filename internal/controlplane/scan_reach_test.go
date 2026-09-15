package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A SCAN THAT NEVER WALKED THE TREE MUST NOT REPORT A CLEAN TREE.
//
// ScanTree is the belt-and-braces half of the export contract: the journals are hash-chained, so
// this scan exists for the case verification cannot see — a compromised writer producing a valid
// chain whose records contain key material anyway. Its answer is therefore a security claim, and
// the two ways it can be wrong are opposite:
//
//	it misses a secret that is there   -> shapesArmedWith already covers this, by scanning a
//	                                      freshly generated canary through the same code path
//	                                      before any real input, and refusing if it cannot see it
//	it never looked at all             -> this operand, and nothing exercised it
//
// Measured with :208 neutralised, against a pristine "walk ...: no such file or directory":
//
//	ScanTree(missing root) -> findings=0  err=<nil>
//
// Zero findings and no error is exactly what a clean tree returns. The caller cannot tell "I
// scanned it and found nothing" from "I could not scan it".
//
// THE ARMING PROOF DOES NOT COVER THIS, AND THE TWO ARE NOT SUBSTITUTES. shapesArmedWith answers
// "can this detector see what it is looking for"; :208 answers "was this detector given anything to
// look at". Here the arming proof PASSES — the canary is generated, scanned and found, so the
// detector is genuinely armed — and the walk still touched no file. A reader who assumes the canary
// already covers reach will delete this test.
//
// THE OTHER scan.go SURVIVORS ARE NOW ACCOUNTED FOR in survivor_pool_ledger_test.go. In
// particular, the former claim that canary's rand.Read error was unconstructible became false
// under Go 1.26: rand.Read terminates instead of returning that error. The package now has an
// explicit entropy boundary and TestCanaryEntropyFailureCannotProduceAnArmedVerdict reaches the
// fail-closed path without killing the process. The remaining timing-dependent rows are:
//
//	:126  probe == "" is masked by canary's now-tested entropy refusal and by the positive-control
//	      scan returning no findings for an empty probe.
//	:186  file.Stat, :194/:195 read errors — these need a file that is REGULAR at walk time and gone
//	      or unreadable at read time. A dangling symlink does NOT reach them: `!entry.Type()
//	      .IsRegular()` skips it two lines earlier. Established by mutating both guards and watching
//	      the output not change, rather than by reading the skip and concluding.
func TestScanTreeRefusesATreeItCouldNotWalk(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	findings, err := ScanTree(missing)

	if err == nil {
		t.Fatalf("ScanTree reported success for a tree it never walked: findings=%d.\n"+
			"Zero findings and a nil error is what a CLEAN tree returns, so a caller acting on "+
			"this cannot tell 'scanned, nothing found' from 'never scanned' — and for a secret "+
			"scanner those are opposite answers.", len(findings))
	}
	if !strings.Contains(err.Error(), "walk") {
		t.Fatalf("error = %q, which does not name the walk as the failure", err)
	}
	if findings != nil {
		t.Fatalf("a failed scan returned findings: %#v", findings)
	}
}

// THE ANCHOR, so the refusal above is about the unwalkable tree and not about ScanTree refusing
// everything: a real tree with nothing secret in it returns no findings AND no error, which is the
// state the test above must be distinguishable from.
func TestScanTreeAcceptsATreeItCouldWalk(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "notes.txt"), []byte("nothing secret here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	findings, err := ScanTree(directory)

	if err != nil {
		t.Fatalf("a walkable tree was refused: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("a clean tree produced findings: %#v", findings)
	}
}
