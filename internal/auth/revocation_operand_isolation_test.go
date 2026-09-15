package auth

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Two operands in revocation.go survived a sweep, and both survived for reasons that are properties
// of the TESTS rather than of the code. Recorded here because each is a shape worth recognising.
//
// A FIXTURE THAT VIOLATES TWO RULES AT ONCE PINS NEITHER. The parser's refusal has two operands —
// `!ok` for a line that is not an integer at all, and `value.Sign() < 0` for one that is a negative
// integer. TestParseRevocationListRejectsGarbageAndHandlesBlanks feeds a file containing BOTH a
// "-1" line and a "not-a-number" line, and asserts only that an error came back. Because the parser
// returns on the first bad line, deleting the sign operand simply lets parsing run on to the
// non-numeric line, which refuses instead — same outcome, test still green. The assertion's own
// wording ("negative or non-numeric") records that the author had both cases in mind; what it could
// not do is tell them apart. The fix is one fixture per operand, and an assertion on the message,
// which names the offending line and value.
//
// A GUARD MASKED BY ITS OWN SUCCESSOR IS STILL PINNABLE IF THE MESSAGES DIFFER. load() refuses four
// times in a row — open failed, descriptor wrap failed, fstat failed, not a regular file — and each
// refusal produces the error the NEXT one would have produced anyway, so no test asserting merely
// "an error occurred" can distinguish them. The messages do differ, though, and the open failure
// carries the underlying errno, so asserting the WRAPPED SENTINEL rather than the string pins the
// first of the chain.
//
// TWO OF THE FOUR ARE NOT PINNED, DELIBERATELY, because no fixture can reach them. `file == nil`
// fires only when os.NewFile is handed a negative descriptor, which unix.Open returns only when it
// has also returned an error — and that error is refused one line earlier. `unix.Fstat` on a
// descriptor that was just opened successfully fails only for EBADF or EFAULT, neither of which a
// caller can construct through this API. They are unreachable in the §17 sense, and a test for
// either would assert an outcome its siblings already produce.
//
// A MUTATION CAN HANG RATHER THAN FAIL. Removing the not-a-regular-file refusal does not make the
// suite go red: TestRevocationRejectsNonRegularFileAtPath points the list at a FIFO, and reading a
// FIFO with no writer blocks forever. The run stalls until Go's ten-minute test timeout fires. A
// sweep whose per-run timeout is longer than that, or absent, records nothing at all for such an
// operand — not a survivor, not a kill. Hence `-timeout` on every run.

// TestRevocationRefusesANegativeSerialOnItsOwn pins the sign operand of the parser's refusal.
//
// A negative serial is not a typo an operator can afford: certificate serial numbers are
// non-negative, so an entry like "-22222" can never match the value Authenticate looks up. Without
// this operand the line parses cleanly and is stored under the key "-22222", the file loads without
// complaint, and the operator is left believing a certificate is revoked while every presentation of
// it authenticates. That is a fail-open reached by a single stray keystroke.
//
// Isolation: the fixture's only defective line is the negative one, and it IS a valid base-ten
// integer, so the sibling `!ok` operand cannot fire. The surrounding serials are well-formed, which
// the control below proves by loading them successfully. The assertion is on the message because
// that is the only thing distinguishing this refusal from its sibling's.
func TestRevocationRefusesANegativeSerialOnItsOwn(t *testing.T) {
	dir := t.TempDir()

	// Control: the same file without the negative line must load, or a refusal below would prove
	// only that the fixture is malformed in some other way.
	sound := filepath.Join(dir, "sound.txt")
	if err := os.WriteFile(sound, []byte("11111\n# a comment\n\n22222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRevocationList(sound); err != nil {
		t.Fatalf("control is broken, so the refusal below would prove nothing: a file of well-formed "+
			"serials failed to load: %v", err)
	}

	path := filepath.Join(dir, "negative.txt")
	if err := os.WriteFile(path, []byte("11111\n# a comment\n\n-22222\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := NewRevocationList(path)
	if err == nil {
		t.Fatalf("DEFECT: a revocation file whose only defect is the negative serial -22222 loaded "+
			"without error (list=%v); the entry is stored under a key no certificate serial can "+
			"equal, so the operator believes a certificate is revoked while it authenticates", list)
	}
	// Line 4, not line 1: the comment and the blank line are counted, which is what makes the
	// number useful to an operator opening the file in an editor.
	if want := `line 4: "-22222" is not a non-negative integer serial`; !strings.Contains(err.Error(), want) {
		t.Fatalf("refusal is %q, want it to contain %q — the message is the only thing telling this "+
			"operand apart from its non-numeric sibling, so an assertion on the error alone would "+
			"pass with this operand deleted", err.Error(), want)
	}
}

// TestRevocationSurfacesTheOpenFailureRatherThanADownstreamOne pins load()'s first refusal, the
// error check on unix.Open.
//
// It is masked three times over: without it the negative descriptor makes os.NewFile return nil and
// the next guard refuses, without that one unix.Fstat refuses on the bad descriptor, and without
// that one the zeroed stat mode is not S_IFREG and the fourth refuses. Every one of those returns an
// error, so "the list refused" is true whichever survives, and the existing missing-file test —
// which asserts exactly that — passes with this operand deleted.
//
// What does not survive the masking is the CAUSE. Only the first refusal wraps the errno, so an
// operator whose revocation list was renamed by a bad deploy is told "no such file or directory"
// rather than "descriptor wrap failed" or "must be a regular file", both of which point at the file
// having the wrong shape instead of being absent. Asserting the wrapped sentinel pins it.
//
// Isolation: the file is created, loads successfully, and is then removed — so the control proves
// the path, mode and contents are all sound, and deletion is the only difference between the two
// calls.
func TestRevocationSurfacesTheOpenFailureRatherThanADownstreamOne(t *testing.T) {
	path := writeRevocationFile(t, "11111")
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatalf("control is broken: a well-formed revocation list failed to construct: %v", err)
	}
	if revoked, err := list.Check("11111"); err != nil || !revoked {
		t.Fatalf("control is broken, so the refusal below would prove nothing: Check on the "+
			"still-present file gave revoked=%v err=%v, want revoked=true and no error", revoked, err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("fixture did not take effect: the file is still there after Remove (stat gave %v), "+
			"so the operand under test is never reached", statErr)
	}

	revoked, err := list.Check("11111")
	if err == nil {
		t.Fatalf("DEFECT: Check on a deleted revocation list returned revoked=%v with no error; an "+
			"absent list is \"cannot tell\", which must refuse rather than admit", revoked)
	}
	if revoked {
		t.Fatalf("DEFECT: Check reported revoked=true alongside error %v; a failed read must not "+
			"also assert a verdict", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("refusal %q does not wrap fs.ErrNotExist, so the reason the list could not be read "+
			"has been replaced by a downstream guard's account of it; an operator whose file was "+
			"renamed by a bad deploy is told the file has the wrong shape rather than that it is "+
			"missing", err.Error())
	}
}
