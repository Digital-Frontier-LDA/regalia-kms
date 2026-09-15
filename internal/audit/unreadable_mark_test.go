package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AN UNREADABLE HIGH-WATER MARK IS NOT AN ABSENT ONE.
//
// readMark distinguishes three states and only two of them were pinned. NOT
// EXIST returns genesis, a successful read returns the mark, and any other read
// failure is refused -- and that third arm had no detecting test at all.
//
// Measured with the realistic wrong version rather than an operand flip, because
// that is the shape this repository has already been bitten by twice ("a stat
// error is not absence"): readMark rewritten to return genesis for ANY read
// failure. The whole of internal/audit, internal/controlplane,
// internal/operations and cmd/regalia-kms stayed green -- 0 failing tests.
//
// What that buys an attacker: truncate the journal to nothing and leave a mark
// nobody can read. The mark's recorded position is what says how far the trail
// reached, so reading it as genesis erases the evidence of the truncation, and
// VerifyIntegrity -- the check an operator runs -- returns clean. That is the
// same attack the mark exists to detect, arriving through the mark's
// unreadability instead of its absence.
//
// THE INPUT IS A DIRECTORY AT THE MARK'S PATH, and the shape matters twice over.
// os.Stat SUCCEEDS on it while os.ReadFile fails with EISDIR, which is what
// isolates readMark: a symlink loop fails both, so the stat classification
// further down refuses it too and the counterfactual is caught by the wrong
// guard. And it is not a chmod, because a process running as root ignores mode
// bits -- a permission fixture then passes or fails according to who runs the
// suite, which is a property of the runner and not of the code. EISDIR does not
// care who is asking.
//
// §17 (TESTING.md), RECORDED HERE BECAUSE THIS IS THE GUARD DOING THE WORK.
// audit.go's second stat classification has a third arm, `case statErr != nil:`,
// which no fixture can reach: this refusal fires first, on the mark's CONTENTS,
// one call before its EXISTENCE is classified -- and even past that, the first
// classification's own default arm returns on the same class before the second
// switch is reached. Reaching it would need the stat class to change between two
// stats of one path. It is defence in depth and should stay; what cannot happen
// is a test that appears to cover it, so the guarantee is pinned here instead.
func TestAnUnreadableHighWaterMarkIsRefusedRatherThanReadAsGenesis(t *testing.T) {
	// A journal that never existed, with a mark that cannot be read. This is
	// the case the counterfactual returns CLEAN for: with no events, every
	// downstream guard that might otherwise refuse a genesis mark is skipped.
	t.Run("an empty journal is not made verifiable by an unreadable mark", func(t *testing.T) {
		dir := t.TempDir()
		journal := filepath.Join(dir, "audit.jsonl")
		if err := os.Mkdir(journal+highWaterSuffix, 0o700); err != nil {
			t.Fatalf("plant a directory at the mark path: %v", err)
		}
		if _, statErr := os.Stat(journal + highWaterSuffix); statErr != nil {
			t.Fatalf("os.Stat must SUCCEED on this input (%v), or the refusal below could come "+
				"from the stat classification rather than from the read", statErr)
		}
		events, err := VerifyIntegrity(journal)
		if err == nil {
			t.Fatalf("VerifyIntegrity returned %d events and NO error over a high-water mark it "+
				"could not read. Reading an unreadable mark as genesis erases the position the "+
				"mark exists to record, so a journal truncated to nothing verifies clean",
				len(events))
		}
		if !strings.Contains(err.Error(), "read audit mark") {
			t.Fatalf("refusal is %q, want one naming the unreadable mark — a refusal from any "+
				"other guard here would be the right verdict for the wrong reason, and would "+
				"still pass if this one were removed", err)
		}
	})

	// With events, the counterfactual DOES refuse — but as "the mark was reset
	// to hide how far the journal reached", an accusation of tampering aimed at
	// a mark that is merely unreadable. The message is the assertion.
	t.Run("a populated journal names the unreadable mark, not a reset one", func(t *testing.T) {
		dir := t.TempDir()
		journal := filepath.Join(dir, "audit.jsonl")
		recorder, err := Open(journal, nil)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		for i := 1; i <= 2; i++ {
			item := draft(fmt.Sprintf("018f0000-0000-7000-8000-00000000000%d", i), "allow")
			if err := recorder.Record(context.Background(), item, false); err != nil {
				t.Fatalf("record: %v", err)
			}
		}
		if err := recorder.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		if _, err := VerifyIntegrity(journal); err != nil {
			t.Fatalf("the journal must verify BEFORE the mark is replaced, or the refusal below "+
				"is not attributable to the mark: %v", err)
		}

		mark := journal + highWaterSuffix
		if err := os.Remove(mark); err != nil {
			t.Fatalf("remove mark: %v", err)
		}
		if err := os.Mkdir(mark, 0o700); err != nil {
			t.Fatalf("plant a directory at the mark path: %v", err)
		}
		_, err = VerifyIntegrity(journal)
		if err == nil {
			t.Fatal("VerifyIntegrity accepted a journal whose high-water mark it could not read")
		}
		if !strings.Contains(err.Error(), "read audit mark") {
			t.Fatalf("refusal is %q, want one naming the unreadable mark. \"sits at genesis\" is "+
				"what this becomes when the read failure is swallowed: an accusation that "+
				"somebody reset the mark to hide the journal's reach, made about a mark that was "+
				"never read at all", err)
		}
	})
}
