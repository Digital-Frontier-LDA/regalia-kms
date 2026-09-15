package fencing

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// FOUR INPUT GUARDS IN authority.go THAT NOTHING EXERCISED.
//
// #237's fencing entry was recorded against a tree that no longer exists. Re-derived on current
// main the package has 130 leaf operands, 115 killed and 15 survivors — and every survivor is in
// authority.go, while gate.go (49 operands), issue.go (37), runner.go (7) and standby.go (11) have
// none. The detector demonstrably reaches this file: neutralising :103's kind check fails four
// tests, and :106's Operator operand fails one. The survivors are unexercised, not unreachable.
//
// These are the four whose input is cheap to build. The rest are I/O failure paths (Write, Sync,
// Stat) that need fault injection and are tracked separately on #237.

// A RECORD NAMES AN OPERATOR AND A SITE, AND ONLY ONE HALF HAD A DETECTOR.
//
// `record.Operator == "" || record.Site == ""` is one guard over two operands. Neutralising the
// Operator half fails TestTheAuthorityJournalRefusesTamperingAndBadModes; neutralising the Site
// half failed nothing. Same line, adjacent operands, one covered.
//
// The fixture sets Operator to a real value so ONLY the Site operand can refuse it — a record
// missing both would be refused by the covered half and prove nothing about this one.
func TestAJournalRecordWithoutASiteIsRefused(t *testing.T) {
	journal := openTestJournal(t)
	before := journal.Head()

	err := journal.Append(GrantRecord{Kind: RecordGranted, Operator: "ops@regalia", Site: ""})

	if err == nil {
		t.Fatal("a record naming no site was accepted: an unattributed decision is not a record")
	}
	if !strings.Contains(err.Error(), "site") {
		t.Fatalf("error = %v, which does not name the missing field", err)
	}
	// A REFUSAL THAT STILL APPENDED WOULD BE THE DEFECT. The error alone cannot distinguish
	// "refused before the write" from "written, then reported".
	if after := journal.Head(); after != before {
		t.Fatalf("a refused record advanced the head from %d to %d", before, after)
	}
}

// AN EMPTY PATH IS NOT A JOURNAL. Without this guard filepath.Dir("") is ".", so the constructor
// would go on to stat the current working directory and open a journal named after nothing.
func TestOpeningAnAuthorityJournalWithoutAPathIsRefused(t *testing.T) {
	journal, err := OpenAuthorityJournal("")

	if err == nil {
		t.Fatal("an empty path was accepted as an authority journal")
	}
	if journal != nil {
		t.Fatalf("a refused open returned a usable handle: %#v", journal)
	}
	if !strings.Contains(err.Error(), "path") {
		t.Fatalf("error = %v, which does not name the missing path", err)
	}
}

// A NIL JOURNAL IS NOT AN OPEN ONE, AND MUST NOT PANIC.
//
// Both methods take a pointer receiver and guard `journal == nil` before touching the mutex, so a
// caller holding a nil handle — the value OpenAuthorityJournal returns alongside an error — gets a
// refusal rather than a crash. Without the guard the next statement is journal.mu.Lock() and the
// daemon dies inside a fencing decision.
//
// The panic is recovered deliberately: a regression should be a --- FAIL naming this test, not a
// dead binary that says nothing about which fixture reached it.
func TestNilAuthorityJournalRefusesRatherThanPanicking(t *testing.T) {
	t.Run("Append", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Append on a nil journal panicked: %v", recovered)
			}
		}()
		var journal *AuthorityJournal
		if err := journal.Append(GrantRecord{Kind: RecordGranted, Operator: "ops@regalia", Site: "sitea"}); err == nil {
			t.Fatal("Append on a nil journal reported success")
		}
	})
	t.Run("Head", func(t *testing.T) {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Head on a nil journal panicked: %v", recovered)
			}
		}()
		var journal *AuthorityJournal
		if head := journal.Head(); head != 0 {
			t.Fatalf("Head on a nil journal = %d, want 0", head)
		}
	})
}

// openTestJournal returns a usable journal in a directory the mode discipline accepts.
func openTestJournal(t *testing.T) *AuthorityJournal {
	t.Helper()
	directory := t.TempDir()
	journal, err := OpenAuthorityJournal(filepath.Join(directory, "authority.jsonl"))
	if err != nil {
		t.Fatalf("fixture journal did not open: %v", err)
	}
	return journal
}

// THE MODE DISCIPLINE, WHICH IS A SECURITY GUARD AND HAD NO TEST.
//
// Three more survivors from the same sweep. All three are checked by READING mode bits via Stat
// rather than by attempting a write, so they hold for root as well — a test built on "the write
// fails" would pass for the wrong reason under a container running as uid 0, and would silently
// stop testing anything.
//
// :125 and :209 return the SAME message ("unsafe authority journal"), deliberately: a caller
// holding a file it cannot read should not learn which check fired. So these tests discriminate by
// the code PATH each reaches — Append versus OpenAuthorityJournal — not by the text.

// A journal directory anyone can write to is not a journal directory. The record's own permissions
// are irrelevant: whoever can create files beside it can replace it and re-sign.
func TestAnAuthorityJournalInAWorldWritableDirectoryIsRefused(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}

	journal, err := OpenAuthorityJournal(filepath.Join(directory, "authority.jsonl"))

	if err == nil {
		t.Fatal("a journal in a world-writable directory was accepted")
	}
	if journal != nil {
		t.Fatalf("a refused open returned a usable handle: %#v", journal)
	}
	// The message is the operator-facing half of this guard: it has to say what an attacker could
	// do, or the refusal reads as a permissions nit and gets chmod'ed away.
	if !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("error = %v, which does not name the exposure", err)
	}
}

// A DIRECTORY IS NOT A JOURNAL, AND SAYING SO IS THE POINT.
//
// os.Open succeeds on a directory, so this reaches verifyAuthorityJournal's Stat triple rather than
// failing at the open. But the first version of this test asserted only that an error came back,
// and it PASSED with the IsRegular operand neutralised — the decode layer refuses a directory too,
// so the test was satisfied by a detector it was not written for.
//
// The two paths return different errors, and the difference is the reason this guard earns a test:
//
//	IsRegular live   "fencing: unsafe authority journal"           <- a path the operator misconfigured
//	IsRegular dead   "fencing: authority journal integrity failure" <- the alarm for a TAMPERED chain
//
// Without the guard, a journal path pointing at a directory is reported as an integrity failure on
// the fencing authority chain. That sends whoever is woken by it hunting for an attacker who does
// not exist, on the one signal in this package that must mean what it says. So the assertion is on
// the message, not on the presence of an error.
func TestAnAuthorityJournalPathThatIsADirectoryIsRefused(t *testing.T) {
	directory := t.TempDir()
	asDirectory := filepath.Join(directory, "authority.jsonl")
	if err := os.Mkdir(asDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	// The control: prove os.Open really does accept it, so the refusal below is the IsRegular
	// check and not the open failing first.
	handle, openErr := os.Open(asDirectory)
	if openErr != nil {
		t.Fatalf("os.Open refused the directory (%v), so this fixture never reaches the guard", openErr)
	}
	handle.Close()

	_, err := OpenAuthorityJournal(asDirectory)
	if err == nil {
		t.Fatal("a directory was accepted as an authority journal")
	}
	if !strings.Contains(err.Error(), "unsafe authority journal") {
		t.Fatalf("error = %q, want the unsafe-journal refusal.\n"+
			"An integrity failure here would report a misconfigured path as a tampered chain, "+
			"which is the one alarm in this package that has to mean what it says.", err)
	}
}

// A JOURNAL ANYONE CAN READ IS NOT SAFE TO APPEND TO. Append opens with 0o600, but O_CREATE does
// not change the mode of a file that already exists — so a journal left group- or world-readable
// by an earlier process is what Stat reports, and this operand is the only one that refuses it.
//
// The sibling check inside verifyAuthorityJournal has a detector; this one, inside Append, did not.
func TestAppendingToALooselyPermissionedJournalIsRefused(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "authority.jsonl")
	journal, err := OpenAuthorityJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// CHMOD, BECAUSE os.WriteFile's MODE IS MASKED BY THE UMASK. Requesting 0644 under a umask of
	// 0077 produces 0600, `Perm()&0o077` is then zero, the guard never fires and Append succeeds —
	// so this test FAILS under a restrictive umask and passes in CI only because the runner's umask
	// happens to be 0022. Chmod is not masked. Raised in review on #321; the sibling directory
	// fixture above already did this and this was the one site that did not.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// AND ASSERT THE FIXTURE BUILT THE STATE IT CLAIMS. A fixture that silently fails to produce
	// the condition under test accuses the guard it exists to exonerate: the refusal below would
	// not happen, and the failure would read as "the guard is broken".
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 == 0 {
		t.Fatalf("fixture did not produce a loosely-permissioned journal: mode is %04o, so the "+
			"guard under test cannot fire and this test would assert nothing", info.Mode().Perm())
	}
	before := journal.Head()

	appendErr := journal.Append(GrantRecord{Kind: RecordGranted, Operator: "ops@regalia", Site: "sitea"})

	if appendErr == nil {
		t.Fatal("a decision was appended to a world-readable journal")
	}
	if after := journal.Head(); after != before {
		t.Fatalf("a refused append advanced the head from %d to %d", before, after)
	}
	// And nothing was written: a refusal that still appended would leave a record whose chain
	// position the journal does not know about.
	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(contents) != 0 {
		t.Fatalf("the refused record was written anyway: %q", contents)
	}
}

// A RECORD THAT CANNOT BE ENCODED MUST NOT ADVANCE THE CHAIN.
//
// The eighth survivor, and the one whose premise looked wrong: `json.Marshal` of a GrantRecord
// "obviously cannot fail", since every field is a string or a uint64 — except two, which are
// time.Time. time.Time.MarshalJSON refuses any year outside [0,9999], so an ExpiresAt far enough in
// the future is an encoding failure, and this guard is the only thing that notices.
//
// Measured with the operand neutralised, against a pristine (error, head unchanged, one record):
//
//	appendErr = <nil>     Append reports SUCCESS for a decision it never wrote
//	head      = 2         the in-memory sequence advanced past it
//	journal  += "\n"      a bare newline; json.Decoder skips it, so the file holds ONE record
//	verify    = <nil>     and the tamper-evident chain verifies clean
//
// That is the failure this package exists to prevent, produced by its own writer.
//
// REACHABLE FROM THE CLI, not only from a hand-built record — asked in review, so it was measured
// rather than assumed. `regalia-fence` takes `-not-before` as an RFC3339 string and computes
// `ExpiresAt = start.Add(-valid-for)`. RFC3339 will not parse a five-digit year, so `-not-before`
// alone cannot reach this. But `9999-12-31T23:59:59Z` parses, and:
//
//	-not-before 9999-12-31T23:59:59Z -valid-for 1s  ->  ExpiresAt year 10000, lease duration 1s
//
// A one-second lease passes every validation this package has, MaxLeaseDuration (10 minutes)
// included, and only the encoder refuses it. The record written on the REFUSAL path carries the
// same times, so a rejected grant journals through here too.
func TestARecordThatCannotBeEncodedDoesNotAdvanceTheChain(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "authority.jsonl")
	journal, err := OpenAuthorityJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	// An anchor first: a normal record appends, so the refusal below is about the bad one.
	if err := journal.Append(GrantRecord{Kind: RecordGranted, Operator: "ops@regalia", Site: "sitea"}); err != nil {
		t.Fatal(err)
	}
	before, sizeBefore := journal.Head(), journalSize(t, path)

	// Year 10000 is outside the range time.Time can encode. Every other field is valid, so the
	// record is refused by the encoder and not by the kind or attribution guards above it.
	appendErr := journal.Append(GrantRecord{
		Kind: RecordGranted, Operator: "ops@regalia", Site: "sitea",
		ExpiresAt: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	if appendErr == nil {
		// THE MESSAGE A READER ACTUALLY SEES. This assertion fires first under the mutation this
		// test exists for, so it is the one that has to explain the consequence rather than just
		// name the expectation.
		t.Fatalf("Append reported success for a record it could not encode.\n" +
			"json.Marshal returns nil alongside its error, so the journal receives a bare newline, " +
			"the sequence advances past a record that was never written, and json.Decoder skips the " +
			"blank line — so the chain still verifies clean. The running process and a restart now " +
			"read different sequences, and every integrity check this package offers reports the " +
			"journal intact.")
	}
	if after := journal.Head(); after != before {
		t.Fatalf("the chain advanced from %d to %d for a record that was never written.\n"+
			"The running process now holds sequence %d and a lastHash chaining from a record that "+
			"is not in the file; a restart reads %d from the journal. The two disagree, and every "+
			"integrity check this package offers still reports the journal intact.",
			before, after, after, before)
	}
	if after := journalSize(t, path); after != sizeBefore {
		t.Fatalf("the journal grew from %d to %d bytes for a record that failed to encode",
			sizeBefore, after)
	}
	// And the file still has to verify — a blank line appended here would leave a journal that
	// verifies clean while holding fewer records than the authority believes it wrote.
	if _, _, verifyErr := verifyAuthorityJournal(path); verifyErr != nil {
		t.Fatalf("the journal no longer verifies after a refused append: %v", verifyErr)
	}
}

func journalSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// AN APPEND THAT CANNOT OPEN THE JOURNAL MUST NOT ADVANCE THE CHAIN EITHER.
//
// The handle is obtained once and reused, so the file it names can stop existing between
// OpenAuthorityJournal and any later Append — a directory removed underneath a running daemon is
// the ordinary way that happens. Without the guard the nil *os.File is dereferenced on the next
// line and the daemon dies inside a fencing decision.
func TestAppendingWhenTheJournalCannotBeOpenedIsRefused(t *testing.T) {
	directory := t.TempDir()
	inner := filepath.Join(directory, "inner")
	if err := os.Mkdir(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenAuthorityJournal(filepath.Join(inner, "authority.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(inner); err != nil {
		t.Fatal(err)
	}
	before := journal.Head()

	appendErr := journal.Append(GrantRecord{Kind: RecordGranted, Operator: "ops@regalia", Site: "sitea"})

	if appendErr == nil {
		t.Fatal("a decision was reported as appended to a journal that could not be opened")
	}
	// WRAPPED, not flattened. authority.go splits its errors deliberately: validation failures
	// return a uniform message so a caller learns nothing from which check fired, while I/O
	// conditions an operator must tell apart — disk-full, permissions, ENOENT — keep their cause.
	if !errors.Is(appendErr, os.ErrNotExist) {
		t.Fatalf("error = %v, which has lost os.ErrNotExist: an operator cannot tell a missing "+
			"directory from a permissions fault or a full disk", appendErr)
	}
	if after := journal.Head(); after != before {
		t.Fatalf("the chain advanced from %d to %d for a record that was never written", before, after)
	}
}

// NOT SHIPPED: a test that VerifyAuthorityJournal keeps os.ErrNotExist on a missing journal.
//
// It was written, it passed, and it gated nothing. Under every mutation tried it failed alongside
// eight other tests and was never the sole failure — removing the os.Open error check, and
// flattening the error with %v instead of %w, each fail NINE tests.
//
// The reason is worth more than the test: OpenAuthorityJournal treats os.ErrNotExist as "no
// decisions yet, this is the first" rather than as a failure, so the identity is load-bearing for
// the package's own happy path. EVERY test that opens a fresh journal depends on it. The contract
// is protected by construction, and a tenth assertion of it is documentation.
//
// authority.go:172 — the second os.Open, inside VerifyAuthorityJournal — is likewise recorded as
// unreachable rather than uncovered (TESTING.md §17). verifyAuthorityJournal runs first on the same
// path and returns the identical error, so no input reaches the second check: it would need the
// file to exist for the first open and not the second, which is a race a test cannot construct.
