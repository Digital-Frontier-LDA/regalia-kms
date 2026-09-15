package policy

// THE FAULT-INJECTION HARNESS (#334).
//
// Nineteen sites in this package end in a branch whose only realistic trigger is a fault at the
// OS or filesystem boundary — os.Open on the policy file, file.Stat after it, io.ReadAll, the
// high-water sidecar read, the journal open in VerifyState. Every one of them was unreachable
// from a test, so every one was untested by construction: the suite stayed green, the branch
// returned an error nobody had ever seen produced, and the next person to read it had no
// evidence the guard fires at all.
//
// EIGHTEEN, until this sweep found the nineteenth: VerifyState's "cannot tell" case for the
// high-water stat carried no marker at all. This header said eighteen for one review round
// beside a ledger that said nineteen, which is the same defect as the ones below — a count a
// reader cannot check against anything. It is checkable now: the two enumeration tests at the
// bottom of this file compare the marked sites and the ledger rows in both directions, so
// neither number can move without the other.
//
// THE CLASS IS THE WORK, NOT THE LEAVES. What was missing was not twenty-one tests; it was the
// four primitives below, without which no test could be written. They are here, with their
// preconditions, and fault_injection_leaves_test.go carries one ledger row per leaf.
//
// TWO RULES THE PRIMITIVES ENCODE, BOTH LEARNED THE EXPENSIVE WAY:
//
//  1. PREFER A FAULT THE RUNNER CANNOT REVOKE. A directory where a regular file is expected
//     makes os.Stat SUCCEED and every read fail with EISDIR, on every runner and every uid.
//     chmod does not: root ignores mode bits entirely, so under root a chmod row observes
//     success where it expected refusal and reports green — passing for the exact reason the
//     row exists to rule out. directoryAt is therefore the default and denyAllAccess is used
//     only where the claim under test IS about permissions.
//
//  2. WHEN PERMISSIONS ARE UNAVOIDABLE, GATE ON WHAT THE KERNEL RECORDED, NOT ON WHAT WAS
//     REQUESTED. os.Chmod returning nil says the request was accepted, not that the filesystem
//     kept the bits or that this process is now denied. denyAllAccess stats the file back and
//     then actually attempts the open, and SKIPS — loudly, with the reason — rather than
//     running a row whose refusal would not be evidence.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// failingReader is the reader whose Read always fails. It is the only way to reach the
// io.ReadAll branch in Load: every other reader this package is handed either succeeds or is
// refused before the read.
type failingReader struct{ err error }

func (reader failingReader) Read([]byte) (int, error) { return 0, reader.err }

// directoryAt puts a DIRECTORY where the code expects a regular file.
//
// This is the fault shape that does not depend on who is running the suite: stat succeeds (so
// existence checks pass and the code proceeds to the read it is being tested on), and open/read
// fail with EISDIR for root and for everyone else alike. Where a row needs "the file is there
// and cannot be read", this is how it is spelled.
func directoryAt(t *testing.T, path string) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("clearing %s before injecting a directory: %v", path, err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("injecting a directory at %s: %v", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the injected directory at %s cannot be stat'd (%v) — this fault needs stat to SUCCEED and only the read to fail, so the row would be exercising the wrong branch", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory after Mkdir (mode %v)", path, info.Mode())
	}
	if _, err := os.ReadFile(path); err == nil {
		t.Skipf("this platform reads a directory as an ordinary file, so no read fault was injected at %s — the row would be green without the fault it claims to inject", path)
	}
}

// denyAllAccess is the chmod primitive, used ONLY where the claim under test is about
// permissions specifically — a leaf that must tell os.ErrNotExist and os.ErrPermission apart
// cannot be reached with EISDIR, because EISDIR is neither.
//
// Root ignores mode bits. A row gated only on `os.Chmod(path, 0) == nil` therefore passes under
// root by observing the success it was written to forbid. Both gates below are on the
// KERNEL-OBSERVED state: the mode the filesystem actually recorded, and then a real open. Either
// one failing skips the row and says why, rather than letting it report green.
func denyAllAccess(t *testing.T, path string) {
	t.Helper()
	original, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat before chmod 0000 on %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 0000 on %s: %v", path, err)
	}
	// Restore the mode that was actually there, not a guess. A directory left at 0000 defeats
	// t.TempDir's own cleanup, and this runs before it: cleanups are LIFO and TempDir registered
	// its removal when it was created.
	//
	// The WHOLE FileMode, not Mode().Perm(): sticky, setuid and setgid live outside the
	// permission bits, so restoring Perm() alone silently strips them. os.Chmod's syscallMode
	// carries exactly those three across and ignores the type bits, so passing the full mode is
	// both correct and complete. No fixture here sets them today — which is precisely why the
	// narrower version would have survived until one did.
	t.Cleanup(func() { _ = os.Chmod(path, original.Mode()) })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after chmod 0000 on %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0 {
		t.Skipf("the kernel recorded mode %04o after a chmod to 0000 on %s — this filesystem does not carry permission bits, so a refusal here would not be evidence about the guard", perm, path)
	}
	file, err := os.Open(path)
	if err == nil {
		_ = file.Close()
		t.Skipf("uid %d can still open %s at mode 0000 — chmod denies root nothing, and a row that observes success where it demanded refusal is green for the wrong reason", os.Getuid(), path)
	}
	if !os.IsPermission(err) {
		t.Skipf("opening %s at mode 0000 failed with %v rather than a permission error — the fault this row injects is not the one it would be observing", path, err)
	}
}

// A PRIMITIVE THAT MUTATES MORE THAN IT INJECTED IS NOT AN INJECTION.
//
// denyAllAccess restored Mode().Perm(), which silently drops sticky, setuid and setgid — bits
// that live outside the permission bits and that os.Chmod does carry. Nothing in this package
// sets them, so the narrower restore was invisible and would have stayed invisible until a
// fixture needed one. The row skips rather than fails where the filesystem does not record the
// bit, because "cannot observe the restore" is not "the restore is wrong".
func TestDenyAllAccessRestoresTheWholeFileMode(t *testing.T) {
	target := filepath.Join(t.TempDir(), "sticky-directory")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o700|os.ModeSticky); err != nil {
		t.Skipf("this platform refused to set the sticky bit: %v", err)
	}
	before, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode()&os.ModeSticky == 0 {
		t.Skipf("the kernel recorded mode %v, without the sticky bit — the restore this row checks cannot be observed here", before.Mode())
	}

	// The subtest scopes the t.Cleanup that performs the restore, so the parent observes the
	// mode AFTER it has run. A skip inside denyAllAccess (root, or a filesystem without mode
	// bits) still runs the cleanup, because it is registered before either gate.
	t.Run("inject and restore", func(t *testing.T) { denyAllAccess(t, target) })

	after, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("denyAllAccess left mode %v where it found %v — the helper changed state it did not inject, and a fixture that relied on the dropped bit would fail somewhere else entirely", after.Mode(), before.Mode())
	}
}

// writeGarbage puts bytes that are not JSON into a regular file.
//
// Not a repeated byte: a fixture of one character repeated is indistinguishable from a decoder
// that refuses everything, so the content carries structure a real corruption would (partial
// braces, a stray NUL, a plausible-looking line) without being decodable.
func writeGarbage(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("\x00\x01{\"sequence\": 1, \"reservation\"\nthis line is not a state event either\n"), 0o600); err != nil {
		t.Fatalf("writing garbage to %s: %v", path, err)
	}
}

// severJournalHandle closes the descriptor under a live FileState, which is what a write fault
// looks like from inside Reserve. It is the harness's write-side primitive: the append fails,
// and everything downstream of the append must behave as if it never happened.
func severJournalHandle(t *testing.T, state *FileState) {
	t.Helper()
	if state.file == nil {
		t.Fatal("the state has no journal handle to sever — the fixture never opened one, so nothing about the write path is being exercised")
	}
	if err := state.file.Close(); err != nil {
		t.Fatalf("severing the journal handle: %v", err)
	}
}

// chained builds the event a CORRECT writer would have produced at this position, hashed with
// the production hasher. Rows then break exactly one field and re-hash, which is what makes a
// single operand of the three-operand integrity check isolable: change Sequence and re-hash and
// the sequence operand is the only one objecting.
func chained(sequence uint64, previous, nonce string) stateEvent {
	event := stateEvent{
		Sequence:     sequence,
		Reservation:  reservation(nonce, "2026-09-04", 10, 100),
		PreviousHash: previous,
	}
	event.Hash = stateEventHash(event)
	return event
}

// forgedJournal writes the given events verbatim, so a row can present a journal no writer in
// this package would produce.
func forgedJournal(t *testing.T, events ...stateEvent) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	var buffer bytes.Buffer
	for _, event := range events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("encoding forged event %d: %v", event.Sequence, err)
		}
		buffer.Write(encoded)
		buffer.WriteByte('\n')
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatalf("writing forged journal: %v", err)
	}
	return path
}

// siteTag is the marker each of the guarded sites carries in its comment. The tag exists so the
// ledger and the source cannot drift apart silently: a site marked in the source with no row in
// the ledger is a leaf nobody classified, and a row naming a site that no longer exists is a
// claim about code that moved.
var siteTag = regexp.MustCompile(`FAULT INJECTION CLASS \(#334\) \[([^\]]+)\]`)

// faultInjectionSources is every non-test .go file in the package, SCANNED rather than typed.
//
// It was a hand-written list of the three files that carry markers today, and that made both
// enumeration tests below fail toward clean: a marked site in a new file — or in wire.go or
// policy.go, which were never on the list — would be invisible to them, and the ledger would
// look complete while a leaf went unclassified. An instrument for detecting drift must not
// itself be somewhere drift can hide.
//
// _test.go files are excluded deliberately: a marker names a production guard, and including
// them would match this file's own regexp literal.
func faultInjectionSources(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory to enumerate its sources: %v", err)
	}
	var sources []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sources = append(sources, name)
	}
	if len(sources) == 0 {
		t.Fatal("the scan found no non-test .go files in the package directory — an empty scan and a broken scan are indistinguishable from here, so this is a failure rather than a vacuous pass")
	}
	sort.Strings(sources)
	return sources
}

func markedSites(t *testing.T) []string {
	t.Helper()
	sources := faultInjectionSources(t)
	var found []string
	for _, name := range sources {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s to enumerate its marked sites: %v", name, err)
		}
		for _, match := range siteTag.FindAllStringSubmatch(string(source), -1) {
			found = append(found, match[1])
		}
	}
	if len(found) == 0 {
		t.Fatalf("no #334 site markers were found in %v — an empty result and a broken regexp look identical from here, so this is a failure rather than a vacuous pass", sources)
	}
	sort.Strings(found)
	return found
}

// A SITE ENUMERATED IS NOT A SITE SWEPT. The ledger in fault_injection_leaves_test.go is a
// hand-written list, and a hand-written list drifts: a new fs boundary gets a marker comment and
// no row, or a row survives the code it describes. This compares the two sets in both
// directions, so neither can move without the other.
func TestEveryMarkedFaultInjectionSiteHasALedgerRow(t *testing.T) {
	inSource := map[string]bool{}
	for _, site := range markedSites(t) {
		if inSource[site] {
			t.Fatalf("the site tag %q is used twice in the source — tags identify a site, so a duplicate makes one of the two unreachable from the ledger", site)
		}
		inSource[site] = true
	}
	inLedger := map[string]bool{}
	for _, row := range faultInjectionLedger() {
		inLedger[row.site] = true
	}
	for site := range inSource {
		if !inLedger[site] {
			t.Errorf("%s is marked as a fault-injection site in the source and has no ledger row — an unclassified leaf is one nobody has said is covered, unreachable, or pinned elsewhere", site)
		}
	}
	for site := range inLedger {
		if !inSource[site] {
			t.Errorf("the ledger has a row for %s and no source site carries that tag — the row is asserting about code that moved or went away", site)
		}
	}
	if len(inSource) != len(inLedger) {
		t.Errorf("%d marked sites, %d ledger sites", len(inSource), len(inLedger))
	}
}

// The control for the control. markedSites() returning an empty set would make the test above
// vacuously pass in one direction, and a regexp that matches nothing is indistinguishable from a
// source file with no markers — so the count is asserted against the files themselves, counted a
// different way.
func TestTheSiteMarkerRegexpFindsEveryMarkerLine(t *testing.T) {
	lines := 0
	// The SAME scan markedSites uses. Two enumerations of "the package's sources" that can
	// disagree are two chances for a site to fall between them.
	for _, name := range faultInjectionSources(t) {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lines += strings.Count(string(source), "FAULT INJECTION CLASS (#334)")
	}
	if tagged := len(markedSites(t)); tagged != lines {
		t.Fatalf("%d comment lines announce a #334 fault-injection site but only %d carry a [tag] the ledger can match — an untagged site is invisible to the enumeration test and would look swept", lines, tagged)
	}
}
