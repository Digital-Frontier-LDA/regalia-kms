package controlplane

// GUARD COVERAGE (#237 sweep): four guards in this package had no detector — found by
// mutation, not by reading, and each row below kills its own mutation by NAME (the
// failure message is the guard's absence, stated):
//
//   X16 whitespace-only deployment version   -> refused as blank
//   X18 version file over the plain bound    -> refused by size, before reading
//   S10 non-regular files in a scanned tree  -> skipped, not followed
//   S11 ScanTree's arming call               -> unarmed tree scanning is void
//
// The four-row note that used to follow this list was a partial survivor ledger and became
// stale twice. survivor_pool_ledger_test.go now accounts for the complete current-main pool:
// all 58 survivors, in four buckets that sum to the measured population. Keep classifications
// there so a local note cannot again look exhaustive after the enumerator or package moves.
//
// AND ONE DISMISSAL HERE WAS MEASURABLY WRONG, corrected on the 2026-09-08 re-sweep. The
// nonce-size check was recorded as redundant because "the AEAD catches the same inputs
// downstream". It does not: crypto/cipher PANICS on any nonce length but 12, so the guard is
// the only thing between an attacker-written envelope field and a crash of the offline
// inspector. See envelope_inputs_test.go, which now gates it. The reasoning had answered the
// adjacent question — "is the envelope still unopenable?" — rather than "does the process
// survive to say so?".

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAWhitespaceOnlyDeploymentVersionIsBlank(t *testing.T) {
	// X16: a version file of spaces and newlines is present-but-blank, distinct from empty
	// (which normalises to absent for its kind) and from real text. Without the guard it
	// exported, and a recovery point carried provenance that said nothing.
	f := newFixture(t, true)
	if err := os.WriteFile(f.sources.SiteVersion, []byte(" \n\t\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Build(f.sources, "sitea", time.Now())
	if err == nil || !strings.Contains(err.Error(), "blank") {
		t.Fatalf("a whitespace-only deployment version exported (err=%v) — provenance that says nothing is not provenance", err)
	}
}

func TestAVersionFileOverThePlainBoundIsRefusedBeforeReading(t *testing.T) {
	// X18: plain entries are bounded at 4096 bytes; a "deployment version" past that is
	// not a version. Sparse file, so the refusal costs no disk and proves the STAT path
	// fires rather than the read.
	f := newFixture(t, true)
	handle, err := os.Create(f.sources.SiteVersion)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Truncate(maxPlainFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	handle.Close()
	_, err = Build(f.sources, "sitea", time.Now())
	// "before reading" is asserted, not asserted-about: see assertRefusedOnStatNotOnRead.
	// This row's original assertion was `Contains(err, "bound")`, which the READ backstop's
	// message also satisfies, so the sparse fixture proved nothing the header claimed.
	assertRefusedOnStatNotOnRead(t, err, "an oversized deployment version exported")
}

func TestScanTreeSkipsNonRegularFiles(t *testing.T) {
	// S10: the boundary is a choice and it is pinned as one — a symlink to a
	// secret-bearing file is NOT followed, so its content is never scanned. Without the
	// regular-file check the symlink WAS followed and its content produced findings,
	// silently changing what a clean verdict means. If this row ever fails the other way,
	// the choice moved and the doc comment owes an update.
	root := t.TempDir()
	target := filepath.Join(root, "real.pem")
	if err := os.WriteFile(target, []byte(strings.Join([]string{"-----BEGIN ", "PRIVATE KEY-----"}, "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.pem")); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if strings.HasSuffix(finding.Path, "link.pem") {
			t.Fatalf("a symlink was followed into %s — the tree scan read a file it was not pointed at", finding.Path)
		}
	}
	// The TARGET itself is a regular file in the tree and is caught: the skip is about
	// indirection, not blindness.
	if len(findings) == 0 {
		t.Fatal("the symlink's target was not scanned — skipping links must not mean skipping their targets")
	}
}

func TestAnUnarmedTreeScanVoidsItsOwnVerdict(t *testing.T) {
	// S11: ScanTree arms its own scan before walking. The arming cannot be broken from
	// outside the package — the shapes are package state — so the row does it from
	// inside: the shapes are emptied, and a tree that would otherwise scan clean must
	// come back VOID rather than clean. This is the property the canary design promises
	// and the only place it is proven for the tree path specifically.
	shapes := markerShapes
	markerShapes = nil
	defer func() { markerShapes = shapes }()
	_, err := ScanTree(t.TempDir())
	if !errors.Is(err, ErrScannerUnarmed) {
		t.Fatalf("an unarmed tree scan returned a verdict (err=%v) — clean without proof of being armed is the failure DEV5's counter taught us to refuse", err)
	}
}
