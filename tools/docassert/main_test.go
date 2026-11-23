package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGuaranteeReMatches(t *testing.T) {
	pos := []string{
		"The KMS SHALL verify the signature.",
		"the operation MUST NOT release the reservation",
		"a document is refused before policy evaluation",
		"the append fails closed on sync error",
		"the signature is verified in-daemon",
	}
	for _, s := range pos {
		if !guaranteeRe.MatchString(s) {
			t.Errorf("guaranteeRe should match %q", s)
		}
	}
	neg := []string{
		"This is a plain descriptive sentence.",
		"the value is a uint64 counter",
	}
	for _, s := range neg {
		if guaranteeRe.MatchString(s) {
			t.Errorf("guaranteeRe should NOT match %q", s)
		}
	}
}

func TestLinkReMatches(t *testing.T) {
	pos := []string{
		"see openspec/specs/policy-state-journal/spec.md",
		"see openspec/changes/sequence-recovery-runbook/",
		"the test TestACosmosPolicyWithAFeeOnlyDenominationIsRefusedAtLoad covers this",
		"// spec: policy-state-journal/force-advance",
		"verified by tools/spectrace",
	}
	for _, s := range pos {
		if !linkRe.MatchString(s) {
			t.Errorf("linkRe should match %q", s)
		}
	}
	neg := []string{
		"a sentence with no pointer to a spec or test",
	}
	for _, s := range neg {
		if linkRe.MatchString(s) {
			t.Errorf("linkRe should NOT match %q", s)
		}
	}
}

func TestScanDocFlagsUnlinkedAndPassesLinked(t *testing.T) {
	dir := t.TempDir()
	// Paragraph 1: a guarantee with no link -> flagged.
	// Paragraph 2: a guarantee with a spec link on a sibling line -> not flagged.
	// Paragraph 3: a guarantee with a Test name -> not flagged.
	doc := `# Doc

The KMS SHALL verify every signature before reporting success.

This operation is refused at the parser boundary; see
openspec/specs/cosmos-authinfo-parser/spec.md for the requirement.

The fee cap MUST have a transfer cap; TestACosmosPolicyWithAFeeOnlyDenominationIsRefusedAtLoad covers it.
`
	p := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := scanDoc(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d flagged lines, want 1: %#v", len(got), got)
	}
	if got[0].Line != 3 {
		t.Errorf("flagged line = %d, want 3 (the unlinked SHALL)", got[0].Line)
	}
}

// An unreadable or missing document is an error, never a clean result.
func TestScanDocReportsAnUnreadableDocument(t *testing.T) {
	got, err := scanDoc(filepath.Join(t.TempDir(), "missing.md"))
	if err == nil {
		t.Fatalf("scanDoc on a missing file returned no error (findings %#v): an unread doc would pass -fail", got)
	}
}

// A -docs root that does not exist fails the scan; it is not a clean scan of nothing.
func TestScanTreeReportsAMissingRoot(t *testing.T) {
	got, err := scanTree(filepath.Join(t.TempDir(), "no-such-dir"), "")
	if err == nil {
		t.Fatalf("scanTree on a missing root returned no error (findings %#v)", got)
	}
}

// The control: an existing root with one clean document scans without error.
func TestScanTreeAcceptsAnExistingRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.md"), []byte("# A\n\nplain text\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := scanTree(dir, "")
	if err != nil || len(got) != 0 {
		t.Fatalf("scanTree(clean dir) = %#v, %v; want no findings and no error", got, err)
	}
}
