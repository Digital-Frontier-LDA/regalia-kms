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
		"the test TestForceAdvanceAdvancesToLastPlusOne covers this",
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

The reservation MUST NOT be released; TestForceAdvance covers the retention.
`
	p := filepath.Join(dir, "doc.md")
	if err := os.WriteFile(p, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	got := scanDoc(p)
	if len(got) != 1 {
		t.Fatalf("got %d flagged lines, want 1: %#v", len(got), got)
	}
	if got[0].Line != 3 {
		t.Errorf("flagged line = %d, want 3 (the unlinked SHALL)", got[0].Line)
	}
}
