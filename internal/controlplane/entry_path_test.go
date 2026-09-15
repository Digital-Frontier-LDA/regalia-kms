package controlplane

import (
	"strings"
	"testing"
)

// EVERY OPERAND OF THE ENTRY-PATH SHAPE, AND WHAT EACH ONE ADMITS WHEN IT IS GONE.
//
// validateEntryPath is four operands over payload-controlled input: an Export is decrypted from an
// envelope anyone can seal to the authority's public key, and every one of its seven entries
// carries a Path that reaches verifyExport and the operator's report. The sweep found three of the
// four unexercised, plus one of the two control-character operands.
//
// Measured with each neutralised in turn, not inferred:
//
//	path == ""                 -> PANIC, index out of range: path[0] on an empty string
//	path != filepath.Clean(..) -> "/a/../../../etc/passwd" ACCEPTED
//	len(path) > 512            -> a 513-byte path ACCEPTED
//	r == 0x7f                  -> a DEL-bearing path ACCEPTED
//
// The `path[0] != '/'` operand and the `r < 0x20` operand already had detectors; the rows for them
// are anchors here rather than gates, and are labelled as such.
func TestValidateEntryPathRefusesEveryMalformedShape(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string // "" means accepted
	}{
		// ANCHOR. Without it every refusal below is compatible with "the function refuses everything".
		{"a clean guest-absolute path", "/audit/journal.jsonl", ""},

		// GATE: without this operand, path[0] panics with index out of range.
		{"an empty path", "", "not a clean guest-absolute path"},

		// GATE: the traversal case. This operand is the only thing that refuses it.
		{"a parent-directory traversal", "/a/../../../etc/passwd", "not a clean guest-absolute path"},
		// Same operand, the non-canonical form a reader is likelier to write by hand.
		{"an uncleaned path", "/a/./b", "not a clean guest-absolute path"},

		// GATE: the length bound. A report field with no bound is its own denial of legibility.
		{"a path one byte over the bound", "/" + strings.Repeat("x", 512), "not a clean guest-absolute path"},

		// GATE: DEL. Its sibling (r < 0x20) already had a detector; this one did not.
		{"a path carrying DEL", "/audit/\x7fjournal", "carries a control character"},

		// ANCHORS for the two operands that were already covered, kept so a future edit that
		// removes them fails here rather than silently widening what an export may carry.
		{"a relative path", "relative/path", "not a clean guest-absolute path"},
		{"a path carrying a control byte", "/audit/\x01journal", "carries a control character"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// RECOVERED DELIBERATELY: the empty-path operand crashes rather than refuses when
			// removed, and an unrecovered panic kills the binary and reports nothing about which
			// fixture reached it.
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("validateEntryPath panicked instead of refusing: %v", recovered)
				}
			}()
			err := validateEntryPath(testCase.path)
			if testCase.want == "" {
				if err != nil {
					t.Fatalf("the anchor was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %q as an entry path", testCase.path)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want it to contain %q", err, testCase.want)
			}
		})
	}
}

// AND THE PATH IS REACHABLE FROM THE SEALED ENVELOPE, not only from a direct call.
//
// The table above pins the operands; this pins that they are on the attacker's path. Anyone can
// seal an Export to the authority's published public key, so Inspect decrypts payload-controlled
// bytes — and a traversal path inside one must not survive verifyExport. Without the Clean operand
// this export is accepted and its entry path flows into the operator report.
func TestAForgedExportCannotCarryATraversalPath(t *testing.T) {
	publicPEM, privatePEM := testKeys(t)
	authority, err := ParseAuthorityKey(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	// Only the path is changed: the entry's data and digest still agree, so the digest check
	// cannot be what refuses this and the refusal is attributable to the path shape.
	envelope := sealEvilPayload(t, publicPEM, func(export *Export) {
		export.AuditJournal.Path = "/a/../../../etc/passwd"
	})

	export, err := Inspect(envelope, authority)

	if err == nil {
		t.Fatalf("a forged export carrying a traversal path was accepted: %#v", export.AuditJournal.Path)
	}
	if !strings.Contains(err.Error(), "not a clean guest-absolute path") {
		t.Fatalf("error = %q, want the path-shape refusal — another guard refusing this would "+
			"mean the path operand is not what protects the report", err)
	}
}
