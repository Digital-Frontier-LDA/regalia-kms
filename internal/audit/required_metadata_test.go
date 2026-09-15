package audit

// #237 operand sweep: validateDraft's completeness rule is five operands and had one detector.
//
//	if draft.Operation == "" || draft.Outcome == "" ||
//	   draft.RegistryDigest == "" || draft.PolicyDigest == "" || draft.RBACDigest == ""
//
// TestValidateDraftRejectsEmptyRBACDigest covers the last one. Each of the other four could be
// replaced with a constant and the whole tree stayed green.
//
// The neighbouring suite does not reach them and cannot: draft_validation_test.go walks every
// string field of Draft, but it walks them against the UNSAFE-CONTENT rules — key material,
// control characters, the length cap — and an empty string is safe by all three. Emptiness is a
// different rule with a different message, and the field it is missing from is invisible from
// there.
//
// What that admits is an event naming no operation, or carrying no outcome, or citing neither the
// registry nor the policy it was decided against. It is then hashed into the chain, which is the
// point at which nothing downstream can repair it: the record is the evidence, and an evidence
// line with an empty operation says nothing about what happened while looking exactly like a line
// that does.
//
// A TABLE RATHER THAN A CASE, because which operand is missing ALTERNATES between fields. One row
// leaves the other four exactly as unpinned as they were, and that is the state this file found.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestARecordMissingRequiredMetadataIsRefusedFieldByField(t *testing.T) {
	for field, clear := range map[string]func(*Draft){
		"Operation":      func(item *Draft) { item.Operation = "" },
		"Outcome":        func(item *Draft) { item.Outcome = "" },
		"RegistryDigest": func(item *Draft) { item.RegistryDigest = "" },
		"PolicyDigest":   func(item *Draft) { item.PolicyDigest = "" },
		"RBACDigest":     func(item *Draft) { item.RBACDigest = "" },
	} {
		t.Run(field, func(t *testing.T) {
			item := draft("018f0000-0000-7000-8000-000000000001", "allow")
			clear(&item)

			err := validateDraft(item)
			if err == nil {
				t.Fatalf("an audit draft with an empty %s was accepted: the event is hashed into the chain naming nothing where %s belongs, and no later reader can tell whether the field was empty or the record was never complete", field, field)
			}
			// Compared exactly. validateDraft returns fixed sentinel strings and the rules
			// around this one fire on the same drafts for their own reasons, so a non-nil check
			// or a substring match would be satisfied by a refusal that leaves this field's own
			// operand unpinned.
			if err.Error() != "incomplete audit metadata" {
				t.Fatalf("an empty %s was refused as %q rather than as incomplete metadata: some other rule fired, and this field's operand stays uncovered", field, err)
			}
		})
	}

	// KNOWN-GOOD, so none of the rows above is satisfied by a validator that refuses everything.
	// Placed after the table on purpose: a t.Fatal here would otherwise foreclose the rows it
	// exists to support.
	if err := validateDraft(draft("018f0000-0000-7000-8000-000000000001", "allow")); err != nil {
		t.Fatalf("the baseline draft was refused (%v), so every row above is equally consistent with a validator that accepts nothing", err)
	}
}

// AND THE REFUSAL MUST HAPPEN BEFORE THE CHAIN, not merely somewhere. validateDraft runs first in
// Record, so an incomplete draft never reaches the append; this pins that the journal stays empty
// rather than gaining an event that a later reader would have to interpret.
func TestAnIncompleteDraftNeverReachesTheJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()

	incomplete := draft("018f0000-0000-7000-8000-000000000001", "allow")
	incomplete.Operation = ""
	if err := recorder.Record(context.Background(), incomplete, false); err == nil {
		t.Fatal("Record accepted a draft naming no operation")
	}

	// The journal file is created by Open, so its EXISTENCE proves nothing; its content does.
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(contents)) != "" {
		t.Fatalf("the journal holds %q after a refused draft: the record was written before the rule ran, and a hashed event cannot be withdrawn", contents)
	}

	// The control: the same recorder still accepts a complete draft, so the empty journal above
	// is the refusal's doing rather than a recorder that writes nothing at all.
	if err := recorder.Record(context.Background(), draft("018f0000-0000-7000-8000-000000000002", "allow"), false); err != nil {
		t.Fatalf("a complete draft was refused (%v), so the empty journal above says nothing about the incomplete one", err)
	}
	if events, err := Verify(path); err != nil || len(events) != 1 {
		t.Fatalf("the journal holds %d events (%v) after one refused and one accepted draft, want 1", len(events), err)
	}
}
