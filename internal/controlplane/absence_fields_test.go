package controlplane

// THE ABSENCE RULES, ONE OPERAND PER ROW (#237 sweep).
//
// verifyExport treats "this entry is absent" as a claim to be checked rather than obeyed, and
// two of its three absence rules had no test that could fail alone.
//
// ONE FIXTURE, TWO OPERANDS, PINS NEITHER. The absence-marker guard is a three-way ||:
//
//	if e.Path == "" || len(e.Data) > 0 || e.SHA256 != "" { ... malformed as an absence marker }
//
// TestAnAbsenceMarkerIsCheckedNotObeyed forges an entry that sets BOTH a body AND a digest:
//
//	Entry{Path: …, Data: markerBytes, SHA256: "bogus", Absent: true}
//
// so either operand alone still refuses it and the test stays green with either one gone.
// Measured: both survive mutation. The forgery it describes is real and the test's account of it
// is right — but as a GATE it pins the disjunction, not the operands, and the disjunction is not
// what an attacker gets to choose. An attacker writing this payload writes ONE shape, and the
// cheapest one carries a body with NO digest, because a digest is the field that gets compared.
// The rows below separate them: each sets exactly one of the two, so exactly one operand can
// refuse it.
//
//	Data set, SHA256 empty   -> only `len(e.Data) > 0` refuses. Measured with it neutralised:
//	                            ACCEPTED. The bytes then skip the digest check (absent entries
//	                            are not digested), skip the secret scan (`!named.entry.Absent`
//	                            gates it), and reach the operator's report as the word "absent".
//	SHA256 set, Data empty   -> only `e.SHA256 != ""` refuses. Measured: ACCEPTED — a
//	                            half-formed field the verifier is asked to guess the meaning of.
//
// The third operand, `e.Path == ""`, is NOT given a gate here and is classified instead:
// validateEntryPath two lines below refuses an empty path in the same pass, so it cannot be the
// sole refuser of anything.
//
// AND THE AMPUTATION RULE HAS TWO HALVES, ONE OF WHICH WAS TESTED. A journal may be absent only
// if nothing remembers history it should have; the export checks this for the audit journal and,
// separately, for the policy state journal. Every existing test uses the audit half. Measured
// with the policy half neutralised: a policy journal deleted with its mark left behind — spent
// reservation quota, amputated — is accepted, and a restore built on it re-grants quota that was
// already spent.

import (
	"crypto/ecdh"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// sealAs re-seals a mutated copy of a genuine export to the SAME authority, so a refusal below
// is about the mutation and never about a key mismatch.
func sealAs(t *testing.T, key *ecdh.PrivateKey, export *Export, mutate func(*Export)) []byte {
	t.Helper()
	forged := *export
	mutate(&forged)
	payload, err := json.Marshal(&forged)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(payload, key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestEachAbsenceMarkerFieldIsRefusedOnItsOwn(t *testing.T) {
	_, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// The version file is the probe entry for the same reason the original test chose it: it
	// has no sidecar and no chain, so with the absence guard removed NOTHING else looks at an
	// absent entry's bytes. A journal would trip the sidecar amputation rule first and the
	// mutation would be caught by the wrong detector.
	versionPath := export.SiteVersion.Path
	body := []byte(strings.Join([]string{"-----BEGIN ", "PRIVATE KEY-----"}, "") + " forged-body")

	// ANCHOR: a WELL-FORMED absence marker — a real path and nothing else — is accepted.
	// Without it the two refusals below are compatible with "an absent version file is always
	// refused", which would make them prove nothing about the extra fields.
	anchor := sealAs(t, key, export, func(e *Export) {
		e.SiteVersion = Entry{Path: versionPath, Absent: true}
	})
	if _, err := Inspect(anchor, key); err != nil {
		t.Fatalf("anchor: a well-formed absence marker was refused: %v — a site whose version "+
			"file has not been written yet is a legitimate state", err)
	}

	for _, row := range []struct {
		name  string
		entry Entry
		why   string
	}{
		{
			name:  "a body with no digest",
			entry: Entry{Path: versionPath, Data: body, Absent: true},
			why: "these bytes are in the payload, are never digested (absent entries are not), " +
				"are never secret-scanned (the scan skips absent entries), and are reported to " +
				"the operator as the single word \"absent\"",
		},
		{
			name:  "a digest with no body",
			entry: Entry{Path: versionPath, SHA256: strings.Repeat("ab", 32), Absent: true},
			why: "an absence marker that records a digest is claiming both that there was " +
				"nothing and that the nothing hashed to something",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			envelope := sealAs(t, key, export, func(e *Export) { e.SiteVersion = row.entry })

			opened, err := Inspect(envelope, key)

			if err == nil {
				t.Fatalf("an absence marker carrying %s was accepted (path=%q): %s",
					row.name, opened.SiteVersion.Path, row.why)
			}
			if !strings.Contains(err.Error(), "absence marker") {
				t.Fatalf("refused by the wrong rule: %v — this row exists to pin the "+
					"absence-marker guard, and a refusal from anywhere else means the "+
					"guard is not what protects against this shape", err)
			}
		})
	}
}

func TestThePolicyJournalsAmputationIsCheckedLikeTheAuditJournalsIs(t *testing.T) {
	// The audit half of this rule has a test; the policy half had none, and the two are
	// separate `if` statements over separate fields. A policy state journal deleted while its
	// high-water mark survives is the same amputation: the mark records reservations the
	// payload no longer carries, so a site restored from it re-grants quota that was spent.
	_, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// The fixture's mark must actually record spent quota, or the row is a fixture too
	// generous to be real: a mark at sequence 0 is consistent with an absent journal and
	// this test would pass against a disarmed guard.
	var mark struct {
		Sequence uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(export.PolicyMark.Data, &mark); err != nil {
		t.Fatalf("fixture: the policy mark must be a readable mark: %v", err)
	}
	if mark.Sequence == 0 {
		t.Fatalf("fixture: the policy mark records sequence 0, which is what a never-written "+
			"journal looks like — this row would pass with the guard removed. mark=%s",
			export.PolicyMark.Data)
	}

	envelope := sealAs(t, key, export, func(e *Export) {
		e.PolicyState = Entry{Path: e.PolicyState.Path, Absent: true}
	})

	opened, err := Inspect(envelope, key)

	if err == nil {
		t.Fatalf("a policy state journal deleted with its mark left behind was accepted "+
			"(mark records sequence %d, journal reported %v) — spent reservation quota was "+
			"amputated and the stump certified intact, so a restore re-grants it",
			mark.Sequence, opened.PolicyState.Absent)
	}
	if !strings.Contains(err.Error(), "amputated") {
		t.Fatalf("refused by the wrong rule: %v — the audit journal's half of this rule is "+
			"already tested, so a refusal that does not name amputation would mean this row "+
			"is riding on the other half", err)
	}
}
