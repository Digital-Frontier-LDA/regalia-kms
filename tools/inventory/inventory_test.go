package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// today is fixed so the expiry rule is a question about the fixture rather than about the day the
// suite runs. A test whose result changes at midnight is a test that will fail once, for nobody, on
// a branch nobody is looking at.
var today = time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

// baseDocument is the known-good inventory: one system, one record, every field present and valid.
//
// It is built from maps rather than from the Go structs on purpose. Every negative case below is
// this document with ONE key deleted or changed, and a map is the only representation in which
// "the key is absent" is expressible -- with a struct literal an omitted string is "" and an
// omitted pointer is nil, which is what the decoder has to tell apart, so a struct-based fixture
// would be testing the zero value rather than the absence.
func baseDocument() map[string]any {
	return map[string]any{
		"schema_version": 1,
		"inventory_id":   "regalia-estate",
		"generated_at":   "2026-09-01",
		"systems": []any{
			map[string]any{"id": "forge", "owner": "@df/platform"},
		},
		"records": []any{baseRecord()},
	}
}

func baseRecord() map[string]any {
	return map[string]any{
		"id":          "forge-deploy-credential",
		"system":      "forge",
		"class":       "api-token",
		"owner":       "@df/platform",
		"environment": "production",
		"rotation":    "provider-automated",
		"location":    "saas:forge/settings/credentials",
		"custody":     "hardware-envelope",
	}
}

// exceptionRecord is the base record moved to exception custody, expiring on the given day.
func exceptionRecord(expires string) map[string]any {
	record := baseRecord()
	record["custody"] = "exception"
	record["exception"] = map[string]any{
		"expires":     expires,
		"approved_by": "@jobordu",
		"tracking":    "regalia#33",
	}
	return record
}

func encode(t *testing.T, document any) []byte {
	t.Helper()
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("fixture will not marshal: %v", err)
	}
	return data
}

func verify(t *testing.T, document any) Report {
	t.Helper()
	return Verify(encode(t, document), today)
}

// hasRefusal reports whether some refusal at a location beginning with `where` gave exactly this
// reason.
//
// EXACT REASON, NOT SUBSTRING, and the difference is not pedantry: "id is required" is a substring
// of "inventory_id is required", so a substring assertion for the record's missing id would have
// been satisfied by the document-level refusal and the record rule could have been deleted without
// the test noticing.
func hasRefusal(report Report, where, reason string) bool {
	for _, refusal := range report.Refusals {
		if strings.HasPrefix(refusal.Where, where) && refusal.Reason == reason {
			return true
		}
	}
	return false
}

func hasRefusalContaining(report Report, where, fragment string) bool {
	for _, refusal := range report.Refusals {
		if strings.HasPrefix(refusal.Where, where) && strings.Contains(refusal.Reason, fragment) {
			return true
		}
	}
	return false
}

func dump(report Report) string {
	lines := make([]string, 0, len(report.Refusals))
	for _, refusal := range report.Refusals {
		lines = append(lines, refusal.String())
	}
	if len(lines) == 0 {
		return "(no refusals)"
	}
	return strings.Join(lines, "; ")
}

// TestTheKnownGoodInventoryIsAccepted is the anchor for every negative test in this file (§18). A
// rule that refused EVERYTHING would satisfy all of them, and without this row nothing would say
// so.
func TestTheKnownGoodInventoryIsAccepted(t *testing.T) {
	report := verify(t, baseDocument())
	if !report.OK() {
		t.Fatalf("the known-good inventory was refused: %s", dump(report))
	}
	if report.Records != 1 || report.Systems != 1 {
		t.Fatalf("counted %d records and %d systems, want 1 and 1", report.Records, report.Systems)
	}
	if Verdict(report) != "VERIFIED" {
		t.Fatalf("verdict %q on a clean run", Verdict(report))
	}
}

// TestOmittingAnyRequiredFieldIsRefused deletes exactly one key at a time and requires a refusal
// naming it.
//
// THIS IS THE TABLE THAT FINDS A SILENT DEFAULT, and that is why the fixtures are subtractive
// rather than additive. A test that builds a record by setting every field cannot tell an enforced
// requirement from a field that quietly defaults when absent: both produce a valid record, both go
// green, and the guard reads as covered. Deleting one key at a time is the only arrangement in
// which "this field defaults to something" and "this field is required" have different outcomes.
//
// A missing field here therefore means one of two things, and both are defects: either the rule is
// gone, or the field acquired a default nobody declared.
func TestOmittingAnyRequiredFieldIsRefused(t *testing.T) {
	t.Run("document", func(t *testing.T) {
		for field, reason := range map[string]string{
			"schema_version": "unsupported schema_version 0, expected 1",
			"inventory_id":   "inventory_id is required",
			"generated_at":   "generated_at is required: an inventory with no date cannot be attested to",
			"records":        "inventory declares no records: a run over an empty set is not a statement about the estate",
		} {
			t.Run(field, func(t *testing.T) {
				document := baseDocument()
				delete(document, field)
				report := verify(t, document)
				if !hasRefusal(report, "document", reason) {
					t.Fatalf("omitting %q was not refused with %q: %s", field, reason, dump(report))
				}
			})
		}
		// `systems` is the one document key whose absence is not its own message: the record still
		// names forge, and the dangling-reference rule is what catches it. Asserting the referential
		// refusal rather than inventing a "systems is required" rule keeps one rule per condition.
		t.Run("systems", func(t *testing.T) {
			document := baseDocument()
			delete(document, "systems")
			report := verify(t, document)
			if !hasRefusal(report, "records[0]", `system "forge" is named here but not declared in systems`) {
				t.Fatalf("a record naming an undeclared system was accepted: %s", dump(report))
			}
		})
	})

	t.Run("system", func(t *testing.T) {
		for field, reason := range map[string]string{
			"id":    "id is required",
			"owner": "owner is required",
		} {
			t.Run(field, func(t *testing.T) {
				document := baseDocument()
				system := document["systems"].([]any)[0].(map[string]any)
				delete(system, field)
				report := verify(t, document)
				if !hasRefusal(report, "systems[0]", reason) {
					t.Fatalf("omitting system %q was not refused with %q: %s", field, reason, dump(report))
				}
			})
		}
	})

	t.Run("record", func(t *testing.T) {
		for field, reason := range recordOmissions {
			t.Run(field, func(t *testing.T) {
				document := baseDocument()
				record := document["records"].([]any)[0].(map[string]any)
				delete(record, field)
				report := verify(t, document)
				if !hasRefusal(report, "records[0]", reason) {
					t.Fatalf("omitting record %q was not refused with %q: %s", field, reason, dump(report))
				}
			})
		}
	})
}

// recordOmissions is the expected refusal for deleting each record key. It is a package-level
// variable so TestEveryRecordFieldIsInTheOmissionTable can compare it against the struct.
var recordOmissions = map[string]string{
	"id":          "id is required",
	"system":      "system is required",
	"class":       "class is required",
	"owner":       "owner is required",
	"environment": "environment is required",
	"rotation":    "rotation is required",
	"location":    "location is required",
	"custody":     "custody is required",
}

// TestEveryRecordFieldIsInTheOmissionTable holds the table above to the type it is testing.
//
// AN ENUMERATION IS NOT A SWEEP UNLESS SOMETHING COMPARES THE TWO. The omission table is hand
// written, so adding a field to Record and forgetting to add a row leaves that field with no test
// -- and the suite stays green, because every existing row still passes. This reads the struct
// tags and requires the two to agree, so the failure lands on whoever adds the field rather than
// on whoever later wonders why it was never checked.
//
// `exception` is the one exempt key: it is absent from a valid non-exception record by design, so
// "omitting it is refused" is false for it. Its rules are in TestExceptionCustody below.
func TestEveryRecordFieldIsInTheOmissionTable(t *testing.T) {
	recordType := reflect.TypeOf(Record{})
	if recordType.NumField() == 0 {
		t.Fatal("Record has no fields: this test would pass while checking nothing")
	}
	optional := map[string]struct{}{"exception": {}}
	tags := map[string]struct{}{}
	for i := 0; i < recordType.NumField(); i++ {
		tag := recordType.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			t.Fatalf("Record field %q has no json tag, so no document can address it", recordType.Field(i).Name)
		}
		tags[name] = struct{}{}
		if _, exempt := optional[name]; exempt {
			continue
		}
		if _, covered := recordOmissions[name]; !covered {
			t.Errorf("Record field %q has no row in recordOmissions: nothing tests that it is required", name)
		}
	}
	for name := range recordOmissions {
		if _, exists := tags[name]; !exists {
			t.Errorf("recordOmissions names %q, which Record no longer has: the row tests nothing", name)
		}
	}
	// The base fixture must set every field the table covers, or a row would be deleting a key that
	// was never there and asserting a refusal that some other missing field produced.
	record := baseRecord()
	for name := range recordOmissions {
		if _, set := record[name]; !set {
			t.Errorf("baseRecord does not set %q, so deleting it in the omission table proves nothing", name)
		}
	}
}

// TestVocabularyMatchesThePublishedCustodySchema binds the three shared sets to the custody
// manifest's schema, which is the artifact both this tool and the daemon's loader answer to.
//
// The sets are copied into inventory.go because the loader's own copies are unexported. A copy
// that nothing compares is a copy that drifts: this repository has already shipped a manifest the
// daemon accepted and CI refused, from exactly that shape.
func TestVocabularyMatchesThePublishedCustodySchema(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			CustodyObject struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
			} `json:"custodyObject"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(contents, &schema); err != nil {
		t.Fatal(err)
	}
	for published, local := range map[string]map[string]struct{}{
		"kind":        secretClasses,
		"environment": environments,
		"custody":     custodyModes,
	} {
		enum := schema.Defs.CustodyObject.Properties[published].Enum
		if len(enum) == 0 {
			t.Fatalf("the schema publishes no enum for %q, so this test is checking nothing", published)
		}
		if len(enum) != len(local) {
			t.Errorf("%s: the schema publishes %d values and the inventory accepts %d — a secret described by one vocabulary would not survive being described by the other", published, len(enum), len(local))
		}
		for _, value := range enum {
			if _, ok := local[value]; !ok {
				t.Errorf("%s: the custody manifest publishes %q and this inventory refuses it, so a secret could not be inventoried in the terms it will be held under", published, value)
			}
		}
	}
	// The four classifications #33 names, spelled as the manifest spells them. Asserted by count
	// and by membership rather than only by the loop above, because the loop would still pass if
	// both the schema and this file lost the same mode.
	if len(custodyModes) != 4 {
		t.Fatalf("custody is a closed set of four classifications, found %d", len(custodyModes))
	}
	for _, required := range []string{"direct-hardware", "hardware-envelope", "fido-multi-enrollment", "exception"} {
		if _, ok := custodyModes[required]; !ok {
			t.Errorf("custody classification %q is missing", required)
		}
	}
}

// TestTheIdentifierShapeDivergesFromTheRegistryOnPurpose turns the comment on identifierPattern
// into a check.
//
// The comment claims the two shapes differ in BOTH directions and gives an example each way. An
// earlier draft claimed the opposite -- that this pattern matched the registry's -- which was
// simply false, and nothing would have caught it, because a comment describing a relationship to
// another package is exactly the kind of claim that rots silently. If the registry widens or
// narrows its identifier, this goes red and whoever changes it decides what the inventory should
// do, rather than finding out later that two files disagree about what a name is.
func TestTheIdentifierShapeDivergesFromTheRegistryOnPurpose(t *testing.T) {
	for _, row := range []struct {
		value           string
		inventoryAccept bool
		registryAccept  bool
		why             string
	}{
		{"ci", true, false, "an inventory names short systems; the registry imposes a 3-character minimum"},
		{"forge--a-", false, true, "a doubled or trailing hyphen is a typo in a name people read"},
		{"forge-deploy-credential", true, true, "the ordinary case must be valid to both"},
	} {
		t.Run(row.value, func(t *testing.T) {
			if got := identifierPattern.MatchString(row.value); got != row.inventoryAccept {
				t.Errorf("the inventory %s %q, want %s (%s)",
					accepted(got), row.value, accepted(row.inventoryAccept), row.why)
			}
			if got := registry.MatchesIdentifier(row.value); got != row.registryAccept {
				t.Errorf("the registry %s %q, want %s — the comment on identifierPattern describes a divergence that no longer holds (%s)",
					accepted(got), row.value, accepted(row.registryAccept), row.why)
			}
		})
	}
}

func accepted(ok bool) string {
	if ok {
		return "accepts"
	}
	return "refuses"
}

// TestUnsupportedEnumValueIsRefused covers the closed sets. A value outside the set is the shape
// where an inventory invents a fifth custody classification in prose.
func TestUnsupportedEnumValueIsRefused(t *testing.T) {
	for field, reason := range map[string]string{
		"class":       `unsupported class "made-up"`,
		"environment": `unsupported environment "made-up"`,
		"rotation":    `unsupported rotation "made-up"`,
		"custody":     `unsupported custody "made-up"`,
	} {
		t.Run(field, func(t *testing.T) {
			document := baseDocument()
			document["records"].([]any)[0].(map[string]any)[field] = "made-up"
			report := verify(t, document)
			if !hasRefusal(report, "records[0]", reason) {
				t.Fatalf("an unsupported %s was accepted: %s", field, dump(report))
			}
		})
	}
}

// TestExceptionCustody covers the classification #33 singles out. An exception is the only custody
// mode that is allowed to be temporary, so every rule here is about it staying temporary.
func TestExceptionCustody(t *testing.T) {
	// The whole point of the classification: an approved, in-date exception is a legitimate state
	// and must pass, or the rules below would be satisfied by refusing all exceptions.
	t.Run("in date (known good)", func(t *testing.T) {
		document := baseDocument()
		document["records"] = []any{exceptionRecord("2026-12-31")}
		report := verify(t, document)
		if !report.OK() {
			t.Fatalf("a live exception was refused: %s", dump(report))
		}
	})

	// BOTH SIDES OF THE BOUNDARY. An exception is live through the whole of its final day, so the
	// day itself must pass and the day before must fail. Testing only the expired side would be
	// satisfied by a rule that refused every exception ever written.
	t.Run("expires today", func(t *testing.T) {
		document := baseDocument()
		document["records"] = []any{exceptionRecord("2026-09-08")}
		report := verify(t, document)
		if !report.OK() {
			t.Fatalf("an exception expiring today was refused: %s", dump(report))
		}
	})

	t.Run("expired yesterday", func(t *testing.T) {
		document := baseDocument()
		document["records"] = []any{exceptionRecord("2026-09-07")}
		report := verify(t, document)
		if !hasRefusal(report, "records[0]", "exception expired on 2026-09-07: re-approve it or move the secret to a supported custody mode") {
			t.Fatalf("an expired exception was accepted: %s", dump(report))
		}
	})

	// THE STRUCTURAL RULE. Each of the three fields is required by Exception.UnmarshalJSON, so an
	// exception missing one is not a record that fails validation -- it is a document that does not
	// decode. Deleting the key one at a time is the same subtractive method as the omission table,
	// applied to the nested object.
	t.Run("missing field does not decode", func(t *testing.T) {
		for field, fragment := range map[string]string{
			"expires":     `exception requires "expires"`,
			"approved_by": `exception requires "approved_by"`,
			"tracking":    `exception requires "tracking"`,
		} {
			t.Run(field, func(t *testing.T) {
				document := baseDocument()
				record := exceptionRecord("2026-12-31")
				delete(record["exception"].(map[string]any), field)
				document["records"] = []any{record}
				report := verify(t, document)
				if !hasRefusalContaining(report, "document", fragment) {
					t.Fatalf("an exception without %q decoded: %s", field, dump(report))
				}
			})
		}
	})

	t.Run("expiry must be a date", func(t *testing.T) {
		document := baseDocument()
		record := exceptionRecord("2026-12-31")
		record["exception"].(map[string]any)["expires"] = "next quarter"
		document["records"] = []any{record}
		report := verify(t, document)
		if !hasRefusalContaining(report, "document", `"next quarter" is not a 2006-01-02 date`) {
			t.Fatalf("a prose expiry decoded: %s", dump(report))
		}
	})

	// A DATE THAT IS NOT EVEN A STRING. Also found by the falsifiability sweep: with no test for
	// this, the branch could be deleted and the suite stayed green, because `time.Parse` on the
	// zero value refuses too and the document is still rejected -- by the wrong guard, with a
	// message quoting an empty string instead of naming what was actually written. The refusal is
	// the same; the sentence the operator reads is not.
	t.Run("expiry must be a string", func(t *testing.T) {
		document := baseDocument()
		record := exceptionRecord("2026-12-31")
		record["exception"].(map[string]any)["expires"] = 20261231
		document["records"] = []any{record}
		report := verify(t, document)
		if !hasRefusalContaining(report, "document", "must be a JSON string holding a 2006-01-02 date") {
			t.Fatalf("a numeric expiry was not named as the wrong type: %s", dump(report))
		}
	})

	// PRESENCE IS NOT AUDITABILITY. UnmarshalJSON refuses an exception missing approved_by or
	// tracking, and that was the whole of the check — so `"approved_by": "x"` and `"tracking": "x"`
	// satisfied every rule in the file. The exception is the one record type that exists to be
	// chased down and re-argued before its date, and a reference nobody can follow is the same dead
	// end as no reference at all. trackingPattern was written for this and then never applied,
	// which is why it sat in the package as an unused variable.
	t.Run("the approval and the tracking reference must be followable", func(t *testing.T) {
		for name, mutate := range map[string]func(map[string]any){
			"approved_by is not a handle":     func(e map[string]any) { e["approved_by"] = "x" },
			"approved_by is prose":            func(e map[string]any) { e["approved_by"] = "the security team" },
			"tracking is not a reference":     func(e map[string]any) { e["tracking"] = "x" },
			"tracking has no issue number":    func(e map[string]any) { e["tracking"] = "regalia#" },
			"tracking is a bare number":       func(e map[string]any) { e["tracking"] = "33" },
			"tracking numbers an issue zero":  func(e map[string]any) { e["tracking"] = "regalia#0" },
			"tracking is a whole issue title": func(e map[string]any) { e["tracking"] = "see regalia#33 for the argument" },
		} {
			t.Run(name, func(t *testing.T) {
				document := baseDocument()
				record := exceptionRecord("2026-12-31")
				mutate(record["exception"].(map[string]any))
				document["records"] = []any{record}
				report := verify(t, document)
				if report.OK() {
					t.Fatalf("an exception whose %s was accepted: nothing could chase it down", name)
				}
			})
		}
	})

	t.Run("custody exception requires the block", func(t *testing.T) {
		document := baseDocument()
		record := baseRecord()
		record["custody"] = "exception"
		document["records"] = []any{record}
		report := verify(t, document)
		if !hasRefusal(report, "records[0]", `custody "exception" requires an exception block naming expires, approved_by and tracking`) {
			t.Fatalf("custody exception with no terms was accepted: %s", dump(report))
		}
	})

	// The other direction: an expired exception parked on a hardware record would never be looked
	// at again, because the expiry rule only runs for exception custody.
	t.Run("the block requires custody exception", func(t *testing.T) {
		document := baseDocument()
		record := exceptionRecord("2020-01-01")
		record["custody"] = "direct-hardware"
		document["records"] = []any{record}
		report := verify(t, document)
		if !hasRefusal(report, "records[0]", `an exception block is only meaningful with custody "exception", not "direct-hardware"`) {
			t.Fatalf("an exception block on hardware custody was accepted: %s", dump(report))
		}
	})
}

// TestSystemReferencesAreCheckedBothWays covers the fourth required refusal. The two directions are
// separate tests because they are separate defects with separate consequences.
func TestSystemReferencesAreCheckedBothWays(t *testing.T) {
	t.Run("named by a record but not declared", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["system"] = "registrar"
		report := verify(t, document)
		if !hasRefusal(report, "records[0]", `system "registrar" is named here but not declared in systems`) {
			t.Fatalf("a dangling system reference was accepted: %s", dump(report))
		}
	})

	t.Run("declared but named by no record", func(t *testing.T) {
		document := baseDocument()
		document["systems"] = append(document["systems"].([]any),
			map[string]any{"id": "registrar", "owner": "@df/platform"})
		report := verify(t, document)
		if !hasRefusal(report, "systems registrar", "declared but named by no record: either it holds no secrets and should say so, or its discovery is unfinished") {
			t.Fatalf("a system with no records was accepted: %s", dump(report))
		}
	})

	t.Run("duplicate system id", func(t *testing.T) {
		document := baseDocument()
		document["systems"] = append(document["systems"].([]any),
			map[string]any{"id": "forge", "owner": "@df/security"})
		report := verify(t, document)
		if !hasRefusal(report, "systems[1]", `duplicate system id "forge"`) {
			t.Fatalf("a duplicate system id was accepted: %s", dump(report))
		}
	})

	t.Run("duplicate record id", func(t *testing.T) {
		document := baseDocument()
		document["records"] = []any{baseRecord(), baseRecord()}
		report := verify(t, document)
		if !hasRefusal(report, "records[1]", `duplicate record id "forge-deploy-credential"`) {
			t.Fatalf("a duplicate record id was accepted: %s", dump(report))
		}
	})
}

// TestARunThatExaminedNothingRefuses is the gate against the failure this repository actually hit:
// a tool that exited 0 having matched zero files and printed a sentence about files it never
// opened.
func TestARunThatExaminedNothingRefuses(t *testing.T) {
	t.Run("no records", func(t *testing.T) {
		document := baseDocument()
		document["records"] = []any{}
		document["systems"] = []any{}
		report := verify(t, document)
		if report.OK() {
			t.Fatal("an inventory with no records was VERIFIED: the tool reported on an estate it never looked at")
		}
		if !hasRefusal(report, "document", "inventory declares no records: a run over an empty set is not a statement about the estate") {
			t.Fatalf("the empty inventory was refused for some other reason: %s", dump(report))
		}
	})

	t.Run("every record refused", func(t *testing.T) {
		first, second := baseRecord(), baseRecord()
		second["id"] = "forge-signing-credential"
		delete(first, "owner")
		delete(second, "owner")
		document := baseDocument()
		document["records"] = []any{first, second}
		report := verify(t, document)
		if !hasRefusal(report, "document", "all 2 records were refused: this run verified nothing") {
			t.Fatalf("a wholly unreadable inventory was not named as such: %s", dump(report))
		}
	})

	// The counterfactual for the rule above: with one good record among the bad, the run is a
	// partial result and must NOT claim to have verified nothing. Without this, a rule that fired
	// on every document with any refusal would pass the test above.
	t.Run("one good record is not nothing", func(t *testing.T) {
		bad := baseRecord()
		bad["id"] = "forge-signing-credential"
		delete(bad, "owner")
		document := baseDocument()
		document["records"] = []any{baseRecord(), bad}
		report := verify(t, document)
		if hasRefusalContaining(report, "document", "this run verified nothing") {
			t.Fatalf("a run with one valid record claimed to have verified nothing: %s", dump(report))
		}
	})
}

// TestVerdictIsAFunctionOfTheRefusals pins the summary word to the outcome directly, without going
// through a document.
//
// Every other test here reaches Verdict through Verify, so all of them would still pass if Verdict
// returned a constant on some path -- they only ever ask whether a particular document was refused.
// This asks the question the failing sibling tool got wrong: can the success word appear next to a
// non-zero refusal count?
func TestVerdictIsAFunctionOfTheRefusals(t *testing.T) {
	clean := Report{Records: 7, Systems: 3}
	if Verdict(clean) != "VERIFIED" || !clean.OK() {
		t.Fatalf("a report with no refusals gave verdict %q", Verdict(clean))
	}
	for _, count := range []int{1, 2, 50} {
		report := Report{Records: 7, Systems: 3}
		for i := 0; i < count; i++ {
			report.refuse("document", "refusal %d", i)
		}
		if Verdict(report) != "REFUSED" {
			t.Fatalf("a report with %d refusals gave verdict %q", count, Verdict(report))
		}
		if report.OK() {
			t.Fatalf("a report with %d refusals reported OK, so the tool would exit 0", count)
		}
	}
	// A report can carry counts that look like a successful run -- records examined, systems
	// covered, no blockers -- and still be a refusal. The verdict must not be reading those.
	busy := Report{Records: 400, Systems: 40, Blockers: 0}
	busy.refuse("records[399]", "owner is required")
	if Verdict(busy) != "REFUSED" {
		t.Fatal("a large, otherwise healthy-looking run with one refusal was VERIFIED")
	}
}

// TestASecretValueHasNowhereToGo covers the three mechanisms documented at the top of inventory.go.
func TestASecretValueHasNowhereToGo(t *testing.T) {
	// MECHANISM 2, and the one that does the real work. Without DisallowUnknownFields every case
	// here decodes cleanly, the extra key is dropped in memory, the tool prints VERIFIED, and the
	// value stays in the committed file -- the worst available outcome, because the file now has a
	// green check against it.
	t.Run("an unknown field is refused rather than ignored", func(t *testing.T) {
		t.Run("document", func(t *testing.T) {
			document := baseDocument()
			document["value"] = "correct-horse-battery-staple"
			report := verify(t, document)
			if report.OK() {
				t.Fatal("an unknown document key was silently dropped and the inventory verified")
			}
		})
		t.Run("record", func(t *testing.T) {
			document := baseDocument()
			document["records"].([]any)[0].(map[string]any)["value"] = "correct-horse-battery-staple"
			report := verify(t, document)
			if report.OK() {
				t.Fatal("an unknown record key was silently dropped and the inventory verified")
			}
		})
		// The nested object is the hole a custom UnmarshalJSON opens: it receives raw bytes and
		// inherits nothing from the outer decoder, so this case fails unless Exception's own
		// decoder sets DisallowUnknownFields too.
		t.Run("exception", func(t *testing.T) {
			document := baseDocument()
			record := exceptionRecord("2026-12-31")
			record["exception"].(map[string]any)["value"] = "correct-horse-battery-staple"
			document["records"] = []any{record}
			report := verify(t, document)
			if report.OK() {
				t.Fatal("an unknown key inside the exception block was silently dropped and the inventory verified")
			}
		})
		t.Run("system", func(t *testing.T) {
			document := baseDocument()
			document["systems"].([]any)[0].(map[string]any)["value"] = "correct-horse-battery-staple"
			report := verify(t, document)
			if report.OK() {
				t.Fatal("an unknown system key was silently dropped and the inventory verified")
			}
		})
	})

	// MECHANISMS 1 AND 3: with no field that accepts content, material has to be forced into a
	// reference field, where the length cap and the pattern refuse it.
	//
	// The armour header is assembled from two halves rather than written out. .gitleaks.toml
	// requires that: the scanner cannot tell a test fixture from a committed key, which is the
	// property that makes it worth having, and the composed value is byte-identical.
	t.Run("credential shaped text does not fit a reference field", func(t *testing.T) {
		armour := "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + strings.Repeat("b3BlbnNzaC1rZXktdjEA", 20)
		for _, field := range []string{"id", "system", "owner", "location", "class", "custody"} {
			t.Run(field, func(t *testing.T) {
				document := baseDocument()
				document["records"].([]any)[0].(map[string]any)[field] = armour
				report := verify(t, document)
				if report.OK() {
					t.Fatalf("an armoured private key pasted into %q was accepted", field)
				}
			})
		}
	})

	t.Run("an over-long field is refused by size", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["owner"] = "@" + strings.Repeat("a", maxFieldBytes)
		report := verify(t, document)
		if !hasRefusalContaining(report, "records[0]", "over the 128-byte cap") {
			t.Fatalf("an over-long owner was not refused by size: %s", dump(report))
		}
	})

	// THE LENGTH CAP ON `location` NEEDED ITS OWN FIXTURE, and the falsifiability sweep is what
	// said so: deleting the cap broke nothing. The armoured-key rows above look like they cover it,
	// but that string contains a newline and spaces, so `location` refuses it on the scheme
	// separator and the cap is never the guard that fires. A fixture refused by a sibling guard
	// pins neither guard. This one is well-formed in every respect except its size, so the cap is
	// the only thing that can refuse it.
	t.Run("a well-formed but over-long location is refused by size", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["location"] = "sops:" + strings.Repeat("a", maxFieldBytes)
		report := verify(t, document)
		if !hasRefusalContaining(report, "records[0]", "location is 133 bytes, over the 128-byte cap") {
			t.Fatalf("an over-long location was not refused by size: %s", dump(report))
		}
	})

	t.Run("an over-long document is refused before decoding", func(t *testing.T) {
		report := Verify(make([]byte, maxDocumentBytes+1), today)
		if !hasRefusalContaining(report, "document", "exceeds the 1048576-byte cap") {
			t.Fatalf("an over-sized inventory was not refused: %s", dump(report))
		}
	})

	// THE FIELD IS NOT THE ONLY PLACE A VALUE CAN LIVE. Everything above proves a secret has no
	// field to be stored in; this proves it cannot ride out in the error message instead.
	//
	// checkEnum quoted its value with no cap at all, so a five-kilobyte `class` was echoed verbatim
	// into the report and into CI logs — in a tool whose stated premise is that it holds metadata
	// and public identifiers only. It is the third instance of one defect class in this file:
	// unvalidated input reaching output, after the location cap no fixture reached and the record
	// id landing in the refusal label. Every enum field is walked, because the defect was in the
	// shared helper and fixing one call site would have left the other three.
	t.Run("a large value is truncated rather than echoed", func(t *testing.T) {
		huge := strings.Repeat("s", 5000)
		for _, field := range []string{"class", "environment", "rotation", "custody"} {
			t.Run(field, func(t *testing.T) {
				document := baseDocument()
				document["records"].([]any)[0].(map[string]any)[field] = huge
				report := verify(t, document)
				if report.OK() {
					t.Fatalf("a 5000-byte %s was accepted", field)
				}
				for _, refusal := range report.Refusals {
					if strings.Contains(refusal.Reason, huge) {
						t.Fatalf("%s: the whole 5000-byte value was echoed into the report", field)
					}
					if len(refusal.Reason) > 2*maxFieldBytes {
						t.Fatalf("%s: refusal is %d bytes, so the value was not bounded: %.120q…",
							field, len(refusal.Reason), refusal.Reason)
					}
				}
			})
		}
	})

	// The same hole in the two places outside checkEnum where caller text reaches a message with
	// nothing having bounded it first: the date parser and the decoder's own error, which quotes
	// the offending key back at you.
	t.Run("a large expiry is truncated rather than echoed", func(t *testing.T) {
		huge := strings.Repeat("s", 5000)
		document := baseDocument()
		record := exceptionRecord("2026-12-31")
		record["exception"].(map[string]any)["expires"] = huge
		document["records"] = []any{record}
		report := verify(t, document)
		if report.OK() {
			t.Fatal("a 5000-byte expiry was accepted")
		}
		for _, refusal := range report.Refusals {
			if strings.Contains(refusal.Reason, huge) {
				t.Fatal("the whole 5000-byte expiry was echoed into the report")
			}
		}
	})

	// THE SWEEP FOUND THIS ONE, AND IT IS A LESSON ABOUT WHERE A TEST HAS TO SIT. Deleting the clip
	// inside Date.UnmarshalJSON killed nothing, because through a document the date error is
	// wrapped by encoding/json and then bounded again by the decode-error clip above — so the
	// document path cannot distinguish a bounded inner error from an unbounded one. Two guards, one
	// outcome, and the inner one was therefore pinned by nothing.
	//
	// Date is exported and so is its UnmarshalJSON, which makes the message part of its contract
	// for any caller that does not come through Verify. The test goes where the guard is.
	t.Run("the date parser bounds its own error", func(t *testing.T) {
		huge := strings.Repeat("s", 5000)
		encoded, err := json.Marshal(huge)
		if err != nil {
			t.Fatal(err)
		}
		var date Date
		err = date.UnmarshalJSON(encoded)
		if err == nil {
			t.Fatal("a 5000-byte string parsed as a date")
		}
		if strings.Contains(err.Error(), huge) {
			t.Fatalf("the date parser echoed all %d bytes into its error", len(huge))
		}
	})

	t.Run("a large unknown key is truncated rather than echoed", func(t *testing.T) {
		huge := strings.Repeat("s", 5000)
		document := baseDocument()
		document[huge] = "x"
		report := verify(t, document)
		if report.OK() {
			t.Fatal("a 5000-byte unknown key was accepted")
		}
		for _, refusal := range report.Refusals {
			if strings.Contains(refusal.Reason, huge) {
				t.Fatal("the whole 5000-byte key was echoed into the report")
			}
		}
	})

	// clip cuts at a BYTE offset, and maxFieldBytes can land in the middle of a multi-byte rune.
	// %q would render the orphaned bytes as \xNN escapes — not wrong, but debris in a report a
	// person reads, and debris that looks like data. This repository already learned the byte
	// versus code-point lesson in guardenum; the same split applies to anything that slices a
	// string at a fixed offset.
	//
	// THE RUNE WIDTH IS LOAD-BEARING AND THE FIRST VERSION OF THIS TEST GOT IT WRONG. It used "é",
	// which is two bytes, and maxFieldBytes is 128 — an exact multiple of two, so the cut landed on
	// a boundary every time and the test passed with the boundary logic deleted. The sweep is what
	// said so. "…" is three bytes and 128 is not a multiple of three, so byte 128 falls inside the
	// 43rd rune and the backup loop is the only thing that can produce valid output.
	//
	// A test that cannot fail is worth less than no test, because it is counted.
	//
	// AND THE SECOND VERSION COULD NOT FAIL EITHER, FOR A DIFFERENT REASON. It asserted
	// utf8.ValidString over the rendered refusal, which is always true: the message is built with
	// %q, and %q renders an invalid byte as the printable four-character escape \xe2. Quoting
	// launders the defect into valid ASCII before the assertion ever sees it. Twice now the guard
	// was real and the instrument was pointed at the wrong surface — so this asserts on clip
	// itself, where the boundary logic lives, and checks the rendered message only for the escapes
	// that %q would have had to emit.
	t.Run("truncation lands on a rune boundary", func(t *testing.T) {
		if maxFieldBytes%3 == 0 {
			t.Fatalf("maxFieldBytes is %d, a multiple of the fixture's 3-byte rune: the cut would land on a boundary and this test would check nothing", maxFieldBytes)
		}
		clipped := clip(strings.Repeat("…", 2000))
		if !utf8.ValidString(clipped) {
			t.Fatalf("clip split a rune and returned invalid UTF-8: %q", clipped)
		}
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["class"] = strings.Repeat("…", 2000)
		report := verify(t, document)
		if report.OK() {
			t.Fatal("a 6000-byte class was accepted")
		}
		for _, refusal := range report.Refusals {
			if strings.Contains(refusal.Reason, `\x`) {
				t.Fatalf("the report carries byte escapes, so truncation split a rune: %q", refusal.Reason)
			}
		}
	})

	// clip must not damage the ordinary case, or every refusal message in the tool becomes
	// unreadable to buy a bound that only over-long input needs.
	t.Run("a short value is quoted in full", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["class"] = "made-up"
		report := verify(t, document)
		if !hasRefusal(report, "records[0]", `unsupported class "made-up"`) {
			t.Fatalf("clip truncated a short value: %s", dump(report))
		}
	})

	// THE BOUND MUST BE APPLIED BEFORE THE READ, NOT AFTER IT. os.ReadFile sizes its buffer from
	// stat and reads the lot, so the cap in Verify refused a document only once the whole thing was
	// already in memory — the same shape as the enum gap, a bound applied after the damage.
	t.Run("an over-sized file is not read whole", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "huge.json")
		if err := os.WriteFile(path, make([]byte, 4*maxDocumentBytes), 0o600); err != nil {
			t.Fatal(err)
		}
		data, err := ReadBounded(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) != maxDocumentBytes+1 {
			t.Fatalf("read %d bytes from a %d-byte file, want the cap plus one: the read is not bounded",
				len(data), 4*maxDocumentBytes)
		}
		if Verify(data, today).OK() {
			t.Fatal("the bounded read of an over-sized file was verified")
		}
	})
}

// TestMalformedFieldsAreRefused covers the pattern half of checkField, which the omission table
// cannot reach: an empty field and a malformed one take different branches.
func TestMalformedFieldsAreRefused(t *testing.T) {
	t.Run("owner must be a handle", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["owner"] = "Platform Team"
		report := verify(t, document)
		if !hasRefusalContaining(report, "records[0]", `owner "Platform Team" does not match`) {
			t.Fatalf("a prose owner was accepted: %s", dump(report))
		}
	})

	t.Run("record id must be an identifier", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["id"] = "Forge Deploy Credential"
		report := verify(t, document)
		if !hasRefusalContaining(report, "records[0]", "id \"Forge Deploy Credential\" does not match") {
			t.Fatalf("a non-identifier record id was accepted: %s", dump(report))
		}
	})

	// THE OUTPUT IS THE PRODUCT, so a field that reaches it before being checked is untrusted text.
	// One refusal per line is what a person reads to decide custody, and an id carrying a newline
	// prints a second finding that is indistinguishable from a real one -- here, a forged
	// "declared but named by no record" against a system that is perfectly fine.
	t.Run("a malformed record id cannot forge an output line", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["id"] = "x\nsystems forge: declared but named by no record"
		report := verify(t, document)
		if report.OK() {
			t.Fatal("a record id containing a newline was accepted")
		}
		for _, refusal := range report.Refusals {
			if strings.ContainsAny(refusal.String(), "\n\r") {
				t.Fatalf("a refusal spans more than one line, so the report can be forged: %q", refusal.String())
			}
		}
	})

	t.Run("location needs a scheme", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["location"] = "somewhere in the admin console"
		report := verify(t, document)
		if !hasRefusal(report, "records[0]", `location "somewhere in the admin console" must be scheme:reference`) {
			t.Fatalf("a prose location was accepted: %s", dump(report))
		}
	})

	t.Run("location scheme is closed", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["location"] = "dropbox:shared/keys.txt"
		report := verify(t, document)
		if !hasRefusal(report, "records[0]", `unsupported location scheme "dropbox"`) {
			t.Fatalf("an unsupported location scheme was accepted: %s", dump(report))
		}
	})

	t.Run("location reference is constrained", func(t *testing.T) {
		document := baseDocument()
		document["records"].([]any)[0].(map[string]any)["location"] = "sops:secrets file.yaml"
		report := verify(t, document)
		if !hasRefusalContaining(report, "records[0]", "location reference \"secrets file.yaml\" does not match") {
			t.Fatalf("a location reference with whitespace was accepted: %s", dump(report))
		}
	})

	// Every supported scheme must actually be usable, or the closed set would be enforcing a rule
	// against values it also refuses. A scheme in the set that no record can use is a typo.
	t.Run("every declared scheme is usable", func(t *testing.T) {
		for scheme := range storageSchemes {
			t.Run(scheme, func(t *testing.T) {
				document := baseDocument()
				document["records"].([]any)[0].(map[string]any)["location"] = scheme + ":forge/credentials"
				report := verify(t, document)
				if !report.OK() {
					t.Fatalf("scheme %q is in the set but a record using it was refused: %s", scheme, dump(report))
				}
			})
		}
	})
}

// TestUndeterminedRotationIsABlockerNotARefusal pins the decision documented on rotationMethods:
// an unknown rotation method is reported and counted, and does not fail the run.
//
// Both halves matter. If it refused, the row would be deleted from the inventory rather than
// investigated, and #33's fifth criterion -- blockers visible rather than silently omitted -- would
// be defeated by the tool meant to serve it. If it were not counted, it would be invisible.
func TestUndeterminedRotationIsABlockerNotARefusal(t *testing.T) {
	document := baseDocument()
	document["records"].([]any)[0].(map[string]any)["rotation"] = "undetermined"
	report := verify(t, document)
	if !report.OK() {
		t.Fatalf("an undetermined rotation refused the run: %s", dump(report))
	}
	if report.Blockers != 1 {
		t.Fatalf("counted %d blockers, want 1: an unresolved rotation method that nothing counts is silently omitted", report.Blockers)
	}
	clean := verify(t, baseDocument())
	if clean.Blockers != 0 {
		t.Fatalf("a fully determined inventory reported %d blockers", clean.Blockers)
	}
}

// TestDocumentLevelRefusals covers what makes a file unreadable as an inventory at all.
func TestDocumentLevelRefusals(t *testing.T) {
	t.Run("not json", func(t *testing.T) {
		report := Verify([]byte("systems: [forge]"), today)
		if report.OK() {
			t.Fatal("a non-JSON file verified")
		}
	})

	t.Run("wrong schema version", func(t *testing.T) {
		document := baseDocument()
		document["schema_version"] = 2
		report := verify(t, document)
		if !hasRefusal(report, "document", "unsupported schema_version 2, expected 1") {
			t.Fatalf("an unknown schema version was accepted: %s", dump(report))
		}
	})

	// A second document riding behind the first is where an unreviewed set of records gets in: the
	// reviewer reads the file to its closing brace and stops.
	//
	// EVERY TRAILING SHAPE, BECAUSE decoder.More() ONLY CAUGHT SOME OF THEM. More() reports whether
	// another element follows in the array or object being parsed, and answers false when it cannot
	// lex what comes next — so `{...}}` was waved through, which is the one shape least likely to
	// be deliberate. Measured before the change:
	//
	//	second object   {...}{...}     More()=true    refused either way
	//	garbage         {...}garbage   More()=true    refused either way
	//	close brace     {...}}         More()=FALSE   ACCEPTED — the gap
	//	whitespace      {...}          More()=false   correctly accepted
	//
	// Token() asks whether the stream is finished, and only io.EOF says yes. The whitespace row is
	// in the table as the known-good anchor: without it, a rule that refused every document would
	// satisfy the other three.
	t.Run("trailing bytes", func(t *testing.T) {
		for name, trailer := range map[string]string{
			"second document": `{"schema_version":1}`,
			"garbage":         `garbage`,
			"close brace":     `}`,
			"array":           `[1,2]`,
		} {
			t.Run(name, func(t *testing.T) {
				data := append(encode(t, baseDocument()), []byte(trailer)...)
				report := Verify(data, today)
				if !hasRefusal(report, "document", "inventory must contain exactly one JSON document") {
					t.Fatalf("a file with %s after the document was accepted: %s", name, dump(report))
				}
			})
		}
		t.Run("whitespace only (known good)", func(t *testing.T) {
			data := append(encode(t, baseDocument()), []byte("\n\t \n")...)
			report := Verify(data, today)
			if !report.OK() {
				t.Fatalf("trailing whitespace was refused: %s", dump(report))
			}
		})
	})
}
