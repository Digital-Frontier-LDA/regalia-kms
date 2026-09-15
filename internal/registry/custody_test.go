package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// THE PUBLISHED SCHEMA AND THE LOADER MUST ALLOW THE SAME VALUES.
//
// The Python validator already has a test binding it to config/custody-manifest.schema.json. The Go
// loader had no such binding and no enums at all — it checked these fields were non-empty and
// accepted any string, so a typo like classification "criticla" was rejected in CI and accepted by
// the daemon.
func TestLoaderEnumsMatchThePublishedSchema(t *testing.T) {
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

	for field, loader := range map[string]map[string]struct{}{
		"kind":           objectKinds,
		"classification": objectClassifications,
	} {
		published := schema.Defs.CustodyObject.Properties[field].Enum
		if len(published) == 0 {
			t.Fatalf("the schema publishes no enum for %q, so this test is checking nothing", field)
		}
		if len(published) != len(loader) {
			t.Fatalf("%s: schema publishes %d values, the loader accepts %d — a manifest valid to one would be refused by the other", field, len(published), len(loader))
		}
		for _, value := range published {
			if _, ok := loader[value]; !ok {
				t.Errorf("%s: the schema publishes %q and the loader rejects it, so a documented manifest would not start the daemon", field, value)
			}
		}
	}
	// custodyModes is map[string]custodyClass, so it does not fit the loop above's value type. The
	// key set has the same shape as the loop: schema enum == loader keys. The classification of each
	// key is held by TestEveryCustodyModeIsClassified.
	published := schema.Defs.CustodyObject.Properties["custody"].Enum
	if len(published) == 0 {
		t.Fatal("the schema publishes no enum for custody: this test is checking nothing")
	}
	if len(published) != len(custodyModes) {
		t.Fatalf("custody: schema publishes %d values, the loader accepts %d — a manifest valid to one would be refused by the other", len(published), len(custodyModes))
	}
	for _, value := range published {
		if _, ok := custodyModes[value]; !ok {
			t.Errorf("custody: the schema publishes %q and the loader rejects it, so a documented manifest would not start the daemon", value)
		}
	}
}

// A PRODUCTION KEY ON ONE DEVICE IS ONE FAILURE AWAY FROM BEING GONE.
//
// "production object requires at least 2 hardware bindings" lived in kms/tools/custody_manifest.py
// and nowhere else. That tool validates the manifest in the REPOSITORY during CI; the daemon loads
// whatever registry_path points at and re-checks none of it. The rule therefore held for manifests
// that went through review and for no others — and its absence was silent, because the daemon
// started, routed and signed regardless.
func TestProductionObjectsRequireTwoBindings(t *testing.T) {
	single := loadExampleObject(t, func(object map[string]any) {
		bindings := object["bindings"].([]any)
		object["bindings"] = bindings[:1]
	})
	if _, err := loadManifest(t, single); err == nil {
		t.Fatal("a production object with one binding was accepted: losing that device loses the key, and nothing said so")
	} else if !strings.Contains(err.Error(), "2 hardware bindings") {
		t.Fatalf("the error does not explain what is wrong: %v", err)
	}

	// "exception" is the declared, reviewable way to say a key is deliberately single-homed.
	declared := loadExampleObject(t, func(object map[string]any) {
		object["bindings"] = object["bindings"].([]any)[:1]
		object["custody"] = "exception"
	})
	if _, err := loadManifest(t, declared); err != nil {
		t.Fatalf("custody \"exception\" did not permit a single-homed production key: %v", err)
	}
}

// Two bindings on one device is redundancy on paper only.
func TestBindingsMustUseDistinctDevices(t *testing.T) {
	duplicate := loadExampleObject(t, func(object map[string]any) {
		bindings := object["bindings"].([]any)
		first := bindings[0].(map[string]any)
		second := bindings[1].(map[string]any)
		second["device_id"] = first["device_id"]
	})
	if _, err := loadManifest(t, duplicate); err == nil {
		t.Fatal("two bindings naming the same device were accepted as redundancy")
	}
}

// EVERY CUSTODY MODE THE LOADER ACCEPTS MUST SAY WHETHER THE DAEMON OPERATES IT OR ONLY RECORDS IT.
//
// custodyModes is a map[string]custodyClass, so the zero value of a key is custodyUnclassified:
// a mode reached without a decision is refused at Load rather than assumed operable. This is the
// structural form of "every mode is classified" — a fifth mode cannot be added without typing
// custodyOperated or custodyRecord, and the bug #130 fixes (a daemon that demands a backend for an
// object nothing signs) cannot be reintroduced by a mode that inherited a default.
//
// TestLoaderEnumsMatchThePublishedSchema already pins the keys against the schema enum, so the
// set of modes the loader accepts and the set the schema publishes cannot drift apart — but that
// is the KEYS, not the classes. The schema has no concept of custodyOperated vs custodyRecord:
// those are loader-side decisions the type system holds this test against. A mode added to both
// the schema and the map but parked at custodyUnclassified would be a "I will decide later"
// entry, and this test is the only thing that catches it.
//
// Verified by adding "ledger-snapshot": custodyUnclassified to custodyModes AND "ledger-snapshot"
// to the schema's custody enum, then re-running: the enum test stayed satisfied (keys still match)
// and this test failed naming the new mode as unclassified. Reverted. The earlier note in this
// comment said `custodyOperated` and was wrong: custodyOperated IS a classification, so a mutation
// that typed the new mode as operated exercises nothing — only an unclassified mode can be the
// defect this test pins, because that is the only value that reads as "nobody decided".
func TestEveryCustodyModeIsClassified(t *testing.T) {
	if len(custodyModes) == 0 {
		t.Fatal("custodyModes is empty: this test would pass while checking nothing")
	}
	for mode, class := range custodyModes {
		if class == custodyUnclassified {
			t.Errorf("custody mode %q in custodyModes is custodyUnclassified: it must be custodyOperated (the daemon "+
				"routes to and signs for it) or custodyRecord (the manifest records it but nothing here operates it). "+
				"The zero value reads as undecided so a new mode cannot be added without a deliberate choice.", mode)
		}
	}
}

// The zero value of a custody mode absent from custodyModes is custodyUnclassified.
//
// `isCustodyRecord` looks up `custodyModes[custody]` and compares to custodyRecord; a missing
// key reads as custodyUnclassified, which is not custodyRecord, so the equality fails and the
// function returns false.
// That means *operated*: the daemon routes to it, signs for it, and refuses to come up if it
// has no backend. A typo in the manifest that names a custody mode nobody classified would
// silently treat the object as something the daemon operates on, which is the wrong direction
// for a credential whose custodian is not yet understood.
//
// The safety that prevents the zero-value path from being reachable lives in validateCustody,
// which refuses to load any object whose custody mode is custodyUnclassified. Therefore the
// lookup is only safe to call on objects that passed Load — but the gate is in a different
// function, and the reader of `isCustodyRecord` does not see it from the call site. This test
// pins the zero-value contract at the lookup so a future reader cannot mistake "this is
// false" for "this is safe": false here means *operated*, the unsafe default.
//
// Each assertion is independently falsifiable; the mutation that targets one does not reach the
// other two. Earlier versions of this comment recorded a single mutation that flipped
// `== custodyRecord` to `!= custodyRecord` and claimed three failures, but the known-good
// assertion is `t.Fatal`, so it stops the run and the second and third assertions never fire under
// that mutation. Adding the known-good case (§18) invalidated the multi-assertion falsification
// that predated it. The three mutations below are keyed by the assertion they isolate (not by line
// number, which drifts the moment anything above them moves):
//
//	known-good assertion — "fido-multi-enrollment" is custodyRecord, isCustodyRecord must return true:
//	  flip `== custodyRecord` to `!= custodyRecord` in isCustodyRecord.
//	  fails with `"fido-multi-enrollment" is custodyRecord … must return true`. Restored.
//
//	unclassified-mode assertion — "not-a-custody-mode" is absent from custodyModes, function must return false:
//	  add `if _, ok := custodyModes[custody]; !ok { return true }` before the return.
//	  fails with `an unclassified mode reads as custodyRecord …`. Restored.
//
//	operated-mode loop — every custodyOperated mode must read as not-custodyRecord:
//	  flip `== custodyRecord` to `!= custodyUnclassified` in isCustodyRecord.
//	  fails once per operated mode, naming each one. The count is deliberately not written down
//	  here: it is whatever custodyModes currently holds, and the operatedCount floor in the test
//	  is what keeps it from being zero. Restored.
//
// Negative result worth keeping: changing the iota to `custodyUnclassified custodyClass = iota + 2`
// compiles and *survives* this test, because no constant equals 0 any more, so a missing key reads
// as 0 and 0 is still not custodyRecord — the assertion under test does not see the defect. A
// different test (TestUnknownCustodyValuesAreRefused) catches the side effect. Recording the iota
// mutation as "this assertion is unfalsifiable" would have been a fabricated finding: the mutation
// did not produce the defect the test was checking for. The `!ok` mutation above is the one that
// does.
func TestIsCustodyRecordReturnsFalseForUnclassifiedMode(t *testing.T) {
	if !isCustodyRecord("fido-multi-enrollment") {
		t.Fatal("\"fido-multi-enrollment\" is custodyRecord in custodyModes; isCustodyRecord must return true")
	}
	// A mode absent from custodyModes. The lookup returns the zero value (custodyUnclassified),
	// which is not custodyRecord, so the equality in isCustodyRecord fails and the function
	// returns false. That is the unsafe default for a typo, and the load-time gate is what
	// keeps it from being reachable.
	if isCustodyRecord("not-a-custody-mode") {
		t.Fatal("an unclassified mode reads as custodyRecord: a typo would silently route an undecided object, the wrong direction for safety")
	}
	// A mode classified as custodyOperated also returns false — it routes to the daemon, the
	// opposite of "records but does not operate." Pin this so a future mutation that flips the
	// comparison direction fails here rather than in production routing.
	//
	// Floor on reach: the loop must visit at least one operated mode, otherwise a future edit
	// that empties custodyOperated would shrink the corpus to zero and this branch would
	// silently pass while checking nothing. TestEveryCustodyModeIsClassified already pins the
	// "no unclassified mode is allowed" side; this is the "at least one is operated" side.
	operatedCount := 0
	for mode, class := range custodyModes {
		if class != custodyOperated {
			continue
		}
		operatedCount++
		if isCustodyRecord(mode) {
			t.Errorf("custody mode %q is custodyOperated but isCustodyRecord returned true: the comparison is to the wrong class", mode)
		}
	}
	if operatedCount == 0 {
		t.Fatal("custodyModes has no custodyOperated entry: the loop above checked nothing, so the comparison-direction pin is silent")
	}
}

// An unknown enum value must be refused rather than carried as an opaque string.
func TestUnknownCustodyValuesAreRefused(t *testing.T) {
	for field, value := range map[string]string{
		"kind":           "not-a-kind",
		"classification": "criticla",
		"custody":        "whatever",
	} {
		mutated := loadExampleObject(t, func(object map[string]any) { object[field] = value })
		if _, err := loadManifest(t, mutated); err == nil {
			t.Errorf("%s=%q was accepted by the daemon: CI would have rejected it, so the two disagree about what a valid manifest is", field, value)
		}
	}
}

// loadExampleObject returns the shipped manifest with one mutation applied to the first object.
func loadExampleObject(t *testing.T, mutate func(map[string]any)) map[string]any {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(contents, &document); err != nil {
		t.Fatal(err)
	}
	objects, ok := document["objects"].([]any)
	if !ok || len(objects) == 0 {
		t.Fatal("the shipped manifest has no objects: this test is checking nothing")
	}
	first, ok := objects[0].(map[string]any)
	if !ok {
		t.Fatal("manifest schema changed under this test")
	}
	if first["environment"] != "production" {
		t.Fatalf("the first object is %v, not production, so the production rule is not being exercised", first["environment"])
	}
	mutate(first)
	return document
}

func loadManifest(t *testing.T, document map[string]any) (*Registry, error) {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadFile(path, "sitea", nil)
}

// THE BINDING STATES ARE SPELLED IN THREE FILES AND NOTHING COMPARED THEM.
//
// TestLoaderEnumsMatchThePublishedSchema binds the loader to the schema for the custodyObject
// enums, and the Python validator has the mirror test for the same ones. Neither reached
// $defs.binding.properties.state, so the state list was the one enum in this manifest with no
// guard at all — and it is the one that diverged.
//
// #160 added "revoked" to the Go chain and to neither the schema nor kms/tools/custody_manifest.py.
// The daemon then loaded a manifest CI refused, which meant no committed manifest could exercise
// the feature the state was added for. A reviewer caught it; the suite could not, because an
// inline `!=` chain has no set to compare against. That is why registry.go now spells these as
// maps: the fix for the divergence is not "remember to update three files", it is making the
// disagreement fail.
//
// commissionedStates is checked too. The schema encodes that subset twice, in
// binding.allOf[].if.properties.state, to require device_serial and devaut_fingerprint — so a
// state added to the loader's subset and not the schema's would let the daemon demand pinning
// where CI does not, or the reverse.
func TestBindingStatesMatchThePublishedSchema(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			Binding struct {
				Properties map[string]struct {
					Enum []string `json:"enum"`
				} `json:"properties"`
				AllOf []struct {
					If struct {
						Properties map[string]struct {
							Enum []string `json:"enum"`
						} `json:"properties"`
					} `json:"if"`
				} `json:"allOf"`
			} `json:"binding"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(contents, &schema); err != nil {
		t.Fatal(err)
	}

	published := schema.Defs.Binding.Properties["state"].Enum
	if len(published) == 0 {
		t.Fatal("the schema publishes no enum for binding.state, so this test is checking nothing")
	}
	// Report the ACTUAL difference rather than the historical one. Naming "revoked" here would be
	// right about #160 and wrong about every later drift, and a failure message that confidently
	// names the wrong value costs more than one that names none.
	onlySchema, onlyLoader := []string{}, []string{}
	inSchema := make(map[string]struct{}, len(published))
	for _, value := range published {
		inSchema[value] = struct{}{}
		if _, ok := bindingStates[value]; !ok {
			onlySchema = append(onlySchema, value)
		}
	}
	for value := range bindingStates {
		if _, ok := inSchema[value]; !ok {
			onlyLoader = append(onlyLoader, value)
		}
	}
	sort.Strings(onlyLoader)
	if len(onlySchema) > 0 || len(onlyLoader) > 0 {
		t.Fatalf("binding.state: the schema and the loader disagree — a manifest valid to one is "+
			"refused by the other.\n  only in the schema (the daemon would refuse a documented "+
			"manifest): %v\n  only in the loader (the daemon accepts what CI rejects, so no "+
			"committed manifest can exercise it): %v", onlySchema, onlyLoader)
	}
	// The commissioned subset appears once per allOf branch that keys off it. Every branch that
	// names states must name the same ones; a branch disagreeing with the loader is the same
	// divergence one level down.
	branches := 0
	for index, branch := range schema.Defs.Binding.AllOf {
		subset := branch.If.Properties["state"].Enum
		if len(subset) == 0 {
			continue
		}
		branches++
		if len(subset) != len(commissionedStates) {
			t.Errorf("binding.allOf[%d]: the schema conditions on %d states %v, the loader treats "+
				"%d as commissioned — one of them would require a pinned serial where the other "+
				"does not", index, len(subset), subset, len(commissionedStates))
			continue
		}
		for _, value := range subset {
			if _, ok := commissionedStates[value]; !ok {
				t.Errorf("binding.allOf[%d]: the schema conditions on %q, which the loader does not "+
					"treat as commissioned", index, value)
			}
		}
	}
	if branches == 0 {
		t.Fatal("no allOf branch conditions on binding.state, so the commissioned subset above is " +
			"unchecked and this half of the test proves nothing")
	}
}
