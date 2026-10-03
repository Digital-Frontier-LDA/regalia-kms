package membership

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// tests/vectors/membership-v1.json holds every accept() call the Python membership tests make, with its
// outcome. The Go port decides each one the same way: the same manifest accepted (by digest), or refused.
func TestEveryRecordedDecisionIsTheSame(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "membership-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := load(raw, 64<<20, true) // the fixture records manifests that hold floats, to be refused
	if err != nil {
		t.Fatal(err)
	}
	calls := document.(map[string]any)["calls"].([]any)
	if len(calls) < 100 {
		t.Fatalf("only %d recorded calls", len(calls))
	}
	accepted, refused := 0, 0
	for i, value := range calls {
		call := value.(map[string]any)
		current, _ := call["current"].(map[string]any)
		got, err := Accept(current, call["envelope"], call["root_key"].(string))
		if want, ok := call["accepted"].(string); ok {
			accepted++
			if err != nil || Digest(got) != want {
				t.Errorf("call %d: Python accepted %s, Go: %v", i, want[:12], err)
			}
			continue
		}
		refused++
		if err == nil {
			t.Errorf("call %d: Python refused (%s), Go accepted", i, call["refused"])
		} else if _, ok := err.(*Refused); !ok {
			t.Errorf("call %d: Go failed without a refusal: %v", i, err)
		}
	}
	t.Logf("%d accepted and %d refused, as the Python decided", accepted, refused)
}

// The crafted cases: one change to a valid manifest, signed again, so only the rule in question refuses it.
// And documents as bytes: what the reader itself refuses, and the canonical form of one it takes.
func TestEveryCraftedCaseAndDocumentIsDecidedAlike(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "membership-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, _ := load(raw, 64<<20, true)
	crafted := document.(map[string]any)["crafted"].([]any)
	for _, value := range crafted {
		c := value.(map[string]any)
		current, _ := c["current"].(map[string]any)
		_, err := Accept(current, c["envelope"], c["root_key"].(string))
		if _, accepted := c["accepted"]; accepted != (err == nil) {
			t.Errorf("%s: Python %v, Go %v", c["name"], c["accepted"] != nil, err)
		}
		// and validate() alone, which the transition rules use on both manifests
		_, invalid := Validate(c["envelope"].(map[string]any)["manifest"])
		if valid := c["valid"].(bool); valid != (invalid == nil) {
			t.Errorf("%s: Python's validate says %v, Go's %v", c["name"], valid, invalid)
		}
	}
	for _, value := range document.(map[string]any)["documents"].([]any) {
		d := value.(map[string]any)
		bytes, _ := hex.DecodeString(d["hex"].(string))
		got, err := LoadDocument(bytes)
		if taken := d["taken"].(bool); taken != (err == nil) {
			t.Errorf("%s: Python took it: %v; Go: %v", d["name"], taken, err)
		} else if taken && string(Canonical(got)) != d["canonical"].(string) {
			t.Errorf("%s: canonical %s, not %s", d["name"], Canonical(got), d["canonical"])
		}
	}
	if len(crafted) < 30 {
		t.Fatalf("only %d crafted cases", len(crafted))
	}
}
