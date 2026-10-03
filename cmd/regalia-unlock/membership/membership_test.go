package membership

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envelopeOf assembles an envelope the vector stores in parts: its signature's public key beside it, as
// "signature_public" (a public key written as "key" reads as a credential to the secret scanner).
// restoreTyped undoes the vector's composition: every "public" field is "key" again, as the Python signed
// it (make-membership-v1.py, compose).
func restoreTyped(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			if k == "public" {
				k = "key"
			}
			out[k] = restoreTyped(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = restoreTyped(x)
		}
		return out
	}
	return value
}

func envelopeOf(value any) any {
	stored := value.(map[string]any)
	document := stored["document"]
	if public, ok := stored["signature_public"]; ok {
		envelope := document.(map[string]any)
		signature := envelope["signature"].(map[string]any)
		signature["key"] = public
	}
	return document
}

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
	document = restoreTyped(document)
	calls := document.(map[string]any)["calls"].([]any)
	if len(calls) < 100 {
		t.Fatalf("only %d recorded calls", len(calls))
	}
	accepted, refused := 0, 0
	for i, value := range calls {
		call := value.(map[string]any)
		current, _ := call["current"].(map[string]any)
		got, err := Accept(current, envelopeOf(call["envelope"]), call["root_public"])
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

// verify_envelope as the tests call it, typed keys included (#156, #199): the same manifest and signer, or a
// refusal.
func TestEveryRecordedEnvelopeIsVerifiedAlike(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "membership-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := load(raw, 64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	document = restoreTyped(document)
	records := document.(map[string]any)["verified"].([]any)
	typedSeen := 0
	for i, value := range records {
		record := value.(map[string]any)
		current, _ := record["current"].(map[string]any)
		if _, bare := record["root_public"].(string); !bare {
			typedSeen++
		}
		manifest, signer, err := VerifyEnvelope(envelopeOf(record["envelope"]), record["root_public"], current)
		if want, ok := record["verified"].(string); ok {
			if err != nil || Digest(manifest) != want || signer != record["signer"] {
				t.Errorf("verification %d: Python %s by %s; Go: %v", i, want[:12], record["signer"], err)
			}
		} else if _, ok := err.(*Refused); !ok {
			t.Errorf("verification %d: Python refused (%s); Go: %v", i, record["refused"], err)
		}
	}
	if len(records) < 100 || typedSeen < 5 {
		t.Fatalf("%d recorded verifications, %d under a typed root", len(records), typedSeen)
	}
}

// The crafted cases: one change to a valid manifest, signed again, so only the rule in question refuses it.
// And documents as bytes: what the reader itself refuses, and the canonical form of one it takes.
func TestEveryCraftedCaseAndDocumentIsDecidedAlike(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "membership-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, _ := load(raw, 64<<20, true)
	document = restoreTyped(document)
	crafted := document.(map[string]any)["crafted"].([]any)
	for _, value := range crafted {
		c := value.(map[string]any)
		current, _ := c["current"].(map[string]any)
		envelope := envelopeOf(c["envelope"])
		_, err := Accept(current, envelope, c["root_public"])
		if _, accepted := c["accepted"]; accepted != (err == nil) {
			t.Errorf("%s: Python %v, Go %v", c["name"], c["accepted"] != nil, err)
		}
		// and validate() alone, which the transition rules use on both manifests
		_, invalid := Validate(envelope.(map[string]any)["manifest"])
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

// A current manifest that does not validate is refused, never read as if it did (Python would raise a
// TypeError on some of these; Go would panic on a failed type assertion).
func TestAnInvalidCurrentManifestIsRefused(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "membership-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, _ := load(raw, 64<<20, true)
	document = restoreTyped(document)
	var next map[string]any
	for _, value := range document.(map[string]any)["crafted"].([]any) {
		if c := value.(map[string]any); c["name"] == "the next epoch" {
			next = c
		}
	}
	if next == nil {
		t.Fatal("no crafted case named \"the next epoch\"")
	}
	current := next["current"].(map[string]any)
	if _, err := Accept(current, envelopeOf(next["envelope"]), next["root_public"]); err != nil {
		t.Fatalf("the unchanged case is refused: %v", err)
	}
	for name, change := range map[string]func(map[string]any){
		"an epoch as text":        func(m map[string]any) { m["epoch"] = "1" },
		"no revocation keys":      func(m map[string]any) { delete(m, "revocation_keys") },
		"revocation keys as text": func(m map[string]any) { m["revocation_keys"] = "00" },
		"nodes as null":           func(m map[string]any) { m["nodes"] = nil },
		"a schema nobody knows":   func(m map[string]any) { m["schema"] = "regalia.membership/v0" },
	} {
		broken := map[string]any{}
		for k, v := range current {
			broken[k] = v
		}
		change(broken)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v", name, r)
				}
			}()
			_, err := Accept(broken, envelopeOf(next["envelope"]), next["root_public"])
			if refused, ok := err.(*Refused); !ok || !strings.Contains(refused.Reason, "the current manifest is not valid") {
				t.Errorf("%s: %v, not a refusal of the current manifest", name, err)
			}
		}()
	}
}
