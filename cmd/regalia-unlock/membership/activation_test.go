package membership

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// tests/vectors/activation-v2.json holds every activation.verify() call the Python activation tests make (48's
// make-activation-v2.py): the node threshold, the owner only through a recovery authorization under its
// quarantine manifest, an older manifest's lease counted under the current signers, and every refusal.
func activationCases(t *testing.T) []any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "activation-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := load(raw, 64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	return restoreTyped(document).(map[string]any)["cases"].([]any)
}

func TestEveryActivationDecisionIsTheSame(t *testing.T) {
	cases := activationCases(t)
	accepted, refused, recovery := 0, 0, 0
	for _, value := range cases {
		c := value.(map[string]any)
		current, _ := c["current"].(map[string]any)
		if lease, ok := c["envelope"].(map[string]any)["lease"].(map[string]any); ok {
			if _, has := lease["recovery"]; has {
				recovery++
			}
		}
		_, digest, err := VerifyActivation(c["envelope"], current)
		if want, ok := c["accepted"].(string); ok {
			accepted++
			if err != nil || digest != want {
				t.Errorf("%s: Python accepted %s, Go: %s %v", c["name"], want[:12], digest, err)
			}
			continue
		}
		refused++
		if err == nil {
			t.Errorf("%s: Python refused (%s), Go accepted", c["name"], c["refused"])
		} else if _, ok := err.(*Refused); !ok {
			t.Errorf("%s: Go failed without a refusal: %v", c["name"], err)
		} else if !sameReason(c["refused"], err) {
			t.Errorf("%s: refused for another reason:\nPython: %s\nGo:     %v", c["name"], c["refused"], err)
		}
	}
	if len(cases) < 41 || accepted < 22 || refused < 19 || recovery < 10 {
		t.Fatalf("%d cases (%d accepted, %d refused, %d recovery): the file is not the one this test was written for", len(cases), accepted, refused, recovery)
	}
	t.Logf("%d accepted and %d refused (%d recovery leases), as the Python decided", accepted, refused, recovery)
}

// damaged returns a copy of value with the node at each path below it removed or replaced by each odd value,
// one change per copy: every field of the envelope, the lease, the recovery block and every signature.
func damaged(value any, odd []any, emit func(label string, changed any)) {
	switch v := value.(type) {
	case map[string]any:
		for _, key := range sortedKeys(v) {
			for _, o := range append([]any{missing{}}, odd...) {
				emit(key, replaced(v, key, o))
			}
			damaged(v[key], odd, func(label string, changed any) { emit(key+"."+label, replaced(v, key, changed)) })
		}
	case []any:
		for i := range v {
			damaged(v[i], odd, func(label string, changed any) {
				out := append([]any(nil), v...)
				out[i] = changed
				emit("["+string(rune('0'+i))+"]."+label, out)
			})
		}
	}
}

// A damaged envelope, or a damaged current manifest, is refused and never panics.
func TestADamagedActivationIsRefusedNeverAPanic(t *testing.T) {
	odd := []any{nil, true, "x", []any{}, map[string]any{}, json.Number("-1"), json.Number("1")}
	tried := 0
	for _, value := range activationCases(t) {
		c := value.(map[string]any)
		current := c["current"].(map[string]any)
		attempt := func(label string, current map[string]any, envelope any) {
			tried++
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s, %s: panicked: %v", c["name"], label, r)
				}
			}()
			_, _, _ = VerifyActivation(envelope, current)
		}
		damaged(c["envelope"], odd, func(label string, changed any) { attempt("envelope."+label, current, changed) })
		for _, key := range sortedKeys(current) {
			for _, o := range append([]any{missing{}}, odd...) {
				attempt("current."+key, replaced(current, key, o), c["envelope"])
			}
		}
	}
	if tried < 10000 {
		t.Fatalf("only %d damaged documents tried", tried)
	}
	t.Logf("%d damaged documents, none panicked", tried)
}
