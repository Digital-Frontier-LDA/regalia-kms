package membership

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func v4Cases(t *testing.T) []any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "membership-v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := load(raw, 64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	return restoreTyped(document).(map[string]any)["cases"].([]any)
}

// tests/vectors/membership-v4.json holds every accept() call the Python v4 tests make (95's #350), replayed
// by them too: the signer rules and their floors, owner and signing keys, the root never a party, quorum
// envelopes, a party twice, a node that does not count, restrictive-only quorums and the root's move from v3.
// Go decides each one the same way: the same manifest accepted (by digest), or refused for the same reason.
func TestEveryV4DecisionIsTheSame(t *testing.T) {
	cases := v4Cases(t)
	accepted, refused, quorum := 0, 0, 0
	for _, value := range cases {
		c := value.(map[string]any)
		current, _ := c["current"].(map[string]any)
		if _, has := c["envelope"].(map[string]any)["signatures"]; has {
			quorum++
		}
		got, err := Accept(current, c["envelope"], c["root_public"])
		if want, ok := c["accepted"].(string); ok {
			accepted++
			if err != nil || Digest(got) != want {
				t.Errorf("%s: Python accepted %s, Go: %v", c["name"], want[:12], err)
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
	if len(cases) < 86 || accepted < 18 || quorum < 20 {
		t.Fatalf("%d cases (%d accepted, %d quorum-signed): the file is not the one this test was written for", len(cases), accepted, quorum)
	}
	t.Logf("%d accepted and %d refused (%d quorum-signed), as the Python decided", accepted, refused, quorum)
}

// A damaged v4 document, current or candidate, is refused and never panics: every field of a v4 case's
// manifests removed, or replaced by a value of another type, and every signature entry's field too.
func TestADamagedV4DocumentIsRefusedNeverAPanic(t *testing.T) {
	odd := []any{nil, true, "x", []any{}, map[string]any{}, json.Number("-1")}
	tried := 0
	for _, value := range v4Cases(t) {
		c := value.(map[string]any)
		current, _ := c["current"].(map[string]any)
		envelope := c["envelope"].(map[string]any)
		if current == nil || current["schema"] != SchemaV4 {
			continue
		}
		attempt := func(label string, current map[string]any, envelope any) {
			tried++
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s, %s: panicked: %v", c["name"], label, r)
				}
			}()
			_, _ = Accept(current, envelope, c["root_public"])
		}
		for _, key := range sortedKeys(current) {
			for _, v := range append([]any{missing{}}, odd...) {
				attempt("current."+key, replaced(current, key, v), envelope)
				manifest := envelope["manifest"].(map[string]any)
				attempt("manifest."+key, current, replaced(envelope, "manifest", replaced(manifest, key, v)))
			}
		}
		if sigs, ok := envelope["signatures"].([]any); ok && len(sigs) > 0 {
			first := sigs[0].(map[string]any)
			for _, key := range sortedKeys(first) {
				for _, v := range append([]any{missing{}}, odd...) {
					changed := append([]any{replaced(first, key, v)}, sigs[1:]...)
					attempt("signatures[0]."+key, current, replaced(envelope, "signatures", changed))
				}
			}
		}
	}
	if tried < 1000 {
		t.Fatalf("only %d damaged documents tried", tried)
	}
}

type missing struct{}

func replaced(object map[string]any, key string, value any) map[string]any {
	out := map[string]any{}
	for k, v := range object {
		out[k] = v
	}
	if _, drop := value.(missing); drop {
		delete(out, key)
	} else {
		out[key] = value
	}
	return out
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for k := range object {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
