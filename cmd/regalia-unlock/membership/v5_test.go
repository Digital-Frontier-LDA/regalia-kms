package membership

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func v5Cases(t *testing.T) []any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "membership-v5.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := load(raw, 64<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	return restoreTyped(document).(map[string]any)["cases"].([]any)
}

// tests/vectors/membership-v5.json holds every accept() call the Python v5 tests make (regalia-kms-dx7.1), replayed by
// them too: the topology field, the floors as a majority of the designed nodes, the single-node shape, a topology no
// signer changes, and the root's move from v4. Go decides each one the same way: the same manifest accepted (by
// digest), or refused for the same reason.
func TestEveryV5DecisionIsTheSame(t *testing.T) {
	cases := v5Cases(t)
	accepted, refused, quorum, single := 0, 0, 0, 0
	for _, value := range cases {
		c := value.(map[string]any)
		current, _ := c["current"].(map[string]any)
		envelope := c["envelope"].(map[string]any)
		if _, has := envelope["signatures"]; has {
			quorum++
		}
		if topology, ok := envelope["manifest"].(map[string]any)["topology"].(map[string]any); ok && topology["profile"] == singleNode {
			single++
		}
		got, err := Accept(current, envelope, c["root_public"])
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
	if len(cases) < 60 || accepted < 15 || refused < 40 || quorum < 5 || single < 20 {
		t.Fatalf("%d cases (%d accepted, %d refused, %d quorum-signed, %d single-node): the file is not the one this test was written for",
			len(cases), accepted, refused, quorum, single)
	}
	t.Logf("%d accepted and %d refused (%d quorum-signed, %d single-node), as the Python decided", accepted, refused, quorum, single)
}

// A damaged v5 document, current or candidate, is refused and never panics: every field of a v5 case's manifests and
// of their topology removed, or replaced by a value of another type.
func TestADamagedV5DocumentIsRefusedNeverAPanic(t *testing.T) {
	odd := []any{nil, true, "x", []any{}, map[string]any{}, json1, json3}
	tried := 0
	for _, value := range v5Cases(t) {
		c := value.(map[string]any)
		envelope := c["envelope"].(map[string]any)
		manifest := envelope["manifest"].(map[string]any)
		if manifest["schema"] != SchemaV5 {
			continue
		}
		current, _ := c["current"].(map[string]any)
		attempt := func(label string, candidate map[string]any) {
			tried++
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s, %s: panicked: %v", c["name"], label, r)
				}
			}()
			_, _ = Accept(current, replaced(envelope, "manifest", candidate), c["root_public"])
			_, _ = Validate(candidate)
		}
		for _, key := range sortedKeys(manifest) {
			for _, v := range append([]any{missing{}}, odd...) {
				attempt("manifest."+key, replaced(manifest, key, v))
			}
		}
		if topology, ok := manifest["topology"].(map[string]any); ok {
			for _, key := range sortedKeys(topology) {
				for _, v := range append([]any{missing{}}, odd...) {
					attempt("topology."+key, replaced(manifest, "topology", replaced(topology, key, v)))
				}
			}
		}
	}
	if tried < 1000 {
		t.Fatalf("only %d damaged documents tried", tried)
	}
}

// dx7.1: a v5 chain tip is production as a v4 one is (Store._judge_by, membership.QUORUM_SCHEMAS): an owner-written
// anchor is Unusable under it, one node or three. Each vector case that refuses an owner-written anchor under a v4 tip is
// read again with that tip's schema v5 (the same refusal) and v3 (the control: not refused for that).
func TestAV5TipRefusesAnOwnerWrittenAnchorAsV4Does(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "highwater-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := Load(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	vector := document.(map[string]any)
	rootKey := vector["root_public"].(string)
	chains := map[string][]any{}
	for name, value := range vector["chains"].(map[string]any) {
		for _, e := range value.([]any) {
			e := e.(map[string]any)
			chains[name] = append(chains[name], map[string]any{"manifest": restoreTyped(e["manifest"]),
				"signature": map[string]any{"signer": "root", "key": rootKey, "sig": e["sig"]}})
		}
	}
	tried := 0
	for _, value := range vector["cases"].([]any) {
		c := value.(map[string]any)
		reason, _ := c["unusable"].(string)
		if !strings.Contains(reason, "is owner-written: under "+SchemaV4) {
			continue
		}
		manifests, err := ReadChain(chains[c["chain"].(string)][:int(asInt64(c["length"]).(int64))], rootKey)
		if err != nil {
			t.Fatalf("%s: the chain does not read: %v", c["name"], err)
		}
		tip := len(manifests) - 1
		for _, schema := range []string{SchemaV5, SchemaV3} {
			read := append(append([]map[string]any(nil), manifests[:tip]...), replaced(manifests[tip], "schema", schema))
			_, err := Anchored(fakeOf(t, c["tpm"].(map[string]any)), read, policyOf(c["policy"]))
			var unusable *Unusable
			refusedAlike := errors.As(err, &unusable) && unusable.Reason == reason
			if refusedAlike != (schema == SchemaV5) {
				t.Errorf("%s, the tip as %s: %v", c["name"], schema, err)
			}
		}
		tried++
	}
	if tried < 2 {
		t.Fatalf("only %d owner-written cases", tried)
	}
}
