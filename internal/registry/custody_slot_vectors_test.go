package registry

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE DAEMON AND CI JUDGE THESE MANIFESTS ALIKE (regalia-kms-wd6).
//
// tests/vectors/custody-slot-rules-v1.json holds whole manifests for the object_id spelling rule,
// the declared-slot rule and the secret-KEK rule (regalia-kms-091), each with the one verdict
// both validators must reach. tests/test_custody_slot_vectors.py runs the same file through
// tools/custody_manifest.py. A case is named in both suites, so a rule changed on one side only
// fails by that name on the other.
func TestCustodySlotRuleVectors(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "custody-slot-rules-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Site  string `json:"site"`
		Cases []struct {
			Name     string          `json:"name"`
			Refused  *string         `json:"refused"`
			Manifest json.RawMessage `json:"manifest"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 || vectors.Site == "" {
		t.Fatal("the vector file holds no cases, so this test is checking nothing")
	}
	for _, vector := range vectors.Cases {
		var document struct {
			Objects []struct {
				Bindings []Binding `json:"bindings"`
			} `json:"objects"`
		}
		if err := json.Unmarshal(vector.Manifest, &document); err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		healthy := map[string]bool{}
		for _, object := range document.Objects {
			for _, binding := range object.Bindings {
				healthy[binding.DeviceID] = true
			}
		}
		_, err := Load(bytes.NewReader(vector.Manifest), vectors.Site, &healthMap{states: healthy})
		switch {
		case vector.Refused == nil && err != nil:
			t.Errorf("%s: must load, was refused: %v", vector.Name, err)
		case vector.Refused != nil && err == nil:
			t.Errorf("%s: must be refused (%q), loaded", vector.Name, *vector.Refused)
		case vector.Refused != nil && !strings.Contains(err.Error(), *vector.Refused):
			t.Errorf("%s: must be refused for %q, was refused for something else: %v", vector.Name, *vector.Refused, err)
		}
	}
}
