package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// ONE CAPABILITY TABLE, READ BY BOTH LANGUAGES.
//
// There were two. Capabilities() in Go decided what the daemon accepts, and CAPABILITIES in
// kms/tools/custody_manifest.py decided what CI accepts — and they disagreed in both directions.
// Python had no p256 or p384 for nitrokey-pkcs11 at all, so the validator rejected manifests the
// daemon supports; it lacked certificate-sign and key-agreement everywhere; and it still carried
// aes-256/unwrap after the driver was shown to refuse it.
//
// A manifest could therefore pass review and fail at the daemon, or fail review while being
// perfectly serviceable. Syncing two literals by hand would only postpone the next divergence, so
// the Go table is the source and this test keeps the generated file honest. The Python validator
// reads the file and holds no table of its own.
func TestGeneratedCapabilityFileMatchesTheMatrix(t *testing.T) {
	path := filepath.Join("..", "..", "config", "backend-capabilities.json")
	want, err := json.MarshalIndent(exportable(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')

	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != string(want) {
		// The update branch has to come before the read is treated as fatal, or a missing file
		// could never be generated — the escape hatch would only work once it was unnecessary.
		if os.Getenv("REGALIA_UPDATE_CAPABILITIES") != "" {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Log("regenerated", path)
			return
		}
		if readErr != nil {
			t.Fatalf("%s is missing. The Python custody-manifest validator reads it.\nRegenerate from the repository root with: REGALIA_UPDATE_CAPABILITIES=1 go -C kms test ./internal/registry -run GeneratedCapabilityFile", path)
		}
		t.Fatalf("%s is out of date with registry.Capabilities(). The Python custody-manifest validator reads this file, so CI and the daemon would disagree about what the hardware can do.\nRegenerate from the repository root with: REGALIA_UPDATE_CAPABILITIES=1 go -C kms test ./internal/registry -run GeneratedCapabilityFile", path)
	}
}

// exportable renders the matrix as sorted operation lists, which JSON can represent faithfully.
func exportable() map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for backend, algorithms := range Capabilities() {
		out[backend] = map[string][]string{}
		for algorithm, operations := range algorithms {
			names := make([]string, 0, len(operations))
			for operation, allowed := range operations {
				if allowed {
					names = append(names, operation)
				}
			}
			sort.Strings(names)
			out[backend][algorithm] = names
		}
	}
	return out
}
