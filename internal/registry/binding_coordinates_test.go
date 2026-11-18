package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AN OBJECT_ID THE DRIVER PARSES HAS ONE SPELLING (review F1). The table is the drivers' parsing:
// findObject hex-decodes PKCS#11 ids (1 to 64 bytes), parseSlot lower-cases a PIV slot, strips
// "0x" and reads it as hex.
func TestAnObjectIDTheDriverParsesHasOneSpelling(t *testing.T) {
	for _, test := range []struct {
		backend, objectID string
		ok                bool
	}{
		{"nitrokey-pkcs11", "01", true},
		{"nitrokey-pkcs11", "0a", true},
		{"nitrokey-pkcs11", strings.Repeat("ab", 64), true},
		{"yubikey-openpgp", "03", true},
		{"yubikey-piv", "9c", true},
		{"fido2", "github-enrollment-a", true},
		{"nitrokey-pkcs11", "0A", false},
		{"nitrokey-pkcs11", "a", false},
		{"nitrokey-pkcs11", "0x0a", false},
		{"nitrokey-pkcs11", "slot-1", false},
		{"nitrokey-pkcs11", strings.Repeat("ab", 65), false},
		{"yubikey-openpgp", "0A", false},
		{"yubikey-piv", "9C", false},
		{"yubikey-piv", "0x9c", false},
		{"yubikey-piv", "09c", false},
	} {
		err := validateBindingCoordinates(Binding{Site: "sitea", Backend: test.backend, DeviceID: "d", ObjectID: test.objectID})
		if (err == nil) != test.ok {
			t.Errorf("%s object_id %q: err = %v, want accepted = %v", test.backend, test.objectID, err, test.ok)
		}
	}
	if err := validateBindingCoordinates(Binding{Site: "sitea", Backend: "nitrokey-pkcs11", DeviceID: "d"}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("a binding with no object_id: err = %v", err)
	}
}

// The schema publishes the same spellings, so CI's schema check and the daemon refuse the same
// object_id. A pattern changed on one side only fails here, by backend.
func TestObjectIDPatternsMatchThePublishedSchema(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	type pattern struct {
		Pattern string `json:"pattern"`
	}
	var schema struct {
		Defs struct {
			Binding struct {
				AllOf []struct {
					If struct {
						Properties struct {
							Backend struct {
								Enum  []string `json:"enum"`
								Const string   `json:"const"`
							} `json:"backend"`
						} `json:"properties"`
					} `json:"if"`
					Then struct {
						Properties struct {
							ObjectID pattern `json:"object_id"`
						} `json:"properties"`
					} `json:"then"`
				} `json:"allOf"`
			} `json:"binding"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(contents, &schema); err != nil {
		t.Fatal(err)
	}
	published := map[string][]string{}
	for _, branch := range schema.Defs.Binding.AllOf {
		if branch.Then.Properties.ObjectID.Pattern == "" {
			continue
		}
		backends := branch.If.Properties.Backend.Enum
		if branch.If.Properties.Backend.Const != "" {
			backends = append(backends, branch.If.Properties.Backend.Const)
		}
		for _, backend := range backends {
			published[backend] = append(published[backend], branch.Then.Properties.ObjectID.Pattern)
		}
	}
	for backend, want := range map[string]string{
		"nitrokey-pkcs11": pkcs11ObjectIDPattern.String(),
		"yubikey-openpgp": pkcs11ObjectIDPattern.String(),
		"yubikey-piv":     pivSlotPattern.String(),
	} {
		if got := published[backend]; len(got) != 1 || got[0] != want {
			t.Errorf("%s: the schema publishes object_id patterns %q, the loader enforces %q", backend, got, want)
		}
	}
	if got := published["fido2"]; len(got) != 0 {
		t.Errorf("fido2: the schema constrains object_id %q, the loader does not", got)
	}
}
