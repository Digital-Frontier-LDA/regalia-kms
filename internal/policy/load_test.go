package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryPolicyFileLoads(t *testing.T) {
	path := filepath.Join("..", "..", "config", "policy.example.json")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	policies, digest, err := Load(file)
	if err != nil {
		t.Fatal(err)
	}
	// Assert properties, not the count. This used to require exactly one policy, which pinned an
	// incidental fact about the example rather than anything about the loader — so completing the
	// example (three of its four objects declared policies that did not exist) broke the test, and
	// the test would have argued against the fix.
	if len(policies) == 0 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("loaded policies = %#v digest=%q", policies, digest)
	}
	cosmos := 0
	for _, item := range policies {
		if item.ID == "" || item.ObjectID == "" || item.Operation == "" {
			t.Fatalf("policy is missing its identity: %#v", item)
		}
		if item.Cosmos != nil {
			cosmos++
		}
	}
	if cosmos == 0 {
		t.Fatal("the example no longer exercises a Cosmos policy, so the Cosmos evaluator is unrepresented in the shipped configuration")
	}
}

// BOTH FIXTURES USED TO BE REFUSED BY A THIRD RULE, so this test was green against a loader with
// neither of the two it names (#237). They read `"policies":[]`, and an empty policy list is
// refused by the schema guard a few lines below the two decoders — so defeating either the
// unknown-field rule or the one-document rule left this passing.
//
// It matters most for the unknown-field half, because encoding/json does NOT abandon the value
// when DisallowUnknownFields objects. Measured:
//
//	{"schema_version":1,"policies":[{...}],"default":"allow"}
//	  -> err = json: unknown field "default"   AND a fully populated document
//
// So a loader that ignores that error loads the policy set and drops the unknown key on the
// floor. Every fixture below therefore carries a REAL policy, and the control at the end shows
// the same document loading once the offending part is removed — without it these rows are
// equally consistent with a loader that refuses everything.
func TestPolicyLoaderRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	const policyEntry = `{"id":"p","object_id":"o","purpose":"sign","environment":"production",` +
		`"operation":"sign","algorithm":"secp256k1","content_types":["application/octet-stream"],` +
		`"max_payload_bytes":1024,"max_future_seconds":60}`
	sound := `{"schema_version":1,"policies":[` + policyEntry + `]}`

	for name, input := range map[string]string{
		"an unknown key beside a real policy set": `{"schema_version":1,"policies":[` + policyEntry +
			`],"default":"allow"}`,
		"an unknown key inside a policy": `{"schema_version":1,"policies":[` +
			strings.Replace(policyEntry, `{"id":"p"`, `{"id":"p","fallback":"allow"`, 1) + `]}`,
		"a second document after a loadable first": sound + " " + sound,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Load(strings.NewReader(input)); err == nil {
				t.Fatalf("Load() accepted %s — a key this loader does not understand is a rule "+
					"somebody wrote and nothing enforces, and a second document is a policy set "+
					"that differs from the one a reader sees at the end of the file", input)
			}
		})
	}

	// The control, run after the rows so a broken fixture cannot stop them reporting first.
	policies, digest, err := Load(strings.NewReader(sound))
	if err != nil {
		t.Fatalf("the same document without the unknown key or the second copy was refused (%v) — "+
			"every row above would pass against a loader that refuses everything", err)
	}
	if len(policies) != 1 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("the control loaded %d policies with digest %q", len(policies), digest)
	}
}
