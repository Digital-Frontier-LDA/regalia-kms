package operations

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The shipped example policy granted release-secret for "application/octet-stream". A release request
// cannot carry a content type (the API refuses one), and the coordinator evaluates it under
// DataKeyContentType, so a deployment that copied the example had EVERY secret release denied
// "content". Found by the bench control-plane drill (2026-09-24) running the real daemon; no test
// joined the example to the coordinator. This one does.
func TestTheExamplePolicyAdmitsTheContentTypeReleaseAndSealAreEvaluatedUnder(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Policies []struct {
			ID           string   `json:"id"`
			Operation    string   `json:"operation"`
			ContentTypes []string `json:"content_types"`
		} `json:"policies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, p := range doc.Policies {
		if p.Operation != "release-secret" && p.Operation != "seal-envelope" {
			continue
		}
		checked++
		found := false
		for _, ct := range p.ContentTypes {
			found = found || ct == DataKeyContentType
		}
		if !found {
			t.Errorf("policy %s (%s) lists %v; the coordinator evaluates %s under %q, so every request would be denied",
				p.ID, p.Operation, p.ContentTypes, p.Operation, DataKeyContentType)
		}
	}
	if checked == 0 {
		t.Fatal("the example has no release-secret or seal-envelope policy, so this check proves nothing")
	}
}
