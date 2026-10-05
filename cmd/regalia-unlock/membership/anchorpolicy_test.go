package membership

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tests/vectors/anchor-policy-v1.json (#361, measured on swtpm by tests/vectors/make-anchor-policy-v1.py): K_A's public
// area and TPM Name as tpm2_loadexternal loads it, and each class's authPolicy = PolicyAuthorize(Name(K_A), ref). The Go
// reader expects the same bytes, or every policy-written index would read as not this node's.
func TestAnchorPolicyMatchesTheTPMsOwnValues(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "anchor-policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Schema string `json:"schema"`
		KA     struct {
			Name       string `json:"name"`
			Point      string `json:"point"`
			TPMTPublic string `json:"tpmt_public"`
		} `json:"k_a"`
		KSys struct {
			Name            string `json:"name"`
			PEM             string `json:"pem"`
			PolicyAuthorize string `json:"policy_authorize"`
		} `json:"k_sys"`
		Refs map[string]struct {
			AuthPolicy   string `json:"auth_policy"`
			PolicyRefHex string `json:"policy_ref_hex"`
		} `json:"refs"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Schema != "regalia.anchor-policy-vectors/v1" {
		t.Fatalf("schema %q", v.Schema)
	}
	name, err := AnchorPolicyKeyName(v.KA.Point)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(name) != v.KA.Name {
		t.Fatalf("K_A's Name: Go %x, the TPM %s", name, v.KA.Name)
	}
	public, _ := hex.DecodeString(v.KA.TPMTPublic)
	point, _ := hex.DecodeString(v.KA.Point)
	if !bytes.Equal(public[2:], anchorPolicyPublic(point[1:33], point[33:])) {
		t.Fatalf("K_A's TPMT_PUBLIC differs from the TPM's")
	}
	if len(v.Refs) < 2 || v.Refs["anchor"].AuthPolicy == "" || v.Refs["slots"].AuthPolicy == "" {
		t.Fatalf("the vectors name no anchor and slots classes: %v", v.Refs)
	}
	for class, want := range v.Refs {
		ref, _ := hex.DecodeString(want.PolicyRefHex)
		if string(ref) != class {
			t.Errorf("%s: the policyRef is %q, not the class name", class, ref)
		}
		got, err := AnchorPolicy(v.KA.Point, class)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != want.AuthPolicy {
			t.Errorf("%s: Go %x, the TPM %s", class, got, want.AuthPolicy)
		}
	}
	// the empty-ref case is B2a's PolicyAuthorize of the system-phase key, unchanged
	sysName, sysPolicy, err := PCRKeyPolicy([]byte(v.KSys.PEM))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sysName) != v.KSys.Name || hex.EncodeToString(sysPolicy) != v.KSys.PolicyAuthorize {
		t.Fatalf("K_sys: Go %x / %x, the TPM %s / %s", sysName, sysPolicy, v.KSys.Name, v.KSys.PolicyAuthorize)
	}
}

func TestAnAnchorPolicyKeyThatIsNotAP256PointIsRefused(t *testing.T) {
	good := "049d51373a8fa0defe9fb67b76efacec1ebcb970823f441071862e9a150c445bd1e996f2aa2281cd89b2674b037fe5972b3cbb36c38144ff20978f2da805d2e16d"
	if _, err := AnchorPolicyKeyName(good); err != nil {
		t.Fatal(err)
	}
	offCurve := good[:128] + "6c"
	for label, key := range map[string]string{
		"short":         good[:128],
		"upper case":    strings.ToUpper(good),
		"compressed":    "02" + good[2:],
		"off the curve": offCurve,
	} {
		if _, err := AnchorPolicyKeyName(key); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
}
