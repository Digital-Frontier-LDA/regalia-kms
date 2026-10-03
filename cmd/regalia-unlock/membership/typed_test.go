package membership

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// The vector file shared with the Python (tests/vectors/typed-keys-p256.json, 48's, #262): P-256 signatures,
// two of them made on a Nitrokey HSM 2, and first manifests under a typed root. Both sides decide each alike.
func TestTheSharedTypedKeyVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "typed-keys-p256.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := load(raw, 1<<20, true)
	if err != nil {
		t.Fatal(err)
	}
	vector := document.(map[string]any)
	cases := vector["cases"].([]any)
	nitrokey := 0
	for _, value := range cases {
		c := value.(map[string]any)
		message, _ := hex.DecodeString(c["message"].(string))
		sig, _ := hex.DecodeString(c["sig"].(string))
		if got := verifySignature(c["alg"].(string), c["public"].(string), sig, message); got != c["valid"].(bool) {
			t.Errorf("%s: the Python says %v, Go %v", c["name"], c["valid"], got)
		}
		if c["valid"].(bool) && len(c["name"].(string)) > 8 && c["name"].(string)[:8] == "nitrokey" {
			nitrokey++
		}
	}
	if len(cases) < 9 || nitrokey < 2 {
		t.Fatalf("%d signature cases, %d valid ones from the Nitrokey", len(cases), nitrokey)
	}
	manifests := vector["manifests"].([]any)
	for _, value := range manifests {
		m := value.(map[string]any)
		envelope := m["envelope"].(map[string]any)
		signature := map[string]any{"key": envelope["signature_public"]}
		for k, v := range envelope["signature"].(map[string]any) {
			signature[k] = v
		}
		restored := map[string]any{"manifest": restoreTyped(envelope["manifest"]), "signature": signature}
		_, err := Accept(nil, restored, restoreTyped(m["root_public"]))
		if valid := m["valid"].(bool); valid != (err == nil) {
			t.Errorf("%s: the Python says %v; Go: %v", m["name"], valid, err)
		}
	}
	if len(manifests) < 3 {
		t.Fatalf("only %d manifests", len(manifests))
	}
}
