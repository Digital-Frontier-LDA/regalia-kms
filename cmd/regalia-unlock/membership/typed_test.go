package membership

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestTheRootKeyFile(t *testing.T) {
	ed := "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	point, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	p256 := hex.EncodeToString(point)
	files := map[string]string{
		"bare":            `"` + ed + `"`,
		"typed":           `{"alg":"ecdsa-p256","key":"` + p256 + `"}`,
		"rotation":        `["` + ed + `",{"alg":"ecdsa-p256","key":"` + p256 + `"}]`,
		"newline":         `"` + ed + `"` + "\n",
		"spaced":          `{"alg": "ecdsa-p256", "key": "` + p256 + `"}`,
		"unsorted":        `{"key":"` + p256 + `","alg":"ecdsa-p256"}`,
		"duplicate field": `{"alg":"ecdsa-p256","alg":"ecdsa-p256","key":"` + p256 + `"}`,
		"empty list":      `[]`,
		"twice":           `["` + ed + `","` + ed + `"]`,
		"not a key":       `"` + ed[:62] + `"`,
		"an object":       `{"root":"` + ed + `"}`,
		"too large":       `"` + strings.Repeat("a", rootKeyMaxBytes) + `"`,
	}
	read := func(path string) ([]byte, error) {
		if body, ok := files[path]; ok {
			return []byte(body), nil
		}
		return nil, errors.New("no such file")
	}
	for name, want := range map[string]int{"bare": 1, "typed": 1, "rotation": 2} {
		root, entries, err := LoadRoot(read, name)
		if err != nil || len(entries) != want {
			t.Errorf("%s: %d entries, %v", name, len(entries), err)
		} else if again, _ := RootEntries(root, "x"); len(again) != want {
			t.Errorf("%s: the value returned is not the root read", name)
		}
	}
	for name, reason := range map[string]string{"newline": "canonical", "spaced": "canonical", "unsorted": "canonical",
		"duplicate field": "not JSON", "empty list": "one to eight", "twice": "distinct", "not a key": "64 lowercase hex",
		"an object": "fields mismatch", "too large": "over", "missing": "cannot be read"} {
		_, _, err := LoadRoot(read, name)
		var refused *Refused
		if !errors.As(err, &refused) || !strings.Contains(refused.Reason, reason) {
			t.Errorf("%s: %v, not a refusal naming %q", name, err, reason)
		}
	}
}
