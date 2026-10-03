package bootcfg

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

func vector(t *testing.T) map[string]any {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "bootcreds-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := membership.Load(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return document.(map[string]any)
}

// Every render of the vector, byte for byte as bootcreds.render gave it, and every refusal a refusal.
func TestEveryRenderIsTheSameBytes(t *testing.T) {
	v := vector(t)
	sites, manifests := v["sites"].(map[string]any), v["manifests"].(map[string]any)
	rendered, refused := 0, 0
	for _, value := range v["renders"].([]any) {
		r := value.(map[string]any)
		name := r["site"].(string) + " / " + r["manifest"].(string)
		site, err := ReadSite([]byte(sites[r["site"].(string)].(string)))
		if err != nil {
			t.Fatalf("%s: the site does not read: %v", name, err)
		}
		got, err := Render(manifests[r["manifest"].(string)].(map[string]any), site)
		if want, ok := r["files"].(map[string]any); ok {
			rendered++
			if err != nil {
				t.Errorf("%s: Python rendered, Go: %v", name, err)
				continue
			}
			if len(got) != len(want) {
				t.Errorf("%s: %d files, not %d", name, len(got), len(want))
			}
			for file, body := range want {
				if string(got[file]) != body.(string) {
					t.Errorf("%s: %s differs:\nPython: %q\nGo:     %q", name, file, body, got[file])
				}
			}
			continue
		}
		refused++
		if _, ok := err.(*Refused); !ok {
			if _, ok := err.(*membership.Refused); !ok {
				t.Errorf("%s: Python refused (%s), Go: %v", name, r["refused"], err)
			}
		}
	}
	if rendered < 80 || refused < 20 {
		t.Fatalf("%d rendered and %d refused", rendered, refused)
	}
}

// Every regalia.site document of the vector, taken or refused as bootcreds.read_site decided.
func TestEverySiteDocumentIsReadAlike(t *testing.T) {
	documents := vector(t)["documents"].([]any)
	for _, value := range documents {
		d := value.(map[string]any)
		raw, _ := hex.DecodeString(d["hex"].(string))
		_, err := ReadSite(raw)
		if taken := d["taken"].(bool); taken != (err == nil) {
			t.Errorf("%s: Python took it: %v (%v); Go: %v", d["name"], taken, d["refused"], err)
		}
	}
	if len(documents) < 25 {
		t.Fatalf("only %d documents", len(documents))
	}
}
