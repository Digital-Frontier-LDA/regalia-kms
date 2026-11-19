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
	v := document.(map[string]any)
	v["manifests"] = restored(v["manifests"])
	return v
}

// restored undoes the vector's composition (make-bootcreds-v1.py, composed): every "public" field of a manifest is "key"
// again, as bootcreds.render was given it.
func restored(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, item := range v {
			if k == "public" {
				k = "key"
			}
			out[k] = restored(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = restored(item)
		}
		return out
	}
	return value
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
		if got, ok := err.(*Refused); !ok || got.Class != r["class"] {
			t.Errorf("%s: Python refused, for %s (%s); Go: %#v", name, r["class"], r["refused"], err)
		}
	}
	if rendered < 80 || refused < 20 {
		t.Fatalf("%d rendered and %d refused", rendered, refused)
	}
}

// A single-node regalia.site (dx7.6) reads back with its owner, the boot mesh's one peer, and no node peer.
func TestASingleNodeSiteReadsItsOwner(t *testing.T) {
	sites := vector(t)["sites"].(map[string]any)
	site, err := ReadSite([]byte(sites["a, single-node"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	if site.Owner == nil || *site.Owner != (Peer{membership.OwnerParty, "203.0.113.50", "10.89.0.9"}) || len(site.Peers) != 0 {
		t.Fatalf("the owner is %+v and the peers %v", site.Owner, site.Peers)
	}
	multi, err := ReadSite([]byte(sites["a"].(string)))
	if err != nil || multi.Owner != nil || len(multi.Peers) != 2 {
		t.Fatalf("a multi-node site reads as %+v (%v)", multi, err)
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
		} else if got, ok := err.(*Refused); !taken && (!ok || got.Class != d["class"]) {
			t.Errorf("%s: Python refused it for %s (%s); Go: %#v", d["name"], d["class"], d["refused"], err)
		}
	}
	if len(documents) < 25 {
		t.Fatalf("only %d documents", len(documents))
	}
}
