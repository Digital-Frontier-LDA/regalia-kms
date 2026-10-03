package membership

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// fakeNV is a TPM's NV indices as the vector records them (FakeTpm's rules: a read of more than the
// index's size, or of an index never written, fails).
type fakeNV struct {
	nv                      map[uint32]map[string]any
	broken                  bool
	publicFails, unreadable map[uint32]bool
}

func (f fakeNV) Defined() (map[uint32]bool, error) {
	if f.broken {
		return nil, errors.New("the TPM said no")
	}
	defined := map[uint32]bool{}
	for index := range f.nv {
		defined[index] = true
	}
	return defined, nil
}

func (f fakeNV) Public(index uint32) (uint32, int, error) {
	entry, ok := f.nv[index]
	if f.broken || f.publicFails[index] || !ok {
		return 0, 0, errors.New("the TPM said no")
	}
	return uint32(entry["attributes"].(int64)), int(entry["size"].(int64)), nil
}

func (f fakeNV) Read(index uint32, size int) ([]byte, error) {
	entry, ok := f.nv[index]
	if f.broken || f.unreadable[index] || !ok || entry["data"] == nil || size > int(entry["size"].(int64)) {
		return nil, errors.New("the TPM said no")
	}
	data, _ := hex.DecodeString(entry["data"].(string))
	return data[:size], nil
}

func indexOf(t *testing.T, text string) uint32 {
	n, err := strconv.ParseUint(text, 0, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(n)
}

func asInt64(value any) any {
	if n, ok := value.(json.Number); ok {
		i, _ := n.Int64()
		return i
	}
	return value
}

func fakeOf(t *testing.T, state map[string]any) fakeNV {
	f := fakeNV{nv: map[uint32]map[string]any{}, broken: state["broken"].(bool), publicFails: map[uint32]bool{}, unreadable: map[uint32]bool{}}
	for text, value := range state["nv"].(map[string]any) {
		entry := map[string]any{}
		for k, v := range value.(map[string]any) {
			entry[k] = asInt64(v)
		}
		f.nv[indexOf(t, text)] = entry
	}
	for _, text := range state["public_fails"].([]any) {
		f.publicFails[indexOf(t, text.(string))] = true
	}
	for _, text := range state["unreadable"].([]any) {
		f.unreadable[indexOf(t, text.(string))] = true
	}
	return f
}

func TestEveryAnchorIsReadAlike(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "highwater-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := Load(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	vector := document.(map[string]any)
	rootKey := vector["root_public"].(string)
	chains := map[string][]any{}
	for name, value := range vector["chains"].(map[string]any) {
		for _, e := range value.([]any) {
			e := e.(map[string]any)
			chains[name] = append(chains[name], map[string]any{"manifest": e["manifest"],
				"signature": map[string]any{"signer": "root", "key": rootKey, "sig": e["sig"]}})
		}
	}
	cases := vector["cases"].([]any)
	seen := map[string]int{}
	for _, value := range cases {
		c := value.(map[string]any)
		name := c["name"].(string)
		length := int(asInt64(c["length"]).(int64))
		manifests, err := ReadChain(chains[c["chain"].(string)][:length], rootKey)
		if err != nil {
			t.Fatalf("%s: the chain does not read: %v", name, err)
		}
		hw, err := Anchored(fakeOf(t, c["tpm"].(map[string]any)), manifests)
		var unusable *Unusable
		var refused *Refused
		switch {
		case c["high_water"] != nil:
			seen["high_water"]++
			if want := uint64(asInt64(c["high_water"]).(int64)); err != nil || hw != want {
				t.Errorf("%s: Python: high-water %d; Go: %d, %v", name, want, hw, err)
			}
		case c["unusable"] != nil:
			seen["unusable"]++
			if !errors.As(err, &unusable) || unusable.Reason != c["unusable"] {
				t.Errorf("%s: Python: unusable: %s\nGo: %#v", name, c["unusable"], err)
			}
		default:
			seen["refused"]++
			if !errors.As(err, &refused) || refused.Reason != c["refused"] {
				t.Errorf("%s: Python: refused: %s\nGo: %#v", name, c["refused"], err)
			}
		}
	}
	if seen["high_water"] < 15 || seen["unusable"] < 15 || seen["refused"] < 6 {
		t.Fatalf("too few cases of a kind: %v", seen)
	}
}

// The jump bound advance() applies: a chain more than 1000 epochs above the high-water is an anomaly.
// Too long a chain for the vector, so built here: Anchored takes manifests ReadChain verified, and checks no
// signature itself.
func TestAChainTooFarAheadIsAnAnomaly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "highwater-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, _ := Load(raw, 1<<20)
	var state map[string]any
	for _, value := range document.(map[string]any)["cases"].([]any) {
		if c := value.(map[string]any); c["name"] == "defined only (epoch 0, a zero digest), the chain at 1" {
			state = c["tpm"].(map[string]any)
		}
	}
	if state == nil {
		t.Fatal("no epoch-0 case in the vector")
	}
	var manifests []map[string]any
	prev := ""
	for epoch := 1; epoch <= maxJump+1; epoch++ {
		manifest := map[string]any{"schema": SchemaV1, "epoch": json.Number(strconv.Itoa(epoch)), "prev_digest": prev, "policy_version": "p1",
			"issued_at": "2026-10-03T12:00:00Z", "revocation_keys": []any{}, "nodes": []any{map[string]any{
				"node_id": "n1", "state": "ACTIVE", "ek_name": "000b" + fmt.Sprintf("%064x", 1), "ak_name": "000b" + fmt.Sprintf("%064x", 2),
				"wg_boot_pub": fmt.Sprintf("%064x", 3), "wg_service_pub": fmt.Sprintf("%064x", 4), "hsm_serials": []any{"DENK0000001"}}}}
		manifests = append(manifests, manifest)
		prev = Digest(manifest)
	}
	if hw, err := Anchored(fakeOf(t, state), manifests[:maxJump]); err != nil || hw != 0 {
		t.Fatalf("a chain %d above the high-water: %d, %v", maxJump, hw, err)
	}
	_, err = Anchored(fakeOf(t, state), manifests)
	if err == nil || err.Error() != fmt.Sprintf("epoch jump %d exceeds the bound %d: anomaly", maxJump+1, maxJump) {
		t.Fatalf("a chain %d above the high-water: %v", maxJump+1, err)
	}
}
