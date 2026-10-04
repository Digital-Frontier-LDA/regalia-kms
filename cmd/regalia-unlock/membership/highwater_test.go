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

func (f fakeNV) Public(index uint32) (uint32, int, []byte, error) {
	entry, ok := f.nv[index]
	if f.broken || f.publicFails[index] || !ok {
		return 0, 0, nil, errors.New("the TPM said no")
	}
	return uint32(entry["attributes"].(int64)), int(entry["size"].(int64)), policyBytes(entry["policy"]), nil
}

// policyOf is a vector case's configured policy, as Anchored takes it: nil for null (none configured).
func policyOf(value any) func() ([]byte, error) {
	if value == nil {
		return nil
	}
	policy := policyBytes(value)
	return func() ([]byte, error) { return policy, nil }
}

// policyBytes is a vector's policy: hex, or null for none ("" is a policy that is empty, not none).
func policyBytes(value any) []byte {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	policy, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return policy
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
		hw, err := Anchored(fakeOf(t, c["tpm"].(map[string]any)), manifests, policyOf(c["policy"]))
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
	if hw, err := Anchored(fakeOf(t, state), manifests[:maxJump], nil); err != nil || hw != 0 {
		t.Fatalf("a chain %d above the high-water: %d, %v", maxJump, hw, err)
	}
	_, err = Anchored(fakeOf(t, state), manifests, nil)
	if err == nil || err.Error() != fmt.Sprintf("epoch jump %d exceeds the bound %d: anomaly", maxJump+1, maxJump) {
		t.Fatalf("a chain %d above the high-water: %v", maxJump+1, err)
	}
}

// The approved-image policy is asked for only when a policy-written index is met, and at most once in a
// read (HighWater.policy, #242 B2a); a policy that cannot be established refuses the read, a Refused and
// never an Unusable (nothing a re-anchor would repair), and an owner-written anchor reads without it.
func TestThePolicyIsAskedForLazilyAndOnce(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "highwater-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, _ := Load(raw, 1<<20)
	vector := document.(map[string]any)
	rootKey := vector["root_public"].(string)
	chain := func(c map[string]any) []map[string]any {
		var envelopes []any
		for _, e := range vector["chains"].(map[string]any)[c["chain"].(string)].([]any) {
			e := e.(map[string]any)
			envelopes = append(envelopes, map[string]any{"manifest": e["manifest"], "signature": map[string]any{"signer": "root", "key": rootKey, "sig": e["sig"]}})
		}
		manifests, err := ReadChain(envelopes[:int(asInt64(c["length"]).(int64))], rootKey)
		if err != nil {
			t.Fatal(err)
		}
		return manifests
	}
	byName := map[string]map[string]any{}
	for _, value := range vector["cases"].([]any) {
		c := value.(map[string]any)
		byName[c["name"].(string)] = c
	}
	policyWritten, ownerWritten := byName["a policy-written anchor, this node's policy"], byName["anchored at 3, the chain at 3"]
	if policyWritten == nil || ownerWritten == nil {
		t.Fatalf("the vector cases this test reads are gone")
	}
	counted := func(policy []byte, err error) (func() ([]byte, error), *int) {
		n := 0
		return func() ([]byte, error) { n++; return policy, err }, &n
	}
	// every index policy-written (counter and both slots): one question
	ask, n := counted(policyBytes(policyWritten["policy"]), nil)
	if hw, err := Anchored(fakeOf(t, policyWritten["tpm"].(map[string]any)), chain(policyWritten), ask); err != nil || hw != uint64(asInt64(policyWritten["high_water"]).(int64)) || *n != 1 {
		t.Errorf("a policy-written anchor: %d, %v, asked %d times", hw, err, *n)
	}
	// an owner-written anchor: never asked, even with a source that would refuse
	ask, n = counted(nil, &Refused{Reason: "no key"})
	if _, err := Anchored(fakeOf(t, ownerWritten["tpm"].(map[string]any)), chain(ownerWritten), ask); err != nil || *n != 0 {
		t.Errorf("an owner-written anchor: %v, asked %d times", err, *n)
	}
	// a source that refuses: the read is refused with its reason, never Unusable
	ask, _ = counted(nil, &Refused{Reason: "the image's PCR public key cannot be read"})
	_, err = Anchored(fakeOf(t, policyWritten["tpm"].(map[string]any)), chain(policyWritten), ask)
	var unusable *Unusable
	if refused, ok := err.(*Refused); !ok || refused.Reason != "the image's PCR public key cannot be read" || errors.As(err, &unusable) {
		t.Errorf("a source that refuses: %#v", err)
	}
	// and a source that returns something that is not a 32-byte digest
	ask, _ = counted([]byte{1, 2, 3}, nil)
	if _, err := Anchored(fakeOf(t, policyWritten["tpm"].(map[string]any)), chain(policyWritten), ask); err == nil || errors.As(err, &unusable) {
		t.Errorf("a short policy: %v", err)
	}
}
