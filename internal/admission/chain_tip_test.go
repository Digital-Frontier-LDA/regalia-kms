package admission

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// AN ADMISSION IS GOOD ONLY FOR THE EPOCH IT WAS JUDGED UNDER (48 on #432). With the chain path set, the gate
// admits only an admission whose epoch and manifest digest are the published chain's tip, verified from the
// pinned root.

func renamePublic(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			if k == "public" {
				k = "key"
			}
			out[k] = renamePublic(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = renamePublic(x)
		}
		return out
	}
	return value
}

// twoEpochs finds, in tests/vectors/membership-v4.json, a root-signed genesis and an envelope that follows it:
// the chain at epoch 1, then at epoch 2, with its root.
func twoEpochs(t *testing.T) (genesis, next any, root any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "membership-v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := membership.Load(raw, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	cases := renamePublic(document).(map[string]any)["cases"].([]any)
	for _, a := range cases {
		g := a.(map[string]any)
		if g["current"] != nil || g["accepted"] == nil {
			continue
		}
		for _, b := range cases {
			n := b.(map[string]any)
			if n["accepted"] == nil || n["current"] == nil {
				continue
			}
			if _, err := membership.ReadChain([]any{g["envelope"], n["envelope"]}, g["root_public"]); err == nil {
				return g["envelope"], n["envelope"], g["root_public"]
			}
		}
	}
	t.Fatal("the v4 vector holds no genesis with an envelope that follows it")
	return nil, nil, nil
}

func tipOf(t *testing.T, envelopes []any, root any) (int, string) {
	t.Helper()
	manifests, err := membership.ReadChain(envelopes, root)
	if err != nil {
		t.Fatal(err)
	}
	tip := manifests[len(manifests)-1]
	epoch, err := strconv.Atoi(fmt.Sprint(tip["epoch"]))
	if err != nil {
		t.Fatal(err)
	}
	return epoch, membership.Digest(tip)
}

func TestAnAdmissionIsGoodOnlyForTheChainsTip(t *testing.T) {
	genesis, next, root := twoEpochs(t)
	w := newWorld(t)
	w.write("chain.json", membership.Canonical([]any{genesis}), 0o644)
	gate, err := Open(Options{
		Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"), OwnerUID: uint32(os.Getuid()),
		SessionOwnerUID: uint32(os.Getuid()), Boottime: func() (int64, error) { return w.now, nil },
		BootID: func() (string, error) { return testBoot, nil }, ChainPath: w.path("chain.json"), ChainOwnerUID: uint32(os.Getuid()), Root: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	epoch1, digest1 := tipOf(t, []any{genesis}, root)
	admitted := good(w.now)
	admitted["epoch"], admitted["manifest_digest"] = epoch1, digest1
	w.put(admitted)
	expect := func(want string) {
		t.Helper()
		status := gate.Check(context.Background())
		if want == "" {
			if !status.Admitted {
				t.Fatalf("not admitted: %s", status.Reason)
			}
			return
		}
		if status.Admitted || !strings.Contains(status.Reason, want) {
			t.Fatalf("admitted=%v, reason %q, not %q", status.Admitted, status.Reason, want)
		}
	}
	expect("")
	// the chain moves on (sync published epoch 2): the admission judged under epoch 1 is refused at once
	w.write("chain.json", membership.Canonical([]any{genesis, next}), 0o644)
	expect("the admission is for epoch 1; the chain is at 2")
	// admission catches up: admitted again
	epoch2, digest2 := tipOf(t, []any{genesis, next}, root)
	admitted["epoch"], admitted["manifest_digest"] = epoch2, digest2
	w.put(admitted)
	expect("")
	// the same epoch with another manifest
	admitted["manifest_digest"] = strings.Repeat("ab", 32)
	w.put(admitted)
	expect("for another manifest at epoch 2")
	admitted["manifest_digest"] = digest2
	w.put(admitted)
	// a chain that does not verify from the pinned root, or that cannot be read safely, admits nothing
	w.write("chain.json", []byte(`[{"manifest":{},"signature":{}}]`), 0o644)
	expect("the membership chain:")
	w.write("chain.json", membership.Canonical([]any{genesis, next}), 0o666)
	expect("the membership chain: it is not a file only its owner or root can write")
	if err := os.Remove(w.path("chain.json")); err != nil {
		t.Fatal(err)
	}
	expect("the membership chain:")
	w.write("chain.json", membership.Canonical([]any{genesis, next}), 0o644)
	expect("")
	// Open refuses a chain path with no pinned root
	if _, err := Open(Options{Path: w.path("admission.json"), NodeID: "a", SessionPath: w.path("boot-session"),
		BootID: func() (string, error) { return testBoot, nil }, ChainPath: w.path("chain.json")}); err == nil {
		t.Fatal("a chain path with no root was taken")
	}
}
