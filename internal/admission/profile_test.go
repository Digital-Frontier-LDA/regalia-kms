package admission

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

func TestProfileComesFromTheVerifiedAdmissionDecision(t *testing.T) {
	for _, tc := range []struct{ profile, mode string }{
		{membership.ProfileSingleNode, ModeSingle},
		{membership.ProfileMultiNode, ModeLease},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			_, gate, document := chained(t, tc.profile, tc.mode)
			for i := 0; i < 2; i++ { // also exercise the unchanged verified-chain cache
				status := gate.Check(context.Background())
				if !status.Admitted || status.Profile != tc.profile || status.Epoch != uint64(document["epoch"].(int)) {
					t.Fatalf("admitted decision lacks its verified topology: admitted=%v profile=%q epoch=%d reason=%q", status.Admitted, status.Profile, status.Epoch, status.Reason)
				}
			}
		})
	}
}

func TestProfileIsNotInferredForChainlessLegacyAdmission(t *testing.T) {
	w := newWorld(t)
	status := w.gate.Check(context.Background())
	if !status.Admitted || status.Profile != "" {
		t.Fatalf("legacy peer admission guessed a topology: admitted=%v profile=%q reason=%q", status.Admitted, status.Profile, status.Reason)
	}
	document := good(w.now)
	document["mode"] = ModeSingle
	w.put(document)
	status = w.gate.Check(context.Background())
	if status.Admitted || status.Profile != "" {
		t.Fatalf("single mode without a chain acquired a topology: admitted=%v profile=%q", status.Admitted, status.Profile)
	}
}

func TestProfileDoesNotSurviveARefusedDecision(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*world, *Gate, map[string]any)
	}{
		{"expired", func(w *world, _ *Gate, _ map[string]any) { w.now += 25_000 }},
		{"wrong-epoch", func(w *world, _ *Gate, d map[string]any) { d["epoch"] = d["epoch"].(int) + 1; w.put(d) }},
		{"wrong-digest", func(w *world, _ *Gate, d map[string]any) { d["manifest_digest"] = strings.Repeat("0", 64); w.put(d) }},
		{"wrong-mode", func(w *world, _ *Gate, d map[string]any) { d["mode"] = ModeLease; w.put(d) }},
		{"missing-chain", func(w *world, _ *Gate, _ map[string]any) {
			if err := os.Remove(w.path("chain.json")); err != nil {
				w.t.Fatal(err)
			}
		}},
		{"malformed-chain", func(w *world, _ *Gate, _ map[string]any) { w.write("chain.json", []byte(`not-json`), 0o644) }},
		{"unverified-chain", func(w *world, _ *Gate, _ map[string]any) {
			w.write("chain.json", []byte(`[{"manifest":{},"signature":{}}]`), 0o644)
		}},
		{"writable-chain", func(w *world, _ *Gate, _ map[string]any) {
			if err := os.Chmod(w.path("chain.json"), 0o666); err != nil {
				w.t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, gate, document := chained(t, membership.ProfileSingleNode, ModeSingle)
			before := gate.Check(context.Background())
			if !before.Admitted || before.Profile != membership.ProfileSingleNode {
				t.Fatalf("positive control lacks verified profile: %+v", before)
			}
			tc.change(w, gate, document)
			status := gate.Check(context.Background())
			if status.Admitted || status.Profile != "" || status.Reason == "" {
				t.Fatalf("refused decision retained a topology: admitted=%v profile=%q reason=%q", status.Admitted, status.Profile, status.Reason)
			}
		})
	}
}

func TestProfileOfAVerifiedLegacyChainIsMultiNode(t *testing.T) {
	genesis, _, root := twoEpochs(t)
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
	document := good(w.now)
	document["epoch"], document["manifest_digest"] = tipOf(t, []any{genesis}, root)
	w.put(document)
	status := gate.Check(context.Background())
	if !status.Admitted || status.Profile != membership.ProfileMultiNode {
		t.Fatalf("verified legacy chain lost multi-node topology: admitted=%v profile=%q reason=%q", status.Admitted, status.Profile, status.Reason)
	}
}

func TestProfileIsEmptyOnCancellationAndAnUnwiredGate(t *testing.T) {
	_, gate, _ := chained(t, membership.ProfileSingleNode, ModeSingle)
	if status := gate.Check(context.Background()); !status.Admitted || status.Profile != membership.ProfileSingleNode {
		t.Fatalf("positive control lacks verified profile: %+v", status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, status := range []Status{gate.Check(ctx), (*Gate)(nil).Check(context.Background())} {
		if status.Admitted || status.Profile != "" || status.Reason == "" {
			t.Fatalf("unavailable decision carries a topology: %+v", status)
		}
	}
}
