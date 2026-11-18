package admission

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// regalia-kms-dx7.3 (docs/design/single-node.md 4.3): mode single, the single-node profile's self-issued lease. It
// serves stateless and stateful operations as a peer's lease does, with the lease's state, and only against a
// membership chain whose verified tip is of the single-node profile.

// genesisOf finds, in tests/vectors/membership-v5.json, a root-signed genesis of `profile`, with its root.
func genesisOf(t *testing.T, profile string) (envelope any, root any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "membership-v5.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := membership.Load(raw, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range renamePublic(document).(map[string]any)["cases"].([]any) {
		g := c.(map[string]any)
		if g["current"] != nil || g["accepted"] == nil {
			continue
		}
		manifests, err := membership.ReadChain([]any{g["envelope"]}, g["root_public"])
		if err != nil {
			continue
		}
		if got, err := membership.Profile(manifests[0]); err == nil && got == profile {
			return g["envelope"], g["root_public"]
		}
	}
	t.Fatalf("the v5 vector holds no %s genesis", profile)
	return nil, nil
}

// chained is a gate over a published chain of one genesis of `profile`, and an admission of `mode` for its tip.
func chained(t *testing.T, profile, mode string) (*world, *Gate, map[string]any) {
	t.Helper()
	genesis, root := genesisOf(t, profile)
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
	epoch, digest := tipOf(t, []any{genesis}, root)
	document := good(w.now)
	document["epoch"], document["manifest_digest"], document["mode"] = epoch, digest, mode
	w.put(document)
	return w, gate, document
}

func TestSingleServesUnderTheSingleNodeProfileWithTheLeasesState(t *testing.T) {
	_, gate, document := chained(t, membership.ProfileSingleNode, ModeSingle)
	status := gate.Check(context.Background())
	if !status.Admitted {
		t.Fatalf("not admitted: %s", status.Reason)
	}
	want := LeaseState{ClusterID: testCluster, StateEpoch: 2, StateRevision: 41, SessionKey: testKey}
	if status.State != want || status.Recovery || status.RequestedBoottimeMs != document["requested_boottime_ms"].(int64) {
		t.Fatalf("status %+v: the lease's state and request time are carried as under a peer's lease", status)
	}
	// stateful work runs (AdmittedRunner), and a token is served under it as under a peer's lease (#72)
	if !gate.Admits(context.Background(), "DENK0404144", 0) {
		t.Fatal("a listed token is not served in mode single")
	}
}

func TestTheModeMustFitTheChainsProfile(t *testing.T) {
	for _, c := range []struct{ profile, mode, want string }{
		{membership.ProfileSingleNode, ModeLease, "admission mode lease is refused under the single-node profile"},
		{membership.ProfileMultiNode, ModeSingle, "admission mode single is refused under the multi-node profile"},
	} {
		t.Run(c.profile+"/"+c.mode, func(t *testing.T) {
			w, gate, _ := chained(t, c.profile, c.mode)
			w.gate = gate
			w.refused(c.want)
		})
	}
	// a peer's lease under multi-node is as before
	_, gate, _ := chained(t, membership.ProfileMultiNode, ModeLease)
	if status := gate.Check(context.Background()); !status.Admitted {
		t.Fatalf("a peer's lease under multi-node: %s", status.Reason)
	}
}

func TestRecoveryUnderTheSingleNodeProfileServesNothing(t *testing.T) {
	w, gate, document := chained(t, membership.ProfileSingleNode, ModeRecovery)
	document["cluster_id"], document["state_epoch"], document["state_revision"], document["session_key"] =
		strings.Repeat("0", 16), 0, 0, strings.Repeat("0", 64)
	w.put(document)
	if status := gate.Check(context.Background()); status.Admitted {
		t.Fatal("recovery admitted under the single-node profile")
	}
}

func TestSingleWithNoChainConfiguredIsRefused(t *testing.T) {
	w := newWorld(t)
	document := good(w.now)
	document["mode"] = ModeSingle
	w.put(document)
	w.refused("an admission in mode single is served only against the membership chain's single-node profile, and no membership chain is configured")
}

func TestASingleAdmissionThatServesCarriesTheLeasesState(t *testing.T) {
	document := good(1_000_000)
	document["mode"], document["cluster_id"] = ModeSingle, strings.Repeat("0", 16)
	encoded, _ := json.Marshal(document)
	if _, err := Parse(encoded); err == nil || !strings.Contains(err.Error(), "serves under a lease but carries no lease state") {
		t.Fatalf("a single admission serving with no state: %v", err)
	}
	document["serve_until_boottime_ms"] = 0 // not serving: zeros are what the writer puts there
	encoded, _ = json.Marshal(document)
	if _, err := Parse(encoded); err != nil {
		t.Fatalf("a single admission not serving: %v", err)
	}
}

// TestTheSelfLeaseVector replays tests/vectors/self-lease-v1.json, which deploy/baremetal's lease and admission replay
// too: whether each mode fits each profile, and that the document the lease service writes in that mode parses.
func TestTheSelfLeaseVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "self-lease-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Schema string
		Cases  []struct {
			Name, Profile string
			Mode          *string
			Fits          bool
		}
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Schema != "regalia.test-vectors/self-lease-v1" || len(vector.Cases) == 0 {
		t.Fatalf("the vector is %q with %d cases", vector.Schema, len(vector.Cases))
	}
	replayed := 0
	for _, c := range vector.Cases {
		if c.Mode == nil {
			continue // a lease refused before any admission is written: lease.verify's, in Python
		}
		replayed++
		err := modeFitsProfile(*c.Mode, c.Profile)
		if (err == nil) != c.Fits {
			t.Errorf("%s: modeFitsProfile(%s, %s) = %v, the vector says fits=%v", c.Name, *c.Mode, c.Profile, err, c.Fits)
		}
		document := good(1_000_000)
		document["mode"] = *c.Mode
		if *c.Mode == ModeRecovery {
			document["cluster_id"], document["state_epoch"], document["state_revision"], document["session_key"] =
				strings.Repeat("0", 16), 0, 0, strings.Repeat("0", 64)
		}
		encoded, _ := json.Marshal(document)
		if _, err := Parse(encoded); err != nil {
			t.Errorf("%s: the lease service's document in mode %s does not parse: %v", c.Name, *c.Mode, err)
		}
	}
	if replayed < 5 {
		t.Fatalf("only %d cases replayed", replayed)
	}
	if err := modeFitsProfile(ModeSingle, "two-node"); err == nil {
		t.Fatal("an unknown profile fits")
	}
	if err := modeFitsProfile("standby", membership.ProfileMultiNode); err == nil {
		t.Fatal("an unknown mode fits")
	}
}
