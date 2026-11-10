package opstate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// EtcdState against tests/vectors/sequence-cases-v1.json (regalia-07k): every case as documented, except the pairs
// the vector lists as divergent, which must STILL diverge, so a change of rule shows here and removes its pair.
func TestEtcdStateAnswersTheSequenceCases(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "sequence-cases-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name       string  `json:"name"`
			Previous   *uint64 `json:"previous"`
			Value      uint64  `json:"value"`
			Documented string  `json:"documented"`
		} `json:"cases"`
		Divergent struct {
			Bead  string              `json:"bead"`
			Cases map[string][]string `json:"cases"`
		} `json:"divergent"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Cases) == 0 {
		t.Fatalf("the vector: %v (%d cases)", err, len(v.Cases))
	}
	w := newTwoServers(t)
	ctx := context.Background()
	for i, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			at := func(nonce string, value uint64) policy.Reservation {
				r := w.reservation(nonce, 1, &value)
				r.SequenceKey = fmt.Sprintf("cosmoshub-4\x00%d", 100+i) // one sequence per case
				r.DailyCaps = map[string]uint64{"signatures": 1000}     // the cases share a day's quota: never the refusal here
				return r
			}
			if c.Previous != nil {
				if err := w.a.Reserve(ctx, at(fmt.Sprintf("018f00000000700080000000000b%04x", 2*i), *c.Previous)); err != nil {
					t.Fatalf("the previous sequence %d: %v", *c.Previous, err)
				}
			}
			err := w.b.Reserve(ctx, at(fmt.Sprintf("018f00000000700080000000000b%04x", 2*i+1), c.Value))
			got := "accept"
			if err != nil {
				if !errors.Is(err, policy.ErrSequence) {
					t.Fatalf("refused for another reason than the sequence: %v", err)
				}
				got = "refuse"
			}
			if slices.Contains(v.Divergent.Cases["etcdstate"], c.Name) {
				if got == c.Documented {
					t.Fatalf("%s: EtcdState now answers as documented (%s): the divergence is gone; remove it from the vector's divergent list (%s)", c.Name, got, v.Divergent.Bead)
				}
				t.Logf("%s: EtcdState answers %s, documented %s: a known divergence (%s)", c.Name, got, c.Documented, v.Divergent.Bead)
				return
			}
			if got != c.Documented {
				t.Fatalf("%s: EtcdState answers %s; documented: %s", c.Name, got, c.Documented)
			}
		})
	}
}
