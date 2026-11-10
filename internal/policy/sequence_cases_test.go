package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// sequenceCases is tests/vectors/sequence-cases-v1.json: the account-sequence rule every policy.State answers the
// same way (regalia-07k), with the pairs known to diverge until it is decided.
type sequenceCases struct {
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

func loadSequenceCases(t *testing.T) sequenceCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "sequence-cases-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v sequenceCases
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("the vector has no cases")
	}
	return v
}

// FileState answers every case as documented, and is listed as divergent on none.
func TestFileStateAnswersEverySequenceCaseAsDocumented(t *testing.T) {
	v := loadSequenceCases(t)
	if len(v.Divergent.Cases["filestate"]) != 0 {
		t.Fatalf("the vector lists FileState as divergent on %v: FileState is the documented rule", v.Divergent.Cases["filestate"])
	}
	for i, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			state, err := OpenFileState(filepath.Join(t.TempDir(), "state.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			at := func(nonce string, value uint64) Reservation {
				r := reservation(nonce, "2026-10-23", 1, 1_000)
				r.Sequence, r.SequenceKey = &value, fmt.Sprintf("cosmoshub-4\x00%d", i)
				return r
			}
			if c.Previous != nil {
				if err := state.Reserve(context.Background(), at("nonce_previous_00001", *c.Previous)); err != nil {
					t.Fatalf("the previous sequence %d: %v", *c.Previous, err)
				}
			}
			err = state.Reserve(context.Background(), at("nonce_this_000000001", c.Value))
			got := "accept"
			if err != nil {
				if !errors.Is(err, ErrSequence) {
					t.Fatalf("refused for another reason than the sequence: %v", err)
				}
				got = "refuse"
			}
			if got != c.Documented {
				t.Fatalf("%s: FileState answers %s; documented: %s", c.Name, got, c.Documented)
			}
		})
	}
}
