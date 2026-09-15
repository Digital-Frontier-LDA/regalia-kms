package controlplane

import (
	"fmt"
	"testing"
)

// The two controls point opposite ways deliberately. A loop that never swaps
// leaves the descending row wrong; a loop that swaps every adjacent pair even
// when they are already ordered leaves the ascending row wrong. Together they
// distinguish all four operand-direction survivors found in #237's loop sweep.
func TestSortStringsOrdersBothDirections(t *testing.T) {
	for name, input := range map[string][]string{
		"descending requires swaps": {"zeta", "middle", "beta", "alpha"},
		"ascending forbids swaps":   {"alpha", "beta", "middle", "zeta"},
	} {
		t.Run(name, func(t *testing.T) {
			want := []string{"alpha", "beta", "middle", "zeta"}
			sortStrings(input)
			if fmt.Sprint(input) != fmt.Sprint(want) {
				t.Fatalf("sorted keys are %v, want %v — finding order then depends on map iteration, "+
					"so identical source can produce different reports", input, want)
			}
		})
	}
}
