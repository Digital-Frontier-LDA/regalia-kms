package main

// GUARD COVERAGE (#237 sweep). `cmd/regalia-fence` was one of nine packages the campaign
// never named. 24 mutations, verdicts from exit codes: 14 survived (58%).
//
// THE REQUIRED-FLAG GUARDS SURVIVED AS WHOLE GUARDS AND AS EVERY ONE OF THEIR SEVEN
// OPERANDS. Two tests already exercise them, and neither can detect a single flag becoming
// optional, because each omits several flags at once:
//
//   TestPromotionWithoutAttributionIsRefused  omits -operator AND -journal together, so
//                                             either operand alone still refuses
//   the fixture's own grant()                 always passes all seven
//
// One fixture that trips two operands cannot pin either. The table below omits exactly one
// flag per row, with every other flag valid, so each row's guard is the only thing that can
// refuse — and asserts the message, because on a path of sequential refusals `err != nil` is
// satisfied by whichever guard happens to fire first.

import (
	"strings"
	"testing"
)

func TestEveryRequiredFlagIsRequiredOnItsOwn(t *testing.T) {
	const digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for _, row := range []struct {
		omit    string // the flag left out; every other flag is supplied and valid
		wantMsg string
	}{
		{"-key", "are required"},
		{"-state", "are required"},
		{"-out", "are required"},
		{"-site", "are required"},
		{"-registry-digest", "are required"},
		{"-operator", "auditable"},
		{"-journal", "auditable"},
	} {
		t.Run("without "+row.omit, func(t *testing.T) {
			fixture := newIssuer(t)
			complete := map[string]string{
				"-key": fixture.key, "-state": fixture.state, "-out": fixture.lease,
				"-site": "sitea", "-registry-digest": digest,
				"-operator": "ops@regalia", "-journal": fixture.journal,
			}
			var arguments []string
			for flag, value := range complete {
				if flag == row.omit {
					continue
				}
				arguments = append(arguments, flag, value)
			}
			arguments = append(arguments, "-epoch", "1")

			err := run(arguments, fixture.out)
			if err == nil {
				t.Fatalf("%s was omitted and the promotion was accepted — a flag the tool does not enforce is a flag the tool does not require", row.omit)
			}
			if !strings.Contains(err.Error(), row.wantMsg) {
				t.Fatalf("%s omitted, refused by a different rule: %v — this row exists to prove the guard naming %q fires", row.omit, err, row.wantMsg)
			}
		})
	}

	// KNOWN-GOOD IN THE SAME TEST (§18). With all seven supplied the grant succeeds, so no row
	// above is satisfied by a tool that refuses every invocation.
	fixture := newIssuer(t)
	if err := run([]string{
		"-key", fixture.key, "-state", fixture.state, "-out", fixture.lease,
		"-site", "sitea", "-registry-digest", digest,
		"-operator", "ops@regalia", "-journal", fixture.journal, "-epoch", "1",
	}, fixture.out); err != nil {
		t.Fatalf("a complete invocation was refused (%v) — the rows above prove nothing against a tool that refuses everything", err)
	}
}
