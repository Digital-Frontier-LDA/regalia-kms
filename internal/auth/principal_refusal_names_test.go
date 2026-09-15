package auth

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// LoadPolicy's principal guard refused three different ways through one message that named
// nothing, while the duplicate-principal refusal two lines below and compileGrant's wrapper one
// layer down both named the principal (#333). An operator with one bad entry among many was told
// only that something was invalid, and could not tell whether the URI failed to parse, failed
// canonicalisation, or the entry simply had no grants — three different repairs.
//
// Every fixture here puts a VALID principal first and the offending one second. That is the shape
// the issue is about, and it pins something the single-principal shape cannot: that the message
// names the principal that failed rather than the first one in the file.
func TestAPolicyPrincipalRefusalNamesThePrincipalAndWhichOperandRefusedIt(t *testing.T) {
	const good = `{"uri":"spiffe://regalia/workload/tx-signer","grants":[{"objects":["k"],"operations":["sign"],"environments":["production"]}]}`
	const grant = `{"objects":["k"],"operations":["sign"],"environments":["production"]}`

	policy := func(second string) string {
		return `{"schema_version":1,"principals":[` + good + `,` + second + `]}`
	}

	// arm names which switch arm the row must reach. It is a field rather than something inferred
	// from the subtest name: keying the fixture check on prose means renaming a subtest silently
	// changes what the fixture asserts, and the row would go on passing while pinning nothing.
	for _, testCase := range []struct {
		name    string
		arm     string
		uri     string
		second  string
		wantErr string
	}{
		{
			name:   "a URI the parser rejects",
			arm:    "parse",
			uri:    "spiffe://regalia/workload/%zz",
			second: `{"uri":"spiffe://regalia/workload/%zz","grants":[` + grant + `]}`,
			wantErr: `RBAC principal "spiffe://regalia/workload/%zz": URI does not parse: ` +
				`parse "spiffe://regalia/workload/%zz": invalid URL escape "%zz"`,
		},
		{
			name:   "a URI that parses but is the trust domain rather than a workload under it",
			arm:    "canonical",
			uri:    "spiffe://regalia/",
			second: `{"uri":"spiffe://regalia/","grants":[` + grant + `]}`,
			wantErr: `RBAC principal "spiffe://regalia/": ` +
				`URI is not a canonical workload identity under "spiffe://regalia/"`,
		},
		{
			name:    "a canonical URI carrying no grants at all",
			arm:     "no-grants",
			uri:     "spiffe://regalia/workload/no-grants",
			second:  `{"uri":"spiffe://regalia/workload/no-grants","grants":[]}`,
			wantErr: `RBAC principal "spiffe://regalia/workload/no-grants": no grants`,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// The fixture must reach the arm under test rather than an earlier one, so assert what
			// the parser actually does with this URI instead of assuming it. A fixture refused by
			// the wrong operand would accuse the guard it is supposed to be exercising.
			prefix, prefixErr := url.Parse("spiffe://regalia/")
			if prefixErr != nil {
				t.Fatalf("fixture: the trust-domain prefix does not parse: %v", prefixErr)
			}
			identity, parseErr := url.Parse(testCase.uri)
			if testCase.arm == "parse" {
				if parseErr == nil {
					t.Fatalf("fixture: url.Parse(%q) succeeded, so this row cannot reach the parse arm "+
						"and would be refused by canonicalisation instead", testCase.uri)
				}
			} else {
				if parseErr != nil {
					t.Fatalf("fixture: url.Parse(%q) failed with %v, so this row is refused by the parse "+
						"arm and pins nothing about the %s arm it names", testCase.uri, parseErr, testCase.arm)
				}
				canonical := canonicalURISAN(identity, prefix)
				if testCase.arm == "canonical" && canonical {
					t.Fatalf("fixture: %q IS a canonical workload identity, so it never reaches the "+
						"canonicalisation arm this row is meant to pin", testCase.uri)
				}
				if testCase.arm == "no-grants" && !canonical {
					t.Fatalf("fixture: %q is NOT canonical, so it is refused by the canonicalisation arm "+
						"and pins nothing about the no-grants arm", testCase.uri)
				}
			}

			want := testCase.wantErr
			if testCase.arm == "parse" {
				want = fmt.Sprintf("RBAC principal %q: URI does not parse: %v", testCase.uri, parseErr)
			}

			loaded, err := LoadPolicy(strings.NewReader(policy(testCase.second)))
			if err == nil {
				t.Fatalf("DEFECT: LoadPolicy accepted %q as a principal, granting %+v",
					testCase.uri, loaded.GrantedObjects())
			}
			if err.Error() != want {
				t.Fatalf("LoadPolicy error = %q,\n                  want %q\n"+
					"— an operator repairing this file needs the offending principal and which of the "+
					"three operands refused it; a different message leaves one of them unproven",
					err, want)
			}
			// The valid principal sits FIRST in every fixture, so a message naming it would mean the
			// refusal reported the wrong entry — the failure mode the issue is actually about.
			if strings.Contains(err.Error(), "tx-signer") {
				t.Fatalf("LoadPolicy error = %q — it names the VALID first principal, not the entry "+
					"that failed, which is worse than naming nothing", err)
			}
		})
	}

	// Anchor, not a gate: the good principal these fixtures lead with must load on its own, or every
	// row above could be passing because the FIRST entry is what is being refused.
	t.Run("the valid principal every fixture leads with loads by itself", func(t *testing.T) {
		loaded, err := LoadPolicy(strings.NewReader(`{"schema_version":1,"principals":[` + good + `]}`))
		if err != nil {
			t.Fatalf("LoadPolicy(the valid lead principal) = %v, want it to load — the refusals above "+
				"would then be about this entry rather than the offending one", err)
		}
		if !loaded.Allowed("spiffe://regalia/workload/tx-signer", "k", "sign", "production") {
			t.Fatalf("the lead principal loaded but granted %+v, want its sign grant", loaded.GrantedObjects())
		}
	})
}
