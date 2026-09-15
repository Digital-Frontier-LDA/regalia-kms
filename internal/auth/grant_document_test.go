package auth

import (
	"fmt"
	"strings"
	"testing"
)

// EVERY OPERAND OF THE GRANT-DOCUMENT SHAPE, AND WHAT EACH ONE ADMITS WHEN IT IS GONE.
//
// #237 recorded internal/auth as the largest surface in the repo: 45 survivors, 37 never examined.
// Re-derived on current main, rbac.go measures 18 guards, 29 leaf operands, 13 survivors — and the
// two that would have been security findings are NOT among them:
//
//	:182  objectAllowed && operationAllowed && environmentAllowed   ZERO surviving operands.
//	      Allowed()'s access decision. Widening any one means that dimension stops being required,
//	      and all three are already killed.
//	:161  value == "" || value == "*"                               the WILDCARD half is covered.
//	      A grant carrying "*" is provably refused; a grant carrying "" was not.
//
// What survives is the policy DOCUMENT validation — the shape of an operator-supplied RBAC file,
// which the daemon reads at startup and never checks again. These are the operands nothing
// exercised, each with a fixture that only it can refuse.
//
// The dimensions are checked in order, so each fixture holds the other two dimensions valid:
// a document that is wrong in two ways is refused by whichever guard runs first and proves nothing
// about the second.

func grantPolicy(objects, operations, environments string) string {
	return `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/sops-prod",` +
		`"grants":[{"objects":` + objects + `,"operations":` + operations +
		`,"environments":` + environments + `}]}]}`
}

func TestAGrantDocumentIsRefusedForEachMalformedDimension(t *testing.T) {
	const (
		okObj = `["production-sops"]`
		okOps = `["unwrap"]`
		okEnv = `["production"]`
	)
	cases := []struct {
		name                      string
		objects, operations, envs string
		want                      string // "" means accepted
	}{
		// ANCHOR. Without it every refusal below is compatible with "LoadPolicy refuses everything".
		{"a well-formed grant", okObj, okOps, okEnv, ""},

		// :149 — a dimension may not be empty. One row per operand, the other two valid.
		{"no objects", `[]`, okOps, okEnv, "grant dimensions must be non-empty"},
		{"no operations", okObj, `[]`, okEnv, "grant dimensions must be non-empty"},
		{"no environments", okObj, okOps, `[]`, "grant dimensions must be non-empty"},

		// :156 — values within a dimension must be unique. A duplicate collapses in the set and the
		// length comparison is the only thing that notices; without it the grant silently means
		// something narrower than it reads.
		{"a duplicated object", `["a","a"]`, okOps, okEnv, "grant values must be unique"},
		{"a duplicated operation", okObj, `["unwrap","unwrap"]`, okEnv, "grant values must be unique"},
		{"a duplicated environment", okObj, okOps, `["production","production"]`, "grant values must be unique"},

		// :161 op0 — the empty value. Its sibling (the "*" wildcard) already had a detector; this
		// half did not. An empty string is a value that matches nothing, so a grant carrying one
		// reads as authorising something and authorises nothing — the failure is silent either way,
		// which is why the document is refused rather than cleaned.
		{"an empty object value", `[""]`, okOps, okEnv, "empty values and wildcards are forbidden"},

		// ANCHOR for the covered sibling, kept so a future edit removing it fails here rather than
		// silently admitting a wildcard grant.
		{"a wildcard object value", `["*"]`, okOps, okEnv, "empty values and wildcards are forbidden"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			policy, err := LoadPolicy(strings.NewReader(
				grantPolicy(testCase.objects, testCase.operations, testCase.envs)))

			if testCase.want == "" {
				if err != nil || policy == nil {
					t.Fatalf("the anchor was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted a malformed grant document: objects=%s operations=%s environments=%s",
					testCase.objects, testCase.operations, testCase.envs)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want it to contain %q — a document wrong in one way must be "+
					"refused by the guard for THAT way, or the message sends an operator to the "+
					"wrong line of their policy file", err, testCase.want)
			}
		})
	}
}

// A PRINCIPAL WITH NO GRANTS IS NOT A PRINCIPAL.
//
// The no-grants arm of LoadPolicy's principal switch. It was the third operand of a single
// disjunction whose two siblings (a parse error, and the URI failing the canonical SPIFFE shape)
// were checked elsewhere while this one was not; #333 split the three into arms that each name
// the principal and say which one refused. An entry naming a principal and granting it nothing is
// almost certainly a truncated edit, and admitting it puts a name in the policy that authorises
// nothing — which reads, to anyone auditing the file, as a principal that was deliberately scoped
// to zero rather than one whose grants were lost.
func TestAPrincipalWithNoGrantsIsRefused(t *testing.T) {
	document := `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/sops-prod","grants":[]}]}`

	policy, err := LoadPolicy(strings.NewReader(document))

	if err == nil {
		t.Fatalf("a principal carrying no grants was accepted: %#v", policy)
	}
	const want = `RBAC principal "spiffe://regalia/workload/sops-prod": no grants`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err, want)
	}
	// This assertion was a substring of a message that named nothing, with a NOTE saying the
	// refusal ought to name the offending principal and that asserting the better message would
	// fail on today's code. #333 made that change, so the NOTE is gone and the message is pinned
	// exactly: an operator with fifty principals now learns which entry is truncated, and that
	// the entry is truncated rather than malformed.
}

// THE POLICY FILE HAS A SIZE BOUND, AND NOTHING EXERCISED IT.
//
// :109. The daemon reads this file at startup and the decoder would otherwise be handed whatever
// is on disk. The bound is refused before parsing, so the failure an operator sees names the size
// rather than arriving as a decode error from somewhere inside a multi-megabyte document.
func TestAnOversizedPolicyFileIsRefusedBeforeParsing(t *testing.T) {
	// Valid JSON, just far too much of it: the padding is inside a string so the document stays
	// parseable. If the bound were removed this would decode successfully, so the refusal is
	// attributable to the size check and not to malformed input.
	padding := strings.Repeat("x", maxPolicyBytes)
	oversized := fmt.Sprintf(`{"schema_version":1,"_pad":%q,"principals":[{"uri":"spiffe://regalia/workload/sops-prod",`+
		`"grants":[{"objects":["production-sops"],"operations":["unwrap"],"environments":["production"]}]}]}`, padding)
	path := writePolicyFile(t, oversized, 0o600)

	policy, err := LoadPolicyFile(path)

	if err == nil {
		t.Fatalf("a policy file over the %d-byte bound was accepted: %#v", maxPolicyBytes, policy)
	}
	if !strings.Contains(err.Error(), "exceeds 512 KiB") {
		t.Fatalf("error = %v, which does not name the size as the reason — an operator handed a "+
			"decode error from inside a half-megabyte document has no way to tell a truncated "+
			"file from an oversized one", err)
	}
}
