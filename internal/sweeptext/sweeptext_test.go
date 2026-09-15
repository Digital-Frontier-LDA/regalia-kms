package sweeptext

import "testing"

// TestEveryFalsifierShapeIsRestored is the table both earlier copies of this code were
// missing a row from.
//
// internal/policy's copy and internal/audit's copy each pinned four shapes and each called
// double-nesting "outer-parens", which is a different thing from having no outer parens at
// all. Neither had a row for `false && (X)` — and that is the form this repository's own
// documentation gives for a single-operand guard, `if false && (err != nil) {`, because
// there is no chain to disambiguate. It is the most common guard shape in the tree.
//
// Each shape is its own subtest so a failure names which one broke rather than reporting
// "the stripper is wrong".
func TestEveryFalsifierShapeIsRestored(t *testing.T) {
	const single = "if err != nil {"
	const chain = `if denom == "" || transactionCap == 0 || !exists || dailyCap < transactionCap {`
	for _, row := range []struct {
		shape   string
		mutated string
		want    string
	}{
		{"no outer parens, the documented single-operand form", "if false && (err != nil) {", single},
		{"no outer parens, the true-or twin", "if true || (err != nil) {", single},
		{"no parens at all", "if false && err != nil {", single},
		{
			"outer parens, operand bare",
			`if denom == "" || transactionCap == 0 || (false && !exists) || dailyCap < transactionCap {`,
			chain,
		},
		{
			"outer parens, operand parenthesised",
			`if denom == "" || transactionCap == 0 || (false && (!exists)) || dailyCap < transactionCap {`,
			chain,
		},
		{
			"outer parens, operand parenthesised, true-or twin",
			`if denom == "" || transactionCap == 0 || (true || (!exists)) || dailyCap < transactionCap {`,
			chain,
		},
		{
			"wrapped deeper, because the operand carries its own parens",
			`if denom == "" || transactionCap == 0 || (false && ((!exists))) || dailyCap < transactionCap {`,
			chain,
		},
		{
			"an operand whose own text is parenthesised in the source",
			"if x || ((false && (a && b))) {",
			"if x || (a && b) {",
		},
		{
			"two operands of one guard, neutralised in opposite directions",
			"return (false && !state.closed) && (true || state.file != nil)",
			"return !state.closed && state.file != nil",
		},
	} {
		t.Run(row.shape, func(t *testing.T) {
			if row.mutated == row.want {
				t.Fatal("this row's mutation is a no-op, so it pins nothing")
			}
			if got := StripMutationWrappers(row.mutated); got != row.want {
				t.Fatalf("not restored:\n  got  %s\n  want %s", got, row.want)
			}
		})
	}
}

// TestTextCarryingNoWrapperSurvivesByteForByte is the other direction, and it is the one
// that matters more.
//
// A stripper that rewrote unmutated source would make the drift guard compare the ledger
// against text nobody wrote — it would pass over real drift, silently, which is the same
// failure direction as the bug this package exists to fix.
func TestTextCarryingNoWrapperSurvivesByteForByte(t *testing.T) {
	for _, row := range []struct {
		name string
		text string
	}{
		{"a plain guard", "if err != nil || !info.Mode().IsRegular() {"},
		{"arithmetic with its own parens", "if !known || ^uint64(0)-totals[coin.Denom] < coin.Amount {"},
		{"a regexp call", `if request.Principal == "" || !noncePattern.MatchString(request.Nonce) {`},
		{"a boolean return", "return !state.closed && !state.failed && state.file != nil"},
		{
			"opens and closes with a paren WITHOUT being wrapped in one",
			`if (cfg.RegistryPath == "") != (cfg.Site == "") {`,
		},
		{"an unbalanced wrapper is left alone, not truncated", "if (false && f(x {"},
		{"a bare prefix with an unbalanced group after it", "if false && (f(x {"},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := StripMutationWrappers(row.text); got != row.text {
				t.Fatalf("rewritten:\n  got  %s\n  want %s", got, row.text)
			}
		})
	}
}

// TestUnwrapOnceRemovesOnePairAndOnlyWhenItEnclosesEverything pins the primitive directly,
// because peel() calls it in a loop and a wrong answer there is a silent over-strip.
func TestUnwrapOnceRemovesOnePairAndOnlyWhenItEnclosesEverything(t *testing.T) {
	for _, row := range []struct{ in, want string }{
		{"(!exists)", "!exists"},
		{"((a || b))", "(a || b)"},
		{"!exists", "!exists"},
		{`(a == "") != (b == "")`, `(a == "") != (b == "")`},
		{"(a) && (b)", "(a) && (b)"},
		{"()", ""},
		{"(", "("},
		{"", ""},
		{"(unbalanced", "(unbalanced"},
	} {
		if got := UnwrapOnce(row.in); got != row.want {
			t.Errorf("UnwrapOnce(%q) = %q, want %q", row.in, got, row.want)
		}
	}
}

// The ordering of the two passes is NOT pinned here, and that is deliberate.
//
// A test asserting "the parenthesised form is consumed first" passes whether or not the
// property holds, because stripBare skips occurrences preceded by '(' and the passes are
// therefore order-independent. I wrote that test, measured it by swapping the order, and it
// stayed green — so it gated nothing and is not shipped. What the swap cannot survive is
// removing the skip itself, and the unbalanced-wrapper row above is its sole detector.

// TestGenuineDriftSurvivesTheStripAndStillFailsTheComparison pins the property the shape
// table above cannot reach.
//
// The shape rows distinguish a working strip from a broken one. They do NOT distinguish it
// from an over-aggressive one, and that is the worse failure: a strip that rewrites too much
// makes every shape green INCLUDING the arms that are real drift, so the guard it exists to
// protect is silently disarmed and passes over exactly the edits it was built to catch. Both
// failure modes look identical from the shape table alone.
//
// So these rows are not mutations. They are the guard rewritten the way a person rewrites
// one, and each must come back byte for byte AND still differ from what a ledger recorded —
// the strip must not launder drift into a match.
func TestGenuineDriftSurvivesTheStripAndStillFailsTheComparison(t *testing.T) {
	const recorded = "\tif err != nil {"
	for _, row := range []struct {
		name    string
		drifted string
	}{
		{"operands transposed", "\tif nil != err {"},
		{"a redundant conjunct added", "\tif err != nil && true {"},
		{"the guard inverted", "\tif err == nil {"},
		{"a different error variable", "\tif writeErr != nil {"},
	} {
		t.Run(row.name, func(t *testing.T) {
			if row.drifted == recorded {
				t.Fatal("this row is identical to the recorded guard, so it is not drift and pins nothing")
			}
			got := StripMutationWrappers(row.drifted)
			if got != row.drifted {
				t.Fatalf("drift was rewritten:\n  got  %q\n  want %q", got, row.drifted)
			}
			if got == recorded {
				t.Fatalf("the strip laundered drift into a match with %q, which disarms the drift guard", recorded)
			}
		})
	}
}
