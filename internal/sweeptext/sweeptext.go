// Package sweeptext restores source a mutation sweep has neutralised, so that a ledger's
// drift guard compares the guard it recorded against the guard as WRITTEN rather than
// against the harness's wrapper.
//
// WHY THIS IS SHARED RATHER THAN COPIED. A ledger that quotes live guard text ships a test
// asserting the quote still matches the file. That test sees the mutation wrapper, so it
// fails on every mutation of a guard it cites — and the failure direction is the dangerous
// one: a sweep harness reads a red as KILLED, so an operand no behavioural test detects is
// retired as covered. The gap is invisible from then on.
//
// Two packages grew that trap independently (internal/policy, then internal/audit), and the
// second inherited a bug from the first because the code was copied. Both copies missed the
// same shape, for the same reason. One implementation, tested once, against every shape.
//
// THE SHAPES. A harness must parenthesise an operand whenever it sits in a boolean chain,
// because `a || false && b || c` is not `a || (false && b) || c` — && binds tighter. But a
// SINGLE-operand guard has no chain to disambiguate, so the falsifier this repository
// documents is written literally as `if false && (err != nil) {`, with no outer parens. That
// is the most common guard shape in the tree and it is the one both copies missed.
//
//	false && (X)        no outer parens -- single-operand guards
//	(false && X)        outer parens, operand bare
//	(false && (X))      outer parens, operand parenthesised
//	(false && ((X)))    wrapped deeper, when the operand carries its own parens
//	false && X          no parens at all
//
// and the `true || ` twin of each, which is the neutralisation for an && leaf.
//
// LIMIT, stated because it is not obvious: this is text, not a parser, and it rewrites the
// literals wherever they appear — in prose OR in code.
//
//	if x || true || y {     ->  if x || y {
//	if x && false && y {    ->  if x && y {
//
// Those are dead branches nobody writes, which is why the limit is tolerable, but a ledger
// over a package that genuinely contains either literal would have that text silently
// altered before comparison. TWO non-test files in this module carry them today, both in
// comments:
//
//	kms/tools/guardenum/main.go   describing which neutralisation preserves an operand's siblings
//	kms/internal/sweeptext/sweeptext.go   this file, describing the shapes it strips
//
// No ledger reads either — policy's names guardenum only inside a comment of its own — so
// nothing is corrupted today. But tools/guardenum is one of #237's swept packages, and a
// ledger grown over it would hit exactly this: the drift guard would compare against source
// whose comments this function had rewritten. A ledger over a package whose source or
// comments discuss mutation wrappers needs a real parser, not this.
package sweeptext

import "strings"

// neutralisations are the two forms a sweep applies.
//
// "(false && X)" CONTAINS "false && X", so the bare pass could strip a parenthesised
// wrapper's prefix and leave its opening paren behind. It does not, because stripBare skips
// any occurrence sitting directly after '(' — which makes the two passes order-independent.
// The order below is the readable one, not a correctness requirement; the invariant that
// carries the weight is that skip, and it is pinned by the unbalanced-wrapper row of
// TestTextCarryingNoWrapperSurvivesByteForByte, which is its sole detector.
var neutralisations = []string{"false && ", "true || "}

// StripMutationWrappers returns source with every neutralisation removed and the operand it
// wrapped restored. Text carrying no wrapper is returned byte for byte, and an unbalanced
// wrapper is left alone rather than truncated — a stripper that ate its input would make
// every drift row pass while checking nothing.
func StripMutationWrappers(source string) string {
	for _, bare := range neutralisations {
		source = stripParenthesised(source, "("+bare)
		source = stripBare(source, bare)
	}
	return source
}

// stripParenthesised removes `(false && X)` — the wrapper carries its own parens, so the
// span to remove runs from the opening paren to the one that matches it.
func stripParenthesised(source, prefix string) string {
	for {
		start := strings.Index(source, prefix)
		if start < 0 {
			return source
		}
		end := matchingParen(source, start)
		if end < 0 {
			return source
		}
		source = source[:start] + peel(source[start+len(prefix):end]) + source[end+1:]
	}
}

// stripBare removes `false && ` written without an enclosing pair, together with the
// parentheses around the operand it introduces when the author wrote them. This is the
// documented single-operand form and the shape both earlier copies missed.
func stripBare(source, prefix string) string {
	from := 0
	for {
		offset := strings.Index(source[from:], prefix)
		if offset < 0 {
			return source
		}
		start := from + offset
		// An occurrence sitting directly after '(' belongs to the parenthesised form. If it
		// is still here, stripParenthesised declined it as unbalanced -- so leave it alone
		// rather than removing half a wrapper and corrupting the text.
		if start > 0 && source[start-1] == '(' {
			from = start + len(prefix)
			continue
		}
		rest := source[start+len(prefix):]
		if strings.HasPrefix(rest, "(") {
			end := matchingParen(rest, 0)
			if end < 0 {
				// An unbalanced group after a bare prefix: same rule, leave it whole.
				from = start + len(prefix)
				continue
			}
			source = source[:start] + peel(rest[:end+1]) + rest[end+1:]
			from = start
			continue
		}
		source = source[:start] + rest
		from = start
	}
}

// peel removes every redundant enclosing pair, not just one. An operand that sat in a chain
// AND carried its own parens is wrapped extra-deep, so `(false && ((!exists)))` must come
// back as `!exists` and not as `(!exists)`.
func peel(text string) string {
	for {
		next := UnwrapOnce(text)
		if next == text {
			return text
		}
		text = next
	}
}

// UnwrapOnce removes ONE paren pair, and only when it encloses the whole expression.
//
// `(cfg.RegistryPath == "") != (cfg.Site == "")` opens and closes with a paren without being
// wrapped in one. Unwrapping it would corrupt the very text the ledger compares against, so
// the restore would break exactly the rows it exists to protect.
func UnwrapOnce(text string) string {
	if len(text) < 2 || text[0] != '(' || text[len(text)-1] != ')' {
		return text
	}
	if end := matchingParen(text, 0); end != len(text)-1 {
		return text
	}
	return text[1 : len(text)-1]
}

// matchingParen returns the index of the paren closing the one at open, or -1 when the text
// is unbalanced. Callers return their input untouched on -1.
func matchingParen(text string, open int) int {
	depth := 0
	for index := open; index < len(text); index++ {
		switch text[index] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return index
			}
		}
	}
	return -1
}
