// Command guardenum enumerates every boolean decision point in a Go file, and
// every leaf operand within it, using the parser rather than a pattern.
//
// WHY THIS IS NOT A REGEX. Mutation sweeps in this repo enumerated their targets
// with `^[ \t]*if .*\{[ \t]*$`, which requires the `if` to end on its own line.
// Four separate enumeration defects followed from that choice, each found
// independently, and each made a sweep report BETTER coverage than existed:
//
//	single-line  if err != nil {                          matched
//	multi-line   if a ||\n\tb {                           MISSED
//	if-init      if _, ok := m[k]; ok {                   matched, but "ok" appears
//	                                                      twice, so a mutator that
//	                                                      requires a unique text
//	                                                      match skips the site
//	bool return  return a && b                            MISSED
//	multi-line   return a &&\n\tb                         MISSED
//	bool return
//
// The blindness is not uniform, it SELECTS. A guard is written across lines
// because it is complicated, so the pattern skips the sites that most need
// sweeping. In internal/auth it hid canonicalURISAN entirely -- the SPIFFE
// identity canonicalisation, twelve operands plus a three-operand boolean
// return -- while the package read as swept. And readiness predicates are
// idiomatically boolean returns, so the same blind spot hid the gate deciding
// whether the daemon reports itself ready in several packages at once.
//
// One AST traversal covers these layouts, because the parser sees a condition
// however it is written.
//
// WHAT THIS DOES NOT ENUMERATE. The paragraph that stood here until #237 made a
// completeness claim where a scope statement belonged: that an `if` condition
// and a boolean `return` "are the only places these operands occur, and there is
// no sixth to discover later". It was false, and the FORM of the claim is why it
// survived: a stated limit invites someone to test the boundary, a guarantee
// tells them not to bother, and every consumer downstream then treats the
// enumeration as total rather than as far as the tool reaches.
//
// What it missed is a case clause of a switch with NO tag expression, which is a
// boolean branch carrying neither keyword:
//
//	switch {
//	case provenanceErr != nil:      // a decision, invisible to the old tool
//	case record != nil:
//	}
//
// Measured when that shape was added: 24 operands across 20 case sites in 7
// files, every one of them in a package whose sweep had already been reported.
// Three of the five gaps closed in cmd/regalia-kms (#358) live in this shape,
// including the one where neutralising `case provenanceErr != nil:` makes
// `-check-config` print "preflight passed" over a host it cannot account for.
//
// A CASE CLAUSE MAY LIST SEVERAL EXPRESSIONS, AND EACH IS ITS OWN SITE.
// `case a, b:` is two sites, not one site with two leaves. The clause fires if
// EITHER expression holds, so they compose exactly as `||` does -- which a
// per-expression site already states, since a leaf standing alone reports the
// `||` joiner and `(false && a)` leaves `b` still gating the arm. Folding them
// into one site would also have to invent a Line..EndLine span covering text
// that is not one expression.
//
// The list below is what this tool declines to look at, and why. It is not a
// promise that the list is exhaustive. It is where to start when a count looks
// short.
//
//	switch kind { case "a": }   A TAGGED switch is not a boolean decision: its
//	                            case expressions are compared against the tag,
//	                            not against truth. Neutralising one means
//	                            something else there -- in `switch ok { case a &&
//	                            b: }`, forcing the expression false SELECTS the
//	                            arm whenever ok is false. The joiner would be a
//	                            lie about which direction preserves the siblings,
//	                            which is worse than no record at all.
//	switch v := x.(type) { }    A type switch selects on type, for that reason.
//	return a && b, nil          A boolean return is a site only as the SOLE
//	                            result, so that the site and the value the caller
//	                            branches on are the same thing. Re-measured over
//	                            all non-test Go under kms/ at 7760182: 0
//	                            multi-result returns whose result is a boolean
//	                            operator.
//	ok := a && b                An assignment defers the decision to whatever
//	                            reads `ok`; the branch is enumerated there.
//	return !(a && b)            Negation and conversion are themselves the
//	return bool(a && b)         top-level operator -- see the ReturnStmt case.
//	return f(a && b)            An argument, not a branch.
//
// LOOP CONDITIONS NEED A TIMEOUT, NOT OMISSION. A for-clause condition is a
// boolean decision and is enumerated as kind "for". Its widening mutation can
// keep a loop alive forever, so a consumer sweeping either direction must run
// the package with an explicit timeout and classify a timeout as a detected
// hang. A run without a timeout records nothing about that operand. Infinite
// loops and range loops have no for-clause condition and contribute no site.
//
// Re-measured at 7760182: all non-test Go under kms/ contains 12 for-clause
// sites / 15 operands. #237's inherited 22-package population contains 11/13;
// the remaining two-operand loop is in tools/inventory, outside that issue's
// scope. The issue denominator is 1405 sites / 2007 operands: its case-aware
// 1392/1992 baseline, plus the 11/13 loop delta, plus one single-operand server
// guard added by #367, plus the single-operand Cond guard this enumerator added
// in #372. The earlier 1404/2008 figure mixed populations by including
// internal/backend and omitting tools/guardenum.
//
// Both directions of the 13 in-scope loop operands were run with a timeout: 13
// ordinary detections, 8 panic/lower-bound detections, 1 timeout, and 4 initial
// survivors. The four survivors were the insertion sort in
// controlplane.sortedKeys; TestSortStringsOrdersBothDirections is now their
// sole detector.
//
// OFFSETS, NOT TEXT. Each leaf is reported as a byte range. A mutator that
// slices at those offsets cannot mutate the wrong occurrence, which text
// matching cannot promise: requiring a unique match drops legitimate sites
// (`if _, ok := m[k]; ok {`), and not requiring one mutates whichever came
// first.
//
// THE OFFSETS ARE BYTE OFFSETS. SLICE BYTES, NOT CHARACTERS. Go indexes
// strings by byte and so does this tool. Python and Ruby index by code point;
// JavaScript indexes by UTF-16 code unit. Those two models coincide for BMP
// characters and diverge above U+FFFF -- an emoji is one code point and two
// UTF-16 units -- but BOTH differ from bytes, so a consumer in any of them that
// reads the file as text mis-addresses every operand after the first non-ASCII
// byte, and the drift accumulates.
//
// Two separate splits, and they have different causes. ASTRAL CHARACTERS split
// UTF-16 from code points; ANY non-ASCII character splits both of those from
// bytes. Only the second one matters for addressing this repository.
//
// Measured: pkcs11_driver.go is 39373 bytes and 39333 code points, and its only
// non-ASCII character is U+2014. So code-point and UTF-16 indexing agree here
// today -- a property of the current comments, not a guarantee, since one astral
// character anywhere in a file would separate them.
//
// The byte split is the one that bites, and it is not a rare edge. This
// repository's comments use em-dashes freely: measured across four already-swept
// files, 257 of 315 operand spans land on the wrong text under code-point
// slicing.
//
// The failure is quiet rather than loud. A shifted span is often still valid
// Go, so the mutation compiles and the run yields a plausible verdict about an
// operand nobody chose.
//
// WHICH IS WHY THE TEXT FIELD IS EMITTED AT ALL. It is not a convenience
// duplicate of the offsets, it is the CHECK on them: a consumer should assert
// that the bytes at [start:end] equal the reported text before acting, and stop
// if they do not. Emitting the text is what makes that check possible.
//
// AND THE TEXT IS %q-QUOTED, so that check must DECODE it first. Comparing the
// raw field to the source is a second, independent trap: `principal == ""` is
// emitted as `"principal == \"\""`, so every operand containing a string
// literal differs. Measured on one consumer's two files, 51 of 128 operands
// differed taken raw and 0 differed decoded.
//
// This trap is indexing-independent: it bites a Go consumer too.
//
// The two traps are easy to confuse, and confusing them is expensive. A raw
// comparison fails with the same symptom as a byte/character mix-up -- the span
// does not hold what the field says -- so a consumer that has just fixed the
// offsets reads it as "the fix did not work" and re-examines code that is
// already correct. A diagnostic here should print BOTH sides, the bytes and the
// field, because that distinguishes them at a glance.
//
// A MUTATOR SHOULD BUILD ITS REPLACEMENT FROM src[start:end], NEVER FROM THE
// TEXT FIELD. Splicing the escaped form back in yields
// `(false && (principal == \"\"))`, which usually fails to build -- loud, and
// therefore survivable. But in an && chain the widening form short-circuits, and
// there are operand shapes where the escaped text still compiles: a plausible
// verdict about an operand nobody chose.
//
// Output is one tab-separated record per site:
//
//	<line> <kind> <span> <operandCount> <start>:<end>:<joiner>:<quoted text> ...
//
// The text is Go-quoted rather than printed raw. It is a human aid -- the
// offsets are the source of truth -- but an aid that silently differs from the
// file is worse than none, because it is what a reader diffs against. Collapsing
// whitespace rewrote operands that legitimately contain it, such as a comparison
// against a string literal with two spaces in it, and quoting also keeps a
// multi-line operand on one record without inventing a layout for it.
//
// and a SITES=<n> OPERANDS=<n> summary on stderr, so a caller can check the
// totals without parsing the records. The joiner is the operator binding that
// leaf: it says which neutralisation preserves its siblings -- `(false && x)`
// inside an || chain, `(true || x)` inside an && chain. Which of those is the
// SECURITY-relevant direction is a separate question, answered by whether the
// branch admits or refuses, and this tool does not guess at it.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
)

// Leaf is one operand of a boolean expression, as a byte range in the file.
type Leaf struct {
	Start, End int
	// Joiner is the operator binding this leaf to its siblings, "&&" or "||".
	// A leaf standing alone reports "||", the polarity that neutralises it.
	Joiner string
}

// Site is one boolean decision point: an if or for condition, a boolean return,
// or one expression of a case clause in a tag-less switch.
type Site struct {
	Line, EndLine int
	// Kind is "if", "if-init", "for", "return", "case" or "case-init". The -init
	// suffixes mark a decision whose statement binds a name first, which is the
	// shape where a text-matching mutator has to choose between two occurrences
	// of that name on the line -- `if _, ok := m[k]; ok {` and its switch twin
	// `switch _, ok := m[k]; { case ok: }`.
	Kind   string
	Leaves []Leaf
}

// leaves walks a boolean expression to its operands, descending through
// parentheses and through BOTH boolean operators -- not only the one it
// started with -- so that `a && (b || c)` yields three leaves rather than two.
// Each leaf carries the operator that binds IT, which is why the joiner is
// per-leaf rather than per-site: in that example the outer two are bound by &&
// and the inner two by ||, and neutralising a leaf with the wrong one destroys
// its siblings.
//
// Anything that is not itself a && or || is a leaf, however complex: a call, a
// comparison, an index, a negation. `!f(x)` is one leaf, not a window into
// f(x).
func leaves(expression ast.Expr, joiner string, out *[]Leaf) {
	switch node := expression.(type) {
	case *ast.ParenExpr:
		leaves(node.X, joiner, out)
		return
	case *ast.BinaryExpr:
		if node.Op == token.LAND || node.Op == token.LOR {
			inner := node.Op.String()
			leaves(node.X, inner, out)
			leaves(node.Y, inner, out)
			return
		}
	}
	*out = append(*out, Leaf{Start: int(expression.Pos()), End: int(expression.End()), Joiner: joiner})
}

// Sites enumerates every decision point in src. Offsets in the returned leaves
// are relative to src, not to the parser's global position space.
//
// THE ORDER IS THE TRAVERSAL'S, NOT THE FILE'S, and it never was: a switch's
// case sites are all emitted when the switch statement is visited, so they
// precede any `if` or boolean `return` nested inside its arms. Nothing here
// promises source order -- select a site by Line, or by Kind and operand count,
// not by index.
func Sites(filename string, src []byte) ([]Site, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, filename, src, 0)
	if err != nil {
		return nil, err
	}
	base := fileSet.File(file.Pos()).Base()
	var found []Site
	ast.Inspect(file, func(node ast.Node) bool {
		// A node yields a LIST of conditions rather than one, because a single
		// tag-less switch contributes a site per case expression.
		var conditions []ast.Expr
		var kind string
		switch statement := node.(type) {
		case *ast.IfStmt:
			conditions, kind = []ast.Expr{statement.Cond}, "if"
			if statement.Init != nil {
				kind = "if-init"
			}
		case *ast.ForStmt:
			// `for {}` has no condition. Range loops are *ast.RangeStmt and
			// therefore never reach this case.
			if statement.Cond != nil {
				conditions, kind = []ast.Expr{statement.Cond}, "for"
			}
		case *ast.SwitchStmt:
			// A TAG IS WHAT DECIDES THIS, not the shape of the case
			// expressions. With no tag the switch is `switch true`, so every
			// case expression must be boolean and gates its arm by being TRUE
			// -- the same contract as an if condition, and the joiner this tool
			// emits means the same thing.
			//
			// With a tag it is a comparison, and the joiner would be wrong
			// rather than merely absent. `switch ok { case a && b: }` selects
			// its arm when the expression EQUALS ok, so `(false && a)` does not
			// neutralise the clause -- it makes the arm fire whenever ok is
			// false. Enumerating that would hand a mutator a direction that
			// inverts the branch while claiming to preserve its siblings.
			//
			// A type switch is a different node entirely (*ast.TypeSwitchStmt)
			// and so is never reached here; it selects on type for the same
			// reason it is not a boolean decision.
			if statement.Tag != nil {
				return true
			}
			kind = "case"
			if statement.Init != nil {
				kind = "case-init"
			}
			for _, clause := range statement.Body.List {
				caseClause, isCase := clause.(*ast.CaseClause)
				if !isCase {
					continue
				}
				// `default:` has no expressions, so it contributes nothing --
				// it is the absence of a condition, not a condition.
				conditions = append(conditions, caseClause.List...)
			}
		case *ast.ReturnStmt:
			// Only a boolean expression is a decision point. `return x` is a
			// value and `return f(a && b)` is an argument to a call, not a
			// branch, so the operator must be at the top of the result -- but
			// GROUPING PARENTHESES ARE NOT AN OPERATOR. `return (a && b)` is
			// the same decision as `return a && b`, and reading only the outer
			// node would miss it, which is the very shape of defect this tool
			// exists to remove.
			//
			// `return !(a && b)` and `return bool(a && b)` are deliberately NOT
			// sites: the top-level operator is the negation or the conversion,
			// and treating the inner operands as leaves would report a joiner
			// whose polarity is inverted relative to the value returned. That
			// matches how a negated group is handled in an if-condition, where
			// `if !(a && b) {` is one opaque leaf. Neither shape occurs as a
			// boolean return anywhere in this repository.
			if len(statement.Results) == 1 {
				result := statement.Results[0]
				for {
					paren, wrapped := result.(*ast.ParenExpr)
					if !wrapped {
						break
					}
					result = paren.X
				}
				if binary, ok := result.(*ast.BinaryExpr); ok &&
					(binary.Op == token.LAND || binary.Op == token.LOR) {
					conditions, kind = []ast.Expr{result}, "return"
				}
			}
		}
		for _, condition := range conditions {
			var operands []Leaf
			leaves(condition, "||", &operands)
			for i := range operands {
				operands[i].Start -= base
				operands[i].End -= base
			}
			found = append(found, Site{
				Line:    fileSet.Position(condition.Pos()).Line,
				EndLine: fileSet.Position(condition.End()).Line,
				Kind:    kind,
				Leaves:  operands,
			})
		}
		return true
	})
	return found, nil
}

// formatSite renders one record. Each leaf's text is strconv.Quote'd, so it
// reproduces exactly the bytes the offsets select -- whitespace, escapes and all
// -- and contains no literal tab or newline to break the record's own framing.
func formatSite(src []byte, site Site) string {
	span := "1line"
	if site.EndLine != site.Line {
		span = fmt.Sprintf("%dlines", site.EndLine-site.Line+1)
	}
	fields := make([]string, 0, len(site.Leaves))
	for _, leaf := range site.Leaves {
		fields = append(fields, fmt.Sprintf("%d:%d:%s:%s", leaf.Start, leaf.End, leaf.Joiner,
			strconv.Quote(string(src[leaf.Start:leaf.End]))))
	}
	return fmt.Sprintf("%d\t%s\t%s\t%d\t%s", site.Line, site.Kind, span, len(site.Leaves),
		strings.Join(fields, "\t"))
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: guardenum <file.go>")
		os.Exit(2)
	}
	src, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sites, err := Sites(os.Args[1], src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		os.Exit(1)
	}
	operands := 0
	for _, site := range sites {
		operands += len(site.Leaves)
		fmt.Println(formatSite(src, site))
	}
	fmt.Fprintf(os.Stderr, "SITES=%d OPERANDS=%d\n", len(sites), operands)
}
