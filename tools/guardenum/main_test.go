package main

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// The fixture carries every shape the regex enumerators missed, in the layouts
// that hid them, plus the near-misses that must NOT be counted. It is a string
// rather than a testdata file so that the shape and its expected operand count
// are readable side by side.
//
// THE CASE-CLAUSE SHAPES ARE IN SEPARATE FIXTURES BELOW, deliberately. Every
// test in this file that asserts a total would fail if case clauses stopped
// being enumerated, so folding them in here would leave no mutation with a sole
// detector — and a test that is never the sole failure names nothing. Splitting
// the fixtures buys one: each of the four case-clause behaviours has exactly one
// test that goes red when it alone is broken. The mutation-to-detector matrix is
// recorded above TestTaglessSwitchCaseClausesAreEnumerated.
//
// It also keeps this fixture's counts untouched by the change that added the new
// kind, which is the same inertness the tool's own output was checked for.
const fixture = `package sample

func plain(err error) bool {
	if err != nil {                                    // 1 operand
		return false
	}
	return true
}

func multiLine(a, b, c, d bool) bool {
	if a ||
		b ||
		c || d {                                       // 4 operands, 3 lines
		return false
	}
	return true
}

func withInit(m map[string]int, k string) bool {
	if _, ok := m[k]; ok {                             // 1 operand; "ok" twice on the line
		return true
	}
	return false
}

func boolReturn(a, b bool) bool {
	return a && b                                      // 2 operands
}

func multiLineBoolReturn(a, b, c bool) bool {
	return a &&
		b && c                                         // 3 operands, 2 lines
}

func nested(a, b, c, d bool) bool {
	if a && (b || c) && d {                            // 4 operands, parens descended
		return true
	}
	return false
}

func parenthesisedReturn(a, b bool) bool {
	return (a && b)                                    // 2 operands: parens group, they do not gate
}

func whitespaceOperands(x string) bool {
	return x == "a  b" && x != "\tc"                   // 2 operands carrying meaningful whitespace
}

func notDecisions(a, b bool, n int) bool {
	if n > 0 {                                         // 1 operand
		_ = a
	}
	return use(a && b)                                 // NOT a site: an argument
}

func plainReturn(a bool) bool { return a }             // NOT a site: no operator

func negatedReturn(a, b bool) bool { return !(a && b) } // NOT a site: ! is the top-level operator

func convertedReturn(a, b bool) bool { return bool(a && b) } // NOT a site: a conversion

func use(bool) bool { return true }
`

// Loop conditions have their own fixture so removing their enumerator has one
// detector, not every pre-existing total in this file. The body is never run;
// Sites parses it. The infinite and range forms are controls: neither has a
// boolean for-clause condition to neutralise.
const forClauseFixture = `package sample

func loops(a, b, c bool, n int) {
	for a {}
	for a && b {}
	for i := 0; i < n &&
		(a || b || c); i++ {}
	for {}
	for range []int{} {}
}
`

func TestForClauseConditionsAreEnumerated(t *testing.T) {
	sites, err := Sites("loops.go", []byte(forClauseFixture))
	if err != nil {
		t.Fatalf("loop fixture does not parse, so it measures nothing: %v", err)
	}

	type loop struct {
		kind     string
		operands int
		lines    int
		text     string
		joiners  string
	}
	got := make([]loop, 0, len(sites))
	for _, site := range sites {
		var texts, joiners []string
		for _, leaf := range site.Leaves {
			texts = append(texts, forClauseFixture[leaf.Start:leaf.End])
			joiners = append(joiners, leaf.Joiner)
		}
		got = append(got, loop{
			kind:     site.Kind,
			operands: len(site.Leaves),
			lines:    site.EndLine - site.Line + 1,
			text:     strings.Join(texts, " | "),
			joiners:  strings.Join(joiners, " "),
		})
	}
	want := []loop{
		{kind: "for", operands: 1, lines: 1, text: "a", joiners: "||"},
		{kind: "for", operands: 2, lines: 1, text: "a | b", joiners: "&& &&"},
		{kind: "for", operands: 4, lines: 2, text: "i < n | a | b | c", joiners: "&& || || ||"},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("for-clause enumeration is\n  %v\nwant\n  %v\nA missing entry leaves a loop's "+
			"exit decision outside every operand denominator; an extra entry treats an infinite or "+
			"range loop as though it had a boolean clause", got, want)
	}
}

func TestEveryShapeIsEnumerated(t *testing.T) {
	sites, err := Sites("sample.go", []byte(fixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}

	// Keyed by kind and operand count rather than by line, so inserting a
	// comment in the fixture does not rewrite every expectation.
	type shape struct {
		kind     string
		operands int
		lines    int
	}
	got := make([]shape, 0, len(sites))
	for _, site := range sites {
		got = append(got, shape{site.Kind, len(site.Leaves), site.EndLine - site.Line + 1})
	}
	want := []shape{
		{"if", 1, 1},      // plain
		{"if", 4, 3},      // multi-line if -- MISSED by a single-line pattern
		{"if-init", 1, 1}, // if-init -- the bound name appears twice on the line
		{"return", 2, 1},  // boolean return -- MISSED
		{"return", 3, 2},  // multi-line boolean return -- MISSED
		{"if", 4, 1},      // parenthesised sub-expression descended into
		{"return", 2, 1},  // return (a && b) -- grouping parens are not an operator
		{"return", 2, 1},  // operands whose text carries whitespace that must not be rewritten
		{"if", 1, 1},      // notDecisions' n > 0
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("enumeration is\n  %v\nwant\n  %v\nA missing entry is the defect this tool exists "+
			"to remove: every count it produces is the denominator of a coverage claim", got, want)
	}
}

// A leaf's offsets must select exactly its own source text. This is the property
// that lets a mutator slice instead of matching text, and it is the reason the
// if-init shape is safe: "ok" appears twice on that line and only one of them is
// the operand.
func TestLeafOffsetsSelectTheOperandText(t *testing.T) {
	sites, err := Sites("sample.go", []byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, site := range sites {
		for _, leaf := range site.Leaves {
			if leaf.Start < 0 || leaf.End > len(fixture) || leaf.Start >= leaf.End {
				t.Fatalf("line %d: offsets [%d:%d] are not a range inside a %d-byte file",
					site.Line, leaf.Start, leaf.End, len(fixture))
			}
			text := fixture[leaf.Start:leaf.End]
			if strings.HasPrefix(text, " ") || strings.HasSuffix(text, " ") {
				t.Fatalf("line %d: operand text %q carries SURROUNDING whitespace, so a mutation "+
					"replacing it would disturb the layout it did not intend to. Whitespace INSIDE "+
					"an operand is legitimate -- a string literal may contain it -- and is what the "+
					"round-trip assertion below protects", site.Line, text)
			}
			checked++
		}
	}
	if checked != 20 {
		t.Fatalf("checked %d operands, want 20 — the fixture or the enumerator changed and this "+
			"assertion is no longer covering what it claims", checked)
	}

	// The if-init site specifically: its operand is the SECOND "ok" on the line.
	for _, site := range sites {
		if site.Kind != "if-init" {
			continue
		}
		if text := fixture[site.Leaves[0].Start:site.Leaves[0].End]; text != "ok" {
			t.Fatalf("if-init operand selected %q, want %q", text, "ok")
		}
		if before := strings.Count(fixture[:site.Leaves[0].Start], "ok"); before != 1 {
			t.Fatalf("the if-init operand is occurrence %d of \"ok\", so a text-matching mutator "+
				"would have to choose; offsets are what remove the choice", before+1)
		}
	}
}

// The joiner says which neutralisation preserves a leaf's siblings. Getting it
// backwards destroys the whole predicate and blames whichever test notices.
func TestJoinerReportsTheBindingOperator(t *testing.T) {
	sites, err := Sites("sample.go", []byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range sites {
		for _, leaf := range site.Leaves {
			if leaf.Joiner != "&&" && leaf.Joiner != "||" {
				t.Fatalf("line %d: joiner %q is neither operator", site.Line, leaf.Joiner)
			}
		}
	}
	// nested: a && (b || c) && d -- the inner two are bound by ||, the outer by &&.
	for _, site := range sites {
		if len(site.Leaves) != 4 || site.Kind != "if" || site.EndLine != site.Line {
			continue
		}
		var joiners []string
		for _, leaf := range site.Leaves {
			joiners = append(joiners, leaf.Joiner)
		}
		if want := "&& || || &&"; strings.Join(joiners, " ") != want {
			t.Fatalf("joiners for a && (b || c) && d are %q, want %q — a leaf inside the "+
				"parenthesised group is bound by ||, not by the outer &&",
				strings.Join(joiners, " "), want)
		}
	}
}

// The printed text must reproduce EXACTLY the bytes the offsets select. It is a
// human aid and the offsets are the source of truth, but an aid that silently
// differs from the file is worse than none: it is what a reader diffs against,
// and what a reviewer checks an offset against when the two disagree.
//
// This previously collapsed runs of whitespace, so an operand comparing against
// a literal with two spaces in it printed as though it had one, and a multi-line
// operand printed with its layout invented rather than preserved.
//
// WHAT MAKES THIS CHECK STRICT IS strconv.Unquote, not the fixture. It rejects a
// field that is not a complete, well-formed Go string literal, so a change from
// %q to raw text -- or to a quoter that does not escape inner quotes -- fails
// here whatever the operands contain. That is why the fixture's string-literal
// operands are documentation rather than a gate, and it is also the condition:
// loosen this to a prefix or substring comparison and the escaping becomes
// invisible again, at which point those operands would be the only thing
// catching it.
func TestPrintedOperandTextRoundTripsToTheSelectedBytes(t *testing.T) {
	sites, err := Sites("sample.go", []byte(fixture))
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	for _, site := range sites {
		record := formatSite([]byte(fixture), site)
		if strings.Count(record, "\t") != 4+len(site.Leaves)-1 {
			t.Fatalf("line %d: record has %d tabs, want %d — a literal tab inside an operand would "+
				"break the record's own framing, which is why the text is quoted",
				site.Line, strings.Count(record, "\t"), 4+len(site.Leaves)-1)
		}
		for index, field := range strings.Split(record, "\t")[4:] {
			leaf := site.Leaves[index]
			quoted := field[strings.Index(field, `"`):]
			got, err := strconv.Unquote(quoted)
			if err != nil {
				t.Fatalf("line %d operand %d: emitted text %s does not unquote: %v",
					site.Line, index, quoted, err)
			}
			if want := fixture[leaf.Start:leaf.End]; got != want {
				t.Fatalf("line %d operand %d: printed text %q, but offsets [%d:%d] select %q — the "+
					"record disagrees with the file it points at",
					site.Line, index, got, leaf.Start, leaf.End, want)
			}
			checked++
		}
	}
	if checked != 20 {
		t.Fatalf("round-tripped %d operands, want 20", checked)
	}
}

// A file with non-ASCII text before its guards. Em-dashes are ordinary in this
// repository's comments, and each is three bytes and one code point, so every
// offset after one differs depending on how a consumer slices.
const wideFixture = `package sample

// A comment with an em-dash — and another — before anything interesting.
func f(a, b bool) bool {
	if a || b {
		return true
	}
	return false
}

// Operands carrying string literals, so the %q escaping of the text field is
// exercised. guardenum emits the first of these as the field
//
//	"name == \"\""
//
// -- outer quotes delimiting the literal, inner quotes escaped -- while the bytes
// at its offsets are name == "". A consumer comparing the field to the source
// without decoding sees those differ, which is the second trap documented in
// main.go and is why the text must be strconv.Unquote'd before it is a check.
func g(name, kind string) bool {
	if name == "" || kind != "x" {
		return false
	}
	return true
}
`

// TestOffsetsAreByteOffsetsNotCharacterOffsets pins the property every non-Go
// consumer depends on and no other test here would catch.
//
// Python and Ruby index strings by code point; JavaScript indexes by UTF-16 code
// unit. The two agree below U+FFFF and differ above it, but both differ from
// bytes, so a consumer in any of them that reads the file as text and slices at
// these offsets mis-addresses every operand after the first non-ASCII byte.
//
// The fixture uses em-dashes, which are BMP, so it simulates the code-point
// model exactly and the UTF-16 model incidentally: for this input they are the
// same number. What it separates is either of those from BYTES, which is the
// distinction under test.
//
// The failure it guards against is quiet rather than loud. A shifted span is
// often still valid Go, so the mutation compiles and the run produces a
// plausible verdict about an operand nobody chose.
//
// This asserts both halves -- that byte slicing selects the operand, AND that
// code-point slicing does not -- because only the second fails if the tool ever
// switches to rune offsets.
//
// THAT IS NOT A HYPOTHETICAL AND NO OTHER TEST HERE COVERS IT. Converting the
// normalisation step to rune offsets was measured against the whole file:
// TestLeafOffsetsSelectTheOperandText and
// TestPrintedOperandTextRoundTripsToTheSelectedBytes both PASS, because their
// fixtures are pure ASCII and rune offsets equal byte offsets there. Every other
// test agrees with the broken tool. The property is invisible to any fixture
// without a multi-byte character, and before this one every fixture in the file
// was such a fixture.
func TestOffsetsAreByteOffsetsNotCharacterOffsets(t *testing.T) {
	sites, err := Sites("wide.go", []byte(wideFixture))
	if err != nil {
		t.Fatal(err)
	}
	// Select by LINE, not by index and not by operand text. Sites documents no
	// ordering guarantee -- it falls out of ast.Inspect's traversal today -- so an
	// index would fail confusingly if that changed.
	//
	// Operand text would be WORSE than an index, which is the trap worth recording:
	// reading it means slicing the fixture, and slicing is the very thing under test.
	// A selector built that way breaks in exactly the case this test exists to catch,
	// and reports it as "the fixture has no such guard" -- naming a broken fixture
	// instead of a broken tool. Line numbers come from token positions and are
	// unaffected by how offsets are normalised.
	const guard = "\tif a || b {"
	line := 0
	for index, text := range strings.Split(wideFixture, "\n") {
		if text == guard {
			line = index + 1
			break
		}
	}
	if line == 0 {
		t.Fatalf("fixture no longer contains %q, so the selector cannot find the guard", guard)
	}
	var target *Site
	for i := range sites {
		if sites[i].Line == line {
			target = &sites[i]
		}
	}
	if target == nil || len(target.Leaves) != 2 {
		t.Fatalf("want a site with 2 operands at line %d; found %v among %d sites",
			line, target, len(sites))
	}
	runes := []rune(wideFixture)
	if len(runes) == len(wideFixture) {
		t.Fatal("fixture is pure ASCII, so it cannot distinguish byte from character offsets")
	}
	// Every non-ASCII character here is BMP, so the code-point count below is also the
	// UTF-16 count. Asserting it keeps the comment above true if the fixture ever gains
	// an astral character, which would make the two models diverge.
	utf16 := 0
	for _, r := range wideFixture {
		utf16++
		if r > 0xFFFF {
			utf16++
		}
	}
	if utf16 != len(runes) {
		t.Fatalf("fixture has %d UTF-16 units against %d code points, so it no longer simulates "+
			"one model; the comment above claims they coincide", utf16, len(runes))
	}

	for index, want := range []string{"a", "b"} {
		leaf := target.Leaves[index]
		if got := wideFixture[leaf.Start:leaf.End]; got != want {
			t.Fatalf("operand %d sliced as BYTES is %q, want %q — the offsets do not address the "+
				"file the way Go indexes it", index, got, want)
		}
		if got := string(runes[leaf.Start:leaf.End]); got == want {
			t.Fatalf("operand %d sliced as CODE POINTS also gives %q, so this fixture cannot tell "+
				"the two addressings apart and the assertion above proves nothing", index, got)
		}
	}
}

// A CASE CLAUSE OF A TAG-LESS SWITCH is a boolean branch with neither keyword,
// and it was invisible to this tool until #237. The shapes here mirror the real
// ones: server.health's router compares a request path against string literals,
// so the %q escaping of the text field is exercised by the new kind and not only
// by the old ones.
//
// The em-dash in the comment is load-bearing. It puts a multi-byte character
// BEFORE every operand below, so the offsets these tests slice with are byte
// offsets or they are wrong — the same property
// TestOffsetsAreByteOffsetsNotCharacterOffsets pins for `if`, now pinned for a kind that reaches the same
// normalisation by a different path.
const caseFixture = `package sample

// A router — one decision per arm, and no keyword on any of them.
func route(path string, ready, live bool, err error, n int) int {
	switch {
	case path == "/v1/health/live" || path == "/v1/health/ready":
		return 1
	case err != nil:
		return 2
	case ready &&
		live:
		return 3
	case (n > 0 || n < -1) && ready:
		return 4
	default:
		return 0
	}
}

func nestedInsideAnArm(a, b bool) int {
	switch {
	case a:
		if a && b {
			return 1
		}
	}
	return 0
}
`

// TestTaglessSwitchCaseClausesAreEnumerated is the sole detector for the kind
// label and for the shape of what a case clause contributes.
//
// MUTATION MATRIX for the case-clause enumeration, each verified to produce
// exactly one failing test:
//
//	kind = "case"                       -> "if"            this test, alone
//	caseClause.List...                  -> List[:1]        TestEachExpressionInACaseClauseIsItsOwnSite, alone
//	kind = "case-init" assignment       -> removed         TestACaseClauseWithAnInitStatementIsCaseInit, alone
//	if statement.Tag != nil { return }  -> removed         TestATaggedSwitchIsNotABooleanDecisionPoint, alone
//
// Deleting the whole *ast.SwitchStmt arm reds three of those four at once. That
// is the feature being removed rather than a defect inside it, and no fixture
// split can isolate it: any test that asserts a case site exists must fail when
// none does.
func TestTaglessSwitchCaseClausesAreEnumerated(t *testing.T) {
	sites, err := Sites("case.go", []byte(caseFixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	type shape struct {
		kind     string
		operands int
		lines    int
	}
	got := make([]shape, 0, len(sites))
	for _, site := range sites {
		got = append(got, shape{site.Kind, len(site.Leaves), site.EndLine - site.Line + 1})
	}
	want := []shape{
		{"case", 2, 1}, // two path comparisons joined by ||
		{"case", 1, 1}, // err != nil -- the shape that hid in cmd/regalia-kms
		{"case", 2, 2}, // a case condition written across two lines
		{"case", 3, 1}, // parenthesised sub-expression descended into
		{"case", 1, 1}, // nestedInsideAnArm's own case
		{"if", 2, 1},   // the if INSIDE an arm is still an if, not a case
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("enumeration of tag-less case clauses is\n  %v\nwant\n  %v\nA case clause of a "+
			"switch with no tag is a boolean decision point with neither an `if` nor a `return` "+
			"keyword; a tool that does not report it makes every coverage count derived from it "+
			"an overstatement", got, want)
	}

	// The offsets must select the operand, and they must do so as BYTES. The
	// fixture's em-dash is what separates the two addressings.
	if runes := []rune(caseFixture); len(runes) == len(caseFixture) {
		t.Fatal("fixture is pure ASCII, so it cannot distinguish byte from character offsets")
	}
	wantText := []string{
		`path == "/v1/health/live"`, `path == "/v1/health/ready"`,
		"err != nil",
		"ready", "live",
		"n > 0", "n < -1", "ready",
		"a",
		"a", "b",
	}
	var texts []string
	for _, site := range sites {
		for _, leaf := range site.Leaves {
			texts = append(texts, caseFixture[leaf.Start:leaf.End])
		}
	}
	if fmt.Sprint(texts) != fmt.Sprint(wantText) {
		t.Fatalf("operands sliced as BYTES are\n  %q\nwant\n  %q\nthe offsets do not address the "+
			"file the way Go indexes it", texts, wantText)
	}
	runes := []rune(caseFixture)
	first := sites[0].Leaves[0]
	if string(runes[first.Start:first.End]) == wantText[0] {
		t.Fatalf("the first operand sliced as CODE POINTS also gives %q, so this fixture cannot "+
			"tell the two addressings apart and the assertion above proves nothing", wantText[0])
	}

	// And the text field of a case record is %q-quoted like every other, which
	// is only visible on an operand containing a quote of its own.
	record := formatSite([]byte(caseFixture), sites[0])
	field := strings.Split(record, "\t")[4]
	quoted := field[strings.Index(field, `"`):]
	decoded, err := strconv.Unquote(quoted)
	if err != nil {
		t.Fatalf("case record's text field %s does not unquote: %v — a consumer that decodes "+
			"before comparing, as #343 requires, cannot read this record at all", quoted, err)
	}
	if decoded != wantText[0] {
		t.Fatalf("case record's text field decodes to %q, want %q", decoded, wantText[0])
	}
	if quoted == wantText[0] {
		t.Fatal("the text field is not escaped, so this assertion would pass on a raw-text " +
			"emitter and the escaping documented in #343 has stopped being checked here")
	}
}

// A case clause may list several expressions. Each is its OWN site.
//
// The clause fires if any one of them holds, so they compose exactly as || does
// — which a per-expression site already says, because a leaf standing alone
// reports the || joiner and (false && a) leaves b still gating the arm. One site
// carrying both would also have to invent a Line..EndLine span over text that is
// not a single expression.
const multiExpressionCaseFixture = `package sample

func multi(a, b, c bool) int {
	switch {
	case a, b || c:
		return 1
	}
	return 0
}
`

func TestEachExpressionInACaseClauseIsItsOwnSite(t *testing.T) {
	sites, err := Sites("multi.go", []byte(multiExpressionCaseFixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	if len(sites) != 2 {
		t.Fatalf("`case a, b || c:` produced %d sites, want 2 — each expression in a case list is "+
			"an independent boolean decision, and collapsing them loses one of them from every "+
			"count derived from this tool", len(sites))
	}
	var operands []int
	var joiners []string
	for _, site := range sites {
		operands = append(operands, len(site.Leaves))
		for _, leaf := range site.Leaves {
			joiners = append(joiners, leaf.Joiner)
		}
	}
	if fmt.Sprint(operands) != fmt.Sprint([]int{1, 2}) {
		t.Fatalf("operand counts are %v, want [1 2]", operands)
	}
	// Every leaf here is bound by ||: the two expressions relate to each other
	// as a disjunction, and so do the operands inside the second one. Getting
	// this wrong tells a mutator to widen where it should narrow, which
	// destroys the sibling it claimed to preserve.
	if want := "|| || ||"; strings.Join(joiners, " ") != want {
		t.Fatalf("joiners are %q, want %q — a case expression standing beside another is "+
			"neutralised by (false && x), the same as a leaf inside an || chain",
			strings.Join(joiners, " "), want)
	}
}

// A tag-less switch may bind a name first, exactly as an `if` may, and the kind
// says so for the same reason: the bound name occurs again in the case
// expression, so a mutator matching on text has two occurrences to choose
// between and the offsets are what remove the choice.
const caseInitFixture = `package sample

func present(m map[string]bool, k string) int {
	switch _, ok := m[k]; {
	case ok:
		return 1
	}
	return 0
}
`

func TestACaseClauseWithAnInitStatementIsCaseInit(t *testing.T) {
	sites, err := Sites("caseinit.go", []byte(caseInitFixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	if len(sites) != 1 || sites[0].Kind != "case-init" {
		var kinds []string
		for _, site := range sites {
			kinds = append(kinds, site.Kind)
		}
		t.Fatalf("kinds are %v, want exactly [case-init] — a tag-less switch that binds a name "+
			"first is the switch twin of `if _, ok := m[k]; ok {`, and labelling it plain \"case\" "+
			"hides from a reader the one property the label exists to carry", kinds)
	}
	leaf := sites[0].Leaves[0]
	if text := caseInitFixture[leaf.Start:leaf.End]; text != "ok" {
		t.Fatalf("case-init operand selected %q, want %q", text, "ok")
	}
	if before := strings.Count(caseInitFixture[:leaf.Start], "ok"); before != 1 {
		t.Fatalf("the case-init operand is occurrence %d of \"ok\", so a text-matching mutator "+
			"would have to choose; offsets are what remove the choice", before+1)
	}
}

// A TAGGED switch is not a boolean decision point, and the distinction is the
// tag, not the shape of the case expressions. Every expression below is
// boolean-valued and none of them gates its arm by being TRUE: each is compared
// against the tag.
//
// The middle switch is the trap, and it is why "the expression looks boolean" is
// not a usable test. `switch a { case a && b: }` selects its arm when a && b
// EQUALS a, so the neutralisation this tool's joiner promises — (false && a),
// which should make the arm unreachable — instead makes it fire whenever a is
// false. A record for that clause would not be merely surplus; it would send a
// mutator in the inverting direction while claiming to preserve the siblings.
//
// WHAT THIS TEST CANNOT DETECT, so that no one mistakes it for a wider gate: it
// asserts an exclusion, so it passes just as happily on a tool that enumerates
// no case clause at all. Under-enumeration is
// TestTaglessSwitchCaseClausesAreEnumerated's job. What makes this one non-vacuous is the type-switch arm's
// `if v && b`, which must be found: the fixture is demonstrably being read, so
// zero case sites is an exclusion rather than a silent no-op.
const taggedFixture = `package sample

func tagged(state string, a, b bool) int {
	switch state {
	case "ready":
		return 1
	case "draining", "stopped":
		return 2
	}
	switch a {
	case a && b:
		return 3
	}
	switch x := b; x {
	case a || b:
		return 4
	}
	switch v := any(a).(type) {
	case bool:
		if v && b {
			return 5
		}
	}
	return 0
}
`

func TestATaggedSwitchIsNotABooleanDecisionPoint(t *testing.T) {
	sites, err := Sites("tagged.go", []byte(taggedFixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	for _, site := range sites {
		if strings.HasPrefix(site.Kind, "case") {
			var texts []string
			for _, leaf := range site.Leaves {
				texts = append(texts, taggedFixture[leaf.Start:leaf.End])
			}
			t.Fatalf("line %d: a case clause of a TAGGED switch was enumerated as %q with operands "+
				"%q. Its expression is compared against the tag, not against truth, so the joiner "+
				"reported here is wrong rather than merely surplus: (false && x) does not make the "+
				"arm unreachable, it makes it fire whenever the tag is false. Every count derived "+
				"from this tool also inflates", site.Line, site.Kind, texts)
		}
	}
	// Non-vacuity: the fixture is read, and the one real decision in it is found.
	if len(sites) != 1 || sites[0].Kind != "if" || len(sites[0].Leaves) != 2 {
		t.Fatalf("want exactly one site, an `if` with 2 operands, from the type-switch arm; got "+
			"%d sites %v — without it, zero case sites would be indistinguishable from a tool "+
			"that never read the fixture", len(sites), sites)
	}
}
