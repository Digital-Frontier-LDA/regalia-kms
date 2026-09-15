package main

// THE OUTPUT CONTRACT (#237), and the operands that live in main().
//
// Sites() and formatSite() are tested thoroughly next door. main() was not tested at all, and
// main() is where the contract every ledger on #237 parses actually lives: records on STDOUT, the
// SITES=/OPERANDS= summary on STDERR, tab-separated fields, one record per line, a non-zero exit
// when the tool cannot answer. None of that is reachable from a unit test of Sites, and none of
// it is a boolean operand, so neither the operand sweep nor the existing tests could ask about it.
//
// Swept: 13 sites / 16 operands / 32 operand-directions, plus 8 statement-level mutations of the
// output path. Survivors and their verdicts:
//
//	err != nil after parser.ParseFile      covered here — a file that is not Go must exit non-zero
//	!isCase                                unreachable — a switch body holds only case clauses
//	len(statement.Results) == 1  (widened) covered here — a multi-result return is not a site
//	binary.Op == token.LAND      (widened) covered here — `return a == b` is not a site
//	binary.Op == token.LOR       (both)    covered here — `return a || b` IS a site
//	site.EndLine != site.Line    (both)    covered here — the span field
//	len(os.Args) != 2            (both)    covered here — the usage guard
//	err != nil after os.ReadFile (both)    covered here — an unreadable file
//	err != nil after Sites       (both)    covered here — a file that is not Go
//	records printed to stderr              covered here
//	summary printed to stdout              covered here
//	operands += 1 instead of len(Leaves)   covered here
//	os.Exit(0) on a usage error            covered here
//	span always "1line"                    covered here
//
// WHY THIS BUILDS AND RUNS THE REAL BINARY rather than refactoring main() into a testable
// run(args, stdout, stderr) function. The contract under test IS the process's behaviour --
// which stream a byte lands on and what the exit status is -- and a refactored stand-in would
// let those two diverge from what a consumer actually invokes. A path is not an identity: the
// binary this test asserts about is the one it just built from this package's source, in its own
// temporary directory, so no other agent's stale build can answer for it.
//
// os/exec is imported deliberately and does not cross internal/boundary_test.go's no-shelling-out
// rule, which walks non-test files only: nothing in the shipped tool gains the ability to invoke
// anything.

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// buildGuardenum compiles this package into a fresh binary and returns its path.
func buildGuardenum(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "guardenum")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=auto")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the enumerator failed (%v):\n%s\nEvery ledger on #237 was produced by "+
			"running this binary, so a build failure here is not a test-environment problem to skip "+
			"past — it is the tool being unbuildable", err, output)
	}
	return binary
}

// runGuardenum runs the binary and returns its two streams SEPARATELY, which is the whole point:
// combining them would make "the summary went to stdout" invisible.
func runGuardenum(t *testing.T, binary string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	command := exec.Command(binary, args...)
	var out, errs strings.Builder
	command.Stdout, command.Stderr = &out, &errs
	err := command.Run()
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("running %s %v: %v", binary, args, err)
		}
		code = exit.ExitCode()
	}
	return out.String(), errs.String(), code
}

// contractFixture is a file of its own, not the shared one next door. That file's header explains
// why: every test there asserts a total, so folding a new shape into it leaves no mutation with a
// sole detector. The same reasoning applies to a fixture whose records this file counts.
//
// It carries a one-line guard and a two-line guard so the span field has both answers to give,
// and one guard with three operands so OPERANDS cannot be mistaken for a count of sites.
const contractFixture = `package sample

func oneLine(a, b, c bool) bool {
	if a || b || c {
		return true
	}
	return false
}

func twoLines(a, b bool) bool {
	if a &&
		b {
		return true
	}
	return false
}
`

type record struct {
	line     int
	kind     string
	span     string
	operands int
	fields   []string
}

// parseRecords reads stdout the way every consumer on #237 does, and fails on anything it cannot
// read rather than skipping it -- a consumer that silently drops an unparseable record reports
// better coverage than it measured.
func parseRecords(t *testing.T, stdout string) []record {
	t.Helper()
	var records []record
	for _, text := range strings.Split(strings.TrimRight(stdout, "\n"), "\n") {
		if text == "" {
			continue
		}
		fields := strings.Split(text, "\t")
		if len(fields) < 5 {
			t.Fatalf("record %q splits into %d tab-separated fields, want at least 5 (line, kind, "+
				"span, operand count, and one operand) — the tab is the only thing framing this "+
				"record, and an operand's %%q text may contain spaces", text, len(fields))
		}
		line, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("record %q does not begin with a line number: %v", text, err)
		}
		count, err := strconv.Atoi(fields[3])
		if err != nil {
			t.Fatalf("record %q has a non-numeric operand count: %v", text, err)
		}
		records = append(records, record{line: line, kind: fields[1], span: fields[2],
			operands: count, fields: fields[4:]})
	}
	return records
}

func writeContractFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.go")
	if err := os.WriteFile(path, []byte(contractFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheEnumeratorsOutputContract(t *testing.T) {
	binary := buildGuardenum(t)
	fixture := writeContractFixture(t)

	t.Run("site records are written to stdout", func(t *testing.T) {
		stdout, _, code := runGuardenum(t, binary, fixture)
		if code != 0 {
			t.Fatalf("enumerating a well-formed file exited %d", code)
		}
		records := parseRecords(t, stdout)
		if len(records) != 2 {
			t.Fatalf("stdout carried %d records, want 2 — the records are what every consumer "+
				"parses, and a tool that writes them anywhere else hands each of them an empty "+
				"enumeration that looks exactly like a file with no guards in it", len(records))
		}
	})

	t.Run("the summary is written to stderr and nowhere else", func(t *testing.T) {
		stdout, stderr, _ := runGuardenum(t, binary, fixture)
		if strings.TrimRight(stderr, "\n") != fmt.Sprintf("SITES=%d OPERANDS=%d", 2, 5) {
			t.Fatalf("stderr is %q, want the SITES/OPERANDS summary and nothing else — a caller "+
				"checks the totals without parsing the records, and anything else on this stream "+
				"is read as part of them", stderr)
		}
		if strings.Contains(stdout, "SITES=") {
			t.Fatalf("the summary appeared on stdout:\n%s\nA consumer splitting stdout into records "+
				"then parses 'SITES=2 OPERANDS=5' as a site line, whose first field is not a number", stdout)
		}
	})

	t.Run("OPERANDS counts leaves and SITES counts sites", func(t *testing.T) {
		stdout, stderr, _ := runGuardenum(t, binary, fixture)
		records := parseRecords(t, stdout)
		leaves := 0
		for _, record := range records {
			leaves += record.operands
			if record.operands != len(record.fields) {
				t.Fatalf("record at line %d declares %d operands and carries %d fields",
					record.line, record.operands, len(record.fields))
			}
		}
		want := fmt.Sprintf("SITES=%d OPERANDS=%d", len(records), leaves)
		if strings.TrimRight(stderr, "\n") != want {
			t.Fatalf("summary is %q, want %q — the operand total is the denominator of every "+
				"coverage claim derived from this tool, and a total that counts sites instead "+
				"understates it wherever a guard has more than one leaf", stderr, want)
		}
		if leaves == len(records) {
			t.Fatalf("the fixture has one operand per site, so this assertion cannot tell the two "+
				"totals apart: %d records, %d leaves", len(records), leaves)
		}
	})

	t.Run("the span field says how many lines the guard spans", func(t *testing.T) {
		stdout, _, _ := runGuardenum(t, binary, fixture)
		records := parseRecords(t, stdout)
		var spans []string
		for _, record := range records {
			spans = append(spans, record.span)
		}
		if want := []string{"1line", "2lines"}; fmt.Sprint(spans) != fmt.Sprint(want) {
			t.Fatalf("spans are %v, want %v — a multi-line guard reported as a one-line one sends "+
				"a reader checking a record against the file to the wrong text, which is the exact "+
				"failure the offsets exist to prevent and the span exists to make visible", spans, want)
		}
	})

	t.Run("no argument is a usage error", func(t *testing.T) {
		stdout, stderr, code := runGuardenum(t, binary)
		if code == 0 {
			t.Fatalf("running with no file exited 0 with stdout %q — a caller whose argument "+
				"expansion produced nothing gets a clean exit and an empty enumeration, which is "+
				"indistinguishable from a file with no guards", stdout)
		}
		if !strings.Contains(stderr, "usage") {
			t.Fatalf("running with no file said %q, which does not tell the caller how to invoke it", stderr)
		}
	})

	t.Run("too many arguments is a usage error", func(t *testing.T) {
		_, stderr, code := runGuardenum(t, binary, fixture, fixture)
		if code == 0 {
			t.Fatal("running with two files exited 0 — the second file is silently ignored, so a " +
				"caller sweeping a list enumerates the first and reports the whole list")
		}
		if !strings.Contains(stderr, "usage") {
			t.Fatalf("running with two files said %q", stderr)
		}
	})

	t.Run("a file that cannot be read is an error", func(t *testing.T) {
		absent := filepath.Join(t.TempDir(), "not-there.go")
		stdout, stderr, code := runGuardenum(t, binary, absent)
		if code == 0 {
			t.Fatalf("enumerating a file that does not exist exited 0 with stdout %q — a mistyped "+
				"path then reports zero guards, and a sweep records the package as having none", stdout)
		}
		if stderr == "" {
			t.Fatal("a missing file produced no diagnostic at all")
		}
		// AND IT MUST NOT BE REPORTED AS A PARSE ERROR. Without the ReadFile guard the nil
		// contents reach go/parser, which -- given nil source -- opens the named file itself,
		// fails for the same reason, and the tool exits non-zero anyway. Measured: the exit
		// status alone cannot tell the two apart, and the sentence can. "This file is not Go"
		// and "this file is not there" send a caller to different places, and only the second
		// is a reason to check the path they passed.
		if strings.Contains(stderr, "parse error") {
			t.Fatalf("a file that does not exist was reported as %q — that is the diagnosis for a "+
				"file whose CONTENTS are not Go, and it sends a caller to inspect a file they "+
				"never wrote", strings.TrimSpace(stderr))
		}
	})

	t.Run("a file that is not Go is an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "broken.go")
		if err := os.WriteFile(path, []byte("package sample\n\nfunc f( {\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, stderr, code := runGuardenum(t, binary, path)
		if code == 0 {
			t.Fatalf("enumerating a file that does not parse exited 0 with stdout %q — a partial "+
				"parse enumerates whatever it managed to read, and the sweep that follows reports "+
				"full coverage of a file it never saw", stdout)
		}
		if !strings.Contains(stderr, "parse error") {
			t.Fatalf("an unparseable file was reported as %q, which does not name the cause", stderr)
		}
	})
}

// A CASE CLAUSE IS THE ONLY THING A TAG-LESS SWITCH BODY HOLDS.
//
// `if !isCase { continue }` reads like a guard and is unreachable: go/parser only ever puts
// *ast.CaseClause into a SwitchStmt's Body.List, so the type assertion above it cannot fail.
// TESTING.md §17 -- the row states the property and checks it, so the claim fails if the parser
// ever stops holding it rather than being an assertion nobody can re-derive.
func TestATaglessSwitchBodyHoldsOnlyCaseClauses(t *testing.T) {
	const fixture = `package sample

func f(a, b bool) int {
	switch {
	case a:
		return 1
	case b:
		return 2
	default:
		return 3
	}
}
`
	sites, err := Sites("switch.go", []byte(fixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	// Non-vacuity: the fixture is read and its two case expressions are found, so a claim about
	// what the body does NOT contain is made about a body that was actually walked.
	if len(sites) != 2 {
		t.Fatalf("the fixture produced %d sites, want 2 — without them the assertion below is "+
			"about a file nothing looked at", len(sites))
	}
	// The property itself, re-derived from the parser rather than from the tool: every element
	// of a tag-less switch's body is a case clause, default included.
	if err := requireEverySwitchBodyElementIsACaseClause(fixture); err != nil {
		t.Fatalf("%v — the !isCase guard is then reachable and needs a real detector", err)
	}
}

// requireEverySwitchBodyElementIsACaseClause re-derives the property from go/parser rather than
// from the tool, so the two cannot agree with each other about something neither checks. It also
// refuses to pass vacuously: a fixture with no switch in it proves nothing about switch bodies.
func requireEverySwitchBodyElementIsACaseClause(source string) error {
	file, err := parser.ParseFile(token.NewFileSet(), "switch.go", source, 0)
	if err != nil {
		return fmt.Errorf("the fixture does not parse: %w", err)
	}
	switches, elements := 0, 0
	var found error
	ast.Inspect(file, func(node ast.Node) bool {
		statement, isSwitch := node.(*ast.SwitchStmt)
		if !isSwitch {
			return true
		}
		switches++
		for index, clause := range statement.Body.List {
			elements++
			if _, isCase := clause.(*ast.CaseClause); !isCase {
				found = fmt.Errorf("element %d of a switch body is a %T, not a *ast.CaseClause",
					index, clause)
			}
		}
		return true
	})
	if found != nil {
		return found
	}
	if switches == 0 || elements == 0 {
		return errors.New("the fixture contains no switch body to inspect, so this check passed vacuously")
	}
	return nil
}

// A MULTI-RESULT RETURN IS NOT A DECISION POINT, and nothing said so.
//
// The tool's header states the exclusion and measured zero occurrences in this repository, which
// is exactly the condition under which an exclusion rots: the fixture next door has no such shape,
// so widening the sole-result guard enumerated nothing extra and no test noticed. The site and the
// value a caller branches on must be the same thing; in `return a && b, nil` they are not, and a
// mutator handed that record would neutralise an operand of an expression whose consumer is
// somewhere else entirely.
func TestAMultiResultReturnIsNotASite(t *testing.T) {
	const fixture = `package sample

func pair(a, b bool) (bool, error) {
	return a && b, nil
}

func single(a, b bool) bool {
	return a && b
}
`
	sites, err := Sites("multi.go", []byte(fixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	if len(sites) != 1 {
		var got []string
		for _, site := range sites {
			got = append(got, fmt.Sprintf("%s at line %d", site.Kind, site.Line))
		}
		t.Fatalf("the fixture produced %d sites (%v), want exactly 1 — the sole-result return. A "+
			"multi-result return is not a boolean decision point: the caller branches on one of "+
			"several values, so neutralising an operand of the first one preserves nothing the "+
			"joiner promised", len(sites), got)
	}
	if sites[0].Line != 8 {
		t.Fatalf("the enumerated site is at line %d, want 8 (the sole-result return) — if the "+
			"multi-result one is what was found, the exclusion is inverted", sites[0].Line)
	}
}

// A BINARY OPERATOR THAT IS NOT && OR || IS NOT A DECISION POINT EITHER.
//
// `return a == b` returns a boolean computed by a comparison, and the comparison is one leaf, not
// a site with two. Widening either operator test makes every binary return a site, and each
// record then reports a joiner that is a lie: (false && a) does not preserve `b`, it destroys the
// comparison.
func TestANonBooleanOperatorReturnIsNotASite(t *testing.T) {
	const fixture = `package sample

func compare(a, b int) bool {
	return a == b
}

func add(a, b int) int {
	return a + b
}
`
	sites, err := Sites("compare.go", []byte(fixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	if len(sites) != 0 {
		var got []string
		for _, site := range sites {
			got = append(got, fmt.Sprintf("%s at line %d with %d operands",
				site.Kind, site.Line, len(site.Leaves)))
		}
		t.Fatalf("a return whose top-level operator is neither && nor || was enumerated (%v) — "+
			"every count derived from this tool then inflates, and each such record hands a "+
			"mutator a neutralisation direction that destroys the expression instead of one "+
			"operand of it", got)
	}
	// This test asserts an EXCLUSION, so it would pass just as happily against a tool that
	// enumerates nothing at all. The next test is what makes zero here mean something.
}

// AND A SOLE `||` RETURN IS ONE, which the fixture next door never exercised: every boolean
// return in it is an && chain. Narrowing the LOR test therefore removed a whole shape from the
// enumeration and no test objected -- a readiness predicate written `return degraded || draining`
// would have gone unenumerated in every package.
//
// It is also the non-vacuity control for the exclusion above: this file demonstrably enumerates
// a boolean return when there is one, so zero there is an exclusion rather than a tool that
// never read the fixture.
func TestASoleDisjunctionReturnIsASite(t *testing.T) {
	const fixture = `package sample

func ready(degraded, draining bool) bool {
	return degraded || draining
}
`
	sites, err := Sites("disjunction.go", []byte(fixture))
	if err != nil {
		t.Fatalf("fixture does not parse, so it measures nothing: %v", err)
	}
	if len(sites) != 1 || sites[0].Kind != "return" || len(sites[0].Leaves) != 2 {
		t.Fatalf("`return degraded || draining` produced %v, want one \"return\" site with 2 "+
			"operands — a readiness predicate written as a disjunction is the idiomatic shape, "+
			"and a tool that skips it reports the package swept", sites)
	}
	for index, want := range []string{"degraded", "draining"} {
		leaf := sites[0].Leaves[index]
		if got := fixture[leaf.Start:leaf.End]; got != want {
			t.Fatalf("operand %d selected %q, want %q", index, got, want)
		}
		if leaf.Joiner != "||" {
			t.Fatalf("operand %d reports joiner %q, want ||", index, leaf.Joiner)
		}
	}
}
