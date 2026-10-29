package opstate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// EVERY RULE OF A TWIN HAS A CASE IN THE SHARED VECTOR (regalia-u1r).
//
// The Go functions here that are documented "X is opstate.<fn>" mirror deploy/baremetal/opstate.py, and the
// vector (tests/vectors/opstate-v1.json) holds both to the same decisions and reasons. That held only for the
// rules some case happened to reach: three times in two days a rule changed on one side while no case reached
// it (#496's v2 binding, #516's redfish evidence and its fence set). So this iterates the RULES, not the cases:
// every refuse() a twin can reach, through the package functions it calls, must be matched by the reason of a
// refused case. A rule added without a case fails here before any fixture exercises it.
// tests/test_twin_rule_coverage.py is the same check over opstate.py's require()s.

// twinModules are the Python modules whose twins this covers.
var twinModules = []string{"opstate", "survivor", "lease"}

// twinRefusals is every refuse() format reachable from a twin of one of twinModules, by the function it sits in.
func twinRefusals(t *testing.T) map[string][]string {
	t.Helper()
	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	funcs := map[string]*ast.FuncDecl{}
	var roots []string
	twin := regexp.MustCompile(`^[A-Za-z0-9_]+ is (` + strings.Join(twinModules, "|") + `)\.[a-z_]+\b`)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			funcs[fn.Name.Name] = fn
			if fn.Doc != nil && twin.MatchString(fn.Doc.Text()) {
				roots = append(roots, fn.Name.Name)
			}
		}
	}
	if len(roots) < 10 {
		t.Fatalf("found %d twins (%v): the doc convention this test reads has changed", len(roots), roots)
	}
	found := map[string][]string{}
	seen := map[string]bool{}
	for todo := roots; len(todo) > 0; {
		name := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		fn, ok := funcs[name]
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			callee, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if callee.Name == "refuse" && len(call.Args) > 0 {
				format, ok := literal(call.Args[0])
				if !ok {
					t.Errorf("%s: a refuse() whose format is not a literal at %s: this test cannot read its rule", name, fset.Position(call.Pos()))
				}
				found[format] = append(found[format], name)
			} else if _, local := funcs[callee.Name]; local {
				todo = append(todo, callee.Name)
			}
			return true
		})
	}
	return found
}

// literal is a string literal, or a concatenation of them.
func literal(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(x.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if x.Op != token.ADD {
			return "", false
		}
		l, ok1 := literal(x.X)
		r, ok2 := literal(x.Y)
		return l + r, ok1 && ok2
	}
	return "", false
}

var verb = regexp.MustCompile(`%[-+ #0-9.]*[sdvqx]`)

// formatPattern matches what a format can print: each verb at least one character.
func formatPattern(format string) *regexp.Regexp {
	parts := verb.Split(strings.ReplaceAll(format, "%%", "\x00"), -1)
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(regexp.QuoteMeta(p), "\x00", "%")
	}
	return regexp.MustCompile(`(?s)^` + strings.Join(parts, `.+?`) + `$`)
}

// vectorReasons are the reasons of every refused case in the shared vector, any section.
func vectorReasons(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, section := range opstateVector(t) {
		cases, ok := section.([]any)
		if !ok {
			continue
		}
		for _, c := range cases {
			if m, ok := c.(map[string]any); ok && m["accept"] == false {
				if reason, ok := m["python_reason"].(string); ok && reason != "" {
					out = append(out, reason)
				}
			}
		}
	}
	return out
}

func TestEveryRuleOfAGoTwinHasAVectorCase(t *testing.T) {
	reasons := vectorReasons(t)
	found := twinRefusals(t)
	var missing []string
	for format, where := range found {
		pattern := formatPattern(format)
		hit := false
		for _, r := range reasons {
			if pattern.MatchString(r) {
				hit = true
				break
			}
		}
		if !hit {
			sort.Strings(where)
			missing = append(missing, "  "+strconv.Quote(format)+" (in "+strings.Join(where, ", ")+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d of %d rules the Go twins of %v can refuse with have no refused case in tests/vectors/opstate-v1.json "+
			"(add one to make-opstate-v1.py; never an exemption):\n%s", len(missing), len(found), twinModules, strings.Join(missing, "\n"))
	}
}

// The check itself: a rule a twin reaches with no case is found (a planted refuse() in a copy of the package), so
// a clean result above is not the scan reading nothing.
func TestTheRuleScanFindsAnUncoveredRule(t *testing.T) {
	dir := t.TempDir()
	paths, _ := filepath.Glob("*.go")
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if path == "verify.go" {
			raw = []byte(strings.Replace(string(raw), "func ValidateEntry(value any) (map[string]any, string, error) {",
				"func ValidateEntry(value any) (map[string]any, string, error) {\n\tif value == \"planted\" {\n\t\treturn nil, \"\", refuse(\"a planted rule no case reaches\")\n\t}", 1))
			if !strings.Contains(string(raw), "a planted rule") {
				t.Fatal("ValidateEntry's signature moved: the plant did not apply")
			}
		}
		if err := os.WriteFile(filepath.Join(dir, path), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	here, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(here)
	found := twinRefusals(t)
	if _, ok := found["a planted rule no case reaches"]; !ok {
		t.Fatal("the scan did not see a refuse() planted in ValidateEntry")
	}
}
