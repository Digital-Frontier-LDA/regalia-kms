// Package nodeunitsguard holds node-units.yml's paths filter to the Go build graph of the binaries its jobs build
// (#694, option b).
//
// The filter deliberately does not list every repository package those binaries build from. A full node-units
// run on every Go PR costs too much, by GA ruling on #694. ci.yml unit-tests every package on every PR, and
// node-units.yml's nightly schedule runs every job unfiltered as the backstop (tests/test_node_units_nightly.py
// holds the schedule in place). This test makes the split a decision rather than an accident: every repository
// package in the build graph is either inside the filter or named in nightlyOnly. A package that joins the graph
// is a named failure until someone decides which, and so is an entry that has gone stale.
//
// os/exec is test-only here and does not cross internal/boundary_test.go's no-shelling-out rule, which walks
// non-test files only. `go test` puts its own toolchain's bin directory first on PATH, so "go" is that toolchain.
package nodeunitsguard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/Digital-Frontier-LDA/regalia-kms"

// What node-units.yml's jobs `go build`, with the tags they build it with.
var binaries = []struct{ pkg, tags string }{
	{"./cmd/regalia-kms", "piv"},
	{"./cmd/regalia-audit-collector", ""},
	{"./cmd/regalia-audit-ship", ""},
	{"./cmd/regalia-unlock", ""},
}

// The packages in the build graph that the filter leaves to the nightly (#694, measured at main bb3d90c5).
var nightlyOnly = map[string]bool{
	"internal/api": true, "internal/approval": true, "internal/auth": true, "internal/backend": true,
	"internal/backend/nitrokey": true, "internal/backend/pcscwatch": true, "internal/backend/reauth": true,
	"internal/backend/yubikey": true, "internal/certs": true, "internal/controlplane": true, "internal/envelope": true,
	"internal/executor": true, "internal/fencing": true, "internal/keywrap": true, "internal/operations": true,
	"internal/opstate": true, "internal/pin": true, "internal/policy": true, "internal/registry": true,
	"internal/secrets": true, "internal/server": true, "internal/telemetry": true,
}

// filterPaths is the pull_request event's paths list.
func filterPaths(workflow string) []string {
	var globs []string
	event, inPaths := "", false
	for _, line := range strings.Split(workflow, "\n") {
		switch {
		case regexp.MustCompile(`^  \w+:\s*$`).MatchString(line):
			event, inPaths = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ":")), false
		case regexp.MustCompile(`^\S`).MatchString(line):
			event, inPaths = "", false
		case event == "pull_request" && regexp.MustCompile(`^    paths:\s*$`).MatchString(line):
			inPaths = true
		case inPaths && strings.HasPrefix(line, "      - "):
			globs = append(globs, strings.TrimSpace(strings.TrimPrefix(line, "      - ")))
		case inPaths && !strings.HasPrefix(line, "      "):
			inPaths = false
		}
	}
	return globs
}

// globRegexp is GitHub's paths glob: ** crosses directories, * stays inside one.
func globRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	for i := 0; i < len(glob); {
		switch {
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(".*")
			i += 2
		case glob[i] == '*':
			b.WriteString("[^/]*")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(glob[i : i+1]))
			i++
		}
	}
	return regexp.MustCompile(`\A` + b.String() + `\z`)
}

// filtered reports whether a change to a Go file of the package directory pkg starts node-units.
func filtered(pkg string, globs []string) bool {
	for _, g := range globs {
		if globRegexp(g).MatchString(pkg + "/x.go") {
			return true
		}
	}
	return false
}

// decide returns one problem per package of the graph that is in neither or both, and per stale nightly entry.
func decide(graph []string, globs []string, nightly map[string]bool) []string {
	var problems []string
	inGraph := map[string]bool{}
	for _, pkg := range graph {
		inGraph[pkg] = true
		switch in := filtered(pkg, globs); {
		case in && nightly[pkg]:
			problems = append(problems, pkg+": inside the filter and named nightly-only")
		case !in && !nightly[pkg]:
			problems = append(problems, pkg+": built by node-units, outside its filter, and not named nightly-only")
		}
	}
	for pkg := range nightly {
		if !inGraph[pkg] {
			problems = append(problems, pkg+": named nightly-only but no node-units binary builds from it")
		}
	}
	sort.Strings(problems)
	return problems
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// buildGraph lists the repository packages the binaries build from, as module-relative directories.
func buildGraph(t *testing.T, root string) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, b := range binaries {
		args := []string{"list", "-deps", "-f", "{{.ImportPath}}"}
		if b.tags != "" {
			args = append(args, "-tags", b.tags)
		}
		cmd := exec.Command("go", append(args, b.pkg)...)
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
		out, err := cmd.Output()
		if err != nil {
			stderr := ""
			if e, ok := err.(*exec.ExitError); ok {
				stderr = string(e.Stderr)
			}
			t.Fatalf("go list -deps %s: %v\n%s", b.pkg, err, stderr)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if rel, ok := strings.CutPrefix(line, module+"/"); ok {
				seen[rel] = true
			}
		}
	}
	graph := make([]string, 0, len(seen))
	for pkg := range seen {
		graph = append(graph, pkg)
	}
	sort.Strings(graph)
	return graph
}

func TestEveryBuiltPackageIsFilteredOrNightlyOnly(t *testing.T) {
	root := repoRoot(t)
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "node-units.yml"))
	if err != nil {
		t.Fatal(err)
	}
	globs := filterPaths(string(workflow))
	if len(globs) < 20 {
		t.Fatalf("read %d paths from node-units.yml's pull_request filter: the reader went blind", len(globs))
	}
	graph := buildGraph(t, root)
	// a graph gone blind decides nothing: it must hold what #694 measured by hand
	if len(graph) < 30 {
		t.Fatalf("the build graph has %d repository packages, #694 measured 32: %v", len(graph), graph)
	}
	for _, want := range []string{"cmd/regalia-kms", "cmd/regalia-unlock/askpass", "internal/admission", "internal/operations", "internal/backend/nitrokey"} {
		if !contains(graph, want) {
			t.Errorf("the build graph lacks %s: %v", want, graph)
		}
	}
	for _, p := range decide(graph, globs, nightlyOnly) {
		t.Errorf("%s (decide: add it to node-units.yml's paths, both events, or to nightlyOnly here)", p)
	}
}

func TestDecideNamesEachWayASplitGoesWrong(t *testing.T) {
	globs := []string{"internal/admission/**", "cmd/x/**"}
	got := decide([]string{"internal/admission", "internal/new", "internal/twice", "cmd/x/sub"}, globs,
		map[string]bool{"internal/twice": true, "internal/gone": true, "internal/admission": false})
	want := []string{
		"internal/gone: named nightly-only but no node-units binary builds from it",
		"internal/new: built by node-units, outside its filter, and not named nightly-only",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("decide = %q\nwant      %q", got, want)
	}
	if got := decide([]string{"internal/admission"}, globs, map[string]bool{"internal/admission": true}); len(got) != 1 ||
		!strings.Contains(got[0], "inside the filter and named nightly-only") {
		t.Errorf("a package both filtered and nightly-only = %q", got)
	}
}

func TestTheFilterReaderAndGlobFollowGitHub(t *testing.T) {
	yml := "on:\n  schedule:\n    - cron: '1 2 * * *'\n  pull_request:\n    paths:\n      - internal/a/**\n      - cmd/b/*\n  push:\n    paths:\n      - other/**\n"
	if got := filterPaths(yml); fmt.Sprint(got) != "[internal/a/** cmd/b/*]" {
		t.Errorf("filterPaths = %q", got)
	}
	if !filtered("internal/a/deep/er", []string{"internal/a/**"}) || filtered("cmd/b/deep", []string{"cmd/b/*"}) ||
		!filtered("cmd/b", []string{"cmd/b/*"}) || filtered("internal/ab", []string{"internal/a/**"}) {
		t.Error("the glob does not follow GitHub's paths rules")
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}
