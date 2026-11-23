// Command spectrace enforces the spec-to-test join key.
//
// Every OpenSpec scenario (a `#### Scenario:` block under a `### Requirement:`
// in openspec/specs/<capability>/spec.md) is a testable claim. A scenario is
// *covered* when some Go test carries an annotation of the form:
//
//	// spec: <capability>/<scenario-slug>
//
// where <scenario-slug> is the scenario title lowercased with every run of
// non-alphanumeric characters collapsed to a single hyphen (see slug). The
// tool fails (exit 1) on either direction of the join breaking:
//
//   - an ORPHAN SCENARIO: a scenario no test claims. The spec made a promise
//     no test is holding.
//   - a DANGLING LINK: a test claims a scenario that does not exist in the
//     spec. The test is guarding a sentence that was rewritten or removed,
//     which is how a test goes silent the moment the spec it protects moves.
//
// This is the spine of the docs<->spec<->test loop: the scenario is the join
// key, and CI refuses to let either side drift. Run it from the repo root:
//
//	spectrace -specs ../openspec/specs -tests .
//
// (or see the Makefile/CI invocation). It is read-only; it changes nothing.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// triple identifies one scenario in the spec tree.
type triple struct {
	Capability  string
	Requirement string
	Scenario    string
	Slug        string
	SpecPath    string
	SpecLine    int
}

// link is one `// spec:` annotation found in a test file.
type link struct {
	Capability string
	Slug       string
	TestPath   string
	TestLine   int
}

var (
	requirementRe = regexp.MustCompile(`^### Requirement:\s*(.+?)\s*$`)
	scenarioRe    = regexp.MustCompile(`^#### Scenario:\s*(.+?)\s*$`)
	linkRe        = regexp.MustCompile(`//\s*spec:\s*([a-z0-9-]+)/([a-z0-9-]+)`)
)

// slug canonicalizes a scenario title into its join-key form.
func slug(title string) string {
	var b strings.Builder
	lastHyphen := false
	for _, r := range strings.ToLower(title) {
		alnum := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if alnum {
			b.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen {
			b.WriteByte('-')
			lastHyphen = true
		}
	}
	s := strings.Trim(b.String(), "-")
	return s
}

// parseSpec walks one spec.md and yields its scenario triples.
func parseSpec(path string) ([]triple, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	capability := filepath.Base(filepath.Dir(path))
	var out []triple
	var req string
	for i, line := range strings.Split(string(data), "\n") {
		if m := requirementRe.FindStringSubmatch(line); m != nil {
			req = m[1]
			continue
		}
		if m := scenarioRe.FindStringSubmatch(line); m != nil {
			title := m[1]
			out = append(out, triple{
				Capability:  capability,
				Requirement: req,
				Scenario:    title,
				Slug:        slug(title),
				SpecPath:    path,
				SpecLine:    i + 1,
			})
		}
	}
	return out, nil
}

// collectSpecs loads every spec under the specs root.
func collectSpecs(root string) ([]triple, error) {
	var all []triple
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, "spec.md") {
			return nil
		}
		ts, err := parseSpec(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		all = append(all, ts...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

// collectLinks walks test files and gathers every `// spec:` annotation. It
// skips the tools/ tree: the tools' own tests carry `// spec:` fixture strings
// (and capability/slug literals) that are examples, not real coverage claims,
// and scanning them would report dangling links that are not.
func collectLinks(testsRoot string) ([]link, error) {
	var all []link
	err := filepath.WalkDir(testsRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			rel, _ := filepath.Rel(testsRoot, path)
			base := filepath.Base(path)
			if base == "tools" && (rel == "." || rel == "tools" || strings.HasPrefix(rel, "tools"+string(filepath.Separator))) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, m := range linkRe.FindAllStringSubmatch(line, -1) {
				all = append(all, link{
					Capability: m[1],
					Slug:       m[2],
					TestPath:   path,
					TestLine:   i + 1,
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

func main() {
	specsRoot := flag.String("specs", "../openspec/specs", "root directory of openspec specs")
	testsRoot := flag.String("tests", ".", "root directory of Go test files")
	quiet := flag.Bool("q", false, "print only failures and the summary")
	allow := flag.String("allow", "", "comma-separated scenario keys (cap/slug) that are KNOWN post-landing — their spec states behavior a pending change will implement, so no test exists yet. They are reported as 'acknowledged' and do not fail the gate. This is a deliberate, visible exception: every key here is a debt that a pending change must retire.")
	flag.Parse()

	// The acknowledged set: scenarios whose coverage is a known, named debt.
	acknowledged := map[string]bool{}
	if *allow != "" {
		for _, k := range strings.Split(*allow, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				acknowledged[k] = true
			}
		}
	}

	scenarios, err := collectSpecs(*specsRoot)
	if err != nil {
		fatalf("read specs: %v", err)
	}
	links, err := collectLinks(*testsRoot)
	if err != nil {
		fatalf("read tests: %v", err)
	}

	// Index scenarios by (capability, slug) -> scenario (detect duplicate slugs).
	scenByKey := make(map[string]triple)
	var dupSlugs []string
	for _, s := range scenarios {
		key := s.Capability + "/" + s.Slug
		if prev, ok := scenByKey[key]; ok {
			dupSlugs = append(dupSlugs, fmt.Sprintf("%s (line %d) collides with %s (line %d)",
				s.Scenario, s.SpecLine, prev.Scenario, prev.SpecLine))
			continue
		}
		scenByKey[key] = s
	}
	covered := make(map[string]bool) // scenario key -> covered

	var dangling []link
	for _, l := range links {
		key := l.Capability + "/" + l.Slug
		if _, ok := scenByKey[key]; !ok {
			dangling = append(dangling, l)
			continue
		}
		covered[key] = true
	}

	var orphans, acknowledgedList []triple
	for _, s := range scenarios {
		if covered[s.Capability+"/"+s.Slug] {
			continue
		}
		key := s.Capability + "/" + s.Slug
		if acknowledged[key] {
			acknowledgedList = append(acknowledgedList, s)
			continue
		}
		orphans = append(orphans, s)
	}

	sort.Slice(orphans, func(i, j int) bool {
		if orphans[i].Capability != orphans[j].Capability {
			return orphans[i].Capability < orphans[j].Capability
		}
		return orphans[i].SpecLine < orphans[j].SpecLine
	})
	sort.Slice(dangling, func(i, j int) bool {
		if dangling[i].TestPath != dangling[j].TestPath {
			return dangling[i].TestPath < dangling[j].TestPath
		}
		return dangling[i].TestLine < dangling[j].TestLine
	})

	if !*quiet {
		fmt.Printf("spectrace: %d scenarios across %s, %d spec links in tests under %s\n",
			len(scenarios), *specsRoot, len(links), *testsRoot)
	}

	// An -allow key that names no scenario is a typo or a scenario that was
	// renamed away — it would silently stop being enforced. Report it and fail
	// so the allow-list cannot drift from the spec.
	var badAllow []string
	for k := range acknowledged {
		if _, ok := scenByKey[k]; !ok {
			badAllow = append(badAllow, k)
		}
	}
	sort.Strings(badAllow)
	if len(badAllow) > 0 {
		fmt.Fprintln(os.Stderr, "unknown -allow keys (name no scenario):")
		for _, k := range badAllow {
			fmt.Fprintf(os.Stderr, "  - %s\n", k)
		}
	}

	if len(acknowledgedList) > 0 {
		if !*quiet {
			fmt.Printf("acknowledged post-landing scenarios (%d) — coverage is a named debt a pending change must retire:\n", len(acknowledgedList))
			for _, s := range acknowledgedList {
				fmt.Printf("  - %s  [%s:%d]\n", s.Capability+"/"+s.Slug, s.SpecPath, s.SpecLine)
			}
		}
	}

	fail := false
	if len(badAllow) > 0 {
		fail = true
	}
	if len(dupSlugs) > 0 {
		fail = true
		fmt.Fprintln(os.Stderr, "duplicate scenario slugs (ambiguous join key):")
		for _, d := range dupSlugs {
			fmt.Fprintln(os.Stderr, "  - "+d)
		}
	}
	if len(dangling) > 0 {
		fail = true
		fmt.Fprintln(os.Stderr, fmt.Sprintf("dangling links (%d) — test claims a scenario not in the spec:", len(dangling)))
		for _, l := range dangling {
			fmt.Fprintf(os.Stderr, "  - %s:%d  ->  %s/%s\n", l.TestPath, l.TestLine, l.Capability, l.Slug)
		}
	}
	if len(orphans) > 0 {
		fail = true
		fmt.Fprintln(os.Stderr, fmt.Sprintf("orphan scenarios (%d) — spec scenario with no test:", len(orphans)))
		for _, s := range orphans {
			fmt.Fprintf(os.Stderr, "  - %s  [%s:%d]\n      requirement: %s\n",
				s.Capability+"/"+s.Slug, s.SpecPath, s.SpecLine, s.Requirement)
		}
	}

	if fail {
		fmt.Fprintf(os.Stderr, "\nspectrace: FAIL — %d orphan scenario(s), %d dangling link(s), %d duplicate slug(s), %d bad allow-key(s)\n",
			len(orphans), len(dangling), len(dupSlugs), len(badAllow))
		os.Exit(1)
	}
	fmt.Printf("spectrace: OK — %d scenarios covered, %d acknowledged post-landing, no dangling links\n",
		len(scenarios)-len(acknowledgedList), len(acknowledgedList))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "spectrace: "+format+"\n", args...)
	os.Exit(2)
}
