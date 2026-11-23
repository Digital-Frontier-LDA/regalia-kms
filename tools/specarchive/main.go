// Command specarchive is the archive-time code-target existence check.
//
// An OpenSpec change's `## Impact` section names the code it will touch
// (`kms/internal/policy/cosmos.go`, `kms/COSMOS-SUPPORT.md`, a function
// reference like `parseFee`, …). By the time a change is archived — its code
// has landed — those targets must still exist: a change pointing at a file
// that moved, or a symbol that was renamed, is the B3-class drift this repo
// keeps hitting by hand. specarchive parses the Impact section of every
// pending (non-archived) change and verifies each concrete target still
// resolves:
//
//   - a file path (with or without a `kms/` or `regalia/` repo prefix) must
//     exist on disk;
//   - a `*_test.go` glob must match at least one file;
//   - a `package.go::symbol` or bare `symbol` reference in a named .go file
//     must appear as a declared identifier in that file.
//
// It is read-only and prints a report; it exits 1 if any named target is
// missing, so it can gate the archive step. Run it from the regalia tracking
// repo (where openspec/changes/ lives):
//
//	specarchive -changes ../openspec/changes \
//	  -kms /path/to/regalia-kms -regalia /path/to/regalia \
//	  -ceremony /path/to/regalia-ceremony
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// target is one concrete code reference pulled from an Impact section.
type target struct {
	Raw    string // as written in the Impact line
	Kind   string // "file", "glob", "symbol"
	Repo   string // "kms", "regalia", "ceremony", or "" (relative)
	Path   string // filesystem path after prefix substitution (file/glob)
	Symbol string // for kind=symbol
	Source string // the change dir this came from
}

var (
	// backticked tokens in the Impact section.
	backtickRe = regexp.MustCompile("`([^`]+)`")
	// a `file.go::symbol` or `file.go` reference.
	fileTokRe = regexp.MustCompile(`^([A-Za-z0-9_./*-]+\.go)(?:::(\w+))?$`)
	// a markdown/doc path.
	docTokRe = regexp.MustCompile(`^([A-Za-z0-9_./-]+\.md)$`)
)

// extractTargets pulls concrete targets out of one change's proposal.md Impact
// section.
func extractTargets(proposalPath, changeDir string) ([]target, error) {
	data, err := os.ReadFile(proposalPath)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	// Isolate the ## Impact section.
	var impact []string
	inImpact := false
	for _, line := range lines {
		if strings.HasPrefix(line, "## ") {
			inImpact = strings.TrimSpace(strings.TrimPrefix(line, "## ")) == "Impact"
			continue
		}
		if inImpact {
			impact = append(impact, line)
		}
	}
	impactText := strings.Join(impact, "\n")

	var out []target
	for _, m := range backtickRe.FindAllStringSubmatch(impactText, -1) {
		tok := strings.TrimSpace(m[1])
		// Strip a repo prefix: kms/..., regalia/..., regalia-ceremony:...
		repo, rest := stripRepoPrefix(tok)
		if rest == "" {
			continue
		}
		// A glob test reference.
		if strings.Contains(rest, "*") && strings.HasSuffix(rest, "_test.go") {
			out = append(out, target{Raw: tok, Kind: "glob", Repo: repo, Path: rest, Source: changeDir})
			continue
		}
		if fm := fileTokRe.FindStringSubmatch(rest); fm != nil {
			t := target{Raw: tok, Repo: repo, Path: fm[1], Source: changeDir}
			if fm[2] != "" {
				t.Kind = "symbol"
				t.Symbol = fm[2]
			} else {
				t.Kind = "file"
			}
			out = append(out, t)
			continue
		}
		if dm := docTokRe.FindStringSubmatch(rest); dm != nil {
			out = append(out, target{Raw: tok, Kind: "file", Repo: repo, Path: dm[1], Source: changeDir})
			continue
		}
	}
	return out, nil
}

// stripRepoPrefix maps a token to (repo, path-within-that-repo).
func stripRepoPrefix(tok string) (repo, path string) {
	switch {
	case strings.HasPrefix(tok, "kms/"):
		return "kms", strings.TrimPrefix(tok, "kms/")
	case strings.HasPrefix(tok, "regalia/"):
		return "regalia", strings.TrimPrefix(tok, "regalia/")
	case strings.HasPrefix(tok, "regalia-ceremony:"):
		return "ceremony", strings.TrimPrefix(tok, "regalia-ceremony:")
	case strings.HasPrefix(tok, "doc/"):
		// doc/ lives in the regalia tracking repo.
		return "regalia", tok
	default:
		return "", tok
	}
}

// repoRoot resolves a target's repo to an absolute root directory.
func repoRoot(t target, roots map[string]string) string {
	if t.Repo == "" {
		// relative to the regalia repo by default (openspec lives there)
		return roots["regalia"]
	}
	return roots[t.Repo]
}

func main() {
	changes := flag.String("changes", "../openspec/changes", "openspec/changes directory")
	kms := flag.String("kms", "", "path to the regalia-kms repo")
	regalia := flag.String("regalia", ".", "path to the regalia tracking repo (default cwd)")
	ceremony := flag.String("ceremony", "", "path to the regalia-ceremony repo (optional)")
	flag.Parse()

	roots := map[string]string{
		"kms":      *kms,
		"regalia":  *regalia,
		"ceremony": *ceremony,
	}

	failed, err := scanChanges(*changes, roots)
	if err != nil {
		fmt.Fprintf(os.Stderr, "specarchive: walk: %v\n", err)
		os.Exit(2)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\nspecarchive: FAIL — %d change(s) with missing targets\n", failed)
		os.Exit(1)
	}
	fmt.Println("specarchive: OK — all named targets present")
}

// scanChanges checks every pending change under changesDir and returns the
// total number of missing targets. It skips the archive/ subtree (archived
// changes are history, not pending work). Any walk error, including a
// changesDir that does not exist, and any unreadable proposal is returned as an
// error: the check fails rather than reports "all present" for what it never read.
func scanChanges(changesDir string, roots map[string]string) (int, error) {
	failed := 0
	err := filepath.WalkDir(changesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "archive" && path != changesDir {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "proposal.md" {
			return nil
		}
		changeDir := filepath.Dir(path)
		n, err := checkChange(changeDir, filepath.Base(changeDir), roots)
		if err != nil {
			return err
		}
		failed += n
		return nil
	})
	return failed, err
}

// checkChange verifies one change's targets; it returns the number of
// missing targets (0 = all present), or an error if the proposal cannot be read.
func checkChange(changeDir, name string, roots map[string]string) (int, error) {
	proposal := filepath.Join(changeDir, "proposal.md")
	targets, err := extractTargets(proposal, changeDir)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", proposal, err)
	}
	if len(targets) == 0 {
		fmt.Printf("%s: no concrete code targets in Impact (nothing to verify)\n", name)
		return 0, nil
	}
	var missing []string
	for _, t := range targets {
		ok, why := verify(t, roots)
		if !ok {
			missing = append(missing, fmt.Sprintf("%s [%s] %s", t.Raw, t.Kind, why))
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		fmt.Printf("%s: FAIL — %d missing target(s):\n", name, len(missing))
		for _, m := range missing {
			fmt.Printf("    - %s\n", m)
		}
		return len(missing), nil
	}
	fmt.Printf("%s: OK — %d target(s) present\n", name, len(targets))
	return 0, nil
}

func verify(t target, roots map[string]string) (bool, string) {
	root := repoRoot(t, roots)
	full := filepath.Join(root, t.Path)
	switch t.Kind {
	case "glob":
		matches, err := filepath.Glob(full)
		if err != nil || len(matches) == 0 {
			return false, "no file matches the glob"
		}
		return true, ""
	case "symbol":
		data, err := os.ReadFile(full)
		if err != nil {
			return false, "file not found: " + full
		}
		if !symbolDeclared(string(data), t.Symbol) {
			return false, fmt.Sprintf("symbol %q not declared in %s", t.Symbol, full)
		}
		return true, ""
	default: // file
		if _, err := os.Stat(full); err != nil {
			return false, "file not found: " + full
		}
		return true, ""
	}
}

// symbolDeclared reports whether name is declared at the top level of the Go
// source src: a func or method, a type, or a const or var (grouped
// declarations included). It parses the file, so a name that appears only in a
// comment or a string does not count. Source that does not parse declares
// nothing.
func symbolDeclared(src, name string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "", src, parser.SkipObjectResolution)
	if err != nil {
		return false
	}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == name {
				return true
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.Name == name {
						return true
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.Name == name {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
