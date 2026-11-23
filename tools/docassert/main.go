// Command docassert is the doc-assertion linker.
//
// The developer/operator docs in this repo restate safety guarantees in prose
// ("is refused", "SHALL verify", "fails closed"). That restatement is how the
// EGM round kept finding a doc promising a guard the code did not implement —
// a doc sentence can drift from the spec requirement and the test that prove
// it, and nothing notices until a human reads all three.
//
// docassert is the cheap first net. It scans each doc for a line that asserts a
// safety guarantee — a guarantee keyword (SHALL / MUST / "is refused" /
// "is verified" / "fails closed" / "is not …") — and flags the line unless the
// line (or its paragraph) also carries a link to the thing that proves it: a
// `openspec/…` spec path, a `tools/spectrace` join-key reference, or a `Test…`
// name. A flagged line is not necessarily wrong; it is an *unlinked*
// guarantee — one the reader cannot verify without hunting. The point is to
// make the author add the link, not to second-guess the claim.
//
// It is a linter, not a gate by default: run with -fail to make it exit 1 on
// any flagged line (use it in review, not necessarily in CI, until the corpus
// is fully linked). Run it from either repo root:
//
//	docassert -docs . -specs /path/to/openspec/specs
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

// guaranteeRe matches a line that asserts a safety property.
var guaranteeRe = regexp.MustCompile(
	`(?i)\b(SHALL|MUST NOT|MUST)\b|` + // normative keywords
		`\b(is (refused|rejected|verified|retained|consumed|checked|validated|enforced))\b|` +
		`\b(fails? closed|is not (a gap|an (authorization|integrity))|cannot (be )?(silently|accidentally))\b`)

// linkRe matches a line (or paragraph) that points at the proof.
var linkRe = regexp.MustCompile(
	`openspec/(specs|changes)/|` + // spec path
		`// spec: |` + // spectrace join key
		`\bTest[A-Z][A-Za-z0-9]*\b|` + // a Go test name
		`tools/(spectrace|specarchive)\b`)

// flagged is one unlinked guarantee line.
type flagged struct {
	Path string
	Line int
	Text string
}

func scanDoc(path string) []flagged {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	lines := strings.Split(string(data), "\n")
	// Group into paragraphs (blank-line separated) so a link on any line of a
	// paragraph satisfies every guarantee line in it.
	var res []flagged
	var para []int // line numbers in the current paragraph
	paraHasLink := false
	flush := func() {
		if !paraHasLink {
			for _, ln := range para {
				text := strings.TrimSpace(lines[ln-1])
				if guaranteeRe.MatchString(text) {
					res = append(res, flagged{Path: path, Line: ln, Text: text})
				}
			}
		}
		para = nil
		paraHasLink = false
	}
	for i, line := range lines {
		n := i + 1
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		para = append(para, n)
		if linkRe.MatchString(line) {
			paraHasLink = true
		}
	}
	flush()
	sort.Slice(res, func(i, j int) bool {
		if res[i].Path != res[j].Path {
			return res[i].Path < res[j].Path
		}
		return res[i].Line < res[j].Line
	})
	return res
}

func main() {
	docs := flag.String("docs", ".", "root directory of markdown docs")
	_ = flag.String("specs", "", "openspec/specs root (accepted for symmetry; links are matched in-text)")
	fail := flag.Bool("fail", false, "exit 1 if any guarantee line is unlinked")
	only := flag.String("only", "", "only scan docs whose path contains this substring")
	flag.Parse()

	var all []flagged
	err := filepath.WalkDir(*docs, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".md") {
			return nil
		}
		if *only != "" && !strings.Contains(path, *only) {
			return nil
		}
		all = append(all, scanDoc(path)...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "docassert: walk: %v\n", err)
		os.Exit(2)
	}

	if len(all) == 0 {
		fmt.Println("docassert: no unlinked guarantee lines")
		return
	}
	for _, f := range all {
		fmt.Printf("%s:%d  %s\n", f.Path, f.Line, truncate(f.Text, 100))
	}
	fmt.Printf("\ndocassert: %d unlinked guarantee line(s)\n", len(all))
	if *fail && len(all) > 0 {
		os.Exit(1)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
