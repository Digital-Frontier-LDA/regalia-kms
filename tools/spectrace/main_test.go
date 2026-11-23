package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSlugCollapsesNonAlphanumeric(t *testing.T) {
	cases := map[string]string{
		"Tip field present":                                        "tip-field-present",
		"Repeated amount entries for one denomination":             "repeated-amount-entries-for-one-denomination",
		"VerifyState runs against a live journal":                  "verifystate-runs-against-a-live-journal",
		"Per-day cap below per-transaction cap is refused at load": "per-day-cap-below-per-transaction-cap-is-refused-at-load",
		"A -- tricky — title":                                      "a-tricky-title",
		"  padded  ":                                               "padded",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func writeSpec(t *testing.T, dir, cap, content string) string {
	t.Helper()
	cdir := filepath.Join(dir, cap)
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(cdir, "spec.md")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseSpecCapturesRequirementAndScenario(t *testing.T) {
	dir := t.TempDir()
	writeSpec(t, dir, "demo", `# Demo

### Requirement: One thing
prose

#### Scenario: Alpha is refused
- **WHEN** x
- **THEN** y

#### Scenario: Beta is accepted
- **WHEN** x
- **THEN** y

### Requirement: Another thing

#### Scenario: Gamma is refused
- **WHEN** x
- **THEN** y
`)
	got, err := parseSpec(filepath.Join(dir, "demo", "spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d scenarios, want 3: %#v", len(got), got)
	}
	if got[0].Requirement != "One thing" || got[0].Scenario != "Alpha is refused" {
		t.Errorf("scenario 0 wrong: %#v", got[0])
	}
	if got[0].Slug != "alpha-is-refused" {
		t.Errorf("slug 0 = %q, want alpha-is-refused", got[0].Slug)
	}
	if got[1].Requirement != "One thing" {
		t.Errorf("scenario 1 requirement = %q, want One thing (same requirement)", got[1].Requirement)
	}
	if got[2].Requirement != "Another thing" {
		t.Errorf("scenario 2 requirement = %q, want Another thing", got[2].Requirement)
	}
	if got[2].Capability != "demo" {
		t.Errorf("capability = %q, want demo", got[2].Capability)
	}
}

func TestCollectLinksFindsAnnotations(t *testing.T) {
	dir := t.TempDir()
	content := `package x
import "testing"

// spec: demo/alpha-is-refused
func TestAlpha(t *testing.T) {}

// Two on one line is legal.
// spec: demo/beta-is-accepted
// spec: demo/gamma-is-refused
func TestBeta(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	links, bad, err := collectLinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 0 {
		t.Errorf("malformed = %#v, want none", bad)
	}
	var got []string
	for _, l := range links {
		got = append(got, l.Capability+"/"+l.Slug)
	}
	want := []string{"demo/alpha-is-refused", "demo/beta-is-accepted", "demo/gamma-is-refused"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("links = %v, want %v", got, want)
	}
}

func TestJoinKeyDetectsOrphanAndDangling(t *testing.T) {
	// Reuse the two parsers to simulate the join without running main().
	dir := t.TempDir()
	writeSpec(t, dir, "demo", `### Requirement: R
#### Scenario: Alpha is refused
x
#### Scenario: Beta is accepted
x
`)
	specs, err := collectSpecs(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Only alpha is claimed by a test.
	tfile := `package x
import "testing"
// spec: demo/alpha-is-refused
func TestA(t *testing.T) {}
// spec: demo/not-in-spec
func TestB(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(dir, "z_test.go"), []byte(tfile), 0o644); err != nil {
		t.Fatal(err)
	}
	links, _, err := collectLinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	scenByKey := map[string]bool{}
	for _, s := range specs {
		scenByKey[s.Capability+"/"+s.Slug] = true
	}
	covered := map[string]bool{}
	dangling := 0
	for _, l := range links {
		key := l.Capability + "/" + l.Slug
		if scenByKey[key] {
			covered[key] = true
		} else {
			dangling++
		}
	}
	orphans := 0
	for _, s := range specs {
		if !covered[s.Capability+"/"+s.Slug] {
			orphans++
		}
	}
	if orphans != 1 {
		t.Errorf("orphans = %d, want 1 (beta)", orphans)
	}
	if dangling != 1 {
		t.Errorf("dangling = %d, want 1 (not-in-spec)", dangling)
	}
}

// Spec-like text in a string literal is not an annotation.
func TestCollectLinksIgnoresStringLiterals(t *testing.T) {
	dir := t.TempDir()
	content := "package x\n\nconst fixture = \"// spec: demo/alpha-is-refused\"\n\nvar raw = `\n// spec: demo/beta-is-accepted\n`\n"
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	links, bad, err := collectLinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 || len(bad) != 0 {
		t.Errorf("links = %#v, malformed = %#v; want none from string literals", links, bad)
	}
}

// A key that is not exactly <capability>/<slug> is malformed, not truncated to a
// valid prefix; the complete key beside it stays valid.
func TestCollectLinksReportsMalformedKeys(t *testing.T) {
	dir := t.TempDir()
	content := `package x

// spec: demo/alpha_old
func TestOld(t *testing.T) {}

// spec: demo/alpha
func TestNew(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	links, bad, err := collectLinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0].Capability+"/"+links[0].Slug != "demo/alpha" {
		t.Errorf("links = %#v, want exactly demo/alpha", links)
	}
	if len(bad) != 1 || bad[0].FileLine != 3 {
		t.Errorf("malformed = %#v, want one at line 3 (demo/alpha_old)", bad)
	}
}

// A test file that does not parse is an error, not a file with no annotations.
func TestCollectLinksFailsOnUnparsableFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte("package x\nfunc {\n// spec: demo/alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := collectLinks(dir); err == nil {
		t.Fatal("an unparsable test file returned no error")
	}
}
