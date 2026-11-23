package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStripRepoPrefix(t *testing.T) {
	cases := []struct {
		tok        string
		repo, path string
	}{
		{"kms/internal/policy/cosmos.go", "kms", "internal/policy/cosmos.go"},
		{"regalia/doc/SECRETS.md", "regalia", "doc/SECRETS.md"},
		{"regalia-ceremony:qubes/README.md", "ceremony", "qubes/README.md"},
		{"doc/SECRETS.md", "regalia", "doc/SECRETS.md"},
		{"bare/path.go", "", "bare/path.go"},
	}
	for _, c := range cases {
		repo, path := stripRepoPrefix(c.tok)
		if repo != c.repo || path != c.path {
			t.Errorf("stripRepoPrefix(%q) = (%q,%q), want (%q,%q)", c.tok, repo, path, c.repo, c.path)
		}
	}
}

func TestExtractTargetsFromImpact(t *testing.T) {
	dir := t.TempDir()
	proposal := `# Change

## Why
prose with a ` + "`cosmos.go`" + ` mention that is NOT in Impact and must be ignored.

## Impact
- ` + "`kms/internal/policy/cosmos.go`" + ` — the parser.
- ` + "`kms/internal/policy/cosmos.go::parseFee`" + ` — a symbol.
- ` + "`kms/internal/policy/*_test.go`" + ` — tests.
- ` + "`kms/COSMOS-SUPPORT.md`" + ` — the doc.

## Sibling dependency
- ` + "`kms/internal/policy/wire.go`" + ` — after Impact, must be ignored.
`
	p := filepath.Join(dir, "proposal.md")
	if err := os.WriteFile(p, []byte(proposal), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := extractTargets(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, g := range got {
		kinds = append(kinds, g.Kind+":"+g.Raw)
	}
	want := []string{
		"file:kms/internal/policy/cosmos.go",
		"symbol:kms/internal/policy/cosmos.go::parseFee",
		"glob:kms/internal/policy/*_test.go",
		"file:kms/COSMOS-SUPPORT.md",
	}
	if !reflect.DeepEqual(kinds, want) {
		t.Errorf("targets = %v, want %v", kinds, want)
	}
}

func TestSymbolDeclared(t *testing.T) {
	src := `package p

// parseFee is a doc comment, not a declaration by itself.
func parseFee(input []byte) ([]Coin, uint64, error) {
	return nil, 0, nil
}

type highWaterMark struct {
	Sequence uint64
}

const stateGenesisHash = "x"

var mu struct{}
`
	if !symbolDeclared(src, "parseFee") {
		t.Error("parseFee should be declared")
	}
	if !symbolDeclared(src, "highWaterMark") {
		t.Error("highWaterMark should be declared")
	}
	if !symbolDeclared(src, "stateGenesisHash") {
		t.Error("stateGenesisHash should be declared")
	}
	if symbolDeclared(src, "noSuchThing") {
		t.Error("noSuchThing should NOT be declared")
	}
}

func TestVerifyFileAndSymbol(t *testing.T) {
	kmsRoot := t.TempDir()
	gofile := filepath.Join(kmsRoot, "internal", "policy")
	if err := os.MkdirAll(gofile, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gofile, "cosmos.go"), []byte("package p\nfunc parseFee() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := map[string]string{"kms": kmsRoot, "regalia": kmsRoot}

	if ok, _ := verify(target{Kind: "file", Repo: "kms", Path: "internal/policy/cosmos.go"}, roots); !ok {
		t.Error("existing file should verify")
	}
	if ok, _ := verify(target{Kind: "file", Repo: "kms", Path: "internal/policy/missing.go"}, roots); ok {
		t.Error("missing file should not verify")
	}
	if ok, _ := verify(target{Kind: "symbol", Repo: "kms", Path: "internal/policy/cosmos.go", Symbol: "parseFee"}, roots); !ok {
		t.Error("declared symbol should verify")
	}
	if ok, _ := verify(target{Kind: "symbol", Repo: "kms", Path: "internal/policy/cosmos.go", Symbol: "gone"}, roots); ok {
		t.Error("missing symbol should not verify")
	}
}

// A name in a block comment is not a declaration; a name in a grouped const is.
func TestSymbolDeclaredParsesDeclarations(t *testing.T) {
	src := "package p\n\n/*\nfunc gone() {}\n*/\n\nconst (\n\tgroupedA = 1\n\tgroupedB = 2\n)\n\nvar s = \"func alsoGone() {}\"\n"
	if symbolDeclared(src, "gone") {
		t.Error("a func inside a block comment must not count as declared")
	}
	if symbolDeclared(src, "alsoGone") {
		t.Error("a func inside a string must not count as declared")
	}
	if !symbolDeclared(src, "groupedB") {
		t.Error("a name in a grouped const must count as declared")
	}
}

func writeChange(t *testing.T, dir, impact string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proposal.md"), []byte("# P\n\n## Impact\n\n"+impact+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A -changes root that does not exist fails; it is not "all named targets present".
func TestScanChangesReportsAMissingRoot(t *testing.T) {
	if _, err := scanChanges(filepath.Join(t.TempDir(), "no-such-dir"), map[string]string{}); err == nil {
		t.Fatal("scanChanges on a missing root returned no error")
	}
}

// A proposal.md that cannot be read fails the check rather than counting as clean.
func TestScanChangesReportsAnUnreadableProposal(t *testing.T) {
	changes := t.TempDir()
	dir := filepath.Join(changes, "broken")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A dangling symlink: unreadable for any user, root included.
	if err := os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "proposal.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := scanChanges(changes, map[string]string{"regalia": changes}); err == nil {
		t.Fatal("an unreadable proposal.md returned no error")
	}
}

// archive/ is pruned: an archived change naming a removed target does not fail
// the pending set, while the same target in a pending change does.
func TestScanChangesSkipsTheArchive(t *testing.T) {
	changes := t.TempDir()
	roots := map[string]string{"regalia": changes, "kms": changes}
	writeChange(t, filepath.Join(changes, "archive", "old-change"), "- `kms/removed-long-ago.md`")
	n, err := scanChanges(changes, roots)
	if err != nil || n != 0 {
		t.Fatalf("archived change was checked: missing=%d err=%v", n, err)
	}
	// Control: the same target in a pending change is reported missing.
	writeChange(t, filepath.Join(changes, "pending-change"), "- `kms/removed-long-ago.md`")
	n, err = scanChanges(changes, roots)
	if err != nil || n != 1 {
		t.Fatalf("pending change: missing=%d err=%v, want 1 missing", n, err)
	}
}
