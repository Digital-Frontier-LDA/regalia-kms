//go:build piv

package yubikey

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// pivCards and pivOpen are package-level seams (#237 round two). A future test
// in this package that calls t.Parallel would race against every other test in
// the package that swaps the seam, because the swaps are not per-test mutex-
// guarded — they are t.Cleanup-restored, which is fine while tests run serially
// and unsafe the moment any test marks itself parallel.
//
// This test fails the build if any *_test.go file in this package contains a
// t.Parallel() call. It is a discipline guard, not a coverage check; the gate
// is `-race`, which catches the race when the rule is broken. Together they
// make the rule enforceable without trusting the next reader to remember it.

func TestNoTestInThisPackageCallsTParallel(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	pkgDir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var offenders []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(pkgDir, entry.Name())
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if ident.Name == "t" && sel.Sel.Name == "Parallel" {
					pos := fset.Position(call.Pos())
					offenders = append(offenders, pos.Filename+":"+strconv.Itoa(pos.Line))
				}
				return true
			})
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("t.Parallel() is forbidden in package yubikey (a package-level seam races); found at:\n  %s\n"+
			"remove the call, then re-run. -race catches the race; this guard catches the cause.",
			strings.Join(offenders, "\n  "))
	}
}
