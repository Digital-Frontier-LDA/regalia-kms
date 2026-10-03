package sweeptext

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// A ledger cites a guard as "file.go:Func{anchor}[i]": the function the guard is in, a piece of
// the guard's own text, and i the operand index (#282). The citation names no line number, so an
// edit elsewhere in the file changes no citation. A line number did: one field added to
// audit.Event renumbered 61 citations of audit.go, none of them about the change.
//
// SHARED FOR THE SAME REASON AS StripMutationWrappers. Two ledgers cite guards (internal/audit and
// internal/backend/yubikey); one resolver keeps one spelling and one set of refusals.

// CitationPattern is one citation; the operand index is optional in prose. The function is Name,
// (T).Name or (*T).Name. An anchor holds no braces.
var CitationPattern = regexp.MustCompile(`\b([a-z_]+\.go):((?:\(\*?[A-Za-z_]\w*\)\.)?[A-Za-z_]\w*)\{([^{}]+)\}(\[\d+\])?`)

// LineCitationPattern is the form #282 retired, "file.go:N[i]": a line number, renumbered by every
// edit above it. A ledger allows it only as history ("Was …", "formerly …", group 1), naming where
// a row used to be.
var LineCitationPattern = regexp.MustCompile(`(?i)(was |formerly )?\b([a-z_]+\.go):(\d+)\b`)

// Sources reads a cited file by its base name.
type Sources func(file string) (string, error)

// DirSources reads the files of dir through StripMutationWrappers, so a citation resolves during
// an in-flight sweep -- without the strip, a row whose guard has just been mutated would go red on
// its own drift guard, and a sweep harness reading a red as KILLED would retire the operand as
// covered when nothing detects it.
func DirSources(dir string) Sources {
	return func(file string) (string, error) {
		data, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return "", err
		}
		return StripMutationWrappers(string(data)), nil
	}
}

// ResolveCitation finds the source line a citation names, and returns it with its text (trailing
// blanks trimmed).
//
// The function is found by the parser, and the anchor is searched only within its declaration,
// and only in its code: comments are blanked first, so a comment that still says the anchor text
// after the guard is gone cannot stand in for it (regalia-kms-d9).
//   - {text}: the one line of the function holding text. None, or more than one, is an error: an
//     ambiguous anchor names no line.
//   - {text#n}: the n-th line holding text, for a guard written twice word for word in one
//     function; refused when text is on one line only, so every citation has one spelling.
//   - {first then text}: for the guards whose own text is not unique, `err != nil` after the call
//     that set err. text must be on the one line holding first, or on the next line holding code;
//     a line put between them is an error, not a citation that silently moves to another guard.
//
// A `\"` in the anchor is read as `"`, so a citation quoted inside a Go string resolves as written.
func ResolveCitation(sources Sources, citation string) (int, string, error) {
	match := CitationPattern.FindStringSubmatch(citation)
	if match == nil || match[0] != citation {
		return 0, "", fmt.Errorf("not a citation of the form file.go:Func{anchor}[i]")
	}
	file, function, anchor := match[1], match[2], strings.ReplaceAll(match[3], `\"`, `"`)
	source, err := sources(file)
	if err != nil {
		return 0, "", err
	}
	positions := token.NewFileSet()
	parsed, err := parser.ParseFile(positions, file, source, parser.SkipObjectResolution|parser.ParseComments)
	if err != nil {
		return 0, "", err
	}
	lines := strings.Split(source, "\n")
	code := []byte(source)
	for _, group := range parsed.Comments {
		for offset := positions.Position(group.Pos()).Offset; offset < positions.Position(group.End()).Offset; offset++ {
			if code[offset] != '\n' {
				code[offset] = ' '
			}
		}
	}
	codeLines := strings.Split(string(code), "\n")
	first, last := 0, 0
	for _, declaration := range parsed.Decls {
		decl, ok := declaration.(*ast.FuncDecl)
		if !ok || declName(decl) != function {
			continue
		}
		if first != 0 {
			return 0, "", fmt.Errorf("%s declares %s twice", file, function)
		}
		first, last = positions.Position(decl.Pos()).Line, positions.Position(decl.End()).Line
	}
	if first == 0 {
		return 0, "", fmt.Errorf("%s declares no function %s", file, function)
	}
	text, then, chained := strings.Cut(anchor, " then ")
	occurrence := 0
	if hash := strings.LastIndex(text, "#"); hash >= 0 {
		if n, err := strconv.Atoi(text[hash+1:]); err == nil && n >= 1 {
			text, occurrence = text[:hash], n
		}
	}
	var holding []int
	for number := first; number <= last; number++ {
		if strings.Contains(codeLines[number-1], text) {
			holding = append(holding, number)
		}
	}
	switch {
	case occurrence != 0 && len(holding) < 2:
		return 0, "", fmt.Errorf("%q is on %d line(s) of %s: #%d is for a text written more than once", text, len(holding), function, occurrence)
	case occurrence != 0 && occurrence > len(holding):
		return 0, "", fmt.Errorf("%q is on %d lines of %s, not %d", text, len(holding), function, occurrence)
	case occurrence != 0:
		holding = holding[occurrence-1 : occurrence]
	case len(holding) != 1:
		return 0, "", fmt.Errorf("%q is on %d lines of %s: an anchor must name one", text, len(holding), function)
	}
	line := holding[0]
	if chained && !strings.Contains(codeLines[line-1], then) {
		next := line + 1
		for next <= last && strings.TrimSpace(codeLines[next-1]) == "" {
			next++
		}
		if next > last || !strings.Contains(codeLines[next-1], then) {
			return 0, "", fmt.Errorf("%q is not on the line holding %q or the next line of code in %s", then, text, function)
		}
		line = next
	}
	return line, strings.TrimRight(lines[line-1], " \t\r"), nil
}

// declName is a function's name as a citation spells it: Name, (T).Name or (*T).Name.
func declName(decl *ast.FuncDecl) string {
	if decl.Recv == nil || len(decl.Recv.List) == 0 {
		return decl.Name.Name
	}
	receiver := decl.Recv.List[0].Type
	star := ""
	if pointer, ok := receiver.(*ast.StarExpr); ok {
		receiver, star = pointer.X, "*"
	}
	switch generic := receiver.(type) {
	case *ast.IndexExpr:
		receiver = generic.X
	case *ast.IndexListExpr:
		receiver = generic.X
	}
	if ident, ok := receiver.(*ast.Ident); ok {
		return "(" + star + ident.Name + ")." + decl.Name.Name
	}
	return decl.Name.Name
}
