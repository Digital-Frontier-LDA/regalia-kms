package sweeptext

import (
	"strings"
	"testing"
)

const citedSource = `package cited

type store struct{ closed bool }

type cache[K comparable] struct{ open bool }

func open(path string) error {
	file, err := create(path)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	switch {
	case info == "":
	case info == "":
	}
	return nil
}

func (s *store) close() bool {
	if s.closed {
		return false
	}
	return true
}

func (s store) name() string { return "store" }

func (c *cache[K]) ready() bool {
	// c.closed is not checked here
	if c.open && c != nil {
		return true
	}
	return false
}

type pair[K, V any] struct{}

func (p pair[K, V]) get() bool { return true }

func far() error {
	_, err := create("x")
	_ = 1
	if err != nil {
		return err
	}
	_, err = create("y")
	// a note between the call and its check

	if err != nil {
		return err
	}
	return nil
}
`

func sourcesOf(source string) Sources {
	return func(string) (string, error) { return source, nil }
}

// Each anchor form names the line it should, for each receiver spelling.
func TestCitationResolvesEachForm(t *testing.T) {
	for citation, want := range map[string]string{
		"cited.go:open{create(path) then err != nil}[0]": "\tif err != nil {",
		"cited.go:open{file.Stat() then err != nil}[0]":  "\tif err != nil {",
		`cited.go:open{info == \"\"#2}[0]`:               "\tcase info == \"\":",
		"cited.go:(*store).close{s.closed}[0]":           "\tif s.closed {",
		"cited.go:(store).name{return}":                  "func (s store) name() string { return \"store\" }",
		"cited.go:(*cache).ready{c.open && c != nil}[1]": "\tif c.open && c != nil {",
		"cited.go:(pair).get{return true}":               "func (p pair[K, V]) get() bool { return true }",
		"cited.go:far{create(\"y\") then err != nil}[0]": "\tif err != nil {",
	} {
		_, have, err := ResolveCitation(sourcesOf(citedSource), citation)
		if err != nil || have != want {
			t.Errorf("%s: have %q, %v; want %q", citation, have, err, want)
		}
	}
}

// What an anchor cannot do: name no line, name two, name a comment, use #n on a unique text,
// skip a line of code between a call and its check, or name a function the file does not declare.
func TestCitationRefusesWhatNamesNoOneLine(t *testing.T) {
	for citation, refusal := range map[string]string{
		"cited.go:open{err != nil}[0]":                "on 2 lines of open",
		"cited.go:open{no such text}[0]":              "on 0 lines of open",
		"cited.go:(*store).close{s.closed#1}[0]":      "#1 is for a text written more than once",
		`cited.go:open{info == \"\"#3}[0]`:            "not 3",
		"cited.go:far{create(\"x\") then err != nil}": "or the next line of code",
		"cited.go:(*cache).ready{c.closed}[0]":        "on 0 lines",
		"cited.go:(store).close{s.closed}[0]":         "declares no function (store).close",
		"cited.go:shut{s.closed}[0]":                  "declares no function shut",
		"cited.go:42[0]":                              "not a citation",
	} {
		_, _, err := ResolveCitation(sourcesOf(citedSource), citation)
		if err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%s: have %v, want a refusal holding %q", citation, err, refusal)
		}
	}
}

// The reason for the form: a line added above every guard changes no citation's text.
func TestCitationIgnoresALineAddedAbove(t *testing.T) {
	shifted := strings.Replace(citedSource, "package cited\n", "package cited\n\n// added\n", 1)
	for _, citation := range []string{"cited.go:open{file.Stat() then err != nil}[0]", "cited.go:(*store).close{s.closed}[0]"} {
		line, text, _ := ResolveCitation(sourcesOf(citedSource), citation)
		moved, movedText, err := ResolveCitation(sourcesOf(shifted), citation)
		if err != nil || movedText != text || moved != line+2 {
			t.Errorf("%s: line %d %q, then %d %q (%v)", citation, line, text, moved, movedText, err)
		}
	}
}

// A sweep in flight: the guard reads as written, not as the wrapper.
func TestCitationResolvesThroughAMutationWrapper(t *testing.T) {
	mutated := strings.Replace(citedSource, "if s.closed {", "if false && (s.closed) {", 1)
	_, text, err := ResolveCitation(func(string) (string, error) { return StripMutationWrappers(mutated), nil }, "cited.go:(*store).close{s.closed}[0]")
	if err != nil || text != "\tif s.closed {" {
		t.Errorf("have %q, %v", text, err)
	}
}
