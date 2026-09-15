package telemetry

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE CONTRACT DOCUMENT MUST NOT BE ABLE TO PROMISE A SERIES NOTHING EMITS.
//
// Three things have to agree: OBSERVABILITY.md (the promise), the alert rules (what pages),
// and this package (what is actually rendered). Two of the three pairs were already checked
// -- kms/tests/test_alert_rules.py pins rules against the document, and
// kms/tests/test_alert_firing.py drives a fault at every rule -- but the third pair was not.
//
// TestRenderedSeriesCarryTheirValueAndFreshness (in telemetry_test.go) reads a list written
// out by hand there, so "promised" meant "remembered", not "documented". A series added to the
// document and given a rule, but never emitted, satisfies both existing checks: the document
// and the rules agree with each other, and the hand-written list simply never mentions it.
// The result is a rule that cannot fire, which is the failure the document itself calls out
// -- "a rule naming a series nothing emits pages nobody about nothing".
//
// This closes that pair by deriving the expectation from the document instead of from memory.
func TestEveryDocumentedSeriesIsActuallyEmitted(t *testing.T) {
	documented := documentedSeries(t)
	if len(documented) < 15 {
		t.Fatalf("only %d series parsed from OBSERVABILITY.md: the table shape changed and this "+
			"test would pass while checking almost nothing", len(documented))
	}

	handler := NewHandler(NewCollector([]string{"/v1/operations/sign"}), fullSources(),
		[]string{"spiffe://regalia/operator/monitoring"})
	// Scrape twice: the first request is what gives the request counters a sample to report,
	// so a counter that only appears after traffic is still covered here.
	requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path)
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

	for _, name := range documented {
		if !strings.Contains(body, name) {
			t.Errorf("OBSERVABILITY.md documents %s and a fully-sourced scrape never emits it: "+
				"any alert on it can never fire", name)
		}
	}
}

// The reverse direction: something rendered but undocumented is a surface nobody agreed to.
func TestEveryEmittedSeriesIsDocumented(t *testing.T) {
	documented := map[string]bool{}
	for _, name := range documentedSeries(t) {
		documented[name] = true
	}

	handler := NewHandler(NewCollector([]string{"/v1/operations/sign"}), fullSources(),
		[]string{"spiffe://regalia/operator/monitoring"})
	requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path)
	body := requestAs(t, handler, "spiffe://regalia/operator/monitoring", http.MethodGet, Path).Body.String()

	emitted := regexp.MustCompile(`(?m)^(?:# (?:HELP|TYPE) )?(regalia_[a-z0-9_]+)`)
	seen := map[string]bool{}
	for _, match := range emitted.FindAllStringSubmatch(body, -1) {
		seen[match[1]] = true
	}
	if len(seen) == 0 {
		t.Fatal("no series were parsed out of the scrape: this test would pass while checking nothing")
	}
	for name := range seen {
		if !documented[name] {
			t.Errorf("the scrape emits %s and OBSERVABILITY.md does not document it: "+
				"an undocumented series carries no agreed alert condition", name)
		}
	}
}

// documentedSeries reads the series column of the OBSERVABILITY.md table.
func documentedSeries(t *testing.T) []string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "OBSERVABILITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(root)
	if err != nil {
		t.Fatalf("cannot read the observability contract: %v", err)
	}
	var names []string
	inTable := false
	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, "| Series") {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		if strings.HasPrefix(line, "| ---") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		name := strings.Trim(strings.TrimSpace(cells[0]), "`")
		if strings.HasPrefix(name, "regalia_") {
			names = append(names, name)
		}
	}
	return names
}
