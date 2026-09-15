package config

// GUARD COVERAGE (#237 sweep): 63 mutations across `internal/config` and
// `adapters/sops/sopsrpc`, verdicts from exit codes. sopsrpc survived nothing — both its
// guards are detected, and it is recorded as checked-and-clear rather than left unexamined.
// config survived 15, and the shape of them is the finding:
//
// THREE RANGE CHECKS EACH HAD EXACTLY ONE SIDE TESTED, AND THEY ALTERNATE WHICH SIDE.
// operation_timeout's lower bound, shutdown_timeout's upper, max_concurrent_operations'
// upper. Every one of the three already had a test, so nothing looked missing; a
// whole-guard mutation is killed by the tested half and only a per-operand pass shows it.
//
// THE PRINCIPAL VALIDATOR HAD ONE RULE OF FOUR TESTED — the spiffe:// prefix. Over-length
// and embedded-whitespace entries were undetected and are pinned here. The empty-length
// operand is NOT a gap and is not claimed as one: see the §17 note at that row.
//
// Each row below is the operand that survived, and each fixture is built so the guard under
// test is the ONLY thing that can refuse: values sit one step outside the bound with every
// other field valid, and the oversize document is padded with JSON whitespace so it still
// parses.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// EVERY RANGE IS A RANGE AT BOTH ENDS. A bound tested on one side only is a bound that can
// be widened on the other without any test noticing — and for these three the untested half
// differs each time, so "it has a test" was true of all three.
func TestEveryDurationAndCountBoundIsRefusedAtBothEnds(t *testing.T) {
	for _, row := range []struct {
		name    string
		mutate  func(*Config)
		wantMsg string
	}{
		{"operation_timeout below the floor", func(c *Config) { c.OperationTimeout = 99 * time.Millisecond }, "operation_timeout"},
		{"operation_timeout above the ceiling", func(c *Config) { c.OperationTimeout = 10*time.Minute + time.Millisecond }, "operation_timeout"},
		{"shutdown_timeout below the floor", func(c *Config) { c.ShutdownTimeout = 999 * time.Millisecond }, "shutdown_timeout"},
		{"shutdown_timeout above the ceiling", func(c *Config) { c.ShutdownTimeout = 2*time.Minute + time.Millisecond }, "shutdown_timeout"},
		{"max_concurrent_operations below the floor", func(c *Config) { c.MaxConcurrentOperations = 0 }, "max_concurrent_operations"},
		{"max_concurrent_operations above the ceiling", func(c *Config) { c.MaxConcurrentOperations = 65 }, "max_concurrent_operations"},
	} {
		t.Run(row.name, func(t *testing.T) {
			cfg := baseConfig()
			row.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("a value one step outside the %s bound was accepted — a range checked on one side is not a range", row.wantMsg)
			}
			if !strings.Contains(err.Error(), row.wantMsg) {
				t.Fatalf("refused, but by a different rule: %v — this row exists to prove the %s bound fires", err, row.wantMsg)
			}
		})
	}

	// KNOWN-GOOD IN THE SAME TEST (§18): the in-range configuration these rows are derived
	// from must still validate, or every assertion above would be satisfied by a rule that
	// refuses everything.
	if err := baseConfig().Validate(); err != nil {
		t.Fatalf("the in-range base configuration was refused (%v) — the rows above prove nothing against a rule that refuses every config", err)
	}
}

// A PRINCIPAL THAT CANNOT AUTHENTICATE IS A SILENT NO-OP, WHICH IS WHY ALL FOUR RULES MATTER.
// The comment at the guard says exactly this and only the prefix rule was pinned.
func TestEveryMetricsPrincipalRuleRefuses(t *testing.T) {
	// §17 ON THE EMPTY-LENGTH OPERAND, measured rather than assumed. `len(principal) == 0`
	// survives its own mutation even with the row below present, because it can never be the
	// SOLE refuser: an empty string also fails the prefix rule, and the shortest string that
	// satisfies that rule is 17 bytes. No input reaches the length operand alone, so no test
	// can pin it and this file does not pretend to. The row stays as a behaviour pin — an
	// empty entry IS refused — but it is not evidence for that operand.
	//
	// I wrote this row believing it covered the operand, and the falsification pass said
	// otherwise: exit 0, nothing failed. Red by the wrong detector, in the test written to
	// close exactly that class.
	for _, row := range []struct{ name, principal string }{
		{"empty", ""},
		{"over 256 bytes", "spiffe://regalia/" + strings.Repeat("a", 256)},
		{"embedded space", "spiffe://regalia/metrics reader"},
		{"embedded tab", "spiffe://regalia/metrics\treader"},
		{"embedded newline", "spiffe://regalia/metrics\nreader"},
		{"wrong trust domain", "spiffe://elsewhere/metrics"},
	} {
		t.Run(row.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.MetricsReaderPrincipals = []string{row.principal}
			if err := cfg.Validate(); err == nil {
				t.Fatalf("metrics_reader_principals accepted %q — an entry that can never authenticate is a silent no-op, not a permission", row.principal)
			}
		})
	}

	// KNOWN-GOOD (§18): a well-formed principal is accepted, so the rows above are not
	// passing against a validator that refuses every entry.
	cfg := baseConfig()
	cfg.MetricsReaderPrincipals = []string{"spiffe://regalia/metrics-reader"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a well-formed spiffe principal was refused: %v", err)
	}
}

// THE CONFIGURATION MUST BE A REGULAR FILE. The fixture is a DIRECTORY with mode 0700, not
// /dev/null: /dev/null is world-writable, so the permission check two lines below would also
// refuse it and this row would pass without ever reaching the guard it names.
func TestAConfigurationThatIsNotARegularFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config-as-directory")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("a directory was accepted as the configuration file")
	}
	if !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("refused, but not by the file-shape guard: %v — 0700 was chosen so the group/world-writable rule cannot fire", err)
	}
}

// OVER THE SIZE BOUND, AND STILL VALID JSON. Padding with whitespace rather than junk is what
// isolates the guard: a malformed oversize document is refused by the decoder, and this row
// would pass with the size check deleted.
func TestAConfigurationOverTheSizeBoundIsRefusedBeforeItIsParsed(t *testing.T) {
	document := `{"listen_address":"127.0.0.1:8443"}` + strings.Repeat(" ", maxConfigBytes)
	if len(document) <= maxConfigBytes {
		t.Fatalf("the fixture is %d bytes, not over the %d bound — it cannot reach the guard", len(document), maxConfigBytes)
	}
	_, err := Decode(strings.NewReader(document))
	if err == nil {
		t.Fatal("a configuration over the size bound was decoded")
	}
	if !strings.Contains(err.Error(), "32 KiB") {
		t.Fatalf("refused, but not by the size guard: %v — the padding is whitespace precisely so the parser has nothing to object to", err)
	}

	// KNOWN-GOOD (§18): the same document under the bound decodes, so the row is about size
	// and not about the shape of the fixture.
	if _, err := Decode(strings.NewReader(`{"listen_address":"127.0.0.1:8443"}`)); err != nil {
		t.Fatalf("the unpadded document was refused: %v", err)
	}
}
