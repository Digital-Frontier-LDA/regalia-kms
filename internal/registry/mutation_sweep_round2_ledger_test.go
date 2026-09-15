package registry

// ROUND 2 OF THE #237 MUTATION SWEEP — REGISTRY LAYER (REVISED).
//
// Re-derived on origin/main (c976467) with kms/tools/guardenum, built in
// this worktree:
//
//   guardenum sha256: 4c135057fd6c486920a03da3074db7483fceaf1b5597b11ad787f4aecd14218a
//
// Population: 120 sites / 164 operands / 328 operand-directions. Reconciles
// with the peer's 1cb2af1 measurement at the prior commit (30464dd)
// bit-for-bit: registry.go did not change between 30464dd and c976467.
//
// THE DRIFT GUARD. v1 used absolute byte offsets into registry.go. A peer
// measurement showed that inserting a single comment line above any row
// shifts the byte window for every later row, producing a "drift" that
// does not exist (19 of 19 rows red, the guard reports the source as
// broken when the actual bytes are unchanged). The cause is structural:
// byte offsets are positions-in-the-whole-file, so any insertion upstream
// invalidates them. The fix in this revision: compare by LINE TEXT.
//
// For each row, the ledger records `Site` — the verbatim source line the
// sweep measured — and `LineNo`. The drift guard reads registry.go,
// splits on newline, takes `lines[LineNo-1]`, runs
// sweeptext.StripMutationWrappers on THAT line (NOT the whole file, to
// avoid stranding a wrapper that crosses lines), and compares to `Site`.
// A comment inserted anywhere else is now invisible; a wrapper dropped on
// the row's own line is restored; an edit on the row's own line that
// changes `Site` makes the guard red.
//
// IDIOMATOLOGY. The shared stripper in kms/internal/sweeptext (DEV5, #379,
// drift-pinned by #381) handles all five documented wrapper shapes
// including the single-operand form. The per-line strip in the drift
// guard takes the same path the audit package takes in
// kms/internal/audit/ledger_test.go:466 — split on \n, strip the line
// the row cites, compare against the recorded `Site`.
//
// THE MASKED BUCKET. Round-1 used NEUTRAL polarity `(false && x)` for
// every operand, regardless of chain. For `||` chains this is the
// passive direction: an operand whose contribution the suite never sees
// when neutralised can still be load-bearing when DOMINATED. Round-2's
// control arm flipped to `(true || x)` for the 19 SURVIVED rows and
// re-ran the suite: ALL 19 KILLED in the opposite polarity, none
// survived both. The MASKED bucket records that pair: M-alone SURVIVED,
// Control KILLED, every row. Round 1's "single direction suffices"
// hypothesis is falsified for this layer.
//
// The distribution (population = 164):
//
//	KILLED       145
//	MASKED       19
//	PANIC         0
//	BUILD-FAILED  0
//	TIMEOUT       0
//
// PER-ROW ANATOMY.
//
//	ID                  "registry.go:LINE[op]"
//	LineNo              line in registry.go where Site is taken from
//	Site                verbatim source line; drift guard compares this
//	Operand             the byte slice the sweep measured at LineNo
//	Join                "||" / "&&" for chains; "" for sole operand.
//	                    The honest value matters — a future round's
//	                    polarity choice depends on it.
//	MAlone              SURVIVED | KILLED for round-1's (false && x)
//	Control             SURVIVED | KILLED for round-2's (true || x)
//	ControlFailingCount count of FAIL: lines in the control arm run
//	Detector            name of test that exercises the operand ("" if
//	                    none — a MASKED row's contribution is unmapped)
//	MaskedBy            multi-operand: sibling operand ID; sole-operand:
//	                    the parent-function guard that catches the joint
//	                    bypass (best-effort inference; joint-experiment
//	                    pending for sole-operand rows)
//	Notes               prose: defect class + masking story per row
//	Bucket              MASKED
//
// THE LEDGER IS THE TEST. There are NO file-reading tests. The
// cross-check that the embedded counts equal the sweep output lives in
// the PR description, where the measurement file does not have to ship.

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/sweeptext"
)

// ledgerRow is one row of the round-2 ledger. See the file header for the
// definition of every field.
type ledgerRow struct {
	ID                  string
	LineNo              int
	Site                string
	Operand             string
	Join                string
	MAlone              string
	Control             string
	ControlFailingCount int
	Detector            string
	MaskedBy            string
	Notes               string
	Bucket              string
}

// sweepSurvivors is the table of every survivor from round-1 verified
// against the on-disk `.sweep/registry_enum.txt` at sweep time and the
// control arm's failing-test SETs. Each row's `Site` is the verbatim
// line text from registry.go at the row's `LineNo` on current main
// (c976467); TestSweepLedgerRowsNameLiveSource re-reads the file and
// asserts Site still matches after stripping in-flight sweep wrappers.
var sweepSurvivors = []ledgerRow{
	// === Sole-operand err != nil checks ===

	// rotationDeadline: json.Unmarshal(raw, &policy) at the top of the
	// unmarshal-and-check chain. L273 (MaximumAgeDays/LastRotated check)
	// catches the joint bypass when the JSON parses but the policy is
	// semantically empty; the `(false && err != nil)` neutral keeps
	// unmarshal on its original path, and the round-1 sweep did not
	// construct an input where that path's err value matters.
	{
		ID: "registry.go:270[0]", LineNo: 270,
		Site:    "\tif err := json.Unmarshal(raw, &policy); err != nil {",
		Operand: "err != nil", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 71,
		Detector: "",
		MaskedBy: "registry.go:273[0]",
		Notes:    "joint bypass when rotation deadline is malformed; the round-2 control arm triggers the explicit error path on 71 failing tests",
		Bucket:   "MASKED",
	},

	// envelopeMaxAge: json.Unmarshal(policy.EnvelopeMaxAgeDays, &days).
	// Masked by L292 (len == 0 returns 0): any test that exercises the
	// unmarshal path passes L292 only when EnvelopeMaxAgeDays is set,
	// and 297 more importantly L304 (days < 1 check) catches integer
	// negatives immediately.
	{
		ID: "registry.go:299[0]", LineNo: 299,
		Site:    "\tif err := json.Unmarshal(policy.EnvelopeMaxAgeDays, &days); err != nil {",
		Operand: "err != nil", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 3,
		Detector: "",
		MaskedBy: "registry.go:304[0]",
		Notes:    "sole operand; the L304 days<1 check catches the wrong-integer case before the if fires; joint-experiment for the err-side bypass pending",
		Bucket:   "MASKED",
	},

	// LoadFile: os.Open err check. Masked by the very next guard at
	// L374 (info.Mode().IsRegular check) — any test that opens a
	// regular file passes L374, and L374 fires first if the file's
	// mode bits are wrong.
	{
		ID: "registry.go:366[0]", LineNo: 366,
		Site:    "\tif err != nil {",
		Operand: "err != nil", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 71,
		Detector: "",
		MaskedBy: "registry.go:374[0]",
		Notes:    "sole operand in LoadFile's open/stat/mode chain; L374 mode check is the catch-the-bypass guard",
		Bucket:   "MASKED",
	},

	// LoadFile: file.Stat err check. L374 (mode check) follows.
	{
		ID: "registry.go:371[0]", LineNo: 371,
		Site:    "\tif err != nil {",
		Operand: "err != nil", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 3,
		Detector: "",
		MaskedBy: "registry.go:374[0]",
		Notes:    "sole operand; mode-bits check at L374 catches before the stat-err path matters for round-1 tests",
		Bucket:   "MASKED",
	},

	// Load: selectBinding(..., site) err check. The L420
	// validateObject check fires first and refuses a malformed binding
	// before the selectBinding call.
	{
		ID: "registry.go:427[0]", LineNo: 427,
		Site:    "\t\tif err != nil {",
		Operand: "err != nil", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 71,
		Detector: "",
		MaskedBy: "registry.go:420[0]",
		Notes:    "sole operand in Load's per-object validation chain; validateObject refusal pre-empts selectBinding errors",
		Bucket:   "MASKED",
	},

	// Load: rotationDeadline err check. Masked by L438
	// envelopeMaxAge — both read object.Rotation; L438's
	// `EnvelopMaxAgeDays set with malformed days` test path trips
	// envelopeMaxAge first.
	{
		ID: "registry.go:435[0]", LineNo: 435,
		Site:    "\t\tif err != nil {",
		Operand: "err != nil", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 71,
		Detector: "",
		MaskedBy: "registry.go:438[0]",
		Notes:    "sole operand; envelopeMaxage (L438) precedes rotationDeadline error visibility in the round-1 test paths",
		Bucket:   "MASKED",
	},

	// supports: !ok check in the algorithm-table lookup. Masked by
	// L932 (algorithms[algorithm][operation] returns false) — when
	// !ok is bypassed (made true), the table access panics, which
	// round-1's tests do not exercise.
	{
		ID: "registry.go:929[0]", LineNo: 929,
		Site:    "\tif !ok {",
		Operand: "!ok", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 76,
		Detector: "",
		MaskedBy: "registry.go:932[0]",
		Notes:    "sole operand; the post-map-lookup access at L932 returns the operation's truth value without an intermediate !ok short-circuit",
		Bucket:   "MASKED",
	},

	// selectBindingForState: !found check after the for-loop. Masked
	// by L942 (multiple-active-bindings) and L962 (wrong-state
	// continue) — round-1 tests provide either zero bindings (caught
	// at L970) or many-but-not-many-on-right-site bindings (caught at
	// L942).
	{
		ID: "registry.go:970[0]", LineNo: 970,
		Site:    "\tif !found {",
		Operand: "!found", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 7,
		Detector: "",
		MaskedBy: "registry.go:942[0]",
		Notes:    "sole operand at the loop's exit; round-1 tests do not exercise the no-allowed-state end case",
		Bucket:   "MASKED",
	},

	// === Multi-operand || chains ===

	// Registry.clock: registry == nil checks first; the sibling [1]
	// catches the joint bypass via the `else now()`-with-nil path.
	{
		ID: "registry.go:977[0]", LineNo: 977,
		Site:    "\tif registry == nil || registry.now == nil {",
		Operand: "registry == nil", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 1,
		Detector: "",
		MaskedBy: "registry.go:977[1]",
		Notes:    "first operand of the nil-receiver/now-func chain; sibling [1] masks via the same if",
		Bucket:   "MASKED",
	},
	{
		ID: "registry.go:977[1]", LineNo: 977,
		Site:    "\tif registry == nil || registry.now == nil {",
		Operand: "registry.now == nil", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 1,
		Detector: "",
		MaskedBy: "registry.go:977[0]",
		Notes:    "second operand of the same chain; sibling [0] masks it; the if uses `time.Now()` as the fallback, so neither side fires when both are masked",
		Bucket:   "MASKED",
	},

	// Registry.Route: the assigned-or-health-or-healthy chain. Three
	// operands. Round-1's neutral hides one operand; the other two
	// still trip the if. round-2's polarity forces the if always true
	// and triggers the explicit CodeDependencyUnavailable error path.
	{
		ID: "registry.go:999[0]", LineNo: 999,
		Site:    "\tif !entry.assigned || registry.health == nil || !safeHealthy(ctx, registry.health, entry.route.Binding) {",
		Operand: "!entry.assigned", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 7,
		Detector: "",
		MaskedBy: "registry.go:999[1]",
		Notes:    "first of three operands in Route's dependency-unavailable chain; siblings [1] and [2] catch the joint bypass",
		Bucket:   "MASKED",
	},
	{
		ID: "registry.go:999[1]", LineNo: 999,
		Site:    "\tif !entry.assigned || registry.health == nil || !safeHealthy(ctx, registry.health, entry.route.Binding) {",
		Operand: "registry.health == nil", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 7,
		Detector: "",
		MaskedBy: "registry.go:999[0]",
		Notes:    "second of three operands; sibling [0] catches; sibling [2] is the equivalent health-call operand on the same chain",
		Bucket:   "MASKED",
	},

	// Route: isCustodyRecord check. Sole-operand, but masked by earlier
	// route-validation guards (L985/L988/L991) that catch the same
	// downstream effect on round-1's tests.
	{
		ID: "registry.go:1039[0]", LineNo: 1039,
		Site:    "\tif isCustodyRecord(entry.custody) {",
		Operand: "isCustodyRecord(entry.custody)", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 9,
		Detector: "",
		MaskedBy: "registry.go:985[0]",
		Notes:    "sole operand in Route's denial chain; L985 (entries-not-found) pre-empts the custody refusal for round-1's test inputs",
		Bucket:   "MASKED",
	},

	// RouteForKEKVersion: registry.health check paired with
	// safeHealthy. Two operands; sibling [1] masks.
	{
		ID: "registry.go:1089[0]", LineNo: 1089,
		Site:    "\tif registry.health == nil || !safeHealthy(ctx, registry.health, selected) {",
		Operand: "registry.health == nil", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 6,
		Detector: "",
		MaskedBy: "registry.go:1089[1]",
		Notes:    "first of two operands in RouteForKEKVersion's dependency-unavailable chain",
		Bucket:   "MASKED",
	},

	// RouteForSeal: isCustodyRecord check. Masked by L1127 (operations
	// set does not contain "seal-envelope").
	{
		ID: "registry.go:1130[0]", LineNo: 1130,
		Site:    "\tif isCustodyRecord(entry.custody) {",
		Operand: "isCustodyRecord(entry.custody)", Join: "",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 7,
		Detector: "",
		MaskedBy: "registry.go:1127[0]",
		Notes:    "sole operand in RouteForSeal's denial chain; L1127 (operations check) pre-empts the custody refusal for seal's test inputs",
		Bucket:   "MASKED",
	},

	// RouteForSeal: registry.health check paired with safeHealthy.
	{
		ID: "registry.go:1142[0]", LineNo: 1142,
		Site:    "\tif registry.health == nil || !safeHealthy(ctx, registry.health, binding) {",
		Operand: "registry.health == nil", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 6,
		Detector: "",
		MaskedBy: "registry.go:1142[1]",
		Notes:    "first of two operands in RouteForSeal's dependency-unavailable chain",
		Bucket:   "MASKED",
	},

	// Registry.Ready: entries-empty || health-nil. Two operands;
	// sibling [1] masks.
	{
		ID: "registry.go:1162[0]", LineNo: 1162,
		Site:    "\tif len(registry.entries) == 0 || registry.health == nil {",
		Operand: "len(registry.entries) == 0", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 3,
		Detector: "",
		MaskedBy: "registry.go:1162[1]",
		Notes:    "first of two operands in Ready's early-exit chain; sibling [1] catches the joint bypass",
		Bucket:   "MASKED",
	},
	{
		ID: "registry.go:1162[1]", LineNo: 1162,
		Site:    "\tif len(registry.entries) == 0 || registry.health == nil {",
		Operand: "registry.health == nil", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 3,
		Detector: "",
		MaskedBy: "registry.go:1162[0]",
		Notes:    "second operand; sibling [0] masks it",
		Bucket:   "MASKED",
	},

	// Ready's per-entry operability check. Two operands; sibling [1]
	// masks via the safeHealthy refutation.
	{
		ID: "registry.go:1176[0]", LineNo: 1176,
		Site:    "\t\tif !entry.assigned || !safeHealthy(ctx, registry.health, entry.route.Binding) {",
		Operand: "!entry.assigned", Join: "||",
		MAlone: "SURVIVED", Control: "KILLED", ControlFailingCount: 3,
		Detector: "",
		MaskedBy: "registry.go:1176[1]",
		Notes:    "first of two operands in per-entry operability check; siblings [1] catches the joint bypass",
		Bucket:   "MASKED",
	},
}

// sweepOutcomeTotals is the round-1 distribution. The MASKED count is
// the row count of sweepSurvivors, which TestSweepLedgerBucketsSumToThePopulation
// pins against this constant.
const (
	sweepKilled    = 145
	sweepMasked    = 19
	sweepPanic     = 0
	sweepBuildFail = 0
	sweepTimeout   = 0
)

// registrySourcePath resolves to internal/registry/registry.go from
// this test's runtime location. The package directory is found via
// runtime.Caller so the test is independent of `cd` and the go-test
// invocation path.
func registrySourcePath() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return thisFile[:len(thisFile)-len("mutation_sweep_round2_ledger_test.go")] + "registry.go"
}

// TestSweepLedgerSurvivorsAreAllMasked asserts the verdict pattern that
// drives round-2: every survivor is MASKED — MAlone SURVIVED and Control
// KILLED. If a future sweep introduces a bucket other than MASKED, this
// test will fail and force the bucket label to be re-derived.
//
// The MASKED verdict pair is also what the per-row "Bucket" string must
// match, so a typo in the table will fail this test rather than slip
// through silently.
func TestSweepLedgerSurvivorsAreAllMasked(t *testing.T) {
	for _, r := range sweepSurvivors {
		if r.MAlone != "SURVIVED" {
			t.Errorf("%s: MAlone=%s, want SURVIVED", r.ID, r.MAlone)
		}
		if r.Control != "KILLED" {
			t.Errorf("%s: Control=%s, want KILLED", r.ID, r.Control)
		}
		if r.Bucket != "MASKED" {
			t.Errorf("%s: Bucket=%s, want MASKED", r.ID, r.Bucket)
		}
		if r.ControlFailingCount < 1 {
			t.Errorf("%s: ControlFailingCount=%d, want >=1", r.ID, r.ControlFailingCount)
		}
	}
}

// TestSweepLedgerBucketsSumToThePopulation pins the distribution. The
// KILLED count is the implicit bucket — the ledger does not enumerate
// the 145 individually because that would be tautological with the
// sweep output. The MASKED count is the row count of sweepSurvivors,
// which this test asserts equals sweepMasked.
//
// The total must equal the population (164 = 120 sites worth of
// operands; some sites have multiple operands).
func TestSweepLedgerBucketsSumToThePopulation(t *testing.T) {
	killed := sweepKilled
	masked := len(sweepSurvivors)
	other := sweepPanic + sweepBuildFail + sweepTimeout

	if masked != sweepMasked {
		t.Errorf("MASKED row count: got %d, want %d (sweepMasked)",
			masked, sweepMasked)
	}
	if got := killed + masked + other; got != 164 {
		t.Errorf("tally sum %d (KILLED=%d + MASKED=%d + other=%d) != 164 (population)",
			got, killed, masked, other)
	}
}

// TestSweepLedgerRowsNameLiveSource confirms every row's recorded line
// still names the recorded Site on current main. The drift guard
// compares against `lines[LineNo-1]` after a per-line strip — a comment
// inserted anywhere above is invisible, a wrapper dropped on the row's
// own line is restored, and an edit on the row's own line that changes
// `Site` makes the guard red.
//
// FALSIFY-ARM 1 (drift): insert one comment line at the top of
// registry.go and re-run. The test must NOT red — the Site matches
// lines[LineNo-1] regardless of upstream edits.
//
// FALSIFY-ARM 2 (genuine drift): replace one row's Site with
// "INTENTIONALLY BROKEN". The test must red naming that row.
func TestSweepLedgerRowsNameLiveSource(t *testing.T) {
	raw, err := os.ReadFile(registrySourcePath())
	if err != nil {
		t.Fatalf("read %s: %v", registrySourcePath(), err)
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) < 1 {
		t.Fatalf("empty source: %s", registrySourcePath())
	}
	for _, r := range sweepSurvivors {
		if r.LineNo < 1 || r.LineNo > len(lines) {
			t.Errorf("%s: LineNo=%d out of range (file has %d lines)",
				r.ID, r.LineNo, len(lines))
			continue
		}
		// Strip the row's line (not the whole file) so a wrapper that
		// spans lines is not stranded. sweeptext handles all five
		// documented wrapper shapes including the single-operand form.
		stripped := sweeptext.StripMutationWrappers(lines[r.LineNo-1])
		have := strings.TrimRight(stripped, " \t\r")
		want := strings.TrimRight(r.Site, " \t\r")
		if have != want {
			t.Errorf("%s: drift at %s:%d\n  have: %q\n  want: %q",
				r.ID, registrySourcePath(), r.LineNo, have, want)
		}
	}
}

// TestSweepLedgerJoinMatchesChainShapes asserts that every row's Join
// matches the actual chain shape of its Site. For a sole-operand guard
// (`if cond {`, no `||` or `&&`), Join must be empty; for a multi-
// operand chain, Join must be `||` or `&&`. The peer measured that 10
// of 19 rows in the prior version wrongly claimed `||` on sole-operand
// guards; this test pins the correction.
//
// FALSIFY: change one row's Join from "" to "||" or vice versa. The
// test fails naming the row.
func TestSweepLedgerJoinMatchesChainShapes(t *testing.T) {
	for _, r := range sweepSurvivors {
		ops := strings.Count(r.Site, "||") + strings.Count(r.Site, "&&")
		operandCount := ops + 1
		switch {
		case operandCount == 1 && r.Join != "":
			t.Errorf("%s: sole operand (no ||/&& in Site), Join=%q, want \"\" (no chain)",
				r.ID, r.Join)
		case operandCount > 1 && r.Join == "":
			t.Errorf("%s: %d-operand chain, Join=\"\", want \"||\" or \"&&\"",
				r.ID, operandCount)
		case operandCount > 1 && r.Join != "||" && r.Join != "&&":
			t.Errorf("%s: %d-operand chain, Join=%q, want \"||\" or \"&&\"",
				r.ID, operandCount, r.Join)
		}
	}
}

// TestSweepLedgerMaskedByNamesASiblingOrAGuard pins the convention that
// each row's MaskedBy is non-empty. For multi-operand rows it points
// to the sibling operand on the same chain; for sole-operand rows it
// points to the parent-function guard that catches the joint bypass.
// An empty MaskedBy on a masked row would be the half of the verdict
// a reviewer cannot check.
//
// FALSIFY: drop the MaskedBy field on one row. The test fails naming
// the row.
func TestSweepLedgerMaskedByNamesASiblingOrAGuard(t *testing.T) {
	for _, r := range sweepSurvivors {
		if r.MaskedBy == "" {
			t.Errorf("%s: MaskedBy is empty; a MASKED row must name "+
				"either the sibling operand on a multi-operand chain "+
				"or the parent-function guard that catches the joint "+
				"bypass", r.ID)
		}
	}
}

// TestSweepLedgerIDsAreUnique catches a copy-paste hazard: two rows
// with the same registry.go:LINE[op] would silently merge in the PR
// review.
func TestSweepLedgerIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range sweepSurvivors {
		if seen[r.ID] {
			t.Errorf("duplicate ledger row id %s", r.ID)
		}
		seen[r.ID] = true
	}
}

// TestSweepLedgerSweeptextRestoresTheStrippedOperands is the strip's
// drift guard for THIS ledger: for every row, take the recorded
// operand and confirm the shared strip helper passes it through both
// wrapper forms. This catches the case where sweeptext over-strips
// (rewriting text that does not carry a wrapper) — in which case the
// live-source comparison would silently pass against rewritten text.
//
// Sweeptext is shared via kms/internal/sweeptext (DEV5, #379, drift-pinned
// by #381); the falsifier shapes in that package's own test file are
// the canonical list. The subsets exercised here are the forms the
// round-2 sweep harness and round-2 control arm apply.
func TestSweepLedgerSweeptextRestoresTheStrippedOperands(t *testing.T) {
	for _, r := range sweepSurvivors {
		// M-alone polarity: (false && X)
		mutated := "(false && " + r.Operand + ")"
		got := sweeptext.StripMutationWrappers(mutated)
		if got != r.Operand {
			t.Errorf("%s: (false &&) wrap not stripped: got %q, want %q",
				r.ID, got, r.Operand)
		}
		// Control-arm polarity: (true || X)
		mutated = "(true || " + r.Operand + ")"
		got = sweeptext.StripMutationWrappers(mutated)
		if got != r.Operand {
			t.Errorf("%s: (true ||) wrap not stripped: got %q, want %q",
				r.ID, got, r.Operand)
		}
		// Single-operand form (the case prior strip copies missed): a
		// single-operand guard has no chain to disambiguate, so the
		// harness writes `if false && (X) {` — no outer parens.
		mutated = "if false && (" + r.Operand + ") {"
		got = sweeptext.StripMutationWrappers(mutated)
		if !strings.Contains(got, r.Operand) {
			t.Errorf("%s: single-operand form lost operand: got %q, must contain %q",
				r.ID, got, r.Operand)
		}
	}
}

// TestSweepLedgerNoByteOffsets guards the regression that v1 introduced:
// byte-offset fields ByteStart/ByteEnd. Their existence was the source of
// the drift guard's false KILLED on insert-comment-above. The schema
// guard here enforces the absence: if either field reappears, this test
// fails and the line-based drift guard can no longer be silently
// replaced by the byte-offset form.
func TestSweepLedgerNoByteOffsets(t *testing.T) {
	if len(sweepSurvivors) == 0 {
		t.Fatal("no rows to inspect")
	}
	rt := reflect.TypeOf(sweepSurvivors[0])
	for _, name := range []string{"ByteStart", "ByteEnd"} {
		if _, ok := rt.FieldByName(name); ok {
			t.Errorf("field %q exists on ledgerRow — the v1 drift guard "+
				"used absolute byte offsets and produced a false KILLED "+
				"on insert-comment-above. Remove the field.", name)
		}
	}
}

// TestSweepLedgerFieldsAreStable is the schema guard: every row
// carries the same field set, in the documented order. A future round
// that adds a field must update this check; one that REMOVES a field
// will be caught by the same.
//
// This test catches drift in the schema, not the data.
func TestSweepLedgerFieldsAreStable(t *testing.T) {
	want := []string{
		"ID", "LineNo", "Site", "Operand", "Join",
		"MAlone", "Control", "ControlFailingCount",
		"Detector", "MaskedBy", "Notes", "Bucket",
	}
	if len(sweepSurvivors) == 0 {
		t.Fatal("no rows to inspect")
	}
	rt := reflect.TypeOf(sweepSurvivors[0])
	got := make([]string, rt.NumField())
	for i := range got {
		got[i] = rt.Field(i).Name
	}
	if len(got) != len(want) {
		t.Fatalf("field count: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// _ unused-import style check, kept here so future edits can stay
// honest about which helpers they rely on.
var _ = fmt.Sprintf
