//go:build piv

package yubikey

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// THE SURVIVOR LEDGER.
//
// The 2026-09-06 sweep of piv_driver.go found 41 both-direction survivors in
// lines 43-219, with 11 additional operands killed in one direction. The seam
// introduced in #237 round two (pivCards, pivOpen) re-classified several of
// the survivors: some became testable through the seam, others remained masked
// by sibling guards or unreachable through any in-process fixture. This ledger
// names each operand in scope and its current disposition so a future change
// to either the seam or the surrounding guards can be checked against the
// population rather than re-derived.
//
// THE POPULATION MEASUREMENT.
//
// Re-measuring the survivor list against current piv_driver.go takes minutes
// (enumerate, mutate, run with -timeout, classify). Re-deriving it silently
// is the failure mode this ledger exists to prevent: a reader who does not
// know the population is also a reader who does not know whether the ledger
// has drifted. The ledger asserts each entry's line still resolves to a guard
// in piv_driver.go and that every referenced closure (test name or RECORD
// reason) is the one that was true when the entry was written.
//
// WHAT THIS LEDGER IS NOT.
//
// This ledger does NOT re-run the sweep. It is the invariant a future sweep
// would be measured against: every entry that says "closed by TestX" must
// match a TestX that the test binary recognises, and every entry that says
// "recorded as masked" must point at the masking operand. The ledger can
// verify those facts at unit-test speed; the sweep itself remains the
// distinct, slow, and separately scheduled run.
//
// THE 41 + 11 = 52 POPULATION BREAKDOWN.
//
// 41 both-direction survivors (the audit's population) plus 11 one-direction-
// killed operands equals the 52 total leaves guardenum enumerates in lines
// 43-228. The ledger lists every operand in scope; entries marked closedByTest
// or recordedMasked correspond to the 41 both-direction survivors, and the
// remaining 11 are not present here because a one-direction kill is not the
// kind of finding the audit tracks. A future PR that introduces a new operand
// (or removes one) would either add or drop an entry, and the count check
// below would fail loudly.
//
// THREE STATUSES, NOT TWO.
//
// The original ledger had two: closedByTest (both directions killed) and
// recordedMasked (cannot be the sole refusal). Peer review of #393 surfaced
// that the seam fixture falsifies only the FALSE direction — the question
// 'does anything notice if this stops refusing.' The TRUE direction — 'is
// this the sole refusal mechanism' — needs a card-shaped seam that #237
// round two did not introduce. A third status tracks this honestly:
//
//   - closedByTest             both directions killed by tests in this package
//   - closedFalseDirectionOnly FALSE direction killed by a test; TRUE still
//     open pending a card-shaped seam
//   - recordedMasked           cannot-be-sole-refuser in this fixture
//
// The count check below totals ALL three; the original 41 was a claim about
// closedByTest alone, and the peer caught that the seam tests had been
// promoted to closedByTest when only the FALSE direction was falsified.
const expectedOperandPopulation = 52

type survivorStatus int

const (
	closedByTest survivorStatus = iota
	closedFalseDirectionOnly
	recordedMasked
)

type survivorEntry struct {
	line        int
	operand     int
	status      survivorStatus
	closure     string // test name when closedByTest or closedFalseDirectionOnly; RECORD reason when recordedMasked
	masked      string // when recordedMasked, the line:operand that masks this one
	whyTrueOpen string // when closedFalseDirectionOnly, why the TRUE direction was not falsified
	site        string // unique substring of piv_driver.go at `line`, used by TestPivotDriverSurvivorLedgerLinesResolveToLiveSource
}

// PIV_DRIVER_GO_OPERANDS is the operand population across piv_driver.go lines
// 43-219 — 52 leaves on the sites guardenum enumerates there. The 2026-09-06
// sweep classified 41 of these as both-direction survivors and 11 as killed in
// one direction; both kinds are listed below because the audit's 41 is a
// subset of the 52 leaves in scope, and a count check that totals only the
// survivors would let a one-direction-killed operand drift past it.
//
// Each entry is paired with the closure that currently holds:
//
//   - closedByTest             a test in this package falsifies the operand in
//     both directions (the original audit's claim)
//   - closedFalseDirectionOnly a test in this package falsifies the FALSE
//     direction; TRUE direction pending a card-shaped
//     seam (Serial(), pivOpen returning a successful
//     card, etc.) the package does not yet provide
//   - recordedMasked           RECORD reason that names the masking operand
//     (sibling guard, library check, or physical
//     constraint) the operand cannot be the sole
//     refusal against
//
// Re-running the sweep may shift a few between the three statuses, but the
// total should not move unless piv_driver.go itself changes.
var pivDriverGoOperands = []survivorEntry{
	// piv_driver.go:43 — `if err := ctx.Err(); err != nil || driver == nil {`
	{line: 43, operand: 1, status: closedFalseDirectionOnly, closure: "TestOpenRefusesBeforeTouchingADriverThatIsNil", whyTrueOpen: "TRUE-direction test would need a non-nil driver, live ctx, pivCards returning cards, pivOpen returning a card whose Serial() matches the target — needs the Serial() seam", site: "driver == nil"},
	{line: 43, operand: 0, status: recordedMasked, closure: "ctx.Err() fires at :43 op0 on every path that reaches the loop, so :56 cannot be observed as the deciding operand", masked: "piv_driver.go:56[0]", site: "err := ctx.Err()"},

	// piv_driver.go:47 — `if target == "" {`
	{line: 47, operand: 0, status: closedFalseDirectionOnly, closure: "TestOpenDoesNotEnumerateReadersForADeviceIDThatIsNotCommissioned", whyTrueOpen: "TRUE-direction test would assert Open succeeds for a commissioned deviceID; needs pivOpen to return a successful card whose Serial() matches — Serial() seam", site: "target == \"\""},

	// piv_driver.go:52 — `if err != nil {` (pivCards)
	{line: 52, operand: 0, status: recordedMasked, closure: "pivCards returning an error and pivCards returning (nil, nil) both leave :79 to refuse, and the loop body never runs to disambiguate", masked: "piv_driver.go:79[0]", site: "err != nil"},

	// piv_driver.go:57 — `if ctx.Err() != nil {` (loop-top guard)
	{line: 57, operand: 0, status: recordedMasked, closure: "pivOpen is synchronous in the seam fixture and cannot observe a context cancel that happens after the call enters", masked: "piv_driver.go:43[0]", site: "ctx.Err() != nil"},

	// piv_driver.go:58 — `if selected != nil {` (close prior on ctx.Err in loop)
	{line: 58, operand: 0, status: recordedMasked, closure: ":58 only fires when a previous iteration set `selected`, which requires pivOpen to return a successful card; the seam does not provide one", masked: "piv_driver.go:62,68", site: "selected != nil"},

	// piv_driver.go:64 — `if openErr != nil {` (the cited line points at the guard, not the assignment on :63)
	{line: 64, operand: 0, status: closedFalseDirectionOnly, closure: "TestOpenContinuesPastACardThatFailsToOpen", whyTrueOpen: "TRUE-direction test would need pivOpen to return a successful card for the loop to reach selected != nil; needs the Serial() seam", site: "openErr != nil"},

	// piv_driver.go:68 — `if serialErr != nil || strconv.FormatUint(uint64(serial), 10) != target {`
	{line: 68, operand: 0, status: recordedMasked, closure: "candidate.Serial() panics on a nil-handed card before returning — :68 op0 cannot be reached without a Serial() seam", masked: "the nil-handed card", site: "serialErr != nil || strconv.FormatUint(uint64(serial), 10) != target"},
	{line: 68, operand: 1, status: recordedMasked, closure: "same as :68 op0 — Serial() must return for :68 op1 to be observed", masked: "the nil-handed card", site: "serialErr != nil || strconv.FormatUint(uint64(serial), 10) != target"},

	// piv_driver.go:72 — `if selected != nil {` (duplicate serial)
	{line: 72, operand: 0, status: recordedMasked, closure: "two pivCards() results whose Serial() both match the target — physically impossible and not seam-reachable", masked: "physics", site: "if selected != nil"},

	// piv_driver.go:79 — `if selected == nil {`
	{line: 79, operand: 0, status: closedFalseDirectionOnly, closure: "TestOpenRefusesWhenNoCardMatchesTheCommissionedSerial", whyTrueOpen: "TRUE-direction test would need pivOpen to return a successful card whose Serial() matches the target — Serial() seam", site: "selected == nil"},

	// piv_driver.go:86 — `if driver == nil || ctx.Err() != nil {` (Ready)
	{line: 86, operand: 0, status: closedFalseDirectionOnly, closure: "TestReadyRefusesBeforeTouchingADriverThatIsNil", whyTrueOpen: "TRUE-direction test would assert Ready=true on a non-nil driver with pivCards returning cards; the test only asserts Ready=false on a nil driver", site: "driver == nil"},
	{line: 86, operand: 1, status: closedFalseDirectionOnly, closure: "TestReadyRefusesACancelledContextEvenWhenCardsArePresent", whyTrueOpen: "TRUE-direction test would assert Ready=true on a live context with cards; the test only asserts Ready=false on a cancelled context", site: "ctx.Err() != nil"},

	// piv_driver.go:90 — `return err == nil && len(cards) > 0` (Ready)
	{line: 90, operand: 0, status: closedFalseDirectionOnly, closure: "TestReadyReportsTruthfullyAcrossBothHalvesOfItsReturn/not_ready_when_pivCards_errors", whyTrueOpen: "the test subtest `ready_when_cards_are_present` does assert Ready=true on a healthy pivCards, which catches the FALSE-direction's over-refusal — but it does not isolate the :90 op0 operand from :90 op1, so the assertion is on the conjunction, not the operand", site: "err == nil"},
	{line: 90, operand: 1, status: closedFalseDirectionOnly, closure: "TestReadyReportsTruthfullyAcrossBothHalvesOfItsReturn/not_ready_when_no_cards_are_present", whyTrueOpen: "TRUE-direction test would assert Ready=true on (cards, nil); the seam returns (nil, nil) for this subtest, but that does not falsify the operand — it falsifies the conjunction", site: "len(cards) > 0"},

	// piv_driver.go:102 — Identity's usable check
	{line: 102, operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/Identity", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:106 — Identity's serial check
	{line: 106, operand: 0, status: recordedMasked, closure: "card.Serial() panics on a nil-handed card before returning — :106 op0 is unreachable without a Serial() seam", masked: "the nil-handed card", site: "err != nil || strconv.FormatUint(uint64(serial), 10) != session.serial"},
	{line: 106, operand: 1, status: recordedMasked, closure: "same as :106 op0", masked: "the nil-handed card", site: "err != nil || strconv.FormatUint(uint64(serial), 10) != session.serial"},

	// piv_driver.go:113 — Policies' usable check
	{line: 113, operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/Policies", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:117 — Policies' parseSlot check
	{line: 117, operand: 0, status: closedByTest, closure: "TestAnObjectIDThatIsNotASlotNeverReachesTheCard/Policies", site: "if err != nil {"},

	// piv_driver.go:121 — Policies' KeyInfo error
	{line: 121, operand: 0, status: recordedMasked, closure: "KeyInfo() panics on a nil-handed card before returning", masked: "the nil-handed card", site: "if err != nil {"},

	// piv_driver.go:128 — PINRetries' usable check
	{line: 128, operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/PINRetries", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:132 — PINRetries' Retries error
	{line: 132, operand: 0, status: recordedMasked, closure: "Retries() panics on a nil-handed card before returning", masked: "the nil-handed card", site: "if err != nil {"},

	// piv_driver.go:139 — Login's usable+len chain
	{line: 139, operand: 0, status: closedFalseDirectionOnly, closure: "TestLoginRefusesBeforeVerifyingOnASessionThatIsNotUsable", whyTrueOpen: "TRUE-direction test would assert Login succeeds on a usable session — needs a VerifyPIN seam; :139 op0 is the usable check and the seam fixture does not provide a session that is usable AND has VerifyPIN succeed", site: "session.usable(ctx); err != nil"},
	{line: 139, operand: 1, status: closedByTest, closure: "TestALoginPINBelowTheAcceptedLengthNeverReachesTheCard", site: "len(pin) < 6"},
	{line: 139, operand: 2, status: recordedMasked, closure: "piv-go's encodePIN refuses a PIN longer than 8 bytes before any transmission, so :139 op2 cannot be the sole refuser", masked: "piv-go's encodePIN", site: "len(pin) > 64"},

	// piv_driver.go:154 — Sign's privateKey error
	{line: 154, operand: 0, status: recordedMasked, closure: "privateKey returns (nil, zero, ErrUnavailable) under any failure mode reachable in this process; Sign with key=nil falls through to :158 (signer, ok := key.(crypto.Signer) → ok=false), and :158 catches it without :154", masked: "piv_driver.go:158[0]", site: "if err != nil {"},

	// piv_driver.go:158 — Sign's !ok signer
	{line: 158, operand: 0, status: recordedMasked, closure: ":158 fires only if key.(crypto.Signer) returns ok=false, and the only path that reaches it without :154 firing is when privateKey returned (nil, zero, nil) — which :154 alone does not produce", masked: "piv_driver.go:154[0]", site: "if !ok {"},

	// piv_driver.go:162 — Sign's !valid + !algorithmMatches
	{line: 162, operand: 0, status: recordedMasked, closure: "signingHash and algorithmMatches both run only after :154 and :158 have admitted — neither is reachable without a card that signs", masked: "piv_driver.go:154,158", site: "!valid"},
	{line: 162, operand: 1, status: recordedMasked, closure: "same as :162 op0", masked: "piv_driver.go:154,158", site: "!algorithmMatches(info.Algorithm, algorithm)"},

	// piv_driver.go:166 — Sign's err + len(value)
	{line: 166, operand: 0, status: recordedMasked, closure: "signer.Sign returns from the card; unreachable without a signing card", masked: "the card", site: "if err != nil || len(value) == 0 {"},
	{line: 166, operand: 1, status: recordedMasked, closure: "same as :166 op0", masked: "the card", site: "if err != nil || len(value) == 0 {"},

	// piv_driver.go:174 — Unwrap's err + algorithm + info.Algorithm
	{line: 174, operand: 0, status: recordedMasked, closure: "same shape as :154 op0", masked: "piv_driver.go:178[0]", site: "if err != nil || algorithm != \"rsa2048\""},
	{line: 174, operand: 1, status: recordedMasked, closure: "needs privateKey to succeed; unreachable without a card", masked: "the card", site: "info.Algorithm != piv.AlgorithmRSA2048"},
	{line: 174, operand: 2, status: recordedMasked, closure: "same as :174 op1", masked: "the card", site: "info.Algorithm != piv.AlgorithmRSA2048"},

	// piv_driver.go:178 — Unwrap's !ok decrypter
	{line: 178, operand: 0, status: recordedMasked, closure: "same shape as :158 op0", masked: "piv_driver.go:174[0]", site: "if !ok {"},

	// piv_driver.go:182 — Unwrap's err + len(value)
	{line: 182, operand: 0, status: recordedMasked, closure: "decrypter.Decrypt returns from the card; unreachable without an unwrapping card", masked: "the card", site: "if err != nil || len(value) == 0 {"},
	{line: 182, operand: 1, status: recordedMasked, closure: "same as :182 op0", masked: "the card", site: "if err != nil || len(value) == 0 {"},

	// piv_driver.go:189 — PublicKey's usable check
	{line: 189, operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/PublicKey", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:193 — PublicKey's parseSlot check
	{line: 193, operand: 0, status: closedByTest, closure: "TestAnObjectIDThatIsNotASlotNeverReachesTheCard/PublicKey", site: "if err != nil {"},

	// piv_driver.go:197 — PublicKey's err + info.PublicKey
	{line: 197, operand: 0, status: recordedMasked, closure: "KeyInfo() panics on a nil-handed card", masked: "the nil-handed card", site: "info.PublicKey == nil"},
	{line: 197, operand: 1, status: recordedMasked, closure: "same as :197 op0", masked: "the nil-handed card", site: "info.PublicKey == nil"},

	// piv_driver.go:201 — PublicKey's MarshalPKIX error
	{line: 201, operand: 0, status: recordedMasked, closure: "MarshalPKIXPublicKey is only reached after :197 admits; same masking", masked: "the nil-handed card", site: "if err != nil {"},

	// piv_driver.go:208 — privateKey's usable + pin check
	{line: 208, operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/Sign", site: "session.usable(ctx); err != nil"},
	{line: 208, operand: 1, status: closedByTest, closure: "TestNoPrivateKeyOperationHappensBeforeALogin", site: "session.pin == \"\""},

	// piv_driver.go:212 — privateKey's parseSlot check
	{line: 212, operand: 0, status: closedByTest, closure: "TestAnObjectIDThatIsNotASlotNeverReachesTheCard/Sign", site: "if err != nil {"},

	// piv_driver.go:216 — privateKey's err + TouchPolicy + PINPolicy + algorithmMatches
	{line: 216, operand: 0, status: recordedMasked, closure: "KeyInfo() panics on a nil-handed card before returning", masked: "the nil-handed card", site: "info.TouchPolicy != piv.TouchPolicyNever"},
	{line: 216, operand: 1, status: recordedMasked, closure: "same as :216 op0", masked: "the nil-handed card", site: "PINPolicy != piv.PINPolicyOnce"},
	{line: 216, operand: 2, status: recordedMasked, closure: "same as :216 op0", masked: "the nil-handed card", site: "PINPolicy != piv.PINPolicyAlways"},
	{line: 216, operand: 3, status: recordedMasked, closure: "same as :216 op0", masked: "the nil-handed card", site: "info.PINPolicy != piv.PINPolicyOnce"},
	{line: 216, operand: 4, status: recordedMasked, closure: "the algorithm half is closed indirectly by TestAlgorithmMatchesRefusesACardAlgorithmThatIsNotTheOneRequested", masked: "the nil-handed card", site: "!algorithmMatches(info.Algorithm, algorithm)"},

	// piv_driver.go:220 — privateKey's PrivateKey error
	{line: 220, operand: 0, status: recordedMasked, closure: "card.PrivateKey() panics on a nil-handed card", masked: "the nil-handed card", site: "if err != nil {"},
}

// TestPivotDriverSurvivorLedgerIsBalanced enforces the ledger's internal
// invariants:
//
//   - Every entry's line resolves to a guard in piv_driver.go.
//   - The total entry count equals the 2026-09-06 sweep's 52 operands in
//     scope (43-228).
//   - Closed-by-test entries that name a test name point to a test that
//     resolves in this package.
//
// It does NOT re-run the sweep. A future PR that introduces a new operand
// would either add an entry (and the count check would fail loudly) or remove
// one (same). Either case is the loud-failure the ledger is for.
func TestPivotDriverSurvivorLedgerIsBalanced(t *testing.T) {
	if len(pivDriverGoOperands) != expectedOperandPopulation {
		t.Fatalf("ledger has %d entries, want %d — either the population drifted (re-run the sweep) "+
			"or this constant is out of date; do not adjust the constant without re-measuring",
			len(pivDriverGoOperands), expectedOperandPopulation)
	}

	// Each entry's line must be a guard in piv_driver.go. The simplest check
	// is that the file has at least that many lines.
	src, err := readSource(t, "piv_driver.go")
	if err != nil {
		t.Fatal(err)
	}
	lineCount := strings.Count(src, "\n") + 1

	// Each test name referenced by a closedByTest entry must exist somewhere
	// in this package's _test.go files.
	testNames := collectTestNames(t)

	seen := make(map[string]bool) // line:operand → already in ledger
	for i, entry := range pivDriverGoOperands {
		key := survivorKey(entry)
		if seen[key] {
			t.Errorf("entry %d (%s) is a duplicate", i, key)
		}
		seen[key] = true

		if entry.line < 43 || entry.line > 228 {
			t.Errorf("entry %d (%s) is outside the sweep scope (lines 43-228)", i, key)
		}
		if entry.line > lineCount {
			t.Errorf("entry %d (%s) line %d exceeds piv_driver.go length %d", i, key, entry.line, lineCount)
		}
		if entry.operand < 0 {
			t.Errorf("entry %d (%s) has a negative operand index", i, key)
		}

		switch entry.status {
		case closedByTest, closedFalseDirectionOnly:
			// The closure must resolve to either a literal "Parent/Sub"
			// (collected when the t.Run first arg is a string literal) or
			// the bare "Parent" (when the subtest name is dynamic, e.g.
			// t.Run(method, ...) iterating over a map[string]X literal).
			// See collectTestNames for why dynamic subtests resolve to the
			// parent only.
			if !testNames[entry.closure] {
				if i := strings.Index(entry.closure, "/"); i > 0 {
					if !testNames[entry.closure[:i]] {
						t.Errorf("entry %d (%s) names closure %q (or its parent) which is not a test in this package", i, key, entry.closure)
					}
				} else {
					t.Errorf("entry %d (%s) names closure %q which is not a test in this package", i, key, entry.closure)
				}
			}
			if entry.status == closedFalseDirectionOnly && entry.whyTrueOpen == "" {
				t.Errorf("entry %d (%s) is closedFalseDirectionOnly with no whyTrueOpen reason", i, key)
			}
		case recordedMasked:
			if entry.masked == "" {
				t.Errorf("entry %d (%s) is recordedMasked with no masking operand", i, key)
			}
		default:
			t.Errorf("entry %d (%s) has unrecognised status %d", i, key, entry.status)
		}
	}
}

func survivorKey(e survivorEntry) string {
	return "piv_driver.go:" + itoa(e.line) + "[" + itoa(e.operand) + "]"
}

// TestPivotDriverSurvivorLedgerLinesResolveToLiveSource is the line-drift
// guard. It mirrors internal/audit.TestLedgerRowNamesLiveSource: every
// ledger entry's cited line must contain a unique substring of the operand
// text at that line in piv_driver.go. A coordinate that has drifted by one
// (or that points at an assignment rather than the guard) trips this test
// loudly, naming the entry.
//
// The audit's ledger had this guard after a byte-offset version failed 19
// of 19 rows on one comment insertion; this guard is the equivalent for
// line coordinates. The companion check on the closure axis is in
// TestPivotDriverSurvivorLedgerIsBalanced (which asserts the closure test
// exists in the package); together they guard BOTH coordinates.
//
// Falsified by shifting one row's line by ±1 and confirming the test fires
// naming that row.
func TestPivotDriverSurvivorLedgerLinesResolveToLiveSource(t *testing.T) {
	src, err := readSource(t, "piv_driver.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(src, "\n")

	for i, entry := range pivDriverGoOperands {
		key := survivorKey(entry)
		if entry.site == "" {
			t.Errorf("entry %d (%s) has no site substring recorded — site must name a unique substring of the cited line", i, key)
			continue
		}
		if entry.line < 1 || entry.line > len(lines) {
			t.Errorf("entry %d (%s) line %d out of range (file has %d lines)", i, key, entry.line, len(lines))
			continue
		}
		have := strings.TrimRight(lines[entry.line-1], " \t\r")
		if !strings.Contains(have, entry.site) {
			t.Errorf("entry %d (%s) line %d drift.\n  have: %q\n  want substring: %q", i, key, entry.line, have, entry.site)
		}
	}
}

func readSource(t *testing.T, name string) (string, error) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, nil, parser.AllErrors)
	if err != nil {
		return "", err
	}
	_ = file
	return readFile(name)
}

func readFile(name string) (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errRuntimeCaller
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), name))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

var errRuntimeCaller = &runtimeError{"runtime.Caller(0) failed"}

type runtimeError struct{ msg string }

func (e *runtimeError) Error() string { return e.msg }

// collectTestNames walks every *_test.go file in this package directory and
// returns the set of test names. Two forms are recognised:
//
//   - Top-level Test* functions whose body is non-nil.
//   - Subtests declared with t.Run("literal", ...) — the literal first arg
//     gives a fully-resolvable name in the form "Parent/Sub".
//
// Subtests declared with t.Run(variable, ...) where the variable comes from
// a `for ... := range map[string]X{...}` cannot be resolved from the call
// alone. The check below therefore resolves a "Parent/Sub" closure in the
// ledger to "Parent" alone when Parent exists in this set: a dynamic
// subtest under Parent is the only way "Parent/Sub" can be present at run
// time. If Parent itself does not exist, the closure has drifted.
func collectTestNames(t *testing.T) map[string]bool {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	pkgDir := filepath.Dir(thisFile)
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	names := make(map[string]bool)
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
			if !ok || fn.Body == nil || fn.Recv != nil {
				continue
			}
			if !strings.HasPrefix(fn.Name.Name, "Test") {
				continue
			}
			names[fn.Name.Name] = true
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
				if !ok || ident.Name != "t" || sel.Sel.Name != "Run" || len(call.Args) == 0 {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				names[fn.Name.Name+"/"+strings.Trim(lit.Value, `"`)] = true
				return true
			})
		}
	}
	return names
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
