//go:build piv

package yubikey

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/sweeptext"
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
// THE 41 + 11 = 52 POPULATION BREAKDOWN (53 since 2026-09-23: see the pivClearVerified entry below).
//
// 41 both-direction survivors (the audit's population) plus 11 one-direction-
// killed operands equals the 52 total leaves guardenum enumerates in lines
// 43-238. The ledger lists every operand in scope; entries marked closedByTest
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
const expectedOperandPopulation = 53

type survivorStatus int

const (
	closedByTest survivorStatus = iota
	closedFalseDirectionOnly
	recordedMasked
)

type survivorEntry struct {
	// at is the guard, cited as "piv_driver.go:Func{anchor}" (sweeptext.ResolveCitation): the
	// function and a piece of the guard's text, no line number, so an edit elsewhere in the file
	// renumbers nothing (#290, as #282 for internal/audit).
	at          string
	operand     int
	status      survivorStatus
	closure     string // test name when closedByTest or closedFalseDirectionOnly; RECORD reason when recordedMasked
	masked      string // when recordedMasked, what masks this one; a citation in it must resolve
	whyTrueOpen string // when closedFalseDirectionOnly, why the TRUE direction was not falsified
	site        string // the operand's text; the line `at` resolves to must hold it (TestPivotDriverSurvivorLedgerLinesResolveToLiveSource)
}

// PIV_DRIVER_GO_OPERANDS is the operand population across piv_driver.go's
// sweepScope (lines 43-238 when swept) — 52 leaves on the sites guardenum enumerates there, plus the pivClearVerified guard
// recorded on 2026-09-23 without a re-sweep (53). The 2026-09-06
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
	// piv_driver.go:(*PIVDriver).Open{err := ctx.Err()} — `if err := ctx.Err(); err != nil || driver == nil {`
	{at: "piv_driver.go:(*PIVDriver).Open{err := ctx.Err()}", operand: 1, status: closedFalseDirectionOnly, closure: "TestOpenRefusesBeforeTouchingADriverThatIsNil", whyTrueOpen: "TRUE-direction test would need a non-nil driver, live ctx, pivCards returning cards, pivOpen returning a card whose Serial() matches the target — needs the Serial() seam", site: "driver == nil"},
	{at: "piv_driver.go:(*PIVDriver).Open{err := ctx.Err()}", operand: 0, status: recordedMasked, closure: "ctx.Err() fires at piv_driver.go:(*PIVDriver).Open{err := ctx.Err()}[0] on every path that reaches the loop, so piv_driver.go:(*PIVDriver).Open{ctx.Err() != nil} cannot be observed as the deciding operand", masked: "piv_driver.go:(*PIVDriver).Open{ctx.Err() != nil}[0]", site: "err := ctx.Err()"},

	// piv_driver.go:(*PIVDriver).Open{target == ""} — `if target == "" {`
	{at: "piv_driver.go:(*PIVDriver).Open{target == \"\"}", operand: 0, status: closedFalseDirectionOnly, closure: "TestOpenDoesNotEnumerateReadersForADeviceIDThatIsNotCommissioned", whyTrueOpen: "TRUE-direction test would assert Open succeeds for a commissioned deviceID; needs pivOpen to return a successful card whose Serial() matches — Serial() seam", site: "target == \"\""},

	// piv_driver.go:(*PIVDriver).Open{pivCards() then err != nil} — `if err != nil {` (pivCards)
	{at: "piv_driver.go:(*PIVDriver).Open{pivCards() then err != nil}", operand: 0, status: recordedMasked, closure: "pivCards returning an error and pivCards returning (nil, nil) both leave piv_driver.go:(*PIVDriver).Open{selected == nil} to refuse, and the loop body never runs to disambiguate", masked: "piv_driver.go:(*PIVDriver).Open{selected == nil}[0]", site: "err != nil"},

	// piv_driver.go:(*PIVDriver).Open{ctx.Err() != nil} — `if ctx.Err() != nil {` (loop-top guard)
	{at: "piv_driver.go:(*PIVDriver).Open{ctx.Err() != nil}", operand: 0, status: recordedMasked, closure: "pivOpen is synchronous in the seam fixture and cannot observe a context cancel that happens after the call enters", masked: "piv_driver.go:(*PIVDriver).Open{err := ctx.Err()}[0]", site: "ctx.Err() != nil"},

	// piv_driver.go:(*PIVDriver).Open{ctx.Err() != nil then selected != nil} — `if selected != nil {` (close prior on ctx.Err in loop)
	{at: "piv_driver.go:(*PIVDriver).Open{ctx.Err() != nil then selected != nil}", operand: 0, status: recordedMasked, closure: "piv_driver.go:(*PIVDriver).Open{ctx.Err() != nil then selected != nil} only fires when a previous iteration set `selected`, which requires pivOpen to return a successful card; the seam does not provide one", masked: "piv_driver.go:(*PIVDriver).Open{openErr != nil}[0], piv_driver.go:(*PIVDriver).Open{serialErr != nil}", site: "selected != nil"},

	// piv_driver.go:(*PIVDriver).Open{openErr != nil} — `if openErr != nil {` (the guard, not the pivOpen assignment above it)
	{at: "piv_driver.go:(*PIVDriver).Open{openErr != nil}", operand: 0, status: closedFalseDirectionOnly, closure: "TestOpenContinuesPastACardThatFailsToOpen", whyTrueOpen: "TRUE-direction test would need pivOpen to return a successful card for the loop to reach selected != nil; needs the Serial() seam", site: "openErr != nil"},

	// piv_driver.go:(*PIVDriver).Open{serialErr != nil} — `if serialErr != nil || strconv.FormatUint(uint64(serial), 10) != target {`
	{at: "piv_driver.go:(*PIVDriver).Open{serialErr != nil}", operand: 0, status: recordedMasked, closure: "candidate.Serial() panics on a nil-handed card before returning — piv_driver.go:(*PIVDriver).Open{serialErr != nil}[0] cannot be reached without a Serial() seam", masked: "the nil-handed card", site: "serialErr != nil || strconv.FormatUint(uint64(serial), 10) != target"},
	{at: "piv_driver.go:(*PIVDriver).Open{serialErr != nil}", operand: 1, status: recordedMasked, closure: "same as piv_driver.go:(*PIVDriver).Open{serialErr != nil}[0] — Serial() must return for piv_driver.go:(*PIVDriver).Open{serialErr != nil}[1] to be observed", masked: "the nil-handed card", site: "serialErr != nil || strconv.FormatUint(uint64(serial), 10) != target"},

	// piv_driver.go:(*PIVDriver).Open{selected != nil#2} — `if selected != nil {` (duplicate serial)
	{at: "piv_driver.go:(*PIVDriver).Open{selected != nil#2}", operand: 0, status: recordedMasked, closure: "two pivCards() results whose Serial() both match the target — physically impossible and not seam-reachable", masked: "physics", site: "if selected != nil"},

	// piv_driver.go:(*PIVDriver).Open{selected == nil} — `if selected == nil {`
	{at: "piv_driver.go:(*PIVDriver).Open{selected == nil}", operand: 0, status: closedFalseDirectionOnly, closure: "TestOpenRefusesWhenNoCardMatchesTheCommissionedSerial", whyTrueOpen: "TRUE-direction test would need pivOpen to return a successful card whose Serial() matches the target — Serial() seam", site: "selected == nil"},

	// piv_driver.go:(*PIVDriver).Open{pivClearVerified(selected)} — `if err := pivClearVerified(selected); err != nil {` (added 2026-09-23 by
	// regalia-kms#33, recorded without a re-sweep; the physical guard is
	// TestPIVPhysicalSessionNeitherInheritsNorLeavesPINVerification)
	{at: "piv_driver.go:(*PIVDriver).Open{pivClearVerified(selected)}", operand: 0, status: recordedMasked, closure: "piv_driver.go:(*PIVDriver).Open{pivClearVerified(selected)} runs only after a card is selected, which needs pivOpen to return a card whose Serial() matches — the Serial() seam the package does not provide", masked: "piv_driver.go:(*PIVDriver).Open{selected == nil}[0]", site: "pivClearVerified(selected); err != nil"},

	// piv_driver.go:(*PIVDriver).Ready{driver == nil || ctx.Err() != nil} — `if driver == nil || ctx.Err() != nil {` (Ready)
	{at: "piv_driver.go:(*PIVDriver).Ready{driver == nil || ctx.Err() != nil}", operand: 0, status: closedFalseDirectionOnly, closure: "TestReadyRefusesBeforeTouchingADriverThatIsNil", whyTrueOpen: "TRUE-direction test would assert Ready=true on a non-nil driver with pivCards returning cards; the test only asserts Ready=false on a nil driver", site: "driver == nil"},
	{at: "piv_driver.go:(*PIVDriver).Ready{driver == nil || ctx.Err() != nil}", operand: 1, status: closedFalseDirectionOnly, closure: "TestReadyRefusesACancelledContextEvenWhenCardsArePresent", whyTrueOpen: "TRUE-direction test would assert Ready=true on a live context with cards; the test only asserts Ready=false on a cancelled context", site: "ctx.Err() != nil"},

	// piv_driver.go:(*PIVDriver).Ready{len(cards) > 0} — `return err == nil && len(cards) > 0` (Ready)
	{at: "piv_driver.go:(*PIVDriver).Ready{len(cards) > 0}", operand: 0, status: closedFalseDirectionOnly, closure: "TestReadyReportsTruthfullyAcrossBothHalvesOfItsReturn/not_ready_when_pivCards_errors", whyTrueOpen: "the test subtest `ready_when_cards_are_present` does assert Ready=true on a healthy pivCards, which catches the FALSE-direction's over-refusal — but it does not isolate the piv_driver.go:(*PIVDriver).Ready{len(cards) > 0}[0] operand from piv_driver.go:(*PIVDriver).Ready{len(cards) > 0}[1], so the assertion is on the conjunction, not the operand", site: "err == nil"},
	{at: "piv_driver.go:(*PIVDriver).Ready{len(cards) > 0}", operand: 1, status: closedFalseDirectionOnly, closure: "TestReadyReportsTruthfullyAcrossBothHalvesOfItsReturn/not_ready_when_no_cards_are_present", whyTrueOpen: "TRUE-direction test would assert Ready=true on (cards, nil); the seam returns (nil, nil) for this subtest, but that does not falsify the operand — it falsifies the conjunction", site: "len(cards) > 0"},

	// piv_driver.go:(*pivSession).Identity{session.usable(ctx)} — Identity's usable check
	{at: "piv_driver.go:(*pivSession).Identity{session.usable(ctx)}", operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/Identity", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:(*pivSession).Identity{!= session.serial} — Identity's serial check
	{at: "piv_driver.go:(*pivSession).Identity{!= session.serial}", operand: 0, status: recordedMasked, closure: "card.Serial() panics on a nil-handed card before returning — piv_driver.go:(*pivSession).Identity{!= session.serial}[0] is unreachable without a Serial() seam", masked: "the nil-handed card", site: "err != nil || strconv.FormatUint(uint64(serial), 10) != session.serial"},
	{at: "piv_driver.go:(*pivSession).Identity{!= session.serial}", operand: 1, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).Identity{!= session.serial}[0]", masked: "the nil-handed card", site: "err != nil || strconv.FormatUint(uint64(serial), 10) != session.serial"},

	// piv_driver.go:(*pivSession).Policies{session.usable(ctx)} — Policies' usable check
	{at: "piv_driver.go:(*pivSession).Policies{session.usable(ctx)}", operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/Policies", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:(*pivSession).Policies{parseSlot(objectID) then err != nil} — Policies' parseSlot check
	{at: "piv_driver.go:(*pivSession).Policies{parseSlot(objectID) then err != nil}", operand: 0, status: closedByTest, closure: "TestAnObjectIDThatIsNotASlotNeverReachesTheCard/Policies", site: "if err != nil {"},

	// piv_driver.go:(*pivSession).Policies{session.card.KeyInfo(slot) then err != nil} — Policies' KeyInfo error
	{at: "piv_driver.go:(*pivSession).Policies{session.card.KeyInfo(slot) then err != nil}", operand: 0, status: recordedMasked, closure: "KeyInfo() panics on a nil-handed card before returning", masked: "the nil-handed card", site: "if err != nil {"},

	// piv_driver.go:(*pivSession).PINRetries{session.usable(ctx)} — PINRetries' usable check
	{at: "piv_driver.go:(*pivSession).PINRetries{session.usable(ctx)}", operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/PINRetries", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:(*pivSession).PINRetries{readPINRetries then err != nil} — PINRetries' Retries error
	{at: "piv_driver.go:(*pivSession).PINRetries{readPINRetries then err != nil}", operand: 0, status: recordedMasked, closure: "Retries() panics on a nil-handed card before returning", masked: "the nil-handed card", site: "if err != nil {"},

	// piv_driver.go:(*pivSession).Login{len(pin) < 6} — Login's usable+len chain
	{at: "piv_driver.go:(*pivSession).Login{len(pin) < 6}", operand: 0, status: closedFalseDirectionOnly, closure: "TestLoginRefusesBeforeVerifyingOnASessionThatIsNotUsable", whyTrueOpen: "TRUE-direction test would assert Login succeeds on a usable session — needs a VerifyPIN seam; piv_driver.go:(*pivSession).Login{len(pin) < 6}[0] is the usable check and the seam fixture does not provide a session that is usable AND has VerifyPIN succeed", site: "session.usable(ctx); err != nil"},
	{at: "piv_driver.go:(*pivSession).Login{len(pin) < 6}", operand: 1, status: closedByTest, closure: "TestALoginPINBelowTheAcceptedLengthNeverReachesTheCard", site: "len(pin) < 6"},
	{at: "piv_driver.go:(*pivSession).Login{len(pin) < 6}", operand: 2, status: recordedMasked, closure: "piv-go's encodePIN refuses a PIN longer than 8 bytes before any transmission, so piv_driver.go:(*pivSession).Login{len(pin) < 6}[2] cannot be the sole refuser", masked: "piv-go's encodePIN", site: "len(pin) > 64"},

	// piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil} — Sign's privateKey error
	{at: "piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil}", operand: 0, status: recordedMasked, closure: "privateKey returns (nil, zero, ErrUnavailable) under any failure mode reachable in this process; Sign with key=nil falls through to piv_driver.go:(*pivSession).Sign{!ok} (signer, ok := key.(crypto.Signer) → ok=false), and piv_driver.go:(*pivSession).Sign{!ok} catches it without piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil}", masked: "piv_driver.go:(*pivSession).Sign{!ok}[0]", site: "if err != nil {"},

	// piv_driver.go:(*pivSession).Sign{!ok} — Sign's !ok signer
	{at: "piv_driver.go:(*pivSession).Sign{!ok}", operand: 0, status: recordedMasked, closure: "piv_driver.go:(*pivSession).Sign{!ok} fires only if key.(crypto.Signer) returns ok=false, and the only path that reaches it without piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil} firing is when privateKey returned (nil, zero, nil) — which piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil} alone does not produce", masked: "piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil}[0]", site: "if !ok {"},

	// piv_driver.go:(*pivSession).Sign{!valid} — Sign's !valid + !algorithmMatches
	{at: "piv_driver.go:(*pivSession).Sign{!valid}", operand: 0, status: recordedMasked, closure: "signingHash and algorithmMatches both run only after piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil} and piv_driver.go:(*pivSession).Sign{!ok} have admitted — neither is reachable without a card that signs", masked: "piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil}[0], piv_driver.go:(*pivSession).Sign{!ok}[0]", site: "!valid"},
	{at: "piv_driver.go:(*pivSession).Sign{!valid}", operand: 1, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).Sign{!valid}[0]", masked: "piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil}[0], piv_driver.go:(*pivSession).Sign{!ok}[0]", site: "!algorithmMatches(info.Algorithm, algorithm)"},

	// piv_driver.go:(*pivSession).Sign{len(value) == 0} — Sign's err + len(value)
	{at: "piv_driver.go:(*pivSession).Sign{len(value) == 0}", operand: 0, status: recordedMasked, closure: "signer.Sign returns from the card; unreachable without a signing card", masked: "the card", site: "if err != nil || len(value) == 0 {"},
	{at: "piv_driver.go:(*pivSession).Sign{len(value) == 0}", operand: 1, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).Sign{len(value) == 0}[0]", masked: "the card", site: "if err != nil || len(value) == 0 {"},

	// piv_driver.go:(*pivSession).Unwrap{info.Algorithm != piv.AlgorithmRSA2048} — Unwrap's err + algorithm + info.Algorithm
	{at: "piv_driver.go:(*pivSession).Unwrap{info.Algorithm != piv.AlgorithmRSA2048}", operand: 0, status: recordedMasked, closure: "same shape as piv_driver.go:(*pivSession).Sign{session.privateKey then err != nil}[0]", masked: "piv_driver.go:(*pivSession).Unwrap{!ok}[0]", site: "if err != nil || algorithm != \"rsa2048\""},
	{at: "piv_driver.go:(*pivSession).Unwrap{info.Algorithm != piv.AlgorithmRSA2048}", operand: 1, status: recordedMasked, closure: "needs privateKey to succeed; unreachable without a card", masked: "the card", site: "info.Algorithm != piv.AlgorithmRSA2048"},
	{at: "piv_driver.go:(*pivSession).Unwrap{info.Algorithm != piv.AlgorithmRSA2048}", operand: 2, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).Unwrap{info.Algorithm != piv.AlgorithmRSA2048}[1]", masked: "the card", site: "info.Algorithm != piv.AlgorithmRSA2048"},

	// piv_driver.go:(*pivSession).Unwrap{!ok} — Unwrap's !ok decrypter
	{at: "piv_driver.go:(*pivSession).Unwrap{!ok}", operand: 0, status: recordedMasked, closure: "same shape as piv_driver.go:(*pivSession).Sign{!ok}[0]", masked: "piv_driver.go:(*pivSession).Unwrap{info.Algorithm != piv.AlgorithmRSA2048}[0]", site: "if !ok {"},

	// piv_driver.go:(*pivSession).Unwrap{len(value) == 0} — Unwrap's err + len(value)
	{at: "piv_driver.go:(*pivSession).Unwrap{len(value) == 0}", operand: 0, status: recordedMasked, closure: "decrypter.Decrypt returns from the card; unreachable without an unwrapping card", masked: "the card", site: "if err != nil || len(value) == 0 {"},
	{at: "piv_driver.go:(*pivSession).Unwrap{len(value) == 0}", operand: 1, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).Unwrap{len(value) == 0}[0]", masked: "the card", site: "if err != nil || len(value) == 0 {"},

	// piv_driver.go:(*pivSession).PublicKey{session.usable(ctx)} — PublicKey's usable check
	{at: "piv_driver.go:(*pivSession).PublicKey{session.usable(ctx)}", operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/PublicKey", site: "session.usable(ctx); err != nil"},

	// piv_driver.go:(*pivSession).PublicKey{parseSlot(objectID) then err != nil} — PublicKey's parseSlot check
	{at: "piv_driver.go:(*pivSession).PublicKey{parseSlot(objectID) then err != nil}", operand: 0, status: closedByTest, closure: "TestAnObjectIDThatIsNotASlotNeverReachesTheCard/PublicKey", site: "if err != nil {"},

	// piv_driver.go:(*pivSession).PublicKey{info.PublicKey == nil} — PublicKey's err + info.PublicKey
	{at: "piv_driver.go:(*pivSession).PublicKey{info.PublicKey == nil}", operand: 0, status: recordedMasked, closure: "KeyInfo() panics on a nil-handed card", masked: "the nil-handed card", site: "info.PublicKey == nil"},
	{at: "piv_driver.go:(*pivSession).PublicKey{info.PublicKey == nil}", operand: 1, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).PublicKey{info.PublicKey == nil}[0]", masked: "the nil-handed card", site: "info.PublicKey == nil"},

	// piv_driver.go:(*pivSession).PublicKey{x509.MarshalPKIXPublicKey then err != nil} — PublicKey's MarshalPKIX error
	{at: "piv_driver.go:(*pivSession).PublicKey{x509.MarshalPKIXPublicKey then err != nil}", operand: 0, status: recordedMasked, closure: "MarshalPKIXPublicKey is only reached after piv_driver.go:(*pivSession).PublicKey{info.PublicKey == nil} admits; same masking", masked: "the nil-handed card", site: "if err != nil {"},

	// piv_driver.go:(*pivSession).privateKey{session.pin == ""} — privateKey's usable + pin check
	{at: "piv_driver.go:(*pivSession).privateKey{session.pin == \"\"}", operand: 0, status: closedByTest, closure: "TestASessionThatIsNotUsableRefusesWithoutReachingTheCard/Sign", site: "session.usable(ctx); err != nil"},
	{at: "piv_driver.go:(*pivSession).privateKey{session.pin == \"\"}", operand: 1, status: closedByTest, closure: "TestNoPrivateKeyOperationHappensBeforeALogin", site: "session.pin == \"\""},

	// piv_driver.go:(*pivSession).privateKey{parseSlot(objectID) then err != nil} — privateKey's parseSlot check
	{at: "piv_driver.go:(*pivSession).privateKey{parseSlot(objectID) then err != nil}", operand: 0, status: closedByTest, closure: "TestAnObjectIDThatIsNotASlotNeverReachesTheCard/Sign", site: "if err != nil {"},

	// piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever} — privateKey's err + TouchPolicy + PINPolicy + algorithmMatches
	{at: "piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}", operand: 0, status: recordedMasked, closure: "KeyInfo() panics on a nil-handed card before returning", masked: "the nil-handed card", site: "info.TouchPolicy != piv.TouchPolicyNever"},
	{at: "piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}", operand: 1, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}[0]", masked: "the nil-handed card", site: "PINPolicy != piv.PINPolicyOnce"},
	{at: "piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}", operand: 2, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}[0]", masked: "the nil-handed card", site: "PINPolicy != piv.PINPolicyAlways"},
	{at: "piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}", operand: 3, status: recordedMasked, closure: "same as piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}[0]", masked: "the nil-handed card", site: "info.PINPolicy != piv.PINPolicyOnce"},
	{at: "piv_driver.go:(*pivSession).privateKey{info.TouchPolicy != piv.TouchPolicyNever}", operand: 4, status: recordedMasked, closure: "the algorithm half is closed indirectly by TestAlgorithmMatchesRefusesACardAlgorithmThatIsNotTheOneRequested", masked: "the nil-handed card", site: "!algorithmMatches(info.Algorithm, algorithm)"},

	// piv_driver.go:(*pivSession).privateKey{session.card.PrivateKey then err != nil} — privateKey's PrivateKey error
	{at: "piv_driver.go:(*pivSession).privateKey{session.card.PrivateKey then err != nil}", operand: 0, status: recordedMasked, closure: "card.PrivateKey() panics on a nil-handed card", masked: "the nil-handed card", site: "if err != nil {"},
}

// TestPivotDriverSurvivorLedgerIsBalanced enforces the ledger's internal
// invariants:
//
//   - Every entry cites a function in the sweep's scope (sweepScope); that the
//     citation resolves is TestPivotDriverSurvivorLedgerLinesResolveToLiveSource.
//   - The total entry count equals the 2026-09-06 sweep's 52 operands in
//     scope, plus the guard recorded on 2026-09-23.
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

	// Each test name referenced by a closedByTest entry must exist somewhere
	// in this package's _test.go files.
	testNames := collectTestNames(t)

	seen := make(map[string]bool) // citation[operand] → already in ledger
	for i, entry := range pivDriverGoOperands {
		key := survivorKey(entry)
		if seen[key] {
			t.Errorf("entry %d (%s) is a duplicate", i, key)
		}
		seen[key] = true

		if match := sweeptext.CitationPattern.FindStringSubmatch(entry.at); match == nil || match[0] != entry.at || match[4] != "" || !sweepScope[match[2]] {
			t.Errorf("entry %d (%s) does not cite a function of the sweep scope as piv_driver.go:Func{anchor}", i, key)
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

// sweepScope is the functions the 2026-09-06 sweep covered (lines 43-238 then). Close, usable,
// parseSlot, algorithmMatches and the policy-name helpers are pinned by
// piv_session_boundary_test.go instead, and NewPIVDriver by sweep_uncovered_test.go.
var sweepScope = map[string]bool{
	"(*PIVDriver).Open": true, "(*PIVDriver).Ready": true, "(*pivSession).Identity": true,
	"(*pivSession).Policies": true, "(*pivSession).PINRetries": true, "(*pivSession).Login": true,
	"(*pivSession).Sign": true, "(*pivSession).Unwrap": true, "(*pivSession).PublicKey": true,
	"(*pivSession).privateKey": true,
}

func survivorKey(e survivorEntry) string {
	return e.at + "[" + itoa(e.operand) + "]"
}

// TestPivotDriverSurvivorLedgerLinesResolveToLiveSource is the drift guard. It mirrors
// internal/audit.TestLedgerRowNamesLiveSource and shares its resolver (sweeptext.ResolveCitation):
// every entry's citation must name one line of piv_driver.go, and that line must hold the
// entry's site. A citation in a masked field must resolve too: those were never checked while
// they were line numbers, and three had drifted to a line that was not the masking guard.
//
// FALSIFY: change one entry's site, or its anchor to a text its function holds twice or not at
// all; or a masked citation's anchor. The test fails naming that entry.
func TestPivotDriverSurvivorLedgerLinesResolveToLiveSource(t *testing.T) {
	checkSurvivorsResolve(t, packageSources())
}

// TestPivotDriverSurvivorLedgerSurvivesALineAddedAbove is #290's "done when": a line added at the
// top of piv_driver.go needs no ledger edit.
func TestPivotDriverSurvivorLedgerSurvivesALineAddedAbove(t *testing.T) {
	live := packageSources()
	checkSurvivorsResolve(t, func(file string) (string, error) {
		source, err := live(file)
		return "// a line added above every guard (#290)\n" + source, err
	})
}

// TestNoYubiKeyTestCitesPivDriverByLineNumber keeps the one citation style: a "piv_driver.go:N"
// in this package's tests is refused unless it is marked as history ("Was …", "formerly …"), and
// every piv_driver.go citation must resolve.
func TestNoYubiKeyTestCitesPivDriverByLineNumber(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	tests, _ := filepath.Glob(filepath.Join(filepath.Dir(thisFile), "*_test.go"))
	sources := packageSources()
	for _, test := range tests {
		data, err := os.ReadFile(test)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "regexp.MustCompile") {
				continue
			}
			where := filepath.Base(test) + ":" + itoa(number+1)
			for _, match := range sweeptext.LineCitationPattern.FindAllStringSubmatch(line, -1) {
				if match[1] == "" && match[2] == "piv_driver.go" {
					t.Errorf("%s cites %s by line number: cite piv_driver.go:Func{anchor} (#290)", where, match[0])
				}
			}
			for _, cited := range sweeptext.CitationPattern.FindAllString(line, -1) {
				if strings.HasPrefix(cited, "piv_driver.go:") && !strings.HasPrefix(cited, "piv_driver.go:Func{") {
					if _, _, err := sweeptext.ResolveCitation(sources, cited); err != nil {
						t.Errorf("%s cites %s: %v", where, cited, err)
					}
				}
			}
		}
	}
}

// bareLineReference is a ":N" line number in an entry's prose, the short form of a line citation.
var bareLineReference = regexp.MustCompile(`(?:^|[^\w.)]):\d+\b`)

func packageSources() sweeptext.Sources {
	_, thisFile, _, _ := runtime.Caller(0)
	return sweeptext.DirSources(filepath.Dir(thisFile))
}

func checkSurvivorsResolve(t *testing.T, sources sweeptext.Sources) {
	t.Helper()
	for i, entry := range pivDriverGoOperands {
		key := survivorKey(entry)
		if entry.site == "" {
			t.Errorf("entry %d (%s) has no site recorded — site must be the operand's text on the cited line", i, key)
			continue
		}
		line, have, err := sweeptext.ResolveCitation(sources, entry.at)
		if err != nil {
			t.Errorf("entry %d (%s): %v", i, key, err)
			continue
		}
		if !strings.Contains(have, entry.site) {
			t.Errorf("entry %d (%s) resolves to line %d, which drifted.\n  have: %q\n  want substring: %q", i, key, line, have, entry.site)
		}
		// The closure prose cites by function and anchor too: a bare ":N" there was never
		// resolved, and ":56" had drifted to 57 before #292 converted them (regalia-kms-d9).
		for _, field := range []string{entry.closure, entry.whyTrueOpen} {
			if bare := bareLineReference.FindString(field); bare != "" {
				t.Errorf("entry %d (%s) cites %q by line number in its prose: cite piv_driver.go:Func{anchor}", i, key, bare)
			}
			for _, cited := range sweeptext.CitationPattern.FindAllString(field, -1) {
				if _, _, err := sweeptext.ResolveCitation(sources, cited); err != nil {
					t.Errorf("entry %d (%s) cites %s: %v", i, key, cited, err)
				}
			}
		}
		for _, masking := range sweeptext.CitationPattern.FindAllString(entry.masked, -1) {
			if _, _, err := sweeptext.ResolveCitation(sources, masking); err != nil {
				t.Errorf("entry %d (%s) is masked by %s: %v", i, key, masking, err)
			}
		}
	}
}

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
