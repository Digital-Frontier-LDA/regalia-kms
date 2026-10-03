package audit

// #237 ledger — survivors of the round-2 fault-injection sweep on this package,
// each classified into one of seven buckets. The full prose reasons are inline
// in each row's Notes field; there is no second copy in another file, because
// having two ledgers that can disagree was the wrong shape (the prose version
// was deleted in this PR — see the PR body).
//
// Bucket key:
//   - "reachable-untested-test-added" — the round-2 PR added a test that fires
//     the bug; without the test the operand SURVIVED.
//   - NOTE ON "killed-on-compose": its membership test is "Compose is non-empty", which is
//     WEAKER than the claim it supports. To justify "X cannot be the sole refuser" the compose
//     must add a failing test M alone does not -- Compose must STRICTLY CONTAIN MAlone. Rows
//     satisfying the bucket but not the claim are classified "M-sufficient" by
//     TestLedgerControlArmClassifications, which computes the real comparison. Five rows are in
//     that position once the drift guard is filtered out, and audit.go:(*Recorder).Record{recorder.closed}[0] is a sixth under
//     the conjunctive reading of its mask.
//   - "killed-on-compose" — the operand SURVIVES alone but a sibling operand
//     catches it; the existing tests are sufficient when both are neutralised.
//   - "panic-killed-on-compose" — same as killed-on-compose but the joint
//     bypass panics in the goroutine before the test fires.
//   - "unreachable" — no test construct in this package can put the operand
//     on the wrong side of its branch.
//   - "cannot-pin" — the bug shape is real but no fixture produces the input
//     deterministically.
//   - "panic-on-bypass" — the bypass panics; existing tests suppress the
//     panic by accident, not by design.
// THE DRIFT GUARD IS EXCLUDED FROM MAlone AND Compose, and this is stated rather than applied
// silently so an empty MAlone cannot be mistaken for an unmeasured one.
//
// TestLedgerRowNamesLiveSource fires on ANY mutation of a line this ledger cites, so it appears
// in both arms of every row it touches and cancels in the set difference. Leaving it in was not
// merely noise: because it made MAlone non-empty for 16 of 49 rows, NO row could ever come back
// as "M alone was already sufficient". Filtering it is what made seven such rows visible.
//
// A row reading MAlone: []string{} now means no BEHAVIOURAL test detected the masking guard
// alone — which is what a reader was entitled to assume it already meant.
//
// M-ALONE IS AMBIGUOUS WHEN Masking NAMES A CONJUNCTION. For audit.go:(*Recorder).Record{recorder.closed}[0], whose mask is
// audit.go:(*Recorder).Record{recorder.file.Write(line)}[0]+audit.go:(*Recorder).Record{recorder.file.Sync()}[0], each guard singly SURVIVES while the two together KILL. So
// "M alone" reads as [] under one interpretation and as {TestDurableIsFalseWhenTheWriteItselfFailed} under the other, and
// the two give opposite verdicts. The claim the arm tests is "X cannot be the sole refuser
// because M catches it", and M is the mask AS NAMED — so the conjunction is the correct reading.
// Both are recorded below, because singles-survive-but-conjunction-kills locates the masking in
// the PAIR rather than in a member, which is more than either number alone says.
//
//   - "needs-fixing" — control-arm measurement (X+M vs M-alone) showed
//     neither arm fires a test; the prior compose-only classification was
//     wrong.
//
// FALSIFY: edit any row's Site (the source-line text), trim leading
// whitespace, and re-run the test. The match fails naming the row whose
// Site no longer matches the live source. A separate Site field per row
// is the assertion; the slice as a whole is the cross-reference.
//
// The drift guard strips the sweep's mutation wrappers before comparing
// (sweeptext.StripMutationWrappers), so it survives an in-flight sweep and
// does not false-KILL the very rows it cites. See
// TestEveryFalsifierShapeIsRestored for the pin.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/sweeptext"
)

// ledgerRow is one survivor from #237's fault-injection sweep on this package.
// ID is a citation, "file.go:Func{anchor}[i]" (#282): the function the guard is in, a piece of
// the guard's own text, and i the operand index (multi-operand guards like
// shipper.go:(*shipper).waitShipped{shipper.failures != failures} have [0] and [1]). See
// resolveCitation for the anchor forms. A citation names no line number, so an edit elsewhere in
// the file leaves every ID, and every prose citation of it, unchanged.
//
// MAlone and Compose carry the per-row control-arm measurement (X+M vs
// M-alone failing-test sets). Both are empty slices when the row is not
// part of the masking study. The control-arm is what distinguishes
// "killed-on-compose" from "needs-fixing": the first has non-empty Compose,
// the second has Compose == [] && MAlone == [].
type ledgerRow struct {
	ID      string // e.g. "audit.go:VerifyIntegrity{readShippedMark(path) then err != nil}[0]"
	Verdict string // see bucket key above
	Site    string // verbatim source line text
	Notes   string // bucket-specific prose (defect + masking guard + test name, etc.)
	Test    string // for "*-on-compose" verdicts: the test that catches the joint bypass
	Masking string // for "*-on-compose" verdicts: the sibling operand ID
	// Direction is REQUIRED for "hangs-on-bypass" and is the fix for a precision gap this
	// ledger had one bucket over from the one it was correcting: a hang is a property of ONE
	// direction, and the other direction of the same operand routinely does something else
	// entirely. Of the six rows below, the other direction PANICS for two and is KILLED for four
	// (for shipper.go:(*shipper).waitShipped{shipper.failures != failures}[0] and [1] only since #458; before that each survived alone). A reader
	// acting on a direction-less "hangs-on-bypass" hunts a missing loop terminator and may be
	// looking at a missing nil guard.
	//
	// Format: the mutation that produces the hang, then what the OTHER direction does.
	// TestLedgerHangRowsNameTheirDirection enforces its presence.
	Direction string
	// MAlone: failing tests when the masking guard alone is neutralised.
	// Compose: failing tests when X and the masking guard are both neutralised.
	// Together they classify the row: informative (Compose ⊃ MAlone),
	// M-sufficient (Compose == MAlone), or not-killed (Compose == []).
	MAlone  []string
	Compose []string
}

func ledgerRows() []ledgerRow {
	return []ledgerRow{
		// ===== Bucket 1: reachable-untested-test-added (9) =====
		{
			ID: "verifier.go:(*Recorder).StartVerifier{recorder.closed || recorder.verifyStarted}[1]", Verdict: "reachable-untested-test-added",
			Site:  "\tif recorder.closed || recorder.verifyStarted {",
			Notes: "With verifyStarted bypassed, a second StartVerifier installs a sibling goroutine whose loopCtx outlives recorder.verifyStop; Close() blocks on the leaked goroutine. TestStartVerifierTwiceIsANoOp closes this gap.",
			Test:  "TestStartVerifierTwiceIsANoOp",
		},
		// The round-three rows, classified. Seven were carried as "unclassified", found by
		// reconciling measured survivors against row IDs rather than against the row count. Every
		// operand below was re-measured on 363ce16 before a test was written, and each is KILLED by
		// the test it names. Two did not come from that list: httpsink.go:(*HTTPSink).Send{sink.site != ""}[0] was found by
		// measuring the Send twin of httpsink.go:(*HTTPSink).CommittedHead{site != ""}[0], and shipper.go:nextShipBackoff{backoff < maxShipBackoff}[0] was recorded as
		// unreachable when one direction of it is a behaviour change.
		{
			ID: "audit.go:VerifyIntegrity{errors.Is(statErr, os.ErrNotExist)#2}[0]", Verdict: "reachable-untested-test-added",
			Site:  "\t\tcase errors.Is(statErr, os.ErrNotExist):",
			Notes: "Measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, every case takes the absent arm, so a mark that is PRESENT but behind the collector's acknowledged head -- a forged sidecar -- is reported as durability loss. Both arms refuse; only the diagnosis differs, and the existing tests pinned the absent diagnosis alone.",
			Test:  "TestAMarkBehindTheCollectorIsDiagnosedAsForgedRatherThanLost",
		},
		{
			ID: "httpsink.go:(*HTTPSink).Send{sink.site != \"\"}[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif sink.site != \"\" {",
			Notes: "NOT in the round-three list. Found by measuring the Send twin of httpsink.go:(*HTTPSink).CommittedHead{site != \"\"}[0] on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, Send files the identity-keyed stream's events with X-Regalia-Site present and empty instead of absent.",
			Test:  "TestAnEmptySiteSendsNoSiteHeaderOnEitherCall",
		},
		{
			ID: "httpsink.go:(*HTTPSink).CommittedHead{site != \"\"}[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif site != \"\" {",
			Notes: "Measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, CommittedHead asks about the identity-keyed stream with X-Regalia-Site present and empty. Send and CommittedHead must address the same stream, and the collector contract keys on the header 'when present'; this repository's collector reads absent and empty alike, so only the request shows the difference.",
			Test:  "TestAnEmptySiteSendsNoSiteHeaderOnEitherCall",
		},
		{
			ID: "httpsink.go:(*HTTPSink).CommittedHead{auditHashPattern.MatchString}[1]", Verdict: "reachable-untested-test-added",
			Site:  "\tif (position.Sequence > 0) != (position.Hash != \"\") || (position.Hash != \"\" && !auditHashPattern.MatchString(position.Hash)) {",
			Notes: "Measured on 363ce16: FALSE SURVIVED / TRUE KILLED. Forced false, the pattern half of the guard never runs, so a head with a sequence and a present hash that is not a chained hash is accepted as the one authoritative value in reconciliation. KILLED by that test's 'a hash that is not a chained hash' row.",
			Test:  "TestCommittedHeadRefusesShapesTheCollectorCannotEmit",
		},
		{
			ID: "httpsink.go:(*HTTPSink).CommittedHead{auditHashPattern.MatchString}[2]", Verdict: "reachable-untested-test-added",
			Site:  "\tif (position.Sequence > 0) != (position.Hash != \"\") || (position.Hash != \"\" && !auditHashPattern.MatchString(position.Hash)) {",
			Notes: "Measured on 363ce16: FALSE SURVIVED / TRUE KILLED. Forced false it is the same bypass as httpsink.go:(*HTTPSink).CommittedHead{auditHashPattern.MatchString}[1] forced false, so the one fixture kills both.",
			Test:  "TestCommittedHeadRefusesShapesTheCollectorCannotEmit",
		},
		{
			ID: "shipper.go:nextShipBackoff{backoff < maxShipBackoff}[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif backoff < maxShipBackoff {",
			Notes: "Was shipper.go:181[0], recorded unreachable. Re-measured on 363ce16 (pre-extraction): FALSE SURVIVED / TRUE SURVIVED. Forced false is a BEHAVIOUR change, not an unreachable branch: the backoff never doubles, and a down collector is retried every 100ms for as long as it is down. Forced true cannot be told apart: doubling the maximum is capped straight back. The comparison moved into nextShipBackoff so it can be tested without a minute of real timers, and the move was proved behaviour-identical against 363ce16 by a differential trace of the real run loop (same failures in, same delays out, the cap and reset-on-success included).",
			Test:  "TestShipBackoffDoublesAndIsHeldAtItsMaximum",
		},
		{
			ID: "shipper.go:nextShipBackoff{backoff > maxShipBackoff}[0]", Verdict: "reachable-untested-test-added",
			Site:  "\t\tif backoff > maxShipBackoff {",
			Notes: "Was shipper.go:183[0]. Measured on 363ce16 (pre-extraction): FALSE SURVIVED / TRUE KILLED. Forced false, doubling from 25.6s overshoots to 51.2s and stays there, since the outer comparison stops any further doubling (not 'without bound', as first recorded): every recovery waits up to 51.2s instead of 30s. Extraction and differential proof as for shipper.go:nextShipBackoff{backoff < maxShipBackoff}[0].",
			Test:  "TestShipBackoffDoublesAndIsHeldAtItsMaximum",
		},
		{
			ID: "verifier.go:(*Recorder).VerifyNow{len(events) > 0}[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif len(events) > 0 {",
			Notes: "Measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, a verify run over an empty journal reads the head of an empty slice and panics. Reachable on every fresh site: the periodic verifier's first run sees no events.",
			Test:  "TestVerifyingARecorderThatHasWrittenNothingIsIntact",
		},

		// ===== Bucket 2: compose-proved (14, after control-arm re-classification) =====
		// killed-on-compose sub-bucket (10). MAlone / Compose are the 3-arm
		// measurement from the control-arm script.
		{
			ID: "audit.go:Open{readShippedMark(path) then err != nil}[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Open's redo of the journal's collector-side position (the readShippedMark call is just above the if check); the joint bypass with the audit.go:VerifyIntegrity{readShippedMark(path) then err != nil}[0] masking guard is caught by the test in Test and Compose.",
			Test:    "TestACorruptShippedMarkIsRefusedNotIgnored",
			Masking: "audit.go:VerifyIntegrity{readShippedMark(path) then err != nil}[0]",
			MAlone:  []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
			Compose: []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
		},
		{
			ID: "audit.go:(*Recorder).Record{recorder.file.Write(line)}[0]", Verdict: "killed-on-compose",
			Site:    "\tif _, err := recorder.file.Write(line); err != nil {",
			Notes:   "Append-then-Sync; the masking guard at audit.go:(*Recorder).Record{recorder.file.Sync()}[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestDurableIsFalseWhenTheWriteItselfFailed",
			Masking: "audit.go:(*Recorder).Record{recorder.file.Sync()}[0]",
			MAlone:  []string{},
			Compose: []string{"TestDurableIsFalseWhenTheWriteItselfFailed"},
		},
		{
			ID: "audit.go:(*Recorder).Record{recorder.file.Sync()}[0]", Verdict: "killed-on-compose",
			Site:    "\tif err := recorder.file.Sync(); err != nil {",
			Notes:   "Sync after Write; the masking guard at audit.go:(*Recorder).Record{recorder.file.Write(line)}[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestDurableIsFalseWhenTheWriteItselfFailed",
			Masking: "audit.go:(*Recorder).Record{recorder.file.Write(line)}[0]",
			MAlone:  []string{},
			Compose: []string{"TestDurableIsFalseWhenTheWriteItselfFailed"},
		},
		{
			ID: "audit.go:verifyEvents{decoder.Decode(&event)}[0]", Verdict: "killed-on-compose",
			Site:    "\t\tif err := decoder.Decode(&event); err != nil {",
			Notes:   "Per-event decoder; the masking guard at audit.go:verifyEvents{event.PreviousHash != previous}[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestAnEventDeletedFromTheMiddleAndRelinkedIsRefused",
			Masking: "audit.go:verifyEvents{event.PreviousHash != previous}[0]",
			MAlone:  []string{"TestAnEventDeletedFromTheMiddleAndRelinkedIsRefused"},
			Compose: []string{"TestAnEventDeletedFromTheMiddleAndRelinkedIsRefused"},
		},
		{
			ID: "reconcile.go:ReconcileContinuity{readShippedForReconcile(journalPath) then err != nil}[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Local shipped mark read in ReconcileContinuity; the masking guard at audit.go:VerifyIntegrity{readShippedMark(path) then err != nil}[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestACorruptShippedMarkIsRefusedNotIgnored",
			Masking: "audit.go:VerifyIntegrity{readShippedMark(path) then err != nil}[0]",
			MAlone:  []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
			Compose: []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
		},
		{
			ID: "reconcile.go:readShippedForReconcile{err != nil}[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "readShippedForReconcile inner read; the masking guard at audit.go:VerifyIntegrity{readShippedMark(path) then err != nil}[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestACorruptShippedMarkIsRefusedNotIgnored",
			Masking: "audit.go:VerifyIntegrity{readShippedMark(path) then err != nil}[0]",
			MAlone:  []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
			Compose: []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
		},
		{
			ID: "verifier.go:(*Recorder).VerifyNow{os.Open(path) then err != nil}[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "VerifyNow's os.Open failure check (the os.Open call is just above the if check); the masking guard at verifier.go:(*Recorder).VerifyNow{verifyEvents(io.LimitReader then err != nil}[0] catches the joint bypass via the verifyEvents error path. The 3-arm protocol shows TestVerifyNowOnAMissingJournalReturnsUnreadableRatherThanPanicking fires ONLY on the joint bypass, not on M-alone — proof the masking guard's tests do NOT cover X alone.",
			Test:    "TestVerifyNowOnAMissingJournalReturnsUnreadableRatherThanPanicking",
			Masking: "verifier.go:(*Recorder).VerifyNow{verifyEvents(io.LimitReader then err != nil}[0]",
			MAlone:  []string{"TestVerifierClassifiesAReadFailureAsUnreadableNotBroken"},
			Compose: []string{"TestVerifierClassifiesAReadFailureAsUnreadableNotBroken", "TestVerifierDistinguishesUnreadableFromBroken", "TestVerifyNowOnAMissingJournalReturnsUnreadableRatherThanPanicking"},
		},
		{
			ID: "verifier.go:(*Recorder).VerifyNow{headHash != lastHash}[0]", Verdict: "killed-on-compose",
			Site:    "\tif head != sequence || headHash != lastHash {",
			Notes:   "Prefix-vs-recorder-head divergence check; the masking guard at verifier.go:(*Recorder).VerifyNow{headHash != lastHash}[1] catches the joint bypass via TestAReplacementChainOfTheSameLengthIsReportedAsBroken.",
			Test:    "TestAReplacementChainOfTheSameLengthIsReportedAsBroken",
			Masking: "verifier.go:(*Recorder).VerifyNow{headHash != lastHash}[1]",
			MAlone:  []string{"TestAReplacementChainOfTheSameLengthIsReportedAsBroken"},
			Compose: []string{"TestAReplacementChainOfTheSameLengthIsReportedAsBroken", "TestATruncationUnderARunningRecorderIsReportedAsBroken"},
		},
		{
			ID: "verifier.go:(*Recorder).StartVerifier{recorder.closed || recorder.verifyStarted}[0]", Verdict: "killed-on-compose",
			Site:    "\tif recorder.closed || recorder.verifyStarted {",
			Notes:   "StartVerifier's second-call refusal, first operand (recorder.closed); the masking guard at verifier.go:(*Recorder).StartVerifier{recorder.closed || recorder.verifyStarted}[1] catches the joint bypass via TestStartVerifierTwiceIsANoOp. Control-arm: Compose == MAlone (both fire TestStartVerifierTwiceIsANoOp); X is uninformative — the masking guard's bypass alone catches the bug. Verdict stays killed-on-compose because the joint bypass IS caught, but the [1] operand is the load-bearing one.",
			Test:    "TestStartVerifierTwiceIsANoOp",
			Masking: "verifier.go:(*Recorder).StartVerifier{recorder.closed || recorder.verifyStarted}[1]",
			MAlone:  []string{"TestStartVerifierTwiceIsANoOp"},
			Compose: []string{"TestStartVerifierTwiceIsANoOp"},
		},
		// 3-way compose (1)
		{
			ID: "audit.go:(*Recorder).Record{recorder.closed}[0]", Verdict: "killed-on-compose",
			Site:    "\tif recorder.closed {",
			Notes:   "Record's recorder-closed refusal. CONJUNCTIVE MASK: audit.go:(*Recorder).Record{recorder.file.Write(line)}[0] and :387[0] each SURVIVE alone; the two together KILL TestDurableIsFalseWhenTheWriteItselfFailed. MAlone above uses the mask as NAMED, the reading the claim requires -- under it Compose == MAlone, the compose adds nothing, and this row is M-sufficient. Under the singles reading MAlone is [] and the row reads informative. Two defensible readings, opposite verdicts; recorded because singles-survive-but-conjunction-kills locates the masking in the PAIR, which is more than either number says.",
			Test:    "TestDurableIsFalseWhenTheWriteItselfFailed",
			Masking: "audit.go:(*Recorder).Record{recorder.file.Write(line)}[0]+audit.go:(*Recorder).Record{recorder.file.Sync()}[0]",
			MAlone:  []string{"TestDurableIsFalseWhenTheWriteItselfFailed"}, // the mask AS NAMED; each guard singly SURVIVES
			Compose: []string{"TestDurableIsFalseWhenTheWriteItselfFailed"},
		},
		// panic-killed-on-compose sub-bucket (4)
		{
			ID: "audit.go:Open{os.OpenFile(path then err != nil}[0]", Verdict: "panic-killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Open's file-open err check (the OpenFile call is just above it); the masking guard at audit.go:Open{file.Stat() then err != nil}[0] catches the joint bypass. The panic propagates through defer file.Close() on a nil handle.",
			Test:    "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes",
			Masking: "audit.go:Open{file.Stat() then err != nil}[0]",
			MAlone:  []string{},
			Compose: []string{"TestTheAcceptedFileModesAreTheOnesTheMessageDescribes", "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes/owner_cannot_write, _so_the_append-only_open_fails_first"},
		},
		{
			ID: "audit.go:Open{file.Stat() then err != nil}[0]", Verdict: "panic-killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Open's file-Stat err check (the Stat call is just above it); the masking guard at audit.go:Open{os.OpenFile(path then err != nil}[0] catches the joint bypass. With both operands neutralised, the nil file deref panics.",
			Test:    "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes",
			Masking: "audit.go:Open{os.OpenFile(path then err != nil}[0]",
			MAlone:  []string{},
			Compose: []string{"TestTheAcceptedFileModesAreTheOnesTheMessageDescribes", "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes/owner_cannot_write, _so_the_append-only_open_fails_first"},
		},
		{
			ID: "audit.go:(*Recorder).Ready{recorder.shipper != nil}[1]", Verdict: "panic-killed-on-compose",
			Site:    "\treturn recorder != nil && recorder.sink != nil && recorder.shipper != nil &&",
			Notes:   "Readiness conjunction. RE-MEASURED with -vet=off, because go test runs vet and vet refuses the same-chain compose `false && false`: in the FALSE direction X alone is KILLED by 4 tests and X+M kills the same 4, so the masking claim is vacuous THERE -- the operand is detected on its own. The surviving direction is TRUE, which the compose arms do not exercise. As with hangs-on-bypass, a compose verdict is direction-dependent and this row does not say which direction it describes.",
			Test:    "TestAnUnwiredRecorderIsNeverReady",
			Masking: "audit.go:(*Recorder).Ready{recorder.shipper != nil}[2]",
			MAlone:  []string{},
			Compose: []string{"TestAnUnwiredRecorderIsNeverReady"},
		},
		{
			ID: "audit.go:(*Recorder).Ready{recorder.shipper != nil}[2]", Verdict: "panic-killed-on-compose",
			Site:    "\treturn recorder != nil && recorder.sink != nil && recorder.shipper != nil &&",
			Notes:   "Readiness conjunction. RE-MEASURED with -vet=off, because go test runs vet and vet refuses the same-chain compose `false && false`: in the FALSE direction X alone is KILLED by 4 tests and X+M kills the same 4, so the masking claim is vacuous THERE -- the operand is detected on its own. The surviving direction is TRUE, which the compose arms do not exercise. As with hangs-on-bypass, a compose verdict is direction-dependent and this row does not say which direction it describes.",
			Test:    "TestAnUnwiredRecorderIsNeverReady",
			Masking: "audit.go:(*Recorder).Ready{recorder.shipper != nil}[1]",
			MAlone:  []string{},
			Compose: []string{"TestAnUnwiredRecorderIsNeverReady"},
		},

		// ===== Bucket 6: re-classified after control-arm (2: 1 unreachable, 1 cannot-be-sole-refuser) =====
		{
			ID: "shipper.go:(*shipper).run{shipper.stopped || shipper.ctx.Err() != nil}[0]", Verdict: "unreachable",
			Site:    "\t\tif shipper.stopped || shipper.ctx.Err() != nil {",
			Notes:   "UNREACHABLE, reclassified from needs-fixing. shipper.stopped has exactly two writers -- shipper.go:(*shipper).run{shipper.stopped || shipper.ctx.Err() != nil then shipper.stopped = true} and :167 -- both immediately followed by `return` from run(), which newShipper starts once with no restart path and never sets, and close() does not set. So at :133 the operand is always false. Measured signature of an always-false operand in an || chain: deleting it SURVIVES (a no-op) while forcing it true is KILLED. The control arm's Compose == [] and MAlone == [] was correct; the inference 'Real defect' was not -- 'no test fires' has several causes and unreachable is one of them.",
			MAlone:  []string{},
			Compose: []string{},
		},
		{
			ID: "shipper.go:(*shipper).run{if shipper.ctx.Err() != nil}[0]", Verdict: "cannot-be-sole-refuser",
			Site:    "\t\tif shipper.ctx.Err() != nil {",
			Notes:   "CANNOT BE THE SOLE REFUSER, reclassified from needs-fixing. Masked by shipper.go:(*shipper).run{shipper.stopped || shipper.ctx.Err() != nil}[1], the ctx check at the top of the loop. Deleted, a failed send with a cancelled context falls to the backoff select, which wakes IMMEDIATELY on <-shipper.ctx.Done(), loops, and exits at :133. The shipper does not continue sending; the exit is delayed one iteration. Measured: deleting it SURVIVES, forcing it true is KILLED.",
			MAlone:  []string{},
			Compose: []string{},
		},

		// ===== Bucket 3: unreachable (15) =====
		{
			ID: "audit.go:Durable{errors.Is(err, ErrDurable)}[0]", Verdict: "unreachable",
			Site:  "func Durable(err error) bool { return err != nil && errors.Is(err, ErrDurable) }",
			Notes: "Durable is the public classification helper; the err operand is the only way to reach errors.Is(err, ErrDurable).",
		},
		{
			ID: "audit.go:writeMark{json.Marshal(mark) then err != nil}[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "json.Marshal(highWaterMark) cannot fail for a struct of strings and numbers (the Marshal call is just above the if check).",
		},
		{
			ID: "audit.go:VerifyIntegrity{statErr != nil}[0]", Verdict: "unreachable",
			Site:  "\t\tcase statErr != nil:",
			Notes: "Case-init operand in the mark-existence stat's else branch (handled by the case statErr == nil and the explicit os.ErrNotExist branch).",
		},
		{
			ID: "audit.go:Open{info.Mode().Perm()&0o077}[0]", Verdict: "unreachable",
			Site:  "\tif !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {",
			Notes: "Open's mode-bits check; the audit buffer is created by Open itself with 0o600, so no test construct in this package reaches the wrong side of this branch.",
		},
		{
			ID: "audit.go:(*Recorder).Record{json.Marshal(event) then err != nil}[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "json.Marshal(event) cannot fail for the Event struct's string/number/time fields (the Marshal call is just above the if check).",
		},
		{
			ID: "audit.go:Verify{!info.Mode().IsRegular()}[0]", Verdict: "unreachable",
			Site:  "\tif err != nil || !info.Mode().IsRegular() {",
			Notes: "Verify's info.Mode().IsRegular() check; Verify is called only on a journal the daemon opened itself or that an operator passed via VerifyIntegrity.",
		},
		{
			ID: "httpsink.go:(*HTTPSink).Send{len(body) > 64<<10}[0]", Verdict: "unreachable",
			Site:  "\tif err != nil || len(body) > 64<<10 {",
			Notes: "json.Marshal(event) and the body-size check; NewHTTPSink rejects empty bodies up-front.",
		},
		{
			ID: "httpsink.go:(*HTTPSink).Send{http.MethodPost then err != nil}[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "ValidateSinkURL pre-rejects malformed URLs; NewRequestWithContext with valid input and a method/URL cannot fail (the NewRequestWithContext call is just above the if check).",
		},
		{
			ID: "httpsink.go:(*HTTPSink).Send{response.Body != nil}[0]", Verdict: "unreachable",
			Site:  "\tif response.Body != nil {",
			Notes: "http.Client.Do always returns a non-nil *Response when err is nil; the err != nil check above makes this always true.",
		},
		{
			ID: "httpsink.go:(*HTTPSink).CommittedHead{http.MethodGet then err != nil}[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "Same shape as httpsink.go:(*HTTPSink).Send{http.MethodPost then err != nil}[0] — pre-rejected by ValidateSinkURL (the NewRequestWithContext call is just above the if check).",
		},
		{
			ID: "httpsink.go:(*HTTPSink).CommittedHead{response.Body != nil}[0]", Verdict: "unreachable",
			Site:  "\t\tif response.Body != nil {",
			Notes: "Same shape as httpsink.go:(*HTTPSink).Send{response.Body != nil}[0].",
		},
		{
			ID: "httpsink.go:(*HTTPSink).Ready{sink.client.Do(request) then err != nil}[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "Ready's err check after sink.client.Do (the Do call is just above it); the client/baseURL are validated by NewHTTPSink so no test construct produces the wrong side.",
		},
		{
			ID: "httpsink.go:(*HTTPSink).Ready{response.Body != nil}[0]", Verdict: "unreachable",
			Site:  "\tif response.Body != nil {",
			Notes: "Same shape — Ready follows the same Do/Body pattern.",
		},
		{
			ID: "audit.go:VerifyIntegrity{errors.Is(statErr, os.ErrNotExist)#1}[0]", Verdict: "unreachable",
			Site:  "\tcase errors.Is(statErr, os.ErrNotExist):",
			Notes: "Round three, measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Section 17: the operand is false only for a stat error other than not-exist, and readMark refuses every such error on the same path one call earlier, so reaching it needs the path's stat class to change between the two calls. Pinned where it is enforced by TestAMarkWhoseFileCannotBeStattedIsRefusedByTheReadBeforeTheStat (a symlink loop and an over-long mark name). Compose measured: forced true alone, that test PASSES; readMark relaxed to treat every read failure as absent, it FAILS on the classification's default arm ('cannot be classified'); both together, a one-event journal with an unstattable mark VERIFIES CLEAN. Defence in depth, keep.",
		},
		{
			ID: "verifier.go:(*Recorder).VerifyNow{recorder.closed}[0]", Verdict: "unreachable",
			Site:  "\tif recorder.closed {",
			Notes: "After Close, the cached VerifyState is the only readable view; a fresh run produces the same answer.",
		},

		// ===== Bucket 4: cannot-pin (4) =====
		{
			ID: "audit.go:writeMark{os.WriteFile(temporary}[0]", Verdict: "cannot-pin",
			Site:  "\tif err := os.WriteFile(temporary, encoded, 0o600); err != nil {",
			Notes: "os.WriteFile(.tmp, …) failure requires an OS-level fault (full disk, read-only mount); the masking guard at os.Rename swallows the same fault and we cannot fake just one.",
		},
		{
			ID: "audit.go:VerifyIntegrity{mark.Sequence == 0}[0]", Verdict: "cannot-pin",
			Site:  "\tif len(events) >= 1 && markFileExists && mark.Sequence == 0 {",
			Notes: "verifyMark boundary check requires a sidecar that is structurally valid but semantically wrong; every codepath that writes such a mark is itself guarded.",
		},
		{
			ID: "audit.go:VerifyIntegrity{reachedHash != mark.Hash}[1]", Verdict: "cannot-pin",
			Site:  "\tif reached == mark.Sequence && mark.Hash != genesisHash && reachedHash != mark.Hash {",
			Notes: "Same shape as audit.go:VerifyIntegrity{mark.Sequence == 0}[0] for the second mark kind; documented in source as §17 unreachable.",
		},
		{
			ID: "shipper.go:(*shipper).waitShipped{shipper.stopped}[0]", Verdict: "cannot-pin",
			Site:  "\t\tif shipper.stopped {",
			Notes: "waitShipped returning ErrSinkUnavailable because the caller's context ended first races natural delivery; the bug only shows when cancellation lands in the same scheduling slot as a delivery.",
		},

		// ===== Bucket 5: hangs-on-bypass (6) =====
		{
			ID: "audit.go:(*Recorder).Close{verifyStop != nil}[0]", Verdict: "hangs-on-bypass",
			Site:      "\tif verifyStop != nil {",
			Direction: "deleted (false &&) HANGS; forced true PANICS",
			Notes:     "Close() without prior StartVerifier() leaves verifyStop nil. DELETED, the stop is never called, the verifier goroutine is never wound down and Close waits on it: measured `panic: test timed out after 1m30s` with TestRecorderPersistsOrderedIntegrityChainAndShipsOffHost still running. FORCED TRUE, the nil verifyStop is called and the run nil-derefs. So the two directions have different defect SHAPES -- a missing shutdown path one way, a missing nil guard the other -- and the earlier direction-less verdict pointed at the wrong one.",
		},
		{
			ID: "shipper.go:(*shipper).waitShipped{shipper.shipped >= sequence}[0]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.shipped >= sequence {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED",
			Notes:     "waitShipped's first-poll short-circuit. DELETED, waitShipped never returns nil and the caller waits forever -- measured as a timeout, not a crash; the earlier note's 'hangs in a hot loop' was the right mechanism under the wrong verdict. FORCED TRUE it is KILLED, so this operand IS detected in one direction and the ledger was not crediting itself with that coverage.",
		},
		{
			ID: "shipper.go:(*shipper).run{shipper.stopped || shipper.ctx.Err() != nil}[1]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.stopped || shipper.ctx.Err() != nil {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED",
			Notes:     "Run-loop exit check, ctx-err operand. DELETED, the loop NEVER TERMINATES: this operand is the sole terminator of run(). That single measurement is what makes shipper.go:(*shipper).run{shipper.stopped || shipper.ctx.Err() != nil}[0] and shipper.go:(*shipper).run{if shipper.ctx.Err() != nil}[0] redundant, and is why both were reclassified in this pass rather than each being argued separately. FORCED TRUE the loop exits at once and is KILLED. The earlier note claimed a deref of shipper.sink after teardown; no deref occurs.",
		},
		{
			ID: "shipper.go:(*shipper).run{len(shipper.pending) == 0}[0]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif len(shipper.pending) == 0 {",
			Direction: "forced true HANGS; deleted (false &&) PANICS",
			Notes:     "Run-loop's idle-tick check. FORCED TRUE, the idle branch runs unconditionally and the loop spins without ever draining pending -- a hang. DELETED, the idle branch is never taken and the head read runs against an empty queue, panicking on the index. Both directions are defects and neither is the other's shape.",
		},
		{
			ID: "shipper.go:(*shipper).waitShipped{shipper.failures != failures}[0]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.failures != failures && shipper.shipped < sequence {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED by TestAnEarlierEventsAcknowledgementDoesNotFailAWaitingOperation",
			Notes:     "waitShipped's early fail-closed check: a sink failure since the wait began, with this event still unshipped, fails the operation now instead of holding it through the backoff. Timeout-first classifier, -vet=off. DELETED: HANGS in TestHighRiskRecordFailsClosedAfterDurableLocalAppend -- measured 3/3 on 95453e2 (#456) and 2/2 again on 5359d57 (#458). This is one conjunct of an AND, so deleting it deletes the whole early refusal; no sibling can catch the bypass. FORCED TRUE: the condition reduces to shipped < sequence, so any wake with the event unshipped fails the operation -- including the acknowledgement of an EARLIER event under healthy shipping. Survived until #458; now KILLED 5/5 across the package and 100/100 targeted, only by TestAnEarlierEventsAcknowledgementDoesNotFailAWaitingOperation, built at the Recorder boundary: an event recorded without waiting, a high-risk event parked behind it, and the first acknowledged while the second is held at its gate.",
		},
		{
			ID: "shipper.go:(*shipper).waitShipped{shipper.failures != failures}[1]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.failures != failures && shipper.shipped < sequence {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED by TestAnAcknowledgedEventIsNotReportedFailedWhenAFailureAlsoLanded",
			Notes:     "waitShipped's early fail-closed check: a sink failure since the wait began, with this event still unshipped, fails the operation now instead of holding it through the backoff. Timeout-first classifier, -vet=off. DELETED: HANGS in TestHighRiskRecordFailsClosedAfterDurableLocalAppend -- measured 3/3 on 95453e2 (#456) and 2/2 again on 5359d57 (#458). This is one conjunct of an AND, so deleting it deletes the whole early refusal; no sibling can catch the bypass. FORCED TRUE: the condition reduces to failures != failures0, so a failure seen alongside this event's acknowledgement reports a successful audit write as failed. Survived until #458; now KILLED 5/5 across the package and 100/100 targeted, only by TestAnAcknowledgedEventIsNotReportedFailedWhenAFailureAlsoLanded. THAT TEST DRIVES shipper STATE DIRECTLY, and the section-17 boundary is why: Record holds recorder.mu across waitShipped and is the only caller of enqueue and waitShipped, so no event after this one can be queued while it waits -- #458's hypothesised later-event failure cannot be produced through the Recorder. The remaining path is a failed attempt on an event up to this one, then a retry that acknowledges it, both before the woken waiter re-takes shipper.mu; the retry waits at least minShipBackoff (100ms), so it needs the waiter descheduled for a whole backoff interval. Reachable under load, ordered by the scheduler, not constructible from the Recorder boundary.",
		},
	}
}

// citationPattern is one "file.go:Func{anchor}[i]" citation; the operand index is optional in prose.
// The function is Name, (T).Name or (*T).Name. An anchor holds no braces.
var citationPattern = regexp.MustCompile(`\b([a-z_]+\.go):((?:\(\*?[A-Za-z_]\w*\)\.)?[A-Za-z_]\w*)\{([^{}]+)\}(\[\d+\])?`)

// lineCitationPattern is the form #282 retired, "file.go:N[i]": a line number, renumbered by every
// edit above it. Only history may still use it ("Was …", "formerly …"), naming where a row used to be.
var lineCitationPattern = regexp.MustCompile(`(?i)(was |formerly )?\b([a-z_]+\.go):(\d+)\b`)

// citationSources reads a file of this package for resolveCitation, through
// sweeptext.StripMutationWrappers so a citation resolves during an in-flight sweep -- without the
// strip, a row whose guard has just been mutated would go red on its own drift guard, and a sweep
// harness reading a red as KILLED would retire the operand as covered when nothing detects it.
type citationSources func(file string) (string, error)

func liveSources(t *testing.T) citationSources {
	_, thisFile, _, _ := runtime.Caller(0)
	auditDir := filepath.Dir(thisFile)
	return func(file string) (string, error) {
		data, err := os.ReadFile(filepath.Join(auditDir, file))
		if err != nil {
			return "", err
		}
		return sweeptext.StripMutationWrappers(string(data)), nil
	}
}

// resolveCitation finds the source line a citation names, and returns it with its text.
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
func resolveCitation(sources citationSources, citation string) (int, string, error) {
	match := citationPattern.FindStringSubmatch(citation)
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

// checkRowsResolve is the drift guard over a set of sources: each row's ID resolves to one line,
// and that line is the row's Site.
func checkRowsResolve(t *testing.T, sources citationSources) {
	t.Helper()
	rows := ledgerRows()
	if len(rows) == 0 {
		t.Fatalf("the ledger is empty: post-PR tally is 42 — a zero count means the slice was deleted")
	}
	for _, row := range rows {
		line, have, err := resolveCitation(sources, citationPattern.FindString(row.ID))
		if err != nil {
			t.Errorf("row %q: %v", row.ID, err)
			continue
		}
		if want := strings.TrimRight(row.Site, " \t\r"); have != want {
			t.Errorf("row %q: resolves to line %d, which drifted.\n  have: %q\n  want: %q", row.ID, line, have, want)
		}
	}
}

// TestLedgerRowNamesLiveSource walks the ledger rows and asserts each ID still names one line of
// the live source (resolveCitation), and that line is still the row's Site.
//
// FALSIFY: change one row's Site to a string that does not match the live source, or set Site to
// "INTENTIONALLY BROKEN"; or change an ID's anchor to text the function holds twice, or not at
// all. The test fails naming the row's ID — proof that the assertion is the one tripping.
func TestLedgerRowNamesLiveSource(t *testing.T) {
	checkRowsResolve(t, liveSources(t))
}

// TestLedgerSurvivesALineAddedAboveEveryGuard is #282's "done when": a line added at the top of
// every cited file changes no citation, so the ledger needs no edit. It is the cost the line
// numbers had: one field added to Event renumbered 61 citations of audit.go.
//
// FALSIFY: put a line number back into the resolver (resolve "file.go:N" by N). This fails on
// every row.
func TestLedgerSurvivesALineAddedAboveEveryGuard(t *testing.T) {
	live := liveSources(t)
	checkRowsResolve(t, func(file string) (string, error) {
		source, err := live(file)
		return "// a line added above every guard (#282)\n" + source, err
	})
}

// TestLedgerCoverage asserts every row has a known verdict and the bucketed
// sums equal the current tally (9 reachable-untested-test-added + 10 killed-on-compose +
// 4 panic-killed-on-compose + 16 unreachable + 4 cannot-pin + 6 hangs-on-bypass +
// 1 cannot-be-sole-refuser = 50). The two shipper.go:(*shipper).waitShipped{shipper.failures != failures} rows moved from
// killed-on-compose to hangs-on-bypass on re-measurement (#453); the count moved with them.
// The seven round-three rows left "unclassified" when they got verdicts: six gained tests and
// audit.go:VerifyIntegrity{errors.Is(statErr, os.ErrNotExist)#1}[0] is unreachable, httpsink.go:(*HTTPSink).Send{sink.site != ""}[0] joined as a new row, and the row formerly shipper.go:181[0]
// left unreachable for a test (it is now shipper.go:nextShipBackoff{backoff < maxShipBackoff}[0]).
//
// The sums are computed at test time, so a row dropped from ledgerRows() or a
// verdict renamed without an updated tally surfaces here.
// TestLedgerHangRowsNameTheirDirection makes the Direction field a schema requirement rather
// than a habit.
//
// A hang belongs to ONE direction of an operand; the other direction routinely does something
// with a different remedy — of the six rows here, the other direction panics for two and is
// KILLED for four. A verdict that cannot say which direction it describes sends a reader after the
// wrong defect, which is the failure this whole pass exists to correct.
//
// FALSIFY: drop the Direction from any hangs-on-bypass row. This fails naming that row.
func TestLedgerHangRowsNameTheirDirection(t *testing.T) {
	seen := 0
	for _, row := range ledgerRows() {
		if row.Verdict != "hangs-on-bypass" {
			continue
		}
		seen++
		if row.Direction == "" {
			t.Errorf("%s is hangs-on-bypass with no Direction: a hang is a property of one "+
				"direction, and the other direction of this operand may be a panic or a kill",
				row.ID)
			continue
		}
		if !strings.Contains(row.Direction, "HANG") {
			t.Errorf("%s: Direction %q does not say which mutation hangs", row.ID, row.Direction)
		}
	}
	if seen == 0 {
		t.Fatal("no hangs-on-bypass rows found — this test would pass while checking nothing")
	}
}

func TestLedgerCoverage(t *testing.T) {
	rows := ledgerRows()
	want := map[string]int{
		"reachable-untested-test-added": 9,
		"killed-on-compose":             10,
		"panic-killed-on-compose":       4,
		"unreachable":                   16,
		"cannot-pin":                    4,
		"hangs-on-bypass":               6,
		"cannot-be-sole-refuser":        1,
	}
	got := map[string]int{}
	for _, row := range rows {
		got[row.Verdict]++
	}
	for v, n := range want {
		if got[v] != n {
			t.Errorf("verdict %q: have %d rows, want %d (post-PR tally)", v, got[v], n)
		}
	}
	total := 0
	for _, n := range got {
		total += n
	}
	if total != 50 {
		t.Errorf("total rows: have %d, want 50 (42, then 7 found by reconciling IDs rather than counts, then httpsink.go:(*HTTPSink).Send{sink.site != \"\"}[0] found beside one of them)", total)
	}
	// Sanity: every row has a verdict we counted.
	for v := range got {
		if _, ok := want[v]; !ok {
			t.Errorf("row carries unknown verdict %q: add it to the tally", v)
		}
	}
	// Suppress unused-import style check on fmt (used by no-code-as-yet extension
	// points; kept here so this test file can be edited for future ledger work).
	_ = fmt.Sprintf
}

// TestLedgerControlArmClassifications pins the per-row control-arm verdict against
// the source data, so the MAlone / Compose fields cannot be edited without this
// test naming the row.
//
// A row's classification is:
//   - "informative"   — Compose is non-empty AND Compose != MAlone (X contributes uniquely).
//   - "M-sufficient"  — Compose is non-empty AND Compose == MAlone (masking guard's
//     tests catch the bug alone; X is uninformative).
//   - "not-killed"    — Compose is empty AND MAlone is empty (neither arm fires;
//     moved to needs-fixing bucket in the ledger).
//   - "n/a"           — row is not part of the masking study (Bucket 1, 3, 4, 5).
func TestLedgerControlArmClassifications(t *testing.T) {
	rows := ledgerRows()
	want := map[string]string{
		// informative (Compose non-empty AND Compose != MAlone)
		"audit.go:Open{readShippedMark(path) then err != nil}[0]":                                   "M-sufficient",
		"audit.go:(*Recorder).Record{recorder.file.Write(line)}[0]":                                 "informative",
		"audit.go:(*Recorder).Record{recorder.file.Sync()}[0]":                                      "informative",
		"audit.go:verifyEvents{decoder.Decode(&event)}[0]":                                          "M-sufficient",
		"reconcile.go:ReconcileContinuity{readShippedForReconcile(journalPath) then err != nil}[0]": "M-sufficient",
		"reconcile.go:readShippedForReconcile{err != nil}[0]":                                       "M-sufficient",
		"verifier.go:(*Recorder).VerifyNow{os.Open(path) then err != nil}[0]":                       "informative",
		"verifier.go:(*Recorder).VerifyNow{headHash != lastHash}[0]":                                "informative",
		"audit.go:Open{os.OpenFile(path then err != nil}[0]":                                        "informative",
		"audit.go:Open{file.Stat() then err != nil}[0]":                                             "informative",
		"audit.go:(*Recorder).Ready{recorder.shipper != nil}[1]":                                    "informative",
		"audit.go:(*Recorder).Ready{recorder.shipper != nil}[2]":                                    "informative",
		"audit.go:(*Recorder).Record{recorder.closed}[0]":                                           "M-sufficient", // 3-way; MAlone empty, Compose non-empty
		// M-sufficient (Compose == MAlone)
		"verifier.go:(*Recorder).StartVerifier{recorder.closed || recorder.verifyStarted}[0]": "M-sufficient",
		// not-killed (Compose == [] AND MAlone == [])
		"shipper.go:(*shipper).run{shipper.stopped || shipper.ctx.Err() != nil}[0]": "not-killed",
		"shipper.go:(*shipper).run{if shipper.ctx.Err() != nil}[0]":                 "not-killed",
	}
	got := map[string]string{}
	for _, row := range rows {
		switch {
		case len(row.MAlone) == 0 && len(row.Compose) == 0:
			got[row.ID] = "not-killed"
		case len(row.Compose) == 0:
			got[row.ID] = "informative-no-compose"
		case equalStringSlices(row.MAlone, row.Compose):
			got[row.ID] = "M-sufficient"
		default:
			got[row.ID] = "informative"
		}
	}
	for id, classification := range want {
		if got[id] != classification {
			t.Errorf("row %q: classification %q, want %q", id, got[id], classification)
		}
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestLedgerCitationsNameLiveSource extends the drift guard from the rows' IDs to every other
// citation this package's tests make (a row's Masking, its Notes, the comments), and to the one in
// internal/policy that cites audit.go: each resolves (resolveCitation), and one with an operand
// index names a row or a line that is still a branch (if, case, for, switch, return, && or ||). A
// line-number citation is refused unless it is marked as history ("Was …", "formerly …"): it names
// where a row used to be. (#283, regalia-kms-3e; #282 replaced the line numbers with anchors.)
//
// FALSIFY: cite a guard by line number in a comment (audit.go, a colon, a number), or change an anchor in a Notes field to text its
// function does not hold. This fails naming the file and line of the citation.
func TestLedgerCitationsNameLiveSource(t *testing.T) {
	rows := map[string]bool{}
	for _, row := range ledgerRows() {
		rows[row.ID] = true
	}
	_, thisFile, _, _ := runtime.Caller(0)
	auditDir := filepath.Dir(thisFile)
	branch := regexp.MustCompile(`\bif\b|\bcase\b|\bfor\b|\bswitch\b|\breturn\b|&&|\|\|`)
	sources := liveSources(t)
	tests, _ := filepath.Glob(filepath.Join(auditDir, "*_test.go"))
	tests = append(tests, filepath.Join(auditDir, "..", "policy", "replay_decision_test.go"))
	for _, test := range tests {
		data, err := os.ReadFile(test)
		if err != nil {
			t.Fatal(err)
		}
		for number, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "regexp.MustCompile") {
				continue
			}
			where := fmt.Sprintf("%s:%d", filepath.Base(test), number+1)
			for _, match := range lineCitationPattern.FindAllStringSubmatch(line, -1) {
				if match[1] == "" {
					t.Errorf("%s cites %s by line number: cite file.go:Func{anchor}[i] (#282)", where, match[0])
				}
			}
			for _, cited := range citationPattern.FindAllString(line, -1) {
				if strings.HasPrefix(cited, "file.go:") {
					continue // the form itself, as the comments spell it
				}
				_, text, err := resolveCitation(sources, cited)
				switch {
				case err != nil:
					t.Errorf("%s cites %s: %v", where, cited, err)
				case strings.HasSuffix(cited, "]") && !rows[strings.ReplaceAll(cited, `\"`, `"`)] && !branch.MatchString(text):
					t.Errorf("%s cites %s: not a row, and its line is not a branch: %q", where, cited, text)
				}
			}
		}
	}
}
