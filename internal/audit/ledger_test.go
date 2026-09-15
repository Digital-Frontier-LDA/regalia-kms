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
//     that position once the drift guard is filtered out, and audit.go:366[0] is a sixth under
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
// M-ALONE IS AMBIGUOUS WHEN Masking NAMES A CONJUNCTION. For audit.go:366[0], whose mask is
// audit.go:384[0]+audit.go:387[0], each guard singly SURVIVES while the two together KILL. So
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
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/sweeptext"
)

// ledgerRow is one survivor from #237's fault-injection sweep on this package.
// ID is in the form "file.go:NNN[i]" where NNN is the source line and i is the
// operand index (multi-operand guards like shipper.go:115 have [0] and [1]).
//
// MAlone and Compose carry the per-row control-arm measurement (X+M vs
// M-alone failing-test sets). Both are empty slices when the row is not
// part of the masking study. The control-arm is what distinguishes
// "killed-on-compose" from "needs-fixing": the first has non-empty Compose,
// the second has Compose == [] && MAlone == [].
type ledgerRow struct {
	ID      string // e.g. "audit.go:268[0]"
	Verdict string // see bucket key above
	Site    string // verbatim source line text
	Notes   string // bucket-specific prose (defect + masking guard + test name, etc.)
	Test    string // for "*-on-compose" verdicts: the test that catches the joint bypass
	Masking string // for "*-on-compose" verdicts: the sibling operand ID
	// Direction is REQUIRED for "hangs-on-bypass" and is the fix for a precision gap this
	// ledger had one bucket over from the one it was correcting: a hang is a property of ONE
	// direction, and the other direction of the same operand routinely does something else
	// entirely. Of the six rows below, the other direction PANICS for two and is KILLED for four
	// (for shipper.go:115[0] and [1] only since #458; before that each survived alone). A reader
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
			ID: "verifier.go:127[1]", Verdict: "reachable-untested-test-added",
			Site:  "\tif recorder.closed || recorder.verifyStarted {",
			Notes: "With verifyStarted bypassed, a second StartVerifier installs a sibling goroutine whose loopCtx outlives recorder.verifyStop; Close() blocks on the leaked goroutine. TestStartVerifierTwiceIsANoOp closes this gap.",
			Test:  "TestStartVerifierTwiceIsANoOp",
		},
		// The round-three rows, classified. Seven were carried as "unclassified", found by
		// reconciling measured survivors against row IDs rather than against the row count. Every
		// operand below was re-measured on 363ce16 before a test was written, and each is KILLED by
		// the test it names. Two did not come from that list: httpsink.go:95[0] was found by
		// measuring the Send twin of httpsink.go:127[0], and shipper.go:191[0] was recorded as
		// unreachable when one direction of it is a behaviour change.
		{
			ID: "audit.go:301[0]", Verdict: "reachable-untested-test-added",
			Site:  "\t\tcase errors.Is(statErr, os.ErrNotExist):",
			Notes: "Measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, every case takes the absent arm, so a mark that is PRESENT but behind the collector's acknowledged head -- a forged sidecar -- is reported as durability loss. Both arms refuse; only the diagnosis differs, and the existing tests pinned the absent diagnosis alone.",
			Test:  "TestAMarkBehindTheCollectorIsDiagnosedAsForgedRatherThanLost",
		},
		{
			ID: "httpsink.go:95[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif sink.site != \"\" {",
			Notes: "NOT in the round-three list. Found by measuring the Send twin of httpsink.go:127[0] on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, Send files the identity-keyed stream's events with X-Regalia-Site present and empty instead of absent.",
			Test:  "TestAnEmptySiteSendsNoSiteHeaderOnEitherCall",
		},
		{
			ID: "httpsink.go:127[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif site != \"\" {",
			Notes: "Measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, CommittedHead asks about the identity-keyed stream with X-Regalia-Site present and empty. Send and CommittedHead must address the same stream, and the collector contract keys on the header 'when present'; this repository's collector reads absent and empty alike, so only the request shows the difference.",
			Test:  "TestAnEmptySiteSendsNoSiteHeaderOnEitherCall",
		},
		{
			ID: "httpsink.go:165[1]", Verdict: "reachable-untested-test-added",
			Site:  "\tif (position.Sequence > 0) != (position.Hash != \"\") || (position.Hash != \"\" && !auditHashPattern.MatchString(position.Hash)) {",
			Notes: "Measured on 363ce16: FALSE SURVIVED / TRUE KILLED. Forced false, the pattern half of the guard never runs, so a head with a sequence and a present hash that is not a chained hash is accepted as the one authoritative value in reconciliation. KILLED by that test's 'a hash that is not a chained hash' row.",
			Test:  "TestCommittedHeadRefusesShapesTheCollectorCannotEmit",
		},
		{
			ID: "httpsink.go:165[2]", Verdict: "reachable-untested-test-added",
			Site:  "\tif (position.Sequence > 0) != (position.Hash != \"\") || (position.Hash != \"\" && !auditHashPattern.MatchString(position.Hash)) {",
			Notes: "Measured on 363ce16: FALSE SURVIVED / TRUE KILLED. Forced false it is the same bypass as httpsink.go:165[1] forced false, so the one fixture kills both.",
			Test:  "TestCommittedHeadRefusesShapesTheCollectorCannotEmit",
		},
		{
			ID: "shipper.go:191[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif backoff < maxShipBackoff {",
			Notes: "Was shipper.go:181[0], recorded unreachable. Re-measured on 363ce16 (pre-extraction): FALSE SURVIVED / TRUE SURVIVED. Forced false is a BEHAVIOUR change, not an unreachable branch: the backoff never doubles, and a down collector is retried every 100ms for as long as it is down. Forced true cannot be told apart: doubling the maximum is capped straight back. The comparison moved into nextShipBackoff so it can be tested without a minute of real timers, and the move was proved behaviour-identical against 363ce16 by a differential trace of the real run loop (same failures in, same delays out, the cap and reset-on-success included).",
			Test:  "TestShipBackoffDoublesAndIsHeldAtItsMaximum",
		},
		{
			ID: "shipper.go:193[0]", Verdict: "reachable-untested-test-added",
			Site:  "\t\tif backoff > maxShipBackoff {",
			Notes: "Was shipper.go:183[0]. Measured on 363ce16 (pre-extraction): FALSE SURVIVED / TRUE KILLED. Forced false, doubling from 25.6s overshoots to 51.2s and stays there, since the outer comparison stops any further doubling (not 'without bound', as first recorded): every recovery waits up to 51.2s instead of 30s. Extraction and differential proof as for shipper.go:191[0].",
			Test:  "TestShipBackoffDoublesAndIsHeldAtItsMaximum",
		},
		{
			ID: "verifier.go:93[0]", Verdict: "reachable-untested-test-added",
			Site:  "\tif len(events) > 0 {",
			Notes: "Measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Forced true, a verify run over an empty journal reads the head of an empty slice and panics. Reachable on every fresh site: the periodic verifier's first run sees no events.",
			Test:  "TestVerifyingARecorderThatHasWrittenNothingIsIntact",
		},

		// ===== Bucket 2: compose-proved (14, after control-arm re-classification) =====
		// killed-on-compose sub-bucket (10). MAlone / Compose are the 3-arm
		// measurement from the control-arm script.
		{
			ID: "audit.go:323[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Open's redo of the journal's collector-side position (the readShippedMark call is on line 322; the if check is on 323); the joint bypass with the audit.go:268[0] masking guard is caught by the test in Test and Compose.",
			Test:    "TestACorruptShippedMarkIsRefusedNotIgnored",
			Masking: "audit.go:268[0]",
			MAlone:  []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
			Compose: []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
		},
		{
			ID: "audit.go:384[0]", Verdict: "killed-on-compose",
			Site:    "\tif _, err := recorder.file.Write(line); err != nil {",
			Notes:   "Append-then-Sync; the masking guard at audit.go:387[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestDurableIsFalseWhenTheWriteItselfFailed",
			Masking: "audit.go:387[0]",
			MAlone:  []string{},
			Compose: []string{"TestDurableIsFalseWhenTheWriteItselfFailed"},
		},
		{
			ID: "audit.go:387[0]", Verdict: "killed-on-compose",
			Site:    "\tif err := recorder.file.Sync(); err != nil {",
			Notes:   "Sync after Write; the masking guard at audit.go:384[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestDurableIsFalseWhenTheWriteItselfFailed",
			Masking: "audit.go:384[0]",
			MAlone:  []string{},
			Compose: []string{"TestDurableIsFalseWhenTheWriteItselfFailed"},
		},
		{
			ID: "audit.go:487[0]", Verdict: "killed-on-compose",
			Site:    "\t\tif err := decoder.Decode(&event); err != nil {",
			Notes:   "Per-event decoder; the masking guard at audit.go:494[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestAnEventDeletedFromTheMiddleAndRelinkedIsRefused",
			Masking: "audit.go:494[0]",
			MAlone:  []string{"TestAnEventDeletedFromTheMiddleAndRelinkedIsRefused"},
			Compose: []string{"TestAnEventDeletedFromTheMiddleAndRelinkedIsRefused"},
		},
		{
			ID: "reconcile.go:56[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Local shipped mark read in ReconcileContinuity; the masking guard at audit.go:268[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestACorruptShippedMarkIsRefusedNotIgnored",
			Masking: "audit.go:268[0]",
			MAlone:  []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
			Compose: []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
		},
		{
			ID: "reconcile.go:91[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "readShippedForReconcile inner read; the masking guard at audit.go:268[0] catches the joint bypass; the measured detector is in Test and Compose.",
			Test:    "TestACorruptShippedMarkIsRefusedNotIgnored",
			Masking: "audit.go:268[0]",
			MAlone:  []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
			Compose: []string{"TestACorruptShippedMarkIsRefusedNotIgnored"},
		},
		{
			ID: "verifier.go:74[0]", Verdict: "killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "VerifyNow's os.Open failure check (the os.Open call is on line 73; the if check is on 74); the masking guard at verifier.go:80[0] catches the joint bypass via the verifyEvents error path. The 3-arm protocol shows TestVerifyNowOnAMissingJournalReturnsUnreadableRatherThanPanicking fires ONLY on the joint bypass, not on M-alone — proof the masking guard's tests do NOT cover X alone.",
			Test:    "TestVerifyNowOnAMissingJournalReturnsUnreadableRatherThanPanicking",
			Masking: "verifier.go:80[0]",
			MAlone:  []string{"TestVerifierClassifiesAReadFailureAsUnreadableNotBroken"},
			Compose: []string{"TestVerifierClassifiesAReadFailureAsUnreadableNotBroken", "TestVerifierDistinguishesUnreadableFromBroken", "TestVerifyNowOnAMissingJournalReturnsUnreadableRatherThanPanicking"},
		},
		{
			ID: "verifier.go:96[0]", Verdict: "killed-on-compose",
			Site:    "\tif head != sequence || headHash != lastHash {",
			Notes:   "Prefix-vs-recorder-head divergence check; the masking guard at verifier.go:96[1] catches the joint bypass via TestAReplacementChainOfTheSameLengthIsReportedAsBroken.",
			Test:    "TestAReplacementChainOfTheSameLengthIsReportedAsBroken",
			Masking: "verifier.go:96[1]",
			MAlone:  []string{"TestAReplacementChainOfTheSameLengthIsReportedAsBroken"},
			Compose: []string{"TestAReplacementChainOfTheSameLengthIsReportedAsBroken", "TestATruncationUnderARunningRecorderIsReportedAsBroken"},
		},
		{
			ID: "verifier.go:127[0]", Verdict: "killed-on-compose",
			Site:    "\tif recorder.closed || recorder.verifyStarted {",
			Notes:   "StartVerifier's second-call refusal, first operand (recorder.closed); the masking guard at verifier.go:127[1] catches the joint bypass via TestStartVerifierTwiceIsANoOp. Control-arm: Compose == MAlone (both fire TestStartVerifierTwiceIsANoOp); X is uninformative — the masking guard's bypass alone catches the bug. Verdict stays killed-on-compose because the joint bypass IS caught, but the [1] operand is the load-bearing one.",
			Test:    "TestStartVerifierTwiceIsANoOp",
			Masking: "verifier.go:127[1]",
			MAlone:  []string{"TestStartVerifierTwiceIsANoOp"},
			Compose: []string{"TestStartVerifierTwiceIsANoOp"},
		},
		// 3-way compose (1)
		{
			ID: "audit.go:366[0]", Verdict: "killed-on-compose",
			Site:    "\tif recorder.closed {",
			Notes:   "Record's recorder-closed refusal. CONJUNCTIVE MASK: audit.go:384[0] and :387[0] each SURVIVE alone; the two together KILL TestDurableIsFalseWhenTheWriteItselfFailed. MAlone above uses the mask as NAMED, the reading the claim requires -- under it Compose == MAlone, the compose adds nothing, and this row is M-sufficient. Under the singles reading MAlone is [] and the row reads informative. Two defensible readings, opposite verdicts; recorded because singles-survive-but-conjunction-kills locates the masking in the PAIR, which is more than either number says.",
			Test:    "TestDurableIsFalseWhenTheWriteItselfFailed",
			Masking: "audit.go:384[0]+audit.go:387[0]",
			MAlone:  []string{"TestDurableIsFalseWhenTheWriteItselfFailed"}, // the mask AS NAMED; each guard singly SURVIVES
			Compose: []string{"TestDurableIsFalseWhenTheWriteItselfFailed"},
		},
		// panic-killed-on-compose sub-bucket (4)
		{
			ID: "audit.go:327[0]", Verdict: "panic-killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Open's file-open err check (the OpenFile call is on line 326); the masking guard at audit.go:331[0] catches the joint bypass. The panic propagates through defer file.Close() on a nil handle.",
			Test:    "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes",
			Masking: "audit.go:331[0]",
			MAlone:  []string{},
			Compose: []string{"TestTheAcceptedFileModesAreTheOnesTheMessageDescribes", "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes/owner_cannot_write, _so_the_append-only_open_fails_first"},
		},
		{
			ID: "audit.go:331[0]", Verdict: "panic-killed-on-compose",
			Site:    "\tif err != nil {",
			Notes:   "Open's file-Stat err check (the Stat call is on line 330); the masking guard at audit.go:327[0] catches the joint bypass. With both operands neutralised, the nil file deref panics.",
			Test:    "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes",
			Masking: "audit.go:327[0]",
			MAlone:  []string{},
			Compose: []string{"TestTheAcceptedFileModesAreTheOnesTheMessageDescribes", "TestTheAcceptedFileModesAreTheOnesTheMessageDescribes/owner_cannot_write, _so_the_append-only_open_fails_first"},
		},
		{
			ID: "audit.go:426[1]", Verdict: "panic-killed-on-compose",
			Site:    "\treturn recorder != nil && recorder.sink != nil && recorder.shipper != nil &&",
			Notes:   "Readiness conjunction. RE-MEASURED with -vet=off, because go test runs vet and vet refuses the same-chain compose `false && false`: in the FALSE direction X alone is KILLED by 4 tests and X+M kills the same 4, so the masking claim is vacuous THERE -- the operand is detected on its own. The surviving direction is TRUE, which the compose arms do not exercise. As with hangs-on-bypass, a compose verdict is direction-dependent and this row does not say which direction it describes.",
			Test:    "TestAnUnwiredRecorderIsNeverReady",
			Masking: "audit.go:426[2]",
			MAlone:  []string{},
			Compose: []string{"TestAnUnwiredRecorderIsNeverReady"},
		},
		{
			ID: "audit.go:426[2]", Verdict: "panic-killed-on-compose",
			Site:    "\treturn recorder != nil && recorder.sink != nil && recorder.shipper != nil &&",
			Notes:   "Readiness conjunction. RE-MEASURED with -vet=off, because go test runs vet and vet refuses the same-chain compose `false && false`: in the FALSE direction X alone is KILLED by 4 tests and X+M kills the same 4, so the masking claim is vacuous THERE -- the operand is detected on its own. The surviving direction is TRUE, which the compose arms do not exercise. As with hangs-on-bypass, a compose verdict is direction-dependent and this row does not say which direction it describes.",
			Test:    "TestAnUnwiredRecorderIsNeverReady",
			Masking: "audit.go:426[1]",
			MAlone:  []string{},
			Compose: []string{"TestAnUnwiredRecorderIsNeverReady"},
		},

		// ===== Bucket 6: re-classified after control-arm (2: 1 unreachable, 1 cannot-be-sole-refuser) =====
		{
			ID: "shipper.go:133[0]", Verdict: "unreachable",
			Site:    "\t\tif shipper.stopped || shipper.ctx.Err() != nil {",
			Notes:   "UNREACHABLE, reclassified from needs-fixing. shipper.stopped has exactly two writers -- shipper.go:134 and :167 -- both immediately followed by `return` from run(), which newShipper starts once with no restart path and never sets, and close() does not set. So at :133 the operand is always false. Measured signature of an always-false operand in an || chain: deleting it SURVIVES (a no-op) while forcing it true is KILLED. The control arm's Compose == [] and MAlone == [] was correct; the inference 'Real defect' was not -- 'no test fires' has several causes and unreachable is one of them.",
			MAlone:  []string{},
			Compose: []string{},
		},
		{
			ID: "shipper.go:166[0]", Verdict: "cannot-be-sole-refuser",
			Site:    "\t\tif shipper.ctx.Err() != nil {",
			Notes:   "CANNOT BE THE SOLE REFUSER, reclassified from needs-fixing. Masked by shipper.go:133[1], the ctx check at the top of the loop. Deleted, a failed send with a cancelled context falls to the backoff select, which wakes IMMEDIATELY on <-shipper.ctx.Done(), loops, and exits at :133. The shipper does not continue sending; the exit is delayed one iteration. Measured: deleting it SURVIVES, forcing it true is KILLED.",
			MAlone:  []string{},
			Compose: []string{},
		},

		// ===== Bucket 3: unreachable (15) =====
		{
			ID: "audit.go:49[0]", Verdict: "unreachable",
			Site:  "func Durable(err error) bool { return err != nil && errors.Is(err, ErrDurable) }",
			Notes: "Durable is the public classification helper; the err operand is the only way to reach errors.Is(err, ErrDurable).",
		},
		{
			ID: "audit.go:177[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "json.Marshal(highWaterMark) cannot fail for a struct of strings and numbers (the Marshal call is on line 176; the if check is on 177).",
		},
		{
			ID: "audit.go:304[0]", Verdict: "unreachable",
			Site:  "\t\tcase statErr != nil:",
			Notes: "Case-init operand in the mark-existence stat's else branch (handled by the case statErr == nil and the explicit os.ErrNotExist branch).",
		},
		{
			ID: "audit.go:338[0]", Verdict: "unreachable",
			Site:  "\tif !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {",
			Notes: "Open's mode-bits check; the audit buffer is created by Open itself with 0o600, so no test construct in this package reaches the wrong side of this branch.",
		},
		{
			ID: "audit.go:380[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "json.Marshal(event) cannot fail for the Event struct's string/number/time fields (the Marshal call is on line 379; the if check is on 380).",
		},
		{
			ID: "audit.go:470[0]", Verdict: "unreachable",
			Site:  "\tif err != nil || !info.Mode().IsRegular() {",
			Notes: "Verify's info.Mode().IsRegular() check; Verify is called only on a journal the daemon opened itself or that an operator passed via VerifyIntegrity.",
		},
		{
			ID: "httpsink.go:83[0]", Verdict: "unreachable",
			Site:  "\tif err != nil || len(body) > 64<<10 {",
			Notes: "json.Marshal(event) and the body-size check; NewHTTPSink rejects empty bodies up-front.",
		},
		{
			ID: "httpsink.go:89[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "ValidateSinkURL pre-rejects malformed URLs; NewRequestWithContext with valid input and a method/URL cannot fail (the NewRequestWithContext call is on line 88; the if check is on 89).",
		},
		{
			ID: "httpsink.go:102[0]", Verdict: "unreachable",
			Site:  "\tif response.Body != nil {",
			Notes: "http.Client.Do always returns a non-nil *Response when err is nil; the err != nil check above makes this always true.",
		},
		{
			ID: "httpsink.go:124[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "Same shape as httpsink.go:74[0] — pre-rejected by ValidateSinkURL (the NewRequestWithContext call is on line 123; the if check is on 124).",
		},
		{
			ID: "httpsink.go:136[0]", Verdict: "unreachable",
			Site:  "\t\tif response.Body != nil {",
			Notes: "Same shape as httpsink.go:84[0].",
		},
		{
			ID: "httpsink.go:182[0]", Verdict: "unreachable",
			Site:  "\tif err != nil {",
			Notes: "Ready's err check after sink.client.Do (the Do call is on line 181); the client/baseURL are validated by NewHTTPSink so no test construct produces the wrong side.",
		},
		{
			ID: "httpsink.go:185[0]", Verdict: "unreachable",
			Site:  "\tif response.Body != nil {",
			Notes: "Same shape — Ready follows the same Do/Body pattern.",
		},
		{
			ID: "audit.go:224[0]", Verdict: "unreachable",
			Site:  "\tcase errors.Is(statErr, os.ErrNotExist):",
			Notes: "Round three, measured on 363ce16: FALSE KILLED / TRUE SURVIVED. Section 17: the operand is false only for a stat error other than not-exist, and readMark refuses every such error on the same path one call earlier, so reaching it needs the path's stat class to change between the two calls. Pinned where it is enforced by TestAMarkWhoseFileCannotBeStattedIsRefusedByTheReadBeforeTheStat (a symlink loop and an over-long mark name). Compose measured: forced true alone, that test PASSES; readMark relaxed to treat every read failure as absent, it FAILS on the classification's default arm ('cannot be classified'); both together, a one-event journal with an unstattable mark VERIFIES CLEAN. Defence in depth, keep.",
		},
		{
			ID: "verifier.go:66[0]", Verdict: "unreachable",
			Site:  "\tif recorder.closed {",
			Notes: "After Close, the cached VerifyState is the only readable view; a fresh run produces the same answer.",
		},

		// ===== Bucket 4: cannot-pin (4) =====
		{
			ID: "audit.go:181[0]", Verdict: "cannot-pin",
			Site:  "\tif err := os.WriteFile(temporary, encoded, 0o600); err != nil {",
			Notes: "os.WriteFile(.tmp, …) failure requires an OS-level fault (full disk, read-only mount); the masking guard at os.Rename swallows the same fault and we cannot fake just one.",
		},
		{
			ID: "audit.go:246[0]", Verdict: "cannot-pin",
			Site:  "\tif len(events) >= 1 && markFileExists && mark.Sequence == 0 {",
			Notes: "verifyMark boundary check requires a sidecar that is structurally valid but semantically wrong; every codepath that writes such a mark is itself guarded.",
		},
		{
			ID: "audit.go:258[1]", Verdict: "cannot-pin",
			Site:  "\tif reached == mark.Sequence && mark.Hash != genesisHash && reachedHash != mark.Hash {",
			Notes: "Same shape as audit.go:246[0] for the second mark kind; documented in source as §17 unreachable.",
		},
		{
			ID: "shipper.go:99[0]", Verdict: "cannot-pin",
			Site:  "\t\tif shipper.stopped {",
			Notes: "waitShipped returning ErrSinkUnavailable because the caller's context ended first races natural delivery; the bug only shows when cancellation lands in the same scheduling slot as a delivery.",
		},

		// ===== Bucket 5: hangs-on-bypass (6) =====
		{
			ID: "audit.go:451[0]", Verdict: "hangs-on-bypass",
			Site:      "\tif verifyStop != nil {",
			Direction: "deleted (false &&) HANGS; forced true PANICS",
			Notes:     "Close() without prior StartVerifier() leaves verifyStop nil. DELETED, the stop is never called, the verifier goroutine is never wound down and Close waits on it: measured `panic: test timed out after 1m30s` with TestRecorderPersistsOrderedIntegrityChainAndShipsOffHost still running. FORCED TRUE, the nil verifyStop is called and the run nil-derefs. So the two directions have different defect SHAPES -- a missing shutdown path one way, a missing nil guard the other -- and the earlier direction-less verdict pointed at the wrong one.",
		},
		{
			ID: "shipper.go:95[0]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.shipped >= sequence {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED",
			Notes:     "waitShipped's first-poll short-circuit. DELETED, waitShipped never returns nil and the caller waits forever -- measured as a timeout, not a crash; the earlier note's 'hangs in a hot loop' was the right mechanism under the wrong verdict. FORCED TRUE it is KILLED, so this operand IS detected in one direction and the ledger was not crediting itself with that coverage.",
		},
		{
			ID: "shipper.go:133[1]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.stopped || shipper.ctx.Err() != nil {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED",
			Notes:     "Run-loop exit check, ctx-err operand. DELETED, the loop NEVER TERMINATES: this operand is the sole terminator of run(). That single measurement is what makes shipper.go:133[0] and shipper.go:166[0] redundant, and is why both were reclassified in this pass rather than each being argued separately. FORCED TRUE the loop exits at once and is KILLED. The earlier note claimed a deref of shipper.sink after teardown; no deref occurs.",
		},
		{
			ID: "shipper.go:139[0]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif len(shipper.pending) == 0 {",
			Direction: "forced true HANGS; deleted (false &&) PANICS",
			Notes:     "Run-loop's idle-tick check. FORCED TRUE, the idle branch runs unconditionally and the loop spins without ever draining pending -- a hang. DELETED, the idle branch is never taken and the head read runs against an empty queue, panicking on the index. Both directions are defects and neither is the other's shape.",
		},
		{
			ID: "shipper.go:115[0]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.failures != failures && shipper.shipped < sequence {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED by TestAnEarlierEventsAcknowledgementDoesNotFailAWaitingOperation",
			Notes:     "waitShipped's early fail-closed check: a sink failure since the wait began, with this event still unshipped, fails the operation now instead of holding it through the backoff. Timeout-first classifier, -vet=off. DELETED: HANGS in TestHighRiskRecordFailsClosedAfterDurableLocalAppend -- measured 3/3 on 95453e2 (#456) and 2/2 again on 5359d57 (#458). This is one conjunct of an AND, so deleting it deletes the whole early refusal; no sibling can catch the bypass. FORCED TRUE: the condition reduces to shipped < sequence, so any wake with the event unshipped fails the operation -- including the acknowledgement of an EARLIER event under healthy shipping. Survived until #458; now KILLED 5/5 across the package and 100/100 targeted, only by TestAnEarlierEventsAcknowledgementDoesNotFailAWaitingOperation, built at the Recorder boundary: an event recorded without waiting, a high-risk event parked behind it, and the first acknowledged while the second is held at its gate.",
		},
		{
			ID: "shipper.go:115[1]", Verdict: "hangs-on-bypass",
			Site:      "\t\tif shipper.failures != failures && shipper.shipped < sequence {",
			Direction: "deleted (false &&) HANGS; forced true is KILLED by TestAnAcknowledgedEventIsNotReportedFailedWhenAFailureAlsoLanded",
			Notes:     "waitShipped's early fail-closed check: a sink failure since the wait began, with this event still unshipped, fails the operation now instead of holding it through the backoff. Timeout-first classifier, -vet=off. DELETED: HANGS in TestHighRiskRecordFailsClosedAfterDurableLocalAppend -- measured 3/3 on 95453e2 (#456) and 2/2 again on 5359d57 (#458). This is one conjunct of an AND, so deleting it deletes the whole early refusal; no sibling can catch the bypass. FORCED TRUE: the condition reduces to failures != failures0, so a failure seen alongside this event's acknowledgement reports a successful audit write as failed. Survived until #458; now KILLED 5/5 across the package and 100/100 targeted, only by TestAnAcknowledgedEventIsNotReportedFailedWhenAFailureAlsoLanded. THAT TEST DRIVES shipper STATE DIRECTLY, and the section-17 boundary is why: Record holds recorder.mu across waitShipped and is the only caller of enqueue and waitShipped, so no event after this one can be queued while it waits -- #458's hypothesised later-event failure cannot be produced through the Recorder. The remaining path is a failed attempt on an event up to this one, then a retry that acknowledges it, both before the woken waiter re-takes shipper.mu; the retry waits at least minShipBackoff (100ms), so it needs the waiter descheduled for a whole backoff interval. Reachable under load, ordered by the scheduler, not constructible from the Recorder boundary.",
		},
	}
}

// TestLedgerRowNamesLiveSource walks the ledger rows and asserts each Site
// still equals the file's line at the row's ID. The source file is read
// through stripMutationWrappers so the assertion survives an in-flight
// sweep — without the strip, a row whose cited guard has just been
// mutated would go red on its own drift guard, and a sweep harness
// reading a red as KILLED would retire the operand as covered when
// nothing detects it.
//
// FALSIFY: change one row's Site to a string that does not match the live
// source, or set Site to "INTENTIONALLY BROKEN". The test fails naming the
// row's ID — proof that the assertion is the one tripping.
func TestLedgerRowNamesLiveSource(t *testing.T) {
	rows := ledgerRows()
	if len(rows) == 0 {
		t.Fatalf("the ledger is empty: post-PR tally is 42 — a zero count means the slice was deleted")
	}
	_, thisFile, _, _ := runtime.Caller(0)
	auditDir := filepath.Dir(thisFile)
	for _, row := range rows {
		parts := strings.SplitN(row.ID, ":", 2)
		if len(parts) != 2 {
			t.Fatalf("row ID %q: expected file:line[index]", row.ID)
		}
		file, rest := parts[0], parts[1]
		lineStr := rest
		if i := strings.Index(rest, "["); i >= 0 {
			lineStr = rest[:i]
		}
		lineNo, err := strconv.Atoi(lineStr)
		if err != nil {
			t.Fatalf("row %q: bad line number: %v", row.ID, err)
		}
		path := filepath.Join(auditDir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("row %q: read %s: %v", row.ID, file, err)
		}
		stripped := sweeptext.StripMutationWrappers(string(data))
		lines := strings.Split(stripped, "\n")
		if lineNo < 1 || lineNo > len(lines) {
			t.Fatalf("row %q: %s has %d lines, line %d out of range", row.ID, file, len(lines), lineNo)
		}
		have := strings.TrimRight(lines[lineNo-1], " \t\r")
		want := strings.TrimRight(row.Site, " \t\r")
		if have != want {
			t.Errorf("row %q: %s:%d drift.\n  have: %q\n  want: %q", row.ID, file, lineNo, have, want)
		}
	}
}

// TestLedgerCoverage asserts every row has a known verdict and the bucketed
// sums equal the current tally (9 reachable-untested-test-added + 10 killed-on-compose +
// 4 panic-killed-on-compose + 16 unreachable + 4 cannot-pin + 6 hangs-on-bypass +
// 1 cannot-be-sole-refuser = 50). The two shipper.go:115 rows moved from
// killed-on-compose to hangs-on-bypass on re-measurement (#453); the count moved with them.
// The seven round-three rows left "unclassified" when they got verdicts: six gained tests and
// audit.go:224[0] is unreachable, httpsink.go:95[0] joined as a new row, and shipper.go:181[0]
// left unreachable for a test (it is now shipper.go:191[0]).
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
		t.Errorf("total rows: have %d, want 50 (42, then 7 found by reconciling IDs rather than counts, then httpsink.go:95[0] found beside one of them)", total)
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
		"audit.go:323[0]":    "M-sufficient",
		"audit.go:384[0]":    "informative",
		"audit.go:387[0]":    "informative",
		"audit.go:487[0]":    "M-sufficient",
		"reconcile.go:56[0]": "M-sufficient",
		"reconcile.go:91[0]": "M-sufficient",
		"verifier.go:74[0]":  "informative",
		"verifier.go:96[0]":  "informative",
		"audit.go:327[0]":    "informative",
		"audit.go:331[0]":    "informative",
		"audit.go:426[1]":    "informative",
		"audit.go:426[2]":    "informative",
		"audit.go:366[0]":    "M-sufficient", // 3-way; MAlone empty, Compose non-empty
		// M-sufficient (Compose == MAlone)
		"verifier.go:127[0]": "M-sufficient",
		// not-killed (Compose == [] AND MAlone == [])
		"shipper.go:133[0]": "not-killed",
		"shipper.go:166[0]": "not-killed",
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
