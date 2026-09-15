package policy

// THE LEDGER (#334): one row per leaf at every fs/OS boundary in this package.
//
// The #237 sweep counted these as untested by construction — not "probably fine", not "covered by
// reading the code": a branch with no test that can make it fire is a branch a future edit can
// delete while the suite stays green. This file classifies every one of them, and the
// classification is the deliverable. Four verdicts, and only one of them means "there is a test":
//
//	covered          — the row below IS the sole detector. Neutralise the operand in state.go /
//	                   load.go / cosmos.go and this row is the only failure in the package.
//	pinned-elsewhere — an existing test already detects it, named in `why`. The row is
//	                   documentation: it can never be the sole failure, and says so.
//	unreachable      — no input reaches it (TESTING.md §17). The row states the property that
//	                   makes it unreachable, and where that property is checkable, checks it — so
//	                   the claim fails if the property ever stops holding.
//	undetectable     — reachable, but every input that distinguishes the operand is one whose
//	                   refusal would be an improvement. Pinning such an input pins a gap, so the
//	                   row states the derivation and refuses to pin it.
//
// POLARITY, because getting it backwards reports a covered operand as a survivor: an operand of a
// refusing `||` chain is neutralised with `(false && operand)`, an operand of an `&&` chain with
// `(true || operand)`. The `&&` rows are therefore killed by a LEGITIMATE input being wrongly
// refused, not by a bad input being admitted, and they are written that way.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	verdictCovered         = "covered"
	verdictPinnedElsewhere = "pinned-elsewhere"
	verdictUnreachable     = "unreachable"
	verdictUndetectable    = "undetectable"
)

type faultLeaf struct {
	// site matches the [tag] in the source comment at the guarded site.
	site string
	// operand names the single boolean leaf this row is about.
	operand string
	verdict string
	why     string
	run     func(*testing.T)
}

func faultInjectionLedger() []faultLeaf {
	return []faultLeaf{
		{
			site:    "cosmos.parseSignDoc/account-number-redecode",
			operand: "err != nil after the second decodeVarint of account_number",
			verdict: verdictUnreachable,
			why: "walkFields hands a wire-type-0 visitor exactly the bytes its own decodeVarint " +
				"consumed — terminator included, nothing more — so the second decode is the first " +
				"decode run again on its own output. A varint that runs off the end never reaches " +
				"the visitor: walkFields refuses it first. The comment this replaces claimed the " +
				"branch was reachable by 'a hand-crafted varint that consumes all of value without " +
				"reaching a terminator', which is a fixture the sibling guard eats.",
			run: func(t *testing.T) {
				// The property, checked rather than asserted in prose: every value handed to a
				// wire-type-0 visitor re-decodes cleanly and consumes the whole slice. If
				// walkFields ever widens that slice, this fails and the leaf becomes reachable.
				visited := 0
				for _, value := range []uint64{0, 1, 127, 128, 300, 1 << 62, ^uint64(0)} {
					input := encodeTopVarint(4, value)
					err := walkFields(input, func(_, wire uint64, field []byte) error {
						if wire != 0 {
							return nil
						}
						visited++
						parsed, consumed, err := decodeVarint(field)
						if err != nil {
							t.Errorf("walkFields handed the visitor %v for account_number %d, and re-decoding those same bytes failed: %v — the branch under this row is then reachable and needs a real detector", field, value, err)
						}
						if consumed != len(field) {
							t.Errorf("the visitor's slice for account_number %d is %d bytes and the varint in it is %d — walkFields is handing over more than it decoded", value, len(field), consumed)
						}
						if parsed != value {
							t.Errorf("re-decoding account_number %d yielded %d", value, parsed)
						}
						return nil
					})
					if err != nil {
						t.Fatalf("walkFields refused a well-formed account_number %d: %v — the fixture is wrong and this row proves nothing", value, err)
					}
				}
				if visited != 7 {
					t.Fatalf("the visitor saw %d wire-type-0 fields, want 7 — the loop is not exercising what this row claims", visited)
				}
			},
		},
		{
			site:    "load.LoadFile/open",
			operand: "err != nil after os.Open of the policy file",
			verdict: verdictCovered,
			why: "MEASURED with the operand neutralised, not predicted: os.Open returns a nil " +
				"*os.File, Stat and Close on it return ErrInvalid rather than panicking, the " +
				"ErrInvalid satisfies the first operand of the mode guard, and LoadFile answers " +
				"`policy must be a non-writable regular file` — so an operator is sent to check " +
				"the permissions of a file that is not there. A STAT ERROR IS NOT ABSENCE: this " +
				"row asserts os.ErrNotExist specifically, which is the whole distinction.",
			run: func(t *testing.T) {
				_, _, err := LoadFile(filepath.Join(t.TempDir(), "absent-policy.json"))
				if err == nil {
					t.Fatal("a policy file that does not exist loaded — the daemon would start governed by nothing")
				}
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a missing policy file was refused as %q, which does not carry os.ErrNotExist — 'no such file' and 'the file is wrong' send an operator to different places, and only the Open guard tells them apart", err)
				}
			},
		},
		{
			site:    "load.LoadFile/stat",
			operand: "err != nil in `err != nil || !IsRegular() || Perm()&0o022 != 0`",
			verdict: verdictUnreachable,
			why: "fstat on a descriptor os.Open just returned does not fail in any way a test can " +
				"portably induce, and the operand shares one `return` with two neighbours that ARE " +
				"reachable (a directory, and a group- or world-writable file), both pinned by " +
				"readiness_test.go's TestThePolicyFileMustNotBeWritableByAnyoneElse. Even " +
				"if the fault could be induced, no row could isolate this operand from those two.",
			run: func(t *testing.T) {
				t.Skip("no portable fault makes fstat fail on a freshly opened descriptor; the two reachable operands sharing this return are pinned by readiness_test.go")
			},
		},
		{
			site:    "load.Load/read-and-cap",
			operand: "err != nil after io.ReadAll",
			verdict: verdictCovered,
			why: "Only a failing io.Reader reaches it. Without the guard, a read that failed halfway " +
				"is decoded as though the bytes it did return were the whole document.",
			run: func(t *testing.T) {
				injected := errors.New("injected read fault")
				_, _, err := Load(failingReader{err: injected})
				if err == nil {
					t.Fatal("a reader that returned nothing but an error produced a loaded policy set")
				}
				if !errors.Is(err, injected) {
					t.Fatalf("a failed read was reported as %q, which does not carry the read fault — without the ReadAll guard the truncated bytes are decoded instead, and the caller is told the policy is malformed rather than unread", err)
				}
			},
		},
		{
			site:    "load.Load/read-and-cap",
			operand: "len(contents) > maxPolicyFileBytes",
			verdict: verdictCovered,
			why: "The LimitReader stops at the cap plus one byte, so without this refusal an " +
				"oversize policy is silently TRUNCATED and then reported as a decode failure — the " +
				"operator is told their JSON is malformed when what is wrong is its size.",
			run: func(t *testing.T) {
				oversize := strings.Repeat(`{"schema_version":1,"policies":[]} `, (maxPolicyFileBytes/34)+64)
				if len(oversize) <= maxPolicyFileBytes {
					t.Fatalf("the fixture is %d bytes and the cap is %d — this row would not reach the guard", len(oversize), maxPolicyFileBytes)
				}
				_, _, err := Load(strings.NewReader(oversize))
				if err == nil {
					t.Fatal("a policy document larger than the cap loaded")
				}
				if !strings.Contains(err.Error(), "exceeds 512 KiB") {
					t.Fatalf("an oversize policy was refused as %q — without the size operand the truncated bytes fail to decode, which names the wrong cause", err)
				}
			},
		},
		{
			site:    "state.readHighWater/read",
			operand: "err != nil (the sidecar exists and cannot be read)",
			verdict: verdictCovered,
			why: "Without it, an unreadable sidecar reaches json.Unmarshal with nil contents and is " +
				"reported as 'malformed' — so an operator is sent to inspect the CONTENT of a file " +
				"whose content was never read. The fault is injected as a directory rather than a " +
				"chmod so the row means the same thing under root. This operand has two detectors " +
				"on purpose: this one, which runs everywhere, and " +
				"TestAnUnreadableHighWaterMarkIsNotAnAbsentOne, which makes the sharper " +
				"os.ErrPermission claim and skips where the kernel does not enforce mode bits. " +
				"Neutralise the operand and both go red; no test that predates them does.",
			run: func(t *testing.T) {
				path := journalWith(t, 1)
				directoryAt(t, path+highWaterSuffix)
				_, err := readHighWater(path)
				if err == nil {
					t.Fatal("an unreadable high-water mark was read successfully — a mark that cannot be read must not resolve to any position")
				}
				if !strings.Contains(err.Error(), "read policy state high-water mark") {
					t.Fatalf("an unreadable mark was reported as %q — 'the read failed' and 'the content is malformed' are different faults with different fixes, and only this operand separates them", err)
				}
			},
		},
		{
			site:    "state.readHighWater/read",
			operand: "errors.Is(err, os.ErrNotExist) returning the genesis mark",
			verdict: verdictPinnedElsewhere,
			why: "mark_required_test.go's 'one reservation without a mark is the crash window and " +
				"stays open' deletes the sidecar and requires the journal to verify; neutralising " +
				"this operand makes an absent mark an error and that subtest fails. This row can " +
				"never be the sole failure. The companion claim — that an UNREADABLE mark is not " +
				"treated as an absent one — is pinned by " +
				"TestAnUnreadableHighWaterMarkIsNotAnAbsentOne below.",
			run: func(t *testing.T) {
				t.Skip("pinned by mark_required_test.go: TestAPolicyJournalWithHistoryCannotHaveNoPriorPosition/one_reservation_without_a_mark_is_the_crash_window_and_stays_open")
			},
		},
		{
			site:    "state.writeHighWater/marshal",
			operand: "err != nil from json.Marshal(highWaterMark)",
			verdict: verdictUnreachable,
			why: "highWaterMark is a uint64 and a string. encoding/json fails on channels, " +
				"functions, complex numbers, NaN/Inf floats and unrepresentable map keys, and this " +
				"struct has none of those. The row marshals the extreme values instead of asserting " +
				"the claim in prose, so adding an unmarshalable field breaks it.",
			run: func(t *testing.T) {
				for _, mark := range []highWaterMark{
					{},
					{Sequence: ^uint64(0), Hash: stateGenesisHash},
					{Sequence: 1, Hash: "\xff\xfe not valid utf-8 either"},
				} {
					if _, err := json.Marshal(mark); err != nil {
						t.Errorf("json.Marshal(%+v) failed: %v — the branch this row calls unreachable is now reachable and needs a detector", mark, err)
					}
				}
			},
		},
		{
			site:    "state.VerifyState/read-state",
			operand: "err != nil",
			verdict: verdictCovered,
			why: "Without it, a journal of bytes that are not a hash chain verifies CLEAN: readState's " +
				"error is dropped, the replay runs over zero events, and an operator asking whether " +
				"the record is intact is told it is.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				writeGarbage(t, path)
				_, err := VerifyState(path)
				if err == nil {
					t.Fatal("a journal of non-JSON bytes verified clean — verification answered 'intact' about a record it could not read at all")
				}
				if !strings.Contains(err.Error(), "invalid JSON") {
					t.Fatalf("an unreadable journal was refused as %q — without this operand the read error is discarded and the summary describes an empty journal", err)
				}
			},
		},
		{
			site:    "state.VerifyState/read-state",
			operand: "!errors.Is(err, os.ErrNotExist)",
			verdict: verdictUnreachable,
			why: "VerifyState os.Stats the path and returns before this line if it is missing, so " +
				"readState cannot answer ErrNotExist here — the only way it could is a delete " +
				"landing between the Stat and the Open, which no test can schedule. Neutralising " +
				"the operand is a semantic no-op for every input a test can present.",
			run: func(t *testing.T) {
				// The property that makes it unreachable, checked: the Stat refusal fires first.
				_, err := VerifyState(filepath.Join(t.TempDir(), "absent.jsonl"))
				if err == nil || !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("a missing journal was not refused by the Stat at the top of VerifyState (%v) — if that changes, readState CAN return ErrNotExist here and this operand becomes reachable", err)
				}
				t.Skip("the ErrNotExist half is unreachable while the Stat above refuses a missing journal first; only a TOCTOU delete between the two could reach it")
			},
		},
		{
			site:    "state.VerifyState/read-high-water",
			operand: "err != nil after readHighWater",
			verdict: verdictCovered,
			why: "Without it, an unusable mark becomes the ZERO mark and verification continues " +
				"against it — which then trips the genesis-downgrade rule and reports that the mark " +
				"'was reset to hide how far the journal reached'. That is an accusation of tampering " +
				"raised by a mark nobody could read. The fault is MALFORMED CONTENT rather than an " +
				"unreadable file on purpose: a read fault would travel through readHighWater's own " +
				"err != nil branch, and this row would then also be red when that operand is " +
				"neutralised — it would be reporting about a guard one frame down.",
			run: func(t *testing.T) {
				path := journalWith(t, 2)
				writeGarbage(t, path+highWaterSuffix)
				_, err := VerifyState(path)
				if err == nil {
					t.Fatal("a journal whose high-water mark could not be decoded verified clean")
				}
				if !strings.Contains(err.Error(), "high-water mark is malformed") {
					t.Fatalf("an unusable mark produced %q — without this operand the zero mark is carried into the checks below and the failure accuses the operator of resetting it", err)
				}
			},
		},
		{
			site:    "state.VerifyState/mark-stat-switch",
			operand: "the default (\"cannot tell\") case of the high-water stat switch",
			verdict: verdictUnreachable,
			why: "Found by this sweep rather than inherited from it. readHighWater four lines " +
				"above reads THE SAME PATH and returns on any error that is not ErrNotExist, so " +
				"the default case needs os.Stat to fail oddly on a name os.ReadFile had just " +
				"succeeded or ErrNotExist'ed on — a disagreement no stable filesystem produces. " +
				"Measured: replacing its return with `markFileExists = true` leaves the whole " +
				"package green, TestAnUnknowableMarkIsNeitherAbsentNorPresent included — that row " +
				"is refused by the os.Stat at the TOP of VerifyState, not by this switch, and now " +
				"says so. The guard stays: it is correct, and the ordering above it could change.",
			run: func(t *testing.T) {
				// The property, checked: the only fault that makes the sidecar unstat-able also
				// makes it unreadable, and the read is what reports.
				path := journalWith(t, 2)
				directoryAt(t, path+highWaterSuffix)
				_, err := VerifyState(path)
				if err == nil {
					t.Fatal("a journal whose sidecar is not a file verified clean")
				}
				if strings.Contains(err.Error(), "cannot be checked") {
					t.Fatalf("the high-water stat switch reported first (%v) — readHighWater above it no longer refuses this fault, so the default case IS reachable now and needs a real detector rather than this row", err)
				}
			},
		},
		{
			site:    "state.VerifyState/same-length-rewrite",
			operand: "replay.sequence == mark.Sequence",
			verdict: verdictCovered,
			why: "An `&&` operand: neutralising it WIDENS the refusal to every journal that is AHEAD " +
				"of its mark — which is precisely the crash window the write order creates (append " +
				"and fsync, then the mark). Refusing it takes the service down for a fault that did " +
				"not happen, so the row is a legitimate journal that must verify.",
			run: func(t *testing.T) {
				path := journalWith(t, 2)
				first := firstJournalEvent(t, path)
				if err := writeHighWater(path, highWaterMark{Sequence: first.Sequence, Hash: first.Hash}); err != nil {
					t.Fatal(err)
				}
				summary, err := VerifyState(path)
				if err != nil {
					t.Fatalf("a journal one append ahead of its high-water mark was refused: %v — that is the crash window between the fsync and the mark, and refusing it fails an intact journal closed", err)
				}
				if summary.HeadSequence != 2 {
					t.Fatalf("summary head = %d, want 2", summary.HeadSequence)
				}
			},
		},
		{
			site:    "state.VerifyState/same-length-rewrite",
			operand: "mark.Hash != stateGenesisHash",
			verdict: verdictUndetectable,
			why: "Neutralising it changes the outcome only for a mark that is BOTH at a non-zero " +
				"sequence AND genesis-valued: replay.lastHash != mark.Hash needs at least one event, " +
				"which needs mark.Sequence >= 1, and a present mark at sequence 0 beside history is " +
				"already refused by the genesis-downgrade rule above. No writer produces such a " +
				"mark, so the only fixture is forged — and neutralising the operand makes that " +
				"forgery REFUSED, which is safer, not less safe. A row pinning 'the forged mark " +
				"verifies clean' would pin a gap, so this one states the derivation instead.",
			run: func(t *testing.T) {
				t.Skip("every input that distinguishes this operand is a forged mark whose refusal would be an improvement; pinning it would pin a gap")
			},
		},
		{
			site:    "state.VerifyState/same-length-rewrite",
			operand: "replay.lastHash != mark.Hash",
			verdict: verdictPinnedElsewhere,
			why: "Neutralising it refuses every intact journal whose mark matches, so " +
				"verify_state_test.go's TestVerifyStateReportsAnIntactJournal and " +
				"mark_required_test.go's 'intact with its mark verifies' both fail. This row can " +
				"never be the sole failure.",
			run: func(t *testing.T) {
				t.Skip("pinned by TestVerifyStateReportsAnIntactJournal and TestAPolicyJournalWithHistoryCannotHaveNoPriorPosition/intact_with_its_mark_verifies")
			},
		},
		{
			site:    "state.OpenFileState/read-state",
			operand: "err != nil",
			verdict: verdictCovered,
			why: "Without it, a journal that is not a hash chain OPENS FOR WRITING: every nonce it " +
				"recorded is spendable again, the daily caps reset, and the next append extends a " +
				"chain nobody validated. The fixture carries no sidecar on purpose — with one, the " +
				"truncation rule below would refuse the file anyway and the row would prove nothing " +
				"about this operand.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				writeGarbage(t, path)
				state, err := OpenFileState(path)
				if err == nil {
					_ = state.Close()
					t.Fatal("a journal of non-JSON bytes opened for writing — every nonce and every unit of quota it was supposed to record is available again")
				}
				if !strings.Contains(err.Error(), "invalid JSON") {
					t.Fatalf("an unreadable journal was refused as %q — this operand is what stops the read error being discarded", err)
				}
			},
		},
		{
			site:    "state.OpenFileState/read-state",
			operand: "!errors.Is(err, os.ErrNotExist)",
			verdict: verdictPinnedElsewhere,
			why: "This is the operand that lets a FIRST open create the journal. Neutralising it " +
				"makes every fresh OpenFileState fail, so state_test.go's " +
				"TestFileStatePersistsReplayAndQuotaAcrossRestart and most of the rest of the " +
				"package go red together. It is covered many times over and no row here could ever " +
				"be the sole failure.",
			run: func(t *testing.T) {
				t.Skip("pinned by every test that opens a journal that does not exist yet, e.g. TestFileStatePersistsReplayAndQuotaAcrossRestart")
			},
		},
		{
			site:    "state.OpenFileState/read-high-water",
			operand: "err != nil after readHighWater",
			verdict: verdictCovered,
			why: "Without it, an unusable mark becomes the ZERO mark and the journal opens against " +
				"it — the truncation and rewrite checks below then run against a position that was " +
				"never read, and the service starts with its rollback detection disabled. Malformed " +
				"content rather than a read fault, for the same isolation reason as its VerifyState " +
				"twin: a read fault would make this row red when readHighWater's own guard is " +
				"neutralised, and it is not that guard's detector.",
			run: func(t *testing.T) {
				path := journalWith(t, 2)
				writeGarbage(t, path+highWaterSuffix)
				state, err := OpenFileState(path)
				if err == nil {
					_ = state.Close()
					t.Fatal("a journal whose high-water mark could not be decoded opened for writing — truncation detection is then running against a mark nobody read")
				}
				if !strings.Contains(err.Error(), "high-water mark is malformed") {
					t.Fatalf("an unusable mark produced %q — this operand is what stops the zero mark being carried into the rollback checks", err)
				}
			},
		},
		{
			site:    "state.OpenFileState/open-journal",
			operand: "err != nil after os.OpenFile",
			verdict: verdictCovered,
			why: "MEASURED with the operand neutralised: os.OpenFile returns a nil *os.File, " +
				"file.Stat() on it returns ErrInvalid rather than panicking, and OpenFileState " +
				"answers `stat policy state: invalid argument` — a diagnosis naming a syscall that " +
				"never ran, on a file that was never opened, with an errno that is about the " +
				"handle rather than about the path. The fixture is a path under a directory that " +
				"does not exist, so no permission bit and no uid is involved.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "no-such-directory", "policy-state.jsonl")
				state, err := OpenFileState(path)
				if err == nil {
					_ = state.Close()
					t.Fatal("a journal in a directory that does not exist opened")
				}
				if !strings.Contains(err.Error(), "open policy state") {
					t.Fatalf("a journal that could not be opened was refused as %q — without this operand the nil handle is stat'd instead and the message names the wrong syscall", err)
				}
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("the refusal does not carry os.ErrNotExist: %v", err)
				}
			},
		},
		{
			site:    "state.OpenFileState/stat-journal",
			operand: "err != nil after file.Stat",
			verdict: verdictUnreachable,
			why: "fstat on a descriptor os.OpenFile just returned does not fail in any way a test " +
				"can portably induce. Unlike load.LoadFile/stat, this branch is already SPLIT from " +
				"the mode refusal below it, so the reachable half has its own message and its own " +
				"detector (file_mode_test.go).",
			run: func(t *testing.T) {
				t.Skip("no portable fault makes fstat fail on a freshly opened descriptor; the mode refusal it is split from is pinned by file_mode_test.go")
			},
		},
		{
			site:    "state.Reserve/marshal-event",
			operand: "err != nil from json.Marshal(stateEvent)",
			verdict: verdictUnreachable,
			why: "stateEvent is a uint64, two strings and a Reservation, and Reservation is four " +
				"strings and two map[string]uint64. None of encoding/json's failure modes " +
				"(channels, functions, complex, NaN/Inf, unrepresentable map keys) can occur in that " +
				"shape. Marshalled here rather than argued, so adding such a field breaks the claim.",
			run: func(t *testing.T) {
				event := stateEvent{
					Sequence:     ^uint64(0),
					Reservation:  reservation("nonce_000000000001", "2026-09-04", ^uint64(0), ^uint64(0)),
					PreviousHash: stateGenesisHash,
				}
				event.Hash = stateEventHash(event)
				event.Reservation.Amounts["\xff\xfe not utf-8"] = 1
				event.Reservation.DailyCaps["\xff\xfe not utf-8"] = 2
				if _, err := json.Marshal(event); err != nil {
					t.Errorf("json.Marshal(stateEvent) failed: %v — the branch this row calls unreachable is now reachable and needs a detector", err)
				}
			},
		},
		{
			site:    "state.Reserve/write-high-water",
			operand: "err != nil from writeHighWater",
			verdict: verdictCovered,
			why: "The mark is what makes truncation detectable. If the append lands and the mark " +
				"write fails silently, the journal is one event ahead of a mark that will never " +
				"catch up, and the next deletion of that event is undetectable. The guard must both " +
				"report and LATCH the state failed. Fault injected as a directory at the sidecar's " +
				"temporary path, which is uid-independent.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				state, err := OpenFileState(path)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				directoryAt(t, path+highWaterSuffix+".tmp")
				err = state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 10, 100))
				if err == nil {
					t.Fatal("a reservation succeeded while its high-water mark could not be written — the journal is now ahead of a mark that will never catch up, and the next truncation is undetectable")
				}
				if !strings.Contains(err.Error(), "record policy state high-water mark") {
					t.Fatalf("a failed mark write was reported as %q, which names something else", err)
				}
				if !state.failed {
					t.Fatal("the state did not latch failed after the mark write failed, so the next reservation would append again and widen the gap between journal and mark")
				}
			},
		},
		{
			site:    "state.Ready/nil-file",
			operand: "state.file != nil",
			verdict: verdictCovered,
			why: "Unreachable through the exported constructor — OpenFileState errors out before " +
				"returning a *FileState without a handle — but this package's tests are white-box, " +
				"so the zero-value state IS constructible here. Without the operand a *FileState " +
				"with no journal behind it answers a readiness probe with 'ready', which is the one " +
				"answer that must never be wrong.",
			run: func(t *testing.T) {
				state := &FileState{lastHash: stateGenesisHash, nonces: map[string]struct{}{}, totals: map[string]uint64{}}
				if state.Ready(context.Background()) {
					t.Fatal("a FileState with no journal handle reported itself ready — a readiness probe would advertise a writer that has nothing to write to")
				}
			},
		},
		{
			site:    "state.readState/stat",
			operand: "err != nil in `err != nil || !IsRegular()`",
			verdict: verdictUnreachable,
			why: "fstat on a freshly opened descriptor does not fail portably, and this operand " +
				"shares one `return` with the IsRegular refusal below it, so even an inducible fault " +
				"could not be isolated from it. The reachable half has its own row.",
			run: func(t *testing.T) {
				t.Skip("no portable fault makes fstat fail on a freshly opened descriptor, and the operand shares one return with the reachable IsRegular half")
			},
		},
		{
			site:    "state.readState/stat",
			operand: "!info.Mode().IsRegular()",
			verdict: verdictCovered,
			why: "A directory (or a device, or a FIFO) at the journal path. Without the operand the " +
				"scanner reads the directory itself and the failure surfaces as 'read policy state', " +
				"which describes an I/O error rather than the configuration mistake that caused it.",
			run: func(t *testing.T) {
				journal := filepath.Join(t.TempDir(), "policy-state.jsonl")
				directoryAt(t, journal)
				_, err := readState(journal)
				if err == nil {
					t.Fatal("a directory was read as a policy state journal")
				}
				if !strings.Contains(err.Error(), "not a regular file") {
					t.Fatalf("a directory at the journal path was refused as %q — refused by the read instead of by the shape leaves the shape rule unproven, and names an I/O fault where the cause is a path pointing at the wrong kind of object", err)
				}
			},
		},
		{
			site:    "state.readState/integrity",
			operand: "event.Sequence != uint64(len(events)+1)",
			verdict: verdictCovered,
			why: "The source comment this replaces said a sole detector was 'structurally impossible' " +
				"because the three operands share one message and one return. They do share those — " +
				"and the operands are still isolable, because the hash is computed over the event: " +
				"break the sequence, RE-HASH, and the other two operands are satisfied. Without this " +
				"one a journal can start at any sequence, so an event can be dropped from the front " +
				"and the remainder still validates.",
			run: func(t *testing.T) {
				// Sequence 2 where 1 is required, chained from genesis and re-hashed: the
				// previous-hash and hash operands are both satisfied.
				event := chained(2, stateGenesisHash, "nonce_000000000001")
				_, err := readState(forgedJournal(t, event))
				if err == nil {
					t.Fatal("a journal whose first event is numbered 2 was accepted — an event can be removed from the front and the remainder still chains, so the sequence is the only thing that counts them")
				}
				if !strings.Contains(err.Error(), "integrity check failed") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			site:    "state.readState/integrity",
			operand: "event.PreviousHash != previous",
			verdict: verdictCovered,
			why: "Isolated the same way: an event correctly numbered and correctly hashed, whose " +
				"PreviousHash points at genesis instead of at its predecessor. Without this operand " +
				"the chain is not a chain — any two validly-hashed events in any order pass.",
			run: func(t *testing.T) {
				first := chained(1, stateGenesisHash, "nonce_000000000001")
				// Correct sequence, re-hashed, but chained to genesis rather than to `first`.
				second := chained(2, stateGenesisHash, "nonce_000000000002")
				_, err := readState(forgedJournal(t, first, second))
				if err == nil {
					t.Fatal("a journal whose second event chains to genesis rather than to the first was accepted — without the previous-hash link the events are a list, not a chain, and any of them can be swapped for another")
				}
				if !strings.Contains(err.Error(), "integrity check failed") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			site:    "state.readState/integrity",
			operand: "event.Hash != stateEventHash(event)",
			verdict: verdictPinnedElsewhere,
			why: "state_test.go's TestFileStateRejectsCorruptJournal edits a reservation amount and " +
				"leaves the recorded hash alone, which objects on this operand and no other. This row " +
				"runs the same claim through readState directly for symmetry with its two siblings, " +
				"and can never be the sole failure.",
			run: func(t *testing.T) {
				event := chained(1, stateGenesisHash, "nonce_000000000001")
				event.Reservation.Amounts["uatom"] = 99 // recorded hash left alone
				_, err := readState(forgedJournal(t, event))
				if err == nil {
					t.Fatal("an event whose recorded hash does not cover its own contents was accepted")
				}
				if !strings.Contains(err.Error(), "integrity check failed") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
	}
}

// firstJournalEvent reads back the first event a real writer produced, so a row can position the
// high-water mark at a real earlier point in the chain rather than at a value it invented.
func firstJournalEvent(t *testing.T, path string) stateEvent {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line, _, found := strings.Cut(string(contents), "\n")
	if !found || line == "" {
		t.Fatalf("the journal at %s has no first line", path)
	}
	var event stateEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil {
		t.Fatalf("decoding the journal's first event: %v", err)
	}
	return event
}

func TestFaultInjectionLedger(t *testing.T) {
	for _, row := range faultInjectionLedger() {
		t.Run(row.site+"/"+row.operand, func(t *testing.T) {
			row.run(t)
		})
	}
}

// THE LEDGER MUST STAY A LEDGER. Every row carries a verdict from the fixed set and a reason, and
// the two verdicts that mean "there is no detector" must say where the claim comes from. Without
// this, a row could be silently downgraded to `unreachable` with an empty `why` and the class
// would look swept.
func TestEveryLedgerRowIsClassifiedAndExplained(t *testing.T) {
	counts := map[string]int{}
	for _, row := range faultInjectionLedger() {
		name := row.site + "/" + row.operand
		switch row.verdict {
		case verdictCovered, verdictPinnedElsewhere, verdictUnreachable, verdictUndetectable:
		default:
			t.Errorf("%s carries verdict %q, which is not one of the four", name, row.verdict)
		}
		if len(row.why) < 80 {
			t.Errorf("%s has a %d-character reason — a verdict without a derivation is an assertion, and this file exists because assertions about untested branches were what went wrong", name, len(row.why))
		}
		if row.run == nil {
			t.Errorf("%s has no body", name)
		}
		if row.verdict == verdictPinnedElsewhere && !strings.Contains(row.why, "_test.go") && !strings.Contains(row.why, "Test") {
			t.Errorf("%s is claimed to be pinned elsewhere without naming the test that pins it", name)
		}
		counts[row.verdict]++
	}
	total := 0
	for _, count := range counts {
		total += count
	}
	if total != 28 {
		t.Fatalf("the ledger holds %d rows, not the 28 leaves enumerated at these 19 sites — a leaf that leaves the ledger leaves it silently", total)
	}
	t.Logf("#334 leaves: %d covered, %d pinned elsewhere, %d unreachable, %d undetectable",
		counts[verdictCovered], counts[verdictPinnedElsewhere], counts[verdictUnreachable], counts[verdictUndetectable])
}

// AN UNREADABLE MARK IS NOT AN ABSENT ONE.
//
// readHighWater answers an ABSENT sidecar with the genesis mark, which reopens the journal
// normally — that is the first write's crash window and it has to stay open. It must not give the
// same answer for a mark it merely could not read: that would turn a permission problem into a
// silent reset of the position that makes truncation detectable.
//
// EISDIR cannot express this claim, because EISDIR is neither ErrNotExist nor ErrPermission. This
// row therefore uses chmod, and denyAllAccess skips it — loudly — on any runner where the kernel
// did not actually record the denial, root included.
func TestAnUnreadableHighWaterMarkIsNotAnAbsentOne(t *testing.T) {
	path := journalWith(t, 1)
	sidecar := path + highWaterSuffix
	denyAllAccess(t, sidecar)

	_, err := readHighWater(path)
	if err == nil {
		t.Fatal("a high-water mark that could not be read resolved to a position anyway — an unreadable mark read as an absent one silently restores the journal's rollback detection to genesis")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("an unreadable mark was reported as absent: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("an unreadable mark produced %v, which is neither a permission error nor absence — the two answers this guard exists to separate", err)
	}
}

// A FAILED APPEND MUST NOT ADVANCE THE MARK.
//
// The write order is stated at the Reserve call site: append, fsync, THEN the mark, so a crash
// between them leaves the mark BEHIND the journal (which reopens) rather than ahead of it (which
// would refuse an intact journal and take the service down for a fault that did not happen).
// Nothing measured that ordering. This uses the harness's write-side primitive — the descriptor
// is closed underneath a live state, which is what a write fault looks like from inside Reserve —
// and then asks the sidecar what it recorded.
func TestAFailedAppendLeavesTheHighWaterMarkBehindTheJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 10, 100)); err != nil {
		t.Fatal(err)
	}
	before, err := readHighWater(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Sequence != 1 {
		t.Fatalf("the mark is at %d after one durable append, want 1 — the fixture is not in the state this test reasons about", before.Sequence)
	}

	severJournalHandle(t, state)
	if err := state.Reserve(context.Background(), reservation("nonce_000000000002", "2026-09-04", 10, 100)); err == nil {
		t.Fatal("a reservation succeeded after the journal handle was severed")
	}

	after, err := readHighWater(path)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("the high-water mark moved from %+v to %+v across an append that never landed — a mark ahead of the journal refuses an intact journal on the next open, which is a self-inflicted outage", before, after)
	}
}

// The known-good half, run AFTER every row above so a broken fixture cannot stop them reporting
// first (TESTING.md §18). Without it the integrity rows are equally consistent with a readState
// that refuses everything, and the forged-journal helper is exactly the sort of fixture that can
// drift into being refused for the wrong reason.
func TestTheForgedJournalHelperProducesAJournalReadStateAccepts(t *testing.T) {
	first := chained(1, stateGenesisHash, "nonce_000000000001")
	second := chained(2, first.Hash, "nonce_000000000002")
	events, err := readState(forgedJournal(t, first, second))
	if err != nil {
		t.Fatalf("a correctly chained forged journal was refused (%v) — every integrity row in the ledger would then pass against a readState that refuses everything, and none of them would be evidence", err)
	}
	if len(events) != 2 {
		t.Fatalf("read %d events from a two-event journal", len(events))
	}
	if events[1].PreviousHash != first.Hash {
		t.Fatalf("the helper did not chain the second event to the first")
	}
}

// The failingReader must fail. A reader that silently returns io.EOF would make the ReadAll row
// green for the wrong reason.
func TestTheFailingReaderActuallyFails(t *testing.T) {
	injected := errors.New("injected")
	n, err := failingReader{err: injected}.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, injected) || errors.Is(err, io.EOF) {
		t.Fatalf("failingReader returned (%d, %v), want (0, the injected error)", n, err)
	}
}
