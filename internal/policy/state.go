package policy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

const stateGenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type stateEvent struct {
	Sequence     uint64      `json:"sequence"`
	Reservation  Reservation `json:"reservation"`
	PreviousHash string      `json:"previous_hash"`
	Hash         string      `json:"hash"`
}

type FileState struct {
	mu        sync.Mutex
	file      *os.File
	sequence  uint64
	lastHash  string
	nonces    map[string]struct{}
	totals    map[string]uint64
	sequences map[string]uint64
	// maxEpoch is the highest fencing epoch any committed reservation ever carried. The
	// monotonic rule (#428): a reservation below it is a stale leader spending from a
	// budget a newer leader owns, and an epoch-0 reservation after a fenced one is a
	// site that lost its fence without losing its journal.
	maxEpoch uint64
	closed   bool
	failed   bool
	path     string
}

// highWaterSuffix names the sidecar recording the furthest this journal has ever reached.
//
// WHY A SIDECAR IS NEEDED AT ALL. The journal is a hash chain validated from genesis, which proves
// nobody EDITED it — and says nothing about TRUNCATION, because any valid prefix is itself a valid
// chain. Deleting the tail therefore reopened cleanly with spent nonces and the daily quota
// restored, which is a replay and an overspend obtained with `truncate`. The high-water mark is the
// one fact the journal cannot carry about itself.
const highWaterSuffix = ".high-water"

type highWaterMark struct {
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

func readHighWater(path string) (highWaterMark, error) {
	// FAULT INJECTION CLASS (#334) [state.readHighWater/read]: two leaves. The ErrNotExist
	// branch is pinned by mark_required_test.go's crash-window row. The err != nil branch is
	// what keeps an UNREADABLE mark from being answered like an absent one: without it the
	// nil contents reach json.Unmarshal and a permission fault is reported as malformed
	// content. Reached in the ledger by a directory at the sidecar path (uid-independent),
	// and the absent-vs-unreadable claim itself by
	// TestAnUnreadableHighWaterMarkIsNotAnAbsentOne.
	contents, err := os.ReadFile(path + highWaterSuffix)
	if errors.Is(err, os.ErrNotExist) {
		return highWaterMark{Hash: stateGenesisHash}, nil
	}
	if err != nil {
		return highWaterMark{}, fmt.Errorf("read policy state high-water mark: %w", err)
	}
	var mark highWaterMark
	if err := json.Unmarshal(contents, &mark); err != nil {
		return highWaterMark{}, errors.New("policy state high-water mark is malformed")
	}
	return mark, nil
}

// writeHighWater replaces the sidecar atomically. It is written AFTER the journal append is
// durable, so a crash between the two leaves the mark behind the journal — which reopens fine —
// rather than ahead of it, which would refuse to open a journal that is actually intact.
func writeHighWater(path string, mark highWaterMark) error {
	// FAULT INJECTION CLASS (#334) [state.writeHighWater/marshal]: §17 unreachable. None of
	// encoding/json's failure modes (channels, functions, complex, NaN/Inf, unrepresentable
	// map keys) can occur in a uint64 and a string. The ledger row marshals the extreme
	// values rather than asserting it, so adding an unmarshalable field breaks the claim.
	encoded, err := json.Marshal(mark)
	if err != nil {
		return err
	}
	temporary := path + highWaterSuffix + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path+highWaterSuffix)
}

// StateSummary is what an operator learns from verifying a policy state journal.
type StateSummary struct {
	Reservations uint64
	HeadSequence uint64
	HeadHash     string
	// HeadEpoch is the highest fencing epoch the journal records — the value a promoted
	// site checks its own journal copy against before it serves: a copy whose head epoch
	// already exceeds the epoch the authority granted is stale in the other direction,
	// and one below the last known spend is missing the newer leader's reservations.
	HeadEpoch uint64
}

// VerifyState checks a policy state journal without opening it for writing.
//
// This journal records every quota reservation and every consumed nonce, so shortening it restores
// spent quota and permits replay — which is why the high-water mark exists. Yet there was no way to
// check one: the package exported OpenFileState and nothing else, and OpenFileState takes an
// EXCLUSIVE flock for the process lifetime, so an operator could not even inspect the journal on a
// running host without stopping the daemon.
//
// The audit journal had the same gap and it was worse here: there at least Verify existed. This
// takes no lock and opens nothing for writing, so it is safe to run against a live deployment and
// against a copy taken off one.
func VerifyState(path string) (StateSummary, error) {
	if _, err := os.Stat(path); err != nil {
		// A missing journal is a verification failure even though OpenFileState creates one. The
		// operator is asking about a record that is supposed to exist, so answering "empty and
		// intact" would be a green result for a deleted journal or a typo in the path.
		return StateSummary{}, fmt.Errorf("cannot verify %s: %w", path, err)
	}
	// FAULT INJECTION CLASS (#334) [state.VerifyState/read-state]: two leaves with different
	// verdicts. `err != nil` is covered -- without it a journal that is not a hash chain
	// verifies CLEAN, because the read error is dropped and the replay runs over zero events.
	// `!errors.Is(err, os.ErrNotExist)` is unreachable: the os.Stat above already refused a
	// missing journal, so readState cannot answer ErrNotExist here except through a delete
	// landing between the two calls. Both classified in fault_injection_leaves_test.go.
	events, err := readState(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return StateSummary{}, err
	}
	replay := &FileState{lastHash: stateGenesisHash, nonces: make(map[string]struct{}), totals: make(map[string]uint64), sequences: make(map[string]uint64)}
	for _, event := range events {
		if err := replay.apply(event.Reservation); err != nil {
			return StateSummary{}, fmt.Errorf("policy state journal contains an invalid reservation at sequence %d", event.Sequence)
		}
		replay.sequence, replay.lastHash = event.Sequence, event.Hash
	}
	// FAULT INJECTION CLASS (#334) [state.VerifyState/read-high-water]: without this branch an
	// unreadable or undecodable mark becomes the ZERO mark and verification continues against it -- which then
	// trips the genesis-downgrade rule below and accuses the operator of resetting a mark that
	// was merely unreadable. Covered by a ledger row.
	mark, err := readHighWater(path)
	if err != nil {
		return StateSummary{}, err
	}
	// A JOURNAL WITH HISTORY CANNOT HAVE NO PRIOR POSITION (#223) — the policy twin of
	// audit's rule, for the same reason and with the same one-event crash window: the
	// mark is written after each append is durable, so two or more reservations with an
	// absent or genesis mark means tail and mark were deleted together, reopening spent
	// quota and consumed nonces. One reservation without a mark is the first write's
	// crash window and stays openable.
	markFileExists := true
	switch _, statErr := os.Stat(path + highWaterSuffix); {
	case statErr == nil:
		markFileExists = true
	case errors.Is(statErr, os.ErrNotExist):
		markFileExists = false
	default:
		// FAULT INJECTION CLASS (#334) [state.VerifyState/mark-stat-switch]: UNREACHABLE
		// BEHIND A SIBLING GUARD, and it did not look it. readHighWater four lines up reads
		// THIS SAME PATH and returns on any error that is not ErrNotExist, so reaching this
		// case needs os.Stat to fail oddly while os.ReadFile on the same name succeeded or
		// said ErrNotExist -- a disagreement no stable filesystem produces. Measured, not
		// argued: replacing this return with `markFileExists = true` leaves the whole package
		// green, TestAnUnknowableMarkIsNeitherAbsentNorPresent included. That row is refused
		// by the os.Stat at the top of VerifyState instead, and now says so.
		//
		// A STAT ERROR IS NOT ABSENCE AND NOT PRESENCE. The default-true this replaces
		// proceeded as though the mark were readable whenever the stat failed oddly — a
		// permission or I/O error read as "mark exists", and verification continued
		// against whatever a failed read had left in the mark value. The third state is
		// "cannot tell", and at a verification boundary its only safe reading is refusal.
		return StateSummary{}, fmt.Errorf("policy state journal has %d reservations but its high-water mark cannot be checked: %v — at a verification boundary, unknowable is neither absent nor present", len(events), statErr)
	}
	// ABSENT mark: legitimate only inside the first reservation's crash window — from two
	// on, absence means tail and mark were deleted together, reopening spent quota.
	if len(events) >= 2 && !markFileExists {
		return StateSummary{}, fmt.Errorf("policy state journal has %d reservations but no high-water mark recording a prior position — the write order makes that impossible beyond the first reservation's crash window, so the tail and the mark were deleted together", len(events))
	}
	// PRESENT mark at genesis: the policy twin of audit's downgrade rule, safe for the
	// same measured reason — Reserve is the only write site, it runs after the append is
	// durable, and it writes event.Sequence, never zero. A crash leaves the mark absent or
	// behind, never reset, so no legitimate state is refused here.
	if len(events) >= 1 && markFileExists && mark.Sequence == 0 {
		return StateSummary{}, fmt.Errorf("policy state journal has %d reservations but its high-water mark sits at genesis — the only write site never records zero, so the mark was reset to hide how far the journal reached", len(events))
	}
	if replay.sequence < mark.Sequence {
		return StateSummary{}, fmt.Errorf("policy state journal has been truncated: it ends at sequence %d but reached %d — spent quota and consumed nonces are missing, so both are available again",
			replay.sequence, mark.Sequence)
	}
	// FAULT INJECTION CLASS (#334) [state.VerifyState/same-length-rewrite]: three operands of
	// an && chain, so each is neutralised by making it always-true, which WIDENS the refusal --
	// each is therefore killed by a legitimate journal being wrongly refused, not by a bad one
	// being admitted. sequence==mark.Sequence: covered, by a journal one append AHEAD of its
	// mark (the crash window this write order deliberately creates). replay.lastHash !=
	// mark.Hash: already pinned by TestVerifyStateReportsAnIntactJournal. mark.Hash !=
	// stateGenesisHash: undetectable -- the only inputs that distinguish it are forged marks
	// whose refusal would be an improvement, so pinning one would pin a gap. Derivations in
	// fault_injection_leaves_test.go.
	if replay.sequence == mark.Sequence && mark.Hash != stateGenesisHash && replay.lastHash != mark.Hash {
		return StateSummary{}, errors.New("policy state journal does not match its recorded history: it was rewritten rather than shortened")
	}
	return StateSummary{Reservations: uint64(len(events)), HeadSequence: replay.sequence, HeadHash: replay.lastHash, HeadEpoch: replay.maxEpoch}, nil
}

func OpenFileState(path string) (*FileState, error) {
	state := &FileState{lastHash: stateGenesisHash, nonces: make(map[string]struct{}), totals: make(map[string]uint64), sequences: make(map[string]uint64)}
	// FAULT INJECTION CLASS (#334) [state.OpenFileState/read-state]: `err != nil` is covered --
	// without it a journal that is not a hash chain OPENS FOR WRITING, every nonce it recorded
	// is spendable again and the next append extends a chain nobody validated. The ledger's
	// fixture carries no sidecar on purpose, or the truncation rule below would refuse the file
	// anyway and prove nothing. `!errors.Is(err, os.ErrNotExist)` is the operand that lets a
	// FIRST open create the journal, and is pinned by every test that opens a fresh one.
	events, err := readState(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	for _, event := range events {
		if err := state.apply(event.Reservation); err != nil {
			return nil, errors.New("policy state journal contains an invalid reservation")
		}
		state.sequence, state.lastHash = event.Sequence, event.Hash
	}
	// THE JOURNAL MAY NOT HAVE GONE BACKWARDS. Replay and quota are only durable if the record of
	// them cannot be shortened, and the chain alone cannot detect that.
	// FAULT INJECTION CLASS (#334) [state.OpenFileState/read-high-water]: without this branch an
	// unreadable or undecodable mark becomes the ZERO mark and the journal opens against it, so the truncation
	// and rewrite checks below run against a position nobody read and the service starts with
	// its rollback detection disabled. Covered by a ledger row.
	mark, err := readHighWater(path)
	if err != nil {
		return nil, err
	}
	if state.sequence < mark.Sequence {
		return nil, fmt.Errorf("policy state journal has been truncated: it ends at sequence %d but reached %d — replay and quota history is missing",
			state.sequence, mark.Sequence)
	}
	if state.sequence == mark.Sequence && mark.Hash != stateGenesisHash && state.lastHash != mark.Hash {
		// Same length, different chain: the journal was rewritten rather than shortened.
		return nil, errors.New("policy state journal does not match its recorded history")
	}

	// FAULT INJECTION CLASS (#334) [state.OpenFileState/open-journal]: MEASURED with this
	// branch neutralised, rather than described:
	//
	// 	os.OpenFile(under a missing dir) -> file == nil, "no such file or directory"
	// 	file.Stat()                      -> nil, "invalid argument"   (no panic)
	// 	OpenFileState(...)               -> "stat policy state: invalid argument"
	//
	// A diagnosis naming a syscall that never ran, on a file that was never opened, with an
	// errno about the handle rather than about the path. Covered by a ledger row whose fixture
	// is a path under a directory that does not exist -- no permission bit, no uid.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open policy state: %w", err)
	}
	// FAULT INJECTION CLASS (#334) [state.OpenFileState/stat-journal]: §17 unreachable -- fstat
	// on a descriptor OpenFile just returned does not fail portably. Unlike the load.go twin,
	// this branch is already SPLIT from the mode refusal below, so the reachable half has its
	// own message and its own detector in file_mode_test.go.
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat policy state: %w", err)
	}
	// The guard is on the MODE BITS, and says so. It does not prove no other user can reach the
	// file -- a POSIX ACL can grant access these bits do not show -- and a message claiming it
	// did would be the same overstatement this replaced, one step subtler.
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, errors.New("policy state must be a regular file with group and other permission bits clear")
	}

	// ONE WRITER. Replay and quota are enforced from in-memory maps loaded at open, so a second
	// process on the same journal keeps its own copy: both grant the same nonce and both spend the
	// full daily cap. An advisory lock held for the process lifetime makes that a startup failure
	// instead of a silent double-spend. The active/passive lease governs SITES; this governs one
	// journal, which is a different question and needs its own answer.
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("policy state is already open by another process: %w", err)
	}

	state.path = path
	state.file = file
	return state, nil
}

func (state *FileState) Reserve(ctx context.Context, reservation Reservation) error {
	if err := validateReservation(reservation); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return errors.New("policy state unavailable")
	}
	if state.failed {
		return errors.New("policy state unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// THE EPOCH MAY NOT GO BACKWARDS (#428). Both arms fail closed on the same error:
	// an epoch below the journal's maximum is a replaced leader still spending, and an
	// unfenced reservation after fenced history is the fence disappearing while the
	// budget it protected stays. Equal epochs are the SAME leader continuing, which is
	// the normal case and must keep working.
	if reservation.Epoch < state.maxEpoch || (reservation.Epoch == 0 && state.maxEpoch > 0) {
		return ErrEpoch
	}
	nonce := nonceKey(reservation)
	if _, exists := state.nonces[nonce]; exists {
		return ErrReplay
	}
	if reservation.Sequence != nil {
		key := reservation.SequenceKey
		if previous, exists := state.sequences[key]; exists && *reservation.Sequence != previous+1 {
			return ErrSequence
		}
	}
	for denom, amount := range reservation.Amounts {
		current := state.totals[quotaKey(reservation, denom)]
		cap := reservation.DailyCaps[denom]
		if cap == 0 || amount > cap || current > cap-amount {
			return ErrLimit
		}
	}
	event := stateEvent{Sequence: state.sequence + 1, Reservation: reservation, PreviousHash: state.lastHash}
	event.Hash = stateEventHash(event)
	// FAULT INJECTION CLASS (#334) [state.Reserve/marshal-event]: §17 unreachable. stateEvent is
	// a uint64, two strings and a Reservation of four strings and two map[string]uint64 -- none
	// of encoding/json's failure modes can occur in that shape. The ledger row marshals it at
	// the extremes rather than asserting it, so adding such a field breaks the claim.
	encoded, err := json.Marshal(event)
	if err != nil {
		return errors.New("encode policy state")
	}
	if _, err := state.file.Write(append(encoded, '\n')); err != nil {
		state.failed = true
		return fmt.Errorf("append policy state: %w", err)
	}
	if err := state.file.Sync(); err != nil {
		state.failed = true
		return fmt.Errorf("sync policy state: %w", err)
	}
	if err := state.apply(reservation); err != nil {
		return errors.New("apply committed policy state")
	}
	state.sequence, state.lastHash = event.Sequence, event.Hash

	// AFTER the journal append is durable, never before: a crash between the two must leave the
	// mark BEHIND the journal, which reopens normally, rather than ahead of it, which would refuse
	// an intact journal and take the service down for a fault that did not happen.
	//
	// FAULT INJECTION CLASS (#334) [state.Reserve/write-high-water]: the mark is what makes
	// truncation detectable, so an append that lands while its mark write fails silently leaves
	// the journal permanently ahead of a mark that never catches up -- and the next deletion of
	// that event is then undetectable. The guard must both report and LATCH. Covered by a ledger
	// row whose fault is a directory at the sidecar's temporary path, and the ordering claim in
	// the paragraph above by TestAFailedAppendLeavesTheHighWaterMarkBehindTheJournal.
	if err := writeHighWater(state.path, highWaterMark{Sequence: event.Sequence, Hash: event.Hash}); err != nil {
		state.failed = true
		return fmt.Errorf("record policy state high-water mark: %w", err)
	}
	return nil
}

func (state *FileState) apply(reservation Reservation) error {
	// Replay does not enforce the epoch rule — it RECONSTRUCTS the high-water the rule
	// runs against (a journal that refused a reservation at commit time records nothing,
	// so there is nothing to refuse again). The guard lives in Reserve alone.
	if reservation.Epoch > state.maxEpoch {
		state.maxEpoch = reservation.Epoch
	}
	nonce := nonceKey(reservation)
	if _, exists := state.nonces[nonce]; exists {
		return ErrReplay
	}
	for denom, amount := range reservation.Amounts {
		key := quotaKey(reservation, denom)
		if ^uint64(0)-state.totals[key] < amount {
			return ErrLimit
		}
		state.totals[key] += amount
	}
	state.nonces[nonce] = struct{}{}
	if reservation.Sequence != nil {
		state.sequences[reservation.SequenceKey] = *reservation.Sequence
	}
	return nil
}

func (state *FileState) Ready(context.Context) bool {
	state.mu.Lock()
	defer state.mu.Unlock()
	// FAULT INJECTION CLASS (#334) [state.Ready/nil-file]: unreachable through the exported
	// constructor -- OpenFileState errors out before returning a *FileState without a handle --
	// but this package's tests are white-box, so the zero-value state IS constructible and the
	// operand IS covered. Without it a FileState with no journal behind it answers a readiness
	// probe with "ready", which is the one answer that must never be wrong.
	return !state.closed && !state.failed && state.file != nil
}

func (state *FileState) Close() error {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.closed {
		return nil
	}
	state.closed = true
	return state.file.Close()
}

func readState(path string) ([]stateEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// FAULT INJECTION CLASS (#334) [state.readState/stat]: two leaves. `err != nil` is §17
	// unreachable and shares this return with the IsRegular half, so even an inducible fstat
	// fault could not be isolated from it. `!IsRegular()` IS reachable -- a directory at the
	// journal path -- and is covered by a ledger row: without it the scanner reads the directory
	// and the failure surfaces as an I/O error rather than as the wrong kind of object.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("policy state is not a regular file")
	}
	var events []stateEvent
	previous := stateGenesisHash
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var event stateEvent
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return nil, errors.New("policy state contains invalid JSON")
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, errors.New("policy state contains trailing data")
		}
		// FAULT INJECTION CLASS (#334) [state.readState/integrity]: three operands, and the note
		// here used to say isolating one was structurally impossible because they share a message
		// and a return. They do share those, and they are still isolable: the hash is computed OVER
		// the event, so a row can break one field, RE-HASH, and leave the other two satisfied.
		// Sequence and PreviousHash each have their own covered ledger row on that construction;
		// the Hash operand is pinned by state_test.go's TestFileStateRejectsCorruptJournal.
		if event.Sequence != uint64(len(events)+1) || event.PreviousHash != previous || event.Hash != stateEventHash(event) {
			return nil, errors.New("policy state integrity check failed")
		}
		if err := validateReservation(event.Reservation); err != nil {
			return nil, errors.New("policy state reservation is invalid")
		}
		previous = event.Hash
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read policy state: %w", err)
	}
	return events, nil
}

// utcDateLayout is the only spelling a quota bucket's date may take. Named rather than repeated
// so that the test asserting what this layout does and does not admit is reading the same value
// the validator uses -- a duplicated literal there would keep passing after this one changed.
const utcDateLayout = "2006-01-02"

func validateReservation(reservation Reservation) error {
	if reservation.PolicyID == "" || reservation.ObjectID == "" || reservation.Principal == "" || !noncePattern.MatchString(reservation.Nonce) {
		return errors.New("invalid policy reservation identity")
	}
	parsed, err := time.Parse(utcDateLayout, reservation.UTCDate)
	if err != nil || parsed.Format(utcDateLayout) != reservation.UTCDate {
		return errors.New("invalid policy reservation date")
	}
	for denom, amount := range reservation.Amounts {
		if denom == "" || amount == 0 || reservation.DailyCaps[denom] == 0 || amount > reservation.DailyCaps[denom] {
			return errors.New("invalid policy reservation amount")
		}
	}
	if reservation.Sequence != nil && *reservation.Sequence == ^uint64(0) {
		return errors.New("invalid policy reservation sequence")
	}
	if reservation.Sequence != nil && reservation.SequenceKey == "" {
		return errors.New("invalid policy reservation sequence key")
	}
	return nil
}

func nonceKey(reservation Reservation) string {
	return reservation.PolicyID + "\x00" + reservation.ObjectID + "\x00" + reservation.Principal + "\x00" + reservation.Nonce
}

func quotaKey(reservation Reservation, denom string) string {
	return reservation.PolicyID + "\x00" + reservation.ObjectID + "\x00" + reservation.UTCDate + "\x00" + denom
}

func stateEventHash(event stateEvent) string {
	event.Hash = ""
	encoded, _ := json.Marshal(event)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
