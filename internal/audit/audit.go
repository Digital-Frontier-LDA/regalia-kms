// Package audit writes ordered, tamper-evident events and synchronously ships
// them to an off-host sink for high-risk operations.
package audit

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
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	ErrSinkUnavailable = errors.New("audit sink unavailable")
	// ErrChainRead marks I/O failures inside a chain scan — the journal could not
	// be read, which is a different incident from the chain not verifying. The
	// periodic verifier classifies on it; the two page different people.
	ErrChainRead = errors.New("audit chain could not be read")
	// ErrDurable marks the errors Record returns AFTER the event is already in the local
	// journal. Record advances its sequence only once Write and Sync have both succeeded,
	// and three of its failure returns come after that point: the high-water-mark write,
	// the no-shipper case under requireRemote, and a remote acknowledgement that does not
	// arrive. In all three the event is on disk and will ship when the collector recovers
	// -- "the operation failed closed" and "the record was lost" are different facts, and
	// an error alone cannot tell them apart.
	//
	// Callers that count lost records must exclude these or they over-report; see
	// Durable. Wrapped rather than replacing the cause, so errors.Is against
	// ErrSinkUnavailable keeps working.
	ErrDurable       = errors.New("audit event is already durable")
	requestIDPattern = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)
)

// Durable reports whether err was returned after the event reached the local journal.
//
// A true answer means the operation failed -- the caller still refuses -- but the audit
// record itself is NOT lost: it is written, synced, and queued to ship. A metric counting
// dropped records that includes these is measuring collector latency and calling it data
// loss.
func Durable(err error) bool { return err != nil && errors.Is(err, ErrDurable) }

// durable wraps a post-write failure, preserving nil so callers can pass a result through.
func durable(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrDurable, err)
}

const genesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

type Draft struct {
	Timestamp           time.Time
	RequestID           string
	Principal           string
	Decision            string
	ObjectID            string
	Purpose             string
	Operation           string
	DeviceID            string
	Outcome             string
	LatencyMilliseconds int64
	RegistryDigest      string
	PolicyDigest        string
	// RBACDigest is the digest of the RBAC policy that authorized this
	// operation. Required by validateDraft. Adding this field changes the
	// marshalled JSON of every Event, which means events written by an older
	// audit code cannot be verified after upgrade — TestVerifyRefusesPreRBACDigestEvents
	// pins that decision and PR notes the upgrade-day constraint. Operators
	// upgrading a daemon with an existing journal must rotate the journal
	// file (or drain it forward to a downstream collector) before deploying
	// this code path, or the new daemon will refuse to start.
	RBACDigest string
	// VerifiedApprovers is the set of approvers whose signatures the daemon verified for
	// this request, empty for the overwhelming majority of operations. It answers "who
	// signed off on this?" from the journal alone, which is the only place a dual-control
	// decision can be audited after the fact.
	//
	// It is omitempty on the Event, unlike RBACDigest. Adding a field changes the hashed
	// byte stream, and RBACDigest broke verification of every journal written before it
	// (TestVerifyRefusesPreRBACDigestEvents pins that). Omitting an empty set means events
	// without approvals marshal to exactly the bytes they did before, so existing journals
	// keep verifying and only approval-bearing events carry the field. Stripping the field
	// from an event that had one still changes the hash and is still detected.
	VerifiedApprovers []string
}

type Event struct {
	Sequence            uint64    `json:"sequence"`
	Timestamp           time.Time `json:"timestamp"`
	RequestID           string    `json:"request_id"`
	Principal           string    `json:"principal"`
	Decision            string    `json:"decision"`
	ObjectID            string    `json:"object_id,omitempty"`
	Purpose             string    `json:"purpose,omitempty"`
	Operation           string    `json:"operation"`
	DeviceID            string    `json:"device_id,omitempty"`
	Outcome             string    `json:"outcome"`
	LatencyMilliseconds int64     `json:"latency_ms"`
	RegistryDigest      string    `json:"registry_digest"`
	PolicyDigest        string    `json:"policy_digest"`
	RBACDigest          string    `json:"rbac_digest"`
	VerifiedApprovers   []string  `json:"verified_approvers,omitempty"`
	PreviousHash        string    `json:"previous_hash"`
	Hash                string    `json:"hash"`
}

type Sink interface {
	Send(context.Context, Event) error
	Ready(context.Context) bool
}

type Recorder struct {
	mu       sync.Mutex
	file     *os.File
	sink     Sink
	shipper  *shipper
	sequence uint64
	lastHash string
	path     string
	closed   bool
	// durableOffset is the file size the journal is fsynced through: the periodic
	// verifier reads exactly this prefix and never the in-flight tail.
	durableOffset int64
	// Periodic self-verification state; see verifier.go.
	lastVerify    VerifyState
	verifyStarted bool
	verifyStop    context.CancelFunc
	verifyWg      sync.WaitGroup
}

// highWaterSuffix names the sidecar recording how far the audit chain has reached.
//
// The chain proves nobody EDITED the journal and says nothing about TRUNCATION: any valid prefix is
// itself a valid chain, so dropping the most recent events verified clean and Open resumed from
// the shortened history. For an audit trail that is the interesting attack — the events worth
// removing are always the most recent ones — and it left no trace at all.
const highWaterSuffix = ".high-water"

type highWaterMark struct {
	Sequence uint64 `json:"sequence"`
	Hash     string `json:"hash"`
}

func readMark(file string) (highWaterMark, error) {
	contents, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return highWaterMark{Hash: genesisHash}, nil
	}
	if err != nil {
		return highWaterMark{}, fmt.Errorf("read audit mark: %w", err)
	}
	var mark highWaterMark
	if err := json.Unmarshal(contents, &mark); err != nil {
		return highWaterMark{}, errors.New("audit mark is malformed")
	}
	return mark, nil
}

func readAuditHighWater(path string) (highWaterMark, error) {
	return readMark(path + highWaterSuffix)
}

// writeMark replaces the sidecar atomically, and is called only AFTER the event is
// durable so a crash leaves the mark behind the journal rather than ahead of it.
func writeMark(file string, mark highWaterMark) error {
	encoded, err := json.Marshal(mark)
	if err != nil {
		return err
	}
	temporary := file + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, file)
}

func writeAuditHighWater(path string, mark highWaterMark) error {
	return writeMark(path+highWaterSuffix, mark)
}

// VerifyIntegrity is the whole integrity check, and the one an operator can run.
//
// Verify alone walks the hash chain from genesis, which cannot detect the attack the chain is most
// exposed to: any valid PREFIX of a valid chain is itself a valid chain, so deleting the most recent
// events leaves something that verifies clean. The high-water mark and the collector-acknowledged
// mark are what close that, and until now they were applied only inside Open — reachable by the
// daemon at startup and by nobody else.
//
// That mattered because Verify was also the only exported entry point, and internal/audit cannot be
// imported from outside the module. The KMS wrote a tamper-evident journal that no operator could
// check, and the strongest check it had was not the one on offer.
func VerifyIntegrity(path string) ([]Event, error) {
	events, err := Verify(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// THE TRAIL MAY NOT HAVE GONE BACKWARDS.
	mark, err := readAuditHighWater(path)
	if err != nil {
		return nil, err
	}
	// A JOURNAL WITH HISTORY CANNOT HAVE NO PRIOR POSITION (#223). The mark is written
	// after every event is durable, so the only crash window in which the mark file is
	// absent with events in the journal is the FIRST event's — before any mark write has
	// succeeded. From two events on, an absent mark (or one sitting at genesis) means the
	// tail and the mark were deleted TOGETHER, which is precisely the deletion the mark
	// exists to detect: returning genesis for the missing file made the attack verify
	// clean. One event without a mark stays open: that is the first-write crash window,
	// and refusing it would take down every fresh site's first crash.
	markFileExists := true
	switch _, statErr := os.Stat(path + highWaterSuffix); {
	case statErr == nil:
		markFileExists = true
	case errors.Is(statErr, os.ErrNotExist):
		markFileExists = false
	default:
		// A STAT ERROR IS NOT ABSENCE AND NOT PRESENCE. The default-true this replaces
		// proceeded as though the mark's existence were established whenever the stat
		// failed oddly — a permission or I/O error read as "mark exists". The mark's VALUE
		// was read above; what could not be classified here is its FILE, and the
		// absence/presence rules below each depend on that classification.
		return nil, fmt.Errorf("audit journal has %d events but its high-water mark's file cannot be classified: %v — the mark's value was read, its existence was not established, and the absence and presence rules each depend on which it is", len(events), statErr)
	}
	// ABSENT mark: legitimate only inside the first event's crash window — the mark is
	// written after every event is durable, so from two events on, absence means the tail
	// and the mark were deleted together.
	if len(events) >= 2 && !markFileExists {
		return nil, fmt.Errorf("audit journal has %d events but no high-water mark recording a prior position — the write order makes that impossible beyond the first event's crash window, so the tail and the mark were deleted together", len(events))
	}
	// PRESENT mark sitting at genesis: a state the writer cannot produce. There is exactly
	// one write site for the mark (Record, after the append is durable) and it always
	// writes event.Sequence, which is never zero — so a genesis-valued file beside ANY
	// history, one event included, is a downgrade written after the fact. Refusing it
	// costs no legitimate crash window: the crash leaves the mark ABSENT or BEHIND, never
	// reset to zero.
	if len(events) >= 1 && markFileExists && mark.Sequence == 0 {
		return nil, fmt.Errorf("audit journal has %d events but its high-water mark sits at genesis — the only write site never records zero, so the mark was reset to hide how far the journal reached", len(events))
	}
	var reached uint64
	var reachedHash = genesisHash
	if len(events) > 0 {
		reached, reachedHash = events[len(events)-1].Sequence, events[len(events)-1].Hash
	}
	if reached < mark.Sequence {
		return nil, fmt.Errorf("audit journal has been truncated: it ends at sequence %d but reached %d — events are missing",
			reached, mark.Sequence)
	}
	if reached == mark.Sequence && mark.Hash != genesisHash && reachedHash != mark.Hash {
		return nil, errors.New("audit journal does not match its recorded history")
	}
	// THE JOURNAL MAY NOT FALL BEHIND WHAT THE COLLECTOR ALREADY ACKNOWLEDGED.
	//
	// The high-water mark detects truncation, but an attacker who knows that scheme
	// deletes the sidecar along with the events. The .shipped mark is the second,
	// independent record of how far the trail reached; a journal that ends before
	// it, or disagrees with it, has lost events the off-host copy holds.
	shipped, err := readShippedMark(path)
	if err != nil {
		return nil, err
	}
	if shipped.Sequence > reached {
		return nil, fmt.Errorf("audit journal is missing events the collector already acknowledged: shipped through sequence %d but the journal ends at %d",
			shipped.Sequence, reached)
	}
	if shipped.Sequence > 0 && events[shipped.Sequence-1].Hash != shipped.Hash {
		return nil, fmt.Errorf("audit journal conflicts with the collector-acknowledged event at sequence %d", shipped.Sequence)
	}
	// The high-water mark is written before an event can ship, so the acknowledged head
	// can never legitimately outrun it — with TWO reachable readings, not one (#246: this
	// guard and #223's absent-mark crash window were each falsified alone and never
	// composed; the composed state appeared only under -race -count=200).
	//
	// When the mark FILE is absent: the write order means a mark existed when anything
	// shipped, so its absence beside acknowledged history is DURABILITY LOSS, not the
	// first-write crash window (that window has nothing shipped — the shipper enqueues
	// after the mark write). writeMark is tmp+rename with no directory fsync, so a crash
	// can drop the mark's rename while the shipped mark's survives: reachable, honest,
	// and still a refusal — the truncation record is gone and the journal cannot be
	// verified against it.
	//
	// When the mark file EXISTS and is merely behind: crossed sidecars, the forged reading
	// the original guard named.
	if shipped.Sequence > mark.Sequence {
		// The same three-valued classification the mark-existence probe above applies,
		// because this branch diagnoses BY that classification: absent → durability,
		// present-but-behind → forged, cannot-be-established → refusal without a
		// diagnosis. Letting other stat errors fall into "forged" is the outcome this
		// PR exists to stop — an operator sent hunting an attacker for a transient
		// stat failure (#248 review).
		switch _, statErr := os.Stat(path + highWaterSuffix); {
		case errors.Is(statErr, os.ErrNotExist):
			return nil, fmt.Errorf("the high-water mark is absent but the collector acknowledged sequence %d — the mark is written before any event ships, so this is durability loss or deletion, and the journal cannot be verified against truncation without it",
				shipped.Sequence)
		case statErr != nil:
			return nil, fmt.Errorf("the high-water mark's file cannot be classified (%v) while the collector acknowledged sequence %d — neither the durability nor the forged reading can be chosen on a mark nobody could stat", statErr, shipped.Sequence)
		default:
			return nil, fmt.Errorf("collector-acknowledged head (sequence %d) is ahead of the recorded journal head (sequence %d): one of the audit sidecars was forged",
				shipped.Sequence, mark.Sequence)
		}
	}
	return events, nil
}

func Open(path string, sink Sink) (*Recorder, error) {
	events, err := VerifyIntegrity(path)
	if err != nil {
		return nil, err
	}
	// Re-read rather than thread it out of VerifyIntegrity: that function's job is to answer
	// whether the journal is intact, and its signature should not grow to carry a detail only the
	// shipper needs. It has already refused every way this mark can disagree with the journal.
	shipped, err := readShippedMark(path)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit buffer: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat audit buffer: %w", err)
	}
	// On the MODE BITS specifically. A POSIX ACL can grant access these bits do not show, so
	// claiming "no other user can reach it" would overstate the check the same way the
	// mode-0600 wording did.
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, errors.New("audit buffer must be a regular file with group and other permission bits clear")
	}
	recorder := &Recorder{file: file, sink: sink, lastHash: genesisHash, path: path, durableOffset: info.Size()}
	if len(events) > 0 {
		recorder.sequence = events[len(events)-1].Sequence
		recorder.lastHash = events[len(events)-1].Hash
	}
	if sink != nil {
		// The journal tail past the acknowledged head is the pending shipment
		// queue: replayed here, never copied into a second store.
		recorder.shipper = newShipper(sink, path, append([]Event(nil), events[shipped.Sequence:]...), shipped.Sequence)
	}
	// The startup verification this Open just completed is the zeroth periodic
	// run: if the verifier loop is never started, the metric goes stale from boot
	// instead of being absent, and "nobody is watching" alerts like any other
	// staleness.
	recorder.lastVerify = VerifyState{Outcome: VerifyIntact, At: time.Now().UTC(), Events: len(events)}
	return recorder, nil
}

func (recorder *Recorder) Record(ctx context.Context, draft Draft, requireRemote bool) error {
	if err := validateDraft(draft); err != nil {
		return err
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.closed {
		return errors.New("audit recorder is closed")
	}
	event := Event{
		Sequence: recorder.sequence + 1, Timestamp: draft.Timestamp.UTC(), RequestID: draft.RequestID,
		Principal: draft.Principal, Decision: draft.Decision, ObjectID: draft.ObjectID,
		Purpose: draft.Purpose, Operation: draft.Operation, DeviceID: draft.DeviceID,
		Outcome: draft.Outcome, LatencyMilliseconds: draft.LatencyMilliseconds,
		RegistryDigest: draft.RegistryDigest, PolicyDigest: draft.PolicyDigest, RBACDigest: draft.RBACDigest,
		VerifiedApprovers: draft.VerifiedApprovers,
		PreviousHash:      recorder.lastHash,
	}
	event.Hash = eventHash(event)
	line, err := json.Marshal(event)
	if err != nil {
		return errors.New("encode audit event")
	}
	line = append(line, '\n')
	if _, err := recorder.file.Write(line); err != nil {
		return fmt.Errorf("append audit event: %w", err)
	}
	if err := recorder.file.Sync(); err != nil {
		return fmt.Errorf("sync audit event: %w", err)
	}
	recorder.sequence, recorder.lastHash = event.Sequence, event.Hash
	recorder.durableOffset += int64(len(line))
	if err := writeAuditHighWater(recorder.path, highWaterMark{Sequence: event.Sequence, Hash: event.Hash}); err != nil {
		return durable(fmt.Errorf("record audit high-water mark: %w", err))
	}
	// The event is durable, so shipping it can never be lost — only delayed. A
	// high-risk operation still fails closed when the collector cannot acknowledge
	// the event within the call, but the event itself ships as soon as the
	// collector recovers rather than being dropped by the failed attempt.
	if recorder.shipper == nil {
		if requireRemote {
			return durable(ErrSinkUnavailable)
		}
		return nil
	}
	recorder.shipper.enqueue(event)
	if !requireRemote {
		return nil
	}
	return durable(recorder.shipper.waitShipped(ctx, event.Sequence))
}

func sendEvent(ctx context.Context, sink Sink, event Event) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrSinkUnavailable
		}
	}()
	return sink.Send(ctx, event)
}

// Ready reports whether the audit trail is being shipped. The collector answering
// its health check is not enough: a backlog of events it has never acknowledged
// means the off-host copy is falling behind, so readiness fails past
// maxAuditBacklog even while the collector looks healthy.
func (recorder *Recorder) Ready(ctx context.Context) bool {
	return recorder != nil && recorder.sink != nil && recorder.shipper != nil &&
		recorder.shipper.backlog() <= maxAuditBacklog && sinkReady(ctx, recorder.sink)
}

func sinkReady(ctx context.Context, sink Sink) (ready bool) {
	defer func() {
		if recover() != nil {
			ready = false
		}
	}()
	return sink.Ready(ctx)
}

func (recorder *Recorder) Close() error {
	recorder.mu.Lock()
	if recorder.closed {
		recorder.mu.Unlock()
		return nil
	}
	recorder.closed = true
	verifyStop := recorder.verifyStop
	shipper := recorder.shipper
	recorder.mu.Unlock()
	// Stop the verifier and the shipper without holding the lock: both need it
	// briefly to record their final state, and waiting under the lock deadlocks.
	if verifyStop != nil {
		verifyStop()
	}
	recorder.verifyWg.Wait()
	// The shipper is not drained: what is still pending is durable in
	// the journal and resumes from the .shipped mark on the next Open.
	if shipper != nil {
		shipper.close()
	}
	return recorder.file.Close()
}

func Verify(path string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("audit buffer is not a regular file")
	}
	return verifyEvents(file)
}

// verifyEvents is the chain-integrity scan over any reader, shared by Verify (the
// whole file) and the periodic verifier (bounded to the durable prefix).
func verifyEvents(reader io.Reader) ([]Event, error) {
	var events []Event
	previous := genesisHash
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		var event Event
		decoder := json.NewDecoder(strings.NewReader(scanner.Text()))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&event); err != nil {
			return nil, errors.New("audit chain contains invalid JSON")
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return nil, errors.New("audit event contains trailing data")
		}
		if event.Sequence != uint64(len(events)+1) || event.PreviousHash != previous || event.Hash != eventHash(event) {
			return nil, errors.New("audit chain integrity check failed")
		}
		previous = event.Hash
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrChainRead, err)
	}
	return events, nil
}

func eventHash(event Event) string {
	event.Hash = ""
	encoded, _ := json.Marshal(event)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validateDraft(draft Draft) error {
	if draft.Timestamp.IsZero() || !requestIDPattern.MatchString(draft.RequestID) || draft.LatencyMilliseconds < 0 {
		return errors.New("invalid audit metadata")
	}
	if draft.Decision != "allow" && draft.Decision != "deny" {
		return errors.New("invalid audit decision")
	}
	if draft.Operation == "" || draft.Outcome == "" ||
		draft.RegistryDigest == "" || draft.PolicyDigest == "" || draft.RBACDigest == "" {
		return errors.New("incomplete audit metadata")
	}
	values := []string{draft.RequestID, draft.Principal, draft.Decision, draft.ObjectID, draft.Purpose, draft.Operation, draft.DeviceID, draft.Outcome, draft.RegistryDigest, draft.PolicyDigest, draft.RBACDigest}
	for _, value := range values {
		if len(value) > 512 || strings.Contains(strings.ToUpper(value), "PRIVATE KEY") || strings.Contains(strings.ToUpper(value), "AGE-SECRET-KEY") {
			return errors.New("unsafe audit metadata")
		}
		for _, character := range value {
			if unicode.IsControl(character) {
				return errors.New("unsafe audit metadata")
			}
		}
	}
	return nil
}

// ShippingState is the observable position of off-host delivery: how many recorded
// events await acknowledgement, the timestamp of the oldest one, and the sequence
// the collector has acknowledged. Configured is false on a journal-only host, where
// a zero backlog would otherwise read as a healthy shipper rather than an absent
// one.
type ShippingState struct {
	Configured      bool
	Backlog         int
	OldestUnshipped time.Time
	ShippedSequence uint64
}

func (recorder *Recorder) ShippingState() ShippingState {
	recorder.mu.Lock()
	shipper := recorder.shipper
	recorder.mu.Unlock()
	if shipper == nil {
		return ShippingState{}
	}
	backlog, oldest, shipped := shipper.snapshot()
	return ShippingState{Configured: true, Backlog: backlog, OldestUnshipped: oldest, ShippedSequence: shipped}
}
