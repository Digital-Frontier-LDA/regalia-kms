package audit

// SHIPPING A NODE'S TRAILS (#278).
//
// The node's services and the revocation authority write their trails in Python
// (deploy/baremetal/trails.py): one JSON object a line, chained by "seq" and "prev", the SHA-256 of
// the previous line's exact bytes. This file ships such a trail to the collector, one audit Event a
// line, on a stream of its own (site "<site>.<trail>"), so the trail gets what the daemon's journal
// has: an off-host copy its host cannot rewrite, and a collector that alarms when anyone tries.
//
// NO LOCAL STATE. The shipper keeps no mark of what it shipped. Line n of the file is event n of
// the stream, and the mapping from a line to its event is a pure function of the file (no clock, no
// randomness). So at every pass the shipper rebuilds the events, asks the collector for its
// committed head (N, hash), and goes on only if its own event N has that hash. That is the check a
// chain cannot make on itself: a file cut short, or rewritten under what was shipped, verifies as a
// good chain; it does not reproduce the collector's head. The collector holds the anchor, which is
// the one record on the host's side an attacker on the host cannot move.
//
// A MISMATCH IS A TAMPER SIGNAL, NOT A RETRY. ShipTrail raises an alarm at the collector (the
// file being behind is invisible to the collector's own commit checks: a prefix replays as the
// idempotent case) and returns ErrTrailTampered; the shipper stops for that trail and stays
// stopped. Starting it again repeats the same comparison, so it cannot quietly resume: it ships
// again only once the file again holds what the collector committed.
//
// THE MAPPING IS FROZEN. Changing how a line becomes an event changes every hash, and every stream
// already shipped would read as rewritten. A change needs a new TrailFormat and a new stream.
//
// What it does not do:
//   - ship a final line without its newline: the writer may be in the middle of it (or it was torn
//     by a crash, and the next append terminates it and chains over it; it ships then);
//   - check that a line is in Python's canonical form: an edited line is caught by the next line's
//     prev, and the last line is bound by the collector's copy once it ships;
//   - follow rotation. Trails do not rotate yet; when they do, the first line of a new file chains to
//     the last line of the old (seq and prev go on), the shipper is handed the files in order, and a
//     file is removed only once the collector's head is past its last line (#278).

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// TrailFormat names the line-to-event mapping below; it is in every event's detail.
const TrailFormat = "regalia.trail/v2"

// maxTrailContent bounds the line content copied into an event's detail; a longer line ships its
// hash and length only.
const maxTrailContent = 40 << 10

// trailNotJudged fills the three digests validateDraft requires: a trail line was not decided by
// the daemon's registry, policy or RBAC, and the field says so instead of borrowing a digest.
const trailNotJudged = "none:trail-line"

var (
	// ErrTrailTampered: the file no longer holds what the collector committed, or its own chain is
	// broken. The shipper stops for the trail; an operator acts.
	ErrTrailTampered = errors.New("the trail does not hold what the collector committed")

	trailNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	trailSeqPattern  = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	trailAtPattern   = regexp.MustCompile(`^[0-9]{1,12}$`)
)

// TrailSink is what ShipTrail needs of the collector; HTTPSink is one.
type TrailSink interface {
	Send(context.Context, Event) error
	CommittedHead(context.Context, string) (uint64, string, error)
	ReportAlarm(context.Context, uint64, string, string) error
}

// trailDetail is an event's Detail: which line of which trail it is, and the line itself. LineSHA256 is
// of the line's exact bytes, newline included (what the next line's prev names). Line carries those
// bytes, less the newline, as a JSON string (which decodes back to exactly them), or LineBase64 when
// they are not UTF-8; neither when Withheld says why not. So the collector checks that the content
// is the line the hash names (validateTrailDetail): a shipper cannot ship a line's hash with other
// content, only withhold it. Line is data, control characters included: whatever displays it escapes it.
type trailDetail struct {
	Format     string `json:"format"`
	Trail      string `json:"trail"`
	Kind       string `json:"kind"`
	LineSHA256 string `json:"line_sha256"`
	LineBytes  int    `json:"line_bytes"`
	Line       string `json:"line,omitempty"`
	LineBase64 string `json:"line_base64,omitempty"`
	Withheld   string `json:"withheld,omitempty"`
}

// TrailEvents checks the trail's chain as trails.verify does and returns one event a complete line,
// chained from genesis. A break is ErrTrailTampered.
func TrailEvents(name string, data []byte) ([]Event, error) {
	return TrailEventsFrom(name, TrailStart{}, data)
}

// TrailStart is where data begins in a trail whose older files were pruned (trails.py's prune marker,
// <trail>.pruned): the last pruned line's seq and its number in the stream (Sequence), the event it
// shipped as, its line's SHA-256, and that event's time. The zero value is the start of the trail.
// Every event after it depends on exactly these, so a rebuild from a marker is the rebuild from the
// first line, byte for byte.
type TrailStart struct {
	Seq        uint64 `json:"seq"`
	Sequence   uint64 `json:"sequence"`
	EventHash  string `json:"event_hash"`
	LineSHA256 string `json:"line_sha256"`
	Timestamp  int64  `json:"timestamp"`
}

func (start TrailStart) valid() bool {
	if start == (TrailStart{}) {
		return true
	}
	_, err := hex.DecodeString(start.LineSHA256)
	return start.Sequence > 0 && start.Seq <= start.Sequence && auditHashPattern.MatchString(start.EventHash) &&
		len(start.LineSHA256) == 64 && err == nil && strings.ToLower(start.LineSHA256) == start.LineSHA256 && start.Timestamp >= 0
}

// TrailEventsFrom is TrailEvents for data that continues after start.
func TrailEventsFrom(name string, start TrailStart, data []byte) ([]Event, error) {
	walker, err := NewTrailWalker(name, start)
	if err != nil {
		return nil, err
	}
	var events []Event
	complete := data[:bytes.LastIndexByte(data, '\n')+1]
	for len(complete) > 0 {
		end := bytes.IndexByte(complete, '\n') + 1
		event, err := walker.Next(complete[:end])
		if err != nil {
			return nil, err
		}
		events = append(events, event)
		complete = complete[end:]
	}
	return events, nil
}

// TrailWalker maps a trail one line at a time: TrailEventsFrom's state between lines, so a trail of any
// size is shipped without holding it (#288).
type TrailWalker struct {
	name   string
	at     TrailStart // the last line mapped: what a marker after it would carry
	chainN uint64     // the seq the next chained line must carry
	chain  bool
}

// NewTrailWalker starts after start (the zero value: the first line of the trail).
func NewTrailWalker(name string, start TrailStart) (*TrailWalker, error) {
	if !trailNamePattern.MatchString(name) {
		return nil, fmt.Errorf("%q is not a trail name", name)
	}
	if !start.valid() {
		return nil, fmt.Errorf("%w: the prune marker is not one trails.py writes", ErrTrailTampered)
	}
	return &TrailWalker{name: name, at: start, chainN: start.Seq + 1, chain: start.Seq > 0}, nil
}

// Last is the walker's position: where a prune marker after the last line mapped would start.
func (w *TrailWalker) Last() TrailStart { return w.at }

// Next maps one complete line, its newline included.
func (w *TrailWalker) Next(raw []byte) (Event, error) {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return Event{}, errors.New("a trail line ends with its newline")
	}
	body := raw[:len(raw)-1]
	number := w.at.Sequence + 1
	previousHash, previousTime := genesisHash, time.Unix(0, 0).UTC()
	if w.at.Sequence > 0 {
		previousHash, previousTime = w.at.EventHash, time.Unix(w.at.Timestamp, 0).UTC()
	}
	var fields map[string]json.RawMessage
	kind := "torn"
	if json.Valid(body) {
		kind = "legacy"
		if json.Unmarshal(body, &fields) == nil && fields != nil {
			if seq, ok := fields["seq"]; ok {
				kind = "chained"
				if string(seq) != strconv.FormatUint(w.chainN, 10) || !trailSeqPattern.Match(seq) {
					return Event{}, fmt.Errorf("%w: line %d carries seq %s where %d was expected", ErrTrailTampered, number, seq, w.chainN)
				}
				var prev string
				if json.Unmarshal(fields["prev"], &prev) != nil || prev != w.at.LineSHA256 {
					return Event{}, fmt.Errorf("%w: line %d's prev is not the SHA-256 of the line before it", ErrTrailTampered, number)
				}
			}
		}
		if kind == "legacy" && w.chain {
			return Event{}, fmt.Errorf("%w: line %d has no seq after the chain began", ErrTrailTampered, number)
		}
	}
	event := trailEvent(w.name, number, raw, kind, fields, previousTime)
	event.PreviousHash = previousHash
	event.Hash = eventHash(event)
	sum := sha256.Sum256(raw)
	if kind == "chained" {
		w.at.Seq, w.chainN, w.chain = w.chainN, w.chainN+1, true
	}
	w.at.Sequence, w.at.EventHash, w.at.LineSHA256, w.at.Timestamp = number, event.Hash, hex.EncodeToString(sum[:]), event.Timestamp.Unix()
	return event, nil
}

// maxTrailLine bounds one line read from a trail: trails.py writes at most 64 KiB, and a legacy line
// longer than this is not one of its.
const maxTrailLine = 1 << 20

// Feed maps the lines read from r, calling each for every event in order. An archive (whole) must end
// with a newline; the current file's last line without one is left for the next pass (it may be
// being written).
func (w *TrailWalker) Feed(r io.Reader, whole bool, each func(Event) error) error {
	reader := bufio.NewReaderSize(r, 64<<10)
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			if len(line) > maxTrailLine {
				return fmt.Errorf("a trail line is longer than %d bytes", maxTrailLine)
			}
			continue
		}
		if err == io.EOF {
			if len(line) > 0 && whole {
				return fmt.Errorf("%w: an archive does not end with a whole line: not one rotation made", ErrTrailTampered)
			}
			return nil
		}
		if err != nil {
			return err
		}
		event, mapErr := w.Next(line)
		if mapErr != nil {
			return mapErr
		}
		if err := each(event); err != nil {
			return err
		}
		line = line[:0]
	}
}

// trailEvent maps one line. Every value comes from the line, its number and the trail's name; a
// line that does not say when it was written takes the time of the line before it.
func trailEvent(name string, number uint64, raw []byte, kind string, fields map[string]json.RawMessage, previousTime time.Time) Event {
	sum := sha256.Sum256(raw)
	lineHash := hex.EncodeToString(sum[:])
	text := func(key, fallback string) string {
		var value string
		if json.Unmarshal(fields[key], &value) != nil || !trailValueSafe(value) {
			return fallback
		}
		return value
	}
	timestamp := previousTime
	if at := fields["at"]; trailAtPattern.Match(at) {
		seconds, _ := strconv.ParseInt(string(at), 10, 64)
		timestamp = time.Unix(seconds, 0).UTC()
	}
	operation, outcome := "trail-"+kind+"-line", "RECORDED"
	if kind != "torn" {
		operation, outcome = text("event", operation), text("outcome", outcome)
	}
	decision := "allow"
	switch strings.ToUpper(outcome) {
	case "DENY", "DENIED", "REFUSED":
		decision = "deny"
	}
	id := sha256.Sum256([]byte(TrailFormat + "\x00" + name + "\x00" + strconv.FormatUint(number, 10) + "\x00" + lineHash))
	h := hex.EncodeToString(id[:16])
	return Event{
		Sequence:       number,
		Timestamp:      timestamp,
		RequestID:      h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32],
		Principal:      "trail:" + name,
		Decision:       decision,
		Operation:      operation,
		Outcome:        outcome,
		RegistryDigest: trailNotJudged,
		PolicyDigest:   trailNotJudged,
		RBACDigest:     trailNotJudged,
		Detail:         trailDetailOf(name, kind, raw, lineHash),
	}
}

func trailDetailOf(name, kind string, raw []byte, lineHash string) json.RawMessage {
	body := raw[:len(raw)-1]
	detail := trailDetail{Format: TrailFormat, Trail: name, Kind: kind, LineSHA256: lineHash, LineBytes: len(raw)}
	upper := strings.ToUpper(string(body))
	switch {
	case strings.Contains(upper, "PRIVATE KEY") || strings.Contains(upper, "AGE-SECRET-KEY"):
		detail.Withheld = "the line carries a secret key marker"
	case len(body) > maxTrailContent:
		detail.Withheld = "the line is longer than an event may carry"
	case utf8.Valid(body):
		detail.Line = string(body) // the line's exact text: a JSON string decodes back to these bytes
	default:
		detail.LineBase64 = base64.StdEncoding.EncodeToString(body)
	}
	encoded, _ := json.Marshal(detail) // strings and numbers only: it cannot fail
	return encoded
}

// trailValueSafe is validateDraft's rule for one value, so a line never makes an event the
// collector refuses (a refused head would be retried for ever).
func trailValueSafe(value string) bool {
	upper := strings.ToUpper(value)
	return value != "" && len(value) <= 512 && strings.IndexFunc(value, unicode.IsControl) < 0 &&
		!strings.Contains(upper, "PRIVATE KEY") && !strings.Contains(upper, "AGE-SECRET-KEY")
}

// ShipTrail ships what the collector has not committed yet, after checking the file still holds
// what it has. It returns how many lines are now committed and how many complete lines the file
// holds. ErrTrailTampered (with an alarm raised at the collector) means stop; any other error is
// the collector being unreachable or refusing, and the next pass tries again.
func ShipTrail(ctx context.Context, sink TrailSink, site, name string, data []byte) (uint64, uint64, error) {
	return ShipTrailFrom(ctx, sink, site, name, TrailStart{}, data)
}

// ShipTrailFrom is ShipTrail for a trail whose older files were pruned: data continues after start.
func ShipTrailFrom(ctx context.Context, sink TrailSink, site, name string, start TrailStart, data []byte) (uint64, uint64, error) {
	return ShipTrailLines(ctx, sink, site, name, start, func(walker *TrailWalker, each func(Event) error) error {
		return walker.Feed(bytes.NewReader(data), false, each)
	})
}

// ShipTrailLines is the shipping pass over a trail read line by line: walk feeds the walker the
// trail's files in order. It asks the collector for its head first, checks the line at the head as
// it passes it, and sends each line after it as it is read, so a trail of any size ships without
// being held (#288). The collector must hold at least the pruned lines, and the line it holds at its
// head must be the one walked there, or start itself.
func ShipTrailLines(ctx context.Context, sink TrailSink, site, name string, start TrailStart, walk func(*TrailWalker, func(Event) error) error) (uint64, uint64, error) {
	walker, err := NewTrailWalker(name, start)
	if err != nil {
		return 0, 0, err
	}
	head, hash, err := sink.CommittedHead(ctx, site)
	if err != nil {
		return 0, start.Sequence, err
	}
	switch {
	case head < start.Sequence:
		return head, start.Sequence, raiseTrailAlarm(ctx, sink, head, hash, fmt.Sprintf("the trail %s was pruned through line %d and the collector committed only %d: lines were removed before they shipped", name, start.Sequence, head))
	case head == start.Sequence && head > 0 && start.EventHash != hash:
		return head, start.Sequence, raiseTrailAlarm(ctx, sink, head, hash, fmt.Sprintf("the trail %s's prune marker names line %d as an event the collector did not commit there", name, head))
	}
	committed, total := head, start.Sequence
	var sendErr, rewritten error
	walkErr := walk(walker, func(event Event) error {
		total = event.Sequence
		switch {
		case event.Sequence < head:
			return nil
		case event.Sequence == head:
			if event.Hash != hash {
				rewritten = fmt.Errorf("line %d of the trail %s is not the line the collector committed: the file was rewritten", head, name)
				return rewritten
			}
			return nil
		}
		if err := sink.Send(ctx, event); err != nil {
			sendErr = err
			return err
		}
		committed = event.Sequence
		return nil
	})
	switch {
	case rewritten != nil:
		return head, total, raiseTrailAlarm(ctx, sink, head, hash, rewritten.Error())
	case sendErr != nil:
		return committed, total, sendErr
	case walkErr != nil && errors.Is(walkErr, ErrTrailTampered):
		return committed, total, raiseTrailAlarm(ctx, sink, head, hash, walkErr.Error())
	case walkErr != nil:
		return committed, total, walkErr
	case head > total:
		return head, total, raiseTrailAlarm(ctx, sink, head, hash, fmt.Sprintf("the trail %s holds %d complete lines and the collector committed %d: the file was cut short or replaced", name, total, head))
	}
	return committed, total, nil
}

func raiseTrailAlarm(ctx context.Context, sink TrailSink, head uint64, hash, reason string) error {
	if len(reason) > 512 {
		reason = reason[:512]
	}
	if err := sink.ReportAlarm(ctx, head, hash, reason); err != nil {
		return fmt.Errorf("%w: %s (and the alarm could not be raised at the collector: %v)", ErrTrailTampered, reason, err)
	}
	return fmt.Errorf("%w: %s (alarm raised at the collector)", ErrTrailTampered, reason)
}

// maxDetail bounds Event.Detail so a whole event stays inside the sink's and the collector's
// 64 KiB, with room for every other field at its own 512 byte bound.
const maxDetail = 48 << 10

// validateTrailDetail holds a trail event's detail (trail.go) to the line it names: the content
// decodes to bytes whose SHA-256, newline included, is line_sha256, and whose length is line_bytes;
// or it is withheld, and carries none. A detail of an older trail format is refused.
func validateTrailDetail(detail json.RawMessage) error {
	var head struct {
		Format string `json:"format"`
	}
	if detail == nil || json.Unmarshal(detail, &head) != nil || !strings.HasPrefix(head.Format, "regalia.trail/") {
		return nil
	}
	if head.Format != TrailFormat {
		return fmt.Errorf("a trail line in format %q: this collector takes %s", head.Format, TrailFormat)
	}
	var line struct {
		LineSHA256 string  `json:"line_sha256"`
		LineBytes  int     `json:"line_bytes"`
		Line       *string `json:"line"`
		LineBase64 *string `json:"line_base64"`
		Withheld   string  `json:"withheld"`
	}
	if err := json.Unmarshal(detail, &line); err != nil || len(line.LineSHA256) != 64 {
		return errors.New("a trail detail without its line's hash")
	}
	if line.Withheld != "" {
		if line.Line != nil || line.LineBase64 != nil {
			return errors.New("a trail detail both withholds its line and carries it")
		}
		return nil
	}
	var content []byte
	switch {
	case line.Line != nil && line.LineBase64 != nil:
		return errors.New("a trail detail carries its line twice")
	case line.Line != nil:
		content = []byte(*line.Line)
	case line.LineBase64 != nil:
		decoded, err := base64.StdEncoding.DecodeString(*line.LineBase64)
		if err != nil {
			return errors.New("a trail detail's line_base64 is not base64")
		}
		content = decoded
	}
	sum := sha256.Sum256(append(content, '\n'))
	if hex.EncodeToString(sum[:]) != line.LineSHA256 || len(content)+1 != line.LineBytes {
		return errors.New("a trail detail's line is not the line its hash names")
	}
	return nil
}

// validateDetail is validateDraft's rule for Event.Detail (the one-line field in audit.go, where a doc comment would move
// every line the #237 ledger cites). Detail is omitted when absent, so every event written before it
// existed marshals, and hashes, exactly as it did: absent, or one bounded JSON object
// carrying no private key marker. The collector applies it as it applies validateDraft.
func validateDetail(detail json.RawMessage) error {
	if detail == nil {
		return nil
	}
	if len(detail) > maxDetail {
		return errors.New("audit detail too large")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(detail, &object); err != nil || object == nil {
		return errors.New("audit detail is not a JSON object")
	}
	if upper := strings.ToUpper(string(detail)); strings.Contains(upper, "PRIVATE KEY") || strings.Contains(upper, "AGE-SECRET-KEY") {
		return errors.New("unsafe audit detail")
	}
	return validateTrailDetail(detail)
}
