package audit

// THE OFF-HOST COLLECTOR — the collector half of doc/AUDIT-COLLECTOR-RECONCILIATION.md.
//
// The daemon half (ReconcileContinuity) refuses to serve a journal that disagrees with what
// this process committed; until now there was nothing on the other end of the wire to hold
// that commitment. The obligations, from the protocol document:
//
//   - commit each event to durable storage BEFORE the 204 + X-Regalia-Audit-Hash ack;
//   - key committed heads by mTLS client identity plus the X-Regalia-Site header, and keep
//     them as durable as the events themselves;
//   - reject and alarm — never silently drop — a rewritten journal trying to chain onto the
//     committed copy: a replayed sequence with different content, an out-of-order sequence,
//     or an event whose previous_hash is not the committed hash before it.
//
// One place the protocol document and the daemon's own shipper state the rule differently,
// and the shipper is the one that has to keep working: shipper.go promises "the next start
// replays one extra event and the collector dedupes it on the unchanged Idempotency-Key",
// and its run() retries the SAME head event through backoff whenever an ack is lost. So
// "sequence at or below the committed head" splits in two here: a re-delivery whose hash
// EQUALS the committed copy at that sequence is the idempotent case — re-ack, no second
// append, no alarm, because it is the network's ambiguity, not an attack — and only a hash
// that DIFFERS is a rewrite. Rejecting both would wedge every daemon whose ack was lost in
// transit: the shipper would retry the already-committed event forever.
//
// WHAT THIS PROCESS IS NOT. It is not a query interface: no endpoint returns events, only
// positions. The committed events stay in the per-stream files for an operator with disk
// access; exposing them over the same channel that writes them is a decision this issue
// (#427) does not make.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// maxCollectorEventBody mirrors the sink's own bound (Send refuses to marshal an event past
// 64 KiB), so the two ends of the wire agree on what can travel. A refusal here means the
// daemon sent something its own sink would not have — impossible without a modified client,
// which is exactly the shape worth refusing loudly rather than buffering.
const maxCollectorEventBody = 64 << 10

// collectorSitePattern is the charset a site header may carry to become a FILENAME component.
// The header is attacker-reachable input that names a file under the state directory, so
// "validate then use" is not enough — the pattern IS the path-traversal control, and it runs
// before any file is opened. The daemon's own config does not constrain site names, so this
// is the only place the rule exists; a site outside it is refused with a 400, never mangled
// into a safe one, because a mangled name would silently key a second stream.
var collectorSitePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// identityFingerprintHexPattern names the shape of an identity directory: the hex SHA-256 of
// the client certificate's DER, computed by this process. Anything else under streams/ was
// not written by a collector and is refused at load rather than adopted.
var identityFingerprintHexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const (
	streamsDirName   = "streams"
	alarmsFileName   = "alarms.jsonl"
	streamFilePrefix = "site-"
	streamFileSuffix = ".jsonl"
	noSiteFileName   = streamFilePrefix + streamFileSuffix // site-<empty>.jsonl: same identity, no header
)

// Collector is the durable off-host half of the audit protocol. All mutating state lives
// under one mutex: audit rates are low (the shipper is head-of-line by construction), and a
// single critical section makes the commit-ordering argument — snapshot head, verify chain,
// append, fsync, ack — hold without a second lock to get wrong.
type Collector struct {
	stateDir string
	alarms   *os.File

	mu      sync.Mutex
	streams map[string]*collectorStream
}

// collectorStream is one daemon's committed chain: identity (client certificate
// fingerprint) plus site header, the key the protocol document names. The file is the
// journal format the daemon writes — one canonical JSON event per line, hash-chained —
// so an operator can verify a stream with the same tooling that verifies a local journal.
type collectorStream struct {
	identity string
	site     string
	file     *os.File
	// hashes[i] is the committed hash of sequence i+1; verifyEvents' contiguity rule
	// (sequence == index+1 from genesis) is what makes this an index rather than a search.
	hashes []string
	// size is the file offset through which the stream is durably written; a failed append
	// is truncated back to it so a torn line never survives a recoverable write error.
	size int64
}

// collectorAlarm is the durable "alerted" half of reject-and-alarm. It never echoes the
// event body: the reason, the stream, and the claimed sequence and hash are enough to act
// on, and an alarm log is not a place to copy whatever an attacker just sent.
type collectorAlarm struct {
	Timestamp  time.Time `json:"timestamp"`
	Identity   string    `json:"identity"` // client certificate fingerprint, "unauthenticated" when no certificate was presented
	CommonName string    `json:"common_name,omitempty"`
	Site       string    `json:"site,omitempty"`
	Sequence   uint64    `json:"sequence,omitempty"`
	EventHash  string    `json:"event_hash,omitempty"`
	Reason     string    `json:"reason"`
}

// OpenCollector loads (or starts) the collector state under stateDir. Existing streams are
// fully re-verified with the same chain scan the daemon applies to its own journal — the
// collector's whole value is being an honest memory, so a state directory that does not
// verify is a startup failure, not a best-effort load: an operator restores from backup
// (see doc/AUDIT-COLLECTOR-OPERATIONS.md), and the daemons reconcile against whatever the
// restored memory holds.
func OpenCollector(stateDir string) (*Collector, error) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, errors.New("collector state directory is required")
	}
	streamsRoot := filepath.Join(stateDir, streamsDirName)
	if err := os.MkdirAll(streamsRoot, 0o700); err != nil {
		return nil, fmt.Errorf("collector state directory: %w", err)
	}
	alarms, err := os.OpenFile(filepath.Join(stateDir, alarmsFileName), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("collector alarm log: %w", err)
	}
	collector := &Collector{stateDir: stateDir, alarms: alarms, streams: map[string]*collectorStream{}}
	identities, err := os.ReadDir(streamsRoot)
	if err != nil {
		return nil, fmt.Errorf("collector state directory: %w", err)
	}
	for _, identity := range identities {
		if !identity.IsDir() || !identityFingerprintHexPattern.MatchString(identity.Name()) {
			return nil, fmt.Errorf("collector state holds %q, which no collector wrote: refusing to serve state I cannot attribute", filepath.Join(streamsDirName, identity.Name()))
		}
		files, err := os.ReadDir(filepath.Join(streamsRoot, identity.Name()))
		if err != nil {
			return nil, fmt.Errorf("collector state directory: %w", err)
		}
		for _, file := range files {
			if !strings.HasPrefix(file.Name(), streamFilePrefix) || !strings.HasSuffix(file.Name(), streamFileSuffix) {
				return nil, fmt.Errorf("collector state holds %q, which no collector wrote: refusing to serve state I cannot attribute", filepath.Join(streamsDirName, identity.Name(), file.Name()))
			}
			site := strings.TrimSuffix(strings.TrimPrefix(file.Name(), streamFilePrefix), streamFileSuffix)
			if site != "" && !collectorSitePattern.MatchString(site) {
				return nil, fmt.Errorf("collector state holds stream file %q whose site segment is not a site this collector would have written", file.Name())
			}
			if err := collector.loadStream(identity.Name(), site); err != nil {
				return nil, err
			}
		}
	}
	return collector, nil
}

// loadStream verifies one stream file end to end and keeps it open for appends. The scan is
// the SAME verifyEvents the daemon's VerifyIntegrity runs, so "the collector's copy of the
// chain verifies" and "the daemon's journal verifies" are one claim, not two that could
// drift: a content rewrite with the recorded hashes left in place fails here exactly as it
// fails on the host.
func (c *Collector) loadStream(identity, site string) error {
	path := c.streamPath(identity, site)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("collector stream: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("collector stream %s is not a regular file: refusing state I cannot attribute", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("collector stream: %w", err)
	}
	events, err := verifyEvents(bufio.NewReaderSize(file, 64<<10))
	closeErr := file.Close()
	if err != nil {
		return fmt.Errorf("collector stream %s does not verify: %w — restore from backup (see doc/AUDIT-COLLECTOR-OPERATIONS.md)", path, err)
	}
	if closeErr != nil {
		return fmt.Errorf("collector stream: %w", closeErr)
	}
	appendFile, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("collector stream: %w", err)
	}
	hashes := make([]string, len(events))
	for i, event := range events {
		hashes[i] = event.Hash
	}
	c.streams[streamKey(identity, site)] = &collectorStream{
		identity: identity, site: site, file: appendFile, hashes: hashes, size: info.Size(),
	}
	return nil
}

func streamKey(identity, site string) string {
	return identity + "\x1f" + site
}

func (c *Collector) streamPath(identity, site string) string {
	return filepath.Join(c.stateDir, streamsDirName, identity, streamFilePrefix+site+streamFileSuffix)
}

// Close releases the collector's files. The events and heads are already durable; Close
// exists so a restart in the same process (and tests that must observe load-from-disk) can
// drop every in-memory value before reopening.
func (c *Collector) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var firstErr error
	for _, stream := range c.streams {
		if err := stream.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	c.streams = map[string]*collectorStream{}
	if err := c.alarms.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Handler serves the three endpoints the sink talks to. Method dispatch is the mux's
// (Go 1.22 patterns): a GET to /v1/events is a 405, not a handler that forgot to check.
func (c *Collector) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/events", c.handleEvent)
	mux.HandleFunc("GET /v1/stream-position", c.handlePosition)
	mux.HandleFunc("HEAD /v1/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// peerIdentity extracts the client identity from the connection. The mTLS listener is
// configured RequireAndVerifyClientCert, so a present r.TLS peer IS chain-verified; the
// handler still refuses on its own when the identity is absent, because this function is
// also what stands between a misconfigured listener and an unattributed stream — the value
// the whole reconciliation protocol turns on is "a head the host cannot author", and an
// unauthenticated stream is a head anyone can author.
func peerIdentity(request *http.Request) (fingerprint string, commonName string, authenticated bool) {
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 {
		return "", "", false
	}
	certificate := request.TLS.PeerCertificates[0]
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:]), certificate.Subject.CommonName, true
}

// requestSite reads and validates the stream's site component. The error names the header
// because a 400 the operator cannot trace to a header is a support ticket, not a fix.
func requestSite(request *http.Request) (string, error) {
	site := request.Header.Get("X-Regalia-Site")
	if site == "" {
		return "", nil
	}
	if !collectorSitePattern.MatchString(site) {
		return "", fmt.Errorf("the X-Regalia-Site header must match %s", collectorSitePattern.String())
	}
	return site, nil
}

// reject writes the alarm DURABLY FIRST, then answers. The alert must survive a client that
// disconnects the moment it sees the status; an alarm that only lands when the rejection is
// politely received is an alarm an attacker can unsend.
func (c *Collector) reject(request *http.Request, writer http.ResponseWriter, status int, alarm collectorAlarm) {
	alarm.Timestamp = time.Now().UTC()
	if err := c.appendAlarm(alarm); err != nil {
		// Still refuse — but say the alerting itself failed, because "rejected and alarmed"
		// and "rejected silently" are different incidents for whoever reads the logs.
		http.Error(writer, fmt.Sprintf("collector rejected the request and FAILED TO RECORD THE ALARM: %v", err), http.StatusInternalServerError)
		return
	}
	http.Error(writer, alarm.Reason, status)
}

func (c *Collector) appendAlarm(alarm collectorAlarm) error {
	encoded, err := json.Marshal(alarm)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.appendAlarmLocked(encoded)
}

func (c *Collector) appendAlarmLocked(encoded []byte) error {
	if _, err := c.alarms.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return c.alarms.Sync()
}

func (c *Collector) handleEvent(writer http.ResponseWriter, request *http.Request) {
	identity, commonName, authenticated := peerIdentity(request)
	if !authenticated {
		c.reject(request, writer, http.StatusUnauthorized, collectorAlarm{
			Identity: "unauthenticated",
			Reason:   "no client certificate was presented: audit events are accepted only from an identified client",
		})
		return
	}
	site, err := requestSite(request)
	if err != nil {
		c.reject(request, writer, http.StatusBadRequest, collectorAlarm{
			Identity: identity, CommonName: commonName, Site: request.Header.Get("X-Regalia-Site"),
			Reason: "invalid site header: " + err.Error(),
		})
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxCollectorEventBody+1))
	if err != nil {
		c.reject(request, writer, http.StatusBadRequest, collectorAlarm{
			Identity: identity, CommonName: commonName, Site: site,
			Reason: "the event body could not be read",
		})
		return
	}
	if len(body) > maxCollectorEventBody {
		c.reject(request, writer, http.StatusRequestEntityTooLarge, collectorAlarm{
			Identity: identity, CommonName: commonName, Site: site,
			Reason: fmt.Sprintf("the event body exceeds the %d byte audit contract bound", maxCollectorEventBody),
		})
		return
	}
	var event Event
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&event); err != nil {
		c.reject(request, writer, http.StatusBadRequest, collectorAlarm{
			Identity: identity, CommonName: commonName, Site: site,
			Reason: "the event body is not an audit event: " + err.Error(),
		})
		return
	}
	// NO SECOND DOCUMENT — the same rule the sink applies to the position answer and
	// verifyEvents applies to every journal line.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		c.reject(request, writer, http.StatusBadRequest, collectorAlarm{
			Identity: identity, CommonName: commonName, Site: site,
			Reason: "the event body carries data after the audit event",
		})
		return
	}
	alarm := collectorAlarm{Identity: identity, CommonName: commonName, Site: site, Sequence: event.Sequence, EventHash: event.Hash}
	if !auditHashPattern.MatchString(event.Hash) || !auditHashPattern.MatchString(event.PreviousHash) {
		// The genesis previous-hash is the all-zero shape and matches the same pattern.
		c.reject(request, writer, http.StatusBadRequest, alarm.withReason("the event hashes are not sha256:… values"))
		return
	}
	if eventHash(event) != event.Hash {
		c.reject(request, writer, http.StatusConflict, alarm.withReason("the event's hash does not bind its content"))
		return
	}
	// The collector refuses exactly what the journal's own write-time validation refuses
	// (validateDraft): it is the second net for a compromised WRITER, not a place to invent
	// stricter policy — anything stricter than the producer would wedge a legitimate stream,
	// because the shipper retries a refused head forever.
	if err := validateDraft(Draft{
		Timestamp: event.Timestamp, RequestID: event.RequestID, Principal: event.Principal,
		Decision: event.Decision, ObjectID: event.ObjectID, Purpose: event.Purpose,
		Operation: event.Operation, DeviceID: event.DeviceID, Outcome: event.Outcome,
		LatencyMilliseconds: event.LatencyMilliseconds, RegistryDigest: event.RegistryDigest,
		PolicyDigest: event.PolicyDigest, RBACDigest: event.RBACDigest,
	}); err != nil {
		c.reject(request, writer, http.StatusBadRequest, alarm.withReason("the event fails the audit contract's own field validation: "+err.Error()))
		return
	}
	status, ackHash, reason := c.commit(identity, site, event)
	if status != http.StatusNoContent {
		alarm.Reason = reason
		c.reject(request, writer, status, alarm)
		return
	}
	writer.Header().Set("X-Regalia-Audit-Hash", ackHash)
	writer.WriteHeader(http.StatusNoContent)
}

func (alarm collectorAlarm) withReason(reason string) collectorAlarm {
	alarm.Reason = reason
	return alarm
}

// commit is the ordered heart of the collector: everything before this line is stateless
// validation, everything after holds the lock. The branches, from the protocol document
// plus the shipper's idempotency promise:
//
//	sequence == head+1, chaining onto the committed hash  → append, fsync, ack
//	sequence <= head, hash EQUALS the committed copy      → re-ack, no append, no alarm
//	sequence <= head, hash DIFFERS                        → reject + alarm (a rewrite)
//	anything else                                          → reject + alarm (out of order)
//
// The ack is written only after the append is synced — a client that sees 204 may crash and
// lose everything else, because the collector's answer is the durable one.
func (c *Collector) commit(identity, site string, event Event) (int, string, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := streamKey(identity, site)
	stream := c.streams[key]
	if stream == nil {
		created, err := c.createStreamLocked(identity, site)
		if err != nil {
			return http.StatusInternalServerError, "", "the durable commit failed: " + err.Error()
		}
		stream = created
	}
	head := uint64(len(stream.hashes))
	if event.Sequence == head+1 {
		expected := genesisHash
		if head > 0 {
			expected = stream.hashes[head-1]
		}
		if event.PreviousHash != expected {
			return http.StatusConflict, event.Hash, fmt.Sprintf("event %d does not chain onto the committed copy (previous_hash is not the committed hash of event %d): a rewritten journal cannot chain onto what this collector already holds", event.Sequence, head)
		}
		if err := stream.appendLocked(event); err != nil {
			return http.StatusInternalServerError, "", "the durable commit failed: " + err.Error()
		}
		return http.StatusNoContent, event.Hash, ""
	}
	if event.Sequence >= 1 && event.Sequence <= head {
		if stream.hashes[event.Sequence-1] == event.Hash {
			// The idempotent case: the shipper's documented replay after a lost ack, or a
			// restart replaying from a lagging .shipped mark. The committed copy already
			// binds this exact content (the hash is the chain hash), so re-acknowledging
			// commits nothing new and alarms nobody.
			return http.StatusNoContent, event.Hash, ""
		}
		return http.StatusConflict, event.Hash, fmt.Sprintf("event %d replays a committed sequence with content that differs from the committed copy: the journal was rewritten after the off-host copy was made", event.Sequence)
	}
	return http.StatusConflict, event.Hash, fmt.Sprintf("event %d is out of order: the committed head is %d and only the next link is accepted", event.Sequence, head)
}

// createStreamLocked materialises a new stream. The directory entry is synced before the
// stream becomes servable: an ack for event 1 must not depend on a filename the filesystem
// has not yet made durable.
func (c *Collector) createStreamLocked(identity, site string) (*collectorStream, error) {
	dir := filepath.Join(c.stateDir, streamsDirName, identity)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(c.streamPath(identity, site), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if err := syncDir(dir); err != nil {
		file.Close()
		return nil, err
	}
	if err := syncDir(filepath.Join(c.stateDir, streamsDirName)); err != nil {
		file.Close()
		return nil, err
	}
	stream := &collectorStream{identity: identity, site: site, file: file, hashes: nil, size: 0}
	c.streams[streamKey(identity, site)] = stream
	return stream, nil
}

// appendLocked writes one canonical event line and syncs it. A failure mid-write is
// truncated back to the last durable offset so a recoverable error never leaves a torn line
// in the file — a torn line would make the whole stream fail verification at the next load,
// turning a transient error into a permanent startup refusal.
func (stream *collectorStream) appendLocked(event Event) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	line := append(encoded, '\n')
	written, writeErr := stream.file.Write(line)
	if writeErr == nil {
		writeErr = stream.file.Sync()
	}
	if writeErr != nil {
		if truncateErr := stream.file.Truncate(stream.size); truncateErr != nil {
			return fmt.Errorf("%w (and truncating the torn write back failed too: %v)", writeErr, truncateErr)
		}
		if syncErr := stream.file.Sync(); syncErr != nil {
			return fmt.Errorf("%w (and syncing the truncation failed too: %v)", writeErr, syncErr)
		}
		return writeErr
	}
	stream.size += int64(written)
	stream.hashes = append(stream.hashes, event.Hash)
	return nil
}

func (c *Collector) handlePosition(writer http.ResponseWriter, request *http.Request) {
	identity, commonName, authenticated := peerIdentity(request)
	if !authenticated {
		c.reject(request, writer, http.StatusUnauthorized, collectorAlarm{
			Identity: "unauthenticated",
			Reason:   "no client certificate was presented: stream positions are answered only to an identified client",
		})
		return
	}
	site, err := requestSite(request)
	if err != nil {
		c.reject(request, writer, http.StatusBadRequest, collectorAlarm{
			Identity: identity, CommonName: commonName, Site: request.Header.Get("X-Regalia-Site"),
			Reason: "invalid site header: " + err.Error(),
		})
		return
	}
	c.mu.Lock()
	stream := c.streams[streamKey(identity, site)]
	var position struct {
		Sequence uint64 `json:"sequence"`
		Hash     string `json:"hash"`
	}
	if stream != nil && len(stream.hashes) > 0 {
		position.Sequence = uint64(len(stream.hashes))
		position.Hash = stream.hashes[len(stream.hashes)-1]
	}
	c.mu.Unlock()
	// (0, "") is "holds nothing" and any other shape here would be a position the sink's own
	// three-state rule refuses — the collector emits exactly the shapes its client accepts.
	writer.Header().Set("Content-Type", "application/json")
	encoded, _ := json.Marshal(position)
	_, _ = writer.Write(encoded)
}

// syncDir fsyncs a directory so newly created entries in it survive a crash. Data-only syncs
// do not make the NAME durable; an acked event in a file whose directory entry is still in
// memory would vanish on a power cut and read as "the collector forgot" on the next
// reconciliation — the exact incident the protocol refuses to pass as a fresh stream.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
