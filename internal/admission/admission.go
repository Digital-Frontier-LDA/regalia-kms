// Package admission makes the daemon serve only while this node holds a runtime trust lease
// (regalia-kms#74).
//
// The lease rules live in deploy/baremetal/lease.py and are not written a second time here. A
// root service on the host keeps the lease (deploy/baremetal/admission.py) and writes one narrow
// fact, the admission file; this package reads it. That is the kubelet shape: the agent renews,
// the server reads the outcome.
//
//	{"schema": "regalia.admission/v3", "node_id": ..., "session_id": ..., "boot_id": ...,
//	 "epoch": ..., "manifest_digest": ..., "hsm_serials": ..., "lease_issued_at": ...,
//	 "requested_boottime_ms": ..., "cluster_id": ..., "state_epoch": ..., "state_revision": ...,
//	 "session_key": ..., "serve_until_boottime_ms": ..., "reason": ...}
//
// THE LEASE'S OPERATIONAL STATE (v3; ADR-0002 D32). cluster_id, state_epoch, state_revision and
// session_key are the held lease's own (lease.py v2): what the issuer vouched this node's etcd watch
// had applied, and the session key of the daemon start the lease was asked for. They reach the
// daemon's state gate (internal/opstate.StateGate) as its LeaseFacts; this package only carries them.
//
// NO WALL CLOCK. serve_until_boottime_ms is in this host's CLOCK_BOOTTIME, which runs through
// suspend and cannot be set. The node is admitted while the daemon's own CLOCK_BOOTTIME is below
// it. boot_id is the kernel's boot ID: those numbers mean nothing in another boot, so a file
// carrying another boot's ID is refused whatever its times say.
//
// THE TOKENS ARE THE MANIFEST'S (regalia-kms#72, G1). hsm_serials is this node's entry in the manifest
// the lease service checked under, space-separated: every hardware token it holds. A key is served
// from a token only if its serial is listed (Admits), so the root replacing a token in the manifest
// takes the old one out of service without a change to this daemon's configuration.
//
// NOT ADMITTED IS THE ANSWER TO EVERYTHING ELSE. A file that is missing, unreadable, not root's,
// writable by anyone else, malformed, for another node or boot session, expired, or claiming more
// than one lease lifetime ahead: not admitted. There is no "not configured" answer once a Gate
// exists; whether one must exist is the configuration's to say (runtime_admission).
//
// COOPERATIVE. Root on the node can write the file. What bounds a compromised node is outside it:
// peers refuse its unlocks, verifiers refuse its lease, the fencing authority decides who signs.
package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	Schema = "regalia.admission/v3"
	// MaxReasonBytes is admission.ADMISSION_REASON_LIMIT: the writer cuts its reason there, so a longer
	// limit here would never be used and a shorter one would hide the reason behind "too long".
	MaxReasonBytes = 1024
	// MaxSerials is admission.MAX_SERIALS: the hardware tokens one node may list.
	MaxSerials = 16
	// MaxAheadMilliseconds is one lease lifetime (lease.MAX_LIFETIME, 30 s; ADR-0002 D32). The writer
	// holds a margin back from it, so an admission reaching further ahead was not derived from a lease.
	MaxAheadMilliseconds = 30_000
	maxFileBytes         = 4096
	bootIDPath           = "/proc/sys/kernel/random/boot_id"
	processStatPath      = "/proc/self/stat"
)

// ErrNotAdmitted is what an operation gets while the node holds no runtime lease.
var ErrNotAdmitted = errors.New("KMS node is not admitted: it holds no runtime lease")

var (
	nodeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	hex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex16Pattern  = regexp.MustCompile(`^[0-9a-f]{16}$`)
	bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)
	serialPattern = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
	fields        = []string{"schema", "node_id", "session_id", "boot_id", "epoch", "manifest_digest", "hsm_serials", "lease_issued_at",
		"requested_boottime_ms", "cluster_id", "state_epoch", "state_revision", "session_key", "serve_until_boottime_ms", "reason"}
)

// Document is the admission file, validated.
type Document struct {
	NodeID               string
	SessionID            string
	BootID               string
	Epoch                uint64
	ManifestDigest       string
	HSMSerials           []string
	LeaseIssuedAt        time.Time
	RequestedBoottimeMs  int64
	State                LeaseState
	ServeUntilBoottimeMs int64
	Reason               string
}

// LeaseState is the held lease's operational state (v3): zeros when nothing is served.
type LeaseState struct {
	// ClusterID is the etcd cluster's ID, 16 lowercase hex.
	ClusterID     string
	StateEpoch    uint64
	StateRevision int64
	// SessionKey is the daemon's session key the lease was asked for, 64 lowercase hex.
	SessionKey string
}

// Status is what the gate last decided.
type Status struct {
	Admitted bool
	// Reason says why not; empty when admitted.
	Reason string
	// Epoch is the manifest epoch the file names, 0 when the file could not be read.
	Epoch uint64
	// RequestedBoottimeMs is when the node asked for the lease it holds, 0 when not admitted.
	RequestedBoottimeMs int64
	// HSMSerials are this node's hardware tokens in the manifest, empty when not admitted.
	HSMSerials []string
	// State is the held lease's operational state, zero when not admitted.
	State LeaseState
}

// Options configure a Gate. Boottime, BootID and OwnerUID have production defaults; tests set them.
type Options struct {
	Path        string
	NodeID      string
	SessionPath string
	// OwnerUID is the lease service's user (regalia-kms#191): the admission file and its directory
	// must be that user's or root's. Zero is root.
	OwnerUID uint32
	// SessionOwnerUID is who writes the boot session: root (the unlock client, or
	// regalia-boot-session.service), the default. Only tests set it. The lease service's user is
	// never trusted for this file: it would then choose the session its own admission is checked against.
	SessionOwnerUID uint32
	// Boottime returns CLOCK_BOOTTIME in milliseconds.
	Boottime func() (int64, error)
	// BootID returns the kernel's boot ID.
	BootID func() (string, error)
	// OnTransition is called each time the answer changes, and for the first answer.
	OnTransition func(Status)
}

// Gate answers whether this node may serve right now.
type Gate struct {
	options Options
	bootID  string

	mutex   sync.Mutex
	decided bool
	last    Status
}

// Open prepares a gate. It does not need the admission file to exist: until the lease service
// has written it the node is simply not admitted.
func Open(options Options) (*Gate, error) {
	if options.Path == "" || options.SessionPath == "" {
		return nil, errors.New("admission needs the admission file path and the boot session path")
	}
	if !filepath.IsAbs(options.Path) || !filepath.IsAbs(options.SessionPath) {
		return nil, errors.New("admission paths must be absolute")
	}
	// readTrusted checks the cleaned directory and opens the path as given: the two must be the same
	// path, or a ".." after a link would open a file outside the directories that were checked.
	if filepath.Clean(options.Path) != options.Path || filepath.Clean(options.SessionPath) != options.SessionPath {
		return nil, errors.New("admission paths must be clean, with no \"..\", \".\" or repeated \"/\"")
	}
	if !nodeIDPattern.MatchString(options.NodeID) {
		return nil, errors.New("admission needs this node's ID as the membership manifest spells it")
	}
	if options.Boottime == nil {
		options.Boottime = Boottime
	}
	if options.BootID == nil {
		options.BootID = KernelBootID
	}
	bootID, err := options.BootID()
	if err != nil {
		return nil, fmt.Errorf("read the kernel boot ID: %w", err)
	}
	if !bootIDPattern.MatchString(bootID) {
		return nil, errors.New("the kernel boot ID is not a UUID")
	}
	return &Gate{options: options, bootID: bootID}, nil
}

// Boottime is CLOCK_BOOTTIME in milliseconds.
func Boottime() (int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return ts.Sec*1000 + ts.Nsec/1_000_000, nil
}

// ProcessStart is when this process started, in CLOCK_BOOTTIME milliseconds, as the kernel records it
// in /proc/self/stat. The lease service reads the same number for the daemon's PID
// (deploy/baremetal/admission.py, daemon_started), so "a lease asked for after the daemon started"
// means the same moment on both sides, and the service can ask for one at once instead of at its
// next renewal. The kernel counts it in clock ticks, rounded down; this returns the tick AFTER, so it
// is never before the true start (and up to 10 ms after it): a lease asked for inside the tick the
// process started in, before the process existed, does not count as asked for since.
func ProcessStart() (int64, error) {
	contents, err := os.ReadFile(processStatPath)
	if err != nil {
		return 0, err
	}
	return parseProcessStart(string(contents))
}

// userHZ is the unit of the times in /proc/<pid>/stat. It is 100 on every Linux architecture Go
// supports (the kernel's USER_HZ, not its internal tick rate); deploy/baremetal/admission.py asks
// sysconf and refuses any other value.
const userHZ = 100

// parseProcessStart takes field 22 (starttime) of a /proc/<pid>/stat line. The command name, field
// 2, is in parentheses and may itself contain spaces and parentheses, so the fields are counted
// from the LAST ")".
func parseProcessStart(stat string) (int64, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, errors.New("the process stat line has no command name")
	}
	fields := strings.Fields(stat[end+1:])
	const startTime = 22 - 3 // fields[0] is field 3, the state
	if len(fields) <= startTime {
		return 0, errors.New("the process stat line is too short")
	}
	ticks, err := strconv.ParseInt(fields[startTime], 10, 64)
	if err != nil || ticks <= 0 || ticks > math.MaxInt64/1000 {
		return 0, errors.New("the process start time is not a positive number of ticks")
	}
	return (ticks + 1) * 1000 / userHZ, nil
}

// KernelBootID reads /proc/sys/kernel/random/boot_id.
func KernelBootID() (string, error) {
	contents, err := os.ReadFile(bootIDPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(contents)), nil
}

// Ready reports whether the node is admitted now. A nil gate is not admitted.
func (gate *Gate) Ready(ctx context.Context) bool {
	return gate.Check(ctx).Admitted
}

// Check evaluates the admission file and returns the decision.
func (gate *Gate) Check(ctx context.Context) Status {
	if gate == nil {
		return Status{Reason: "admission is not wired"}
	}
	status := gate.evaluate(ctx)
	gate.mutex.Lock()
	changed := !gate.decided || gate.last.Admitted != status.Admitted
	gate.decided, gate.last = true, status
	hook := gate.options.OnTransition
	gate.mutex.Unlock()
	if changed && hook != nil {
		hook(status)
	}
	return status
}

// Admits reports whether a key may be served from the token with this serial: the node is admitted
// under a lease it asked for after `boottimeMs`, and the manifest lists the serial among this node's
// hardware tokens (regalia-kms#72, PoC 12.4 and G1). One reading of the file answers both.
func (gate *Gate) Admits(ctx context.Context, serial string, boottimeMs int64) bool {
	status := gate.Check(ctx)
	if !status.Admitted || status.RequestedBoottimeMs <= boottimeMs || serial == "" {
		return false
	}
	for _, listed := range status.HSMSerials {
		if listed == serial {
			return true
		}
	}
	return false
}

// RequestedAfter reports whether the node is admitted under a lease it asked for after
// `boottimeMs`. A lease is issued after it is asked for, so this shows a peer vouched after that
// moment without comparing two machines' clocks (regalia-kms#72, PoC 12.4).
func (gate *Gate) RequestedAfter(ctx context.Context, boottimeMs int64) bool {
	status := gate.Check(ctx)
	return status.Admitted && status.RequestedBoottimeMs > boottimeMs
}

func (gate *Gate) evaluate(ctx context.Context) Status {
	if err := ctx.Err(); err != nil {
		return Status{Reason: "the request was cancelled"}
	}
	document, err := gate.read()
	if err != nil {
		return Status{Reason: err.Error()}
	}
	refuse := func(reason string) Status { return Status{Reason: reason, Epoch: document.Epoch} }
	if document.NodeID != gate.options.NodeID {
		return refuse("the admission file is for another node")
	}
	if document.BootID != gate.bootID {
		return refuse("the admission file is from another boot")
	}
	session, err := readTrusted(gate.options.SessionPath, gate.options.SessionOwnerUID)
	if err != nil {
		return refuse("the boot session: " + err.Error())
	}
	if value := strings.TrimSpace(string(session)); !hex64Pattern.MatchString(value) || value != document.SessionID {
		return refuse("the admission file is for another boot session")
	}
	now, err := gate.options.Boottime()
	if err != nil {
		return refuse("CLOCK_BOOTTIME cannot be read")
	}
	if document.ServeUntilBoottimeMs == 0 {
		reason := document.Reason
		if reason == "" {
			reason = "the lease service reports no admission"
		}
		return refuse("not admitted by the lease service: " + reason)
	}
	if now >= document.ServeUntilBoottimeMs {
		return refuse("the admission ran out")
	}
	if document.ServeUntilBoottimeMs-now > MaxAheadMilliseconds {
		return refuse("the admission reaches further ahead than one lease lifetime")
	}
	if document.RequestedBoottimeMs > now {
		return refuse("the admission names a request made in the future")
	}
	return Status{Admitted: true, Epoch: document.Epoch, RequestedBoottimeMs: document.RequestedBoottimeMs, HSMSerials: document.HSMSerials,
		State: document.State}
}

func (gate *Gate) read() (Document, error) {
	contents, err := readTrusted(gate.options.Path, gate.options.OwnerUID)
	if err != nil {
		return Document{}, fmt.Errorf("the admission file: %w", err)
	}
	return Parse(contents)
}

// readTrusted reads a small file that only its writer (ownerUID) or root could have written: opened
// without following a link, regular, owned by one of the two, not writable by group or others, in a
// directory with the same owner and the same restriction. Above that directory nobody else may be able
// to swap it: every ancestor is a real directory owned by one of the two, and one that group or others
// can write must be sticky (as /tmp is) with the next component down owned by one of the two, so
// nobody else can rename it away. The file's own checks run on the opened descriptor, so the file that
// is checked is the file that is read.
func readTrusted(path string, ownerUID uint32) ([]byte, error) {
	trusted := func(uid uint32) bool { return uid == ownerUID || uid == 0 }
	var directory unix.Stat_t
	if err := unix.Lstat(filepath.Dir(path), &directory); err != nil {
		return nil, errors.New("its directory cannot be examined")
	}
	if directory.Mode&unix.S_IFMT != unix.S_IFDIR || !trusted(directory.Uid) || directory.Mode&0o022 != 0 {
		return nil, errors.New("its directory is not one only its owner or root can write")
	}
	if err := ancestorsTrusted(filepath.Dir(path), directory.Uid, trusted); err != nil {
		return nil, err
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("it cannot be opened")
	}
	file := os.NewFile(uintptr(descriptor), filepath.Base(path))
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		return nil, errors.New("it cannot be examined")
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.New("it is not a regular file")
	}
	if !trusted(stat.Uid) || stat.Mode&0o022 != 0 {
		return nil, errors.New("it is not a file only its owner or root can write")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return nil, errors.New("it cannot be read")
	}
	if len(contents) > maxFileBytes {
		return nil, errors.New("it is oversized")
	}
	return contents, nil
}

// ancestorsTrusted walks from directory's parent up to "/". childUID is the owner of the component
// below the one examined.
func ancestorsTrusted(directory string, childUID uint32, trusted func(uint32) bool) error {
	for current := directory; current != "/"; {
		parent := filepath.Dir(current)
		var stat unix.Stat_t
		if err := unix.Lstat(parent, &stat); err != nil {
			return fmt.Errorf("%s, above it, cannot be examined", parent)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || !trusted(stat.Uid) {
			return fmt.Errorf("%s, above it, is not a directory of its owner or root", parent)
		}
		if stat.Mode&0o022 != 0 && (stat.Mode&unix.S_ISVTX == 0 || !trusted(childUID)) {
			return fmt.Errorf("%s, above it, lets someone else replace what is below it", parent)
		}
		current, childUID = parent, stat.Uid
	}
	return nil
}

// Parse validates the bytes of an admission file: one JSON object with exactly the schema's
// fields, each once, each of its type and shape.
func Parse(contents []byte) (Document, error) {
	values, err := object(contents)
	if err != nil {
		return Document{}, err
	}
	if len(values) != len(fields) {
		return Document{}, errors.New("the admission file does not have exactly its fields")
	}
	for _, name := range fields {
		if _, present := values[name]; !present {
			return Document{}, fmt.Errorf("the admission file lacks %s", name)
		}
	}
	text := func(name string) (string, error) {
		var value string
		if err := json.Unmarshal(values[name], &value); err != nil {
			return "", fmt.Errorf("the admission file's %s is not a string", name)
		}
		return value, nil
	}
	count := func(name string) (int64, error) {
		raw := string(values[name])
		if !regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`).MatchString(raw) {
			return 0, fmt.Errorf("the admission file's %s is not a whole number", name)
		}
		var value int64
		if err := json.Unmarshal(values[name], &value); err != nil {
			return 0, fmt.Errorf("the admission file's %s is not a whole number", name)
		}
		return value, nil
	}
	var document Document
	schema, err := text("schema")
	if err != nil {
		return Document{}, err
	}
	if schema != Schema {
		return Document{}, errors.New("the admission file is of another schema")
	}
	if document.NodeID, err = text("node_id"); err != nil {
		return Document{}, err
	}
	if !nodeIDPattern.MatchString(document.NodeID) {
		return Document{}, errors.New("the admission file's node_id is not a node ID")
	}
	if document.SessionID, err = text("session_id"); err != nil {
		return Document{}, err
	}
	if !hex64Pattern.MatchString(document.SessionID) {
		return Document{}, errors.New("the admission file's session_id is not 64 lowercase hex")
	}
	if document.BootID, err = text("boot_id"); err != nil {
		return Document{}, err
	}
	if !bootIDPattern.MatchString(document.BootID) {
		return Document{}, errors.New("the admission file's boot_id is not a UUID")
	}
	epoch, err := count("epoch")
	if err != nil {
		return Document{}, err
	}
	document.Epoch = uint64(epoch)
	if document.ManifestDigest, err = text("manifest_digest"); err != nil {
		return Document{}, err
	}
	if !hex64Pattern.MatchString(document.ManifestDigest) {
		return Document{}, errors.New("the admission file's manifest_digest is not 64 lowercase hex")
	}
	serials, err := text("hsm_serials")
	if err != nil {
		return Document{}, err
	}
	if serials != "" {
		document.HSMSerials = strings.Split(serials, " ")
	}
	seen := map[string]bool{}
	for _, serial := range document.HSMSerials {
		if !serialPattern.MatchString(serial) || seen[serial] {
			return Document{}, errors.New("the admission file's hsm_serials is not distinct serials, one space apart")
		}
		seen[serial] = true
	}
	if len(document.HSMSerials) > MaxSerials {
		return Document{}, fmt.Errorf("the admission file lists more than %d hardware tokens", MaxSerials)
	}
	issued, err := text("lease_issued_at")
	if err != nil {
		return Document{}, err
	}
	if document.LeaseIssuedAt, err = time.Parse("2006-01-02T15:04:05Z", issued); err != nil {
		return Document{}, errors.New("the admission file's lease_issued_at is not UTC, YYYY-MM-DDTHH:MM:SSZ")
	}
	if document.RequestedBoottimeMs, err = count("requested_boottime_ms"); err != nil {
		return Document{}, err
	}
	if document.State.ClusterID, err = text("cluster_id"); err != nil {
		return Document{}, err
	}
	if !hex16Pattern.MatchString(document.State.ClusterID) {
		return Document{}, errors.New("the admission file's cluster_id is not 16 lowercase hex")
	}
	stateEpoch, err := count("state_epoch")
	if err != nil {
		return Document{}, err
	}
	document.State.StateEpoch = uint64(stateEpoch)
	if document.State.StateRevision, err = count("state_revision"); err != nil {
		return Document{}, err
	}
	if document.State.SessionKey, err = text("session_key"); err != nil {
		return Document{}, err
	}
	if !hex64Pattern.MatchString(document.State.SessionKey) {
		return Document{}, errors.New("the admission file's session_key is not 64 lowercase hex")
	}
	if document.ServeUntilBoottimeMs, err = count("serve_until_boottime_ms"); err != nil {
		return Document{}, err
	}
	if document.Reason, err = text("reason"); err != nil {
		return Document{}, err
	}
	if len(document.Reason) > MaxReasonBytes {
		return Document{}, errors.New("the admission file's reason is too long")
	}
	for _, character := range document.Reason {
		if character < ' ' || character > '~' {
			return Document{}, errors.New("the admission file's reason is not printable ASCII")
		}
	}
	return document, nil
}

// object reads one flat JSON object, refusing a repeated key, anything nested and anything after
// it. encoding/json keeps the last of two equal keys without a word, which would let one reader
// see a different document from another.
func object(contents []byte) (map[string]json.RawMessage, error) {
	malformed := errors.New("the admission file is not one flat JSON object")
	decoder := json.NewDecoder(bytes.NewReader(contents))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, malformed
	}
	values := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, malformed
		}
		name, isName := token.(string)
		if !isName {
			return nil, malformed
		}
		if _, repeated := values[name]; repeated {
			return nil, fmt.Errorf("the admission file repeats %s", name)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, malformed
		}
		if trimmed := bytes.TrimSpace(value); len(trimmed) == 0 || trimmed[0] == '{' || trimmed[0] == '[' {
			return nil, malformed
		}
		values[name] = value
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return nil, malformed
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, malformed
	}
	return values, nil
}

// Holder is anything that can say whether the node is admitted.
type Holder interface {
	Ready(context.Context) bool
}

// Runner is the executor a Runner wraps.
type Runner interface {
	Run(context.Context, func(context.Context) error) error
}

// AdmittedRunner runs an operation only while the node is admitted.
type AdmittedRunner struct {
	gate   Holder
	runner Runner
}

// NewRunner wraps runner so that every operation needs admission.
func NewRunner(gate Holder, runner Runner) *AdmittedRunner {
	return &AdmittedRunner{gate: gate, runner: runner}
}

// Run checks admission three times, as internal/fencing checks the lease: before the operation is
// queued, when it starts, and when it has finished. The last is what stops a signature the token
// made after the lease lapsed from being handed back: the coordinator discards the output of a
// run that returns an error.
func (runner *AdmittedRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	if runner == nil || runner.gate == nil || runner.runner == nil || !runner.gate.Ready(ctx) {
		return ErrNotAdmitted
	}
	return runner.runner.Run(ctx, func(operationCtx context.Context) error {
		if !runner.gate.Ready(operationCtx) {
			return ErrNotAdmitted
		}
		if err := operation(operationCtx); err != nil {
			return err
		}
		if !runner.gate.Ready(operationCtx) {
			return ErrNotAdmitted
		}
		return nil
	})
}
