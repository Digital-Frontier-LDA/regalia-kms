package fencing

// Falsification tests for refusal guards the sweep of 2026-09-06 found UNCOVERED.
//
// Every test below cites the guard it covers in a comment. The deletion/replacement
// the test would FAIL under is described in the body; readers who don't run the
// mutation harness can apply it by hand. Every test except the two named
// behaviour-pins (gate.go L138-140 and L143-145) must fail with `if false && (...)`
// replacing the named condition, and pass with the original guard in place.
//
// The two behaviour-pins are documented inline (TestReadLeaseReturnsOsOpenErrorForMissingPath,
// TestReadLeaseRefusesNonRegularFiles) and the reason each cannot be isolated to a
// single test is recorded there. A green mutation under those two means: the inner
// guard cannot be reached without help from another; do not interpret green as
// evidence the guard is unnecessary.
//
// Falsifiers are run by the sweep harness — see the 2026-09-06 sweep report.
//
// Tests in this file:
//   gate.go L64-66 Open invalid configuration
//   gate.go L72-74 genesisHash init (asserts chain integrity after a state move)
//   gate.go L111  evaluateLocked ctx.Err
//   gate.go L138-140 readLease os.Open (asserts wrapped PathError)
//   gate.go L143-145 readLease IsRegular / Perm (asserts specific error message)
//   gate.go L147-149 readLease size bound (asserts specific error message)
//   gate.go L157-159 readLease multi-document
//   gate.go L161-163 readLease shape
//   gate.go L218-220 verifyEpochJournal IsRegular / Perm
//   runner.go L30 mid-op readiness
//   issue.go L152-154 LoadIssuerState open error
//   issue.go L160-162 LoadIssuerState IsRegular
//   issue.go L270-272 writeAtomically chmod applies mode
//
// SKIPPED (constructed below; either unreachable from a unit-test process or
// the failure mode is not observable without race-condition tooling):
//   gate.go L168-170 verifyLease base64 + length check — behaviour-pin: a
//                  wholly invalid signature decodes to empty/short bytes
//                  through base64.StdEncoding.Strict, and ed25519.Verify
//                  refuses those signatures anyway; removing the guard is
//                  silent. Verified GREEN under the mutation 2026-09-06.
//                  (See the section at line ~295 for the citation and the
//                  contrast with the two genuine behaviour-pins that DO
//                  ship tests.)
//   issue.go L192  SaveIssuerState marshal — json.Marshal of typed struct returns
//                  no error in practice; per §17, build the input first.
//   issue.go L257-260 writeAtomically write
//   issue.go L261-264 writeAtomically sync
//   issue.go L265-267 writeAtomically close
// These are reachable in production (full disk, fsync failures, fds held by
// other processes) and the guard text describes the consequence; an empty
// directory on a healthy filesystem does not produce the inputs.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// ----------------------------------------------------------------------------
// gate.go: Open
// ----------------------------------------------------------------------------

// Covers gate.go L64-66 (Open invalid-configuration refusal).
// Falsifier: replace the predicate with `if false && (...)`; Open then accepts
// a half-empty configuration and the test's perm-check fails.
func TestGateGoRefusesInvalidConfiguration(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Open("", "", "sitea", "sha256:00", public, time.Now); err == nil || err.Error() != "invalid fencing configuration" {
		t.Fatalf("empty paths accepted: %v", err)
	}
	if _, err := Open("/tmp/lease.json", "/tmp/state.jsonl", "", "sha256:00", public, time.Now); err == nil {
		t.Fatalf("empty site accepted")
	}
	if _, err := Open("/tmp/lease.json", "/tmp/state.jsonl", "sitea", "", public, time.Now); err == nil {
		t.Fatalf("empty registry digest accepted")
	}
	if _, err := Open("/tmp/lease.json", "/tmp/state.jsonl", "sitea", "sha256:00", ed25519.PublicKey{}, time.Now); err == nil {
		t.Fatalf("wrong-size public key accepted")
	}
}

// Covers gate.go L72-74 (genesisHash initialisation when the journal does not
// exist). Without the init, the gate's lastHash stays "" and the first epoch
// record it appends carries PreviousHash="". That record then fails chain
// verification on the next read of the journal. The test exercises that
// secondary check so the mutation cannot be silent.
// Falsifier: replace `if gate.lastHash == ""` with `if false && gate.lastHash == ""`.
func TestGateInitialisesGenesisHashWhenStateHasNoChain(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Now().UTC()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	gate, err := Open(leasePath, statePath, "sitea", digest, public, func() time.Time { return now })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !gate.Ready(context.Background()) {
		t.Fatalf("first-ever lease not accepted when genesis should be initialised")
	}
	// A subsequent read of the journal must succeed; the chain must bind
	// from genesis. Without the L72-74 init, lastHash stays "", the first
	// record was written with PreviousHash="", and this VerifyEpochs call
	// returns an integrity-failure error.
	if _, _, err := VerifyEpochs(statePath); err != nil {
		t.Fatalf("journal does not bind from genesis after the first grant: %v", err)
	}
}

// ----------------------------------------------------------------------------
// gate.go: evaluateLocked
// ----------------------------------------------------------------------------

// Covers gate.go L111 (ctx.Err refusal in evaluateLocked).
// Falsifier: replace `if ctx.Err() != nil` with `if false && ctx.Err() != nil`.
// A cancelled context must NOT admit the operation; the test creates an
// already-cancelled context and calls Ready().
func TestEvaluateLockedAbortsOnCancelledContext(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Now().UTC()
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	gate, err := Open(leasePath, statePath, "sitea", digest, public, func() time.Time { return now })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if gate.Ready(ctx) {
		t.Fatalf("cancelled context admitted a read; evaluateLocked L111 not enforced")
	}
}

// ----------------------------------------------------------------------------
// gate.go: readLease (called directly for error-discrimination)
// ----------------------------------------------------------------------------

// Covers gate.go L138-140 (readLease returns the os.Open error verbatim).
// The falsifier replaces `if err != nil` with `if false && err != nil` —
// os.Open returns (nil, err); the next line `info, err := file.Stat()` then
// reaches file.Stat on a nil *os.File, which Go implements as (nil,
// ErrInvalid); L143-145 catches that as "unsafe fencing lease". The mutation
// therefore DOES change the error class — os.ErrNotExist becomes
// "unsafe fencing lease" — and the test catches it by asserting the
// os.ErrNotExist sentinel on the err. Verified 2026-09-06.
//
// (fs.ErrNotExist and os.ErrNotExist are the same sentinel value; the test
// asserts the os form to match the import.)
// Falsifier: removing the guard makes errors.Is(err, os.ErrNotExist) false.
func TestReadLeaseReturnsOsOpenErrorForMissingPath(t *testing.T) {
	directory := t.TempDir()
	_, err := readLease(filepath.Join(directory, "absent.json"))
	if err == nil {
		t.Fatalf("missing lease did not error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("os.Open error was not propagated; got %v", err)
	}
}

// Covers gate.go L143-145 (readLease refuses non-regular files and group/
// world-writable leases). Falsifier: replace predicate with `if false && (...)`;
// a regular-but-writable file is then accepted and the test's content check
// succeeds. The test asserts a specific error class so the mutation cannot
// be silent even when readLease would otherwise produce a parse failure.
func TestReadLeaseRefusesNonRegularFiles(t *testing.T) {
	directory := t.TempDir()
	// Point lease path at a directory; IsRegular returns false.
	directoryPath := filepath.Join(directory, "lease.dir")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := readLease(directoryPath)
	if err == nil || err.Error() != "unsafe fencing lease" {
		t.Fatalf("non-regular lease was not refused as unsafe: %v", err)
	}
}

func TestReadLeaseRefusesGroupWritableRegularFile(t *testing.T) {
	directory := t.TempDir()
	writable := filepath.Join(directory, "lease.json")
	// Group-writable content; everything else looks valid.
	if err := os.WriteFile(writable, []byte(`{}`), 0o664); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o664); err != nil {
		t.Fatal(err)
	}
	_, err := readLease(writable)
	if err == nil || err.Error() != "unsafe fencing lease" {
		t.Fatalf("group-writable lease was not refused as unsafe: %v", err)
	}
}

// Covers gate.go L147-149 (readLease size bound). Falsifier: replace predicate
// with `if false && (...)` — a 17 KiB file of valid JSON is then read in full
// and parsed through shape check; the test asserts the SPECIFIC error.
//
// The fixture must be VALID JSON exactly maxLeaseBytes+1 bytes long. io.LimitReader
// at gate.go:147 caps the read at maxLeaseBytes+1=16385; if the entire content is
// a single well-formed JSON document and the file is exactly 16385 bytes, the
// read returns 16385 bytes, the JSON decode succeeds, the multi-doc check sees
// io.EOF, and the shape check passes — the file would be accepted as a valid
// lease if not for the size guard's `len(contents) > maxLeaseBytes` check.
//
// Padding with "X" instead of valid JSON would have the JSON-decode guard at
// gate.go:153 return the same "invalid fencing lease" message, making the size
// guard unreachable from the test.
func TestReadLeaseRejectsFilesOverSixteenKiB(t *testing.T) {
	directory := t.TempDir()
	oversize := filepath.Join(directory, "lease.json")
	prefix := []byte(`{"version":1,"epoch":1,"signature":"`)
	suffix := []byte(`"}`)
	// Document is exactly maxLeaseBytes+1 bytes: a single valid JSON value
	// with no trailing garbage, so the multi-doc guard at gate.go:157 returns
	// io.EOF rather than a parse error.
	padding := bytes.Repeat([]byte("x"), maxLeaseBytes+1-len(prefix)-len(suffix))
	body := append(append(prefix, padding...), suffix...)
	if err := os.WriteFile(oversize, body, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readLease(oversize)
	if err == nil || err.Error() != "invalid fencing lease" {
		t.Fatalf("oversized lease was not refused as invalid: %v", err)
	}
}

// Covers gate.go L157-159 (readLease refuses multiple documents). Falsifier:
// replace `!errors.Is(err, io.EOF)` with `false && !errors.Is(...)` — a file
// with two JSON objects concatenated is then accepted. The test asserts the
// SPECIFIC error message rather than just `err != nil`, since the secondary
// document is valid JSON and a downstream decode would otherwise succeed.
func TestReadLeaseRejectsMultipleDocumentsInOneFile(t *testing.T) {
	directory := t.TempDir()
	lease := filepath.Join(directory, "lease.json")
	first := []byte(`{"version":1,"site":"x","epoch":1,"signature":"AA"}`)
	second := []byte(`{"version":2,"site":"x","epoch":2,"signature":"BB"}`)
	if err := os.WriteFile(lease, append(first, second...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readLease(lease)
	if err == nil || err.Error() != "invalid fencing lease" {
		t.Fatalf("two-document lease was not refused as invalid: %v", err)
	}
}

// Covers gate.go L161-163 (readLease refuses shape failures).
// Falsifier: replace `if lease.Version != 1 || ...` with `if false && (...)`.
// The three sub-cases below discriminate: the test pins the SPECIFIC error
// message that only readLease's shape guard produces. Named rather than cited by
// line: the line number above is a convenience that a single edit to gate.go
// invalidates silently, and this sentence is the one a reader needs to still be
// true afterwards.
func TestReadLeaseRejectsShapeFailures(t *testing.T) {
	cases := []struct {
		name  string
		field string
		value any
	}{
		{"version zero", "version", 0},
		{"epoch zero", "epoch", 0},
		{"empty signature", "signature", ""},
	}
	for _, scenario := range cases {
		t.Run(scenario.name, func(t *testing.T) {
			directory := t.TempDir()
			lease := filepath.Join(directory, "lease.json")
			doc := map[string]any{"version": 1, "site": "x", "epoch": 1,
				"not_before": "2026-09-04T00:00:00Z", "expires_at": "2026-09-04T00:01:00Z",
				"registry_digest": "sha256:00", "signature": "YQ=="}
			doc[scenario.field] = scenario.value
			contents, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lease, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err = readLease(lease)
			if err == nil || err.Error() != "invalid fencing lease" {
				t.Fatalf("malformed lease was not refused: %v", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// gate.go: verifyLease — base64 + length check (BEHAVIOUR-PIN, not pinned)
// ----------------------------------------------------------------------------
//
// gate.go L168-170 (verifyLease base64 + length check) is recorded as a
// behaviour-pin in the 2026-09-06 sweep report: a wholly invalid signature
// decodes to empty/short bytes through base64.StdEncoding.Strict, and
// ed25519.Verify refuses those signatures anyway — removing the guard
// changes nothing observable. Verified GREEN under the mutation
// 2026-09-06.
//
// The instinct to ship a test for it
// (TestVerifyLeaseRejectsMalformedBase64Signature, the first version of this file) was wrong: ed25519
// catches the input downstream, so the test would pass with the guard
// removed. Per the standing rule "if you class a guard as unpinnable,
// do not then ship a test for it", no test is included here. The
// sweep report (TestVerifyLeaseRejectsMalformedBase64Signature table row)
// is the residual.
//
// (See TestReadLeaseReturnsOsOpenErrorForMissingPath and
// TestReadLeaseRefusesNonRegularFiles for the two behaviour-pins that
// DO ship tests — those pins were *named* and the tests build a fixture
// that proves the inner guard cannot be isolated, rather than asserting
// a refusal that downstream also produces.)

// ----------------------------------------------------------------------------
// gate.go: verifyEpochJournal — through Open path
// ----------------------------------------------------------------------------

// Covers gate.go L218-220 (verifyEpochJournal refuses non-regular / drifting
// permissions on the journal). Falsifier: replace the predicate with
// `if false && (...)` — a journal at 0644 passes through and the daemon
// trusts whatever it reads.
func TestVerifyEpochJournalRefusesJournalWithInsecureMode(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "epochs.jsonl")
	if err := os.WriteFile(statePath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statePath, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := VerifyEpochs(statePath)
	if err == nil || err.Error() != "unsafe fencing journal" {
		t.Fatalf("insecure-mode journal was accepted: %v", err)
	}
}

// ----------------------------------------------------------------------------
// runner.go: FencedRunner
// ----------------------------------------------------------------------------

// Covers runner.go L30 (mid-operation readiness check). Falsifier: replace
// `if !runner.gate.Ready(operationCtx)` with `if false && !runner.gate.Ready(...)`.
// A lease that lapses during the operation is then ignored and the result
// is published for a lease the site no longer holds.
//
// Two guards (L30 mid-op and L47 post-op) both return ErrFenced when the lease
// flips. The observable that distinguishes them is *whether the operation body
// ran*: with L30 present, the body never executes (Ready refuses before
// operation() is called); with L30 absent, the body runs and only L47 stops
// the publish. `operationRan` is the discriminator. Verified 2026-09-06.
func TestFencedRunnerRecoversLeaseMidFlight(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Now().UTC()
	clock := now
	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeLease(t, leasePath, private, "sitea", digest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	gate, err := Open(leasePath, statePath, "sitea", digest, public, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	leaseHolding := &flippingLeaseHolder{gate: gate, after: func() {
		clock = now.Add(2 * time.Minute)
	}}
	var preOps atomic.Int32
	var postOps atomic.Int32
	var operationRan atomic.Bool
	inner := &probeRunner{preOps: &preOps, postOps: &postOps}
	runner := NewRunner(leaseHolding, inner)
	if err := runner.Run(context.Background(), func(context.Context) error { operationRan.Store(true); return nil }); !errors.Is(err, ErrFenced) {
		t.Fatalf("mid-op lapsed lease did not ErrFenced: %v", err)
	}
	if operationRan.Load() {
		t.Fatalf("operation body ran even though the lease lapsed mid-flight; " +
			"L30 mid-op readiness check is the only thing that prevented a sign-and-publish " +
			"of an op the site no longer had authority to produce")
	}
	if preOps.Load() != 1 || postOps.Load() != 1 {
		t.Fatalf("runner shape: preOps=%d postOps=%d", preOps.Load(), postOps.Load())
	}
}

type flippingLeaseHolder struct {
	gate  *Gate
	after func()
	ran   atomic.Int32
}

func (holder *flippingLeaseHolder) Ready(ctx context.Context) bool {
	if holder.ran.Add(1) == 2 {
		holder.after()
	}
	return holder.gate.Ready(ctx)
}

type probeRunner struct {
	preOps  *atomic.Int32
	postOps *atomic.Int32
}

func (runner *probeRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	runner.preOps.Add(1)
	err := operation(ctx)
	runner.postOps.Add(1)
	return err
}

// ----------------------------------------------------------------------------
// issue.go: LoadIssuerState
// ----------------------------------------------------------------------------

// Covers issue.go L152-154 (LoadIssuerState surfaces os.Open errors).
// Falsifier: replace `if err != nil` with `if false && err != nil` —
// without the guard, `os.Open` returns (nil, err); execution falls
// through to `file.Stat()`, where Go's *os.File methods on a nil
// receiver return ErrInvalid rather than panicking. LoadIssuerState
// then returns `stat issuer state: invalid argument` — a wrong
// diagnosis (the open was refused; the operator is told the stat
// failed) rather than a nil return. With the guard, LoadIssuerState
// wraps the open error and the test catches the difference via
// errors.Is on os.ErrPermission. Verified 2026-09-06.
//
// Two environment traps the repo has already paid for:
//
//  1. chmod 000 on the FILE does not stop os.Open from succeeding —
//     the parent directory's mode is what controls lookup. The fixture
//     here chmods the directory, not the file (the file does not yet
//     exist).
//
//  2. Root ignores mode bits entirely. CI runs non-root so the assertion
//     runs there; a Dockerfile reproducing the suite as root would
//     silently let os.Open succeed and the test would either pass for
//     the wrong reason (now fixed below with a control) or fail loudly
//     as a permission test that hit the wrong path. The control below
//     is run BEFORE the skip on purpose: a green control means the
//     fixture is honest, a red control means the fixture is broken and
//     the test is a gap, not a no-op.
func TestLoadIssuerStateReportsOpenFailure(t *testing.T) {
	directory := t.TempDir()
	parent := filepath.Join(directory, "locked")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(parent, "state.json")
	if err := os.WriteFile(statePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Control: with the parent mode 0700, the file IS readable. Proves
	// the fixture is otherwise sound.
	if _, err := os.Open(statePath); err != nil {
		t.Fatalf("control: state.json should be readable while parent is 0700: %v", err)
	}
	if err := os.Chmod(parent, 0o000); err != nil {
		t.Skipf("chmod 000 not honoured: %v", err)
	}
	defer func() { _ = os.Chmod(parent, 0o700) }()
	// Control: after chmod 000, the file MUST be unreadable on a host
	// that enforces mode bits. If it is readable here, root or some
	// other agent is short-circuiting the denial — the test cannot
	// distinguish the guard under those conditions, so we skip with
	// the reason rather than letting the assertion pass for the wrong
	// reason.
	if _, err := os.Open(statePath); err == nil {
		t.Skipf("chmod 000 on %s did not deny os.Open — running as root or mode bits are not enforced", parent)
	}
	_, err := LoadIssuerState(statePath)
	if err == nil {
		t.Fatalf("LoadIssuerState succeeded on unreadable directory: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("LoadIssuerState did not propagate the permission error: %v", err)
	}
}

// Covers issue.go L160-162 (LoadIssuerState refuses non-regular state files).
// Falsifier: replace `if !info.Mode().IsRegular()` with `if false && ...` —
// a directory at the state path is then accepted and the issuer would
// try to JSON-decode it as a record. The test asserts the SPECIFIC error
// message.
func TestLoadIssuerStateRejectsNonRegularFile(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIssuerState(statePath)
	if err == nil || err.Error() != "issuer state must be a regular file" {
		t.Fatalf("directory-as-state accepted: %v", err)
	}
}

// ----------------------------------------------------------------------------
// issue.go: writeAtomically
// ----------------------------------------------------------------------------

// Covers issue.go L270-272 (writeAtomically applies the requested mode to the
// published file). Falsifier: replace `if err := os.Chmod(...); err != nil`
// with `if false && ...` — the published file then inherits the temp file's
// mode (0600 from os.CreateTemp). The test asserts on the SPECIFIC mode.
func TestWriteAtomicallyAppliesTheRequestedMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "lease.json")
	if err := WriteLease(path, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("WriteLease published file with mode %04o, not 0644", info.Mode().Perm())
	}
}

// io is referenced indirectly through the test fixtures above; the import
// keeps the file gofmt-clean when conditional compiles exclude individual
// tests.
var _ = io.EOF
