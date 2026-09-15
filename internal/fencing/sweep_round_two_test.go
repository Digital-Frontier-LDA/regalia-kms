package fencing

// Round two of the mutation sweep of this package (#237). Round one measured one
// direction per operand; this round measured both, against every package that can
// see these symbols (fencing, controlplane, integration, regalia-fence, regalia-kms),
// and each test below closes an operand that survived that wider measurement.
//
// Every test names the operand it detects and the mutation it fails under. The
// mutation form is the one the harness applies: `(false && (X))` deletes an operand
// from an `||` chain, `(true || (X))` deletes one from an `&&` chain — in both cases
// the operand stops contributing while still being referenced, so the package builds.
//
// The dominant reason these survived round one is not that the branches are exotic.
// It is that the existing tests assert `err != nil` and every refusal in this package
// is non-nil: deleting an early operand shifts the refusal to a later guard and the
// assertion still holds. Where that is the case the tests below assert the MESSAGE,
// because the message is the only thing that distinguishes which guard fired.
//
// THE POPULATION AND WHERE IT WENT. 89 sites / 145 operands / 290 operand-directions.
// 59 operands survived in at least one direction; none survived in both. The four
// buckets below sum to those 59.
//
// REACHABLE AND UNTESTED — 25, all closed by this file:
//   gate.go:64[0..4] gate.go:68[0] gate.go:72[0] gate.go:82[0] gate.go:121[2]
//   gate.go:121[5] gate.go:129[0] gate.go:200[2] gate.go:219[1] gate.go:235[1..2]
//   authority.go:224[1] [2] [4] [5]  issue.go:85[0] issue.go:172[0] issue.go:183[0]
//   runner.go:26[0]  standby.go:57[0] standby.go:73[0]
//
// CANNOT BE THE SOLE REFUSER — 13. Masking guard named; three were demonstrated by
// neutralising the pair, the rest by an argument that no isolating input exists:
//   gate.go:115[0]    <- lease.Site != gate.site. readLease returns the ZERO
//                        leaseDocument on all five of its error paths, so Site is ""
//                        whenever err is non-nil, and Open forbids an empty gate.site.
//   gate.go:121[0]    <- the duration bound. An unparsed NotBefore is year 1, so the
//                        window is longer than MaxLeaseDuration for any live expiry.
//   gate.go:121[1]    <- !now.Before(expiresAt). An unparsed ExpiresAt is year 1.
//   gate.go:121[4]    <- now.Before(notBefore) and !now.Before(expiresAt) together:
//                        now < expiresAt <= notBefore <= now has no solution.
//   gate.go:169[0..1] <- ed25519.Verify, which returns false for any signature that
//                        is not SignatureSize bytes, so a short one never verifies.
//   gate.go:195[0]    <- gate.go:200[0]; a nil *os.File's Stat returns ErrInvalid.
//                        (pair-discriminated: the pair panics, neither half alone does)
//   gate.go:200[1]    <- gate.go:200[2] for a device node, which is mode 0666, and
//                        gate.go:195[0] for everything else. No non-regular file both
//                        opens O_WRONLY and carries safe permissions.
//   issue.go:63[2]    <- issue.go:75; a zero epoch never exceeds any previous epoch.
//                        (pair-discriminated)
//   standby.go:49[0]  <- gate.go:82; (*Gate)(nil).Ready answers false on its own.
//                        (pair-discriminated)
//   standby.go:82[0]  <- standby.go:49 and standby.go:63; acquire stores and returns
//                        the same nil whether or not it checks the error.
//   authority.go:125[1] <- authority.go:125[2]; the device-node argument again.
//   authority.go:189[0] <- authority.go:224[0]. The source comment there already
//                        records this, and calls the masking an ordering accident.
//
// UNREACHABLE BY ANY FIXTURE — 4. json.Marshal of a struct of strings, uint64s and
// time.Times returns no error, so the error arm has no input:
//   gate.go:173[0]  issue.go:97[0]  issue.go:107[0]  issue.go:193[0]
//
// CANNOT BE DETERMINISTICALLY PINNED — 17. A fault at the OS boundary with no seam
// in this package: Stat on an already-open descriptor (authority.go:125[0] and
// :209[0], gate.go:144[0] :200[0] :219[0], issue.go:157[0]); io.ReadAll from an open
// regular file (gate.go:148[0], issue.go:168[0]); write, sync, close and chmod
// failures (authority.go:133[0] :136[0], gate.go:203[0] :206[0], issue.go:257[0]
// :261[0] :265[0] :270[0]); and a second os.Open of a path the same call already
// opened successfully (authority.go:172[0]).
//
// The line numbers above are the ones this file was measured against. They are a
// coordinate into that measurement, not a claim that they still address the same
// operand after an edit -- re-derive with kms/tools/guardenum before reusing them.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const roundTwoDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// ----------------------------------------------------------------------------
// gate.go:64 — Open's configuration guard, one field at a time
// ----------------------------------------------------------------------------

// Covers gate.go:64 operands [0] leasePath, [1] statePath, [2] site,
// [3] registryDigest and [4] len(publicKey) — five of the guard's six.
//
// The package already had TestGateGoRefusesInvalidConfiguration and all five
// survived it, for two compounding reasons: its first fixture leaves leasePath AND
// statePath empty at once, so deleting either leaves the other refusing; and its
// later rows assert only `err == nil`, which ErrFenced satisfies. Each row here
// invalidates exactly ONE field and asserts the configuration message, so the only
// way to pass is for that field's operand to be the guard that fired.
//
// Falsifier: `(false && (leasePath == ""))` and the equivalent for each other
// operand. Open then reaches refreshLocked and returns ErrFenced — non-nil, and a
// different message.
func TestOpenNamesAConfigurationFaultRatherThanReportingTheSiteFenced(t *testing.T) {
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	lease := filepath.Join(directory, "lease.json")
	state := filepath.Join(directory, "epochs.jsonl")
	for _, row := range []struct {
		name      string
		leasePath string
		statePath string
		site      string
		digest    string
		key       ed25519.PublicKey
	}{
		{"no lease path", "", state, "sitea", roundTwoDigest, public},
		{"no state path", lease, "", "sitea", roundTwoDigest, public},
		{"no site", lease, state, "", roundTwoDigest, public},
		{"no registry digest", lease, state, "sitea", "", public},
		{"truncated public key", lease, state, "sitea", roundTwoDigest, public[:ed25519.PublicKeySize-1]},
	} {
		t.Run(row.name, func(t *testing.T) {
			gate, err := Open(row.leasePath, row.statePath, row.site, row.digest, row.key, time.Now)
			if gate != nil {
				t.Fatal("a gate was returned for an invalid configuration")
			}
			if err == nil || err.Error() != "invalid fencing configuration" {
				t.Fatalf("err = %v, want the configuration refusal; ErrFenced here means a later "+
					"guard refused and the operator is told the site is fenced when the config is wrong", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Nil receivers reached through the interfaces this package publishes
// ----------------------------------------------------------------------------

type roundTwoRunner struct{ ran bool }

func (runner *roundTwoRunner) Run(ctx context.Context, operation func(context.Context) error) error {
	runner.ran = true
	return operation(ctx)
}

// Covers gate.go:82 (`gate == nil` in Gate.Ready).
//
// Round one classified this §17-unreachable on the grounds that the public path
// cannot construct a nil *Gate. It can, and this is the path: Open returns
// (nil, err) on every failure, FencedRunner holds its gate as a LeaseHolder
// INTERFACE, and a nil *Gate stored in an interface is not a nil interface — so
// `runner.gate == nil` on the line above is false and Ready is called on the nil
// pointer. The guard is what makes that a refusal instead of a segfault in the
// request path.
//
// Falsifier: `(false && (gate == nil))`. Ready reaches gate.mu.Lock() on a nil
// receiver and the test panics rather than failing.
func TestANilGateBehindTheLeaseHolderInterfaceFencesRatherThanPanics(t *testing.T) {
	var gate *Gate // exactly what Open hands back when it refuses
	var holder LeaseHolder = gate
	if holder == nil {
		t.Fatal("a nil *Gate in a LeaseHolder is a nil interface on this toolchain; " +
			"the premise of this test no longer holds and the guard needs a different one")
	}
	inner := &roundTwoRunner{}
	if err := NewRunner(holder, inner).Run(context.Background(), func(context.Context) error {
		t.Fatal("the operation ran behind a nil gate")
		return nil
	}); !errors.Is(err, ErrFenced) {
		t.Fatalf("err = %v, want ErrFenced", err)
	}
	if inner.ran {
		t.Fatal("the inner runner was entered behind a nil gate")
	}
}

// Covers runner.go:26 operand [0] (`runner == nil`).
//
// #344 closed [1] and [2] of this guard (nil gate, nil runner) and left the nil
// receiver. FencedRunner is returned by pointer and satisfies no interface of its
// own here, but Run is exported and callable on a nil *FencedRunner by any holder
// of one — including a caller that ignored a constructor error.
//
// Falsifier: `(false && (runner == nil))`. Run dereferences runner.gate on a nil
// pointer and panics.
func TestANilFencedRunnerFencesRatherThanPanics(t *testing.T) {
	var runner *FencedRunner
	if err := runner.Run(context.Background(), func(context.Context) error {
		t.Fatal("the operation ran on a nil runner")
		return nil
	}); !errors.Is(err, ErrFenced) {
		t.Fatalf("err = %v, want ErrFenced", err)
	}
}

// Covers standby.go:57 (`standby == nil` in Snapshot) and standby.go:73
// (`standby == nil` in acquire, reached through Ready).
//
// Snapshot is exported and is what the metrics path calls; NewStandby returns
// (nil, err) on a bad configuration, so a caller that logs the error and carries on
// holds exactly this value. Both guards make the answer "no gate has ever been
// acquired", which is the honest one.
//
// Falsifier: `(false && (standby == nil))` in either function. Snapshot reaches
// standby.mu.Lock() and acquire reaches the same line, both on a nil receiver.
func TestANilStandbyAnswersNotReadyRatherThanPanicking(t *testing.T) {
	var standby *Standby
	held, epoch, checked, ok := standby.Snapshot()
	if ok {
		t.Fatal("a standby that was never constructed reported a gate")
	}
	if held || epoch != 0 || !checked.IsZero() {
		t.Fatalf("snapshot = %v/%d/%v, want the zero answer", held, epoch, checked)
	}
	if standby.Ready(context.Background()) {
		t.Fatal("a standby that was never constructed reported itself ready")
	}
}

// Covers standby.go:49 operand [0] (`gate != nil`) — as a documented NON-closure.
//
// This operand survives deletion and the test below does not detect it, because
// gate.go:82 refuses the same input one call later: with `gate != nil` deleted,
// Ready calls (*Gate)(nil).Ready(ctx), which returns false on its own nil check.
// The two guards produce one outcome. It is recorded here rather than pinned,
// because a test that passes whether or not the operand exists gates nothing —
// see the pair-neutralisation measurement in the sweep report.

// ----------------------------------------------------------------------------
// gate.go:121 — the temporal window
// ----------------------------------------------------------------------------

func roundTwoGate(t *testing.T, clock *time.Time) (*Gate, string, ed25519.PrivateKey, time.Time) {
	t.Helper()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	*clock = now
	writeLease(t, leasePath, private, "sitea", roundTwoDigest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	gate, err := Open(leasePath, statePath, "sitea", roundTwoDigest, public, func() time.Time { return *clock })
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !gate.Ready(context.Background()) {
		t.Fatal("the fixture gate is not ready")
	}
	return gate, leasePath, private, now
}

// Covers gate.go:121 operand [2] (`now.Before(notBefore)`).
//
// No test in this package presented a lease whose window has not opened yet. The
// operand is the only one of the six that refuses it: the lease is signed, for the
// right site and digest, at an epoch that does not roll back, well within
// MaxLeaseDuration, and not expired — every sibling operand is false.
//
// Falsifier: `(false && (now.Before(notBefore)))`. The site goes active before its
// lease begins, which is the half of the handover window ADR-0001 §8 forbids from
// the other side.
func TestALeaseWhoseWindowHasNotOpenedYetDoesNotMakeTheSiteActive(t *testing.T) {
	var clock time.Time
	gate, leasePath, private, now := roundTwoGate(t, &clock)
	writeLease(t, leasePath, private, "sitea", roundTwoDigest, 1, now.Add(2*time.Minute), now.Add(7*time.Minute))
	if gate.Ready(context.Background()) {
		t.Fatal("a lease that starts in two minutes made the site active now")
	}
}

// Covers gate.go:121 operand [5] (`expiresAt.Sub(notBefore) > MaxLeaseDuration`).
//
// SignGrant enforces the same bound and its enforcement is tested (issue.go:69).
// The gate's INDEPENDENT enforcement was not: nothing presented the daemon a lease
// longer than MaxLeaseDuration. That is the enforcement that matters, because the
// issuer's is advisory to anyone holding the signing key — a lease signed by a
// compromised or patched issuer arrives here and nowhere else.
//
// Falsifier: `(false && (expiresAt.Sub(notBefore) > MaxLeaseDuration))`. A
// thirty-one-minute lease is honoured, and the interval a dead site keeps its
// authority — the floor on how fast another site can be promoted — is no longer
// bounded by this daemon at all.
func TestTheGateRefusesALeaseLongerThanMaxLeaseDurationEvenThoughItIsSigned(t *testing.T) {
	var clock time.Time
	gate, leasePath, private, now := roundTwoGate(t, &clock)
	writeLease(t, leasePath, private, "sitea", roundTwoDigest, 1, now.Add(-time.Minute), now.Add(30*time.Minute))
	if gate.Ready(context.Background()) {
		t.Fatalf("the gate honoured a %s lease; MaxLeaseDuration is %s", 31*time.Minute, MaxLeaseDuration)
	}
}

// ----------------------------------------------------------------------------
// gate.go:68 and gate.go:72 — opening over a journal this package already wrote
// ----------------------------------------------------------------------------

// Covers gate.go:68 operand [0] (`err != nil`) and gate.go:72 (`gate.lastHash == ""`).
//
// Every test in this package opened a gate over a MISSING journal. Restarting a
// daemon that has already advanced an epoch is the normal production path and
// nothing exercised it, which left two operands undetected at once:
//
//   - gate.go:68 [0] deleted makes the condition `!errors.Is(err, os.ErrNotExist)`,
//     which is TRUE when err is nil — so a successful verify returns (nil, nil).
//     Callers that check only err then hold a nil *Gate that answers false to
//     everything, and the nil guard at gate.go:82 makes that silent.
//   - gate.go:72 deleted in the other direction — `(true || (gate.lastHash == ""))` —
//     resets lastHash to genesis on every open, so the next appended record points
//     at nothing and the chain this gate wrote stops verifying.
func TestReopeningAGateOverItsOwnJournalKeepsTheChain(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	writeLease(t, leasePath, private, "sitea", roundTwoDigest, 1, now.Add(-time.Minute), now.Add(time.Minute))
	if _, err := Open(leasePath, statePath, "sitea", roundTwoDigest, public, clock); err != nil {
		t.Fatalf("first open: %v", err)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("the first open wrote no journal, so this test proves nothing: %v", err)
	}

	restarted, err := Open(leasePath, statePath, "sitea", roundTwoDigest, public, clock)
	if err != nil {
		t.Fatalf("reopening over the journal this package wrote: %v", err)
	}
	if restarted == nil {
		t.Fatal("Open returned a nil gate AND a nil error; every caller that checks only err " +
			"now holds a *Gate whose nil guard answers false to every question")
	}
	writeLease(t, leasePath, private, "sitea", roundTwoDigest, 2, now.Add(-time.Minute), now.Add(time.Minute))
	if !restarted.Ready(context.Background()) {
		t.Fatal("the restarted gate refused the next epoch")
	}
	epoch, _, err := VerifyEpochs(statePath)
	if err != nil {
		t.Fatalf("the journal this gate wrote no longer verifies: %v", err)
	}
	if epoch != 2 {
		t.Fatalf("head epoch = %d, want 2", epoch)
	}
}

// Covers gate.go:129 (`err != nil` on appendEpoch's result).
//
// The epoch journal is what stops a former active from resuming after a failover.
// If appending fails, the gate has NOT recorded the epoch it is about to act under,
// so a restart would re-admit the superseded lease. With the operand deleted the
// gate reports itself ready anyway and stores an empty chain head.
//
// Falsifier: `(false && (err != nil))`. Ready returns true while the journal still
// ends at epoch 1.
func TestAGateThatCannotRecordTheEpochDoesNotGoActiveOnIt(t *testing.T) {
	var clock time.Time
	gate, leasePath, private, now := roundTwoGate(t, &clock)
	statePath := filepath.Join(filepath.Dir(leasePath), "epochs.jsonl")
	if err := os.Chmod(statePath, 0o400); err != nil {
		t.Fatal(err)
	}
	if file, err := os.OpenFile(statePath, os.O_WRONLY, 0); err == nil {
		file.Close()
		t.Skip("this filesystem allowed a write to a read-only file, so the failure path was not exercised")
	}
	writeLease(t, leasePath, private, "sitea", roundTwoDigest, 2, now.Add(-time.Minute), now.Add(time.Minute))
	if gate.Ready(context.Background()) {
		t.Fatal("the gate went active on an epoch it could not record")
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		t.Fatal(err)
	}
	epoch, _, err := VerifyEpochs(statePath)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("head epoch = %d, want 1 — the failed append must not have advanced the chain", epoch)
	}
}

// ----------------------------------------------------------------------------
// gate.go:219 / gate.go:235 — the epoch chain read back
// ----------------------------------------------------------------------------

// Covers gate.go:219 operand [1] (`!info.Mode().IsRegular()`).
//
// authority.go:209 carries the identical check and
// TestAnAuthorityJournalPathThatIsADirectoryIsRefused pins it by asserting the message. The gate's copy had no such
// test, and asserting only that an error came back does not detect its deletion:
// the decoder then reads a directory, fails, and the caller is told the chain has an
// INTEGRITY FAILURE. That is the tampered-journal alarm. Anyone woken by it goes
// looking for an attacker instead of a misconfigured path.
//
// Falsifier: `(false && (!info.Mode().IsRegular()))`. The message becomes
// "fencing journal integrity failure".
func TestAnEpochJournalPathThatIsADirectoryIsUnsafeNotTampered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "epochs.jsonl")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := VerifyEpochs(path)
	if err == nil {
		t.Fatal("a directory was accepted as an epoch journal")
	}
	if err.Error() != "unsafe fencing journal" {
		t.Fatalf("err = %q, want %q — an integrity failure names an attacker for what is a "+
			"misconfigured path", err, "unsafe fencing journal")
	}
}

func writeEpochChain(t *testing.T, path string, records ...epochRecord) {
	t.Helper()
	var buffer bytes.Buffer
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		buffer.Write(append(encoded, '\n'))
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sealedEpoch(epoch uint64, previous string) epochRecord {
	record := epochRecord{Epoch: epoch, PreviousHash: previous}
	record.Hash = epochHash(record)
	return record
}

// Covers gate.go:235 operands [1] (`record.Epoch <= maximum`) and
// [2] (`record.PreviousHash != previous`).
//
// Operand [3] — the hash check — is tested, and it is why these two survived: every
// existing fixture tampers with CONTENT, which breaks the hash, so [3] refuses first
// and [1] and [2] are never the guard that fires. The hash here is unkeyed, so
// anyone who can edit the journal can recompute it; the records below are internally
// consistent and only the chain rules refuse them.
//
// Falsifier: `(false && (record.Epoch <= maximum))` admits the replayed epoch, and
// `(false && (record.PreviousHash != previous))` admits the detached record.
func TestAnEpochChainThatRehashesItselfIsStillRefused(t *testing.T) {
	first := sealedEpoch(1, genesisHash)
	for _, row := range []struct {
		name    string
		records []epochRecord
	}{
		{"an epoch replayed at the same number", []epochRecord{first, sealedEpoch(1, first.Hash)}},
		{"a record detached from the one before it", []epochRecord{first, sealedEpoch(2, genesisHash)}},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "epochs.jsonl")
			writeEpochChain(t, path, row.records...)
			for _, record := range row.records {
				if record.Hash != epochHash(record) {
					t.Fatal("this fixture's hashes do not verify, so the hash check refuses it " +
						"and the chain rules are never reached")
				}
			}
			if _, _, err := VerifyEpochs(path); err == nil {
				t.Fatal("accepted")
			} else if err.Error() != "fencing journal integrity failure" {
				t.Fatalf("err = %q, want the integrity failure", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// authority.go:224 — the decision chain read back
// ----------------------------------------------------------------------------

func sealedGrant(kind string, sequence uint64, previous string) GrantRecord {
	record := GrantRecord{Kind: kind, Sequence: sequence, Site: "sitea", Epoch: sequence,
		Operator: "op", NotBefore: time.Unix(0, 0).UTC(), ExpiresAt: time.Unix(60, 0).UTC(),
		PreviousHash: previous}
	record.Hash = grantRecordHash(record)
	return record
}

func writeGrantChain(t *testing.T, path string, records ...GrantRecord) {
	t.Helper()
	var buffer bytes.Buffer
	for _, record := range records {
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		buffer.Write(append(encoded, '\n'))
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Covers authority.go:224 operands [1] (`record.Sequence != sequence+1`),
// [2] (`record.PreviousHash != previous`), and the nested pair [4]/[5]
// (`record.Kind != RecordGranted && record.Kind != RecordRefused`).
//
// Same shape as the epoch chain above and the same reason: the hash check refuses
// every content-tampered fixture first. Note the kind pair is a NESTED conjunction
// inside an `||` chain, so deleting either half disables the whole kind check — one
// unknown-kind fixture detects both operands.
//
// Append refuses an unknown kind on the way in (authority.go:103, tested). Nothing
// checked that the VERIFIER refuses one on the way back out, and the journal is a
// plain file: the writer's refusal binds only records this process wrote.
//
// Falsifier: `(false && (...))` on any of the four; the matching row is accepted.
func TestAnAuthorityChainThatRehashesItselfIsStillRefused(t *testing.T) {
	granted := sealedGrant(RecordGranted, 1, genesisHash)
	for _, row := range []struct {
		name    string
		records []GrantRecord
	}{
		{"a sequence that skips a decision", []GrantRecord{granted, sealedGrant(RecordGranted, 3, granted.Hash)}},
		{"a record detached from the one before it", []GrantRecord{granted, sealedGrant(RecordGranted, 2, genesisHash)}},
		{"a decision that is neither a grant nor a refusal", []GrantRecord{sealedGrant("revoked", 1, genesisHash)}},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authority.jsonl")
			writeGrantChain(t, path, row.records...)
			for _, record := range row.records {
				if record.Hash != grantRecordHash(record) {
					t.Fatal("this fixture's hashes do not verify, so the hash check refuses it " +
						"and the chain rules are never reached")
				}
			}
			_, err := VerifyAuthorityJournal(path)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), "authority journal integrity failure") {
				t.Fatalf("err = %q, want the integrity failure", err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// issue.go — the issuer's memory
// ----------------------------------------------------------------------------

// Covers issue.go:183 operand [0] (`previous.Site == ""`) and issue.go:172
// (`json.Unmarshal` error).
//
// Both survived for the same reason: they refuse the same FILE and the caller only
// learned that something was wrong. Deleting the unmarshal check leaves `previous`
// at its zero value, which issue.go:183 then refuses — with the message for a
// damaged record rather than an unreadable one. Deleting [0] of issue.go:183 lets a
// record with no site through, because its two siblings (epoch, expiry) are set.
//
// Falsifier: `(false && (...))` on either; the message changes, or the record is
// accepted as the authority's memory.
func TestTheIssuerSaysWhichWayItsMemoryIsDamaged(t *testing.T) {
	for _, row := range []struct {
		name     string
		contents string
		want     string
	}{
		{
			"a record that does not parse",
			"{not json",
			"issuer state is unreadable; refusing to issue rather than repeat an epoch",
		},
		{
			"a record that parses but names no site",
			`{"site":"","epoch":3,"expires_at":"2026-09-08T12:00:00Z"}`,
			"issuer state exists but does not record a complete grant (site, epoch and expiry); " +
				"refusing to issue rather than treat a damaged record as a first run",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "issuer.json")
			if err := os.WriteFile(path, []byte(row.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			previous, err := LoadIssuerState(path)
			if err == nil {
				t.Fatalf("accepted as the authority's memory: %+v", previous)
			}
			if err.Error() != row.want {
				t.Fatalf("err = %q,\nwant %q", err, row.want)
			}
		})
	}
}

// Covers issue.go:85 operand [0] (`previous.Site != ""`).
//
// The only ADMISSION operand among this round's closures: the other two operands of
// the guard are what refuse an overlapping handover, and this one is what stops that
// refusal firing when there is no previous grant to overlap WITH. Deleting it makes
// a zero PreviousGrant carrying a future expiry — which is what a partially written
// record looks like — refuse every first issuance, and the message names a site that
// is the empty string.
//
// Falsifier: `(true || (previous.Site != ""))`. SignGrant refuses.
func TestAPreviousGrantWithNoSiteDoesNotBlockTheFirstIssuance(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	grant := Grant{Site: "sitea", Epoch: 1, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: roundTwoDigest}
	previous := PreviousGrant{ExpiresAt: now.Add(time.Hour)}
	lease, err := SignGrant(private, grant, previous)
	if err != nil {
		t.Fatalf("an issuer with no site on record was told it would collide with one: %v", err)
	}
	if len(lease) == 0 {
		t.Fatal("no lease")
	}
}

// Covers gate.go:200 operand [2] (`info.Mode().Perm()&0o077 != 0` in appendEpoch).
//
// verifyEpochJournal carries the identical check and runs first, at Open — which is
// why this copy survived: on the Open path the two are one guard. They are not one
// guard on the path that matters. appendEpoch is reached later, on every epoch
// advance, and re-stats the descriptor it just opened precisely because the mode can
// have changed since startup. A daemon that has been running for a week is the case
// this check exists for, and no test moved the mode after Open.
//
// Falsifier: `(false && (info.Mode().Perm()&0o077 != 0))`. The gate appends its
// epoch chain to a file any local user can rewrite, and reports itself active on it.
func TestTheEpochChainIsNotAppendedToAFileThatBecameWritableAfterStartup(t *testing.T) {
	var clock time.Time
	gate, leasePath, private, now := roundTwoGate(t, &clock)
	statePath := filepath.Join(filepath.Dir(leasePath), "epochs.jsonl")
	if err := os.Chmod(statePath, 0o666); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 == 0 {
		t.Skipf("this filesystem kept the mode at %04o, so the loosened-permission path "+
			"was not exercised", info.Mode().Perm())
	}
	writeLease(t, leasePath, private, "sitea", roundTwoDigest, 2, now.Add(-time.Minute), now.Add(time.Minute))
	if gate.Ready(context.Background()) {
		t.Fatal("the gate advanced its epoch into a world-writable journal")
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		t.Fatal(err)
	}
	epoch, _, err := VerifyEpochs(statePath)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if epoch != 1 {
		t.Fatalf("head epoch = %d, want 1", epoch)
	}
}
