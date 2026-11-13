package operations

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE POLICY SPEND JOURNAL IS CHECKED AGAINST THE AUDIT COLLECTOR AT STARTUP (epic #40 gap .1.2, T09).
//
// The journal, its high-water mark and its fencing epoch live on one disk, so restoring the journal
// AND its mark from one earlier backup passes every local check (durability_test.go and
// mark_required_test.go cover the inconsistent cases). These tests drive the real coordinator, a
// real policy.FileState reserved by the policy step, a real audit.Recorder and a collector double
// that commits what it acknowledges, then reopen the journal the ways a restore can leave it.

// committingCollector acknowledges each event and reports the last one as its committed head, as
// the collector's /v1/stream-position does. unreachable makes CommittedHead fail, as a collector
// that does not answer.
type committingCollector struct {
	mu          sync.Mutex
	events      []audit.Event
	unreachable bool
}

func (c *committingCollector) Send(_ context.Context, event audit.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, event)
	return nil
}
func (*committingCollector) Ready(context.Context) bool { return true }
func (c *committingCollector) CommittedHead(context.Context, string) (uint64, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.unreachable {
		return 0, "", audit.ErrSinkUnavailable
	}
	if len(c.events) == 0 {
		return 0, "", nil
	}
	last := c.events[len(c.events)-1]
	return last.Sequence, last.Hash, nil
}

// reservingPolicy reserves in the real journal and allows, as the policy engine does for an
// operation its rules admit: the reservation happens inside Evaluate, before the authorized record.
type reservingPolicy struct {
	state *policy.FileState
	next  int
}

func (value *reservingPolicy) Evaluate(ctx context.Context, _ policy.Request) policy.Decision {
	value.next++
	if err := value.state.Reserve(ctx, anchorReservation(value.next)); err != nil {
		return policy.Decision{Allowed: false, Code: policy.CodeStateUnavailable, PolicyID: "sops"}
	}
	return policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops"}
}

func anchorReservation(n int) policy.Reservation {
	return policy.Reservation{
		PolicyID: "sops", ObjectID: "production-sops", Principal: "spiffe://regalia/workload/sops-prod",
		Nonce: fmt.Sprintf("nonce_%012d", n), UTCDate: "2026-11-13",
		Amounts: map[string]uint64{"ops": 1}, DailyCaps: map[string]uint64{"ops": 100},
	}
}

type anchorSite struct {
	dir, statePath, journalPath string
	collector                   *committingCollector
	recorder                    *audit.Recorder
	state                       *policy.FileState
	coordinator                 *Coordinator
	hardware                    *fakeHardware
}

func newAnchorSite(t *testing.T) *anchorSite {
	t.Helper()
	dir := t.TempDir()
	site := &anchorSite{dir: dir, statePath: filepath.Join(dir, "policy-state.journal"), journalPath: filepath.Join(dir, "audit.journal"), collector: &committingCollector{}}
	var err error
	if site.recorder, err = audit.Open(site.journalPath, site.collector); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = site.recorder.Close() })
	site.openState(t)
	return site
}

func (site *anchorSite) openState(t *testing.T) {
	t.Helper()
	state, err := policy.OpenFileState(site.statePath)
	if err != nil {
		t.Fatalf("OpenFileState: %v (a restore this test makes must pass the LOCAL checks, or it proves nothing about the collector)", err)
	}
	t.Cleanup(func() { _ = state.Close() })
	site.state = state
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048", PolicyID: "sops", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	site.hardware = &fakeHardware{output: []byte("data-key")}
	semantic := &reservingPolicy{state: state, next: int(mustHead(state)) + 100}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, site.recorder, directRunner{}, site.hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	coordinator.SetPolicyHead(state.Head)
	site.coordinator = coordinator
}

func mustHead(state *policy.FileState) uint64 {
	sequence, _ := state.Head()
	return sequence
}

func (site *anchorSite) serve(t *testing.T, operations int) {
	t.Helper()
	for range operations {
		before := site.hardware.calls
		request := operationRequest()
		if _, err := site.coordinator.Execute(context.Background(), request); err != nil || site.hardware.calls != before+1 {
			t.Fatalf("an allowed operation was not served: %v (hardware calls %d -> %d)", err, before, site.hardware.calls)
		}
	}
}

func (site *anchorSite) closeState(t *testing.T) {
	t.Helper()
	if err := site.state.Close(); err != nil {
		t.Fatal(err)
	}
}

func (site *anchorSite) reconcile() error {
	return ReconcilePolicyState(context.Background(), site.state, site.journalPath, site.collector, "")
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	contents, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

// backup copies the journal and its high-water mark together, as one backup of the directory would.
func (site *anchorSite) backup(t *testing.T) string {
	t.Helper()
	to := filepath.Join(t.TempDir(), "backup")
	copyFile(t, site.statePath, to)
	copyFile(t, site.statePath+".high-water", to+".high-water")
	return to
}

func (site *anchorSite) restore(t *testing.T, from string) {
	t.Helper()
	copyFile(t, from, site.statePath)
	copyFile(t, from+".high-water", site.statePath+".high-water")
}

func TestAPolicyJournalIsCheckedAgainstTheAuditCollectorAtStartup(t *testing.T) {
	t.Run("control: an intact reopen is served", func(t *testing.T) {
		site := newAnchorSite(t)
		site.serve(t, 3)
		site.closeState(t)
		site.openState(t)
		if err := site.reconcile(); err != nil {
			t.Fatalf("DEFECT: an intact journal was refused at startup: %v", err)
		}
		site.serve(t, 1)
	})

	t.Run("a journal and mark restored together from an earlier backup are refused", func(t *testing.T) {
		site := newAnchorSite(t)
		site.serve(t, 1)
		earlier := site.backup(t)
		site.serve(t, 2)
		site.closeState(t)
		site.restore(t, earlier)
		site.openState(t) // passes the local checks: the two files agree with each other
		err := site.reconcile()
		if !errors.Is(err, policy.ErrBehindCollector) {
			t.Fatalf("DEFECT: a journal restored with its mark to reservation 1, after the collector acknowledged reservation 3, was not refused as behind the collector: %v", err)
		}
	})

	t.Run("a collector ahead of a wiped journal is refused", func(t *testing.T) {
		site := newAnchorSite(t)
		site.serve(t, 2)
		site.closeState(t)
		for _, path := range []string{site.statePath, site.statePath + ".high-water"} {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		site.openState(t) // a fresh journal opens: nothing local says it ever held anything
		err := site.reconcile()
		if !errors.Is(err, policy.ErrBehindCollector) {
			t.Fatalf("DEFECT: an empty journal, with the collector holding reservation 2, was not refused as behind the collector: %v", err)
		}
	})

	t.Run("a journal replaced by another consistent one is refused", func(t *testing.T) {
		site := newAnchorSite(t)
		site.serve(t, 2)
		site.closeState(t)
		// Another journal of the same length, chained and marked correctly, from other reservations.
		other := filepath.Join(t.TempDir(), "other")
		state, err := policy.OpenFileState(other)
		if err != nil {
			t.Fatal(err)
		}
		for n := 900; n < 902; n++ {
			if err := state.Reserve(context.Background(), anchorReservation(n)); err != nil {
				t.Fatal(err)
			}
		}
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
		site.restore(t, other)
		site.openState(t)
		err = site.reconcile()
		if !errors.Is(err, policy.ErrDivergedFromCollector) {
			t.Fatalf("DEFECT: a replaced journal of the acknowledged length was not refused as diverged: %v", err)
		}
	})

	t.Run("a collector unreachable at open is refused by name", func(t *testing.T) {
		site := newAnchorSite(t)
		site.serve(t, 2)
		site.closeState(t)
		site.openState(t)
		site.collector.mu.Lock()
		site.collector.unreachable = true
		site.collector.mu.Unlock()
		err := site.reconcile()
		if !errors.Is(err, audit.ErrCollectorUnreachable) {
			t.Fatalf("DEFECT: startup with the collector unreachable did not fail closed as audit.ErrCollectorUnreachable: %v", err)
		}
		// The same state reaches the audit journal's own reconciliation, which runs first.
		if err := audit.ReconcileContinuity(context.Background(), site.journalPath, site.collector, ""); !errors.Is(err, audit.ErrCollectorUnreachable) {
			t.Fatalf("DEFECT: audit.ReconcileContinuity with the collector unreachable did not fail as audit.ErrCollectorUnreachable: %v", err)
		}
	})
}

// TestOnlyTheAuthorizedRecordCarriesThePolicyHead pins the wiring the startup check depends on: the
// authorized record carries the journal head after this operation's reservation, and no other
// record carries one (a denial reserved nothing; the success record is not needed).
func TestOnlyTheAuthorizedRecordCarriesThePolicyHead(t *testing.T) {
	site := newAnchorSite(t)
	site.serve(t, 2)
	site.collector.mu.Lock()
	defer site.collector.mu.Unlock()
	var carried []uint64
	for _, event := range site.collector.events {
		if event.Outcome == "authorized" {
			if event.PolicySequence == 0 || event.PolicyHash == "" {
				t.Fatalf("DEFECT: an authorized record carries no policy head: %#v", event)
			}
			carried = append(carried, event.PolicySequence)
		} else if event.PolicySequence != 0 || event.PolicyHash != "" {
			t.Fatalf("a %s record carries a policy head: %#v", event.Outcome, event)
		}
	}
	if len(carried) != 2 || carried[0] != 1 || carried[1] != 2 {
		t.Fatalf("authorized records carry policy heads %v, want [1 2]", carried)
	}
}
