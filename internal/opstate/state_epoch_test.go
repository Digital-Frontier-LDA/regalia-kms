package opstate

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// The vector's state_epoch_checks (deploy/baremetal/opstate.verify_state_epoch, #513): every case accepted or refused
// alike, refused with Python's own words, and an accepted case's epoch the one applied.json is to report.
func TestEveryStateEpochCheckIsTheSame(t *testing.T) {
	v := opstateVector(t)
	var chain []map[string]any
	for _, m := range v["state_epoch_chain"].([]any) {
		chain = append(chain, m.(map[string]any))
	}
	cases := v["state_epoch_checks"].([]any)
	if len(cases) < 20 {
		t.Fatalf("the vector holds %d state-epoch cases", len(cases))
	}
	accepted := 0
	for _, value := range cases {
		c := value.(map[string]any)
		name := c["name"].(string)
		var previous map[string]any
		if p, ok := c["previous"].(map[string]any); ok {
			previous = p
		}
		var store *StoreRef
		if s, ok := c["store"].([]any); ok {
			revision, err := strconv.ParseInt(s[1].(json.Number).String(), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			store = &StoreRef{ClusterID: s[0].(string), ModRevision: revision}
		}
		entry, err := VerifyStateEpoch(c["key"].(string), c["value"], chain, previous, store)
		if c["accept"] == true {
			if err != nil {
				t.Errorf("%s: Python accepted, Go: %v", name, err)
				continue
			}
			accepted++
			if got, want := entry["state_epoch"].(json.Number).String(), c["applied_state_epoch"].(json.Number).String(); got != want {
				t.Errorf("%s: state epoch %s, applied.json is to report %s", name, got, want)
			}
		} else if err == nil || err.Error() != c["python_reason"] {
			t.Errorf("%s: refused for another reason:\nPython: %s\nGo:     %v", name, c["python_reason"], err)
		}
	}
	if accepted < 4 {
		t.Fatalf("only %d accepted cases ran", accepted)
	}
}

// stateEpochCase is the vector's case `name`: its value as stored (canonical JSON) and the chain it is judged by.
func stateEpochCase(t *testing.T, name string) ([]byte, []map[string]any) {
	t.Helper()
	v := opstateVector(t)
	var chain []map[string]any
	for _, m := range v["state_epoch_chain"].([]any) {
		chain = append(chain, m.(map[string]any))
	}
	for _, value := range v["state_epoch_checks"].([]any) {
		c := value.(map[string]any)
		if c["name"] == name {
			return membership.Canonical(c["value"]), chain
		}
	}
	t.Fatalf("no state-epoch case %q", name)
	return nil, nil
}

// startJudged is a cache over a fake store judged by opstate-v1's Judge, with the state-epoch chain.
func startJudged(t *testing.T, chain []map[string]any, seed map[string][]byte, mods map[string]int64, cluster uint64, revision int64) *running {
	t.Helper()
	r := &running{source: newFakeSource(), clock: &clock{now: time.Hour}, states: make(chan string, 64)}
	for k, v := range seed {
		r.source.values[k] = v
	}
	r.source.revision, r.source.cluster, r.source.mods = revision, cluster, mods
	cache, err := New(Options{Source: r.source, Prefix: Prefix, Boottime: r.clock.read, Tombstone: KeyStateTombstone,
		Verify:        Judge(nil, func() map[string]ApproverSet { return nil }, func() []map[string]any { return chain }),
		ProgressEvery: 10 * time.Millisecond, Retry: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	r.cache = cache
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { cache.Run(ctx); close(done) }()
	r.stop = func() { cancel(); <-done }
	t.Cleanup(r.stop)
	return r
}

const vectorCluster = 0x62ff5b5c1a2e3d4f

func waitEpoch(t *testing.T, r *running, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s := r.cache.Snapshot(); s.Live && s.StateEpoch == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the cache's state epoch is %d, not %d (%s)", r.cache.Snapshot().StateEpoch, want, r.cache.Reason())
}

// The cache reports the state epoch the verified entry holds (what applied.json is to say), 0 while the key has never
// been seen, a rise as it comes; and -1 (unusable) for an entry that does not verify, one that goes back, or a delete
// after it was seen: never 0, which would read as genesis, another history.
func TestTheCacheReportsTheVerifiedStateEpochAndNeverForgetsIt(t *testing.T) {
	a, chain := stateEpochCase(t, "a's take-over at its quarantine epoch, signed by the key a holds since that epoch")
	b, _ := stateEpochCase(t, "b's take-over at epoch 4 over a's at 2")

	none := startJudged(t, chain, nil, nil, vectorCluster, 4800)
	none.stream(t)
	waitEpoch(t, none, 0)

	r := startJudged(t, chain, map[string][]byte{StateEpochKey: a}, map[string]int64{StateEpochKey: 4712}, vectorCluster, 4800)
	s := r.stream(t)
	waitEpoch(t, r, 2)
	s <- Update{ClusterID: vectorCluster, Revision: 4801, Changes: []Change{{Key: StateEpochKey, Value: b, ModRevision: 4801}}}
	waitEpoch(t, r, 4)
	s <- Update{ClusterID: vectorCluster, Revision: 4802, Changes: []Change{{Key: StateEpochKey, Value: a, ModRevision: 4802}}}
	waitEpoch(t, r, -1) // 2 after 4: refused, and the key is unusable, never its last good epoch
	if _, _, err := r.cache.Entry(StateEpochKey); err == nil || !strings.Contains(err.Error(), "the store holds state epoch 4; 2 is not above it") {
		t.Fatalf("the epoch going back was not refused for it: %v", err)
	}

	gone := startJudged(t, chain, map[string][]byte{StateEpochKey: a}, map[string]int64{StateEpochKey: 4712}, vectorCluster, 4800)
	g := gone.stream(t)
	waitEpoch(t, gone, 2)
	g <- Update{ClusterID: vectorCluster, Revision: 4801, Changes: []Change{{Key: StateEpochKey, Deleted: true, ModRevision: 4801}}}
	waitEpoch(t, gone, -1) // deleted after it was seen: refused, not genesis

	low := startJudged(t, chain, map[string][]byte{StateEpochKey: a}, map[string]int64{StateEpochKey: 4711}, vectorCluster, 4800)
	low.stream(t)
	waitEpoch(t, low, -1) // stored at the very revision its take-over named: not this store's take-over
	other := startJudged(t, chain, map[string][]byte{StateEpochKey: a}, map[string]int64{StateEpochKey: 4712}, 0x0123456789abcdef, 4800)
	other.stream(t)
	waitEpoch(t, other, -1) // another cluster's
}

// The publisher writes the epoch the cache reports, and nothing at all while it is unusable: the file goes stale and
// its readers (the lease request, the revision floor) refuse it.
func TestThePublisherWritesTheEpochAndNothingWhileItIsUnusable(t *testing.T) {
	dir := t.TempDir()
	publisher, err := NewPublisher(dir, "0f3a9c1e-1111-4222-8333-444455556666", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var said []error
	publisher.Err = func(err error) { said = append(said, err) }
	publisher.Applied(Snapshot{ClusterID: vectorCluster, Revision: 4800, ConfirmedAt: time.Hour, Live: true, StateEpoch: 2})
	raw, err := os.ReadFile(filepath.Join(dir, AppliedFile))
	if err != nil || !strings.Contains(string(raw), `"state_epoch":2`) {
		t.Fatalf("applied.json %s (%v) does not report state epoch 2", raw, err)
	}
	publisher.Applied(Snapshot{ClusterID: vectorCluster, Revision: 4801, ConfirmedAt: time.Hour + 2*time.Second, Live: true, StateEpoch: -1})
	again, _ := os.ReadFile(filepath.Join(dir, AppliedFile))
	if string(again) != string(raw) || len(said) != 1 || !strings.Contains(said[0].Error(), "does not verify") {
		t.Fatalf("an unusable epoch was published, or not said: %s, %v", again, said)
	}
}
