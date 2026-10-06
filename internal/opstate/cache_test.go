package opstate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSource is a store held in memory: List answers from it, and Watch streams what the test sends.
type fakeSource struct {
	mu        sync.Mutex
	values    map[string][]byte
	revision  int64
	listErr   error
	streams   chan chan Update
	from      []int64
	progress  int
	progErr   error
	listCalls int
	cluster   uint64
}

func newFakeSource() *fakeSource {
	return &fakeSource{values: map[string][]byte{}, streams: make(chan chan Update, 8)}
}

func (f *fakeSource) List(ctx context.Context, prefix string) (map[string][]byte, uint64, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.listCalls++
	if f.listErr != nil {
		return nil, 0, 0, f.listErr
	}
	out := map[string][]byte{}
	for k, v := range f.values {
		out[k] = v
	}
	cluster := f.cluster
	if cluster == 0 {
		cluster = 0xc1
	}
	return out, cluster, f.revision, nil
}

func (f *fakeSource) Watch(ctx context.Context, prefix string, from int64) <-chan Update {
	stream := make(chan Update, 8)
	f.mu.Lock()
	f.from = append(f.from, from)
	f.mu.Unlock()
	f.streams <- stream
	return stream
}

func (f *fakeSource) RequestProgress(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.progress++
	return f.progErr
}

type clock struct {
	mu  sync.Mutex
	now time.Duration
}

func (c *clock) read() (time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now, nil
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now += d
	c.mu.Unlock()
}

type running struct {
	cache  *Cache
	source *fakeSource
	clock  *clock
	stop   func()
	states chan string
}

func start(t *testing.T, verify func(string, []byte) error, seed map[string][]byte, revision int64) *running {
	t.Helper()
	r := &running{source: newFakeSource(), clock: &clock{now: time.Hour}, states: make(chan string, 64)}
	for k, v := range seed {
		r.source.values[k] = v
	}
	r.source.revision = revision
	cache, err := New(Options{Source: r.source, Prefix: "/regalia/v1/", Verify: verify, Boottime: r.clock.read,
		ProgressEvery: 10 * time.Millisecond, Retry: 10 * time.Millisecond,
		OnState: func(live bool, reason string) {
			if live {
				reason = "LIVE"
			}
			r.states <- reason
		}})
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

func (r *running) stream(t *testing.T) chan Update {
	t.Helper()
	select {
	case s := <-r.source.streams:
		return s
	case <-time.After(5 * time.Second):
		t.Fatal("no watch was opened")
	}
	return nil
}

func (r *running) waitFor(t *testing.T, ok func(int64, time.Duration, bool) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok(r.cache.Applied()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	rev, at, live := r.cache.Applied()
	t.Fatalf("the cache never reached the state wanted: revision %d, confirmed at %s, live %v (%s)", rev, at, live, r.cache.Reason())
}

func TestTheCacheListsThenWatchesFromTheNextRevision(t *testing.T) {
	r := start(t, nil, map[string][]byte{"/regalia/v1/keys/a/state": []byte("enabled")}, 7)
	s := r.stream(t)
	if r.source.from[0] != 8 {
		t.Fatalf("the watch began at %d, not at the revision after the list (8)", r.source.from[0])
	}
	r.waitFor(t, func(rev int64, _ time.Duration, live bool) bool { return live && rev == 7 })
	if v, ok, err := r.cache.Value("/regalia/v1/keys/a/state"); !ok || err != nil || string(v) != "enabled" {
		t.Fatalf("value %q %v %v", v, ok, err)
	}
	r.clock.advance(time.Second)
	s <- Update{Changes: []Change{{Key: "/regalia/v1/keys/a/state", Value: []byte("disabled"), ModRevision: 9}}}
	r.waitFor(t, func(rev int64, at time.Duration, live bool) bool { return rev == 9 && at == time.Hour+time.Second })
	if v, _, _ := r.cache.Value("/regalia/v1/keys/a/state"); string(v) != "disabled" {
		t.Fatalf("the change was not applied: %q", v)
	}
	s <- Update{Changes: []Change{{Key: "/regalia/v1/keys/a/state", Deleted: true, ModRevision: 10}}}
	r.waitFor(t, func(rev int64, _ time.Duration, _ bool) bool { return rev == 10 })
	if _, ok, _ := r.cache.Value("/regalia/v1/keys/a/state"); ok {
		t.Fatal("a deleted key is still there")
	}
}

// A quiet store confirms itself: a progress notification moves the revision to the store's and restamps the
// confirmation, so the Gate can tell quiet from stalled. The cache asks for one every ProgressEvery.
func TestAProgressNotificationConfirmsAQuietStore(t *testing.T) {
	r := start(t, nil, nil, 3)
	s := r.stream(t)
	r.waitFor(t, func(rev int64, _ time.Duration, live bool) bool { return live && rev == 3 })
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.source.mu.Lock()
		asked := r.source.progress
		r.source.mu.Unlock()
		if asked >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the cache never asked the store for progress")
		}
		time.Sleep(time.Millisecond)
	}
	r.clock.advance(30 * time.Second)
	s <- Update{Progress: true, Revision: 12}
	r.waitFor(t, func(rev int64, at time.Duration, _ bool) bool { return rev == 12 && at == time.Hour+30*time.Second })
	// changes alone never move the revision past their own: only a progress notification says "all up to N"
	s <- Update{Revision: 40, Changes: []Change{{Key: "/regalia/v1/hwm/k/c", Value: []byte("5"), ModRevision: 13}}}
	r.waitFor(t, func(rev int64, _ time.Duration, _ bool) bool { return rev == 13 })
}

// A failed or compacted stream stops the cache being live at once, and it lists again.
func TestAFailedStreamIsNotLiveUntilListedAgain(t *testing.T) {
	for _, c := range []struct {
		name   string
		update Update
		close  bool
		want   string
	}{
		{"error", Update{Err: errors.New("connection reset")}, false, "the watch failed: connection reset"},
		{"compacted", Update{Compacted: true}, false, "fell behind a compaction"},
		{"closed", Update{}, true, "the watch stream ended"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := start(t, nil, nil, 5)
			s := r.stream(t)
			r.waitFor(t, func(_ int64, _ time.Duration, live bool) bool { return live })
			r.source.mu.Lock()
			r.source.listErr = errors.New("the store is unreachable")
			r.source.mu.Unlock()
			if c.close {
				close(s)
			} else {
				s <- c.update
			}
			r.waitFor(t, func(_ int64, _ time.Duration, live bool) bool { return !live })
			if reason := r.cache.Reason(); !strings.Contains(reason, c.want) && !strings.Contains(reason, "cannot be listed") {
				t.Fatalf("not live for %q, not %q", reason, c.want)
			}
			r.source.mu.Lock()
			r.source.listErr = nil
			r.source.revision = 9
			r.source.mu.Unlock()
			r.stream(t)
			r.waitFor(t, func(rev int64, _ time.Duration, live bool) bool { return live && rev == 9 })
		})
	}
}

// An entry that does not verify is kept as refused: the key is unavailable, never its previous value.
func TestAnEntryThatDoesNotVerifyIsUnavailableNotItsPreviousValue(t *testing.T) {
	verify := func(key string, value []byte) error {
		if strings.HasPrefix(string(value), "forged") {
			return errors.New("not signed by the policy authority")
		}
		return nil
	}
	r := start(t, verify, map[string][]byte{"/regalia/v1/keys/a/state": []byte("disabled")}, 4)
	s := r.stream(t)
	r.waitFor(t, func(_ int64, _ time.Duration, live bool) bool { return live })
	s <- Update{Changes: []Change{{Key: "/regalia/v1/keys/a/state", Value: []byte("forged enabled"), ModRevision: 5}}}
	r.waitFor(t, func(rev int64, _ time.Duration, _ bool) bool { return rev == 5 })
	value, ok, err := r.cache.Value("/regalia/v1/keys/a/state")
	if !ok || err == nil || value != nil || !strings.Contains(err.Error(), "does not verify: not signed by the policy authority") {
		t.Fatalf("a forged entry read as %q, %v, %v", value, ok, err)
	}
}

// The store going backwards (a restore from an old snapshot) is refused, never read.
func TestAStoreThatWentBackwardsIsNotRead(t *testing.T) {
	r := start(t, nil, nil, 20)
	s := r.stream(t)
	r.waitFor(t, func(rev int64, _ time.Duration, live bool) bool { return live && rev == 20 })
	r.source.mu.Lock()
	r.source.revision = 15
	r.source.mu.Unlock()
	s <- Update{Err: errors.New("leader changed")}
	r.waitFor(t, func(_ int64, _ time.Duration, live bool) bool { return !live })
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(r.cache.Reason(), "below the 20 already applied") {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("not refused as a rollback: %s", r.cache.Reason())
}

func TestOptionsAreChecked(t *testing.T) {
	for _, o := range []Options{
		{},
		{Source: newFakeSource(), Prefix: "/regalia/v1/", ProgressEvery: time.Second, Retry: time.Second},
		{Source: newFakeSource(), Prefix: "regalia/v1", Boottime: (&clock{}).read, ProgressEvery: time.Second, Retry: time.Second},
		{Source: newFakeSource(), Prefix: "/regalia/v1/", Boottime: (&clock{}).read, Retry: time.Second},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("options %+v were taken", o)
		}
	}
}

// Another cluster behind the same socket (a re-created cluster, a wrong endpoint) is refused, never read.
func TestAnotherClusterIsNotRead(t *testing.T) {
	r := start(t, nil, nil, 5)
	s := r.stream(t)
	r.waitFor(t, func(_ int64, _ time.Duration, live bool) bool { return live })
	r.source.mu.Lock()
	r.source.cluster, r.source.revision = 0xbad, 50
	r.source.mu.Unlock()
	s <- Update{Err: errors.New("member restarted")}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(r.cache.Reason(), "another cluster is not read") {
		if time.Now().After(deadline) {
			t.Fatalf("not refused as another cluster: %s", r.cache.Reason())
		}
		time.Sleep(time.Millisecond)
	}
	if rev, _, live := r.cache.Applied(); live || rev != 5 {
		t.Fatalf("revision %d live %v after another cluster answered", rev, live)
	}
}

func TestThePublisherWritesTheAppliedRevisionWhileLive(t *testing.T) {
	dir := t.TempDir()
	const boot = "0123abcd-0000-4000-8000-0123456789ab"
	publisher, err := NewPublisher(dir, boot, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	read := func() appliedDocument {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, AppliedFile))
		if err != nil {
			t.Fatal(err)
		}
		var d appliedDocument
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	publisher.Applied(Snapshot{ClusterID: 0xc1, Revision: 7, ConfirmedAt: time.Hour, Live: false})
	if _, err := os.Stat(filepath.Join(dir, AppliedFile)); !os.IsNotExist(err) {
		t.Fatal("a cache that is not live wrote the applied revision")
	}
	publisher.Applied(Snapshot{ClusterID: 0xc1, Revision: 7, ConfirmedAt: time.Hour, Live: true})
	if d := read(); d != (appliedDocument{BootID: boot, BoottimeNs: int64(time.Hour), ClusterID: "00000000000000c1", Revision: 7, StateEpoch: 0}) {
		t.Fatalf("wrote %+v", d)
	}
	if raw, _ := os.ReadFile(filepath.Join(dir, AppliedFile)); !strings.Contains(string(raw), `"state_epoch":0`) {
		t.Fatalf("state_epoch is not written: %s", raw) // #489's reader requires exactly five fields
	}
	if info, _ := os.Stat(filepath.Join(dir, AppliedFile)); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v", info.Mode())
	}
	// the same revision confirmed again: rewritten only once Every has passed
	publisher.Applied(Snapshot{ClusterID: 0xc1, Revision: 7, ConfirmedAt: time.Hour + time.Second, Live: true})
	if read().BoottimeNs != int64(time.Hour) {
		t.Fatal("rewritten before Every")
	}
	publisher.Applied(Snapshot{ClusterID: 0xc1, Revision: 7, ConfirmedAt: time.Hour + 5*time.Second, Live: true})
	if read().BoottimeNs != int64(time.Hour+5*time.Second) {
		t.Fatal("a quiet store's confirmation was never written")
	}
	// a new revision: at once
	publisher.Applied(Snapshot{ClusterID: 0xc1, Revision: 8, ConfirmedAt: time.Hour + 6*time.Second, Live: true})
	if d := read(); d.Revision != 8 {
		t.Fatalf("a new revision waited: %+v", d)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left: %v", entries)
	}
	// a write that fails is said, and the next confirmation tries again
	var failed []error
	broken, _ := NewPublisher(filepath.Join(dir, "missing"), boot, time.Second)
	broken.Err = func(err error) { failed = append(failed, err) }
	broken.Applied(Snapshot{ClusterID: 1, Revision: 1, ConfirmedAt: time.Hour, Live: true})
	broken.Applied(Snapshot{ClusterID: 1, Revision: 1, ConfirmedAt: time.Hour, Live: true})
	if len(failed) != 2 {
		t.Fatalf("failures heard: %v", failed)
	}
	for _, bad := range []struct{ dir, boot string }{{"relative", boot}, {dir + "/../x", boot}, {dir, "not-a-uuid"}} {
		if _, err := NewPublisher(bad.dir, bad.boot, time.Second); err == nil {
			t.Errorf("publisher %v taken", bad)
		}
	}
}
