// Package opstate is the daemon's read side of the operational state (ADR-0002 D32, FENCING.md): key state,
// spent approvals and high-water marks, which etcd orders and replicates across the three servers. etcd never
// decides: every entry carries its own authorization, verified here before it is used (Verify).
//
// The everyday path reads only this cache. A watch keeps it current, and the Gate asks Applied() on every
// call: the cache must have applied at least the revision the server's lease carries, and its last
// confirmation (a watch response or a progress notification) must be younger than the lease. A stalled
// watch is stale state, never quiet state: RequestProgress is asked every ProgressEvery, so a live stream
// confirms itself even when nothing changes.
package opstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Prefix is the one prefix every operational-state key is under (#432): keys/, nonces/, seq/, quota/, hwm/,
// sessions/.
const Prefix = "/regalia/v1/"

// Change is one key's new value, or its deletion, at a revision.
type Change struct {
	Key         string
	Value       []byte
	Deleted     bool
	Created     bool // the key's creation (etcd: its create revision is this one)
	ModRevision int64
}

// Update is one watch response: changes, or a progress notification (no changes) confirming that every
// change up to Revision has been delivered.
type Update struct {
	ClusterID uint64
	Revision  int64
	Changes   []Change
	Progress  bool
	Compacted bool
	Err       error
}

// Source is the store, as this package uses it (etcd in production, etcdSource; a fake in tests).
type Source interface {
	// List reads every key under prefix, and the store's cluster ID and revision for that read.
	List(ctx context.Context, prefix string) (map[string][]byte, uint64, int64, error)
	// Watch streams the changes under prefix from fromRevision on, with progress notifications. The channel
	// is closed when ctx ends or the stream fails.
	Watch(ctx context.Context, prefix string, fromRevision int64) <-chan Update
	// RequestProgress asks the store to send a progress notification on the open watch streams.
	RequestProgress(ctx context.Context) error
}

// Options configure a Cache.
type Options struct {
	Source Source
	Prefix string // "/regalia/v1/"
	// Verify judges an entry before it is used, against `previous`: the last entry under that key that
	// verified (nil when there is none). It returns the parsed entry, kept as the next one's previous. A
	// refused entry is kept as refused, so a key whose state does not verify is unavailable (fail closed),
	// never its previous state; and a later entry is still judged against the last good one, so a refused
	// entry cannot reset what a replay is judged against. Nil: every value holds, as raw bytes.
	Verify func(key string, value []byte, previous any) (any, error)
	// Tombstone says which keys, once seen, may never become absent: a delete of one (or its absence from a
	// later list) is kept as a refusal, never "no state" (a key's state deleted, then its first state put
	// back, is a rollback). Nil: none.
	Tombstone func(key string) bool
	// Fresh judges an entry whose CREATION this cache observes (a watch event, never the initial list) against
	// the moment it arrived: opstate.fresh, so a key that may sign a backdated entry cannot place it in real
	// time it never had (1e on #492). Nil: none.
	Fresh func(key string, parsed any) error
	// Boottime is CLOCK_BOOTTIME; confirmations are stamped with it.
	Boottime func() (time.Duration, error)
	// ProgressEvery is how often the cache asks for a progress notification: a fraction of the lease.
	ProgressEvery time.Duration
	// Retry is the wait before listing again after the stream fails.
	Retry time.Duration
	// OnState hears every change of liveness, with the reason when it is lost.
	OnState func(live bool, reason string)
	// OnApplied hears every confirmation while the cache is live (a list, a change, a progress
	// notification), outside the cache's lock: the applied-revision file is written from it.
	OnApplied func(Snapshot)
}

// Snapshot is what the cache has applied, from which cluster, and when it was last confirmed.
type Snapshot struct {
	ClusterID   uint64
	Revision    int64
	ConfirmedAt time.Duration // CLOCK_BOOTTIME
	Live        bool
	// StateEpoch is the state epoch the cache holds: 0 until the signed /regalia/v1/state-epoch entry is verified
	// here (its format is #492's; until then the key is not read and 0 is published, as at genesis).
	StateEpoch int64
}

type entry struct {
	value   []byte
	parsed  any
	refusal error
}

// Cache is the operational state as of the last revision applied.
type Cache struct {
	options Options

	// good is the last entry under each key that verified: what the next one is judged against. Only the
	// Run goroutine reads or writes it, so it needs no lock; it outlives a relist (a store listed again is
	// still judged against what this process saw).
	good map[string]any

	mu          sync.Mutex
	entries     map[string]entry
	clusterID   uint64
	revision    int64
	confirmedAt time.Duration
	live        bool
	reason      string
}

// New checks the options. Run fills the cache.
func New(options Options) (*Cache, error) {
	if options.Source == nil || options.Boottime == nil || !strings.HasPrefix(options.Prefix, "/") || !strings.HasSuffix(options.Prefix, "/") {
		return nil, errors.New("opstate: a source, a clock and a /prefix/ are required")
	}
	if options.ProgressEvery <= 0 || options.Retry <= 0 {
		return nil, errors.New("opstate: ProgressEvery and Retry must be positive")
	}
	return &Cache{options: options, entries: map[string]entry{}, good: map[string]any{}, reason: "the state has not been read yet"}, nil
}

// Applied is the revision the cache has applied, when that was last confirmed (CLOCK_BOOTTIME), and
// whether the watch is live. A cache that is not live answers ok=false whatever it holds.
func (c *Cache) Applied() (revision int64, confirmedAt time.Duration, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.revision, c.confirmedAt, c.live
}

// Snapshot is Applied with the cluster it was read from.
func (c *Cache) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Snapshot{ClusterID: c.clusterID, Revision: c.revision, ConfirmedAt: c.confirmedAt, Live: c.live}
}

func (c *Cache) confirmed() {
	if c.options.OnApplied != nil {
		if s := c.Snapshot(); s.Live {
			c.options.OnApplied(s)
		}
	}
}

// Reason is why the cache is not live; empty when it is.
func (c *Cache) Reason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reason
}

// Value is a key's verified value. ok is false for an absent key; err is the refusal of an entry that did
// not verify, which the caller must treat as unavailable.
func (c *Cache) Value(key string) (value []byte, ok bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	found, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	if found.refusal != nil {
		return nil, true, found.refusal
	}
	return append([]byte(nil), found.value...), true, nil
}

// Run keeps the cache current until ctx ends: list, then watch from the next revision; on any failure of
// the stream (an error, a compaction, a closed channel) the cache stops being live and lists again.
func (c *Cache) Run(ctx context.Context) {
	for ctx.Err() == nil {
		if err := c.cycle(ctx); err != nil && ctx.Err() == nil {
			c.lost(err.Error())
			select {
			case <-ctx.Done():
			case <-time.After(c.options.Retry):
			}
		}
	}
	c.lost("stopped")
}

func (c *Cache) cycle(ctx context.Context) error {
	values, cluster, revision, err := c.options.Source.List(ctx, c.options.Prefix)
	if err != nil {
		return fmt.Errorf("the state cannot be listed: %w", err)
	}
	if err := c.replace(values, cluster, revision); err != nil {
		return err
	}
	c.confirmed()
	watch, cancel := context.WithCancel(ctx)
	defer cancel()
	updates := c.options.Source.Watch(watch, c.options.Prefix, revision+1)
	ticker := time.NewTicker(c.options.ProgressEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.options.Source.RequestProgress(watch); err != nil {
				return fmt.Errorf("no progress could be asked of the store: %w", err)
			}
		case update, open := <-updates:
			if !open {
				return errors.New("the watch stream ended")
			}
			if update.Err != nil {
				return fmt.Errorf("the watch failed: %w", update.Err)
			}
			if update.Compacted {
				return errors.New("the watch fell behind a compaction: listing again")
			}
			if err := c.apply(update); err != nil {
				return err
			}
			c.confirmed()
		}
	}
}

// verify judges value against good[key] and, when it verifies, records it there. A created entry is also
// judged fresh.
func (c *Cache) verify(good map[string]any, key string, value []byte, created bool) entry {
	kept := append([]byte(nil), value...)
	if c.options.Verify == nil {
		return entry{value: kept}
	}
	parsed, err := c.options.Verify(key, kept, good[key])
	if err == nil && created && c.options.Fresh != nil {
		err = c.options.Fresh(key, parsed)
	}
	if err != nil {
		return entry{refusal: fmt.Errorf("the entry at %s does not verify: %w", key, err)}
	}
	good[key] = parsed
	return entry{value: kept, parsed: parsed}
}

func (c *Cache) tombstoned(key string, good map[string]any) bool {
	_, seen := good[key]
	return seen && c.options.Tombstone != nil && c.options.Tombstone(key)
}

func deletedAfterSeen(key string) entry {
	return entry{refusal: fmt.Errorf("the entry at %s was deleted after it was seen: a deleted state is refused, never taken for no state", key)}
}

// Entry is a key's verified entry as Verify parsed it, like Value.
func (c *Cache) Entry(key string) (parsed any, ok bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	found, ok := c.entries[key]
	if !ok {
		return nil, false, nil
	}
	if found.refusal != nil {
		return nil, true, found.refusal
	}
	return found.parsed, true, nil
}

func (c *Cache) replace(values map[string][]byte, cluster uint64, revision int64) error {
	now, err := c.options.Boottime()
	if err != nil {
		return errors.New("CLOCK_BOOTTIME cannot be read")
	}
	good := make(map[string]any, len(c.good))
	for k, v := range c.good {
		good[k] = v
	}
	entries := make(map[string]entry, len(values))
	for key, value := range values {
		if !strings.HasPrefix(key, c.options.Prefix) {
			return fmt.Errorf("the store listed %q, outside %s", key, c.options.Prefix)
		}
		entries[key] = c.verify(good, key, value, false)
	}
	for key := range c.good {
		if _, listed := values[key]; !listed {
			if c.tombstoned(key, c.good) {
				entries[key] = deletedAfterSeen(key)
			} else {
				// collected while the watch was down (a nonce, a day's quota): no trace, as a watched delete leaves
				// none, so the memory of what was seen stays bounded by what the store holds (48)
				delete(good, key)
			}
		}
	}
	c.mu.Lock()
	if c.clusterID != 0 && cluster != c.clusterID {
		c.mu.Unlock()
		return fmt.Errorf("the store is cluster %016x, not the %016x this cache was reading: another cluster is not read", cluster, c.clusterID)
	}
	if revision < c.revision {
		c.mu.Unlock()
		return fmt.Errorf("the store listed revision %d, below the %d already applied: a store rolled back is not read", revision, c.revision)
	}
	c.entries, c.clusterID, c.revision, c.confirmedAt = entries, cluster, revision, now
	c.good = good
	c.setLive(true, "")
	c.mu.Unlock()
	return nil
}

// apply takes one watch response. Changes move the revision to their own; a progress notification confirms
// every change up to its revision, and only it may move the revision past the last change seen.
func (c *Cache) apply(update Update) error {
	now, err := c.options.Boottime()
	if err != nil {
		return errors.New("CLOCK_BOOTTIME cannot be read")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if update.ClusterID != 0 && update.ClusterID != c.clusterID {
		return fmt.Errorf("the watch answered from cluster %016x, not %016x", update.ClusterID, c.clusterID)
	}
	revision := c.revision
	// staged, so a response refused part-way changes nothing (the cache then lists again)
	good, staged := map[string]any{}, map[string]*entry{}
	lookup := func(key string) map[string]any {
		if _, has := good[key]; !has {
			if v, ok := c.good[key]; ok {
				good[key] = v
			}
		}
		return good
	}
	for _, change := range update.Changes {
		if !strings.HasPrefix(change.Key, c.options.Prefix) {
			return fmt.Errorf("the watch delivered %q, outside %s", change.Key, c.options.Prefix)
		}
		if change.ModRevision <= c.revision && c.revision > 0 && change.ModRevision != 0 {
			return fmt.Errorf("the watch delivered revision %d, not after the %d already applied", change.ModRevision, c.revision)
		}
		if change.Deleted {
			if c.tombstoned(change.Key, lookup(change.Key)) {
				refused := deletedAfterSeen(change.Key)
				staged[change.Key] = &refused
			} else {
				staged[change.Key] = nil
			}
		} else {
			judged := c.verify(lookup(change.Key), change.Key, change.Value, change.Created)
			staged[change.Key] = &judged
		}
		if change.ModRevision > revision {
			revision = change.ModRevision
		}
	}
	for key, parsed := range good {
		c.good[key] = parsed
	}
	for key, judged := range staged {
		if judged == nil {
			// a key that may be deleted (a nonce or a day's quota collected after it expired) leaves no trace,
			// so the memory of what was seen stays bounded by what the store holds
			delete(c.entries, key)
			delete(c.good, key)
		} else {
			c.entries[key] = *judged
		}
	}
	if update.Progress && update.Revision > revision {
		revision = update.Revision
	}
	c.revision, c.confirmedAt = revision, now
	c.setLive(true, "")
	return nil
}

func (c *Cache) lost(reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLive(false, reason)
}

// setLive records liveness; the caller holds mu. The hook is called with mu held, so it must not call back.
func (c *Cache) setLive(live bool, reason string) {
	changed := live != c.live || reason != c.reason
	c.live, c.reason = live, reason
	if changed && c.options.OnState != nil {
		c.options.OnState(live, reason)
	}
}
