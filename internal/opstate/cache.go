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

// Change is one key's new value, or its deletion, at a revision.
type Change struct {
	Key         string
	Value       []byte
	Deleted     bool
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
	// Verify judges an entry before it is used: nil means it holds. A refused entry is kept as refused, so
	// a key whose state does not verify is unavailable (fail closed), never its previous state.
	Verify func(key string, value []byte) error
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
}

type entry struct {
	value   []byte
	refusal error
}

// Cache is the operational state as of the last revision applied.
type Cache struct {
	options Options

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
	return &Cache{options: options, entries: map[string]entry{}, reason: "the state has not been read yet"}, nil
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

func (c *Cache) verify(key string, value []byte) entry {
	if c.options.Verify != nil {
		if err := c.options.Verify(key, value); err != nil {
			return entry{refusal: fmt.Errorf("the entry at %s does not verify: %w", key, err)}
		}
	}
	return entry{value: append([]byte(nil), value...)}
}

func (c *Cache) replace(values map[string][]byte, cluster uint64, revision int64) error {
	now, err := c.options.Boottime()
	if err != nil {
		return errors.New("CLOCK_BOOTTIME cannot be read")
	}
	entries := make(map[string]entry, len(values))
	for key, value := range values {
		if !strings.HasPrefix(key, c.options.Prefix) {
			return fmt.Errorf("the store listed %q, outside %s", key, c.options.Prefix)
		}
		entries[key] = c.verify(key, value)
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
	for _, change := range update.Changes {
		if !strings.HasPrefix(change.Key, c.options.Prefix) {
			return fmt.Errorf("the watch delivered %q, outside %s", change.Key, c.options.Prefix)
		}
		if change.ModRevision <= c.revision && c.revision > 0 && change.ModRevision != 0 {
			return fmt.Errorf("the watch delivered revision %d, not after the %d already applied", change.ModRevision, c.revision)
		}
		if change.Deleted {
			delete(c.entries, change.Key)
		} else {
			c.entries[change.Key] = c.verify(change.Key, change.Value)
		}
		if change.ModRevision > revision {
			revision = change.ModRevision
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
