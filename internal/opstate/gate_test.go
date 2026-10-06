package opstate

import (
	"context"
	"strings"
	"testing"
	"time"
)

type fixedCache struct{ s Snapshot }

func (c *fixedCache) Snapshot() Snapshot { return c.s }

func TestTheStateGateServesOnlyOnStateAsNewAsItsLease(t *testing.T) {
	key, _ := NewSessionKey("0123abcd-0000-4000-8000-0123456789ab", 1)
	other, _ := NewSessionKey("0123abcd-0000-4000-8000-0123456789ab", 1)
	lease := LeaseFacts{Admitted: true, StateRevision: 40, ClusterID: 0xc1, SessionKey: key.Hex()}
	cache := &fixedCache{Snapshot{ClusterID: 0xc1, Revision: 40, ConfirmedAt: time.Hour, Live: true}}
	now := time.Hour + 10*time.Second
	var heard []string
	gate, err := NewStateGate(StateGateOptions{
		Lease: func(context.Context) LeaseFacts { return lease }, Cache: cache, Key: key,
		Boottime: func() (time.Duration, error) { return now, nil }, MaxStale: 30 * time.Second,
		OnTransition: func(ready bool, reason string) {
			if ready {
				reason = "READY"
			}
			heard = append(heard, reason)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ready := func() {
		t.Helper()
		if !gate.Ready(context.Background()) {
			t.Fatalf("not ready: %s", gate.Reason())
		}
	}
	refused := func(want string) {
		t.Helper()
		if gate.Ready(context.Background()) {
			t.Fatalf("ready, where %q was expected", want)
		}
		if !strings.Contains(gate.Reason(), want) {
			t.Fatalf("refused for %q, not %q", gate.Reason(), want)
		}
	}
	ready()
	lease.Admitted = false
	refused("no serving lease is held")
	lease.Admitted, lease.SessionKey = true, other.Hex()
	refused("another instance of this daemon")
	lease.SessionKey = key.Hex()
	cache.s.Live = false
	refused("not being watched")
	cache.s.Live, lease.ClusterID = true, 0xbad
	refused("names etcd cluster 0000000000000bad, this server reads 00000000000000c1")
	lease.ClusterID, lease.StateEpoch = 0xc1, 1
	refused("names state epoch 1, this server holds 0")
	lease.StateEpoch, lease.StateRevision = 0, 41
	refused("at revision 40, behind the lease's 41: catching up")
	lease.StateRevision = 39 // a cache ahead of its lease serves
	ready()
	now = time.Hour + 30*time.Second
	refused("last confirmed 30s ago, longer than one lease (30s): the watch has stalled")
	now = time.Hour + 29*time.Second
	ready()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if gate.Ready(cancelled) {
		t.Fatal("ready for a cancelled request")
	}
	if len(heard) < 8 || heard[0] != "READY" {
		t.Fatalf("transitions: %v", heard)
	}
	if _, err := NewStateGate(StateGateOptions{}); err == nil {
		t.Fatal("empty options taken")
	}
}
