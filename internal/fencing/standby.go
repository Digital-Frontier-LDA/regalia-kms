package fencing

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

// Standby is a gate for a site that may not hold the lease yet.
//
// THE PASSIVE SITE IS THE NORMAL CASE, NOT AN ERROR. Open() reports ErrFenced when no valid lease
// is present, which is correct for a caller asking "do I hold it right now" — but a daemon that
// refused to start on that answer could never become active without a restart, and a failover that
// requires someone to restart the standby is not a failover. ADR-0001 §8 wants exactly one signer
// at a time, not exactly one running process.
//
// So Standby separates two questions that Open conflates. Configuration is validated once, eagerly:
// a missing key or an empty path is a startup error, because that is a mistake no lease will ever
// fix. Lease possession is answered on every call: the daemon starts, serves health, reports itself
// NOT ready, and becomes ready the moment a valid lease for its site appears — with no restart and
// no operator step.
//
// The epoch journal keeps that safe. A gate that has observed epoch N refuses any lease below it,
// so a standby that takes over and a former active that comes back cannot both believe they hold
// the site.
type Standby struct {
	mu   sync.Mutex
	gate *Gate
	open func() (*Gate, error)
}

// NewStandby validates the fencing configuration immediately and defers lease acquisition.
func NewStandby(leasePath, statePath, site, registryDigest string, publicKey ed25519.PublicKey, now func() time.Time) (*Standby, error) {
	if leasePath == "" || statePath == "" || site == "" || registryDigest == "" || len(publicKey) != ed25519.PublicKeySize || now == nil {
		return nil, errors.New("invalid fencing configuration")
	}
	key := append(ed25519.PublicKey(nil), publicKey...)
	return &Standby{open: func() (*Gate, error) {
		return Open(leasePath, statePath, site, registryDigest, key, now)
	}}, nil
}

// Ready reports whether this site currently holds a valid lease. It is false while the site is
// passive, and becomes true without a restart once a lease is granted.
func (standby *Standby) Ready(ctx context.Context) bool {
	gate := standby.acquire()
	return gate != nil && gate.Ready(ctx)
}

// Snapshot reports the last lease evaluation without performing one: held is the
// outcome, epoch the high-water mark that survives a later loss, and checked when
// the evaluation happened. ok is false when no gate has ever been acquired, which
// keeps "never held the lease" distinguishable from "lost it".
func (standby *Standby) Snapshot() (held bool, epoch uint64, checked time.Time, ok bool) {
	if standby == nil {
		return false, 0, time.Time{}, false
	}
	standby.mu.Lock()
	gate := standby.gate
	standby.mu.Unlock()
	if gate == nil {
		return false, 0, time.Time{}, false
	}
	held, epoch, checked = gate.snapshot()
	return held, epoch, checked, true
}

// acquire returns the gate, opening it on the first attempt that succeeds. A failed attempt is not
// cached: the point of a standby is that the answer changes.
func (standby *Standby) acquire() *Gate {
	if standby == nil {
		return nil
	}
	standby.mu.Lock()
	defer standby.mu.Unlock()
	if standby.gate != nil {
		return standby.gate
	}
	gate, err := standby.open()
	if err != nil {
		return nil
	}
	standby.gate = gate
	return gate
}
