// Package pcscwatch sees PC/SC reader and card events as they happen, so that a token pulled and put
// back between two operations is known to have been away (regalia-kms#72, G2).
//
// THE READER GOES WITH THE CARD. A Nitrokey HSM 2, a Pico HSM and a YubiKey are each a reader and its
// card in one USB device: pulling one removes the reader itself, and on replug a new reader appears
// whose event counter starts again. Looking at a reader only before each operation could therefore
// miss a pull; this package watches all the time (SCardGetStatusChange on every reader and on the PnP
// notification reader) and keeps a GENERATION per reader name. A generation never repeats: it is
// taken from one counter for the whole process, bumped on every event:
//   - a card inserted or removed, or the reader's event counter moved (the high 16 bits of its
//     event state, which pcsc-lite advances on each insertion and removal);
//   - the reader appearing (a new generation) or disappearing (no generation: Generation says no);
//   - the watcher itself (re)starting, after pcscd restarted or the context was lost: every reader
//     gets a new generation, since nothing was watched meanwhile.
//
// A WARM RESET IS NOT AN EVENT. A card reset with no removal leaves the reader in place and its
// counter where it was, and nothing here moves. That is deliberate: a provider presents the sealed PIN
// on every operation under the current lease, so the card's own login state never authorized
// anything, and a reset takes nothing away that a fresh lease would give back.
//
// WHILE THE WATCHER IS NOT RUNNING, Generation says no for every reader, and a provider refuses a
// removable token rather than serve it unwatched. The PC/SC binding is built only with -tags piv
// (pcsc_cgo.go); without it System returns nothing and the watcher never runs.
package pcscwatch

import (
	"context"
	"errors"
	"sync"
	"time"
)

// The PC/SC values the loop reads (winscard.h, pcsc-lite and macOS alike).
const (
	stateUnaware     = 0x0000
	stateChanged     = 0x0002
	stateUnknown     = 0x0004
	stateUnavailable = 0x0008
	stateEmpty       = 0x0010
	statePresent     = 0x0020

	// PnPReader is pcsc-lite's name for the pseudo-reader whose state changes when a reader is added
	// or removed.
	PnPReader = `\\?PnP?\Notification`

	// ErrTimeout is SCARD_E_TIMEOUT: nothing happened within the timeout.
	codeTimeout = 0x8010000A
	// codeNoReaders is SCARD_E_NO_READERS_AVAILABLE: listing found none, which is an answer.
	codeNoReaders = 0x8010002E

	poll       = time.Second      // how long one SCardGetStatusChange waits, so that a stop is seen
	retryFirst = time.Second      // after a lost context, 1 s doubling
	retryMax   = 30 * time.Second // to 30 s
)

// API is the PC/SC surface the loop needs. pcsc_cgo.go is the real one; tests give a fake.
type API interface {
	Establish() (Context, error)
}

// Context is one PC/SC context.
type Context interface {
	// Readers lists the readers; none is an empty list, not an error.
	Readers() ([]string, error)
	// StatusChange waits up to timeout for any of the readers to leave its current state, and
	// returns each reader's event state. A timeout is ErrTimeout.
	StatusChange(timeout time.Duration, readers []string, current []uint32) ([]uint32, error)
	Release()
}

// ErrTimeout is what StatusChange returns when nothing changed.
var ErrTimeout = errors.New("pcsc: timeout")

// Watcher holds the generations. Its zero value is a watcher that never runs.
type Watcher struct {
	mu      sync.Mutex
	running bool
	next    uint64
	readers map[string]reader
}

type reader struct {
	generation uint64
	event      uint32 // the last event state seen: presence and the event counter
}

// Generation is the reader's current generation, and whether the watcher is running and sees that
// reader now. A token whose reader has no generation is not to be served.
func (watcher *Watcher) Generation(name string) (uint64, bool) {
	if watcher == nil {
		return 0, false
	}
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	if !watcher.running {
		return 0, false
	}
	current, ok := watcher.readers[name]
	return current.generation, ok
}

// Start runs the watcher until ctx ends. With a nil API (a build without PC/SC) it never runs, and
// every Generation says no.
func Start(ctx context.Context, api API, failed func(error)) *Watcher {
	watcher := &Watcher{readers: map[string]reader{}}
	if api == nil {
		return watcher
	}
	go watcher.run(ctx, api, failed, time.Sleep)
	return watcher
}

func (watcher *Watcher) run(ctx context.Context, api API, failed func(error), sleep func(time.Duration)) {
	wait := time.Duration(0)
	for ctx.Err() == nil {
		err := watcher.watch(ctx, api)
		watcher.stop()
		if ctx.Err() != nil {
			return
		}
		if failed != nil && err != nil {
			failed(err)
		}
		wait = min(max(wait*2, retryFirst), retryMax)
		sleep(wait)
	}
}

// stop marks the watcher not running: from here on nothing is known, and every reader will get a new
// generation when it runs again.
func (watcher *Watcher) stop() {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	watcher.running = false
	watcher.readers = map[string]reader{}
}

// watch is one PC/SC context's life: list the readers, give each a new generation, then follow every
// change until the context fails or ctx ends.
func (watcher *Watcher) watch(ctx context.Context, api API) error {
	pcsc, err := api.Establish()
	if err != nil {
		return err
	}
	defer pcsc.Release()
	for ctx.Err() == nil {
		names, err := pcsc.Readers()
		if err != nil {
			return err
		}
		// the readers as they are now: their present state, and (first time round, or after a
		// restart) a generation each
		watched := append(append([]string(nil), names...), PnPReader)
		current := make([]uint32, len(watched))
		events, err := pcsc.StatusChange(0, watched, current) // unaware: returns the state at once
		if err != nil && !errors.Is(err, ErrTimeout) {
			return err
		}
		watcher.listed(names, events)
		for i := range current {
			current[i] = events[i] &^ stateChanged
		}
		// follow every change until the set of readers changes
		for relist := false; !relist; {
			if ctx.Err() != nil {
				return nil
			}
			events, err = pcsc.StatusChange(poll, watched, current)
			if errors.Is(err, ErrTimeout) {
				continue
			}
			if err != nil {
				return err
			}
			for i, name := range watched {
				if events[i]&stateChanged == 0 {
					continue
				}
				if name == PnPReader {
					relist = true
					continue
				}
				watcher.changed(name, events[i])
				current[i] = events[i] &^ stateChanged
			}
		}
	}
	return nil
}

// listed records the readers present now. A reader seen before keeps its generation only if the
// watcher has been running since and its state is the one last seen; one that is new, or back, or
// changed, gets a new generation; one no longer listed has none.
func (watcher *Watcher) listed(names []string, events []uint32) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	fresh := map[string]reader{}
	for i, name := range names {
		event := events[i] &^ stateChanged
		if old, ok := watcher.readers[name]; ok && watcher.running && same(old.event, event) {
			fresh[name] = old
			continue
		}
		watcher.next++
		fresh[name] = reader{generation: watcher.next, event: event}
	}
	watcher.readers, watcher.running = fresh, true
}

// changed records a reader's new event state; any change that is not the same presence and counter is
// a new generation.
func (watcher *Watcher) changed(name string, event uint32) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	event &^= stateChanged
	old, ok := watcher.readers[name]
	if ok && same(old.event, event) {
		return
	}
	watcher.next++
	watcher.readers[name] = reader{generation: watcher.next, event: event}
	if event&(stateUnknown|stateUnavailable) != 0 { // the reader is going: no generation until it is listed again
		delete(watcher.readers, name)
	}
}

// same is whether two event states show the same card in the same reader: the same presence and the
// same insertion/removal count. Other bits (in use, exclusive, mute) come and go with normal use.
func same(a, b uint32) bool {
	const kept = stateEmpty | statePresent | stateUnknown | stateUnavailable
	return a>>16 == b>>16 && a&kept == b&kept
}
