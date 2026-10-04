package pcscwatch

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const stateInUse = 0x0100

// fakePCSC is pcscd as the loop sees it. The test changes its readers and their states with apply,
// which returns once the watcher has taken the change in and is waiting again.
type fakePCSC struct {
	mu      sync.Mutex
	states  map[string]uint32 // reader -> event state (presence | counter<<16 | other bits)
	plugged bool              // the PnP reader's "changed": the set of readers moved
	lost    bool              // the next wait fails as a lost context
	refuse  bool              // Establish fails
	steps   chan func()
	calls   int // waits entered: one more than the last change the watcher took in
}

func newFake(readers map[string]uint32) *fakePCSC {
	return &fakePCSC{states: readers, steps: make(chan func())}
}

func (f *fakePCSC) Establish() (Context, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse {
		return nil, errors.New("pcscd is not running")
	}
	f.lost = false
	return f, nil
}

func (f *fakePCSC) Release() {}

func (f *fakePCSC) Readers() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.plugged = false
	var names []string
	for name := range f.states {
		names = append(names, name)
	}
	return names, nil
}

func (f *fakePCSC) StatusChange(timeout time.Duration, readers []string, current []uint32) ([]uint32, error) {
	if timeout > 0 {
		f.mu.Lock()
		f.calls++ // the watcher has taken in everything before this wait
		f.mu.Unlock()
		select {
		case step := <-f.steps:
			step()
		case <-time.After(20 * time.Millisecond):
			return nil, ErrTimeout
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lost {
		return nil, errors.New("pcsc: SCardGetStatusChange: 80100003") // SCARD_E_INVALID_HANDLE
	}
	events := make([]uint32, len(readers))
	for i, name := range readers {
		if name == PnPReader {
			if f.plugged {
				events[i] = stateChanged
			}
			continue
		}
		state, ok := f.states[name]
		if !ok {
			state = stateUnknown
		}
		events[i] = state
		if state != current[i] {
			events[i] |= stateChanged
		}
	}
	return events, nil
}

// world runs a watcher on a fake and drives it.
type world struct {
	t       *testing.T
	fake    *fakePCSC
	watcher *Watcher
	failed  []error
	cancel  context.CancelFunc
}

func newWorld(t *testing.T, readers map[string]uint32) *world {
	w := &world{t: t, fake: newFake(readers), watcher: &Watcher{readers: map[string]reader{}}}
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	t.Cleanup(cancel)
	go w.watcher.run(ctx, w.fake, func(err error) { w.failed = append(w.failed, err) }, func(time.Duration) {})
	w.wait()
	return w
}

// waitPast returns once the watcher has entered more than `calls` waits: everything before is taken in.
func (w *world) waitPast(calls int) {
	w.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		w.fake.mu.Lock()
		now := w.fake.calls
		w.fake.mu.Unlock()
		if now > calls {
			return
		}
	}
	w.t.Fatal("the watcher never came back to wait")
}

func (w *world) wait() { w.waitPast(0) }

// apply makes one change in pcscd and returns once the watcher has taken it in and waits again.
func (w *world) apply(change func(f *fakePCSC)) {
	w.t.Helper()
	taken := make(chan int, 1) // the wait that took the change in
	select {
	case w.fake.steps <- func() { w.fake.mu.Lock(); change(w.fake); taken <- w.fake.calls; w.fake.mu.Unlock() }:
	case <-time.After(5 * time.Second):
		w.t.Fatal("the watcher took no change")
	}
	w.waitPast(<-taken)
}

func (w *world) generation(name string) (uint64, bool) { return w.watcher.Generation(name) }

const nitrokey = "Nitrokey Nitrokey HSM (DENK04041440000         ) 00 00"

func TestACardPulledAndPutBackIsANewGeneration(t *testing.T) {
	w := newWorld(t, map[string]uint32{nitrokey: statePresent | 1<<16})
	first, ok := w.generation(nitrokey)
	if !ok {
		t.Fatal("a present reader has no generation")
	}
	w.apply(func(f *fakePCSC) { f.states[nitrokey] = stateEmpty | 2<<16 }) // pulled
	pulled, _ := w.generation(nitrokey)
	w.apply(func(f *fakePCSC) { f.states[nitrokey] = statePresent | 3<<16 }) // back
	back, ok := w.generation(nitrokey)
	if !ok || pulled == first || back == pulled || back == first {
		t.Fatalf("generations %d, %d, %d (ok %v): a pull and a return must each be new", first, pulled, back, ok)
	}
}

// Use of the card (in use, exclusive) is not an event; nor is a warm reset, which moves neither the
// presence nor the counter. Only an insertion or removal is.
func TestUseAndAWarmResetAreNotEvents(t *testing.T) {
	w := newWorld(t, map[string]uint32{nitrokey: statePresent | 1<<16})
	first, _ := w.generation(nitrokey)
	w.apply(func(f *fakePCSC) { f.states[nitrokey] = statePresent | stateInUse | 1<<16 }) // a session opened
	w.apply(func(f *fakePCSC) { f.states[nitrokey] = statePresent | 1<<16 })              // and closed: a warm reset looks the same
	if now, ok := w.generation(nitrokey); !ok || now != first {
		t.Fatalf("generation %d -> %d (ok %v): use of the card moved it", first, now, ok)
	}
	// but a counter that moved with the card still present (pulled and back between two looks) does
	w.apply(func(f *fakePCSC) { f.states[nitrokey] = statePresent | 3<<16 })
	if now, _ := w.generation(nitrokey); now == first {
		t.Fatal("the insertion counter moved and the generation did not")
	}
}

// The reader is the device: unplugged, it is gone from the list (no generation), and plugged back it
// is a new reader whose counter starts again, so its generation is new and never one used before.
func TestAReaderUnpluggedAndBackIsNeverItsOldGeneration(t *testing.T) {
	yubikey := "Yubico YubiKey OTP+FIDO+CCID 01 00"
	w := newWorld(t, map[string]uint32{nitrokey: statePresent | 1<<16, yubikey: statePresent | 1<<16})
	first, _ := w.generation(nitrokey)
	other, _ := w.generation(yubikey)
	w.apply(func(f *fakePCSC) { delete(f.states, nitrokey); f.plugged = true })
	if _, ok := w.generation(nitrokey); ok {
		t.Fatal("an unplugged reader still has a generation")
	}
	w.apply(func(f *fakePCSC) { f.states[nitrokey] = statePresent | 1<<16; f.plugged = true }) // the same counter as before
	back, ok := w.generation(nitrokey)
	if !ok || back == first {
		t.Fatalf("plugged back: generation %d (ok %v), was %d", back, ok, first)
	}
	if now, _ := w.generation(yubikey); now != other {
		t.Fatal("another reader's generation moved when one was plugged")
	}
}

// pcscd lost: nothing is known (no generation for any reader) until the watcher runs again, and then
// every reader has a new generation, since nothing was watched meanwhile.
func TestALostContextForgetsEveryReader(t *testing.T) {
	w := newWorld(t, map[string]uint32{nitrokey: statePresent | 1<<16})
	first, _ := w.generation(nitrokey)
	w.apply(func(f *fakePCSC) { f.lost = true })
	again, ok := w.generation(nitrokey)
	if !ok || again == first {
		t.Fatalf("after pcscd came back: generation %d (ok %v), was %d", again, ok, first)
	}
	if len(w.failed) == 0 {
		t.Fatal("the lost context was not reported")
	}
}

func TestWithoutPCSCNothingIsWatched(t *testing.T) {
	watcher := Start(context.Background(), nil, nil)
	if _, ok := watcher.Generation(nitrokey); ok {
		t.Fatal("a watcher with no PC/SC gives a generation")
	}
	var none *Watcher
	if _, ok := none.Generation(nitrokey); ok {
		t.Fatal("a nil watcher gives a generation")
	}
}

// THE WATCHER NEVER TOUCHES A CARD. It is allowed to call PC/SC (internal/boundary_test.go) only to read
// reader states: no connection, no transaction, no APDU, so it cannot be a second path to a token.
func TestTheWatcherNeverConnectsToACard(t *testing.T) {
	source, err := os.ReadFile("pcsc_cgo.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"SCardConnect", "SCardReconnect", "SCardTransmit", "SCardBeginTransaction", "SCardControl", "SCardStatus("} {
		if strings.Contains(string(source), call) {
			t.Errorf("pcsc_cgo.go calls %s", call)
		}
	}
}
