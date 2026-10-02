package yubikey

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// exclusiveCard is a card as PC/SC gives it to this backend: one connection at a time. A second
// Open while a session is open fails, as SCARD_SHARE_EXCLUSIVE does.
type exclusiveCard struct {
	inUse   atomic.Bool
	opens   atomic.Int32
	refused atomic.Int32
	// loginErr makes every login fail, as a wrong PIN does; logins counts the PINs presented.
	loginErr error
	logins   atomic.Int32
}

func (card *exclusiveCard) Open(context.Context, string) (Session, error) {
	card.opens.Add(1)
	if !card.inUse.CompareAndSwap(false, true) {
		card.refused.Add(1)
		return nil, errors.New("the smart card cannot be accessed because of other connections outstanding")
	}
	return &exclusiveSession{fakeSession: &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never", retries: 3, loginErr: card.loginErr}, card: card}, nil
}
func (*exclusiveCard) Ready(context.Context) bool { return true }

type exclusiveSession struct {
	*fakeSession
	card *exclusiveCard
}

// Sign takes long enough for the other requests to arrive while this one holds the card.
func (session *exclusiveSession) Sign(ctx context.Context, slot, algorithm string, digest []byte) ([]byte, error) {
	time.Sleep(5 * time.Millisecond)
	return session.fakeSession.Sign(ctx, slot, algorithm, digest)
}

func (session *exclusiveSession) Login(ctx context.Context, pin []byte) error {
	session.card.logins.Add(1)
	return session.fakeSession.Login(ctx, pin)
}

func (session *exclusiveSession) Close() error {
	session.card.inUse.Store(false)
	return session.fakeSession.Close()
}

// waitForQueue returns once exactly n requests are parked waiting for the turn.
func waitForQueue(t *testing.T, provider *Provider, n int32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for provider.waiting.Load() != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d requests are waiting for the turn, want %d", provider.waiting.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// PIV REQUESTS WAIT FOR EACH OTHER (regalia#541).
//
// One YubiKey holds several keys, and the daemon takes requests for them at the same time. On the
// bench, nine of twelve simultaneous signatures on one card failed as "unavailable": each found the
// card held by another. Falsifier: remove takeTurn from Execute and most of these fail.
func TestSimultaneousRequestsForOneCardAllSucceed(t *testing.T) {
	card := &exclusiveCard{}
	provider, err := New(card, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	const requests = 12
	failures := make(chan error, requests)
	var wg sync.WaitGroup
	for index := 0; index < requests; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err != nil {
				failures <- err
			}
		}()
	}
	wg.Wait()
	close(failures)
	if failed := len(failures); failed != 0 || card.refused.Load() != 0 {
		t.Fatalf("%d of %d simultaneous requests failed, and the card refused %d opens", failed, requests, card.refused.Load())
	}
	if card.opens.Load() != requests {
		t.Fatalf("the card was opened %d times for %d requests", card.opens.Load(), requests)
	}
	// And the card is left usable: a probe after the run finds it healthy.
	if !provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("the card is not healthy after the run")
	}
}

// A request that gives up waiting never touches the card.
func TestARequestWhoseContextEndsWhileWaitingDoesNotOpenTheCard(t *testing.T) {
	card := &exclusiveCard{}
	provider, _ := New(card, &fakePIN{value: []byte("123456")})
	done, ok := provider.takeTurn(context.Background())
	if !ok {
		t.Fatal("the first turn was not granted")
	}
	waiting, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := provider.Execute(waiting, route(), "sign", "", "application/octet-stream", []byte("payload"), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a request that could not get its turn returned %v", err)
	}
	if provider.Healthy(waiting, route().Binding) {
		t.Fatal("a health probe that could not get its turn reported healthy")
	}
	if card.opens.Load() != 0 {
		t.Fatalf("the card was opened %d times by requests that never got their turn", card.opens.Load())
	}
	// There is one turn for every card: finding a card means opening each reader exclusively, so
	// a request for another YubiKey must wait as well, or the two collide on each other's cards.
	other := route()
	other.Binding.DeviceID = "yubi-siteb"
	again, cancelAgain := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelAgain()
	if _, _, err := provider.Execute(again, other, "sign", "", "application/octet-stream", []byte("payload"), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a request for another card did not wait for the turn: %v", err)
	}
	if card.opens.Load() != 0 {
		t.Fatalf("a card was opened %d times while the turn was held", card.opens.Load())
	}
	done()
	if _, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err != nil {
		t.Fatalf("the card is not usable after the turn ended: %v", err)
	}
}

// ONE BAD PIN COSTS ONE TRY, HOWEVER MANY REQUESTS ARE QUEUED.
//
// The requests behind a failing login were admitted before the PIN was refused. If they did not
// look again once their turn came, each would open the card and present the same PIN: with a queue
// of three, a wrong credential would block the card by itself.
func TestQueuedRequestsDoNotPresentAPINThatWasJustRefused(t *testing.T) {
	card := &exclusiveCard{loginErr: errors.New("wrong PIN")}
	provider, _ := New(card, &fakePIN{value: []byte("123456")})
	// Hold the turn until all six have been admitted and are waiting for it: that is the state in
	// which the first one's refused PIN must stop the other five.
	done, ok := provider.takeTurn(context.Background())
	if !ok {
		t.Fatal("the turn was not granted")
	}
	var wg sync.WaitGroup
	for index := 0; index < 6; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
		}()
	}
	waitForQueue(t, provider, 6)
	done()
	wg.Wait()
	if presented := card.logins.Load(); presented != 1 {
		t.Fatalf("the refused PIN was presented %d times, want once", presented)
	}
	if provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("the card is reported healthy with its PIN latched")
	}
}

// A health probe that was waiting while a PIN was refused must not report the card healthy when its
// turn comes: the latch was set while it waited.
func TestAProbeQueuedBehindARefusedPINReportsTheLatch(t *testing.T) {
	card := &exclusiveCard{}
	provider, _ := New(card, &fakePIN{value: []byte("123456")})
	done, ok := provider.takeTurn(context.Background())
	if !ok {
		t.Fatal("the turn was not granted")
	}
	healthy := make(chan bool, 1)
	go func() { healthy <- provider.Healthy(context.Background(), route().Binding) }()
	// The probe has passed the first look at the latch and is waiting for the turn.
	waitForQueue(t, provider, 1)
	provider.blockPIN(route().Binding.DeviceID)
	done()
	if <-healthy {
		t.Fatal("a probe that waited through a refused PIN reported the card healthy")
	}
	if card.opens.Load() != 0 {
		t.Fatalf("the latched card was opened %d times", card.opens.Load())
	}
}
