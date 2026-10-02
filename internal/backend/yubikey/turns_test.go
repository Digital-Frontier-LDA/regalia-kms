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
}

func (card *exclusiveCard) Open(context.Context, string) (Session, error) {
	card.opens.Add(1)
	if !card.inUse.CompareAndSwap(false, true) {
		card.refused.Add(1)
		return nil, errors.New("the smart card cannot be accessed because of other connections outstanding")
	}
	return &exclusiveSession{fakeSession: &fakeSession{serial: "12345678", pinPolicy: "once", touchPolicy: "never"}, card: card}, nil
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

func (session *exclusiveSession) Close() error {
	session.card.inUse.Store(false)
	return session.fakeSession.Close()
}

// REQUESTS FOR ONE CARD WAIT FOR EACH OTHER (regalia#541).
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
	// A health probe during a signature waits too, and then finds a healthy card.
	if !provider.Healthy(context.Background(), route().Binding) {
		t.Fatal("the card is not healthy after the run")
	}
}

// A request that gives up waiting never touches the card.
func TestARequestWhoseContextEndsWhileWaitingDoesNotOpenTheCard(t *testing.T) {
	card := &exclusiveCard{}
	provider, _ := New(card, &fakePIN{value: []byte("123456")})
	done, ok := provider.takeTurn(context.Background(), route().Binding.DeviceID)
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
	// The turn is per card: another card is not held up by this one.
	other := route()
	other.Binding.DeviceID = "yubi-siteb"
	if _, _, err := provider.Execute(context.Background(), other, "sign", "", "application/octet-stream", []byte("payload"), nil); err != nil {
		t.Fatalf("a request for another card waited on this one: %v", err)
	}
	done()
	if _, _, err := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil); err != nil {
		t.Fatalf("the card is not usable after the turn ended: %v", err)
	}
}
