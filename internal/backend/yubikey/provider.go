// Package yubikey provides the unattended PIV boundary. It has no operation
// that requests user presence and verifies the slot policy before private use.
package yubikey

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/reauth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

var ErrUnavailable = errors.New("YubiKey backend unavailable")

type PINSource interface {
	PIN(context.Context, string) ([]byte, error)
}
type pinReleaser interface{ Release([]byte) error }
type Driver interface {
	Open(context.Context, string) (Session, error)
	Ready(context.Context) bool
}
type Session interface {
	Identity(context.Context) (string, error)
	Policies(context.Context, string) (pinPolicy, touchPolicy string, err error)
	PINRetries(context.Context) (int, error)
	Login(context.Context, []byte) error
	Sign(context.Context, string, string, []byte) ([]byte, error)
	Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error)
	PublicKey(context.Context, string) ([]byte, error)
	Close() error
}

type Provider struct {
	driver  Driver
	pins    PINSource
	mu      sync.RWMutex
	blocked map[string]struct{}
	// pinReadings records the last successful pre-authentication counter read.
	// YubiKey PIV cards can make Retries unavailable after Login in the same
	// process; a failed refresh must not turn a previously measured healthy
	// counter into the indistinguishable value zero.
	pinReadings map[string]pinRetryReading
	// turn holds the one slot PIV requests take in order. See takeTurn.
	turn    chan struct{}
	waiting atomic.Int32
	// returned makes a card that was gone wait for a fresh runtime lease. See RequireReauthorization.
	returned reauth.Tracker
	// lockoutLooked is when nameLockout last looked at the readers.
	lockoutLooked time.Time
}

type pinRetryReading struct {
	retries int
	at      time.Time
}

func New(driver Driver, pins PINSource) (*Provider, error) {
	if driver == nil || pins == nil {
		return nil, errors.New("YubiKey driver and PIN source are required")
	}
	return &Provider{driver: driver, pins: pins, blocked: make(map[string]struct{}), pinReadings: make(map[string]pinRetryReading), turn: make(chan struct{}, 1)}, nil
}

// RequireReauthorization makes every card wait, after an absence and after a start of this daemon,
// for a runtime lease asked for since (internal/backend/reauth; regalia-kms#72 PoC 12.4). Without
// this call nothing waits, as before.
//
// WHEN A CARD IS TAKEN TO BE GONE. When it cannot be opened under a live context, whatever the
// reason: absent, held by another process, pcscd restarting, two cards answering to one serial.
// The driver does not say which, and each means this daemon could not vouch for where the card
// was. And when a call on an open card fails and the card then does not answer for its serial on
// that same connection (answers), when the session will not close, and on a panic. A card that
// was pulled cannot answer on a connection made before it left; a card that refused a request (a
// payload of the wrong size, a key the slot does not hold) still does. The distinction matters:
// counting every failed operation as an absence would let any caller who may use a key take the
// card out of service, for every key on it, with one malformed request, and again at will.
func (provider *Provider) RequireReauthorization(gate reauth.Gate, boottime func() (int64, error), sinceMs int64) error {
	return provider.returned.Require(gate, boottime, sinceMs)
}

// AwaitingReauthorization lists the cards that are present and not yet serving, each with the
// boot-clock time (ms) since which a lease must have been asked for, and those last seen gone (-1).
func (provider *Provider) AwaitingReauthorization() map[string]int64 {
	return provider.returned.Awaiting()
}

// notOpened records a card that could not be opened as gone, unless the request's own context has
// ended. The driver opens nothing under a context that has ended, so a caller who hung up before
// the card was reached, or whose time ran out waiting, would otherwise take a card that is there
// out of service. A card that really is gone is recorded by the next look made under a live
// context: the health check of the next routing decision.
func (provider *Provider) notOpened(ctx context.Context, deviceID string) {
	if ctx.Err() == nil {
		provider.returned.Gone(deviceID)
		provider.nameLockout(ctx, deviceID)
	}
}

// goneUnlessItAnswers records the card as gone if, on this open session, it does not answer for
// the bound serial. Where nothing waits on the answer the card is not asked.
func (provider *Provider) goneUnlessItAnswers(ctx context.Context, session Session, binding registry.Binding) {
	if provider.returned.Required() && !answers(ctx, session, binding.DeviceSerial) {
		provider.returned.Gone(binding.DeviceID)
	}
}

// answers reports whether the card behind an open session still answers as the bound card. Asked
// after a call on it failed, to tell a card that has gone from one that refused the request.
//
// IT IS NOT ASKED UNDER THE REQUEST'S CONTEXT. A request that was cancelled, or ran out of time,
// fails, and a session refuses every call made under a context that has ended: asked under it, a
// card that is there would look gone, and a caller could take it out of service by hanging up in
// the middle of a request. The context it is asked under is live and detached from the request's.
// That does not bound the read: on a card, reading the serial is one PC/SC exchange that nothing
// here can interrupt, as every other card call is, and it is made while the turn is held.
func answers(ctx context.Context, session Session, serial string) (answered bool) {
	defer func() {
		if recover() != nil {
			answered = false // a session that panics is not answering
		}
	}()
	own, cancel := context.WithTimeout(context.WithoutCancel(ctx), answerTimeout)
	defer cancel()
	got, err := session.Identity(own)
	return err == nil && got == serial
}

// answerTimeout is the deadline of the context answers asks under. A session looks at it before it
// talks to the card, not while.
const answerTimeout = 5 * time.Second

// closed closes a session. A session that panics while closing has not closed.
func closed(session Session) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnavailable
		}
	}()
	return session.Close()
}

// takeTurn makes PIV requests wait for each other.
//
// A CARD IS OPENED FOR EXCLUSIVE USE, ONE REQUEST AT A TIME. A YubiKey that holds several keys gets
// requests for them at the same moment, and so does any key under load. Without this the second
// request's Open found the card taken and failed as "unavailable": on the bench, nine of twelve
// simultaneous signatures on one card were refused that way (regalia#541).
//
// THERE IS ONE TURN FOR ALL CARDS, NOT ONE PER CARD. The driver finds its card by opening every
// reader in turn to read its serial, exclusively, so a request for one YubiKey briefly holds the
// others; a turn per device would let two requests collide there. A PIV signature takes about a
// tenth of a second, which is what this costs.
//
// A request waits as long as its own context allows, and one that gives up never touches a card.
// It returns the function that ends the turn, or false when the context ended first.
func (provider *Provider) takeTurn(ctx context.Context) (func(), bool) {
	done := func() { <-provider.turn }
	select {
	case provider.turn <- struct{}{}:
		return done, true
	default:
	}
	// waiting counts the requests parked here, so that a test can know they have arrived instead
	// of guessing with a sleep.
	provider.waiting.Add(1)
	defer provider.waiting.Add(-1)
	select {
	case provider.turn <- struct{}{}:
		return done, true
	case <-ctx.Done():
		return nil, false
	}
}

func (provider *Provider) notePINRetries(deviceID string, retries int) {
	provider.mu.Lock()
	if provider.pinReadings == nil {
		provider.pinReadings = make(map[string]pinRetryReading)
	}
	provider.pinReadings[deviceID] = pinRetryReading{retries: retries, at: time.Now().UTC()}
	provider.mu.Unlock()
}

func (provider *Provider) forgetPINRetries(deviceID string) {
	provider.mu.Lock()
	delete(provider.pinReadings, deviceID)
	provider.mu.Unlock()
}

// pinRetries asks the card first and falls back to the last legible reading only
// when the card cannot answer.
//
// THE CARD IS THE ONLY PARTY THAT KNOWS WHEN SOMEBODY ELSE SPENT A RETRY. This read
// used to consult the cache first (#442), so once a reading existed the card was never
// asked again. Any other process's rejected VERIFY — a CI gate run, ykman —
// de-authenticates the card, which makes the counter legible and truthfully lower, and
// a provider answering from its cache presented the PIN into a near-lockout it had been
// told about. Two gate runs spent 3 down to 1 on the staging bench that way.
//
// The fallback is what keeps #405 fixed. The status query is an empty VERIFY (piv-go
// ykPINRetries: INS 0x20, P2 0x80, no data), which consumes no retry. Once THIS
// provider has logged in, the card answers it with 9000 rather than 63Cx, so the count
// is illegible — not zero — and the last legible reading stands in for it. A failed read
// never overwrites that reading, and a device with no reading at all is still refused.
//
// AN ILLEGIBLE COUNT IS ALSO WHAT A CARD THAT HAS GONE GIVES. Where a returned card must wait
// (RequireReauthorization), the earlier reading must not stand in for a card that is no longer
// there: when the read fails the card is asked for its serial on the same connection, and only a
// card that still answers gets the fallback. One that does not is recorded as gone and the read
// fails. Where nothing waits, the fallback is as it was.
func (provider *Provider) pinRetries(ctx context.Context, binding registry.Binding, session Session) (int, error) {
	retries, err := session.PINRetries(ctx)
	if err == nil {
		provider.notePINRetries(binding.DeviceID, retries)
		return retries, nil
	}
	if provider.returned.Required() && !answers(ctx, session, binding.DeviceSerial) {
		provider.returned.Gone(binding.DeviceID)
		return 0, err
	}
	provider.mu.RLock()
	reading, ok := provider.pinReadings[binding.DeviceID]
	provider.mu.RUnlock()
	if ok {
		return reading.retries, nil
	}
	return 0, err
}

func (provider *Provider) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) (output []byte, outputType string, err error) {
	binding := route.Binding
	if binding.Backend != "yubikey-piv" || binding.DeviceID == "" || binding.DeviceSerial == "" || binding.ObjectID == "" ||
		binding.TouchPolicy != "never" || (binding.PINPolicy != "once" && binding.PINPolicy != "always") {
		return nil, "", ErrUnavailable
	}
	if provider.pinBlocked(binding.DeviceID) {
		return nil, "", ErrUnavailable
	}
	done, ok := provider.takeTurn(ctx)
	if !ok {
		return nil, "", ErrUnavailable
	}
	defer done()
	// The latch is read again now that the turn is this request's: the one before it may have just
	// had its PIN refused. Queued behind it, this request would otherwise open the card and
	// present the same PIN a second time, and one bad credential would cost two tries.
	if provider.pinBlocked(binding.DeviceID) {
		return nil, "", ErrUnavailable
	}
	session, err := provider.driver.Open(ctx, binding.DeviceID)
	if err != nil || session == nil {
		provider.notOpened(ctx, binding.DeviceID)
		return nil, "", ErrUnavailable
	}
	defer func() {
		panicked := recover() != nil
		switch {
		case panicked:
			// What state the card is in is not known, and it is not asked: the call that would
			// ask is the code that has just panicked.
			provider.returned.Gone(binding.DeviceID)
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		case err != nil:
			// A request that failed on an open card: gone, or refused? Asked before the session
			// is closed, on the connection the failure happened on. A success needs no question.
			provider.goneUnlessItAnswers(ctx, session, binding)
		}
		if closed(session) != nil {
			// The card did not let go of the connection: what state it is in is not known.
			provider.returned.Gone(binding.DeviceID)
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
	}()
	serial, err := session.Identity(ctx)
	if err != nil || serial != binding.DeviceSerial {
		return nil, "", ErrUnavailable
	}
	pinPolicy, touchPolicy, err := session.Policies(ctx, binding.ObjectID)
	if err != nil || pinPolicy != binding.PINPolicy || touchPolicy != "never" {
		return nil, "", ErrUnavailable
	}
	// A CARD THAT WAS GONE WAITS FOR A FRESH LEASE. Asked once the card has proved to be the bound
	// one, with the key and policies the binding names, and before anything is done with it, the
	// PIN included.
	if !provider.returned.Serves(ctx, binding.DeviceID) {
		return nil, "", ErrUnavailable
	}
	if operation == "public-key" {
		output, err = session.PublicKey(ctx, binding.ObjectID)
		if err != nil || len(output) == 0 {
			zero(output)
			return nil, "", ErrUnavailable
		}
		return output, "application/pkix", nil
	}
	if operation == "wrap" {
		if format != "regalia-envelope-v2" {
			return nil, "", ErrUnavailable
		}
		publicKey, publicErr := session.PublicKey(ctx, binding.ObjectID)
		if publicErr != nil {
			return nil, "", ErrUnavailable
		}
		defer zero(publicKey)
		output, err = keywrap.RSAOAEP(publicKey, data, aad, route.Algorithm)
		if err != nil {
			return nil, "", ErrUnavailable
		}
		return output, "application/vnd.regalia.wrapped-key", nil
	}
	retries, retryErr := provider.pinRetries(ctx, binding, session)
	if retryErr != nil || retries <= 1 {
		if retryErr == nil {
			provider.blockPIN(binding.DeviceID)
		}
		return nil, "", ErrUnavailable
	}
	pin, err := provider.pins.PIN(ctx, binding.DeviceID)
	if err != nil || len(pin) < 6 || len(pin) > 64 {
		zero(pin)
		return nil, "", ErrUnavailable
	}
	defer func() {
		if releaser, ok := provider.pins.(pinReleaser); ok {
			if releaseErr := releaser.Release(pin); releaseErr != nil {
				zero(output)
				output, outputType, err = nil, "", ErrUnavailable
			}
		}
		zero(pin)
	}()
	if session.Login(ctx, pin) != nil {
		provider.forgetPINRetries(binding.DeviceID)
		provider.blockPIN(binding.DeviceID)
		return nil, "", ErrUnavailable
	}
	switch operation {
	case "sign":
		output, err, outputType = executeSign(ctx, session, binding.ObjectID, route.Algorithm, data, contentType)
	case "unwrap":
		if format != "regalia-envelope-v2" && format != "sops-pgp" {
			return nil, "", ErrUnavailable
		}
		var frame []byte
		frame, err = session.Unwrap(ctx, binding.ObjectID, route.Algorithm, data, aad)
		if err == nil {
			defer zero(frame)
			output, err = keywrap.OpenFrame(frame, aad)
		}
		outputType = "application/octet-stream"
	default:
		return nil, "", ErrUnavailable
	}
	if err != nil || len(output) == 0 {
		zero(output)
		return nil, "", ErrUnavailable
	}
	return output, outputType, nil
}

func executeSign(ctx context.Context, session Session, objectID, algorithm string, data []byte, contentType string) ([]byte, error, string) {
	value, err := session.Sign(ctx, objectID, algorithm, data)
	return value, err, contentType
}

func (provider *Provider) Healthy(ctx context.Context, binding registry.Binding) (healthy bool) {
	if binding.Backend != "yubikey-piv" || binding.DeviceSerial == "" || binding.TouchPolicy != "never" {
		return false
	}
	if provider.pinBlocked(binding.DeviceID) {
		return false
	}
	// A health probe waits its turn too: opening the card while a signature is in flight would
	// report a healthy, busy card as unhealthy.
	done, ok := provider.takeTurn(ctx)
	if !ok {
		return false
	}
	defer done()
	if provider.pinBlocked(binding.DeviceID) {
		return false
	}
	session, err := provider.driver.Open(ctx, binding.DeviceID)
	if err != nil || session == nil {
		provider.notOpened(ctx, binding.DeviceID)
		return false
	}
	// As in Execute: a panic, or a session that will not close, leaves a card whose state is not
	// known. It is not healthy, and it waits. A request sent to it would fail on the same close.
	defer func() {
		panicked := recover() != nil
		if closed(session) != nil || panicked {
			provider.returned.Gone(binding.DeviceID)
			healthy = false
		}
	}()
	serial, err := session.Identity(ctx)
	if err != nil || serial != binding.DeviceSerial {
		// It does not answer for the bound serial: the bound card is not there, whether nothing
		// answers or another card does. Execute records the same fact the same way.
		provider.goneUnlessItAnswers(ctx, session, binding)
		return false
	}
	pinPolicy, touchPolicy, err := session.Policies(ctx, binding.ObjectID)
	if err != nil || pinPolicy != binding.PINPolicy || touchPolicy != "never" {
		if err != nil {
			provider.goneUnlessItAnswers(ctx, session, binding)
		}
		return false
	}
	// Present, the right card, and not yet vouched for again: not healthy, so routing and readiness
	// say so. This is also where a card's return is first noticed.
	if !provider.returned.Serves(ctx, binding.DeviceID) {
		return false
	}
	retries, err := provider.pinRetries(ctx, binding, session)
	return err == nil && retries > 1
}

// PINRetriesReadings enumerates the last successful retry-count read per
// device. An absent device has never produced a trustworthy count; a stale
// timestamp is retained rather than replaced by an error or synthetic zero.
func (provider *Provider) PINRetriesReadings() map[string]PINReading {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	readings := make(map[string]PINReading, len(provider.pinReadings))
	for deviceID, reading := range provider.pinReadings {
		readings[deviceID] = PINReading{Retries: reading.retries, At: reading.at}
	}
	return readings
}

type PINReading struct {
	Retries int
	At      time.Time
}

func (provider *Provider) Ready(ctx context.Context) bool {
	return provider != nil && provider.driver != nil && provider.pins != nil && provider.driver.Ready(ctx)
}
func (provider *Provider) ResetPINBlock(deviceID string) {
	provider.mu.Lock()
	delete(provider.blocked, deviceID)
	provider.mu.Unlock()
}
func (provider *Provider) pinBlocked(deviceID string) bool {
	provider.mu.RLock()
	_, blocked := provider.blocked[deviceID]
	provider.mu.RUnlock()
	return blocked
}
func (provider *Provider) blockPIN(deviceID string) {
	provider.mu.Lock()
	provider.blocked[deviceID] = struct{}{}
	provider.mu.Unlock()
}
func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// lockoutLookEvery spaces the looks nameLockout takes: a card that cannot be opened is asked for
// on every request and every health probe, and each look opens every reader.
const lockoutLookEvery = time.Minute

// nameLockout says why, when a card cannot be opened although it is attached: a YubiKey's reader is
// held by another connection. The daemon refuses to start in that state when the card is attached
// then (cmd/regalia-kms, requirePIVCardsOpenBesidePKCS11); a card attached LATER to a daemon whose
// PKCS#11 module does not ignore it meets the same lockout with the daemon running, and without
// this it would fail as "unavailable" with nothing naming the cause. Called with the turn held.
// It returns whether it named the device.
func (provider *Provider) nameLockout(ctx context.Context, deviceID string) bool {
	driver, ok := provider.driver.(reacher)
	if !ok || ctx.Err() != nil {
		return false
	}
	provider.mu.Lock()
	due := provider.lockoutLooked.IsZero() || time.Since(provider.lockoutLooked) >= lockoutLookEvery
	if due {
		provider.lockoutLooked = time.Now()
	}
	provider.mu.Unlock()
	if !due {
		return false
	}
	missing, held, err := driver.Reach(ctx)
	if err != nil || !held {
		return false
	}
	// A held reader cannot be asked which card is in it, so every card that is missing may be the
	// one behind it. All of them are named, as the startup refusal does: with one look a minute for
	// the whole provider, naming only the card this request was for would leave another card's
	// lockout unsaid for as long as this one's requests keep taking the look.
	if !slices.Contains(missing, deviceID) {
		return false
	}
	slog.Error("KMS YubiKey PIV card(s) cannot be opened and another connection holds a YubiKey's reader: one of them is behind it. "+
		"If this daemon also loads a PKCS#11 module, OpenSC must be told to ignore the YubiKey (OPENSC_CONF naming deploy/opensc/ignore-yubikey.conf); otherwise another process is using the card",
		"devices", strings.Join(missing, ", "))
	return true
}

// reacher is a driver that can say, without opening a session, which commissioned cards cannot be
// opened and whether another connection holds a reader (the PIV driver's Reach).
type reacher interface {
	Reach(context.Context) (missing []string, held bool, err error)
}

// Reach asks the driver which commissioned cards cannot be opened and whether another connection
// holds a reader. It takes the turn every request takes. A driver that cannot say reports nothing.
func (provider *Provider) Reach(ctx context.Context) (missing []string, held bool, err error) {
	driver, ok := provider.driver.(reacher)
	if !ok {
		return nil, false, nil
	}
	done, ok := provider.takeTurn(ctx)
	if !ok {
		return nil, false, ErrUnavailable
	}
	defer done()
	return driver.Reach(ctx)
}
