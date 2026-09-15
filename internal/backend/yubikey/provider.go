// Package yubikey provides the unattended PIV boundary. It has no operation
// that requests user presence and verifies the slot policy before private use.
package yubikey

import (
	"context"
	"errors"
	"sync"
	"time"

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
}

type pinRetryReading struct {
	retries int
	at      time.Time
}

func New(driver Driver, pins PINSource) (*Provider, error) {
	if driver == nil || pins == nil {
		return nil, errors.New("YubiKey driver and PIN source are required")
	}
	return &Provider{driver: driver, pins: pins, blocked: make(map[string]struct{}), pinReadings: make(map[string]pinRetryReading)}, nil
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
func (provider *Provider) pinRetries(ctx context.Context, deviceID string, session Session) (int, error) {
	retries, err := session.PINRetries(ctx)
	if err == nil {
		provider.notePINRetries(deviceID, retries)
		return retries, nil
	}
	provider.mu.RLock()
	reading, ok := provider.pinReadings[deviceID]
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
	session, err := provider.driver.Open(ctx, binding.DeviceID)
	if err != nil || session == nil {
		return nil, "", ErrUnavailable
	}
	defer func() {
		if recover() != nil {
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
		if session.Close() != nil {
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
	retries, retryErr := provider.pinRetries(ctx, binding.DeviceID, session)
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

func (provider *Provider) Healthy(ctx context.Context, binding registry.Binding) bool {
	if binding.Backend != "yubikey-piv" || binding.DeviceSerial == "" || binding.TouchPolicy != "never" {
		return false
	}
	if provider.pinBlocked(binding.DeviceID) {
		return false
	}
	session, err := provider.driver.Open(ctx, binding.DeviceID)
	if err != nil || session == nil {
		return false
	}
	defer session.Close()
	serial, err := session.Identity(ctx)
	if err != nil || serial != binding.DeviceSerial {
		return false
	}
	pinPolicy, touchPolicy, err := session.Policies(ctx, binding.ObjectID)
	if err != nil || pinPolicy != binding.PINPolicy || touchPolicy != "never" {
		return false
	}
	retries, err := provider.pinRetries(ctx, binding.DeviceID, session)
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
