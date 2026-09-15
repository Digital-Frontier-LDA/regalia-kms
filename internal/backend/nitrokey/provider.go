package nitrokey

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

var ErrUnavailable = errors.New("Nitrokey backend unavailable")

// kekReason names the latch truthfully.
//
// BOTH OUTCOMES STILL REFUSE AND STILL LATCH -- "cannot prove this KEK is hardware-rooted" is not
// a safer state than "provably is not", the same reasoning as the identity-mismatch latch below.
// What differs is what the operator is told. A read failure reported as "kek-exportable" sends
// someone to re-provision a key that may be perfectly good, and the argument for keeping the two
// definitive reasons apart -- that they lead to different remedies -- applies just as much to the
// third case. A reason string is a diagnosis, and a confident wrong one costs more than an
// uncertain right one.
func kekReason(err, definitive error, definitiveReason string) string {
	if errors.Is(err, definitive) {
		return definitiveReason
	}
	return "kek-provenance-unreadable"
}

type PINSource interface {
	PIN(context.Context, string) ([]byte, error)
}

type pinReleaser interface{ Release([]byte) error }

// Driver is implemented by the OpenSC/PKCS#11 boundary. Every Open returns an
// isolated session; no raw session or mechanism choice crosses into the API.
type Driver interface {
	Open(context.Context, registry.Binding) (Session, error)
	Ready(context.Context) bool
}

type Session interface {
	Identity(context.Context) (deviceSerial, devAuthFingerprint string, err error)
	EstablishSecureChannel(context.Context) error
	PINRetries(context.Context) (int, error)
	Login(context.Context, []byte) error
	Sign(context.Context, string, string, []byte) ([]byte, error)
	// Wrap is the inverse of Unwrap. It exists for symmetry so an end-to-end round trip can be
	// exercised in tests against a real token, but it is intentionally NOT advertised by
	// provider.Execute or the capability matrix: the wrap side of a symmetric KEK is an open
	// design question (#194), and the matrix entry for aes-256 is unwrap-only. A test that
	// reaches Wrap is reaching the driver directly, not through the public surface.
	Wrap(context.Context, string, string, []byte, []byte) ([]byte, error)
	Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error)
	// Derive performs ECDH on the token against a peer public key. The card never releases the
	// private key, and the raw shared secret never leaves this package: see the key-agreement
	// branch in Execute.
	Derive(context.Context, string, string, []byte) ([]byte, error)
	PublicKey(context.Context, string) ([]byte, error)
	// AssertKEKGeneratedOnToken and AssertKEKNonExportable answer #6's "production KEKs are
	// non-exportable hardware keys". They are on the interface rather than probed for with a
	// type assertion so that a session which cannot answer fails to compile: an optional
	// safety check is one a new implementation silently skips, and the skip is invisible.
	AssertKEKGeneratedOnToken(context.Context, string) error
	AssertKEKNonExportable(context.Context, string) error
	Close() error
}

type Provider struct {
	driver Driver
	pins   PINSource
	mu     sync.RWMutex
	// blocked latches a device out of service, keyed by device id, with the reason it was
	// latched. A latch is deliberately sticky: the conditions that set it — a spent PIN budget, a
	// device answering with the wrong identity, a secure channel that would not establish — are
	// not things to retry into. Clearing one is an explicit operator act.
	blocked map[string]string
	// pinReadings caches the last successful PIN-retry read per device, with when it
	// happened. A metrics scrape must not round-trip the token, so the gauge serves
	// this cache; a read that fails updates nothing, because an aging timestamp is
	// the signal that the number is stale.
	pinReadings map[string]pinRetryReading
}

type pinRetryReading struct {
	retries int
	at      time.Time
}

func New(driver Driver, pins PINSource) (*Provider, error) {
	if driver == nil || pins == nil {
		return nil, errors.New("Nitrokey driver and PIN source are required")
	}
	return &Provider{driver: driver, pins: pins, blocked: make(map[string]string), pinReadings: make(map[string]pinRetryReading)}, nil
}

// notePINRetries records a successful retry-count read. Only successes move the
// cache: the point of carrying the timestamp is that a failing token goes stale
// instead of impersonating a fresh reading.
func (provider *Provider) notePINRetries(deviceID string, retries int) {
	provider.mu.Lock()
	provider.pinReadings[deviceID] = pinRetryReading{retries: retries, at: time.Now().UTC()}
	provider.mu.Unlock()
}

func (provider *Provider) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) (output []byte, outputType string, err error) {
	binding := route.Binding
	if binding.Backend != "nitrokey-pkcs11" || binding.DeviceID == "" || binding.ObjectID == "" ||
		binding.DeviceSerial == "" || binding.DevAuthFingerprint == "" {
		return nil, "", ErrUnavailable
	}
	if provider.pinBlocked(binding.DeviceID) {
		return nil, "", ErrUnavailable
	}
	session, err := provider.driver.Open(ctx, binding)
	if err != nil || session == nil {
		return nil, "", ErrUnavailable
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
		if closeErr := session.Close(); closeErr != nil {
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
	}()
	serial, devaut, err := session.Identity(ctx)
	if err != nil || serial != binding.DeviceSerial || devaut != binding.DevAuthFingerprint {
		// A DEVICE ANSWERING WITH THE WRONG IDENTITY IS A SWAP, NOT A GLITCH. Failing only this
		// call would let the next one try again against whatever is now in the slot, so the key is
		// latched out of service until an operator clears it. An unreadable identity latches too:
		// "cannot prove which device this is" is not a safer state than "provably the wrong one".
		provider.quarantine(binding.DeviceID, "identity-mismatch")
		return nil, "", ErrUnavailable
	}
	if err := session.EstablishSecureChannel(ctx); err != nil {
		// A channel that will not establish is a downgrade: everything after this would travel
		// unprotected, so the key is latched rather than used over it.
		provider.quarantine(binding.DeviceID, "secure-channel-failed")
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
	// key-agreement is NOT handled here. It needs the private key, so it lives in the switch
	// below the login. See the case for why that is not a style choice.
	if operation == "wrap" {
		if format != "regalia-envelope-v2" {
			return nil, "", ErrUnavailable
		}
		// A KEK THAT WAS NOT BORN ON THIS TOKEN IS NOT A HARDWARE-ROOTED KEK. Latched rather
		// than failed, for the same reason as identity-mismatch above: the condition is a
		// provisioning fault, not a glitch, and retrying would seal to it again.
		if err := session.AssertKEKGeneratedOnToken(ctx, binding.ObjectID); err != nil {
			provider.quarantine(binding.DeviceID, kekReason(err, ErrKEKNotTokenGenerated, "kek-not-token-generated"))
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
	retries, retryErr := session.PINRetries(ctx)
	if retryErr == nil {
		provider.notePINRetries(binding.DeviceID, retries)
	}
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
	if err := session.Login(ctx, pin); err != nil {
		provider.blockPIN(binding.DeviceID)
		return nil, "", ErrUnavailable
	}
	switch operation {
	case "key-agreement":
		// THIS RAN BEFORE THE LOGIN AND COULD NOT EVER HAVE WORKED ON A REAL TOKEN.
		//
		// It sat with public-key and wrap, above the PIN block, and those two belong there: they
		// need only public objects. ECDH needs the private key, and PKCS#11 hides private objects
		// from a logged-out session, so every key-agreement request against a real module failed
		// as DEPENDENCY_UNAVAILABLE while the capability matrix advertised p256 and p384 for it.
		//
		// Measured on SoftHSM, same session, same key, same peer:
		//
		//	derive BEFORE login: PKCS#11 key agreement unavailable
		//	derive AFTER login:  32 bytes, no error
		//
		// Nothing caught it because every key-agreement test in the package runs against a fake
		// session, and a fake has no login state to be wrong about.
		//
		// The same trap applies to session.Wrap on aes-256: a CKO_SECRET_KEY is private, so the
		// caller must have reached this point (past the Login on line 204) before routing there.
		// See pkcs11_driver.go:354 for the wrap-side comment, and the cross-reference at the
		// door of the switch below.
		if len(aad) == 0 {
			// Context binding is mandatory. Without it the derivation is unbound and reusable.
			return nil, "", ErrUnavailable
		}
		var shared []byte
		shared, err = session.Derive(ctx, binding.ObjectID, route.Algorithm, data)
		if err != nil || len(shared) == 0 {
			zero(shared)
			return nil, "", ErrUnavailable
		}
		defer zero(shared)
		// THE RAW SHARED SECRET IS NEVER RETURNED. An ECDH result is a curve point coordinate: it
		// is secret but not uniformly random, and handing it to a caller invites it to be used
		// directly as a key. HKDF turns it into a uniform key, and binding the request context
		// into the info parameter means the same peer key under a different context yields a
		// different key, so a derived key cannot be repurposed for another operation.
		output, err = hkdf.Key(sha256.New, shared, nil, string(aad), 32)
		outputType = "application/vnd.regalia.derived-key"
	case "sign":
		output, err = session.Sign(ctx, binding.ObjectID, route.Algorithm, data)
		outputType = contentType
	case "unwrap":
		if format != "regalia-envelope-v2" && format != "sops-pgp" {
			return nil, "", ErrUnavailable
		}
		// Asked here and not at wrap because the private object is invisible to a logged-out
		// session, and this path has already logged in.
		if assertErr := session.AssertKEKNonExportable(ctx, binding.ObjectID); assertErr != nil {
			provider.quarantine(binding.DeviceID, kekReason(assertErr, ErrKEKExportable, "kek-exportable"))
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

func (provider *Provider) Healthy(ctx context.Context, binding registry.Binding) (healthy bool) {
	if binding.Backend != "nitrokey-pkcs11" || binding.DeviceSerial == "" || binding.DevAuthFingerprint == "" {
		return false
	}
	if provider.pinBlocked(binding.DeviceID) {
		return false
	}
	session, err := provider.driver.Open(ctx, binding)
	if err != nil || session == nil {
		return false
	}
	// A session that will not close means this device cannot serve, so Healthy must not
	// report it as one that can. Execute already treats the identical failure as fatal --
	// its deferred close feeds pkcs11Session.Close's refusal back as ErrUnavailable -- so
	// discarding it here only made routing keep selecting a device on which every request
	// then failed, which is the worst of the two: the fault stays invisible in the health
	// signal and visible only as unexplained operation failures. When C_Logout is the half
	// that failed, what is left behind is an authenticated session on the card.
	//
	// This deliberately does NOT quarantine. Identity mismatch and a secure channel that
	// will not establish latch until an operator calls ResetPINBlock, because they mean the
	// wrong device or a broken trust setup and no amount of retrying fixes either. A close
	// failure may be transient, and Healthy is re-evaluated on EVERY routing decision --
	// registry.safeHealthy is called from Route, RouteForUnwrap and Ready, with no cache and
	// no latch -- so returning false skips the device exactly while it is failing and stops
	// skipping it the moment it recovers, with no operator action. See #312.
	defer func() {
		if session.Close() != nil {
			healthy = false
		}
	}()
	serial, devaut, err := session.Identity(ctx)
	if err != nil || serial != binding.DeviceSerial || devaut != binding.DevAuthFingerprint {
		provider.quarantine(binding.DeviceID, "identity-mismatch")
		return false
	}
	if session.EstablishSecureChannel(ctx) != nil {
		provider.quarantine(binding.DeviceID, "secure-channel-failed")
		return false
	}
	retries, err := session.PINRetries(ctx)
	if err == nil {
		provider.notePINRetries(binding.DeviceID, retries)
	}
	return err == nil && retries > 1
}

func (provider *Provider) Ready(ctx context.Context) bool {
	return provider != nil && provider.driver != nil && provider.pins != nil && provider.driver.Ready(ctx)
}

// ResetPINBlock is an explicit operator action after the credential and device
// retry state have been independently checked. No timer automatically retries a
// possibly wrong credential.
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
	provider.quarantine(deviceID, "pin-budget-spent")
}

// quarantine latches a device out of service. The FIRST reason wins: the earliest fault is the one
// worth reporting, and a later symptom must not overwrite the cause.
//
// A latch is deliberately sticky. The conditions that set it — a spent PIN budget, a device
// answering with the wrong identity, a secure channel that would not establish — are not states to
// retry into, so returning the device to service is an explicit operator act.
func (provider *Provider) quarantine(deviceID, reason string) {
	provider.mu.Lock()
	if _, exists := provider.blocked[deviceID]; !exists {
		provider.blocked[deviceID] = reason
	}
	provider.mu.Unlock()
}

// QuarantineReason reports why a device is latched, so the condition is diagnosable rather than
// surfacing only as an unavailable backend.
func (provider *Provider) QuarantineReason(deviceID string) (string, bool) {
	provider.mu.RLock()
	reason, blocked := provider.blocked[deviceID]
	provider.mu.RUnlock()
	return reason, blocked
}

// Quarantined enumerates every latched device with its reason. The latch existed
// before this accessor did, and without it a device out of service was only
// discoverable one failing operation at a time.
func (provider *Provider) Quarantined() map[string]string {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	out := make(map[string]string, len(provider.blocked))
	for deviceID, reason := range provider.blocked {
		out[deviceID] = reason
	}
	return out
}

// PINReading is one device's last successful PIN-retry read and when it happened.
type PINReading struct {
	Retries int
	At      time.Time
}

// PINRetriesReadings enumerates every device's last successful retry-count read.
// A device absent from the map has never been probed — the honest answer rather
// than a zero that would read as "no retries left".
func (provider *Provider) PINRetriesReadings() map[string]PINReading {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	out := make(map[string]PINReading, len(provider.pinReadings))
	for deviceID, reading := range provider.pinReadings {
		out[deviceID] = PINReading{Retries: reading.retries, At: reading.at}
	}
	return out
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
