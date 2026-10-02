package nitrokey

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/reauth"
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
	// OffersMechanism reports whether the token lists the mechanism an operation on a key of this
	// algorithm needs: nil, ErrMechanismNotOffered, or another error when it could not be asked. On
	// the interface, like the KEK assertions below, so that a session cannot silently skip it.
	OffersMechanism(ctx context.Context, operation, algorithm string) error
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

	// REAUTHORIZATION AFTER A TOKEN'S ABSENCE (regalia-kms#72, PoC 12.4). Nil unless
	// RequireReauthorization was called. A token that was gone and is back serves again only once
	// the node holds a runtime lease it asked for AFTER the token returned, so that a peer has
	// vouched for the node since. Until then the binding is unavailable and unhealthy; the OS and
	// the rest of the daemon stay up.
	reauthorizer Reauthorizer
	boottime     func() (int64, error)
	// absences is keyed by device id. An entry with returned == false is a token last seen
	// missing; with returned == true it is back and waiting for the lease.
	absences map[string]tokenAbsence
}

// Reauthorizer says whether the node holds a runtime lease it asked for after a moment, given in
// this host's CLOCK_BOOTTIME milliseconds (internal/admission.Gate.RequestedAfter). It is the gate
// every provider takes (internal/backend/reauth), under the name this package has always used.
type Reauthorizer = reauth.Gate

type tokenAbsence struct {
	returned     bool
	returnedAtMs int64
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

// RequireReauthorization makes every token serve only under a runtime lease asked for after the
// token was last seen to arrive. Call it before the provider serves.
//
// EVERY TOKEN STARTS AS JUST ARRIVED. The provider cannot know what happened to a token before this
// process started (a token pulled, the daemon restarted, the token put back would otherwise resume
// on the old lease), so the first time each token is seen it is treated as having returned at
// sinceMs: when this process started, on the boot clock. After a daemon restart key operations
// therefore wait for a lease asked for since; the lease service sees the same start time and asks
// at once (deploy/baremetal/admission.py), and the node's readiness says so meanwhile. sinceMs
// must not be in the future: a start time ahead of the clock would be a lease nobody can ask for.
//
// WHAT COUNTS AS SEEN GONE. A token that cannot be opened. And a token that stopped answering while
// it was open: when a call on an open session fails, the token is asked for its identity again, and
// if it does not answer (the driver looks for the token by serial among the slots and reads it
// afresh: a pulled card is not found), or the session will not close, it is marked gone. A token
// that still answers was not gone: the failure was about the request (a payload the key refuses, a
// malformed blob) or about the caller (it hung up, or its deadline passed). That distinction
// matters, because marking on any failure would let a caller who may sign take a token out of
// service at will, for up to a third of a lease each time.
//
// The question is asked under a context of ITS OWN, not the request's. Every driver call refuses an
// ended context, so under the request's context a caller that disconnects mid-signature, or a
// request that reaches its deadline, would make the token look gone.
//
// Two limits of the question. The driver refuses to pick a slot while ANOTHER slot's token answers
// with an error, so a refused request that coincides with a second token misbehaving costs this one
// a renewal. And a token pulled and put back within the one failed call answers, and is not seen.
//
// WHAT IT CANNOT SEE: an absence nobody looked during. Every routing decision and every readiness
// probe opens the token, so the window is the gap between two of those.
func (provider *Provider) RequireReauthorization(gate Reauthorizer, boottime func() (int64, error), sinceMs int64) error {
	if gate == nil || boottime == nil {
		return errors.New("reauthorization needs the admission gate and the boot clock")
	}
	now, err := boottime()
	if err != nil {
		return errors.New("reauthorization cannot read the boot clock")
	}
	if sinceMs <= 0 || sinceMs > now {
		return errors.New("reauthorization needs the time this process started, on the boot clock and not in the future")
	}
	started := sinceMs
	provider.mu.Lock()
	defer provider.mu.Unlock()
	provider.reauthorizer, provider.boottime = gate, boottime
	provider.absences = map[string]tokenAbsence{"": {returned: true, returnedAtMs: started}}
	return nil
}

// gates reports whether reauthorization is required at all.
func (provider *Provider) gates() bool {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	return provider.reauthorizer != nil
}

// stillAnswersWithin bounds the question stillAnswers asks: long enough for a token that is there,
// short enough that a failed request does not hold its caller.
const stillAnswersWithin = 5 * time.Second

// stillAnswers asks the token for its identity again after a call on it failed. A token that was
// pulled is not found. A driver that panics is not answering either. The context is the question's
// own: the request's may already be cancelled or past its deadline, and that says nothing about the
// token.
func stillAnswers(ctx context.Context, session Session) (answers bool) {
	defer func() {
		if recover() != nil {
			answers = false
		}
	}()
	own, cancel := context.WithTimeout(context.WithoutCancel(ctx), stillAnswersWithin)
	defer cancel()
	_, _, err := session.Identity(own)
	return err == nil
}

// goneUnlessTheRequestEnded is what a failed Open means. The driver refuses to open anything under a
// context that has ended, so a request that arrives already cancelled, or past its deadline, fails
// here with the token in place: that says nothing about the token, and marking it gone would let a
// caller who hangs up take every key on it out of service until the next renewal. Under a live
// context a failed Open is the token not being there. A token that IS gone while a request ends is
// marked by the next look made under a live context: the health check of the next routing decision.
func (provider *Provider) goneUnlessTheRequestEnded(ctx context.Context, deviceID string) {
	if ctx.Err() == nil {
		provider.tokenGone(deviceID)
	}
}

// tokenGone records that a token could not be opened, or stopped answering while it was open.
// Whatever lease the node holds now was asked for before the token comes back.
func (provider *Provider) tokenGone(deviceID string) {
	provider.mu.Lock()
	defer provider.mu.Unlock()
	// "" is not a device: it is the key the baseline for never-seen devices is kept under.
	if provider.reauthorizer != nil && deviceID != "" {
		provider.absences[deviceID] = tokenAbsence{}
	}
}

// reauthorized reports whether a token that has just been opened, and has proved to be the right
// one, may serve. The first time it is seen back, that moment is recorded; it serves once the node
// holds a lease asked for after it.
func (provider *Provider) reauthorized(ctx context.Context, deviceID string) bool {
	provider.mu.Lock()
	gate := provider.reauthorizer
	if gate == nil {
		provider.mu.Unlock()
		return true
	}
	if deviceID == "" { // not a device: the baseline's own key, which serving must never overwrite
		provider.mu.Unlock()
		return false
	}
	absence, known := provider.absences[deviceID]
	if !known {
		// never seen in this process: it arrived, at the earliest, when reauthorization was required
		absence = provider.absences[""]
	}
	if !absence.returned {
		now, err := provider.boottime()
		if err != nil {
			provider.mu.Unlock()
			return false
		}
		absence = tokenAbsence{returned: true, returnedAtMs: now}
	}
	provider.absences[deviceID] = absence
	provider.mu.Unlock()
	if !gate.RequestedAfter(ctx, absence.returnedAtMs) {
		return false
	}
	provider.mu.Lock()
	// cleared only if nothing changed meanwhile: a token that went away again during the check stays marked
	if current, still := provider.absences[deviceID]; still && current == absence {
		provider.absences[deviceID] = tokenAbsence{returned: true, returnedAtMs: -1}
	}
	provider.mu.Unlock()
	return true
}

// AwaitingReauthorization lists the devices that are present but not yet serving, each with the
// CLOCK_BOOTTIME (ms) since which a lease must have been asked for, and the devices last seen
// missing (-1). For the log and the metrics surface.
func (provider *Provider) AwaitingReauthorization() map[string]int64 {
	provider.mu.RLock()
	defer provider.mu.RUnlock()
	waiting := map[string]int64{}
	for device, absence := range provider.absences {
		switch {
		case device == "":
		case !absence.returned:
			waiting[device] = -1
		case absence.returnedAtMs >= 0:
			waiting[device] = absence.returnedAtMs
		}
	}
	return waiting
}

func (provider *Provider) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) (output []byte, outputType string, err error) {
	binding := route.Binding
	if !servedBackend(binding.Backend) || binding.DeviceID == "" || binding.ObjectID == "" || !identifiable(binding) {
		return nil, "", ErrUnavailable
	}
	// THE OPENPGP APPLET SIGNS WITH ED25519, AND DOES NOTHING ELSE HERE. Its capability row also
	// lists unwrap, which belongs to the legacy sops-pgp path this driver does not implement, and
	// RSA keys, which belong on an HSM: the applet is served for the one algorithm no HSM offers.
	// Refused before the token is opened, so no PIN is presented for what cannot be served.
	if binding.Backend == OpenPGPAppletBackend && (route.Algorithm != "ed25519" || (operation != "sign" && operation != "public-key")) {
		return nil, "", ErrUnavailable
	}
	if provider.pinBlocked(binding.DeviceID) {
		return nil, "", ErrUnavailable
	}
	session, err := provider.driver.Open(ctx, binding)
	if err != nil || session == nil {
		provider.goneUnlessTheRequestEnded(ctx, binding.DeviceID)
		return nil, "", ErrUnavailable
	}
	// gated is set once this token has passed the reauthorization check below: from then on, a
	// failure is looked at to see whether the token itself went away (RequireReauthorization).
	gated := false
	defer func() {
		panicked := recover() != nil
		if panicked {
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
		if gated && (panicked || (err != nil && !stillAnswers(ctx, session))) {
			provider.tokenGone(binding.DeviceID)
		}
		if closeErr := session.Close(); closeErr != nil {
			if gated {
				provider.tokenGone(binding.DeviceID)
			}
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
	}()
	// A DEVICE ANSWERING WITH THE WRONG IDENTITY IS A SWAP, NOT A GLITCH. Failing only this call
	// would let the next one try again against whatever is now in the slot, so the key is latched
	// out of service until an operator clears it. An unreadable identity latches too: "cannot prove
	// which device this is" is not a safer state than "provably the wrong one".
	if reason := verifyIdentity(ctx, session, binding); reason != "" {
		provider.quarantine(binding.DeviceID, reason)
		return nil, "", ErrUnavailable
	}
	if err := session.EstablishSecureChannel(ctx); err != nil {
		// A channel that will not establish is a downgrade: everything after this would travel
		// unprotected, so the key is latched rather than used over it.
		provider.quarantine(binding.DeviceID, "secure-channel-failed")
		return nil, "", ErrUnavailable
	}
	if reason := verifyPinnedPublicKey(ctx, session, binding); reason != "" {
		provider.quarantine(binding.DeviceID, reason)
		return nil, "", ErrUnavailable
	}
	// A TOKEN THAT WAS GONE WAITS FOR A FRESH LEASE (#72 PoC 12.4). Checked after the identity and
	// the pinned key, so that a different card in the slot is still quarantined as a swap and only
	// the RIGHT token, back, is what waits; and before anything is done with it, the PIN included.
	if !provider.reauthorized(ctx, binding.DeviceID) {
		return nil, "", ErrUnavailable
	}
	gated = provider.gates()
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
		//
		// WHERE THAT IS PROVEN depends on what the binding pins (ADR-0002 D1). A binding that pins
		// the KEK's public key had its provenance verified ONCE, at commissioning, from the card's
		// own attestation (EF CExx, hsm-key-attestation-verify.py) — which PKCS#11 cannot reach —
		// and verifyPinnedPublicKey above has just confirmed this is that key. Asking CKA_LOCAL
		// again would only get the answer #447 measured: on an SC-HSM it tracks whether a
		// certificate exists, not where the key was born. A binding without that pin still gets the
		// runtime check, which is all it has.
		if _, pinned := pinnedPublicKey(binding); !pinned {
			if err := session.AssertKEKGeneratedOnToken(ctx, binding.ObjectID); err != nil {
				provider.quarantine(binding.DeviceID, kekReason(err, ErrKEKNotTokenGenerated, "kek-not-token-generated"))
				return nil, "", ErrUnavailable
			}
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
	// A TOKEN THAT DOES NOT OFFER THE MECHANISM IS NOT GIVEN THE PIN. The answer is permanent for
	// this object on this token, so nothing is gained by logging in to be told so again, and an
	// answer that could not be read is refused the same way. The device is NOT latched: the fault is
	// in one object's binding, and latching would let whoever may call that object take every other
	// key on the token out of service. The daemon names the object at startup when the token is
	// attached then (requireTokensOfferBoundMechanisms). When it is not, this refusal is all there
	// is: the caller sees the same retryable "unavailable" as before, and nothing names the cause.
	// What changed for that case is that the PIN is no longer presented for it.
	if session.OffersMechanism(ctx, operation, route.Algorithm) != nil {
		return nil, "", ErrUnavailable
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

// servedBackend reports the backend names this provider answers for. Whether the OpenPGP applet is
// actually served is the driver's decision (ServeLocalTokens): the provider only declines names
// that are not PKCS#11 tokens at all.
func servedBackend(name string) bool {
	return name == smartCardHSMBackend || name == OpenPGPAppletBackend
}

func (provider *Provider) Healthy(ctx context.Context, binding registry.Binding) (healthy bool) {
	if !servedBackend(binding.Backend) || !identifiable(binding) {
		return false
	}
	if provider.pinBlocked(binding.DeviceID) {
		return false
	}
	session, err := provider.driver.Open(ctx, binding)
	if err != nil || session == nil {
		provider.goneUnlessTheRequestEnded(ctx, binding.DeviceID)
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
	gated := false
	defer func() {
		if session.Close() != nil {
			if gated {
				provider.tokenGone(binding.DeviceID)
			}
			healthy = false
		}
	}()
	if reason := verifyIdentity(ctx, session, binding); reason != "" {
		provider.quarantine(binding.DeviceID, reason)
		return false
	}
	if session.EstablishSecureChannel(ctx) != nil {
		provider.quarantine(binding.DeviceID, "secure-channel-failed")
		return false
	}
	if reason := verifyPinnedPublicKey(ctx, session, binding); reason != "" {
		provider.quarantine(binding.DeviceID, reason)
		return false
	}
	// Present, the right token, and not yet vouched for again: not healthy, so routing and
	// readiness say so, and this is also where its return is first noticed.
	if !provider.reauthorized(ctx, binding.DeviceID) {
		return false
	}
	gated = provider.gates()
	retries, err := session.PINRetries(ctx)
	if err == nil {
		provider.notePINRetries(binding.DeviceID, retries)
	} else if gated && !stillAnswers(ctx, session) {
		provider.tokenGone(binding.DeviceID)
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

// DEVICE IDENTITY (ADR-0002 D1). What a binding can pin, and what the daemon can check at runtime:
//
//   - device_serial, always — PKCS#11 reports it (CK_TOKEN_INFO).
//   - devaut_fingerprint, when the token exposes its device certificate as a PKCS#11 object. A
//     genuine SmartCard-HSM does not: it keeps C.DevAut in EF 2F02, which only an APDU reaches
//     (regalia#448, measured on DENK0404144). Its genuineness is verified at commissioning instead.
//   - public_key_sha256 — "sha256:" + the SHA-256 of the bound object's public key exactly as
//     PublicKey returns it — recorded at commissioning, after the card's attestation proved the key
//     was generated on it. Checking it here proves this is still that key on that card: a swapped
//     card cannot carry the same private key, because the hardware will not let it out.
//
// A binding must pin the serial and at least one of the other two. Whatever it pins is enforced.
var publicKeyPinPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func pinnedPublicKey(binding registry.Binding) (string, bool) {
	return binding.PublicKeySHA256, publicKeyPinPattern.MatchString(binding.PublicKeySHA256)
}

func identifiable(binding registry.Binding) bool {
	_, pinned := pinnedPublicKey(binding)
	return binding.DeviceSerial != "" && (binding.DevAuthFingerprint != "" || pinned)
}

// verifyIdentity returns a quarantine reason, or "" when the device is the one the binding names.
func verifyIdentity(ctx context.Context, session Session, binding registry.Binding) string {
	serial, devaut, err := session.Identity(ctx)
	if err != nil || serial != binding.DeviceSerial {
		return "identity-mismatch"
	}
	// A pinned DevAut must still match. A token that exposes none reports "", which cannot equal a
	// pinned "sha256:…" — so pinning one keeps the strict check wherever it is actually possible.
	if binding.DevAuthFingerprint != "" && devaut != binding.DevAuthFingerprint {
		return "identity-mismatch"
	}
	return ""
}

// verifyPinnedPublicKey returns a quarantine reason, or "" when the binding pins no public key or
// the bound object's public key hashes to the pin. Unreadable is refused like wrong: "cannot show
// this is the commissioned key" is not safer than "provably another key".
func verifyPinnedPublicKey(ctx context.Context, session Session, binding registry.Binding) string {
	pin, pinned := pinnedPublicKey(binding)
	if binding.PublicKeySHA256 != "" && !pinned {
		return "public-key-mismatch"
	}
	if !pinned {
		return ""
	}
	publicKey, err := session.PublicKey(ctx, binding.ObjectID)
	if err != nil || len(publicKey) == 0 {
		return "public-key-mismatch"
	}
	sum := sha256.Sum256(publicKey)
	if subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(pin)) != 1 {
		return "public-key-mismatch"
	}
	return ""
}
