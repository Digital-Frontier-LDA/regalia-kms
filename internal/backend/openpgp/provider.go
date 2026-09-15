package openpgp

import (
	"context"
	"errors"
	"fmt"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// Driver opens a card. The daemon wires NO implementation of it.
//
// The admission tests below this interface run against test doubles. The implementation in
// openpgp/driver, over the PC/SC transport in openpgp/pcsc (-tags piv), has run against one real
// card: YubiKey 5C NFC 25923902 in TestOpenPGPPhysicalQualification, covering positive operations
// negative controls, exclusive access and PW1-block recovery. Removal is not qualified yet. Writing the
// implementation from the card specification alone would be exactly the "datasheet is not proof of
// compatibility" move ADR-0001 §4 refuses; a (model, firmware, middleware, adapter) tuple is
// eligible only after a physical test records positive operations, negative controls, immutable
// policy metadata, concurrency, removal behaviour and recovery.
//
// The shape mirrors yubikey.Driver/Session deliberately. The PIV adapter is the nearest thing that
// works, and a second card adapter that invented its own lifecycle would make the two impossible to
// review against each other.
type Driver interface {
	Open(ctx context.Context, deviceID string) (Card, error)
	Ready(ctx context.Context) bool
}

// Card is one opened OpenPGP applet.
//
// There is no Login method and that is deliberate. PW1 on this applet is not PIV's PIN: it has two
// separate verification states (0x81 for signing, 0x82 for everything else) that do not satisfy
// each other, so "logged in" is not a property a card has. Presenting the right PW1 for the
// requested operation is the driver's problem, and hiding it behind a single Login would let a
// caller believe a verified decryption PIN authorises a signature. What this interface needs from
// the driver instead is the truth about the card's PIN MODE, which is what Status reports.
type Card interface {
	// Status reports the card's identity and its unattended-operation state.
	Status(ctx context.Context) (CardStatus, error)
	// Sign performs PSO:CDS with the signature key.
	Sign(ctx context.Context, algorithm string, data []byte) ([]byte, error)
	// Decipher performs PSO:DEC with the decryption key, returning the recovered data key.
	Decipher(ctx context.Context, algorithm string, ciphertext []byte) ([]byte, error)
	Close() error
}

// CardStatus is what the adapter must know about a card before it will use one unattended.
//
// These are the facts the registry cannot check. A custody manifest records what the operator
// INTENDED — touch_policy: never, pin_policy: once — and validateBinding enforces that the
// intention is a legal one. Whether the card in the slot actually behaves that way is a different
// claim, and on this applet the two come apart in a way they do not on PIV.
type CardStatus struct {
	// Serial is the card serial, compared against the binding's pinned device_serial.
	Serial string
	// SignaturePINValidForMultipleSignatures is the applet's PW1 status byte for PSO:CDS
	// (OpenPGP card specification 3.4, "PW1 status byte"): false means PW1 is reset after ONE
	// signature and must be presented again for the next one.
	//
	// THIS IS THE FACT THAT BREAKS UNATTENDED OPERATION, AND IT IS INVISIBLE TO THE MANIFEST.
	// A binding may say pin_policy: once — which validateBinding accepts — while the card resets
	// PW1 after every signature. The daemon would then present the PIN far more often than the
	// reviewed policy says it does, or stall, depending on the driver. Either way the deployment
	// is not the one that was approved. It applies to the signature key ONLY; the 0x82 state that
	// authorises PSO:DEC is not consumed per operation, which is why the check below is per slot
	// rather than per card.
	SignaturePINValidForMultipleSignatures bool
	// TouchRequiredForSignature and TouchRequiredForDecryption are the applet's User Interaction
	// Flag for each key. Unattended means no human, so either being set is disqualifying for the
	// slot it names — and only for that slot, because a card may carry a touch-gated signature key
	// and an untouched decryption key at the same time.
	TouchRequiredForSignature  bool
	TouchRequiredForDecryption bool
}

// ErrUnavailable is what leaves this package when a card or driver fails rather than when a rule
// refuses. Refusals wrap ErrRefused; failures wrap this. Callers that cannot tell the two apart
// will report a policy decision as an outage, which sends an operator to look at hardware.
var ErrUnavailable = errors.New("OpenPGP backend unavailable")

// Provider is the constrained adapter. It satisfies backend.Provider; the compile-time assertion
// lives in the test file so this package does not import the one that would import it back.
type Provider struct {
	driver    Driver
	admission *Admission
}

// New refuses a nil driver or a nil admission layer.
//
// A provider with no admission layer would be the unconstrained OpenPGP backend this issue exists
// to prevent, reached by passing nil. There is no "no exceptions configured" convenience default
// for the same reason: NewAdmission(nil, clock) already expresses that, and it expresses it at a
// call site somebody had to write.
func New(driver Driver, admission *Admission) (*Provider, error) {
	if driver == nil {
		return nil, errors.New("an OpenPGP driver is required")
	}
	if admission == nil {
		return nil, errors.New("an admission layer is required: a provider without one is the unconstrained backend this adapter exists to prevent")
	}
	return &Provider{driver: driver, admission: admission}, nil
}

// Execute admits the route, then does the one thing the admitted slot can do.
//
// ADMISSION HAPPENS BEFORE A DEVICE HANDLE EXISTS. Everything refused here is refused without the
// card being opened, which is asserted by TestARefusedRouteNeverReachesTheCard using a Driver whose
// Open fails the test. That ordering is the difference between a limit and a preference: a limit
// enforced after the card is open has already used the card.
func (provider *Provider) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) (output []byte, outputType string, err error) {
	if provider == nil || provider.driver == nil {
		return nil, "", ErrUnavailable
	}
	slot, err := provider.admission.Admit(route, operation)
	if err != nil {
		return nil, "", err
	}
	if err := admitFormat(slot, format); err != nil {
		return nil, "", err
	}
	binding := route.Binding
	if binding.DeviceID == "" || binding.DeviceSerial == "" || binding.ObjectID == "" {
		return nil, "", fmt.Errorf("%w: binding must pin a device, a serial and an object", ErrCardContradictsBinding)
	}
	card, err := provider.driver.Open(ctx, binding.DeviceID)
	if err != nil || card == nil {
		return nil, "", ErrUnavailable
	}
	defer func() {
		if recover() != nil {
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
		if card.Close() != nil {
			zero(output)
			output, outputType, err = nil, "", ErrUnavailable
		}
	}()
	status, err := card.Status(ctx)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	if err := unattended(status, slot, binding); err != nil {
		return nil, "", err
	}
	switch slot {
	case SlotSignature:
		output, err = card.Sign(ctx, route.Algorithm, data)
		outputType = contentType
	case SlotDecryption:
		output, err = card.Decipher(ctx, route.Algorithm, data)
		outputType = "application/octet-stream"
	default:
		// Unreachable while SlotFor returns only the two slots above, and kept because the
		// alternative to a refusal here is a silent nil return that reads as success. A third
		// admitted slot would arrive as a refusal, not as an empty answer.
		return nil, "", fmt.Errorf("%w: slot %q has no operation", ErrOperationNotOnThisApplet, slot)
	}
	if err != nil || len(output) == 0 {
		zero(output)
		return nil, "", ErrUnavailable
	}
	return output, outputType, nil
}

// admitFormat holds unwrap to legacy material.
//
// regalia-envelope-v2 is what /v1/operations/wrap PRODUCES, and this adapter refuses wrap, so no
// regalia envelope can ever have been created against this applet. Accepting one for unwrap would
// therefore mean opening an envelope whose KEK reference names a backend that did not wrap it —
// which is either a manifest error or an attempt to move new material onto the card being retired.
// Both should be refused, and refusing them here costs a legacy consumer nothing: sops-pgp is the
// centralized SOPS integration point (api/README.md) and is the whole reason this backend exists.
func admitFormat(slot Slot, format string) error {
	if slot != SlotDecryption {
		return nil
	}
	if format != "sops-pgp" {
		return fmt.Errorf("%w: unwrap on the OpenPGP applet accepts sops-pgp only, not %q; this backend wraps nothing, so no regalia envelope can name it", ErrLegacyMaterialRequired, format)
	}
	return nil
}

// unattended refuses a card that will not do the slot's work without a human.
//
// Per slot rather than per card, because the two facts are per slot on this applet: the PW1
// multiple-signature state governs PSO:CDS alone, and the User Interaction Flag is set on each key
// independently. A per-card check would refuse a perfectly usable decryption key because the
// signature key beside it is touch-gated.
func unattended(status CardStatus, slot Slot, binding registry.Binding) error {
	if status.Serial != binding.DeviceSerial {
		return fmt.Errorf("%w: card serial does not match the pinned device_serial", ErrCardContradictsBinding)
	}
	switch slot {
	case SlotSignature:
		if status.TouchRequiredForSignature {
			return fmt.Errorf("%w: the signature key has its user interaction flag set while the binding promised touch_policy=never", ErrInteractionRequired)
		}
		// A binding claiming pin_policy: once is claiming the PIN is presented once and then
		// holds. On this applet that is only true when PW1 is valid for several signatures. A
		// binding claiming pin_policy: always makes no such claim and is admitted either way.
		if binding.PINPolicy == "once" && !status.SignaturePINValidForMultipleSignatures {
			return fmt.Errorf("%w: binding says pin_policy=once but the card resets PW1 after one signature; either set the card's PW1 multiple-signature state or record pin_policy=always", ErrCardContradictsBinding)
		}
	case SlotDecryption:
		if status.TouchRequiredForDecryption {
			return fmt.Errorf("%w: the decryption key has its user interaction flag set while the binding promised touch_policy=never", ErrInteractionRequired)
		}
	}
	return nil
}

// Healthy reports whether this binding's card can be used unattended right now.
//
// It answers for the slots the binding could reach, which is both of them: a binding is a key in a
// slot, and Healthy is asked before an operation is chosen. A card that can decrypt but not sign
// unattended is therefore not healthy, which is the conservative direction — the alternative is
// reporting healthy and refusing at the operation.
func (provider *Provider) Healthy(ctx context.Context, binding registry.Binding) bool {
	if provider == nil || provider.driver == nil || binding.Backend != BackendName {
		return false
	}
	if binding.DeviceID == "" || binding.DeviceSerial == "" || binding.TouchPolicy != "never" {
		return false
	}
	card, err := provider.driver.Open(ctx, binding.DeviceID)
	if err != nil || card == nil {
		return false
	}
	defer card.Close()
	status, err := card.Status(ctx)
	if err != nil {
		return false
	}
	for _, slot := range []Slot{SlotSignature, SlotDecryption} {
		if unattended(status, slot, binding) != nil {
			return false
		}
	}
	return true
}

// Ready reports whether the adapter could serve anything at all.
func (provider *Provider) Ready(ctx context.Context) bool {
	return provider != nil && provider.driver != nil && provider.admission != nil && provider.driver.Ready(ctx)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
