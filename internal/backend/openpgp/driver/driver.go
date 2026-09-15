// Package openpgpdriver is the OpenPGP card protocol layer: the APDU construction,
// response parsing, and PIN discipline for the Driver and Card seams the constrained
// adapter in the parent package consumes.
//
// WHAT THIS PACKAGE IS AND IS NOT (#21). It is production code for the protocol half of
// the driver — every byte below is built and parsed by this package and exercised by
// wire-level tests against a scripted transport, which is a strictly deeper seam than the
// Card-level test doubles the admission layer was built against. It is NOT a qualified
// implementation in the ADR-0001 §4 sense yet. The one boundary this package does not own is the
// transport (Transport below). Its PC/SC binding is openpgp/pcsc, and through it this package has
// run against YubiKey 5C NFC 25923902 (TestOpenPGPPhysicalQualification). That run found the BCD
// serial, the A6 cipher DO and the 6982 wrong-PIN answer below. Positive operations and negative
// controls, exclusive access and PW1-block recovery are recorded; removal is not. Until it is, the daemon
// constructs nothing from this package, and the reachability ledger's unwired-control entry stays
// true.
//
// The protocol references are the OpenPGP card specification (version 3.4 as published;
// the command shapes are stable across 2.x–3.x): SELECT AID §; GET DATA for the
// application related data (tag 6E) and PW status bytes (C4); User Interaction Flag
// (D6 for the signature key, D7 for the confidentiality key); VERIFY with P2 selecting
// the PW1 role (0x81 signing, 0x82 everything else); PSO:CDS 00 2A 9E 9A; PSO:DEC
// 00 2A 80 86 with the padding indicator for RSA and the A6/7F49/86 key-agreement form
// for X25519.
package openpgpdriver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"

	openpgp "github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp"
)

// Transport is ONE card connection's exchange: a command APDU in, the response body and
// status word out. This is the single hardware boundary of the package. The PC/SC binding
// lives in openpgp/pcsc, built only with -tags piv, so this package stays free of cgo.
//
// Transmit returns the response body WITHOUT the status word, and sw separately, because
// a status word like 63 Cx (verification failed, n tries left) carries information in
// both halves and collapsing them loses the half the error message needs.
type Transport interface {
	Transmit(command []byte) (response []byte, sw uint16, err error)
	Close() error
}

// TransportOpener discovers a device and selects the OpenPGP applet on it.
type TransportOpener interface {
	// Open returns a Transport whose FIRST command has already been answered: the caller
	// sends SELECT itself so the AID bytes live in exactly one place — here.
	Open(ctx context.Context, deviceID string) (Transport, error)
	Ready(ctx context.Context) bool
}

// PINSource supplies the applet's PW1. The driver asks per role, because PW1 has two
// verification states on this applet and "the PIN" is ambiguous until the operation names
// which one it needs.
type PINSource interface {
	PW1(ctx context.Context, deviceID, role string) ([]byte, error)
}

var errTransport = errors.New("OpenPGP card transport failed")

// Driver rediscovers the card for every operation, the same discipline as the PIV
// driver: a card removed between operations is an operation that must fail, not one that
// limps on through a stale handle.
type Driver struct {
	opener TransportOpener
	pins   PINSource
}

// NewDriver refuses an openerless or PINless construction: a driver with no PIN source
// would open cards it can never use, and one with no opener is a test double wearing a
// production name.
func NewDriver(opener TransportOpener, pins PINSource) (*Driver, error) {
	if opener == nil {
		return nil, errors.New("an OpenPGP transport opener is required")
	}
	if pins == nil {
		return nil, errors.New("an OpenPGP PW1 source is required")
	}
	return &Driver{opener: opener, pins: pins}, nil
}

// Open selects the applet and returns the Card. The applet is SELECTED here rather than
// by the opener so the AID exists in one place only.
func (driver *Driver) Open(ctx context.Context, deviceID string) (openpgp.Card, error) {
	if err := ctx.Err(); err != nil || driver == nil {
		return nil, openpgp.ErrUnavailable
	}
	transport, err := driver.opener.Open(ctx, deviceID)
	if err != nil || transport == nil {
		return nil, openpgp.ErrUnavailable
	}
	if _, err := selectApplication(transport); err != nil {
		transport.Close()
		return nil, openpgp.ErrUnavailable
	}
	return &card{transport: transport, deviceID: deviceID, pins: driver.pins}, nil
}

func (driver *Driver) Ready(ctx context.Context) bool {
	return driver != nil && driver.opener.Ready(ctx)
}

// card is one selected OpenPGP applet session.
type card struct {
	mu        sync.Mutex
	transport Transport
	deviceID  string
	pins      PINSource

	// PW1 verification states, tracked because the applet does not offer a cheap way to
	// ask and because the discipline differs per role: the 0x82 state authorises every
	// decipher until reset, while 0x81 — when the card is in one-signature mode — is
	// consumed by each PSO:CDS. verified0x81 records what the CARD's PW1 status byte
	// promises, not merely what was sent: in multiple-signature mode one verification
	// holds, and re-sending it would present the PIN more often than the reviewed policy
	// believes it is presented.
	pw1Status        pw1Status
	verifiedSigning  bool
	verifiedDecipher bool
}

type pw1Status struct {
	// multipleSignatures is PW1 status byte [0]: 1 means PW1 0x81 remains valid across
	// signatures; 0 means it is consumed by each PSO:CDS.
	multipleSignatures bool
	loaded             bool
}

// openPGPAID is the OpenPGP application identifier (spec §, RID D2 76 00 01 24, app 01).
var openPGPAID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

func selectApplication(transport Transport) ([]byte, error) {
	command := make([]byte, 0, 5+len(openPGPAID))
	command = append(command, 0x00, 0xA4, 0x04, 0x00, byte(len(openPGPAID)))
	command = append(command, openPGPAID...)
	response, sw, err := transport.Transmit(command)
	if err != nil {
		return nil, errTransport
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("%w: SELECT AID answered %04X", errTransport, sw)
	}
	return response, nil
}

// Status reads the three data objects the adapter's unattended rules turn on: the AID
// (for the serial), the PW status bytes (for the multiple-signature fact), and the two
// User Interaction Flags (for touch). It reads each with its own GET DATA so a card that
// answers one and not the others fails naming the one it failed, and nothing is inferred
// from an object that was not returned.
func (session *card) Status(ctx context.Context) (openpgp.CardStatus, error) {
	if err := ctx.Err(); err != nil {
		return openpgp.CardStatus{}, openpgp.ErrUnavailable
	}
	aid, err := getData(session.transport, 0x4F)
	if err != nil {
		return openpgp.CardStatus{}, openpgp.ErrUnavailable
	}
	serial, err := serialFromAID(aid)
	if err != nil {
		return openpgp.CardStatus{}, openpgp.ErrUnavailable
	}
	pwStatus, err := getData(session.transport, 0xC4)
	if err != nil || len(pwStatus) < 1 {
		return openpgp.CardStatus{}, openpgp.ErrUnavailable
	}
	session.mu.Lock()
	session.pw1Status = pw1Status{multipleSignatures: pwStatus[0] == 1, loaded: true}
	session.mu.Unlock()

	uifSignature, err := getData(session.transport, 0xD6)
	if err != nil {
		return openpgp.CardStatus{}, openpgp.ErrUnavailable
	}
	uifDecryption, err := getData(session.transport, 0xD7)
	if err != nil {
		return openpgp.CardStatus{}, openpgp.ErrUnavailable
	}
	return openpgp.CardStatus{
		Serial:                                 serial,
		SignaturePINValidForMultipleSignatures: pwStatus[0] == 1,
		TouchRequiredForSignature:              interactionRequired(uifSignature),
		TouchRequiredForDecryption:             interactionRequired(uifDecryption),
	}, nil
}

// interactionRequired reads a User Interaction Flag data object: 0 is off, 1 is on,
// 2 is permanently on. Anything a future specification adds is treated as REQUIRED —
// the unattended contract fails closed on facts it cannot classify.
func interactionRequired(uif []byte) bool {
	if len(uif) < 1 {
		return true
	}
	return uif[0] != 0
}

// serialFromAID lifts the card serial from the application identifier. The AID is
// D2 76 00 01 24 01 | version(2) | manufacturer(2) | serial(4) | flags(2), and the serial is
// the four bytes at offset 10. The adapter compares it as a string against the binding's
// pinned device_serial, which is the decimal serial the YubiKey reports everywhere else in
// this repository (ykman, PIV).
//
// THOSE FOUR BYTES ARE BCD ON A YUBIKEY, NOT BINARY. Measured 2026-09-14 on YubiKey 5C NFC
// 25923902 (fw 5.4.3): GET DATA 4F answered D2 76 00 01 24 01 03 04 00 06 25 92 39 02 00 00.
// The first version of this function read the serial bytes as a big-endian integer and reported
// 630339842, so a binding pinning the card's real serial could never match. The scripted
// transport never noticed, because its fixture was built on the same assumption.
//
// Only the manufacturer that has been measured is decoded. The encoding is the manufacturer's
// choice, and ADR-0001 §4 admits a tuple after a physical test, never from a datasheet. Any
// other manufacturer is refused by name rather than decoded by guess.
const manufacturerYubico = 0x0006

// SerialFromAID is serialFromAID for the PC/SC transport, which has to read a card's serial to
// find it before the driver opens it.
func SerialFromAID(aid []byte) (string, error) { return serialFromAID(aid) }

func serialFromAID(aid []byte) (string, error) {
	if len(aid) < 14 {
		return "", fmt.Errorf("%w: AID is %d bytes, too short to carry a serial", errTransport, len(aid))
	}
	if manufacturer := binary.BigEndian.Uint16(aid[8:10]); manufacturer != manufacturerYubico {
		return "", fmt.Errorf("%w: AID manufacturer %04X has no measured serial encoding", errTransport, manufacturer)
	}
	var serial uint64
	for _, packed := range aid[10:14] {
		high, low := packed>>4, packed&0x0F
		if high > 9 || low > 9 {
			return "", fmt.Errorf("%w: AID serial byte %02X is not BCD", errTransport, packed)
		}
		serial = serial*100 + uint64(high)*10 + uint64(low)
	}
	return strconv.FormatUint(serial, 10), nil
}

func getData(transport Transport, tag byte) ([]byte, error) {
	response, sw, err := transport.Transmit([]byte{0x00, 0xCA, 0x00, tag})
	if err != nil {
		return nil, errTransport
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("%w: GET DATA %02X answered %04X", errTransport, tag, sw)
	}
	return response, nil
}

// Sign performs PSO:CDS with the signature key, presenting PW1 0x81 first — and again
// before EVERY signature when the card is in one-signature mode, because that is the
// mode's meaning: the verification state does not survive the operation.
func (session *card) Sign(ctx context.Context, algorithm string, data []byte) ([]byte, error) {
	switch algorithm {
	case "ed25519", "ecdsa", "rsa2048", "rsa3072", "rsa4096":
	default:
		return nil, fmt.Errorf("%w: algorithm %q has no PSO:CDS mapping on this applet", errTransport, algorithm)
	}
	if err := session.verifySigning(ctx); err != nil {
		return nil, err
	}
	signature, err := pso(session.transport, []byte{0x9E, 0x9A}, data)
	if err != nil {
		session.mu.Lock()
		session.verifiedSigning = false
		session.mu.Unlock()
		// Wrapped, not replaced: errors.Is still answers ErrUnavailable and the operator
		// still sees WHICH status word the card gave.
		return nil, fmt.Errorf("%w: PSO:CDS failed: %w", openpgp.ErrUnavailable, err)
	}
	return signature, nil
}

// Decipher performs PSO:DEC with the decryption key, presenting PW1 0x82 first. The
// 0x82 state is not consumed per operation (the asymmetry with 0x81 is the whole reason
// the Card seam has no Login method), so one verification holds for the session.
//
// The two algorithm shapes need different command data: RSA carries the padding
// indicator 0x00 before the ciphertext (the card performs the raw recovery); X25519 key
// agreement wraps the external public key in A6 / 7F49 / 86.
func (session *card) Decipher(ctx context.Context, algorithm string, ciphertext []byte) ([]byte, error) {
	var payload []byte
	switch algorithm {
	case "rsa2048", "rsa3072", "rsa4096":
		payload = make([]byte, 0, 1+len(ciphertext))
		payload = append(payload, 0x00) // padding indicator: no padding, raw RSA recovery
		payload = append(payload, ciphertext...)
	case "cv25519":
		// The external public key arrives as 32 raw X25519 bytes. The card wants it in an 86
		// (external public key) DO, inside the 7F49 public key template, inside the A6 cipher
		// DO. Measured 2026-09-14 on YubiKey 5C NFC 25923902, after VERIFY 82: the form without
		// A6 answered 6A80, and the A6-wrapped form answered 9000 with 32 bytes equal to the
		// X25519 shared secret computed off-card. The first version of this code sent the
		// unwrapped form, and so did its wire test.
		if len(ciphertext) != 32 {
			return nil, fmt.Errorf("%w: X25519 key agreement takes a 32-byte external public key, got %d", errTransport, len(ciphertext))
		}
		payload = make([]byte, 0, 7+32)
		payload = append(payload, 0xA6, 0x24, 0x7F, 0x49, 0x22, 0x86, 0x20)
		payload = append(payload, ciphertext...)
	default:
		return nil, fmt.Errorf("%w: algorithm %q has no PSO:DEC mapping on this applet", errTransport, algorithm)
	}
	if err := session.verifyDecipher(ctx); err != nil {
		return nil, err
	}
	recovered, err := pso(session.transport, []byte{0x80, 0x86}, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: PSO:DEC failed: %w", openpgp.ErrUnavailable, err)
	}
	return recovered, nil
}

func (session *card) Close() error {
	if session == nil || session.transport == nil {
		return nil
	}
	err := session.transport.Close()
	session.transport = nil
	return err
}

// verifySigning presents PW1 0x81, honouring the card's multiple-signature mode: when
// the mode holds, the first successful verification stands for the session; when it does
// not, every signature re-presents. The PIN is never cached — a failed PW1 answer
// refuses the operation rather than retrying a guess.
func (session *card) verifySigning(ctx context.Context) error {
	session.mu.Lock()
	status := session.pw1Status
	already := session.verifiedSigning
	session.mu.Unlock()
	if already && status.loaded && status.multipleSignatures {
		return nil
	}
	if err := session.verify(ctx, 0x81, "signing"); err != nil {
		return err
	}
	session.mu.Lock()
	session.verifiedSigning = true
	session.mu.Unlock()
	return nil
}

func (session *card) verifyDecipher(ctx context.Context) error {
	session.mu.Lock()
	already := session.verifiedDecipher
	session.mu.Unlock()
	if already {
		return nil
	}
	if err := session.verify(ctx, 0x82, "decryption"); err != nil {
		return err
	}
	session.mu.Lock()
	session.verifiedDecipher = true
	session.mu.Unlock()
	return nil
}

// verify sends VERIFY with the named PW1 role and maps the applet's answers: 63 Cx is a
// wrong PIN with x tries left, 69 83 is the method blocked, and anything else is a
// transport-level failure rather than a judgement about the PIN.
func (session *card) verify(ctx context.Context, role byte, roleName string) error {
	pin, err := session.pins.PW1(ctx, session.deviceID, roleName)
	if err != nil || len(pin) == 0 {
		return openpgp.ErrUnavailable
	}
	command := make([]byte, 0, 5+len(pin))
	command = append(command, 0x00, 0x20, 0x00, role, byte(len(pin)))
	command = append(command, pin...)
	_, sw, err := session.transport.Transmit(command)
	if err != nil {
		return openpgp.ErrUnavailable
	}
	switch {
	case sw == 0x9000:
		return nil
	case sw>>8 == 0x63:
		// 63 Cx carries the remaining tries in the low nibble; the high nibble is the
		// constant C. Reading the whole byte reported "194 tries left" for C2 — a
		// diagnosis with no failing state, caught by the wire test that scripted it.
		return fmt.Errorf("%w: PW1 %s refused, %d tries left", openpgp.ErrUnavailable, roleName, sw&0x0F)
	case sw == 0x6982:
		// A YUBIKEY SAYS A WRONG PW1 THIS WAY, NOT WITH 63 Cx. Measured 2026-09-14 on YubiKey 5C NFC
		// 25923902: a wrong PW1 answered 6982 and the try WAS spent (PW status byte 4 went 3 -> 2).
		// Reporting that as an unexplained status word would hide a spent PIN try from the
		// operator, so the count is read back from C4 and named.
		if status, err := getData(session.transport, 0xC4); err == nil && len(status) >= 5 {
			if status[4] == 0 {
				return fmt.Errorf("%w: PW1 %s refused and now blocked; the card requires unblocking before it will verify anything", openpgp.ErrUnavailable, roleName)
			}
			return fmt.Errorf("%w: PW1 %s refused, %d tries left", openpgp.ErrUnavailable, roleName, status[4])
		}
		return fmt.Errorf("%w: PW1 %s refused (6982), and the remaining tries could not be read", openpgp.ErrUnavailable, roleName)
	case sw == 0x6983:
		return fmt.Errorf("%w: PW1 %s is blocked; the card requires unblocking before it will verify anything", openpgp.ErrUnavailable, roleName)
	default:
		return fmt.Errorf("%w: PW1 %s verification answered %04X", openpgp.ErrUnavailable, roleName, sw)
	}
}

// pso sends a Perform Security Operation command with the given P1 P2 and data,
// chaining when the data exceeds a short APDU's Lc and following 61 xx with GET
// RESPONSE, and refusing the two status words that mean "this operation needs a human"
// (68 81 / 68 82 per the specification's User Interaction Flag behaviour) so a
// touch-gated card surfaces as a refusal rather than a mysterious failure.
func pso(transport Transport, p1p2 []byte, data []byte) ([]byte, error) {
	response, sw, err := transmitChained(transport, 0x2A, p1p2[0], p1p2[1], data)
	if err != nil {
		return nil, err
	}
	for sw>>8 == 0x61 {
		more, moreSW, moreErr := transport.Transmit([]byte{0x00, 0xC0, 0x00, 0x00, byte(sw & 0xFF)})
		if moreErr != nil {
			return nil, errTransport
		}
		response = append(response, more...)
		sw = moreSW
	}
	switch {
	case sw == 0x9000:
		return response, nil
	case sw == 0x6881 || sw == 0x6882:
		return nil, fmt.Errorf("%w: the card requested user interaction for a PSO the adapter admitted as unattended (SW %04X)", errTransport, sw)
	default:
		return nil, fmt.Errorf("%w: PSO %02X%02X answered %04X", errTransport, p1p2[0], p1p2[1], sw)
	}
}

// transmitChained sends a case-4 command whose data may exceed one short APDU: every
// block but the last sets CLA bit 0x10 (more commands follow), and only the last carries
// Le. 255 is the largest Lc a short APDU addresses.
func transmitChained(transport Transport, ins, p1, p2 byte, data []byte) ([]byte, uint16, error) {
	const maxShortData = 255
	if len(data) <= maxShortData {
		command := make([]byte, 0, 6+len(data))
		command = append(command, 0x00, ins, p1, p2, byte(len(data)))
		command = append(command, data...)
		command = append(command, 0x00)
		response, sw, err := transport.Transmit(command)
		return response, sw, err
	}
	blocks := (len(data) + maxShortData - 1) / maxShortData
	for index := 0; index < blocks; index++ {
		block := data[index*maxShortData : min((index+1)*maxShortData, len(data))]
		cla := byte(0x00)
		if index < blocks-1 {
			cla = 0x10
		}
		command := append([]byte{cla, ins, p1, p2, byte(len(block))}, block...)
		if index == blocks-1 {
			// Le trails the data, exactly as in the single-block case above; the first
			// version of this put it between Lc and the data, and only the wire-level
			// script caught it — a Card-level double would have modelled the same bug.
			command = append(command, 0x00)
		}
		response, sw, err := transport.Transmit(command)
		if err != nil {
			return nil, 0, errTransport
		}
		if index == blocks-1 {
			return response, sw, nil
		}
		if sw != 0x9000 {
			return nil, 0, fmt.Errorf("%w: chained PSO block %d answered %04X", errTransport, index, sw)
		}
	}
	return nil, 0, errTransport
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// The card's verification-state fields sit behind mu even though the adapter serialises
// operations per card: the fields are written on the Status and verify paths and read on
// the operation paths, and a future caller that overlaps them should get a race, not
// silent torn reads.
