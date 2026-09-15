//go:build piv

// Package pcsc is the PC/SC transport for the OpenPGP card driver (#21): the one hardware
// boundary openpgp/driver does not own.
//
// It is built only with -tags piv, the same tag that links the PIV backend's own PC/SC code, so the
// default build stays free of cgo and of pcsclite.
//
// DISCOVERY TOUCHES YUBICO READERS ONLY. Finding a card by serial means SELECTing the OpenPGP
// applet on it, and a SELECT changes that reader's current application. On a host where a
// SmartCard-HSM shares the bus, SELECTing on its reader would pull the HSM out from under whatever
// session holds it. So only readers whose PC/SC name contains "Yubico" are opened. That is also the
// only manufacturer whose AID serial encoding has been measured; see openpgpdriver.SerialFromAID.
// The name is a pre-filter; the serial read from the card is what decides.
//
// THE CHOSEN CARD IS HELD EXCLUSIVELY. The OpenPGP applet's PW1 verification state belongs to the
// connection, and a shared connection would let another process on the host use a state this
// driver created.
package pcsc

/*
#cgo darwin LDFLAGS: -framework PCSC
#cgo linux pkg-config: libpcsclite
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <stdint.h>
#include <stdlib.h>

// Every PC/SC return code is widened through uint32_t, because LONG is 32 bits on macOS and 64 on
// Linux and the error codes have the top bit set.
static int64_t rg_establish(SCARDCONTEXT *ctx) {
	return (int64_t)(uint32_t)SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, ctx);
}
static int64_t rg_release(SCARDCONTEXT ctx) { return (int64_t)(uint32_t)SCardReleaseContext(ctx); }
static int64_t rg_list_size(SCARDCONTEXT ctx, uint32_t *size) {
	DWORD n = 0;
	int64_t rc = (int64_t)(uint32_t)SCardListReaders(ctx, NULL, NULL, &n);
	*size = (uint32_t)n;
	return rc;
}
static int64_t rg_list(SCARDCONTEXT ctx, char *buffer, uint32_t *size) {
	DWORD n = *size;
	int64_t rc = (int64_t)(uint32_t)SCardListReaders(ctx, NULL, buffer, &n);
	*size = (uint32_t)n;
	return rc;
}
static int64_t rg_connect(SCARDCONTEXT ctx, const char *reader, int exclusive, SCARDHANDLE *handle) {
	DWORD protocol = 0;
	return (int64_t)(uint32_t)SCardConnect(ctx, reader,
		exclusive ? SCARD_SHARE_EXCLUSIVE : SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, handle, &protocol);
}
static int64_t rg_disconnect(SCARDHANDLE handle) {
	return (int64_t)(uint32_t)SCardDisconnect(handle, SCARD_LEAVE_CARD);
}
static int64_t rg_begin(SCARDHANDLE handle) { return (int64_t)(uint32_t)SCardBeginTransaction(handle); }
static int64_t rg_end(SCARDHANDLE handle) {
	return (int64_t)(uint32_t)SCardEndTransaction(handle, SCARD_LEAVE_CARD);
}
static int64_t rg_transmit(SCARDHANDLE handle, const unsigned char *command, uint32_t commandLength,
		unsigned char *response, uint32_t *responseLength) {
	DWORD n = *responseLength;
	int64_t rc = (int64_t)(uint32_t)SCardTransmit(handle, SCARD_PCI_T1, command, commandLength, NULL, response, &n);
	*responseLength = (uint32_t)n;
	return rc;
}
*/
import "C"

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	openpgpdriver "github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp/driver"
)

const scardSuccess = 0

// maxResponse is a short APDU's largest answer: 256 data bytes and the status word.
const maxResponse = 258

var openPGPSelect = []byte{0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}
var getAID = []byte{0x00, 0xCA, 0x00, 0x4F}

// Opener finds the card for a device id by the serial pinned for it.
type Opener struct {
	serials map[string]string
}

// NewOpener refuses an empty pin set and any device pinned to an empty serial: an opener that
// would take the first card it sees is exactly the ambiguity the serial exists to remove.
func NewOpener(serials map[string]string) (*Opener, error) {
	if len(serials) == 0 {
		return nil, errors.New("pcsc: at least one device must be pinned to a card serial")
	}
	pinned := make(map[string]string, len(serials))
	for device, serial := range serials {
		if device == "" || serial == "" {
			return nil, fmt.Errorf("pcsc: device %q is pinned to serial %q; both are required", device, serial)
		}
		pinned[device] = serial
	}
	return &Opener{serials: pinned}, nil
}

// Ready reports whether the PC/SC service answers. It says nothing about any card.
func (opener *Opener) Ready(ctx context.Context) bool {
	if opener == nil || ctx.Err() != nil {
		return false
	}
	scard, err := establish()
	if err != nil {
		return false
	}
	defer scard.release()
	_, err = scard.readers()
	return err == nil
}

// Open returns an exclusive connection to the one Yubico card whose OpenPGP AID carries the serial
// pinned for deviceID. None, or more than one, is a refusal.
func (opener *Opener) Open(ctx context.Context, deviceID string) (openpgpdriver.Transport, error) {
	if opener == nil {
		return nil, errors.New("pcsc: no opener")
	}
	want, ok := opener.serials[deviceID]
	if !ok {
		return nil, fmt.Errorf("pcsc: device %q is not pinned", deviceID)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	scard, err := establish()
	if err != nil {
		return nil, err
	}
	readers, err := scard.readers()
	if err != nil {
		scard.release()
		return nil, err
	}
	var matches []string
	for _, reader := range readers {
		if !strings.Contains(reader, "Yubico") {
			continue
		}
		if serial, err := scard.probeSerial(reader); err == nil && serial == want {
			matches = append(matches, reader)
		}
	}
	if len(matches) != 1 {
		scard.release()
		return nil, fmt.Errorf("pcsc: %d Yubico cards carry the serial pinned for %q, want exactly 1", len(matches), deviceID)
	}
	handle, err := scard.connect(matches[0], true)
	if err != nil {
		scard.release()
		return nil, err
	}
	return &transport{scard: scard, handle: handle}, nil
}

type context_ struct{ value C.SCARDCONTEXT }

func establish() (*context_, error) {
	var value C.SCARDCONTEXT
	if rc := C.rg_establish(&value); rc != scardSuccess {
		return nil, fmt.Errorf("pcsc: SCardEstablishContext: %08X", uint32(rc))
	}
	return &context_{value: value}, nil
}

func (scard *context_) release() { C.rg_release(scard.value) }

func (scard *context_) readers() ([]string, error) {
	var size C.uint32_t
	if rc := C.rg_list_size(scard.value, &size); rc != scardSuccess {
		return nil, fmt.Errorf("pcsc: SCardListReaders: %08X", uint32(rc))
	}
	if size == 0 {
		return nil, nil
	}
	buffer := make([]byte, size)
	if rc := C.rg_list(scard.value, (*C.char)(unsafe.Pointer(&buffer[0])), &size); rc != scardSuccess {
		return nil, fmt.Errorf("pcsc: SCardListReaders: %08X", uint32(rc))
	}
	var readers []string
	for _, name := range bytes.Split(buffer[:size], []byte{0}) {
		if len(name) > 0 {
			readers = append(readers, string(name))
		}
	}
	return readers, nil
}

func (scard *context_) connect(reader string, exclusive bool) (C.SCARDHANDLE, error) {
	name := C.CString(reader)
	defer C.free(unsafe.Pointer(name))
	flag := C.int(0)
	if exclusive {
		flag = 1
	}
	var handle C.SCARDHANDLE
	if rc := C.rg_connect(scard.value, name, flag, &handle); rc != scardSuccess {
		return 0, fmt.Errorf("pcsc: SCardConnect %q: %08X", reader, uint32(rc))
	}
	return handle, nil
}

// probeSerial reads the OpenPGP AID serial on a shared connection, inside one transaction, and
// leaves the card as it found it apart from the applet selection.
func (scard *context_) probeSerial(reader string) (string, error) {
	handle, err := scard.connect(reader, false)
	if err != nil {
		return "", err
	}
	defer C.rg_disconnect(handle)
	if rc := C.rg_begin(handle); rc != scardSuccess {
		return "", fmt.Errorf("pcsc: SCardBeginTransaction: %08X", uint32(rc))
	}
	defer C.rg_end(handle)
	if _, sw, err := transmit(handle, openPGPSelect); err != nil || sw != 0x9000 {
		return "", fmt.Errorf("pcsc: no OpenPGP applet on %q", reader)
	}
	aid, sw, err := transmit(handle, getAID)
	if err != nil || sw != 0x9000 {
		return "", fmt.Errorf("pcsc: GET DATA 4F on %q failed", reader)
	}
	return openpgpdriver.SerialFromAID(aid)
}

func transmit(handle C.SCARDHANDLE, command []byte) ([]byte, uint16, error) {
	if len(command) == 0 {
		return nil, 0, errors.New("pcsc: empty command")
	}
	var response [maxResponse]byte
	length := C.uint32_t(len(response))
	rc := C.rg_transmit(handle, (*C.uchar)(unsafe.Pointer(&command[0])), C.uint32_t(len(command)),
		(*C.uchar)(unsafe.Pointer(&response[0])), &length)
	if rc != scardSuccess {
		return nil, 0, fmt.Errorf("pcsc: SCardTransmit: %08X", uint32(rc))
	}
	if length < 2 {
		return nil, 0, fmt.Errorf("pcsc: a %d-byte response carries no status word", length)
	}
	body := append([]byte(nil), response[:length-2]...)
	return body, uint16(response[length-2])<<8 | uint16(response[length-1]), nil
}

type transport struct {
	mu     sync.Mutex
	scard  *context_
	handle C.SCARDHANDLE
	closed bool
}

func (connection *transport) Transmit(command []byte) ([]byte, uint16, error) {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.closed {
		return nil, 0, errors.New("pcsc: transport is closed")
	}
	return transmit(connection.handle, command)
}

func (connection *transport) Close() error {
	connection.mu.Lock()
	defer connection.mu.Unlock()
	if connection.closed {
		return nil
	}
	connection.closed = true
	C.rg_disconnect(connection.handle)
	connection.scard.release()
	return nil
}
