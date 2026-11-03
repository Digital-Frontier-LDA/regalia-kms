//go:build piv

package pcscwatch

/*
#cgo darwin LDFLAGS: -framework PCSC
#cgo linux pkg-config: libpcsclite
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Every PC/SC return code is widened through uint32_t, as in openpgp/pcsc: LONG is 32 bits on macOS
// and 64 on Linux, and the error codes have the top bit set.
static int64_t rw_establish(SCARDCONTEXT *ctx) {
	return (int64_t)(uint32_t)SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, ctx);
}
static int64_t rw_release(SCARDCONTEXT ctx) { return (int64_t)(uint32_t)SCardReleaseContext(ctx); }
static int64_t rw_list(SCARDCONTEXT ctx, char *buffer, uint32_t *size) {
	DWORD n = *size;
	int64_t rc = (int64_t)(uint32_t)SCardListReaders(ctx, NULL, buffer, &n);
	*size = (uint32_t)n;
	return rc;
}
static int64_t rw_status_change(SCARDCONTEXT ctx, uint32_t timeout, char **names, uint32_t *current,
		uint32_t *event, uint32_t n) {
	SCARD_READERSTATE *states = calloc(n, sizeof(SCARD_READERSTATE));
	if (states == NULL) {
		return (int64_t)(uint32_t)SCARD_E_NO_MEMORY;
	}
	for (uint32_t i = 0; i < n; i++) {
		states[i].szReader = names[i];
		states[i].dwCurrentState = current[i];
	}
	int64_t rc = (int64_t)(uint32_t)SCardGetStatusChange(ctx, timeout, states, n);
	for (uint32_t i = 0; i < n; i++) {
		event[i] = (uint32_t)states[i].dwEventState;
	}
	free(states);
	return rc;
}
*/
import "C"

import (
	"fmt"
	"strings"
	"time"
	"unsafe"
)

// System is the host's PC/SC (pcscd), through libpcsclite.
func System() API { return systemAPI{} }

type systemAPI struct{}

type systemContext struct{ handle C.SCARDCONTEXT }

func (systemAPI) Establish() (Context, error) {
	var handle C.SCARDCONTEXT
	if rc := C.rw_establish(&handle); rc != 0 {
		return nil, fmt.Errorf("pcsc: SCardEstablishContext: %08X", uint32(rc))
	}
	return &systemContext{handle: handle}, nil
}

func (pcsc *systemContext) Release() { C.rw_release(pcsc.handle) }

func (pcsc *systemContext) Readers() ([]string, error) {
	size := C.uint32_t(64 << 10)
	buffer := (*C.char)(C.malloc(C.size_t(size)))
	defer C.free(unsafe.Pointer(buffer))
	rc := C.rw_list(pcsc.handle, buffer, &size)
	if uint32(rc) == codeNoReaders {
		return nil, nil
	}
	if rc != 0 {
		return nil, fmt.Errorf("pcsc: SCardListReaders: %08X", uint32(rc))
	}
	var names []string
	for _, name := range strings.Split(C.GoStringN(buffer, C.int(size)), "\x00") {
		if name != "" {
			names = append(names, name)
		}
	}
	return names, nil
}

func (pcsc *systemContext) StatusChange(timeout time.Duration, readers []string, current []uint32) ([]uint32, error) {
	n := len(readers)
	names := (*[1 << 20]*C.char)(C.malloc(C.size_t(n) * C.size_t(unsafe.Sizeof(uintptr(0)))))[:n:n]
	states := (*[1 << 20]C.uint32_t)(C.malloc(C.size_t(n) * 4))[:n:n]
	events := (*[1 << 20]C.uint32_t)(C.malloc(C.size_t(n) * 4))[:n:n]
	defer C.free(unsafe.Pointer(&names[0]))
	defer C.free(unsafe.Pointer(&states[0]))
	defer C.free(unsafe.Pointer(&events[0]))
	for i, reader := range readers {
		names[i] = C.CString(reader)
		states[i] = C.uint32_t(current[i])
	}
	defer func() {
		for _, name := range names {
			C.free(unsafe.Pointer(name))
		}
	}()
	rc := C.rw_status_change(pcsc.handle, C.uint32_t(timeout/time.Millisecond), &names[0], &states[0], &events[0], C.uint32_t(n))
	out := make([]uint32, n)
	for i := range out {
		out[i] = uint32(events[i])
	}
	if uint32(rc) == codeTimeout {
		return out, ErrTimeout
	}
	if rc != 0 {
		return nil, fmt.Errorf("pcsc: SCardGetStatusChange: %08X", uint32(rc))
	}
	return out, nil
}
