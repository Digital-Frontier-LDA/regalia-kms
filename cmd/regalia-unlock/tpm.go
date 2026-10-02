package main

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"syscall"
)

// One TPM command, written out by hand: TPM2_Quote by the persistent attestation key. The pre-root
// client needs nothing else from the TPM, and a TPM library would be the largest piece of code in it.
// TCG TPM 2.0 Library, Part 3, section 18.4 (TPM2_Quote); Part 1, section 18 (command structure).
const (
	stSessions = 0x8002
	ccQuote    = 0x00000158
	rsPassword = 0x40000009
	akHandle   = 0x81010002 // attest.AK_HANDLE: where node-init makes the AK persistent
)

// openTPM opens the TPM: the kernel's resource-manager device, or (for tests against swtpm) a UNIX
// socket given as unix:PATH.
func openTPM(path string) (io.ReadWriteCloser, error) {
	if socket, ok := strings.CutPrefix(path, "unix:"); ok {
		return net.Dial("unix", socket)
	}
	// A BLOCKING descriptor, opened by hand. os.OpenFile puts a pollable character device in
	// non-blocking mode, and the kernel's TPM device then only queues the command on write and returns
	// 0 bytes to a read made before the response is ready: every quote would look truncated. In blocking
	// mode the write runs the command and the read that follows returns the whole response.
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// quoteCommand is the TPM2_Quote command: the AK's empty password authorization, the qualifying data,
// the key's own signing scheme (TPM_ALG_NULL), and one selection of SHA-256 PCRs.
func quoteCommand(handle uint32, qualifying []byte, pcrs []int) ([]byte, error) {
	if len(qualifying) != 32 || len(pcrs) == 0 {
		return nil, errors.New("a quote needs 32 bytes of qualifying data and at least one PCR")
	}
	var selection [3]byte
	for _, pcr := range pcrs {
		if pcr < 0 || pcr > 23 {
			return nil, errors.New("PCRs must be 0-23")
		}
		selection[pcr/8] |= 1 << (pcr % 8)
	}
	body := binary.BigEndian.AppendUint32(nil, handle)
	body = binary.BigEndian.AppendUint32(body, 9)          // authorization area size
	body = binary.BigEndian.AppendUint32(body, rsPassword) // a password session
	body = append(body, 0, 0, 0, 0, 0)                     // empty nonce, no attributes, empty password
	body = binary.BigEndian.AppendUint16(body, uint16(len(qualifying)))
	body = append(body, qualifying...)
	body = binary.BigEndian.AppendUint16(body, algNull) // inScheme: the key's own
	body = binary.BigEndian.AppendUint32(body, 1)       // one PCR selection
	body = binary.BigEndian.AppendUint16(body, algSHA256)
	body = append(body, 3)
	body = append(body, selection[:]...)
	command := binary.BigEndian.AppendUint16(nil, stSessions)
	command = binary.BigEndian.AppendUint32(command, uint32(10+len(body)))
	command = binary.BigEndian.AppendUint32(command, ccQuote)
	return append(command, body...), nil
}

// transact sends one command and reads one response. The kernel device returns the whole response to
// one read; a socket may return it in pieces.
func transact(device io.ReadWriter, command []byte) ([]byte, error) {
	if _, err := device.Write(command); err != nil {
		return nil, errors.New("the TPM did not take the command")
	}
	buffer := make([]byte, 4096)
	have := 0
	for have < 10 || have < int(binary.BigEndian.Uint32(buffer[2:6])) {
		if have >= 10 && binary.BigEndian.Uint32(buffer[2:6]) > uint32(len(buffer)) {
			return nil, errors.New("the TPM's response is too long")
		}
		n, err := device.Read(buffer[have:])
		have += n
		if err != nil || n == 0 {
			return nil, errors.New("the TPM's response is truncated")
		}
	}
	return buffer[:binary.BigEndian.Uint32(buffer[2:6])], nil
}

// tpmQuote asks the TPM for a quote and returns the signed TPMS_ATTEST and its ECDSA signature in DER,
// the two values deploy/baremetal/attest.py's verifier takes.
func tpmQuote(device io.ReadWriter, qualifying []byte, pcrs []int) (attest, signature []byte, err error) {
	command, err := quoteCommand(akHandle, qualifying, pcrs)
	if err != nil {
		return nil, nil, err
	}
	reply, err := transact(device, command)
	if err != nil {
		return nil, nil, err
	}
	r := &reader{data: reply}
	tag, _, code := r.u16(), r.u32(), r.u32()
	if r.bad {
		return nil, nil, errors.New("the TPM's response is truncated")
	}
	if code != 0 {
		// 0x921 is dictionary-attack lockout (deploy/baremetal/tpm-lockout.sh); 0x18b a missing AK
		return nil, nil, fmt.Errorf("the TPM refused the quote (response code 0x%03x)", code)
	}
	if tag != stSessions {
		return nil, nil, errors.New("the TPM's response has no session area")
	}
	r.u32() // parameter size
	attest = r.sized()
	if r.u16() != algECDSA || r.u16() != algSHA256 {
		return nil, nil, errors.New("the quote is not signed with ECDSA and SHA-256")
	}
	sigR, sigS := r.sized(), r.sized()
	if r.bad || len(attest) == 0 || len(sigR) == 0 || len(sigS) == 0 {
		return nil, nil, errors.New("the TPM's quote is malformed")
	}
	signature, err = asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sigR), new(big.Int).SetBytes(sigS)})
	if err != nil {
		return nil, nil, err
	}
	return attest, signature, nil
}
