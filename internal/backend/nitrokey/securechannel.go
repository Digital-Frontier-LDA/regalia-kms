package nitrokey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// AttestedSecureChannel satisfies SecureChannel from recorded commissioning evidence.
//
// READ THIS BEFORE USING IT. PKCS#11 has no secure-messaging surface: there is no call that asks
// the middleware whether SmartCard-HSM secure messaging is in force, so nothing reachable through
// that API can PROVE the channel state at runtime. The interface exists because the alternative —
// a silent no-op — would let the KMS behave as though the channel were established when it may not
// be.
//
// This is not that no-op, and it is not a proof either. It is an operator ATTESTATION, made
// explicit and given an expiry:
//
//   - it names the device serial it applies to, so one device's evidence never covers another;
//   - it records who verified the channel, when, and against which firmware;
//   - it EXPIRES, so the claim has to be re-made after a firmware or middleware change rather than
//     ageing quietly into fiction;
//   - it fails closed on a missing, malformed, expired or mismatched entry.
//
// A runtime proof belongs here instead as soon as the middleware can provide one; until then this
// keeps the claim visible, dated and auditable rather than assumed.
type AttestedSecureChannel struct {
	entries map[string]channelEvidence
	now     func() time.Time
}

type channelEvidence struct {
	DeviceSerial string    `json:"device_serial"`
	VerifiedBy   string    `json:"verified_by"`
	VerifiedAt   time.Time `json:"verified_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Firmware     string    `json:"firmware"`
	SecureMsg    bool      `json:"secure_messaging_established"`
}

type channelEvidenceDocument struct {
	SchemaVersion int               `json:"schema_version"`
	Devices       []channelEvidence `json:"devices"`
}

const maximumEvidenceBytes = 64 << 10

// LoadSecureChannelEvidence reads commissioning evidence from a regular file.
//
// THE FILE IS TRUSTED, SO THE FILE IS CHECKED. This document is the only thing standing between the
// KMS and operating a token over a channel nobody proved; anyone who can rewrite it can assert that
// secure messaging is established. os.ReadFile would have followed a symlink into an
// attacker-writable location and read a FIFO forever, so the descriptor is opened without following
// links and its mode is checked on the descriptor that was actually opened rather than on a path
// that could change underneath. Group- and world-writable evidence is refused for the same reason
// the PIN credentials are: the value is only as good as the set of people who can edit it.
func LoadSecureChannelEvidence(path string, now func() time.Time) (*AttestedSecureChannel, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("secure-channel evidence path is required")
	}
	if now == nil {
		now = time.Now
	}
	contents, err := readEvidenceFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var document channelEvidenceDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("secure-channel evidence is malformed")
	}
	// A second JSON value in the file means two documents disagree about the fleet and only the
	// first was read. Refuse rather than silently honour whichever one came first.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("secure-channel evidence contains more than one JSON value")
	}
	if document.SchemaVersion != 1 || len(document.Devices) == 0 {
		return nil, errors.New("secure-channel evidence names no device")
	}
	entries := make(map[string]channelEvidence, len(document.Devices))
	for _, device := range document.Devices {
		serial := strings.TrimSpace(device.DeviceSerial)
		if serial == "" || strings.TrimSpace(device.VerifiedBy) == "" || device.VerifiedAt.IsZero() || device.ExpiresAt.IsZero() {
			return nil, errors.New("secure-channel evidence is incomplete")
		}
		if !device.ExpiresAt.After(device.VerifiedAt) {
			return nil, errors.New("secure-channel evidence expires before it was made")
		}
		if _, duplicate := entries[serial]; duplicate {
			return nil, fmt.Errorf("secure-channel evidence names %q twice", serial)
		}
		entries[serial] = device
	}
	return &AttestedSecureChannel{entries: entries, now: now}, nil
}

func (channel *AttestedSecureChannel) Establish(ctx context.Context, _, serial string) error {
	if channel == nil || len(channel.entries) == 0 {
		return errors.New("no secure-channel evidence is loaded")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	evidence, present := channel.entries[strings.TrimSpace(serial)]
	if !present {
		return fmt.Errorf("no secure-channel evidence for device %q", serial)
	}
	if !evidence.SecureMsg {
		return fmt.Errorf("secure messaging is recorded as NOT established for device %q", serial)
	}
	if !channel.now().Before(evidence.ExpiresAt) {
		return fmt.Errorf("secure-channel evidence for device %q expired at %s", serial, evidence.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// readEvidenceFile opens the evidence without following symlinks and refuses anything that is not
// a regular, non-group-writable file. The checks run against the opened descriptor so the file
// that is validated is the file that is read.
func readEvidenceFile(path string) ([]byte, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("read secure-channel evidence: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "secure-channel-evidence")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("secure-channel evidence is unreadable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("secure-channel evidence is unreadable")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("secure-channel evidence must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("secure-channel evidence must not be group- or world-writable")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumEvidenceBytes+1))
	if err != nil {
		return nil, errors.New("secure-channel evidence is unreadable")
	}
	if len(contents) > maximumEvidenceBytes {
		return nil, errors.New("secure-channel evidence exceeds 64 KiB")
	}
	return contents, nil
}
