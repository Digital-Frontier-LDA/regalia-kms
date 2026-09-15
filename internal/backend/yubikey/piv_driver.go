//go:build piv

package yubikey

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/go-piv/piv-go/v2/piv"
)

// PIVDriver rediscovers a card for every operation. The map binds a
// server-owned logical device ID to its commissioned decimal serial.
type PIVDriver struct{ devices map[string]string }

func NewPIVDriver(devices map[string]string) (*PIVDriver, error) {
	if len(devices) == 0 {
		return nil, errors.New("commissioned YubiKey devices are required")
	}
	copyDevices := make(map[string]string, len(devices))
	for deviceID, serial := range devices {
		if deviceID == "" || serial == "" {
			return nil, errors.New("invalid commissioned YubiKey")
		}
		if _, err := strconv.ParseUint(serial, 10, 32); err != nil {
			return nil, errors.New("invalid commissioned YubiKey serial")
		}
		copyDevices[deviceID] = serial
	}
	return &PIVDriver{devices: copyDevices}, nil
}

func (driver *PIVDriver) Open(ctx context.Context, deviceID string) (Session, error) {
	if err := ctx.Err(); err != nil || driver == nil {
		return nil, ErrUnavailable
	}
	target := driver.devices[deviceID]
	if target == "" {
		return nil, ErrUnavailable
	}

	cards, err := pivCards()
	if err != nil {
		return nil, ErrUnavailable
	}
	var selected *piv.YubiKey
	for _, card := range cards {
		if ctx.Err() != nil {
			if selected != nil {
				_ = selected.Close()
			}
			return nil, ErrUnavailable
		}
		candidate, openErr := pivOpen(card)
		if openErr != nil {
			continue
		}
		serial, serialErr := candidate.Serial()
		if serialErr != nil || strconv.FormatUint(uint64(serial), 10) != target {
			_ = candidate.Close()
			continue
		}
		if selected != nil {
			_ = candidate.Close()
			_ = selected.Close()
			return nil, ErrUnavailable
		}
		selected = candidate
	}
	if selected == nil {
		return nil, ErrUnavailable
	}
	return &pivSession{card: selected, serial: target}, nil
}

func (driver *PIVDriver) Ready(ctx context.Context) bool {
	if driver == nil || ctx.Err() != nil {
		return false
	}
	cards, err := pivCards()
	return err == nil && len(cards) > 0
}

type pivSession struct {
	mu     sync.Mutex
	card   *piv.YubiKey
	serial string
	pin    string
	closed bool
}

func (session *pivSession) Identity(ctx context.Context) (string, error) {
	if err := session.usable(ctx); err != nil {
		return "", err
	}
	serial, err := session.card.Serial()
	if err != nil || strconv.FormatUint(uint64(serial), 10) != session.serial {
		return "", ErrUnavailable
	}
	return session.serial, nil
}

func (session *pivSession) Policies(ctx context.Context, objectID string) (string, string, error) {
	if err := session.usable(ctx); err != nil {
		return "", "", err
	}
	slot, err := parseSlot(objectID)
	if err != nil {
		return "", "", ErrUnavailable
	}
	info, err := session.card.KeyInfo(slot)
	if err != nil {
		return "", "", ErrUnavailable
	}
	return pinPolicyName(info.PINPolicy), touchPolicyName(info.TouchPolicy), nil
}

func (session *pivSession) PINRetries(ctx context.Context) (int, error) {
	if err := session.usable(ctx); err != nil {
		return 0, err
	}
	retries, err := readPINRetries(ctx, session.card.Retries)
	if err != nil {
		return 0, ErrUnavailable
	}
	return retries, nil
}

func (session *pivSession) Login(ctx context.Context, pin []byte) error {
	if err := session.usable(ctx); err != nil || len(pin) < 6 || len(pin) > 64 {
		return ErrUnavailable
	}
	// piv-go requires a string. Retain it only for this exclusive session,
	// clear the reference on Close, and never expose it through an error.
	value := string(pin)
	if err := session.card.VerifyPIN(value); err != nil {
		return ErrUnavailable
	}
	session.pin = value
	return nil
}

func (session *pivSession) Sign(ctx context.Context, objectID, algorithm string, digest []byte) ([]byte, error) {
	key, info, err := session.privateKey(ctx, objectID, algorithm)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrUnavailable
	}
	hash, valid := signingHash(algorithm, len(digest))
	if !valid || !algorithmMatches(info.Algorithm, algorithm) {
		return nil, ErrUnavailable
	}
	value, err := signer.Sign(rand.Reader, digest, hash)
	if err != nil || len(value) == 0 {
		return nil, ErrUnavailable
	}
	return value, nil
}

func (session *pivSession) Unwrap(ctx context.Context, objectID, algorithm string, ciphertext, _ []byte) ([]byte, error) {
	key, info, err := session.privateKey(ctx, objectID, algorithm)
	if err != nil || algorithm != "rsa2048" || info.Algorithm != piv.AlgorithmRSA2048 {
		return nil, ErrUnavailable
	}
	decrypter, ok := key.(crypto.Decrypter)
	if !ok {
		return nil, ErrUnavailable
	}
	value, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{Hash: keywrap.OAEPHash})
	if err != nil || len(value) == 0 {
		return nil, ErrUnavailable
	}
	return value, nil
}

func (session *pivSession) PublicKey(ctx context.Context, objectID string) ([]byte, error) {
	if err := session.usable(ctx); err != nil {
		return nil, err
	}
	slot, err := parseSlot(objectID)
	if err != nil {
		return nil, ErrUnavailable
	}
	info, err := session.card.KeyInfo(slot)
	if err != nil || info.PublicKey == nil {
		return nil, ErrUnavailable
	}
	encoded, err := x509.MarshalPKIXPublicKey(info.PublicKey)
	if err != nil {
		return nil, ErrUnavailable
	}
	return encoded, nil
}

func (session *pivSession) privateKey(ctx context.Context, objectID, algorithm string) (crypto.PrivateKey, piv.KeyInfo, error) {
	if err := session.usable(ctx); err != nil || session.pin == "" {
		return nil, piv.KeyInfo{}, ErrUnavailable
	}
	slot, err := parseSlot(objectID)
	if err != nil {
		return nil, piv.KeyInfo{}, ErrUnavailable
	}
	info, err := session.card.KeyInfo(slot)
	if err != nil || info.TouchPolicy != piv.TouchPolicyNever || (info.PINPolicy != piv.PINPolicyOnce && info.PINPolicy != piv.PINPolicyAlways) || !algorithmMatches(info.Algorithm, algorithm) {
		return nil, piv.KeyInfo{}, ErrUnavailable
	}
	key, err := session.card.PrivateKey(slot, info.PublicKey, piv.KeyAuth{PIN: session.pin, PINPolicy: info.PINPolicy})
	if err != nil {
		return nil, piv.KeyInfo{}, ErrUnavailable
	}
	return key, info, nil
}

func (session *pivSession) Close() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	session.closed = true
	session.pin = ""
	if session.card == nil {
		return nil
	}
	return session.card.Close()
}

func (session *pivSession) usable(ctx context.Context) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.card == nil {
		return ErrUnavailable
	}
	return nil
}

func parseSlot(value string) (piv.Slot, error) {
	number, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(value), "0x"), 16, 8)
	if err != nil {
		return piv.Slot{}, err
	}
	switch number {
	case 0x9a:
		return piv.SlotAuthentication, nil
	case 0x9c:
		return piv.SlotSignature, nil
	case 0x9d:
		return piv.SlotKeyManagement, nil
	case 0x9e:
		return piv.SlotCardAuthentication, nil
	}
	if number >= 0x82 && number <= 0x95 {
		if slot, ok := piv.RetiredKeyManagementSlot(uint32(number)); ok {
			return slot, nil
		}
	}
	return piv.Slot{}, fmt.Errorf("unsupported PIV slot")
}

func pinPolicyName(value piv.PINPolicy) string {
	if value == piv.PINPolicyOnce {
		return "once"
	}
	if value == piv.PINPolicyAlways {
		return "always"
	}
	return "unsupported"
}

func touchPolicyName(value piv.TouchPolicy) string {
	if value == piv.TouchPolicyNever {
		return "never"
	}
	return "unsupported"
}

func algorithmMatches(value piv.Algorithm, algorithm string) bool {
	return (value == piv.AlgorithmEC256 && algorithm == "p256") ||
		(value == piv.AlgorithmEC384 && algorithm == "p384") ||
		(value == piv.AlgorithmRSA2048 && algorithm == "rsa2048")
}

func signingHash(algorithm string, size int) (crypto.Hash, bool) {
	switch algorithm {
	case "p256", "rsa2048":
		return crypto.SHA256, size == crypto.SHA256.Size()
	case "p384":
		return crypto.SHA384, size == crypto.SHA384.Size()
	default:
		return 0, false
	}
}
