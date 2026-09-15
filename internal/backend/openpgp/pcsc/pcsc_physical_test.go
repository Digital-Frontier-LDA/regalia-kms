//go:build piv

package pcsc

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	openpgp "github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp"
	openpgpdriver "github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp/driver"
)

// TestOpenPGPPhysicalQualification runs openpgp/driver, through this transport, against a real
// OpenPGP card. It is opt-in because ordinary CI has no card reader.
//
// REGALIA_OPENPGP_SERIAL names the card, and REGALIA_OPENPGP_PIN is its PW1. The card must hold an
// Ed25519 signature key and an X25519 decryption key, both with touch off and PW1 valid for
// several signatures. That is the unattended posture the adapter admits. The staging card was
// provisioned that way with yubikit's OpenPgpSession.generate_ec_key (doc/drills).
//
// It proves, on the card:
//   - the card is found by its serial, and a wrong serial finds nothing;
//   - Status reads the serial ykman reports, PW1-once and touch off;
//   - two signatures present PW1 81 ONCE, and both verify against the card's own public key;
//   - X25519 decipher presents PW1 82 once and returns the shared secret computed off-card;
//   - a wrong PW1 is refused with the tries left named, and the correct PW1 restores the count;
//   - while the driver holds the card, a second connection to it is refused (concurrency);
//   - a PW1 blocked by three wrong tries is refused as blocked, and after the Admin PIN resets
//     the retry counter the card signs again (recovery). This arm runs only with
//     REGALIA_OPENPGP_ADMIN_PIN set, because it deliberately blocks PW1.
//
// Removal is NOT exercised here: it needs the card pulled from the bus by a person.
func TestOpenPGPPhysicalQualification(t *testing.T) {
	serial := os.Getenv("REGALIA_OPENPGP_SERIAL")
	pin := os.Getenv("REGALIA_OPENPGP_PIN")
	if serial == "" {
		t.Skip("set REGALIA_OPENPGP_SERIAL (and REGALIA_OPENPGP_PIN) for the physical OpenPGP qualification")
	}
	if pin == "" {
		t.Fatal("REGALIA_OPENPGP_SERIAL is set but REGALIA_OPENPGP_PIN is not: the qualification cannot run")
	}
	ctx := context.Background()

	t.Run("a serial no attached card carries finds nothing", func(t *testing.T) {
		opener, err := NewOpener(map[string]string{"staging": "1"})
		if err != nil {
			t.Fatal(err)
		}
		if connection, err := opener.Open(ctx, "staging"); err == nil {
			connection.Close()
			t.Fatal("a card was opened for serial 1")
		}
	})

	opener, err := NewOpener(map[string]string{"staging": serial})
	if err != nil {
		t.Fatal(err)
	}
	if !opener.Ready(ctx) {
		t.Fatal("PC/SC is not ready")
	}
	counting := &countingOpener{inner: opener}
	driver, err := openpgpdriver.NewDriver(counting, fixedPIN(pin))
	if err != nil {
		t.Fatal(err)
	}
	card, err := driver.Open(ctx, "staging")
	if err != nil {
		t.Fatalf("open the card pinned to %s: %v", serial, err)
	}
	defer card.Close()

	status, err := card.Status(ctx)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.Serial != serial {
		t.Fatalf("status serial = %q, want %q", status.Serial, serial)
	}
	if !status.SignaturePINValidForMultipleSignatures || status.TouchRequiredForSignature || status.TouchRequiredForDecryption {
		t.Fatalf("card is not in the unattended posture: %+v", status)
	}

	t.Run("a second connection is refused while the driver holds the card", func(t *testing.T) {
		if second, err := opener.Open(ctx, "staging"); err == nil {
			second.Close()
			t.Fatal("a second connection to the card was opened while the first held it exclusively")
		}
	})

	signaturePublic := readPublicKey(t, counting.last(), 0xB6)
	decryptionPublic := readPublicKey(t, counting.last(), 0xB8)

	t.Run("two signatures, PW1 81 presented once, both verify", func(t *testing.T) {
		before := counting.verifies(0x81)
		for round := 0; round < 2; round++ {
			message := make([]byte, 32)
			if _, err := rand.Read(message); err != nil {
				t.Fatal(err)
			}
			signature, err := card.Sign(ctx, "ed25519", message)
			if err != nil {
				t.Fatalf("sign %d: %v", round, err)
			}
			if len(signaturePublic) != ed25519.PublicKeySize || !ed25519.Verify(signaturePublic, message, signature) {
				t.Fatalf("signature %d does not verify against the card's Ed25519 public key", round)
			}
		}
		if got := counting.verifies(0x81) - before; got != 1 {
			t.Fatalf("PW1 81 was presented %d times for two signatures on a PW1-once card, want 1", got)
		}
	})

	t.Run("X25519 decipher returns the shared secret", func(t *testing.T) {
		peer, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cardKey, err := ecdh.X25519().NewPublicKey(decryptionPublic)
		if err != nil {
			t.Fatalf("card decryption public key: %v", err)
		}
		want, err := peer.ECDH(cardKey)
		if err != nil {
			t.Fatal(err)
		}
		before := counting.verifies(0x82)
		got, err := card.Decipher(ctx, "cv25519", peer.PublicKey().Bytes())
		if err != nil {
			t.Fatalf("decipher: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("the card's X25519 result is not the shared secret computed off-card")
		}
		if n := counting.verifies(0x82) - before; n != 1 {
			t.Fatalf("PW1 82 was presented %d times, want 1", n)
		}
	})

	t.Run("a wrong PW1 is refused with the tries named, and the right one restores them", func(t *testing.T) {
		wrong, err := openpgpdriver.NewDriver(opener, fixedPIN("000000000"))
		if err != nil {
			t.Fatal(err)
		}
		card.Close()
		refused, err := wrong.Open(ctx, "staging")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := refused.Status(ctx); err != nil {
			t.Fatal(err)
		}
		_, signErr := refused.Sign(ctx, "ed25519", make([]byte, 32))
		refused.Close()
		if !errors.Is(signErr, openpgp.ErrUnavailable) || !strings.Contains(signErr.Error(), "2 tries left") {
			t.Fatalf("wrong PW1: %v, want a refusal naming 2 tries left", signErr)
		}
		right, err := driver.Open(ctx, "staging")
		if err != nil {
			t.Fatal(err)
		}
		defer right.Close()
		if _, err := right.Status(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := right.Sign(ctx, "ed25519", make([]byte, 32)); err != nil {
			t.Fatalf("the correct PW1 after one wrong try: %v", err)
		}
		tries, err := readTries(counting.last())
		if err != nil || tries != 3 {
			t.Fatalf("PW1 tries after the correct PIN = %d, %v; want 3", tries, err)
		}
	})
}

type fixedPIN string

func (pin fixedPIN) PW1(context.Context, string, string) ([]byte, error) { return []byte(pin), nil }

// countingOpener wraps the real opener so the test can count what the driver sent to the card.
type countingOpener struct {
	inner *Opener
	mu    sync.Mutex
	open  *countingTransport
}

func (opener *countingOpener) Open(ctx context.Context, deviceID string) (openpgpdriver.Transport, error) {
	connection, err := opener.inner.Open(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	wrapped := &countingTransport{inner: connection, counts: map[byte]int{}}
	opener.mu.Lock()
	opener.open = wrapped
	opener.mu.Unlock()
	return wrapped, nil
}

func (opener *countingOpener) Ready(ctx context.Context) bool { return opener.inner.Ready(ctx) }

func (opener *countingOpener) last() *countingTransport {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.open
}

func (opener *countingOpener) verifies(role byte) int {
	connection := opener.last()
	connection.mu.Lock()
	defer connection.mu.Unlock()
	return connection.counts[role]
}

type countingTransport struct {
	inner  openpgpdriver.Transport
	mu     sync.Mutex
	counts map[byte]int
}

func (connection *countingTransport) Transmit(command []byte) ([]byte, uint16, error) {
	if len(command) >= 4 && command[1] == 0x20 {
		connection.mu.Lock()
		connection.counts[command[3]]++
		connection.mu.Unlock()
	}
	return connection.inner.Transmit(command)
}

func (connection *countingTransport) Close() error { return connection.inner.Close() }

// readPublicKey reads an existing public key with GENERATE ASYMMETRIC KEY PAIR in read mode
// (P1 81) and returns the 86 element of the 7F49 template.
func readPublicKey(t *testing.T, connection openpgpdriver.Transport, crt byte) []byte {
	t.Helper()
	response, sw, err := connection.Transmit([]byte{0x00, 0x47, 0x81, 0x00, 0x02, crt, 0x00, 0x00})
	if err != nil || sw != 0x9000 {
		t.Fatalf("read public key %02X: %04X %v", crt, sw, err)
	}
	index := bytes.Index(response, []byte{0x86})
	if index < 0 || index+2 > len(response) || index+2+int(response[index+1]) > len(response) {
		t.Fatalf("public key %02X: no 86 element in % X", crt, response)
	}
	return response[index+2 : index+2+int(response[index+1])]
}

// readTries reads PW1's remaining tries from PW status byte 4 (GET DATA C4).
func readTries(connection openpgpdriver.Transport) (int, error) {
	response, sw, err := connection.Transmit([]byte{0x00, 0xCA, 0x00, 0xC4})
	if err != nil || sw != 0x9000 || len(response) < 5 {
		return 0, errors.New("GET DATA C4 failed")
	}
	return int(response[4]), nil
}

// TestOpenPGPPhysicalRecoveryFromABlockedPW1 blocks PW1 with three wrong tries, proves the driver
// reports the block, resets the retry counter with the Admin PIN, and proves the card signs again.
// It is separate from the qualification above because it is deliberately destructive to the PIN
// state, and it runs only when REGALIA_OPENPGP_ADMIN_PIN is set.
func TestOpenPGPPhysicalRecoveryFromABlockedPW1(t *testing.T) {
	serial := os.Getenv("REGALIA_OPENPGP_SERIAL")
	pin := os.Getenv("REGALIA_OPENPGP_PIN")
	admin := os.Getenv("REGALIA_OPENPGP_ADMIN_PIN")
	if serial == "" || admin == "" {
		t.Skip("set REGALIA_OPENPGP_SERIAL, REGALIA_OPENPGP_PIN and REGALIA_OPENPGP_ADMIN_PIN to block and recover PW1 on a staging card")
	}
	if pin == "" {
		t.Fatal("REGALIA_OPENPGP_PIN is required to prove the card signs again after recovery")
	}
	ctx := context.Background()
	opener, err := NewOpener(map[string]string{"staging": serial})
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := openpgpdriver.NewDriver(opener, fixedPIN("000000000"))
	if err != nil {
		t.Fatal(err)
	}
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		card, err := wrong.Open(ctx, "staging")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := card.Status(ctx); err != nil {
			card.Close()
			t.Fatal(err)
		}
		_, last = card.Sign(ctx, "ed25519", make([]byte, 32))
		card.Close()
		if last != nil && strings.Contains(last.Error(), "blocked") {
			break
		}
	}
	if last == nil || !strings.Contains(last.Error(), "blocked") {
		t.Fatalf("after repeated wrong PW1 the refusal does not name the block: %v", last)
	}

	// Recovery with the Admin PIN: VERIFY PW3 (83), then RESET RETRY COUNTER for PW1 (2C 02 81).
	connection, err := opener.Open(ctx, "staging")
	if err != nil {
		t.Fatal(err)
	}
	send := func(command []byte) uint16 {
		_, sw, err := connection.Transmit(command)
		if err != nil {
			t.Fatal(err)
		}
		return sw
	}
	if sw := send(openPGPSelect); sw != 0x9000 {
		t.Fatalf("SELECT: %04X", sw)
	}
	if sw := send(append([]byte{0x00, 0x20, 0x00, 0x83, byte(len(admin))}, admin...)); sw != 0x9000 {
		connection.Close()
		t.Fatalf("Admin PIN VERIFY: %04X", sw)
	}
	if sw := send(append([]byte{0x00, 0x2C, 0x02, 0x81, byte(len(pin))}, pin...)); sw != 0x9000 {
		connection.Close()
		t.Fatalf("RESET RETRY COUNTER: %04X", sw)
	}
	tries, err := readTries(connection)
	connection.Close()
	if err != nil || tries != 3 {
		t.Fatalf("PW1 tries after the reset = %d, %v; want 3", tries, err)
	}

	right, err := openpgpdriver.NewDriver(opener, fixedPIN(pin))
	if err != nil {
		t.Fatal(err)
	}
	card, err := right.Open(ctx, "staging")
	if err != nil {
		t.Fatal(err)
	}
	defer card.Close()
	if _, err := card.Status(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := card.Sign(ctx, "ed25519", make([]byte, 32)); err != nil {
		t.Fatalf("the card does not sign after the Admin PIN reset PW1: %v", err)
	}
}
