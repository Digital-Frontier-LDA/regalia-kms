package openpgpdriver

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	openpgp "github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp"
)

// scriptedTransport is a card at the WIRE: every step names the exact command bytes it
// expects and the response (body, status word) it gives back. This is deliberately one
// seam deeper than the parent package's Card doubles — the assertions here are about the
// APDUs the protocol requires, so a driver that constructs the wrong command fails
// against the script rather than against its own model of itself.
type scriptedStep struct {
	expect      []byte // the exact command APDU
	respond     []byte // response body
	status      uint16 // status word
	transmitErr error  // simulate a transport-level failure instead
}

type scriptedTransport struct {
	mu      sync.Mutex
	steps   []scriptedStep
	calls   [][]byte
	lastErr error
}

func (script *scriptedTransport) Transmit(command []byte) ([]byte, uint16, error) {
	script.mu.Lock()
	defer script.mu.Unlock()
	script.calls = append(script.calls, append([]byte(nil), command...))
	if len(script.steps) == 0 {
		script.lastErr = errors.New("script exhausted after " + hex.EncodeToString(command))
		return nil, 0, script.lastErr
	}
	step := script.steps[0]
	script.steps = script.steps[1:]
	if step.transmitErr != nil {
		return nil, 0, step.transmitErr
	}
	if !bytesEqual(step.expect, command) {
		script.lastErr = errors.New("unexpected APDU: got " + hex.EncodeToString(command) + " want " + hex.EncodeToString(step.expect))
		return nil, 0, script.lastErr
	}
	return step.respond, step.status, nil
}

func (script *scriptedTransport) Close() error { return nil }

func (script *scriptedTransport) call(n int) []byte {
	script.mu.Lock()
	defer script.mu.Unlock()
	return script.calls[n]
}

func (script *scriptedTransport) callCount() int {
	script.mu.Lock()
	defer script.mu.Unlock()
	return len(script.calls)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fixturePIN is a fixed-length test PW1; the applet's minimum is 6 and the protocol
// field is one byte of Lc, so an 8-digit PIN is representative without being magic.
const fixturePIN = "12345678"

type scriptedOpener struct {
	transport Transport
	ready     bool
}

func (opener *scriptedOpener) Open(context.Context, string) (Transport, error) {
	return opener.transport, nil
}
func (opener *scriptedOpener) Ready(context.Context) bool { return opener.ready }

type staticPIN struct{}

func (staticPIN) PW1(context.Context, string, string) ([]byte, error) {
	return []byte(fixturePIN), nil
}

// failingPIN refuses, so the PIN-unavailable path is reachable without a fixture card.
type failingPIN struct{}

func (failingPIN) PW1(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("no PW1 available")
}

// openScripted runs Driver.Open against a fully scripted session (SELECT first).
func openScripted(t *testing.T, steps ...scriptedStep) (openpgp.Card, *scriptedTransport) {
	t.Helper()
	script := &scriptedTransport{steps: append([]scriptedStep{
		{expect: append([]byte{0x00, 0xA4, 0x04, 0x00, 0x06}, openPGPAID...), status: 0x9000},
	}, steps...)}
	driver, err := NewDriver(&scriptedOpener{transport: script, ready: true}, staticPIN{})
	if err != nil {
		t.Fatal(err)
	}
	card, err := driver.Open(context.Background(), "wallet-1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = card.Close() })
	return card, script
}

// realYubiKeyAID is GET DATA 4F exactly as YubiKey 5C NFC 25923902 (fw 5.4.3) answered it on
// 2026-09-14: D2 76 00 01 24 01 | version 03 04 | manufacturer 00 06 (Yubico) | serial
// 25 92 39 02 | 00 00. The serial is BCD. The fixture this replaced built its serial as a
// big-endian integer, which is the assumption the driver made, so the two agreed with each
// other and not with the card.
var realYubiKeyAID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x25, 0x92, 0x39, 0x02, 0x00, 0x00}

func aidWith(manufacturer uint16, serial [4]byte) []byte {
	aid := append([]byte(nil), realYubiKeyAID...)
	aid[8], aid[9] = byte(manufacturer>>8), byte(manufacturer)
	copy(aid[10:14], serial[:])
	return aid
}

func statusSteps(pw1Multiple byte, uifSignature, uifDecryption byte) []scriptedStep {
	return []scriptedStep{
		{expect: []byte{0x00, 0xCA, 0x00, 0x4F}, respond: realYubiKeyAID, status: 0x9000},
		{expect: []byte{0x00, 0xCA, 0x00, 0xC4}, respond: []byte{pw1Multiple, 32, 32, 32, 3, 3, 3}, status: 0x9000},
		{expect: []byte{0x00, 0xCA, 0x00, 0xD6}, respond: []byte{uifSignature, 0x00}, status: 0x9000},
		{expect: []byte{0x00, 0xCA, 0x00, 0xD7}, respond: []byte{uifDecryption, 0x00}, status: 0x9000},
	}
}

// openStatused is openScripted plus the Status call the provider always makes first —
// it consumes the statusSteps at the head of every script and loads the PW1 mode.
func openStatused(t *testing.T, steps ...scriptedStep) (openpgp.Card, *scriptedTransport) {
	t.Helper()
	card, script := openScripted(t, steps...)
	if _, err := card.Status(context.Background()); err != nil {
		t.Fatalf("status: %v (wire mismatch: %v)", err, script.lastError())
	}
	return card, script
}

func TestStatusParsesTheWireFacts(t *testing.T) {
	cases := []struct {
		name                                     string
		pw1Multiple, uifSignature, uifDecryption byte
		wantMultiple, wantTouchSig, wantTouchDec bool
	}{
		{"unattended card: PW1 holds, no touch", 1, 0, 0, true, false, false},
		{"one-signature mode", 0, 0, 0, false, false, false},
		{"touch on the signature key only", 1, 1, 0, true, true, false},
		{"touch permanent on the signature key", 1, 2, 0, true, true, false},
		{"touch on the decryption key only", 1, 0, 1, true, false, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// Status is THIS test's subject, so the card is opened without the helper's
			// own Status call — the assertion below is what consumes the script.
			card, _ := openScripted(t, statusSteps(testCase.pw1Multiple, testCase.uifSignature, testCase.uifDecryption)...)
			status, err := card.Status(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if status.Serial != "25923902" {
				t.Fatalf("serial = %q, want 25923902, the serial ykman and PIV report for the card that answered this AID", status.Serial)
			}
			if status.SignaturePINValidForMultipleSignatures != testCase.wantMultiple {
				t.Fatalf("PW1 multiple-signatures = %v, want %v (C4 byte 0 is %d)", status.SignaturePINValidForMultipleSignatures, testCase.wantMultiple, testCase.pw1Multiple)
			}
			if status.TouchRequiredForSignature != testCase.wantTouchSig {
				t.Fatalf("touch(signature) = %v, want %v", status.TouchRequiredForSignature, testCase.wantTouchSig)
			}
			if status.TouchRequiredForDecryption != testCase.wantTouchDec {
				t.Fatalf("touch(decryption) = %v, want %v", status.TouchRequiredForDecryption, testCase.wantTouchDec)
			}
		})
	}
}

// THE UNCLASSIFIED UIF FAILS CLOSED: a zero-length User Interaction Flag data object is a
// fact the unattended contract cannot read, and reading it as "no touch required" would
// admit a card that never said so.
func TestAnEmptyUserInteractionFlagCountsAsRequired(t *testing.T) {
	card, _ := openScripted(t,
		scriptedStep{expect: []byte{0x00, 0xCA, 0x00, 0x4F}, respond: realYubiKeyAID, status: 0x9000},
		scriptedStep{expect: []byte{0x00, 0xCA, 0x00, 0xC4}, respond: []byte{1}, status: 0x9000},
		scriptedStep{expect: []byte{0x00, 0xCA, 0x00, 0xD6}, respond: nil, status: 0x9000},
		scriptedStep{expect: []byte{0x00, 0xCA, 0x00, 0xD7}, respond: []byte{0x00, 0x00}, status: 0x9000},
	)
	status, err := card.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.TouchRequiredForSignature {
		t.Fatal("an empty UIF was read as touch-not-required — an unreadable interaction fact must fail closed")
	}
}

func TestAShortAIDIsRefusedNotZeroFilled(t *testing.T) {
	card, _ := openScripted(t,
		scriptedStep{expect: []byte{0x00, 0xCA, 0x00, 0x4F}, respond: []byte{0xD2, 0x76}, status: 0x9000},
	)
	if _, err := card.Status(context.Background()); !errors.Is(err, openpgp.ErrUnavailable) {
		t.Fatalf("a 2-byte AID was accepted: %v", err)
	}
}

func TestSignPresentsPW1PerTheCardMode(t *testing.T) {
	signature := []byte{0xAA, 0xBB, 0xCC}
	t.Run("one-signature mode re-presents PW1 before every signature", func(t *testing.T) {
		card, script := openStatused(t, append(statusSteps(0, 0, 0),
			scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x9000},
			scriptedStep{expect: append(append([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x03}, signature...), 0x00), respond: []byte{0x01}, status: 0x9000},
		)...)
		if _, err := card.Sign(context.Background(), "ed25519", signature); err != nil {
			t.Fatalf("first sign: %v (wire mismatch: %v)", err, script.lastError())
		}
		// A second signature in one-signature mode must VERIFY again first.
		script.steps = append(script.steps,
			scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x9000},
			scriptedStep{expect: append(append([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x03}, signature...), 0x00), respond: []byte{0x02}, status: 0x9000},
		)
		if _, err := card.Sign(context.Background(), "ed25519", signature); err != nil {
			t.Fatal(err)
		}
		verifies := 0
		for _, call := range allCalls(script) {
			if len(call) == 5+8 && call[1] == 0x20 && call[3] == 0x81 {
				verifies++
			}
		}
		if verifies != 2 {
			t.Fatalf("PW1 0x81 presented %d times for two signatures in one-signature mode, want 2 — the card consumes the verification with each PSO:CDS", verifies)
		}
	})

	t.Run("multiple-signature mode presents PW1 once", func(t *testing.T) {
		card, script := openStatused(t, append(statusSteps(1, 0, 0),
			scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x9000},
			scriptedStep{expect: append(append([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x03}, signature...), 0x00), respond: []byte{0x01}, status: 0x9000},
		)...)
		if _, err := card.Sign(context.Background(), "ed25519", signature); err != nil {
			t.Fatal(err)
		}
		script.steps = append(script.steps,
			scriptedStep{expect: append(append([]byte{0x00, 0x2A, 0x9E, 0x9A, 0x03}, signature...), 0x00), respond: []byte{0x02}, status: 0x9000},
		)
		if _, err := card.Sign(context.Background(), "ed25519", signature); err != nil {
			t.Fatal(err)
		}
		verifies := 0
		for _, call := range allCalls(script) {
			if len(call) == 5+8 && call[1] == 0x20 && call[3] == 0x81 {
				verifies++
			}
		}
		if verifies != 1 {
			t.Fatalf("PW1 0x81 presented %d times across two signatures in multiple-signature mode, want 1 — re-presenting would exceed the reviewed policy's PIN-presentation count", verifies)
		}
	})
}

func TestDecipherBuildsTheTwoAlgorithmShapes(t *testing.T) {
	t.Run("RSA carries the padding indicator", func(t *testing.T) {
		ciphertext := []byte{0xDE, 0xAD, 0xBE, 0xEF}
		card, script := openStatused(t, append(statusSteps(1, 0, 0),
			scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x82, 0x08}, []byte(fixturePIN)...), status: 0x9000},
			scriptedStep{expect: append(append([]byte{0x00, 0x2A, 0x80, 0x86, 0x05, 0x00}, ciphertext...), 0x00), respond: []byte{0x11}, status: 0x9000},
		)...)
		recovered, err := card.Decipher(context.Background(), "rsa2048", ciphertext)
		if err != nil || len(recovered) != 1 {
			t.Fatalf("RSA decipher: %v %v", recovered, err)
		}
		got := script.call(6)
		if got[4] != 0x05 || got[5] != 0x00 || got[len(got)-1] != 0x00 {
			t.Fatalf("the RSA PSO:DEC did not carry padding indicator 00 before the ciphertext and Le after it: %s", hex.EncodeToString(got))
		}
	})

	t.Run("cv25519 wraps the external public key in A6/7F49/86, the form a real card accepts", func(t *testing.T) {
		publicKey := make([]byte, 32)
		for i := range publicKey {
			publicKey[i] = byte(i)
		}
		card, _ := openStatused(t, append(statusSteps(1, 0, 0),
			scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x82, 0x08}, []byte(fixturePIN)...), status: 0x9000},
			scriptedStep{expect: append(append([]byte{0x00, 0x2A, 0x80, 0x86, 0x27, 0xA6, 0x24, 0x7F, 0x49, 0x22, 0x86, 0x20}, publicKey...), 0x00), respond: []byte{0x22}, status: 0x9000},
		)...)
		recovered, err := card.Decipher(context.Background(), "cv25519", publicKey)
		if err != nil || len(recovered) != 1 {
			t.Fatalf("cv25519 decipher: %v %v", recovered, err)
		}
	})

	t.Run("a 31-byte external key is refused before the card sees anything", func(t *testing.T) {
		card, script := openStatused(t, statusSteps(1, 0, 0)...)
		if _, err := card.Decipher(context.Background(), "cv25519", make([]byte, 31)); err == nil {
			t.Fatal("a 31-byte X25519 external key was accepted")
		}
		if script.callCount() != 5 { // SELECT + four GET DATA; no PSO, no VERIFY
			t.Fatalf("the malformed key reached the card: %d commands sent", script.callCount())
		}
	})

	t.Run("an unmapped algorithm is refused", func(t *testing.T) {
		card, script := openStatused(t, statusSteps(1, 0, 0)...)
		if _, err := card.Decipher(context.Background(), "aes256", []byte{1}); err == nil || !strings.Contains(err.Error(), "aes256") {
			t.Fatalf("unmapped algorithm refused wrongly: %v", err)
		}
		if _, err := card.Sign(context.Background(), "aes256", []byte{1}); err == nil || !strings.Contains(err.Error(), "aes256") {
			t.Fatalf("unmapped sign algorithm refused wrongly: %v", err)
		}
		if count := script.callCount(); count != 5 { // SELECT + four GET DATA: the refusal happens before any VERIFY or PSO
			t.Fatalf("the unmapped algorithm reached the card (%d commands)", count)
		}
	})
}

func TestVerificationFailuresNameWhatHappened(t *testing.T) {
	cases := []struct {
		name   string
		status uint16
		wants  string
	}{
		{"wrong PIN names the tries left", 0x63C2, "2 tries left"},
		{"blocked names unblocking", 0x6983, "blocked"},
		{"anything else names the status word", 0x6A80, "6A80"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			card, _ := openStatused(t, append(statusSteps(0, 0, 0),
				scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: testCase.status},
			)...)
			_, err := card.Sign(context.Background(), "ed25519", []byte{0x01})
			if err == nil || !strings.Contains(err.Error(), testCase.wants) {
				t.Fatalf("the refusal does not name %q: %v", testCase.wants, err)
			}
		})
	}

	// A YubiKey answers a wrong PW1 with 6982 and spends the try; the count lives in C4 byte 4.
	// The C4 answers below are the bytes YubiKey 5C NFC 25923902 returned on 2026-09-14.
	// Falsifier: drop the 6982 case, and the refusal names the bare status word instead of the
	// tries left.
	yubiKeyCases := []struct {
		name  string
		c4    []byte
		c4SW  uint16
		wants string
	}{
		{"a YubiKey's 6982 names the tries C4 reports", []byte{0x01, 0x7F, 0x7F, 0x7F, 0x02, 0x00, 0x03}, 0x9000, "2 tries left"},
		{"6982 with C4 at zero names the block", []byte{0x01, 0x7F, 0x7F, 0x7F, 0x00, 0x00, 0x03}, 0x9000, "now blocked"},
		{"6982 with C4 unreadable says so", nil, 0x6A88, "could not be read"},
	}
	for _, testCase := range yubiKeyCases {
		t.Run(testCase.name, func(t *testing.T) {
			card, _ := openStatused(t, append(statusSteps(0, 0, 0),
				scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x6982},
				scriptedStep{expect: []byte{0x00, 0xCA, 0x00, 0xC4}, respond: testCase.c4, status: testCase.c4SW},
			)...)
			_, err := card.Sign(context.Background(), "ed25519", []byte{0x01})
			if err == nil || !strings.Contains(err.Error(), testCase.wants) {
				t.Fatalf("the refusal does not name %q: %v", testCase.wants, err)
			}
		})
	}
}

// THE TOUCH-GATED CARD REFUSES RATHER THAN FAILING OPAQUELY: 68 81/68 82 are the
// specification's "operation denied / user interaction required" answers, and a card the
// admission layer passed must surface them as what they are.
func TestAUserInteractionStatusWordIsNamedAsSuch(t *testing.T) {
	card, _ := openStatused(t, append(statusSteps(1, 0, 0),
		scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x9000},
		scriptedStep{expect: []byte{0x00, 0x2A, 0x9E, 0x9A, 0x01, 0x42, 0x00}, status: 0x6881},
	)...)
	if _, err := card.Sign(context.Background(), "ed25519", []byte{0x42}); err == nil || !strings.Contains(err.Error(), "user interaction") {
		t.Fatalf("the interaction-required status word was not named: %v", err)
	}
}

// A failed PSO invalidates the remembered verification: the next signature presents PW1
// again rather than trusting bookkeeping the card contradicted.
func TestAFailedPSOResetsTheVerificationState(t *testing.T) {
	card, script := openStatused(t, append(statusSteps(1, 0, 0),
		scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x9000},
		scriptedStep{expect: []byte{0x00, 0x2A, 0x9E, 0x9A, 0x01, 0x42, 0x00}, status: 0x6985},
	)...)
	if _, err := card.Sign(context.Background(), "ed25519", []byte{0x42}); err == nil {
		t.Fatal("the failed PSO was reported as success")
	}
	script.steps = append(script.steps,
		scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x9000},
		scriptedStep{expect: []byte{0x00, 0x2A, 0x9E, 0x9A, 0x01, 0x42, 0x00}, respond: []byte{0x09}, status: 0x9000},
	)
	if _, err := card.Sign(context.Background(), "ed25519", []byte{0x42}); err != nil {
		t.Fatal(err)
	}
	verifies := 0
	for _, call := range allCalls(script) {
		if len(call) == 13 && call[1] == 0x20 && call[3] == 0x81 {
			verifies++
		}
	}
	if verifies != 2 {
		t.Fatalf("after a failed PSO the driver presented PW1 %d times total, want 2 — the failed operation must not leave stale verification state", verifies)
	}
}

// RSA-4096 ciphertexts (512 bytes) exceed a short APDU: the driver must chain, with
// CLA 0x10 on every block but the last and Le on the last only.
func TestLargeDecipherChainsTheAPDU(t *testing.T) {
	ciphertext := make([]byte, 512)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}
	payload := append([]byte{0x00}, ciphertext...) // padding indicator || ciphertext = 513 bytes
	first := append([]byte{0x10, 0x2A, 0x80, 0x86, 0xFF}, payload[:255]...)
	middle := append([]byte{0x10, 0x2A, 0x80, 0x86, 0xFF}, payload[255:510]...)
	last := append(append([]byte{0x00, 0x2A, 0x80, 0x86, 0x03}, payload[510:]...), 0x00)
	card, script := openStatused(t, append(statusSteps(1, 0, 0),
		scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x82, 0x08}, []byte(fixturePIN)...), status: 0x9000},
		scriptedStep{expect: first, status: 0x9000},
		scriptedStep{expect: middle, status: 0x9000},
		scriptedStep{expect: last, respond: []byte{0x33}, status: 0x9000},
	)...)
	if _, err := card.Decipher(context.Background(), "rsa4096", ciphertext); err != nil {
		t.Fatalf("%v (wire mismatch: %v)", err, script.lastError())
	}
}

// 61 xx: the card has more response bytes than Le carried; the driver follows with
// GET RESPONSE and concatenates.
func TestAResponseContinuationIsFollowed(t *testing.T) {
	card, _ := openStatused(t, append(statusSteps(1, 0, 0),
		scriptedStep{expect: append([]byte{0x00, 0x20, 0x00, 0x81, 0x08}, []byte(fixturePIN)...), status: 0x9000},
		scriptedStep{expect: []byte{0x00, 0x2A, 0x9E, 0x9A, 0x01, 0x42, 0x00}, respond: []byte{0x01, 0x02}, status: 0x6120},
		scriptedStep{expect: []byte{0x00, 0xC0, 0x00, 0x00, 0x20}, respond: []byte{0x03}, status: 0x9000},
	)...)
	signature, err := card.Sign(context.Background(), "ed25519", []byte{0x42})
	if err != nil || len(signature) != 3 {
		t.Fatalf("continuation not followed: %v %v", signature, err)
	}
}

func TestDriverRefusesToConstructWithoutItsHalves(t *testing.T) {
	if _, err := NewDriver(nil, staticPIN{}); err == nil {
		t.Fatal("a driver without an opener was constructed")
	}
	if _, err := NewDriver(&scriptedOpener{}, nil); err == nil {
		t.Fatal("a driver without a PW1 source was constructed")
	}
}

func TestOpenRefusesWhenTheAppletIsNotThere(t *testing.T) {
	script := &scriptedTransport{steps: []scriptedStep{
		{expect: append([]byte{0x00, 0xA4, 0x04, 0x00, 0x06}, openPGPAID...), status: 0x6A82},
	}}
	driver, err := NewDriver(&scriptedOpener{transport: script, ready: true}, staticPIN{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Open(context.Background(), "wallet-1"); !errors.Is(err, openpgp.ErrUnavailable) {
		t.Fatalf("a card without the applet opened: %v", err)
	}
}

// A PIN source that cannot supply PW1 fails the operation — never an empty VERIFY,
// which some applets treat as a verification-status query and answer with success.
func TestAMissingPW1RefusesRatherThanVerifyingEmpty(t *testing.T) {
	script := &scriptedTransport{steps: []scriptedStep{
		{expect: append([]byte{0x00, 0xA4, 0x04, 0x00, 0x06}, openPGPAID...), status: 0x9000},
	}}
	driver, err := NewDriver(&scriptedOpener{transport: script, ready: true}, failingPIN{})
	if err != nil {
		t.Fatal(err)
	}
	card, err := driver.Open(context.Background(), "wallet-1")
	if err != nil {
		t.Fatal(err)
	}
	defer card.Close()
	if _, err := card.Sign(context.Background(), "ed25519", []byte{1}); err == nil {
		t.Fatal("an operation without any PW1 succeeded")
	}
	if script.callCount() != 1 {
		t.Fatalf("a VERIFY was sent anyway: %d commands", script.callCount())
	}
}

func (script *scriptedTransport) lastError() error {
	script.mu.Lock()
	defer script.mu.Unlock()
	return script.lastErr
}

func allCalls(script *scriptedTransport) [][]byte {
	script.mu.Lock()
	defer script.mu.Unlock()
	calls := make([][]byte, len(script.calls))
	copy(calls, script.calls)
	return calls
}

// THE SERIAL IS DECODED THE WAY THE CARD ENCODES IT, AND ONLY FOR THE MANUFACTURER MEASURED.
//
// Falsifiers: read the four serial bytes as a big-endian integer again (the real AID then
// reports 630339842); drop the BCD nibble check (a non-BCD serial is accepted as a number);
// drop the manufacturer check (an unmeasured card is decoded by guess).
func TestTheAIDSerialIsDecodedAsTheCardEncodesIt(t *testing.T) {
	t.Run("the real YubiKey AID yields the serial ykman reports", func(t *testing.T) {
		serial, err := serialFromAID(realYubiKeyAID)
		if err != nil || serial != "25923902" {
			t.Fatalf("serial = %q, %v; want 25923902", serial, err)
		}
	})
	t.Run("leading zero digits are not part of the serial", func(t *testing.T) {
		serial, err := serialFromAID(aidWith(manufacturerYubico, [4]byte{0x01, 0x23, 0x45, 0x67}))
		if err != nil || serial != "1234567" {
			t.Fatalf("serial = %q, %v; want 1234567", serial, err)
		}
	})
	t.Run("a serial byte that is not BCD is refused", func(t *testing.T) {
		if serial, err := serialFromAID(aidWith(manufacturerYubico, [4]byte{0x25, 0x92, 0x3A, 0x02})); err == nil {
			t.Fatalf("a non-BCD serial was decoded as %q", serial)
		}
	})
	t.Run("an unmeasured manufacturer is refused by name", func(t *testing.T) {
		serial, err := serialFromAID(aidWith(0x0005, [4]byte{0x25, 0x92, 0x39, 0x02}))
		if err == nil || !strings.Contains(err.Error(), "0005") {
			t.Fatalf("manufacturer 0005 decoded as %q, %v; want a refusal naming it", serial, err)
		}
	})
}
