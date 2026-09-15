//go:build piv

package yubikey

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// COVERAGE GAPS THE YUBIKEY SWEEP OF 2026-09-06 FOUND.
//
// Each test below cites the specific guard and the falsifier mutating it,
// and was measured against the named mutation before being included.

// ----------------------------------------------------------------------------
// piv_driver.go: NewPIVDriver blank-id / blank-serial
// ----------------------------------------------------------------------------

// Covers piv_driver.go L31-33 (NewPIVDriver rejects an empty device id or
// an empty serial). The existing TestPIVDriverRequiresPinnedDecimalSerials
// sends nil and {"ops":"not-a-serial"} — never a blank id with a parseable
// serial or a blank serial with a parseable id, so removing L31-33 leaves
// every existing test green. This test fills the gap.
//
// Falsifier: replace the predicate with `if false && (deviceID == "" ||
// serial == "")`. The blank-id case ({"" + valid serial}) then passes
// through L34's parse and the function returns success where it should
// refuse. The blank-serial case ({valid id + ""}) is caught by L34 since
// ParseUint("") fails — it is therefore redundant-but-clearer for THAT
// direction, and documented in the comment rather than asserted.
func TestNewPIVDriverRefusesABlankDeviceID(t *testing.T) {
	if _, err := NewPIVDriver(map[string]string{"": "12345678"}); err == nil {
		t.Fatal("NewPIVDriver accepted a blank device id paired with a parseable serial; " +
			"without L31-33 the construct succeeds and the daemon's id-to-serial map is built around an empty key")
	}
}

// ----------------------------------------------------------------------------
// provider.go: Execute Open err + valid session
// ----------------------------------------------------------------------------

// errReturningDriver is a Driver whose Open returns the supplied session
// AND a non-nil error. The existing riggedDriver returns only nil errors,
// so a driver that surfaces an Open error AND a session that would otherwise
// be healthy has no coverage: removing L58-60 lets the function fall through
// to Identity/Policies/PINRetries/Login/Sign, all of which succeed, and the
// operation completes. Without the test, the mutation survives.
type errReturningDriver struct{ session *riggedSession }

func (d *errReturningDriver) Open(context.Context, string) (Session, error) {
	return d.session, errors.New("device open failed")
}
func (*errReturningDriver) Ready(context.Context) bool { return true }

// Covers provider.go L58-60 (Execute refuses err != nil from Open, even
// when the session is otherwise usable). The driver returns the healthy
// session PLUS an error; without L58-60 the function runs Identity,
// Policies, PINRetries, login, and Sign with the session, succeeds at
// every step, and returns a signature — the test catches the mutation.
//
// Falsifier: replace `if err != nil || session == nil` with `if false &&
// err == nil && session != nil`. Erroneous path now reaches signing.
func TestExecuteRefusesAnOpenThatReturnsSessionAndError(t *testing.T) {
	session := healthySession()
	provider, err := New(&errReturningDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}

	output, _, execErr := provider.Execute(context.Background(), route(), "sign", "", "application/octet-stream", []byte("payload"), nil)
	if execErr == nil {
		t.Fatalf("Execute accepted an Open that returned an error: %q", output)
	}
	if !errors.Is(execErr, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", execErr)
	}
	if session.signed {
		t.Fatalf("the signature reached the card despite the Open error")
	}
}

// ----------------------------------------------------------------------------
// provider.go: Execute wrap with a key RSAOAEP cannot parse
// ----------------------------------------------------------------------------

// Covers provider.go L97-100 (Execute refuses RSAOAEP errors in the wrap
// path). The existing TestWrapRefusesAnyFormatButTheEnvelope reaches L97-100
// only after passing format="regalia-envelope-v2"; the test fixture uses
// wrappableSession with a real PKIX-encoded RSA-2048 key, so RSAOAEP
// succeeds and L97-100's branch is never observed. A fixture built from
// the literal "public" bytes makes RSAOAEP's PKIX parse fail, exercising
// L97-100. Without L97-100, the function returns (nil, "application/vnd.
// regalia.wrapped-key", nil) — execErr is nil, the test sees success
// where the source promises a refusal.
//
// Falsifier: replace `if err != nil` with `if false && err != nil`. The
// wrap path now returns the literal wrapped-key content type with a nil
// error.
func TestWrapRefusesAnUnparseableCardKey(t *testing.T) {
	session := healthySession()
	session.publicKey = []byte("public")
	provider, err := New(&riggedDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	wrapRoute := route()
	wrapRoute.Algorithm = "rsa2048"

	output, outputType, execErr := provider.Execute(context.Background(), wrapRoute, "wrap", "regalia-envelope-v2", "", []byte("data-key"), []byte("aad"))
	if execErr == nil {
		t.Fatalf("wrap accepted an unparseable card key: output=%q outputType=%q", output, outputType)
	}
	if !errors.Is(execErr, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", execErr)
	}
	if len(output) != 0 || outputType != "" {
		t.Fatalf("output=%q outputType=%q; the wrap that errored produced a content type — the L97-100 branch "+
			"must return zero bytes and no content type so a partial result cannot masquerade as a successful wrap", output, outputType)
	}
}

// ----------------------------------------------------------------------------
// provider.go: Execute unwrap with a third format
// ----------------------------------------------------------------------------

// framedUnwrapSession is a riggedSession whose Unwrap returns a valid
// regalia-envelope-v2 frame, so OpenFrame returns its declared plaintext
// rather than failing the parse. The frame is built with the same magic
// and length-prefixed layout keywrap.OpenFrame reads (keywrap.rsa.go:43
// frameHeaderLen); without the third-format check at L131-134, the
// unwrap path would call OpenFrame and succeed — an unwrapped key would
// be returned for a format the operator did not name.
type framedUnwrapSession struct {
	*riggedSession
	unwrapFrame []byte
}

func (s *framedUnwrapSession) Unwrap(_ context.Context, _, _ string, _, aad []byte) ([]byte, error) {
	if s.unwrapFrame == nil {
		return nil, errors.New("framedUnwrapSession needs an unwrapFrame")
	}
	return append([]byte(nil), s.unwrapFrame...), nil
}

// framedUnwrapDriver hands Open the wrapper directly so the Session-method
// dispatch reaches framedUnwrapSession.Unwrap (not the embedded
// *riggedSession.Unwrap that always errors).
type framedUnwrapDriver struct{ session *framedUnwrapSession }

func (d *framedUnwrapDriver) Open(context.Context, string) (Session, error) {
	return d.session, nil
}
func (*framedUnwrapDriver) Ready(context.Context) bool { return true }

// Covers provider.go L131-134 (Execute refuses a format that is neither
// regalia-envelope-v2 nor sops-pgp on the unwrap path). The existing tests
// for unwrap do not exercise this branch; without L131-134, the unwrap
// path calls session.Unwrap regardless of format and, if the session
// returns a valid frame, returns the plaintext — silently accepting a
// format the API does not advertise. This test reaches that result
// directly: a session that hands back a valid v2 frame, a format that
// is not in the allowlist, and an assertion that the operation refused.
//
// Falsifier: replace the predicate with `if false`. Without L131-134 the
// unwrap path runs to OpenFrame (with the valid frame above) and returns
// the plaintext bytes — execErr is nil and output equals the declared
// plaintext. The test fails on mutation.
func TestUnwrapRefusesAFormatOutsideTheAllowlist(t *testing.T) {
	session := &framedUnwrapSession{riggedSession: healthySession()}
	aad := []byte("aad-for-third-format-test")
	// 32 bytes — a typical AES-256 data-key size, and short enough that
	// OpenFrame's length-prefix check (gate.go:99) is the only thing that
	// varies across our mutations. Asserted explicitly so a fixture edit
	// that changes the documented length fails the test rather than
	// silently passing the length-check guard.
	plaintext := []byte("decrypted-data-key-32-bytes-long")
	if len(plaintext) != 32 {
		t.Fatalf("plaintext fixture length = %d, want 32; "+
			"a 36-byte literal would have hidden behind the control-case check "+
			"and made the length-prefix guard unreachable", len(plaintext))
	}
	frame := make([]byte, 0, 4+sha256.Size+4+len(plaintext))
	frame = append(frame, 'R', 'G', 'K', 2)
	digest := sha256.Sum256(aad)
	frame = append(frame, digest[:]...)
	var lengthBuf [4]byte
	binary.BigEndian.PutUint32(lengthBuf[:], uint32(len(plaintext)))
	frame = append(frame, lengthBuf[:]...)
	frame = append(frame, plaintext...)
	session.unwrapFrame = frame

	sessionDriver := &framedUnwrapDriver{session: session}
	provider, err := New(sessionDriver, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	unwrapRoute := route()
	unwrapRoute.Algorithm = "rsa2048"

	output, outputType, execErr := provider.Execute(context.Background(), unwrapRoute, "unwrap", "pkcs8", "", []byte("any"), aad)
	if execErr == nil {
		t.Fatalf("unwrap accepted format %q and returned %q as %q — the third-format guard is what stops "+
			"a caller from getting a plaintext key through a path the API does not advertise", "pkcs8", output, outputType)
	}
	if !errors.Is(execErr, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", execErr)
	}
	// Build a control: the same inputs routed through the allowed format
	// would have succeeded. This asserts the test's fixture is sound
	// (OpenFrame would otherwise have made the test trivially pass even
	// without the guard).
	plaintextRoute := route()
	plaintextRoute.Algorithm = "rsa2048"
	if _, _, ctrlErr := provider.Execute(context.Background(), plaintextRoute, "unwrap", "regalia-envelope-v2", "", []byte("any"), aad); ctrlErr != nil {
		t.Fatalf("the same session, allowed format, refused: %v — the fixture is not what the test thinks it is", ctrlErr)
	}
}

// =============================================================================
// THE RESIDUALS SECTION THAT STOOD HERE WAS WRITTEN WITHOUT `-tags piv`.
// =============================================================================
//
// It listed seven guards as residual and six more as "UNREACHABLE — piv-driver
// runtime guards exist only when -tags piv is set", and closed by saying the
// runtime guards "were measured via `go build -tags piv ./...` and `go test
// -tags piv ./internal/backend/yubikey/...` and they remain GREEN under their
// falsifiers".
//
// Re-measured operand by operand for #237, most of that was wrong, and wrong in
// the direction that stops the next sweep looking:
//
//   provider.go:73  said "the divergence path is never observed". It is:
//                   TestPresenceOrSubstitutedDeviceFailsBeforePrivateOperation
//                   sets the card's serial to 87654321 against a binding
//                   pinning 12345678, and that operand is killed.
//   provider.go:77  said "no existing test sets them to divergent values". The
//                   same test sets touchPolicy to "always".
//   provider.go:104 cited coverage "through `fakeDriver.SetPINBlocked`". There
//                   is no such method in this package, and there never was.
//   provider.go:111 said "no falsifiable length error". Two files along,
//                   TestAPINOutsideTheAcceptedLengthNeverReachesTheCard drives
//                   a five-byte and a sixty-five-byte PIN through exactly it.
//   provider.go:124 said the Login error path "is unreachable from the unit
//                   tests". fakeSession.loginErr exists and
//                   TestPINFailureAndLowRetryCountPreventRepeatedLogin uses it.
//   piv_driver.go   the parseSlot residual quoted a mutation, `if false && slot
//                   != piv.Slot{}`, of a line that reads
//                   `number, err := strconv.ParseUint(...)`.
//
// A dismissal is a claim, and it needs the measurement its subject needed. The
// standing classifications for this package now live with the operands
// themselves — provider_boundary_test.go and piv_session_boundary_test.go —
// where each one names the guard that masks it and was confirmed by
// neutralising that operand and observing the suite stay green, rather than by
// argument.
//
// Two of the old residuals survived re-measurement and are recorded there:
// provider.go:137 op0 (masked by the final err/len backstop) and
// piv_driver.go:31 op1 (masked by strconv.ParseUint). Four did not.
