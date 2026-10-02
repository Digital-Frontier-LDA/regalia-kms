//go:build piv

package yubikey

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// The real session's Login says ErrPINNotPresented for every refusal that comes BEFORE the card
// is given the PIN, and never after.
func TestThePIVSessionSaysWhenThePINWasNotPresented(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for name, login := range map[string]func() error{
		"the request has ended":   func() error { return (&pivSession{serial: "1"}).Login(ended, []byte("123456")) },
		"the session has no card": func() error { return (&pivSession{serial: "1"}).Login(context.Background(), []byte("123456")) },
		"the session is closed": func() error {
			return (&pivSession{serial: "1", closed: true}).Login(context.Background(), []byte("123456"))
		},
	} {
		if err := login(); !errors.Is(err, ErrPINNotPresented) {
			t.Errorf("%s: Login = %v, want ErrPINNotPresented", name, err)
		}
	}

	// The text of Login: ErrPINNotPresented is returned before VerifyPIN is called and not after.
	source, err := os.ReadFile("piv_driver.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	start := strings.Index(text, "func (session *pivSession) Login(")
	if start < 0 {
		t.Fatal("pivSession.Login is not in piv_driver.go")
	}
	body := text[start:]
	body = body[:strings.Index(body, "\n}\n")]
	verify := strings.Index(body, "VerifyPIN(")
	if verify < 0 {
		t.Fatal("pivSession.Login no longer calls VerifyPIN: this test must be rewritten for what presents the PIN now")
	}
	if strings.Count(body[:verify], "return ErrPINNotPresented") != 1 {
		t.Fatalf("before VerifyPIN, Login must return ErrPINNotPresented exactly once (the refusal before the PIN is presented)")
	}
	if strings.Contains(body[verify:], "ErrPINNotPresented") {
		t.Fatal("Login says ErrPINNotPresented AFTER VerifyPIN: a PIN the card was given must count against the latch")
	}
}
