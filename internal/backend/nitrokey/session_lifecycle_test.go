package nitrokey

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// acceptingToken answers the three session-lifecycle calls and nothing else.
//
// It ACCEPTS rather than refuses, deliberately. Every test below asserts a refusal that happens
// BEFORE the token is consulted, so a token that said no would produce the right outcome for the
// wrong reason and the tests would pass with the guard deleted. Accepting means a defeated guard
// reaches a token that says yes, and the assertion fails on what actually changed.
//
// The embedded nil cryptoki is the package's existing convention: anything these tests do not stub
// panics rather than returning a usable zero value, so a guard that starts calling something new
// fails loudly here instead of quietly passing against an invented answer.
type acceptingToken struct {
	cryptoki
	logins, logouts, closes int
}

func (token *acceptingToken) Login(pkcs11.SessionHandle, uint, string) error {
	token.logins++
	return nil
}
func (token *acceptingToken) Logout(pkcs11.SessionHandle) error {
	token.logouts++
	return nil
}
func (token *acceptingToken) CloseSession(pkcs11.SessionHandle) error {
	token.closes++
	return nil
}

// TestLoginRefusesAPINThePolicyForbidsBeforeTheTokenSeesIt pins the three PIN-shape operands.
//
// The guard is `usable(ctx) != nil || len(pin) < 6 || len(pin) > 64 || containsZero(pin)`, and a
// sweep kills only the first two of those four: the error clause and the lower bound. Every fixture
// in this package supplies a six-byte PIN, so the length range is approached from below and never
// from above, and no fixture has ever contained a NUL.
//
// The suite states the gap in its own vocabulary. TestExecuteFailsOnTooShortPIN exists; there is no
// TooLong twin, and nothing names an embedded NUL at all.
//
// It matters because the PIN is about to be handed to C_Login as a Go string. A value the policy
// forbids is a misconfigured PIN source, not a credential, and sending it spends one of the few
// retries the budget exists to protect on an attempt that cannot succeed. A NUL is worse than
// useless: string(pin) carries it into the C boundary, where the token may read a truncated
// credential and count a failure against a PIN nobody typed.
//
// Isolation: the session is open and the context live, so the error clause cannot fire; every row
// differs from the accepted control in exactly one property; and the token ACCEPTS, so a defeated
// guard shows up as a successful login rather than as a refusal from the wrong place.
func TestLoginRefusesAPINThePolicyForbidsBeforeTheTokenSeesIt(t *testing.T) {
	// A six-byte PIN is what every other fixture uses, and it must be accepted, or the rows below
	// would pass against a guard that refused everything.
	token := &acceptingToken{}
	session := &pkcs11Session{module: token}
	if err := session.Login(context.Background(), []byte("123456")); err != nil || token.logins != 1 {
		t.Fatalf("control is broken, so the refusals below would prove nothing: a six-byte PIN gave "+
			"err=%v logins=%d", err, token.logins)
	}

	for _, test := range []struct {
		name    string
		pin     []byte
		operand string
	}{
		{"one byte under the lower bound", bytes.Repeat([]byte("a"), 5), "len(pin) < 6"},
		{"one byte over the upper bound", bytes.Repeat([]byte("a"), 65), "len(pin) > 64"},
		{"exactly the upper bound is accepted", bytes.Repeat([]byte("a"), 64), ""},
		{"a NUL inside an otherwise valid PIN", []byte("12\x003456"), "containsZero(pin)"},
		{"a PIN that is only NULs", make([]byte, 8), "containsZero(pin)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := &acceptingToken{}
			session := &pkcs11Session{module: token}
			err := session.Login(context.Background(), test.pin)

			if test.operand == "" {
				if err != nil || token.logins != 1 {
					t.Fatalf("DEFECT: a %d-byte PIN, exactly the upper bound, was refused (err=%v "+
						"logins=%d); the guard is `> 64`, so 64 must be accepted or this is not a "+
						"bound", len(test.pin), err, token.logins)
				}
				return
			}
			if err == nil {
				t.Fatalf("DEFECT: a %d-byte PIN %q was accepted; operand %s is the only thing that "+
					"refuses it, and the value reaches C_Login as a Go string",
					len(test.pin), test.pin, test.operand)
			}
			if token.logins != 0 {
				t.Fatalf("DEFECT: the PIN reached the token (%d logins) before being refused; "+
					"operand %s exists so a value the policy forbids never spends a retry",
					token.logins, test.operand)
			}
		})
	}
}

// TestASessionRefusesUseAfterCloseAndLoginTwice pins the four lifecycle operands.
//
// Each is a state the session tracks itself rather than asks the token about, so none of them can be
// reached through SoftHSM — the e2e drives a well-behaved sequence and never asks a closed session
// to work or logs in twice. They are reachable here only because pkcs11Session is a struct this
// package's tests can build in any state, which is the same door stubSession already uses.
//
// What each prevents:
//
//	:213 loggedIn   a second C_Login on a session already logged in. The token counts it as an
//	                attempt, so a redundant login spends a retry for nothing.
//	:213 closed     a login on a closed session, i.e. a C_Login against a handle the driver has
//	                already returned to the token.
//	:515 closed     any use of a closed session, which is the guard the other entry points share.
//	:527 !loggedIn  a private-key operation before authentication, which the token would refuse -
//	                but refusing here means it is refused without a round trip that could count.
//
// Isolation: the token ACCEPTS every call, so each row's refusal can only come from the state the
// row sets, and the call counters distinguish "refused" from "refused after asking the token".
//
// ONE OF THE FOUR IS PINNED ONLY AS A PAIR, and the reason is worth stating rather than leaving as
// an unexplained survivor. Login's `closed` operand cannot be the sole refuser of any input a test
// can build: Login calls usable() first, and usable refuses a closed session already, so the second
// check never sees a closed session that the first let through. Measured — neutralising Login's
// `closed` operand alone leaves the suite green; neutralising it TOGETHER with usable's turns the
// "login on a closed session" row below red.
//
// It is redundant single-threaded and not redundant at all otherwise. usable() takes the mutex and
// RELEASES it before Login re-acquires it, so a Close() landing in that window closes the session
// between the two checks. Login's own `closed` read, under the lock it then holds, is what refuses
// that interleaving. Forcing it deterministically would need the lock to be released at a chosen
// instant, which a test here cannot do without reaching inside the mutex, so this records the
// operand's purpose instead of pinning it with a race that would pass most of the time.
func TestASessionRefusesUseAfterCloseAndLoginTwice(t *testing.T) {
	t.Run("login on a session already logged in", func(t *testing.T) {
		token := &acceptingToken{}
		session := &pkcs11Session{module: token, loggedIn: true}
		if err := session.Login(context.Background(), []byte("123456")); err == nil {
			t.Fatal("DEFECT: a second login on an already-authenticated session was accepted; the " +
				"token counts the attempt, so it spends a retry to reach the state it is in")
		}
		if token.logins != 0 {
			t.Fatalf("DEFECT: the redundant login reached the token (%d calls)", token.logins)
		}
	})

	t.Run("login on a closed session", func(t *testing.T) {
		token := &acceptingToken{}
		session := &pkcs11Session{module: token, closed: true}
		if err := session.Login(context.Background(), []byte("123456")); err == nil {
			t.Fatal("DEFECT: a login on a closed session was accepted; the handle has already been " +
				"returned to the token")
		}
		if token.logins != 0 {
			t.Fatalf("DEFECT: a closed session logged in (%d calls)", token.logins)
		}
	})

	t.Run("any use of a closed session", func(t *testing.T) {
		open := &pkcs11Session{module: &acceptingToken{}}
		if err := open.usable(context.Background()); err != nil {
			t.Fatalf("control is broken: an open session reports unusable: %v", err)
		}
		closed := &pkcs11Session{module: &acceptingToken{}, closed: true}
		err := closed.usable(context.Background())
		if err == nil {
			t.Fatal("DEFECT: a closed session reports itself usable; every entry point shares this " +
				"guard, so defeating it reopens all of them at once")
		}
		if want := "PKCS#11 session is closed"; !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal is %q, want it to contain %q — the sibling refusal in privateUsable "+
				"says \"login required\", and only the message tells the two states apart",
				err.Error(), want)
		}
	})

	t.Run("a private-key operation before authentication", func(t *testing.T) {
		in := &pkcs11Session{module: &acceptingToken{}, loggedIn: true}
		if err := in.privateUsable(context.Background()); err != nil {
			t.Fatalf("control is broken: an authenticated session refuses private use: %v", err)
		}
		out := &pkcs11Session{module: &acceptingToken{}}
		err := out.privateUsable(context.Background())
		if err == nil {
			t.Fatal("DEFECT: a session that has not logged in was cleared for private-key use")
		}
		if want := "PKCS#11 login required"; !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal is %q, want it to contain %q", err.Error(), want)
		}
	})

	t.Run("closing an already-closed session is a no-op", func(t *testing.T) {
		token := &acceptingToken{}
		session := &pkcs11Session{module: token, closed: true}
		if err := session.Close(); err != nil {
			t.Fatalf("DEFECT: closing an already-closed session returned %v; Close is idempotent so "+
				"a deferred close after an explicit one is not an error", err)
		}
		if token.closes != 0 || token.logouts != 0 {
			t.Fatalf("DEFECT: the second close reached the token (closes=%d logouts=%d); the handle "+
				"is already returned, so this is a use-after-free at the PKCS#11 boundary",
				token.closes, token.logouts)
		}
	})
}
