package nitrokey

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// A REQUEST THAT ENDS IS NEVER EVIDENCE ABOUT THE TOKEN (regalia-kms#178, found by an independent
// read). Every driver call refuses an ended context. The identity, secure-channel, pinned-key and
// KEK-provenance checks latch the token out of service on failure, until an operator resets it; so a
// request cancelled or timed out between Open and one of them latched every key on the token, with
// the token in place and in order. A caller allowed one key could do it by hanging up, and an
// executor timeout did it with nobody attacking.

type endedCase struct {
	name      string
	endBefore string
	operation string
	algorithm string
	pinned    bool // the binding pins the commissioned public key, so PublicKey is a latching check
	logins    int  // how many times the PIN has rightly been presented by the time the request ends
}

var endedCases = []endedCase{
	{"after Open, before the identity is read", "Identity", "sign", "rsa2048", false, 0},
	{"before the secure channel", "EstablishSecureChannel", "sign", "rsa2048", false, 0},
	{"before the pinned public key is read", "PublicKey", "sign", "rsa2048", true, 0},
	{"before the KEK's provenance is asked (wrap)", "AssertKEKGeneratedOnToken", "wrap", "rsa2048", false, 0},
	{"before the KEK's extractability is asked (unwrap, after the login)", "AssertKEKNonExportable", "unwrap", "rsa2048", false, 1},
	{"before the retry counter is read", "PINRetries", "sign", "rsa2048", false, 0},
	{"before the PIN is presented", "Login", "sign", "rsa2048", false, 0},
}

func endedBinding(c endedCase) registry.Binding {
	b := binding()
	if c.pinned {
		b.PublicKeySHA256 = pinFor([]byte("public"))
	}
	return b
}

func executeOn(ctx context.Context, provider *Provider, b registry.Binding, operation, algorithm string) error {
	format, contentType, data, aad := "", "application/vnd.regalia.digest", []byte("digest"), []byte(nil)
	if operation == "wrap" || operation == "unwrap" {
		format, contentType, data, aad = "regalia-envelope-v2", "application/vnd.regalia.data-key", []byte("wrapped"), []byte("context")
	}
	_, _, err := provider.Execute(ctx, registry.Route{Algorithm: algorithm, Binding: b}, operation, format, contentType, data, aad)
	return err
}

func TestARequestThatEndsBetweenOpenAndACheckLatchesNothing(t *testing.T) {
	for _, c := range endedCases {
		t.Run("execute: "+c.name, func(t *testing.T) {
			session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
			pins := &fakePIN{value: []byte("123456")}
			provider, _ := New(&fakeDriver{session: session}, pins)
			b := endedBinding(c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session.endBefore, session.end = c.endBefore, cancel
			if err := executeOn(ctx, provider, b, c.operation, c.algorithm); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("the ended request: %v", err)
			}
			if ctx.Err() == nil {
				t.Fatalf("the request never reached %s: the case tests nothing", c.endBefore)
			}
			if reason, latched := provider.QuarantineReason(b.DeviceID); latched {
				t.Fatalf("a request that ended %s latched the token: %q", c.name, reason)
			}
			if session.loginCalls != c.logins {
				t.Fatalf("the PIN was presented %d times, want %d: nothing is presented under a request that has ended", session.loginCalls, c.logins)
			}
			// the very next request, by anybody, is served: nothing was left behind
			session.endBefore, session.end = "", nil
			if err := executeOn(context.Background(), provider, b, "sign", "rsa2048"); err != nil {
				t.Fatalf("the next request was not served: %v", err)
			}
			if !provider.Healthy(context.Background(), b) {
				t.Fatal("the token is not healthy after a request that ended")
			}
		})
	}
	for _, c := range endedCases[:3] { // the checks Healthy makes
		t.Run("health check: "+c.name, func(t *testing.T) {
			session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
			provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
			b := endedBinding(c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session.endBefore, session.end = c.endBefore, cancel
			if provider.Healthy(ctx, b) {
				t.Fatal("healthy under a request that ended")
			}
			if reason, latched := provider.QuarantineReason(b.DeviceID); latched || ctx.Err() == nil {
				t.Fatalf("latched=%v (%q), ended=%v", latched, reason, ctx.Err() != nil)
			}
			session.endBefore, session.end = "", nil
			if !provider.Healthy(context.Background(), b) {
				t.Fatal("the token is not healthy at the next look")
			}
		})
	}
}

// THE LATCHES STILL LATCH. Under a request that is alive, each check that fails against the token sets
// its latch as before: a swap, a channel that will not establish, a key that is not the pinned one.
func TestACheckThatFailsUnderALiveRequestStillLatches(t *testing.T) {
	for name, c := range map[string]struct {
		breakIt func(*fakeSession, *registry.Binding)
		reason  string
		op      string
	}{
		"another card":             {func(s *fakeSession, _ *registry.Binding) { s.serial = "another" }, "identity-mismatch", "sign"},
		"no secure channel":        {func(s *fakeSession, _ *registry.Binding) { s.secureErr = true }, "secure-channel-failed", "sign"},
		"not the pinned key":       {func(_ *fakeSession, b *registry.Binding) { b.PublicKeySHA256 = pinFor([]byte("another key")) }, "public-key-mismatch", "sign"},
		"a KEK that is exportable": {func(s *fakeSession, _ *registry.Binding) { s.exportable = ErrKEKExportable }, "kek-exportable", "unwrap"},
		"a wrong PIN":              {func(s *fakeSession, _ *registry.Binding) { s.loginErr = errors.New("CKR_PIN_INCORRECT") }, "pin-budget-spent", "sign"},
	} {
		t.Run(name, func(t *testing.T) {
			session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint}
			provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
			b := binding()
			c.breakIt(session, &b)
			if err := executeOn(context.Background(), provider, b, c.op, "rsa2048"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("%v", err)
			}
			if reason, latched := provider.QuarantineReason(b.DeviceID); !latched || reason != c.reason {
				t.Fatalf("latched=%v reason=%q, want %q", latched, reason, c.reason)
			}
		})
	}
}

// THE PIN LATCH IS SKIPPED ONLY WHEN THE PIN CERTAINLY DID NOT REACH THE TOKEN. A request that ends
// WHILE the PIN is with the token has presented it; if the token refused it, the latch must be set,
// or the next request presents the same wrong PIN again and spends another try.
func TestAWrongPINPresentedWhileTheRequestEndsIsStillLatched(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: binding().DevAuthFingerprint, loginErr: errors.New("CKR_PIN_INCORRECT"), endDuringLogin: true}
	provider, _ := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session.end = cancel
	if err := executeOn(ctx, provider, binding(), "sign", "rsa2048"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if ctx.Err() == nil || session.loginCalls != 1 {
		t.Fatalf("the fixture did not present the PIN under a request that then ended: ended=%v presented=%d", ctx.Err() != nil, session.loginCalls)
	}
	if reason, latched := provider.QuarantineReason("hsm-sitea"); !latched || reason != "pin-budget-spent" {
		t.Fatalf("a wrong PIN presented while the request ended was not latched (latched=%v %q): the next request would spend another try", latched, reason)
	}
	session.endDuringLogin, session.end = false, nil
	if err := executeOn(context.Background(), provider, binding(), "sign", "rsa2048"); !errors.Is(err, ErrUnavailable) || session.loginCalls != 1 {
		t.Fatalf("the PIN was presented a second time: err=%v presented=%d", err, session.loginCalls)
	}
}

// The driver says "not presented" before the PIN goes anywhere near the module, and only then.
func TestTheDriverNamesALoginItRefusedBeforeThePINReachedTheToken(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	session := &pkcs11Session{}
	if err := session.Login(ended, []byte("123456")); !errors.Is(err, ErrPINNotPresented) {
		t.Fatalf("under an ended context: %v", err)
	}
	session.closed = true
	if err := session.Login(context.Background(), []byte("123456")); !errors.Is(err, ErrPINNotPresented) {
		t.Fatalf("on a closed session: %v", err)
	}
	// a PIN the driver will not send is refused, and that is NOT "not presented" in the latch's sense:
	// it is the wrong credential, and latching on it is what stops it being tried again
	open := &pkcs11Session{}
	for _, pin := range [][]byte{[]byte("12345"), make([]byte, 65), {'1', '2', 0, '4', '5', '6'}} {
		if err := open.Login(context.Background(), pin); err == nil || errors.Is(err, ErrPINNotPresented) {
			t.Fatalf("a malformed PIN of %d bytes: %v", len(pin), err)
		}
	}
	already := &pkcs11Session{loggedIn: true}
	if err := already.Login(context.Background(), []byte("123456")); err == nil || errors.Is(err, ErrPINNotPresented) {
		t.Fatalf("a second login: %v", err)
	}
}

// THE NEXT LATCH MUST NOT FORGET THE RULE. provider.go's own text is read: a latch may be set only
//   - by quarantineUnlessTheRequestEnded (after a check made under the request's context),
//   - at the low-retry reading (a read that completed: `if retryErr == nil`),
//   - after a Login that was not ErrPINNotPresented.
//
// A new `provider.quarantine(` or `provider.blockPIN(` anywhere else fails here, and whoever adds it
// has to decide which of the three it is.
func TestEveryLatchInTheProviderIsOneOfTheThreeKinds(t *testing.T) {
	source, err := os.ReadFile("provider.go")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(source), "\n")
	before := func(i int) string { // the nearest line above that is not blank and not a comment
		for j := i - 1; j >= 0; j-- {
			if text := strings.TrimSpace(lines[j]); text != "" && !strings.HasPrefix(text, "//") {
				return text
			}
		}
		return ""
	}
	direct, pin := 0, 0
	for i, line := range lines {
		text := strings.TrimSpace(line)
		if strings.HasPrefix(text, "//") {
			continue
		}
		switch {
		case strings.Contains(text, "provider.quarantine("):
			direct++
			above := before(i)
			if above != "if ctx.Err() == nil {" && above != "func (provider *Provider) blockPIN(deviceID string) {" {
				t.Errorf("provider.go:%d sets a latch directly, after %q: go through quarantineUnlessTheRequestEnded", i+1, above)
			}
		case strings.Contains(text, "provider.blockPIN("):
			pin++
			above := before(i)
			if above != "if retryErr == nil {" && above != "if !errors.Is(err, ErrPINNotPresented) {" {
				t.Errorf("provider.go:%d sets the PIN latch after %q: only a completed retry reading or a PIN that was presented may", i+1, above)
			}
		}
	}
	if direct != 2 || pin != 2 {
		t.Fatalf("found %d direct latches and %d PIN latches, want 2 and 2: the provider's latches changed, and this test must be told how", direct, pin)
	}
	if helper := strings.Count(string(source), "provider.quarantineUnlessTheRequestEnded(ctx, "); helper != 8 {
		t.Fatalf("found %d latches through the helper, want 8", helper)
	}
}
