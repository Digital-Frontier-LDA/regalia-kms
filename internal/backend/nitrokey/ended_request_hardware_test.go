package nitrokey

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// endingDriver is the real driver, with the request ending the moment the token has been opened:
// what a caller who hangs up, or an executor timeout, does at the worst moment, made certain.
type endingDriver struct {
	Driver
	end func()
	// opened counts the Opens that returned a session while a request was being ended, and failed
	// keeps the last one that did not: an ended look that never got a session tests nothing.
	opened int
	failed error
}

func (driver *endingDriver) Open(ctx context.Context, binding registry.Binding) (Session, error) {
	session, err := driver.Driver.Open(ctx, binding)
	if driver.end != nil {
		if err == nil && session != nil {
			driver.opened++
		} else {
			driver.failed = fmt.Errorf("open under the request that was to be ended: %v", err)
		}
		driver.end()
	}
	return session, err
}

// A REQUEST THAT ENDS RIGHT AFTER A REAL TOKEN WAS OPENED LATCHES NOTHING (regalia-kms#178).
//
// The defect was found by reading and fixed with stand-in sessions (ended_request_test.go). This
// runs the real driver and the real probes against a real SmartCard-HSM, so that what "the real
// session refuses an ended context" does to the provider is measured, not inferred. No PIN is
// presented and nothing is written: the health check and a public-key read do not log in.
//
//	REGALIA_ENDED_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
//	REGALIA_ENDED_SERIAL=DENK0404144 \
//	  go test ./internal/backend/nitrokey/ -run TestARequestThatEndsAfterARealTokenWasOpenedLatchesNothing -v
//
// THE TOKEN NEEDS NO KEY. A binding must pin something to be served, and the bench token holds no
// object, so the binding pins a public key that is not there. That is put to use: under a LIVE
// request the provider then gets past the identity and the secure channel and stops at the pinned
// key ("public-key-mismatch"), which is the evidence that the identity it called a mismatch under
// an ended request reads correctly under a live one. The identity is also read directly, first.
//
// REGALIA_ENDED_BEFORE_FIX=1 turns the expectation round, for reproducing the defect on a commit
// before the fix (6d722bf): there the token must come out quarantined as "identity-mismatch"
// although it never left.
//
// MEASURED ON DENK0404144 (Nitrokey HSM 2, applet 4.1, OpenSC 0.26.1), 2026-10-02:
//
//	a67dec6 (before the fix)  after the health check and after the public-key operation:
//	                          quarantined=true reason="identity-mismatch", with the token attached
//	                          and answering for its identity under a live request
//	6d722bf (the fix)         quarantined=false after both; the next live request passes the identity
//	                          and the secure channel and stops at the pinned key
//
// Each commit fails the other's expectation.
func TestARequestThatEndsAfterARealTokenWasOpenedLatchesNothing(t *testing.T) {
	modulePath, serial := os.Getenv("REGALIA_ENDED_MODULE"), os.Getenv("REGALIA_ENDED_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_ENDED_MODULE and REGALIA_ENDED_SERIAL")
	}
	beforeFix := os.Getenv("REGALIA_ENDED_BEFORE_FIX") == "1"

	evidence := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(evidence, []byte(fmt.Sprintf(`{"schema_version":1,"devices":[{"device_serial":%q,"verified_by":"bench","verified_at":%q,"expires_at":%q,"firmware":"bench","secure_messaging_established":true}]}`,
		serial, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339))), 0o600); err != nil {
		t.Fatal(err)
	}
	channel, err := LoadSecureChannelEvidence(evidence, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	real, err := NewPKCS11DriverWithProbes(modulePath, channel)
	if err != nil {
		t.Fatalf("load the module: %v", err)
	}
	defer real.Close()
	driver := &endingDriver{Driver: real}
	pins := &fakePIN{value: []byte("000000")} // never fetched: nothing here logs in
	provider, err := New(driver, pins)
	if err != nil {
		t.Fatal(err)
	}
	bound := registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-bench", DeviceSerial: serial, ObjectID: "01", State: "active",
		PublicKeySHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
	route := registry.Route{Algorithm: "p256", Binding: bound}
	live := context.Background()

	// 0. The token is there and answers for its identity under a live request.
	session, err := real.Open(live, bound)
	if err != nil {
		t.Fatalf("setup: open %s: %v", serial, err)
	}
	answered, _, err := session.Identity(live)
	if closeErr := session.Close(); err != nil || closeErr != nil || answered != serial {
		t.Fatalf("setup: the token does not answer for its identity under a live request: %q, %v, close %v", answered, err, closeErr)
	}
	t.Logf("under a live request the token answers for its identity: %s", answered)

	// 1. A request that ends the moment the token has been opened.
	for _, look := range []string{"health check", "public-key operation"} {
		ended, end := context.WithCancel(context.Background())
		driver.end = end
		switch look {
		case "health check":
			if provider.Healthy(ended, bound) {
				t.Fatalf("%s: reported healthy under a request that had ended", look)
			}
		default:
			if _, _, err := provider.Execute(ended, route, "public-key", "", "", nil, nil); err == nil {
				t.Fatalf("%s: served under a request that had ended", look)
			}
		}
		driver.end = nil
		end()
		// The request really got the token open and reached the checks under an ended context.
		// Without this, an Open that failed for any reason would set no latch and the fixed
		// expectation would pass without having tested anything.
		if driver.opened != 1 || driver.failed != nil {
			t.Fatalf("%s: the ended request did not open the token exactly once (%d sessions, %v): the case tests nothing", look, driver.opened, driver.failed)
		}
		driver.opened = 0
		reason, latched := provider.QuarantineReason(bound.DeviceID)
		t.Logf("after a %s whose request ended right after Open: quarantined=%v reason=%q", look, latched, reason)
		if beforeFix {
			if !latched || reason != "identity-mismatch" {
				t.Fatalf("%s: expected the defect (quarantined as identity-mismatch with the token present), got quarantined=%v reason=%q", look, latched, reason)
			}
			t.Logf("DEFECT REPRODUCED: the token never left and answers for its identity, and it is out of service until an operator resets it")
			provider.ResetPINBlock(bound.DeviceID) // the operator's reset, so the second look starts clean
			continue
		}
		if latched {
			t.Fatalf("%s: a request that ended latched the token out of service (%s) although it never left", look, reason)
		}
		// 2. The next request, under a live context, gets PAST the identity and the secure channel:
		// it stops at the pinned key, which this binding gets wrong on purpose.
		if provider.Healthy(live, bound) {
			t.Fatalf("%s: healthy with a pinned key the token does not hold", look)
		}
		reason, latched = provider.QuarantineReason(bound.DeviceID)
		if !latched || reason != "public-key-mismatch" {
			t.Fatalf("%s: the next live request did not get past the identity check to the pinned key: quarantined=%v reason=%q", look, latched, reason)
		}
		t.Logf("the next live request passed the identity and the secure channel and stopped at the pinned key (%s), as it must", reason)
		provider.ResetPINBlock(bound.DeviceID)
	}
	if pins.calls != 0 {
		t.Fatalf("the PIN was fetched %d times: nothing here may log in", pins.calls)
	}
}
