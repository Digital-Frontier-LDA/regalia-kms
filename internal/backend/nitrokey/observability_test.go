package nitrokey

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// A QUARANTINE NOBODY CAN SEE IS A BACKEND THAT IS DOWN FOR NO VISIBLE REASON.
//
// The latch existed and the reason was recorded, but nothing enumerated it: an
// operator learned a device was out of service only by every operation on it
// failing. The gauge must move when the latch does — a test that quarantines a
// device through the real Execute path and asserts the enumeration is what makes
// "reports zero because nothing ever wrote to it" impossible.
func TestQuarantineIsEnumeratedWithTheFirstReason(t *testing.T) {
	session := &fakeSession{serial: "serial-WRONG", devaut: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := provider.Execute(context.Background(), registry.Route{Algorithm: "rsa2048", Binding: binding()}, "sign", "", "application/octet-stream", []byte("payload"), nil); err == nil {
		t.Fatal("a device answering with the wrong identity was allowed to sign")
	}
	quarantined := provider.Quarantined()
	if reason, ok := quarantined["hsm-sitea"]; !ok || reason != "identity-mismatch" {
		t.Fatalf("Quarantined() = %v, want hsm-sitea latched identity-mismatch: the latch moved and the enumeration did not", quarantined)
	}
}

// THE PIN RETRY GAUGE IS ONLY AS GOOD AS ITS LAST SUCCESSFUL READ.
//
// A scrape must not round-trip the token, so the gauge serves the reading cached at
// the last health check or operation — and pairs it with when that read happened,
// because an hour-old "3 retries" is a blind spot, not a healthy card. A failed
// read must age the cached value, never refresh it.
func TestPINRetriesAreCachedWithTheirFreshness(t *testing.T) {
	session := &fakeSession{serial: "serial-1", devaut: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", retries: 3}
	provider, err := New(&fakeDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := provider.PINRetriesReadings()["hsm-sitea"]; ok {
		t.Fatal("a device never probed reported a retry count: the gauge would read a value nothing measured")
	}
	before := time.Now()
	if !provider.Healthy(context.Background(), binding()) {
		t.Fatal("healthy device reported unhealthy")
	}
	after := time.Now()
	reading, ok := provider.PINRetriesReadings()["hsm-sitea"]
	if !ok || reading.Retries != 3 {
		t.Fatalf("PINRetriesReadings = %v, want 3 from the health check's own read", provider.PINRetriesReadings())
	}
	if reading.At.Before(before) || reading.At.After(after) {
		t.Fatalf("reading timestamp %s outside the health check window %s..%s: freshness is not the read's time", reading.At, before, after)
	}

	session.retries = 2
	if !provider.Healthy(context.Background(), binding()) {
		t.Fatal("two retries remaining is still healthy")
	}
	second := provider.PINRetriesReadings()["hsm-sitea"]
	if second.Retries != 2 || second.At.Before(reading.At) {
		t.Fatalf("after re-probe PINRetriesReadings = %v, want 2 at a later time than %s", provider.PINRetriesReadings(), reading.At)
	}

	// A failed read must not touch the cache: the aging value IS the signal.
	session.retriesErr = errors.New("token unreachable")
	if provider.Healthy(context.Background(), binding()) {
		t.Fatal("an unreachable token reported healthy")
	}
	third := provider.PINRetriesReadings()["hsm-sitea"]
	if third.Retries != 2 || !third.At.Equal(second.At) {
		t.Fatalf("a failed read moved the cache to %v: an unreadable token would masquerade as a fresh reading", third)
	}
}
