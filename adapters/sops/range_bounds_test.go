package sopsadapter

// #237 class sweep: `NewMTLSHTTPClient`'s timeout window is `timeout < 1s || timeout > 1m`,
// and only the LOWER side was pinned. transport_test.go passes 0, which trips the floor;
// nothing passed a value above the ceiling, so `timeout > time.Minute` could be deleted and
// the module stayed green.
//
// The ceiling is the side that matters for this particular client. A too-small timeout fails
// loudly on the first request. A too-large one is a KMS call that hangs a SOPS invocation for
// as long as the caller is willing to wait, which is what the bound exists to prevent — the
// constructor's own comment calls it "a direct, bounded client".

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

func TestTheClientTimeoutWindowIsRefusedAtBothEnds(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// The same certificate shape the package's own passing test uses, so the TLS-config guard
	// cannot be what refuses these rows.
	certificate := tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: key}

	for _, row := range []struct {
		name    string
		timeout time.Duration
	}{
		{"below the floor", time.Second - time.Nanosecond},
		{"zero", 0},
		{"negative", -time.Minute},
		{"above the ceiling", time.Minute + time.Nanosecond},
		{"far above the ceiling", time.Hour},
	} {
		t.Run(row.name, func(t *testing.T) {
			client, err := NewMTLSHTTPClient(certificate, x509.NewCertPool(), "kms.internal.example", row.timeout)
			if err == nil {
				t.Fatalf("a %v client timeout was accepted (client=%v) — the constructor promises a BOUNDED client, and an hour-long timeout hangs a SOPS invocation for as long as the caller will wait", row.timeout, client != nil)
			}
		})
	}

	// KNOWN-GOOD IN THE SAME TEST (§18), including both edges: the rows above sit one
	// nanosecond outside, so an off-by-one in either direction would pass without these.
	for _, good := range []time.Duration{time.Second, 15 * time.Second, time.Minute} {
		client, err := NewMTLSHTTPClient(certificate, x509.NewCertPool(), "kms.internal.example", good)
		if err != nil {
			t.Fatalf("a %v timeout was refused (%v) — it is inside the documented window", good, err)
		}
		if client.Timeout != good {
			t.Fatalf("the accepted timeout %v was not applied to the client (got %v) — the bound would be enforced on a value the client never uses", good, client.Timeout)
		}
	}
}
