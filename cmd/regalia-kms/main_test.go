package main

import "testing"

// The listener rule has two axes now: is the address routable, and does the transport
// authenticate the caller. Loopback is permitted either way (development); a routable address is
// permitted ONLY with mutual TLS, because auth reads the verified chain from request.TLS and a
// plaintext routable listener would expose the unauthenticated health routes to the network while
// failing every real operation closed.
func TestRequireLoopbackUnlessMutualTLS(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		mutualTLS bool
		valid     bool
	}{
		// Loopback: allowed with or without TLS.
		{"IPv4 loopback, no TLS", "127.0.0.1:8443", false, true},
		{"IPv4 loopback, mTLS", "127.0.0.1:8443", true, true},
		{"IPv6 loopback, no TLS", "[::1]:8443", false, true},
		{"localhost, no TLS", "localhost:8443", false, true},
		{"localhost, mTLS", "localhost:8443", true, true},

		// Routable without mutual TLS: refused, as before.
		{"all IPv4, no TLS", "0.0.0.0:8443", false, false},
		{"all IPv6, no TLS", "[::]:8443", false, false},
		{"public, no TLS", "192.0.2.1:8443", false, false},

		// Routable WITH mutual TLS: now permitted. This is the behaviour change.
		{"all IPv4, mTLS", "0.0.0.0:8443", true, true},
		{"all IPv6, mTLS", "[::]:8443", true, true},
		{"public, mTLS", "192.0.2.1:8443", true, true},

		// An empty host means ALL interfaces, so it is the routable case spelled differently:
		// refused without mutual TLS, permitted with it, exactly like 0.0.0.0.
		{"empty host, no TLS", ":8443", false, false},
		{"empty host, mTLS", ":8443", true, true},

		// Unparseable addresses stay refused no matter what the transport does.
		{"missing port, no TLS", "127.0.0.1", false, false},
		{"missing port, mTLS", "127.0.0.1", true, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := requireLoopbackUnlessMutualTLS(test.address, test.mutualTLS)
			if test.valid && err != nil {
				t.Fatalf("requireLoopbackUnlessMutualTLS(%q, %v) = %v, want nil", test.address, test.mutualTLS, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("requireLoopbackUnlessMutualTLS(%q, %v) = nil, want error", test.address, test.mutualTLS)
			}
		})
	}
}
