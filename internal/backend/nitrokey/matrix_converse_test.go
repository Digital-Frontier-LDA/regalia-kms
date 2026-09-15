package nitrokey

import (
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE MATRIX PROMISE HAS TWO DIRECTIONS AND ONLY ONE WAS CHECKED.
//
// TestEveryAdvertisedNitrokeyCapabilityIsAcceptedByTheDriver walks advertised ⊆ accepted: nothing
// the registry promises may be refused at the token. This is the converse — nothing the registry
// does NOT promise may be quietly accepted.
//
// All three operations with a driver-level algorithm gate are covered: sign, wrap/unwrap and
// key-agreement. Those are the only ones a converse can be written for, because a converse asks
// "does the driver accept an algorithm the matrix withheld?" and needs a gate to ask it of.
//
// The other three are NOT simply skipped by the forward test, and saying so here was wrong:
//
//   certificate-sign  — certs.Issuer signs the certificate itself and never reaches the driver, so
//                       there is genuinely no gate.
//   release-secret    — the forward test checks something real and different: that SOME algorithm
//   seal-envelope       the backend advertises for unwrap (respectively wrap) is one this driver
//                       accepts, or the capability is one no binding could ever satisfy. An opaque
//                       secret has no algorithm of its own, so the binding names the KEK and the
//                       matrix cannot see it — there is nothing for a converse to withhold.
//
// That is the direction the aes-256/unwrap defect lived in. The matrix advertised it, the driver
// refused it, and the first test catches that pairing. But a driver that starts accepting an
// algorithm the matrix has never advertised produces the same disagreement facing the other way:
// commissioning refuses a binding the daemon would happily serve, and someone eventually "fixes"
// the matrix to match the driver rather than asking which was right.
//
// It is also the direction #75 warns about explicitly. Implementing a symmetric branch in the
// driver would make the forward test pass for aes-256 whether or not the token implements the
// mechanism — because advertised ⊆ accepted is satisfied by widening the driver. Only this
// direction notices that the driver moved first.

// everyAlgorithm is the union of what any backend advertises, plus values that have appeared in
// this repository's history and must not be quietly acquired.
func everyAlgorithm(t *testing.T) []string {
	t.Helper()
	seen := map[string]struct{}{
		// The one that was advertised and refused. If a symmetric branch ever lands, this test is
		// where the matrix and the driver are made to agree deliberately rather than by drift.
		"aes-256": {},
		"opaque":  {}, "ed25519": {}, "rsa1024": {}, "x25519": {}, "p521": {}, "": {},
	}
	for _, algorithms := range registry.Capabilities() {
		for algorithm := range algorithms {
			seen[algorithm] = struct{}{}
		}
	}
	list := make([]string, 0, len(seen))
	for algorithm := range seen {
		list = append(list, algorithm)
	}
	if len(list) < 8 {
		t.Fatalf("only %d algorithms to check: the capability matrix is not being read", len(list))
	}
	return list
}

func TestTheDriverRefusesEveryAlgorithmTheMatrixDoesNotAdvertise(t *testing.T) {
	advertised := registry.Capabilities()["nitrokey-pkcs11"]
	if len(advertised) == 0 {
		t.Fatal("no nitrokey capabilities were read: this test would pass while checking nothing")
	}

	refused, accepted := 0, 0
	for _, algorithm := range everyAlgorithm(t) {
		operations := advertised[algorithm]

		t.Run(algorithm+"/wrap", func(t *testing.T) {
			promised := operations["wrap"] || operations["unwrap"]
			if got := wrappingAlgorithm(algorithm); got != promised {
				if got {
					t.Fatalf("the driver wraps with %q and the matrix does not advertise it: a binding the registry refuses would be served, and the next person reconciles them by widening the matrix", algorithm)
				}
				t.Fatalf("the matrix advertises %q for wrap/unwrap and the driver refuses it", algorithm)
			}
			if promised {
				accepted++
			} else {
				refused++
			}
		})

		t.Run(algorithm+"/sign", func(t *testing.T) {
			promised := operations["sign"]
			_, err := signingMechanism(algorithm)
			if (err == nil) != promised {
				if err == nil {
					t.Fatalf("the driver signs with %q and the matrix does not advertise it", algorithm)
				}
				t.Fatalf("the matrix advertises %q for sign and the driver refuses it: %v", algorithm, err)
			}
		})

		t.Run(algorithm+"/key-agreement", func(t *testing.T) {
			promised := operations["key-agreement"]
			if got := agreementAlgorithm(algorithm); got != promised {
				if got {
					t.Fatalf("the driver derives with %q and the matrix does not advertise it", algorithm)
				}
				t.Fatalf("the matrix advertises %q for key-agreement and the driver refuses it", algorithm)
			}
		})
	}

	// A FLOOR ON REACH, both ways. All-refused would satisfy the loop as readily as the real thing,
	// and so would all-accepted; the matrix genuinely contains some of each and the test must see
	// both. TESTING.md §16.
	if accepted == 0 {
		t.Fatal("no algorithm was accepted for wrapping: the driver refuses everything, and every case above passed by agreeing with a matrix that promises nothing")
	}
	if refused == 0 {
		t.Fatal("no algorithm was refused for wrapping: the driver accepts everything offered, so the converse this test exists for was never exercised")
	}
}
