package nitrokey

import (
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE CAPABILITY MATRIX IS A PROMISE THE DRIVER HAS TO KEEP.
//
// A custody manifest binding an object to (backend, algorithm, operation) is validated against
// registry.Capabilities(), so anything listed there is something an operator may commission and
// expect to work. An entry the driver refuses is worse than a missing one: the manifest validates,
// the registry routes, and the failure arrives at the token when somebody needs the key.
//
// nitrokey-pkcs11 advertised aes-256/unwrap while the driver gates unwrap to rsa2048/3072/4096.
// No driver branch implemented it and no shipped manifest used it; its one other appearance was a
// Python test fixture, which meant CI exercised a binding no daemon would accept.
//
// certificate-sign and release-secret are not checked here: they are served by the certs.Issuer and
// secrets.Releaser decorators in front of this provider, not by the PKCS#11 driver.
func TestEveryAdvertisedNitrokeyCapabilityIsAcceptedByTheDriver(t *testing.T) {
	advertised := registry.Capabilities()["nitrokey-pkcs11"]
	if len(advertised) == 0 {
		t.Fatal("no nitrokey capabilities were read: this test would pass while checking nothing")
	}

	checked := 0
	for algorithm, operations := range advertised {
		for operation, allowed := range operations {
			if !allowed {
				continue
			}
			switch operation {
			case "sign":
				if _, err := signingMechanism(algorithm); err != nil {
					t.Errorf("nitrokey-pkcs11 advertises %s/sign but the driver refuses the algorithm: %v", algorithm, err)
				}
				checked++
			case "key-agreement":
				if !agreementAlgorithm(algorithm) {
					t.Errorf("nitrokey-pkcs11 advertises %s/key-agreement but the driver refuses the algorithm", algorithm)
				}
				checked++
			case "wrap", "unwrap":
				// Both sides of the envelope are RSA-OAEP; the driver refuses anything else.
				if !wrappingAlgorithm(algorithm) {
					t.Errorf("nitrokey-pkcs11 advertises %s/%s but the driver only wraps with RSA: an object commissioned this way would fail at the token", algorithm, operation)
				}
				checked++
			case "certificate-sign":
				// certs.Issuer builds and signs the certificate itself and never reaches the
				// driver's unwrap, so there is no driver-level algorithm to check.
			case "release-secret":
				// NOT merely served in front of this provider. secrets.Releaser decorates the call
				// and then DELEGATES its data-key unwrap to this driver, so an algorithm does arrive
				// here -- just not this one. An opaque secret has no algorithm of its own, so the
				// binding names the KEK and the matrix cannot see it.
				//
				// What the matrix can still promise is that a KEK could exist here at all:
				// advertising release-secret on a backend where nothing it advertises for unwrap is
				// a driver-accepted algorithm would be a capability no binding could ever satisfy.
				//
				// The comment this replaces asserted the operation never reached the driver. That
				// was a guess about the call graph, and it excluded the one broken capability from
				// the check written to catch exactly this: "opaque" was routed to the card, which
				// refuses everything but RSA, so every release failed as a retryable error. See #6.
				usable := false
				for candidate, candidateOperations := range advertised {
					if candidateOperations["unwrap"] && wrappingAlgorithm(candidate) {
						usable = true
					}
				}
				if !usable {
					t.Errorf("nitrokey-pkcs11 advertises %s/release-secret, but no algorithm it advertises for unwrap is one this driver accepts: no binding could name a KEK that works", algorithm)
				}
				checked++
			case "seal-envelope":
				// The mirror of release-secret, one direction over: the sealer delegates a WRAP to
				// this driver under the binding's kek_algorithm, and "opaque" itself never reaches
				// the card. The matrix-checkable promise is that a KEK could exist here at all —
				// a backend advertising seal-envelope with no driver-accepted wrap algorithm is a
				// capability no binding could satisfy.
				usable := false
				for candidate, candidateOperations := range advertised {
					if candidateOperations["wrap"] && wrappingAlgorithm(candidate) {
						usable = true
					}
				}
				if !usable {
					t.Errorf("nitrokey-pkcs11 advertises %s/seal-envelope, but no algorithm it advertises for wrap is one this driver accepts: no binding could name a KEK that works", algorithm)
				}
				checked++
			default:
				t.Errorf("nitrokey-pkcs11 advertises %s/%s and this test does not know how to check it: add a case rather than leaving the promise unverified", algorithm, operation)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no capability was actually checked against the driver")
	}
}
