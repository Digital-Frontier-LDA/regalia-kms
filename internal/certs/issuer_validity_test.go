package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// AN EXPIRED ISSUING CA MUST NOT SIGN, AND THAT BRANCH HAD NO TEST.
//
// Issue refuses to sign when `now` falls outside the CA's [NotBefore, NotAfter] window. Every
// fixture in this package builds a CA valid for a year from now, so no test ever drove `now` outside
// it: the check existed and nothing exercised it, and deleting those two lines left the suite green.
//
// This is not hypothetical. An issuing CA expires on a schedule, and the failure it produces is a
// leaf that verifies against nothing -- issued cheerfully, rejected by every peer, and traceable
// only to an expiry nobody was watching. Refusing at signing time turns that into an error the
// operator sees while they can still act on it.
func TestIssueRefusesACAThatIsNotValidRightNow(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr := newCSR(t, "api.staging.internal", []string{"api.staging.internal"}, subjectKey)
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}

	// Control: the same CA, CSR and profile at a time the CA IS valid must sign. Without it these
	// cases could fail for any reason -- a malformed CSR, a refused name, a bad profile -- and pass
	// while proving nothing about the validity window.
	if _, err := Issue(newCA(t, caKey, time.Now().Add(365*24*time.Hour)), signer, csr, staging(), time.Now()); err != nil {
		t.Fatalf("the control did not sign (%v), so the cases below would prove nothing", err)
	}

	// newCA sets NotBefore an hour in the past and NotAfter to what it is given.
	for _, testCase := range []struct {
		name     string
		notAfter time.Duration
		now      time.Duration
	}{
		{"the CA expired an hour ago", -time.Hour, 0},
		{"the CA expires while the daemon is running", time.Hour, 2 * time.Hour},
		{"signing before the CA is valid", 365 * 24 * time.Hour, -2 * time.Hour},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ca := newCA(t, caKey, time.Now().Add(testCase.notAfter))
			der, err := Issue(ca, signer, csr, staging(), time.Now().Add(testCase.now))
			if err == nil || len(der) != 0 {
				t.Fatalf("a CA outside [%s, %s] signed a certificate: the leaf would verify against nothing, and nothing would say so until a peer rejected it",
					ca.NotBefore, ca.NotAfter)
			}
			if !strings.Contains(err.Error(), "issuer certificate is not valid at this time") {
				t.Fatalf("error = %v, want it to name the CA's validity window", err)
			}
		})
	}
}
