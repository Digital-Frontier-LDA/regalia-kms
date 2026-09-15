package certs

// Sixteen of the thirty-one refusal guards on this path survived a mutation sweep: replacing them
// with a constant left the certs suite green. This file gives the security-bearing ones a detector.
// Two of the survivors are worse than untested — an existing test names the guard it exercises and
// is satisfied by a DIFFERENT one downstream, so the mutation went red for the wrong reason (§19).
// Those are fixed where they live rather than duplicated here.
//
// Every case asserts the MESSAGE, not just that an error came back: on a path with this many
// sequential refusals, `err != nil` is exactly the assertion that let two of them rot.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// issuanceFixture is the arrangement every case below starts from: a valid CA, a card signer over
// it, and a subject key. Cases break exactly one thing so the guard under test is the only refuser.
func issuanceFixture(t *testing.T) (*x509.Certificate, *CardSigner, crypto.Signer) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ca, &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}, subjectKey
}

func requireRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("issued a certificate; wanted a refusal naming %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused by the wrong rule: got %q, want a message containing %q", err, want)
	}
}

// AN ISSUER THAT MAY NOT SIGN CERTIFICATES MUST NOT SIGN ONE. crypto/x509 does not check the
// parent's basic constraints or key usage, so nothing below this guard would object: removing it
// produces a real, parseable certificate signed by a leaf. The two rows are the two halves of the
// condition, because a CA bit without keyCertSign and keyCertSign without the CA bit are different
// deployment mistakes and only one of them is caught by looking at the other.
func TestAnIssuerThatMayNotSignCertificatesIssuesNothing(t *testing.T) {
	_, _, subjectKey := issuanceFixture(t)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}
	csr := newCSR(t, "api.staging.internal", nil, subjectKey)

	selfSigned := func(t *testing.T, isCA bool, usage x509.KeyUsage) *x509.Certificate {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(2),
			Subject:               pkix.Name{CommonName: "not-an-authority"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:              usage,
			BasicConstraintsValid: true,
			IsCA:                  isCA,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, template, caKey.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}

	t.Run("not a CA", func(t *testing.T) {
		leaf := selfSigned(t, false, x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature)
		_, err := Issue(leaf, signer, csr, staging(), time.Now())
		requireRefusal(t, err, "may not sign certificates")
	})
	t.Run("a CA without keyCertSign", func(t *testing.T) {
		authority := selfSigned(t, true, x509.KeyUsageDigitalSignature)
		_, err := Issue(authority, signer, csr, staging(), time.Now())
		requireRefusal(t, err, "may not sign certificates")
	})
	// The known-good row: the same call with a proper authority succeeds, so the two refusals
	// above are about the authority and not about the fixture.
	t.Run("a proper authority (known good)", func(t *testing.T) {
		ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
		if _, err := Issue(ca, signer, csr, staging(), time.Now()); err != nil {
			t.Fatalf("a proper authority was refused: %v", err)
		}
	})
}

// An unconfigured issuer must be refused rather than dereferenced. Removing this guard does not
// return a wrong answer — it PANICS on the next line, which on a request path is a denial of
// service reachable by a deployment mistake rather than by an attacker.
func TestAnUnconfiguredIssuerIsRefusedRatherThanDereferenced(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	csr := newCSR(t, "api.staging.internal", nil, subjectKey)
	t.Run("no certificate", func(t *testing.T) {
		_, err := Issue(nil, signer, csr, staging(), time.Now())
		requireRefusal(t, err, "issuer is not configured")
	})
	t.Run("no signer", func(t *testing.T) {
		_, err := Issue(ca, nil, csr, staging(), time.Now())
		requireRefusal(t, err, "issuer is not configured")
	})
}

// A REQUEST THAT NAMES NOTHING. Removing this guard does not issue an unnamed certificate: names[0]
// panics while building the template. The refusal is the only thing between an empty CSR and a
// crash on the issuing path.
func TestACertificateRequestThatNamesNothingIsRefused(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	nameless, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, subjectKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Issue(ca, signer, nameless, staging(), time.Now())
	requireRefusal(t, err, "names nothing")
}

func TestARequestNamingTooManyHostsIsRefused(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	many := make([]string, 0, maxSANsPerCert+1)
	for i := 0; i <= maxSANsPerCert; i++ {
		many = append(many, fmt.Sprintf("host-%d.staging.internal", i))
	}
	// Every name is inside the namespace and none is malformed, so the count rule is the only
	// thing that can refuse this.
	_, err := Issue(ca, signer, newCSR(t, "", many, subjectKey), staging(), time.Now())
	requireRefusal(t, err, "too many hosts")
}

// IP, EMAIL AND URI SANS ARE REFUSED, NOT DROPPED. The template only ever carries DNSNames, so
// removing this guard does not put an IP SAN in the certificate — it issues one that silently does
// not say what the requester asked for. That is the failure this refusal exists to prevent, and it
// is invisible to any test that only checks for an error.
func TestNameTypesThisProfileDoesNotIssueAreRefused(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	uri, err := url.Parse("spiffe://regalia/api")
	if err != nil {
		t.Fatal(err)
	}
	requests := []struct {
		name     string
		template x509.CertificateRequest
	}{
		{"an IP SAN", x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "api.staging.internal"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.4")}}},
		{"an email SAN", x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "api.staging.internal"}, EmailAddresses: []string{"ops@example.test"}}},
		{"a URI SAN", x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "api.staging.internal"}, URIs: []*url.URL{uri}}},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			der, err := x509.CreateCertificateRequest(rand.Reader, &request.template, subjectKey)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Issue(ca, signer, der, staging(), time.Now())
			requireRefusal(t, err, "a name type this profile does not issue")
		})
	}
}

// The size bound is checked BEFORE parsing, which is the whole point: it is the only thing that
// stops an oversized input from being handed to the ASN.1 parser.
func TestAnOversizedRequestIsRefusedBeforeParsing(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	valid := newCSR(t, "api.staging.internal", nil, subjectKey)
	// Trailing bytes make it oversized without making it a different KIND of malformed: the
	// prefix is still a well-formed request, so a refusal cannot be blamed on the parser.
	oversized := append(append([]byte{}, valid...), make([]byte, maxCSRBytes)...)
	_, err := Issue(ca, signer, oversized, staging(), time.Now())
	requireRefusal(t, err, "empty or oversized")

	_, err = Issue(ca, signer, nil, staging(), time.Now())
	requireRefusal(t, err, "empty or oversized")
}

// THE CARD SIGNER'S INPUT CONTRACT. The RSA branch prepends a SHA-256 DigestInfo prefix to whatever
// it is handed, so a digest that is not a SHA-256 digest produces a structurally valid signature
// over a lie. None of these three refusals had a test.
func TestTheCardSignerRefusesAnythingButASHA256Digest(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("to be signed"))
	signer := &CardSigner{PublicKey: key.Public(), Sign_: emulateCard(t, key)}

	// Known-good first: this exact signer signs this exact digest, so every refusal below is
	// about the thing the row changes.
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("known good: a SHA-256 digest was refused: %v", err)
	}

	t.Run("a different hash", func(t *testing.T) {
		// Length is deliberately still 32, so the length rule below cannot be what refuses it.
		_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512_256)
		requireRefusal(t, err, "only SHA-256 certificate signatures are supported")
	})
	t.Run("a digest of the wrong length", func(t *testing.T) {
		_, err := signer.Sign(rand.Reader, digest[:31], crypto.SHA256)
		requireRefusal(t, err, "not a SHA-256 digest")
	})
	t.Run("no card function", func(t *testing.T) {
		unwired := &CardSigner{PublicKey: key.Public()}
		_, err := unwired.Sign(rand.Reader, digest[:], crypto.SHA256)
		requireRefusal(t, err, "card signer is not configured")
	})
	t.Run("an empty digest", func(t *testing.T) {
		_, err := signer.Sign(rand.Reader, nil, crypto.SHA256)
		requireRefusal(t, err, "card signer is not configured")
	})
}

// An unparseable request must be refused, not dereferenced. TestTamperedRequestIsRefused corrupts
// the signature of a request that still PARSES, so the parse failure itself had no test — and
// removing its guard panics on the nil request two lines later.
func TestAnUnparseableRequestIsRefused(t *testing.T) {
	ca, signer, _ := issuanceFixture(t)
	_, err := Issue(ca, signer, []byte("this is not ASN.1 at all"), staging(), time.Now())
	requireRefusal(t, err, "certificate request is malformed")
}

// A CARD THAT FAILS MUST SURFACE ITS FAILURE. Both branches propagate the card's error, and
// neither had a test: an issuer that swallowed a card error would fall through to the length
// check and report the wrong cause for an unplugged or locked token.
func TestACardFailureIsPropagatedByBothBranches(t *testing.T) {
	digest := sha256.Sum256([]byte("to be signed"))
	refuse := func([]byte) ([]byte, error) { return nil, fmt.Errorf("token is not present") }

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&CardSigner{PublicKey: ecKey.Public(), Sign_: refuse}).Sign(rand.Reader, digest[:], crypto.SHA256)
	requireRefusal(t, err, "token is not present")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&CardSigner{PublicKey: rsaKey.Public(), Sign_: refuse}).Sign(rand.Reader, digest[:], crypto.SHA256)
	requireRefusal(t, err, "token is not present")
}
