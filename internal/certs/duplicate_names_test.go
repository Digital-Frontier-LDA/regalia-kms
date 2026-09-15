package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"
)

// TestARepeatedNameIsIssuedOnceAndCaseIsNotADistinction pins the de-duplication arm of the
// subject-name loop in issue.go — `if _, duplicate := seen[lowered]; duplicate { continue }`.
//
// Nothing exercised it. The operand does not refuse anything, so it produces no error to assert
// on; it silently drops a repeat. Its absence is visible only in the ISSUED CERTIFICATE, which
// no existing test inspects for repeats. Measured on THIS fixture — the common name, two
// identical SAN entries, and one differing only in case:
//
//	guard intact   1 DNS name   [api.staging.internal]
//	guard removed  4 DNS names  [api.staging.internal api.staging.internal
//	                             api.staging.internal api.staging.internal]
//
// Four rather than three because the common name is folded in alongside the SAN entries.
//
// The first draft documented that 4 while shipping a fixture with only one repeated SAN,
// which yields 3. The number came from a probe and was then written beside a different
// fixture. A figure in a comment has to be a measurement of the thing next to it.
//
// The case variant is the half worth keeping. Names are lowered before the map lookup, so
// `API.Staging.Internal` and `api.staging.internal` are one name — a certificate presenting both
// would suggest they are distinct, and DNS is not case-sensitive. Dropping the operand loses the
// repeat suppression AND that equivalence at the same time, so the fixture asserts both by
// carrying a differently-cased copy.
//
// This is a well-formedness defect rather than a security one: a certificate with repeated SANs
// still verifies and still authenticates the same host. It bloats every presentation of it, and
// it makes the issued material disagree with what the operator asked for in a way nothing
// reports.
func TestARepeatedNameIsIssuedOnceAndCaseIsNotADistinction(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newCA(t, caKey, time.Now().Add(365*24*time.Hour))
	signer := &CardSigner{PublicKey: caKey.Public(), Sign_: emulateCard(t, caKey)}
	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// THE CONTROL, in the same run: two DISTINCT names must both survive. Without it the
	// assertion below is equally satisfied by a loop that drops everything after the first
	// name, which would be a far worse defect and would look identical.
	distinct := newCSR(t, "api.staging.internal", []string{"web.staging.internal"}, subjectKey)
	der, err := Issue(ca, signer, distinct, staging(), time.Now())
	if err != nil {
		t.Fatalf("control: a CSR with two distinct names was refused: %v", err)
	}
	control, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(control.DNSNames) != 2 {
		t.Fatalf("control: two distinct names produced %d entries %v — the assertion below would "+
			"pass against a loop that keeps only the first name", len(control.DNSNames), control.DNSNames)
	}

	// THE GATE. The same name four times: the common name, two identical SAN entries, and one
	// differing only in case. The identical pair and the case variant are separate cases — a
	// map keyed on the raw string would collapse the pair and keep the variant.
	repeated := newCSR(t, "api.staging.internal",
		[]string{"api.staging.internal", "api.staging.internal", "API.Staging.Internal"}, subjectKey)
	der, err = Issue(ca, signer, repeated, staging(), time.Now())
	if err != nil {
		t.Fatalf("a CSR repeating one name was refused (%v); repeats are meant to collapse, not "+
			"to make the request unusable", err)
	}
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if len(issued.DNSNames) != 1 {
		t.Fatalf("one name asked for three times was issued %d times %v — the certificate "+
			"disagrees with the request, and a differently-cased copy is the same DNS name",
			len(issued.DNSNames), issued.DNSNames)
	}
	if issued.DNSNames[0] != "api.staging.internal" {
		t.Fatalf("the surviving name is %q, want the lowered form", issued.DNSNames[0])
	}
}
