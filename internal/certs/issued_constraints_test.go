package certs

// AN ANSWER AND ITS RECORD ARE TWO FACTS, AND THE TEMPLATE WRITES THEM IN ONE STATEMENT.
//
// This file exists because of a counterfactual an OPERAND sweep cannot reach. Issue's
// template ends:
//
//	IsCA:                  false,
//	BasicConstraintsValid: true,
//
// with the comment "Never a CA, whatever the request asked for." Two fields, one statement,
// and no boolean operand anywhere in it — so every mutation in the #237 sweep of this
// package went past it.
//
// They are not one fact. `IsCA: false` is the ANSWER; `BasicConstraintsValid: true` is what
// makes crypto/x509 EMIT the basicConstraints extension that records the answer. Set the
// second to false and the issued certificate carries no basicConstraints extension at all —
// it does not say it is not a CA, it says nothing.
//
// MEASURED, `BasicConstraintsValid: false` against the whole dependent suite: green, 10
// packages, nothing failed. The control — flipping `IsCA` to true, the answer itself —
// was killed by three tests at once. So the answer was pinned and its record was not, and
// the two existing assertions cannot tell them apart for a structural reason:
//
//	if leaf.IsCA {                       // certs_test.go
//	if leaf.IsCA || leaf.MaxPathLen > 0 { // refusals_test.go, "claims CA authority"
//
// x509.ParseCertificate sets IsCA only FROM that extension, so with the extension absent it
// parses back as false and both assertions pass — reading the absence of a claim as a claim
// of absence. Chain verification does not close the gap either: RFC 5280 requires
// basicConstraints on a CA certificate, not on a leaf, so Go's verifier accepts the leaf and
// TestIssuedCertificateVerifiesAgainstTheIssuerForBothMechanisms stays green.
//
// What it costs is the property the comment claims. A certificate that omits
// basicConstraints is one whose non-CA status rests on every relying party defaulting the
// right way, and the historically expensive verifier bugs are exactly the ones that did not.
// This issuer states it explicitly, and until now nothing checked that it did.

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"
)

// basicConstraintsOID is id-ce-basicConstraints, RFC 5280 §4.2.1.9.
var basicConstraintsOID = asn1.ObjectIdentifier{2, 5, 29, 19}

// TestTheIssuedCertificateRECORDSThatItIsNotACA pins `BasicConstraintsValid: true`.
//
// It asserts the EXTENSION, not the parsed IsCA field, because the parsed field is exactly
// what cannot distinguish the two states.
func TestTheIssuedCertificateRECORDSThatItIsNotACA(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	der, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, subjectKey), staging(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	// THE GATE. BasicConstraintsValid is the parser reporting that the extension was PRESENT,
	// which is the one thing IsCA cannot tell you.
	if !leaf.BasicConstraintsValid {
		t.Fatal("the issued certificate carries no basicConstraints extension — it does not state " +
			"that it is not a CA, it states nothing, and `leaf.IsCA` reads false either way. Its " +
			"non-CA status now depends on every relying party defaulting the right way")
	}
	// And the extension by OID, because BasicConstraintsValid is a derived field and this is
	// the byte that is actually published.
	var present, critical bool
	for _, extension := range leaf.Extensions {
		if extension.Id.Equal(basicConstraintsOID) {
			present, critical = true, extension.Critical
		}
	}
	if !present {
		t.Fatalf("no extension with OID %v in the issued certificate", basicConstraintsOID)
	}
	if !critical {
		t.Fatal("basicConstraints is present but not marked critical — a verifier is permitted to " +
			"ignore a non-critical extension it does not understand")
	}
	// THE ANSWER the record carries. Asserted here too so this test fails for the right reason
	// if the pair is ever changed the other way.
	if leaf.IsCA {
		t.Fatal("the issued certificate asserts CA authority")
	}
}

// TestTheBackdatingAllowanceIsMinutesNotMonths pins `NotBefore: now.Add(-time.Minute)`.
//
// The certificate is deliberately valid from slightly before it was issued, so a relying
// party whose clock runs behind does not reject a fresh certificate. That is a clock-skew
// allowance, and its SIZE is the whole property: it is also the window in which a
// certificate is valid before anyone decided to issue it.
//
// MEASURED with the minute widened to a year: green across the dependent suite. Nothing
// asserts NotBefore at all — certs_test.go bounds NotAfter and stops there — so the
// allowance could be any length and no test would notice.
func TestTheBackdatingAllowanceIsMinutesNotMonths(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	// A fixed instant, so the bound below is exact rather than a race against the clock.
	now := time.Now()

	der, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, subjectKey), staging(), now)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	// Generous enough to survive the second-granularity of an X.509 UTCTime, tight enough that
	// an allowance measured in hours or days fails.
	const widest = 5 * time.Minute
	if leaf.NotBefore.Before(now.Add(-widest)) {
		t.Fatalf("the certificate is valid from %s, %s before it was issued — a skew allowance is "+
			"also the window in which the certificate is already valid and nobody has yet decided "+
			"to issue it", leaf.NotBefore.UTC(), now.Sub(leaf.NotBefore).Round(time.Second))
	}
	// The other side of the bound: an allowance of zero is a different defect — certificates
	// that a relying party whose clock is a second behind rejects outright.
	if !leaf.NotBefore.Before(now) {
		t.Fatalf("the certificate is valid from %s, which is not before the issuing instant %s — "+
			"there is no skew allowance at all, and a verifier whose clock runs a second behind "+
			"rejects every certificate this issuer produces", leaf.NotBefore.UTC(), now.UTC())
	}
}
