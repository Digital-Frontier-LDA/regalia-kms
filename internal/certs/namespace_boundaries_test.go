package certs

// THE THREE NAMESPACE OPERANDS NO TEST REACHED (#237 sweep of this package:
// 43 sites / 61 operands / 122 operand-directions, 15 surviving directions).
//
// All three live in the name path, and all three survived for the same reason: the suite
// only ever asks for names that are ordinary — a host inside the namespace, or a host
// plainly outside it. The operands below decide what happens at the EDGES of that
// namespace, and no fixture stood on an edge.
//
// Each test states what the package returns with its operand neutralised, because that is
// the fact a later reader deciding the test is redundant needs in front of them.

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

// TestAnEmptySuffixEntryIsNotAWildcard pins issue.go's `suffix == ""` in withinSuffixes.
//
// MEASURED WITH THE OPERAND NEUTRALISED: a profile carrying an empty suffix entry issues a
// certificate for evil.example.com. — a name in nobody's namespace. The empty entry stops
// being skipped and reaches `strings.HasSuffix(name, "."+suffix)`, which with suffix ""
// is `strings.HasSuffix(name, ".")`, so it admits EVERY name ending in a dot. A trailing
// dot is the ordinary absolute form of a DNS name, not an exotic input.
//
// An empty entry is reachable configuration: NewIssuer and Issue both check only that the
// suffix LIST is non-empty, so `AllowedDNSSuffixes: []string{""}` — a stray comma in YAML,
// an unset template variable — constructs and validates. The `continue` is what makes such
// an entry inert rather than a wildcard, and nothing tested it.
func TestAnEmptySuffixEntryIsNotAWildcard(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)
	profile := Profile{
		// The empty entry sits BEFORE the real one so that reaching the real suffix is not
		// what makes the refusal happen: the loop would have to skip the empty entry first.
		AllowedDNSSuffixes: []string{"", "staging.internal"},
		Validity:           90 * 24 * time.Hour,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// THE GATE, before the control: a control that fatals first would foreclose this
	// assertion in exactly the run where it matters (TESTING.md §18).
	der, err := Issue(ca, signer, newCSR(t, "evil.example.com.", nil, subjectKey), profile, time.Now())
	if err == nil {
		t.Fatalf("issued a %d-byte certificate for evil.example.com., which is inside no configured "+
			"suffix — an empty entry in AllowedDNSSuffixes matched it through HasSuffix(name, \".\"), "+
			"so one stray list element turns this issuer into a wildcard for every absolute name", len(der))
	}
	requireRefusal(t, err, "outside this issuer's namespace")

	// THE CONTROL, through the same call and the same profile. Without it the refusal above
	// is equally consistent with a profile that permits nothing at all, and the empty entry
	// would be untested either way.
	if _, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, subjectKey), profile, time.Now()); err != nil {
		t.Fatalf("control: a name inside the configured suffix was refused (%v) — the profile "+
			"permits nothing, so the refusal above is not evidence about the empty entry", err)
	}
}

// TestTheApexOfTheDelegatedNamespaceIsIssuable pins issue.go's `name == suffix`.
//
// MEASURED WITH THE OPERAND NEUTRALISED: a CSR for staging.internal — the delegated zone
// itself — is refused as "outside this issuer's namespace", because the surviving arm
// asks for `strings.HasSuffix("staging.internal", ".staging.internal")`, which is false.
// The suffix names a namespace and the namespace contains its own apex; an issuer that
// refuses it is narrower than the profile says, and the failure arrives at whoever is
// trying to obtain a certificate for the zone apex rather than here.
//
// This is the admitting direction, so it needs an ISSUANCE to detect it. `err != nil`
// would not have shown it: the refusal is real, it is simply the wrong answer.
func TestTheApexOfTheDelegatedNamespaceIsIssuable(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)

	der, err := Issue(ca, signer, newCSR(t, "staging.internal", nil, subjectKey), staging(), time.Now())
	if err != nil {
		t.Fatalf("the apex of the delegated namespace was refused: %v — AllowedDNSSuffixes names a "+
			"namespace, and only the exact-match arm places the apex inside its own namespace", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	// The name must actually be carried, not merely not-refused.
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "staging.internal" {
		t.Fatalf("issued certificate names %v, want exactly [staging.internal]", leaf.DNSNames)
	}

	// THE CONTROL: a name that is genuinely outside is still refused, so the acceptance above
	// is not a namespace check that has stopped checking.
	if _, err := Issue(ca, signer, newCSR(t, "staging.internal.example.com", nil, subjectKey), staging(), time.Now()); err == nil {
		t.Fatal("control: staging.internal.example.com was issued — the namespace check admits " +
			"everything, so the apex being accepted above says nothing about the exact-match arm")
	}
}

// TestAWhitespaceOnlyNameIsRefusedAsUnusableRatherThanAsOutOfNamespace pins issue.go's
// `lowered == ""`.
//
// MEASURED WITH THE OPERAND NEUTRALISED: the request is still refused — by
// withinSuffixes, as `name "" is outside this issuer's namespace`. So `err != nil` cannot
// see this operand at all, and neither can any test that only asks whether a refusal
// happened. What changes is the DIAGNOSIS an operator receives: a CSR whose SAN is a
// stretch of whitespace is a malformed request, and reporting it as a namespace violation
// sends whoever reads it to the issuer's configuration instead of to their own CSR.
//
// The sibling operand does not mask it: `strings.ContainsAny("", " \t*")` is false, so on
// this input the empty-name arm is the only one that can fire.
func TestAWhitespaceOnlyNameIsRefusedAsUnusableRatherThanAsOutOfNamespace(t *testing.T) {
	ca, signer, subjectKey := issuanceFixture(t)

	// A SAN of spaces and a tab. TrimSpace reduces it to "", which is the operand's input.
	_, err := Issue(ca, signer, newCSR(t, "", []string{"  \t "}, subjectKey), staging(), time.Now())
	if err == nil {
		t.Fatal("a certificate request whose only name is whitespace was issued")
	}
	requireRefusal(t, err, "unusable name")
	// Named explicitly, because this is the message the mutant produces and the whole
	// distinction this test exists to keep.
	if strings.Contains(err.Error(), "outside this issuer's namespace") {
		t.Fatalf("a whitespace-only name was refused as a namespace violation (%v) — that points an "+
			"operator at the issuer's AllowedDNSSuffixes for a request that is simply malformed", err)
	}

	// THE CONTROL: an ordinary name through the same call still issues.
	if _, err := Issue(ca, signer, newCSR(t, "api.staging.internal", nil, subjectKey), staging(), time.Now()); err != nil {
		t.Fatalf("control: a well-formed request was refused: %v", err)
	}
}
