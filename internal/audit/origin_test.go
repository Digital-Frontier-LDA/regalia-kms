package audit

import (
	"net/url"
	"testing"
)

// The other half of the pair. See TestKMSURLAcceptsExactlyTheOriginForms in
// adapters/sops/cmd/regalia-sops-kms: the same rule is implemented twice across a module boundary
// that forbids sharing, so the same table is asserted on both sides. A divergence now fails a test
// instead of surfacing as a config that works for one component and not the other.
func TestSinkURLRuleMatchesTheAdapter(t *testing.T) {
	for _, value := range []string{
		"https://audit.internal:8443",
		"https://audit.internal:8443/",
		"https://audit.internal",
	} {
		if err := ValidateSinkURL(value); err != nil {
			t.Errorf("%q was rejected and the SOPS adapter accepts it: the two definitions of an origin disagree again (%v)", value, err)
		}
	}
	for _, value := range []string{
		"http://audit.internal",
		"https://audit.internal/v1/events",
		"https://user:pw@audit.internal",
		"https://audit.internal?a=b",
		"https://audit.internal#f",
		"",
		// #237 operand sweep: the host operand had no row on either side of the pair. It parses
		// cleanly — scheme https, empty host, empty path — so every other operand in the rule
		// accepts it, and the sink would then POST the audit trail to "https:///v1/events",
		// which has no host to reach. Shipping fails forever on a configuration that was
		// accepted at startup.
		"https://",
	} {
		if err := ValidateSinkURL(value); err == nil {
			t.Errorf("%q was accepted as an HTTPS origin", value)
		}
	}
}

// A COLLECTOR ADDRESS THAT DOES NOT PARSE MUST BE REFUSED, NOT DEREFERENCED.
//
// #237 operand sweep: the parse-error operand survived. It is not redundant with the field checks
// that follow it — it is what STOPS them running. url.Parse returns a nil *url.URL alongside its
// error, and the very next operand reads parsed.Scheme, so with the error check gone a mistyped
// collector address does not produce a refusal at all: it panics, and the daemon dies at startup
// on a configuration it was supposed to reject with a sentence.
func TestASinkURLThatDoesNotParseIsRefusedRatherThanDereferenced(t *testing.T) {
	for _, value := range []string{
		"://audit.internal",          // no scheme
		"https://audit.internal\x7f", // a control character in the host
		"https://%zz",                // an invalid percent-escape
		"https://audit internal",     // a space in the host
	} {
		// PROVE THE FIXTURE. This row is about url.Parse FAILING; a value that parses would
		// exercise the ordinary field checks and say nothing about the error operand.
		if _, parseErr := url.Parse(value); parseErr == nil {
			t.Errorf("fixture: url.Parse(%q) succeeded, so this row never reaches the parse-error operand", value)
			continue
		}
		err, panicked := validateSinkURLRecovering(value)
		if panicked != nil {
			t.Errorf("ValidateSinkURL(%q) panicked (%v): url.Parse handed back a nil URL with its error and the next operand dereferenced it, so a typo in the collector address crashes the daemon instead of being refused", value, panicked)
			continue
		}
		if err == nil {
			t.Errorf("%q was accepted as an HTTPS origin although it does not parse as a URL at all", value)
		}
	}
	// KNOWN-GOOD, so the rows above are not satisfied by a rule that refuses everything.
	if err := ValidateSinkURL("https://audit.internal"); err != nil {
		t.Errorf("the baseline origin was refused (%v), so every row above proves nothing", err)
	}
}

// validateSinkURLRecovering reports the refusal AND whether producing it required surviving a
// panic, so the failure above is a named assertion rather than a process abort that takes the
// rest of the package's results with it.
func validateSinkURLRecovering(value string) (err error, panicked any) {
	defer func() { panicked = recover() }()
	return ValidateSinkURL(value), nil
}
