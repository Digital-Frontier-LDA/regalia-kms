package auth

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"
	"time"
)

// Guards pinned here were invisible to the sweep that produced the recorded survivor count for this
// package, for two reasons worth stating because they are properties of the METHOD, not of the code.
//
// FIRST, guards were enumerated with a pattern requiring the `if` to end on its own line. The whole
// of canonicalURISAN is therefore unenumerated — a twelve-operand refusal guard spread over four
// lines, and a three-operand boolean `return`. That is the SPIFFE identity canonicalisation, so the
// enumerator skipped the most security-relevant function in the file and reported the rest covered.
// A multi-line guard is multi-line BECAUSE it is complicated, so the blind spot selects for exactly
// the sites most worth sweeping.
//
// SECOND, an operand is neutralised with `(false && x)`, which widens admission for a REFUSAL guard
// and narrows it for an ADMISSION guard. Middleware's health-route exemption is an admission: the
// `false &&` form makes health probes start requiring authentication, which every existing test
// notices, while the direction that matters — more routes exempted — went unmeasured. Widened
// instead, the liveness operand survives; see TestMiddlewareExemptsBothHealthRoutesFromAuthentication,
// whose readiness row already covers the twin.
//
// ONE MESSAGE FOR EVERY REFUSAL, as the round-two file records: Authenticate returns the same opaque
// "request authentication failed" whatever fired, so these tests assert the DISTINGUISHING VALUES
// (returned principal, whether a panic escaped) and isolation comes from the fixture. Each fixture
// below satisfies every sibling operand on its path and says which those are, and each Authenticate
// test carries a POSITIVE CONTROL: the same certificate under a sound prefix must authenticate. A
// fixture refused for an unrelated reason would otherwise pass this file while pinning nothing.
//
// ONE OPERAND IS DELIBERATELY NOT PINNED. `candidate.Opaque != ""` cannot be made the sole refuser
// by any input, so a test for it would assert an outcome its siblings already produce. url.Parse
// only populates Opaque for a URI with no `//` authority, and such a URI always has an empty Host
// (verified across spiffe:opaque, spiffe:a/b, spiffe:%2f and mailto:x@y.z). Reaching the Opaque
// operand with a matching host therefore requires prefix.Host == "", and the EARLIER operand
// `prefix.Host == ""` refuses first. It is unreachable in the §17 sense, and pinning it would need a
// fixture that violates two rules at once.

// TestCanonicalURISANConfinesAnIdentityToAConfiguredSubPathPrefix pins the HasPrefix operand of
// canonicalURISAN's return chain.
//
// SCOPE, because the operand is easy to overstate. The only production caller is
// cmd/regalia-kms/main.go:400, which passes "spiffe://regalia/" — a prefix whose path is "/". Under
// that configuration this operand never refuses alone: the one identity it would reject is the bare
// trust domain "spiffe://regalia", whose empty path also fails the sibling cleanliness operand
// (path.Clean("") is "."), so both fire together. The operand becomes the sole refuser only under a
// sub-path prefix, which NewAuthenticator accepts from any caller. So this is a contract of an
// exported constructor that nothing exercised, NOT a live confinement failure — widening it changes
// no behaviour reachable from main.go today.
//
// Isolation: with prefix "spiffe://regalia/workload/", the identity "spiffe://regalia/elsewhere"
// satisfies every operand of the four-line refusal guard (scheme and host both match, no user,
// query, fragment, opaque or raw path) and both siblings in the return chain — its path differs from
// the prefix path, and path.Clean leaves it unchanged. HasPrefix is the only false operand.
func TestCanonicalURISANConfinesAnIdentityToAConfiguredSubPathPrefix(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/workload/", nil, func() time.Time { return now }, time.Minute)
	outside := certificate(t, "spiffe://regalia/elsewhere", now.Add(-time.Hour), now.Add(time.Hour), 1)

	// Positive control first: the same prefix must admit an identity inside it, or a refusal below
	// proves only that the fixture is broken.
	inside := certificate(t, "spiffe://regalia/workload/sops-prod", now.Add(-time.Hour), now.Add(time.Hour), 2)
	principal, err := authenticator.Authenticate(authenticatedRequest(inside))
	if err != nil || principal != "spiffe://regalia/workload/sops-prod" {
		t.Fatalf("control is broken, so the refusal below would prove nothing: an identity INSIDE "+
			"the prefix gave principal=%q err=%v, want the identity and no error", principal, err)
	}

	principal, err = authenticator.Authenticate(authenticatedRequest(outside))
	if err == nil {
		t.Fatalf("DEFECT: certificate URI SAN %q authenticated as principal %q against configured "+
			"prefix \"spiffe://regalia/workload/\", which it is not under; the prefix confines nothing",
			"spiffe://regalia/elsewhere", principal)
	}
	if principal != "" {
		t.Fatalf("DEFECT: refused identity still returned principal %q, want empty", principal)
	}
}

// TestCanonicalURISANRefusesAMisconfiguredPrefix pins the three prefix-validation operands of the
// four-line refusal guard.
//
// These defend against operator misconfiguration of the uriPrefix passed to NewAuthenticator, and
// each row below is a prefix state canonicalURISAN can be handed: no prefix at all, one with the
// scheme dropped, one with the trust domain dropped. Nothing exercised any of them.
//
// THE NIL ROW DOES NOT COVER A PARSE FAILURE, and naming it that way would claim coverage this
// test does not have. It sets the prefix to nil directly; nothing here parses. Reaching nil by
// way of an unparseable prefix is a different path with a different guard, and it belongs to
// TestAuthenticateRefusesEveryIdentityWhenTheURIPrefixDoesNotParse below.
//
// The function is called directly rather than through Authenticate because Authenticate's own
// `err != nil` check on url.Parse refuses an unparseable prefix before canonicalURISAN is reached —
// see TestAuthenticateRefusesEveryIdentityWhenTheURIPrefixDoesNotParse for why that pair has to be
// tested together and what it can and cannot pin.
//
// Isolation, per row. The nil prefix is what the two operands after it would dereference, so the
// distinguishing value is whether a panic escapes, not the returned bool. For the empty-scheme row
// the candidate also has no scheme, so the scheme-equality sibling passes and prefix.Scheme == "" is
// the only operand that can refuse; the host sibling passes because both hosts are "regalia". For
// the empty-host row both hosts are "" so the host-equality sibling passes, the scheme sibling
// passes because both are "spiffe", and prefix.Host == "" refuses alone. Every row's candidate path
// is a strict, clean extension of the prefix path, so the return chain would admit it.
func TestCanonicalURISANRefusesAMisconfiguredPrefix(t *testing.T) {
	mustParse := func(raw string) *url.URL {
		t.Helper()
		parsed, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("fixture %q does not parse, so it cannot reach the operand under test: %v", raw, err)
		}
		return parsed
	}

	// A slice, not a map: map iteration order is randomised and two CI logs could not be diffed.
	for _, test := range []struct {
		name      string
		candidate string
		prefix    string
		nilPrefix bool
		operand   string
	}{
		{"no prefix was supplied", "spiffe://regalia/workload/x", "", true, `prefix == nil`},
		{"prefix has no scheme", "//regalia/workload/x", "//regalia/workload/", false, `prefix.Scheme == ""`},
		{"prefix has no trust domain", "spiffe:///workload/x", "spiffe:///workload/", false, `prefix.Host == ""`},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := mustParse(test.candidate)
			var prefix *url.URL
			if !test.nilPrefix {
				prefix = mustParse(test.prefix)
				if prefix.Scheme != "" && prefix.Host != "" {
					t.Fatalf("fixture is not what this row claims: prefix %q has both scheme %q and "+
						"host %q, so operand %s cannot fire", test.prefix, prefix.Scheme, prefix.Host, test.operand)
				}
			}

			var accepted bool
			panicked := recoveredPanic(func() { accepted = canonicalURISAN(candidate, prefix) })
			if panicked != nil {
				t.Fatalf("DEFECT: canonicalURISAN(%q, %s) panicked with %v; operand %s is what stops "+
					"the sibling reads that follow it from dereferencing a nil prefix",
					test.candidate, describePrefix(test.prefix, test.nilPrefix), panicked, test.operand)
			}
			if accepted {
				t.Fatalf("DEFECT: canonicalURISAN(%q, %s) accepted the identity; operand %s is the "+
					"only one on this path that can refuse it",
					test.candidate, describePrefix(test.prefix, test.nilPrefix), test.operand)
			}
		})
	}
}

func describePrefix(prefix string, isNil bool) string {
	if isNil {
		return "nil"
	}
	return `"` + prefix + `"`
}

// TestAuthenticateRefusesEveryIdentityWhenTheURIPrefixDoesNotParse pins Authenticate's url.Parse
// error check TOGETHER WITH canonicalURISAN's nil-prefix operand, and pins neither alone.
//
// That is the finding, not a limitation of the test. Neutralising either operand on its own leaves
// the suite green, because each produces the refusal the other would: drop the `err != nil` check
// and the nil prefix reaches canonicalURISAN, which refuses on `prefix == nil`; drop `prefix == nil`
// and `err != nil` refuses before canonicalURISAN is called. That pattern normally means one guard
// is redundant and the property is covered by the other. Here it is not. Neutralising BOTH AT ONCE
// also leaves the suite green, which is only possible if nothing exercises an unparseable prefix at
// all — so the property "a uriPrefix that fails to parse must not authenticate anyone" was untested
// outright, and the sweep reported two separate survivors rather than one untested property.
//
// The live code is not vulnerable: with both operands gone the sibling read prefix.Scheme
// dereferences nil and the request panics rather than authenticating. The gap is that nothing said
// so.
//
// Isolation: the certificate is otherwise sound, which the positive control proves by authenticating
// the very same certificate under a prefix that parses. The only difference between the two calls is
// the prefix, so nothing else in Authenticate can account for the refusal.
func TestAuthenticateRefusesEveryIdentityWhenTheURIPrefixDoesNotParse(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	sound := certificate(t, "spiffe://regalia/workload/sops-prod", now.Add(-time.Hour), now.Add(time.Hour), 7)

	const malformed = "://regalia/"
	if _, err := url.Parse(malformed); err == nil {
		t.Fatalf("fixture %q parses cleanly, so it cannot reach the operand under test", malformed)
	}

	principal, err := NewAuthenticator("spiffe://regalia/", nil, clock, time.Minute).
		Authenticate(authenticatedRequest(sound))
	if err != nil || principal != "spiffe://regalia/workload/sops-prod" {
		t.Fatalf("control is broken, so the refusal below would prove nothing: the same certificate "+
			"under a prefix that parses gave principal=%q err=%v", principal, err)
	}

	panicked := recoveredPanic(func() {
		principal, err = NewAuthenticator(malformed, nil, clock, time.Minute).
			Authenticate(authenticatedRequest(sound))
	})
	if panicked != nil {
		t.Fatalf("DEFECT: an unparseable uriPrefix %q made Authenticate panic with %v; a "+
			"misconfigured prefix must refuse, not crash the handler", malformed, panicked)
	}
	if err == nil {
		t.Fatalf("DEFECT: an unparseable uriPrefix %q authenticated %q as principal %q; a prefix "+
			"that does not parse confines nothing, so no identity can be checked against it",
			malformed, "spiffe://regalia/workload/sops-prod", principal)
	}
	if principal != "" {
		t.Fatalf("DEFECT: refused identity still returned principal %q, want empty", principal)
	}
}

// TestServerTLSConfigRefusesAPrivateKeyThatIsNotACryptoSigner pins the second operand of
// ServerTLSConfig, whose first is already covered by TestServerTLSConfigRefusesNilClientTrustRoots.
//
// The package comment on ServerTLSConfig states the contract this operand implements:
// "Hardware-backed keys work because tls.Certificate accepts crypto.Signer implementations; callers
// need not expose key bytes." That is the whole point of the assertion — an HSM-resident key is
// reachable only through the crypto.Signer interface, so a caller that passes raw key material, or a
// type that merely looks like a key, has misunderstood the boundary. Without the operand the bogus
// key is accepted into a tls.Config and the failure surfaces at handshake time, on a live
// connection, instead of at construction.
//
// Isolation: the trust roots are non-nil, so the sibling operand cannot fire, and a non-empty pool
// is used rather than an empty one so the fixture cannot be mistaken for a nil-adjacent edge case.
func TestServerTLSConfigRefusesAPrivateKeyThatIsNotACryptoSigner(t *testing.T) {
	roots := x509.NewCertPool()
	if roots == nil {
		t.Fatal("fixture is broken: x509.NewCertPool returned nil, so the sibling operand would fire")
	}

	// A byte slice is what a caller who exported key bytes would hold: it carries the key material
	// but not the interface, which is exactly the mistake the operand exists to catch.
	bogus := tls.Certificate{PrivateKey: []byte("key-material-without-the-interface")}
	if _, ok := bogus.PrivateKey.(crypto.Signer); ok {
		t.Fatal("fixture is broken: the key DOES implement crypto.Signer, so the operand cannot fire")
	}

	config, err := ServerTLSConfig(bogus, roots)
	if err == nil {
		t.Fatalf("DEFECT: ServerTLSConfig accepted a private key of type %T, which does not implement "+
			"crypto.Signer, and returned a usable config (MinVersion=%v, %d certificate(s)); the "+
			"failure now surfaces at handshake time on a live connection",
			bogus.PrivateKey, config.MinVersion, len(config.Certificates))
	}
	if config != nil {
		t.Fatalf("DEFECT: ServerTLSConfig returned both an error (%v) and a non-nil config; a caller "+
			"that checks the config first would serve with an unusable key", err)
	}
	if want := "server TLS private key must implement crypto.Signer"; err.Error() != want {
		t.Fatalf("refusal message is %q, want %q — this test pins the message because it is the only "+
			"thing telling the two ServerTLSConfig refusals apart", err.Error(), want)
	}
}
