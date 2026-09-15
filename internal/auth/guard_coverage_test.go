package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GUARDS NOTHING ELSE IN THIS PACKAGE DETECTS.
//
// A mutation sweep neutered each refusal below one at a time (`if false && (<original>)` for a
// refusal, `true || (<original>)` for a conjunct whose FALSE value is the refusal) and `go test
// ./internal/auth/` stayed green every time: every fixture in auth_test.go carries a ClientAuth
// EKU, a normalised path and a NotBefore inside the tolerance, so nothing in the suite ever
// reached these operands with an input they could refuse. Each test here is written against one
// such guard, with a fixture built so that guard is the only thing in its path that can say no.
//
// Falsifiability matrix — test : guard : what the guard's absence returns instead:
//
//   - TestServerTLSConfigRefusesNilClientTrustRoots        : ServerTLSConfig clientRoots == nil
//     : a usable *tls.Config with ClientCAs=<nil>, which verifies client chains against the HOST
//     trust store — a CA the daemon configured nowhere
//   - TestRevocationOverlongLineFailsClosed                : parseRevocationList scanner.Err()
//     : (1 serial [11111], <nil>) for a file whose lines 3 and 4 were never read
//   - TestAuthenticateRefusesCertificateWithoutClientAuthEKU : Authenticate !permitsClientAuthentication
//     : ("spiffe://regalia/workload/eku-probe", <nil>) for a cert with no EKU at all
//   - TestPermitsClientAuthenticationRejectsWrongPurposeEKU : permitsClientAuthentication usage ==
//     : true for a serverAuth-only or codeSigning-only certificate
//   - TestAuthenticateRefusesNonNormalizedSPIFFEPath       : canonicalURISAN path.Clean == Path
//     : ("spiffe://regalia/a/../admin", <nil>) — an RBAC map key aliasing another principal
//   - TestAuthenticateRefusesCertificateNotYetValidBeyondSkew : Authenticate NotBefore.After
//     : ("spiffe://regalia/workload/pre-issued", <nil>) for a cert issued for next year
//   - TestAuthenticateRefusesPercentEncodedSPIFFEPath      : canonicalURISAN RawPath != ""
//     : ("spiffe://regalia/work%2Fload", <nil>) — a second principal string for one identity
//   - TestAuthenticateRefusesForceQuerySPIFFEIdentity      : canonicalURISAN ForceQuery
//     : ("spiffe://regalia/workload?", <nil>) — likewise
//
// Every Authenticate refusal returns the same opaque "request authentication failed" (deliberately:
// the daemon tells a caller nothing about why). So the message alone cannot name which guard fired,
// and isolation has to come from the fixture: each one below satisfies every sibling operand on its
// path, and the test says which operands those are and why they cannot be the refuser. Where the
// package exposes a narrower predicate (canonicalURISAN, permitsClientAuthentication) the test
// asserts that value too, because it does distinguish.

// TestServerTLSConfigRefusesNilClientTrustRoots pins the one refusal that stands between the daemon
// and the host trust store.
//
// ServerTLSConfig sets ClientAuth: VerifyClientCertIfGiven. With ClientCAs left nil, crypto/tls
// verifies a presented client chain against the SYSTEM roots instead of refusing to build a config
// at all: with this guard mutated away, ServerTLSConfig(cert, nil) returns a non-nil *tls.Config
// with ClientCAs=<nil> ClientAuth=VerifyClientCertIfGiven, and a live handshake by a client whose
// CA is only in the host trust store reaches the handler as
// "spiffe://regalia/workload/rogue" with status 200 — an identity issued by a CA the operator
// configured nowhere. The refusal is the only thing that makes "no client roots" a startup error.
//
// Isolation: the private key is a real ecdsa.PrivateKey, so the sibling crypto.Signer refusal in
// ServerTLSConfig cannot fire; nil clientRoots is the only defect in this input.
func TestServerTLSConfigRefusesNilClientTrustRoots(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate := tls.Certificate{PrivateKey: key}

	config, err := ServerTLSConfig(serverCertificate, nil)
	if err == nil {
		t.Fatalf("DEFECT: ServerTLSConfig(cert, nil) built a config with ClientCAs=%v — presented client chains would be verified against the host trust store", config.ClientCAs)
	}
	if err.Error() != "client trust roots are required" {
		t.Fatalf("ServerTLSConfig(cert, nil) error = %q, want %q — a different refusal leaves the nil-roots one unproven", err, "client trust roots are required")
	}
	if config != nil {
		t.Fatalf("refused ServerTLSConfig returned a non-nil config: %#v", config)
	}

	// Anchor, not a gate: without it a ServerTLSConfig that refused every call would pass the
	// assertions above. An EMPTY pool is still an explicit answer ("trust nobody") and must build.
	roots := x509.NewCertPool()
	accepted, err := ServerTLSConfig(serverCertificate, roots)
	if err != nil {
		t.Fatalf("ServerTLSConfig(cert, empty pool) = %v, want a usable config", err)
	}
	if accepted.ClientCAs != roots {
		t.Fatalf("ServerTLSConfig did not install the caller's pool: ClientCAs=%v", accepted.ClientCAs)
	}
}

// TestRevocationOverlongLineFailsClosed pins the scanner error check in parseRevocationList.
//
// bufio.Scanner stops — silently, returning false from Scan — when a line exceeds the 1 MiB cap the
// parser sets. Without `scanner.Err()`, parseRevocationList reports success on the truncated prefix:
// the observed value for the fixture below is (1 serial [11111], <nil>), NewRevocationList succeeds,
// Check("22222") returns (false, <nil>) although 22222 is on line 3 of the file, and Authenticate
// admits that certificate as "spiffe://regalia/workload/revoked-22222". A revoked serial that the
// parser never read is the fail-open this whole file exists to prevent, and an operator who pads a
// line past the cap — or a truncated write — triggers it with no log line anywhere.
//
// Isolation: lines 1, 3 and 4 are valid decimal serials, so the per-line "not a non-negative
// integer serial" refusal cannot fire; the oversized line is digits too, so it would parse fine if
// the scanner ever handed it over. The scanner error is the only possible refuser.
func TestRevocationOverlongLineFailsClosed(t *testing.T) {
	// The parser calls scanner.Buffer(..., 1<<20); one byte over the cap is the smallest input that
	// reaches bufio.ErrTooLong.
	const scannerCap = 1 << 20
	overlong := "11111\n" + strings.Repeat("9", scannerCap+1) + "\n22222\n33333\n"

	serials, err := parseRevocationList(strings.NewReader(overlong))
	if err == nil {
		t.Fatalf("DEFECT: parseRevocationList returned (%d serials, <nil>) for a file whose scan aborted on line 2 — serials 22222 and 33333 were never read and would authenticate", len(serials))
	}
	if err.Error() != "read: bufio.Scanner: token too long" {
		t.Fatalf("parseRevocationList error = %q, want %q — a different failure leaves the scanner check unproven", err, "read: bufio.Scanner: token too long")
	}

	// The same refusal has to reach the daemon's startup path, not just the parser: this is where a
	// truncated list would otherwise become a live, quietly-shortened list.
	listPath := filepath.Join(t.TempDir(), "revoked.txt")
	if err := os.WriteFile(listPath, []byte(overlong), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRevocationList(listPath); err == nil {
		t.Fatal("DEFECT: NewRevocationList accepted a revocation file whose scan aborted mid-way — the daemon would start with a silently shortened list")
	} else if !strings.Contains(err.Error(), "read: bufio.Scanner: token too long") {
		t.Fatalf("NewRevocationList error = %q, want it to wrap %q", err, "read: bufio.Scanner: token too long")
	}

	// Anchor, not a gate: the refusal must be the CAP, not length in general. A long-but-legal line
	// (a comment, so no big.Int work) still parses, and — the part that matters — the serial AFTER
	// it is still read. Without this row a parser that errored on any long input would look correct.
	legal := "11111\n#" + strings.Repeat("9", scannerCap-16) + "\n22222\n"
	accepted, err := parseRevocationList(strings.NewReader(legal))
	if err != nil {
		t.Fatalf("parseRevocationList(long-but-legal line) = %v, want it to parse", err)
	}
	if _, ok := accepted["22222"]; !ok || len(accepted) != 2 {
		t.Fatalf("parseRevocationList(long-but-legal line) = %v, want both 11111 and 22222", accepted)
	}
}

// TestAuthenticateRefusesCertificateWithoutClientAuthEKU pins the EKU arm of Authenticate's
// purpose check.
//
// permitsClientAuthentication loops over ExtKeyUsage, so an EMPTY list never enters the loop and
// returns false — the refusal is the guard in Authenticate, not the loop body. With that guard
// mutated away the observed result for this fixture is ("spiffe://regalia/workload/eku-probe",
// <nil>): a certificate carrying no client-authentication purpose at all — a CA's server leaf, an
// S/MIME cert, anything a workload was issued for some other reason — authenticates as a workload
// and is handed to RBAC as a principal.
//
// Isolation: the sibling operand `len(certificate.URIs) != 1` is satisfied (exactly one URI), the
// validity window brackets now, the SAN is canonical and revocation is not configured, so the EKU
// operand is the only thing on this path that can refuse.
func TestAuthenticateRefusesCertificateWithoutClientAuthEKU(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/eku-probe", now.Add(-time.Hour), now.Add(time.Hour), 30)
	cert.ExtKeyUsage = nil // the shared helper sets ClientAuth; that is exactly what the suite never varied

	if len(cert.URIs) != 1 {
		t.Fatalf("fixture is not isolated: len(URIs) = %d, the sibling operand would refuse first", len(cert.URIs))
	}
	principal, err := authenticator.Authenticate(authenticatedRequest(cert))
	if err == nil {
		t.Fatalf("DEFECT: a certificate with no extended key usage authenticated as %q — nothing asserts it was issued for client authentication", principal)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("no-EKU certificate error = %q, want %q", err, "request authentication failed")
	}
	if principal != "" {
		t.Fatalf("refused Authenticate returned principal %q, want empty", principal)
	}

	// Anchor, not a gate: the same certificate with ClientAuth restored must authenticate, or this
	// test would also pass against an Authenticate that refused everything.
	cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	principal, err = authenticator.Authenticate(authenticatedRequest(cert))
	if err != nil || principal != "spiffe://regalia/workload/eku-probe" {
		t.Fatalf("Authenticate(same cert, ClientAuth restored) = (%q, %v), want the principal and no error", principal, err)
	}
}

// TestPermitsClientAuthenticationRejectsWrongPurposeEKU pins the membership test inside the loop.
//
// This is the other half of the EKU story and it needs its own fixture: a certificate that DOES
// carry extended key usages, just not client authentication. Widening the membership test (observed
// as `true || (...)`) makes permitsClientAuthentication return true for a serverAuth-only leaf, and
// Authenticate then admits it as "spiffe://regalia/workload/server-only" — the KMS's own server
// certificate, or any TLS leaf the workload's CA issued for a web service, becomes a valid client
// identity.
//
// The predicate is asserted directly rather than through Authenticate on purpose: routing this
// through Authenticate would make the test fire under the auth.go EKU-guard mutation as well, and a
// test that goes red for two different defects cannot name either. Here it goes red only when the
// usage comparison itself changes.
func TestPermitsClientAuthenticationRejectsWrongPurposeEKU(t *testing.T) {
	// A slice, not a map: map iteration order is randomised and two CI logs could not be diffed.
	for _, test := range []struct {
		name   string
		usages []x509.ExtKeyUsage
		want   bool
	}{
		{"serverAuth only", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false},
		{"codeSigning only", []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, false},
		{"OCSP signing and email protection", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning, x509.ExtKeyUsageEmailProtection}, false},
		// Anchors, not gates: without these a predicate that returned false for everything would
		// pass the three rows above and lock every workload out on the next release.
		{"clientAuth", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, true},
		{"any", []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, true},
		{"serverAuth then clientAuth", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := permitsClientAuthentication(&x509.Certificate{ExtKeyUsage: test.usages}); got != test.want {
				t.Fatalf("permitsClientAuthentication(%v) = %v, want %v", test.usages, got, test.want)
			}
		})
	}
}

// TestAuthenticateRefusesNonNormalizedSPIFFEPath pins the path.Clean conjunct of canonicalURISAN.
//
// The string Authenticate returns is the exact RBAC map key (rbac.go looks the principal up in
// policy.grants), and LoadPolicy validates policy entries through this same predicate. Accepting an
// unnormalised path therefore admits an ALIAS on both sides of the lookup: with the conjunct
// widened, the observed results are ("spiffe://regalia/a/../admin", <nil>),
// ("spiffe://regalia//admin", <nil>) and ("spiffe://regalia/admin/", <nil>) — three more spellings
// of a principal an operator wrote once, each of which misses the grant it should match or matches
// one it should not.
//
// Isolation: RawPath is empty for all three (url.Parse does not need to escape them), there is no
// query, fragment, userinfo or opaque part, the scheme and host equal the prefix, and the path is a
// proper extension of "/" — so every sibling operand in the refusal block is satisfied and the
// Clean comparison is the only conjunct left that can return false. The subtest asserts the
// predicate directly as well as Authenticate's refusal, because the predicate's value does name it.
func TestAuthenticateRefusesNonNormalizedSPIFFEPath(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	prefix, err := url.Parse("spiffe://regalia/")
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	for _, test := range []struct {
		name      string
		identity  string
		canonical bool
		serial    int64
	}{
		{name: "dot-dot traversal", identity: "spiffe://regalia/a/../admin", serial: 31},
		{name: "empty path segment", identity: "spiffe://regalia//admin", serial: 32},
		{name: "trailing slash", identity: "spiffe://regalia/admin/", serial: 33},
		// Anchor, not a gate: an already-normalised path must still authenticate.
		{name: "already normalised", identity: "spiffe://regalia/workload/sops-prod", canonical: true, serial: 34},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate, err := url.Parse(test.identity)
			if err != nil {
				t.Fatal(err)
			}
			if candidate.RawPath != "" {
				t.Fatalf("fixture is not isolated: RawPath = %q, the RawPath operand would refuse first", candidate.RawPath)
			}
			if got := canonicalURISAN(candidate, prefix); got != test.canonical {
				t.Fatalf("canonicalURISAN(%q) = %v, want %v (path.Clean(%q) = %q)",
					test.identity, got, test.canonical, candidate.Path, path.Clean(candidate.Path))
			}
			principal, err := authenticator.Authenticate(authenticatedRequest(
				certificate(t, test.identity, now.Add(-time.Hour), now.Add(time.Hour), test.serial)))
			if test.canonical {
				if err != nil || principal != test.identity {
					t.Fatalf("Authenticate(%q) = (%q, %v), want the principal and no error", test.identity, principal, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("DEFECT: unnormalised SAN %q authenticated as principal %q — an RBAC key that aliases another identity", test.identity, principal)
			}
			if err.Error() != "request authentication failed" {
				t.Fatalf("Authenticate(%q) error = %q, want %q", test.identity, err, "request authentication failed")
			}
		})
	}
}

// TestAuthenticateRefusesCertificateNotYetValidBeyondSkew pins the NotBefore arm of the validity
// check.
//
// The suite touches this arm only from INSIDE the tolerance (a rotation cert at now+30s against a
// 1m skew — an accept, not a refusal), so nothing ever proved the arm refuses anything. With it
// mutated away, a certificate whose validity starts a year from now authenticates as
// "spiffe://regalia/workload/pre-issued": a pre-issued leaf, harvested from a CA before its window
// opens, is a live credential today.
//
// Isolation: NotAfter is two years out, so the expiry arm of the same `if` cannot fire; the EKU,
// SAN and (absent) revocation list are all clean.
func TestAuthenticateRefusesCertificateNotYetValidBeyondSkew(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)

	notYetValid := certificate(t, "spiffe://regalia/workload/pre-issued", now.AddDate(1, 0, 0), now.AddDate(2, 0, 0), 35)
	if notYetValid.NotAfter.Before(now) {
		t.Fatalf("fixture is not isolated: NotAfter = %s is already past, the expiry arm would refuse first", notYetValid.NotAfter)
	}
	principal, err := authenticator.Authenticate(authenticatedRequest(notYetValid))
	if err == nil {
		t.Fatalf("DEFECT: a certificate valid from %s authenticated as %q at %s", notYetValid.NotBefore, principal, now)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("not-yet-valid certificate error = %q, want %q", err, "request authentication failed")
	}
	if principal != "" {
		t.Fatalf("refused Authenticate returned principal %q, want empty", principal)
	}

	// Anchor, not a gate: the tolerance is the reason the arm is not a plain `NotBefore.After(now)`,
	// and a rotation cert 30s early against a 1m skew must still authenticate.
	withinSkew := certificate(t, "spiffe://regalia/workload/pre-issued", now.Add(30*time.Second), now.Add(time.Hour), 36)
	principal, err = authenticator.Authenticate(authenticatedRequest(withinSkew))
	if err != nil || principal != "spiffe://regalia/workload/pre-issued" {
		t.Fatalf("Authenticate(NotBefore = now+30s, skew 1m) = (%q, %v), want the principal and no error", principal, err)
	}
}

// TestAuthenticateRefusesPercentEncodedSPIFFEPath pins the RawPath operand of canonicalURISAN.
//
// RawPath is non-empty exactly when the escaped form does not round-trip from Path — i.e. when the
// SAN encodes a character that would otherwise be structural. "spiffe://regalia/work%2Fload" has
// Path="/work/load" and RawPath="/work%2Fload": with the operand mutated away, canonicalURISAN
// returns true and Authenticate returns ("spiffe://regalia/work%2Fload", <nil>) — a SECOND principal
// string for the identity the policy file calls "spiffe://regalia/work/load", so a grant written for
// one is silently not the grant checked for the other.
//
// Isolation: every sibling operand is satisfied (scheme and host match the prefix, no userinfo,
// query, fragment or opaque part), and path.Clean("/work/load") == "/work/load", so the trailing
// Clean conjunct cannot refuse either. RawPath is the only operand left.
func TestAuthenticateRefusesPercentEncodedSPIFFEPath(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	prefix, err := url.Parse("spiffe://regalia/")
	if err != nil {
		t.Fatal(err)
	}
	const encoded = "spiffe://regalia/work%2Fload"
	candidate, err := url.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.RawPath == "" || path.Clean(candidate.Path) != candidate.Path || candidate.RawQuery != "" || candidate.ForceQuery || candidate.Opaque != "" {
		t.Fatalf("fixture is not isolated: RawPath=%q Path=%q RawQuery=%q ForceQuery=%v Opaque=%q",
			candidate.RawPath, candidate.Path, candidate.RawQuery, candidate.ForceQuery, candidate.Opaque)
	}
	if canonicalURISAN(candidate, prefix) {
		t.Fatalf("DEFECT: canonicalURISAN(%q) = true — %q and %q would be two principals for one identity",
			encoded, encoded, "spiffe://regalia/work/load")
	}

	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	principal, err := authenticator.Authenticate(authenticatedRequest(
		certificate(t, encoded, now.Add(-time.Hour), now.Add(time.Hour), 37)))
	if err == nil {
		t.Fatalf("DEFECT: percent-encoded SAN authenticated as principal %q", principal)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("percent-encoded SAN error = %q, want %q", err, "request authentication failed")
	}

	// Anchor, not a gate: the decoded spelling of the same identity is the one the policy names and
	// must authenticate — the refusal is about the encoding, not about the path.
	decoded := "spiffe://regalia/work/load"
	principal, err = authenticator.Authenticate(authenticatedRequest(
		certificate(t, decoded, now.Add(-time.Hour), now.Add(time.Hour), 38)))
	if err != nil || principal != decoded {
		t.Fatalf("Authenticate(%q) = (%q, %v), want the principal and no error", decoded, principal, err)
	}
}

// TestAuthenticateRefusesForceQuerySPIFFEIdentity pins the ForceQuery operand of canonicalURISAN.
//
// A trailing "?" with nothing after it parses as ForceQuery=true and RawQuery="", so the tested
// sibling (auth_test.go's "...sops?role=admin", which trips RawQuery != "") cannot detect it. With
// the operand mutated away, canonicalURISAN returns true and Authenticate returns
// ("spiffe://regalia/workload?", <nil>) — again a second principal string for one identity, and one
// an attacker chooses rather than the operator.
//
// Isolation: RawQuery is empty, RawPath is empty, path.Clean("/workload") == "/workload", and the
// scheme, host and prefix all match, so ForceQuery is the only operand that can refuse.
func TestAuthenticateRefusesForceQuerySPIFFEIdentity(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	prefix, err := url.Parse("spiffe://regalia/")
	if err != nil {
		t.Fatal(err)
	}
	const forced = "spiffe://regalia/workload?"
	candidate, err := url.Parse(forced)
	if err != nil {
		t.Fatal(err)
	}
	if !candidate.ForceQuery || candidate.RawQuery != "" || candidate.RawPath != "" || candidate.Fragment != "" {
		t.Fatalf("fixture is not isolated: ForceQuery=%v RawQuery=%q RawPath=%q Fragment=%q",
			candidate.ForceQuery, candidate.RawQuery, candidate.RawPath, candidate.Fragment)
	}
	if canonicalURISAN(candidate, prefix) {
		t.Fatalf("DEFECT: canonicalURISAN(%q) = true — %q and %q would be two principals for one identity",
			forced, forced, "spiffe://regalia/workload")
	}

	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	principal, err := authenticator.Authenticate(authenticatedRequest(
		certificate(t, forced, now.Add(-time.Hour), now.Add(time.Hour), 39)))
	if err == nil {
		t.Fatalf("DEFECT: SAN with a forced empty query authenticated as principal %q", principal)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("forced-query SAN error = %q, want %q", err, "request authentication failed")
	}

	// Anchor, not a gate: the same identity without the trailing "?" is the one the policy names.
	plain := "spiffe://regalia/workload"
	principal, err = authenticator.Authenticate(authenticatedRequest(
		certificate(t, plain, now.Add(-time.Hour), now.Add(time.Hour), 40)))
	if err != nil || principal != plain {
		t.Fatalf("Authenticate(%q) = (%q, %v), want the principal and no error", plain, principal, err)
	}
}
