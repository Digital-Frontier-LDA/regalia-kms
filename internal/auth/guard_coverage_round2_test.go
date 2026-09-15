package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"
)

// GUARDS NOTHING ELSE IN THIS PACKAGE DETECTS — ROUND TWO.
//
// guard_coverage_test.go closed the first set. A second sweep neutered one operand at a time
// (`false && <operand>` for a refusal operand, `true || <operand>` for a conjunct whose FALSE value
// is the refusal) and the whole kms module — every package `go list ./...` reports when run from
// the `kms/` module root — stayed green for every guard below. The package count is deliberately
// not written here: it was 25 when this was measured, nothing re-derives it, and a comment cannot
// carry the date that would tell a reader when it was last true.
//
// The directory is part of the command, not a detail. There is no go.mod at the repository root, so
// `go list ./...` run from there FAILS ("directory prefix . does not contain main module") rather
// than reporting a different number -- a published command that answers the question only from one
// directory has not made the claim re-derivable. And `kms/adapters/sops` is a SEPARATE module: it
// is not among those packages and was not part of this sweep. Four of
// them do not merely admit a bad input when they are gone: they PANIC, because the operand is what
// stops a nil from reaching the dereference on the next line. Those tests recover deliberately, so
// that a regression is a `--- FAIL:` line naming one test rather than a dead test binary that says
// nothing about which fixture reached it.
//
// Falsifiability matrix — test : operand : what the code does without that operand:
//
//   - TestAuthenticateRefusesAnEmptyVerifiedChain : Authenticate
//     len(request.TLS.VerifiedChains[0]) == 0 : panics with "index out of range [0] with length 0"
//     at the `certificate := request.TLS.VerifiedChains[0][0]` line. net/http recovers per
//     connection, so in production that is a dropped connection instead of a 401.
//   - TestAuthenticateRefusesACertificateWithNoSerialNumber : Authenticate
//     certificate.SerialNumber == nil : ("spiffe://regalia/workload/tx-signer", <nil>). No panic —
//     (*big.Int)(nil).String() is "<nil>", so the revocation lookup runs against the literal string
//     "<nil>", matches nothing, and revocation becomes skippable by omitting a field.
//   - TestAuthenticateRefusesACertificateWhoseURISANEntryIsNil : canonicalURISAN
//     candidate == nil : panics with a nil pointer dereference inside canonicalURISAN, at the
//     `candidate.Scheme != prefix.Scheme` operand. certificate.URIs is []*url.URL, so
//     `URIs: []*url.URL{nil}` has len 1 and passes Authenticate's `len(certificate.URIs) != 1`.
//   - TestAuthenticateRefusesTheBareTrustDomainAsAnIdentity : canonicalURISAN
//     candidate.Path != prefix.Path : ("spiffe://regalia/", <nil>) from Authenticate AND an accepted
//     policy granting {Principal:spiffe://regalia/ ObjectID:k Operation:sign} from LoadPolicy — the
//     trust domain itself becomes a principal on both sides.
//   - TestMiddlewareExemptsBothHealthRoutesFromAuthentication : Middleware
//     request.URL.Path == "/v1/health/ready" : status=401 body="" and the unauthorized counter
//     incremented, for the kubelet's readiness probe.
//   - TestCheckOnANilRevocationListIsANoOpNotAPanic : RevocationList.Check
//     r == nil : panics with a nil pointer dereference at the sibling `r.path == ""` read.
//   - TestLoadPolicyRefusesTrailingJSONDocuments : LoadPolicy
//     !errors.Is(err, io.EOF) on the second Decode : the first document loads and every later one is
//     dropped in silence, while the digest still covers the WHOLE file.
//   - TestLoadPolicyRefusesAnUnsupportedSchemaVersion : LoadPolicy
//     document.SchemaVersion != 1 : a schema_version 99 (or -1) document is interpreted under v1
//     rules — non-nil policy, Ready()=true, Allowed(probe,obj-a,unwrap,production)=true.
//   - TestLoadPolicyRefusesAPolicyWithNoPrincipals : LoadPolicy
//     len(document.Principals) == 0 : a non-nil policy with no grants (Ready()=false, every Allowed
//     denies), which preflight reports as "RBAC policy loads, digest sha256:…" instead of refusing.
//
// ONE MESSAGE FOR EVERY REFUSAL. Authenticate returns the same opaque "request authentication
// failed" whatever the reason, deliberately, so the message cannot name which operand fired. Where
// that is the only string available these tests assert the DISTINGUISHING VALUES instead — the
// returned principal, the HTTP status, the unauthorized-counter delta, whether a panic escaped — and
// isolation comes from the fixture: each one satisfies every sibling operand on its path and says
// which ones those are. LoadPolicy's three refusals do have distinct messages, and those are
// asserted verbatim; the two operands of LoadPolicy's support check share one message, so those two
// fixtures are what tell them apart (real principals with a bad version; version 1 with no
// principals).

// recoveredPanic runs call and returns whatever it panicked with, or nil.
//
// The panic cases below need this: an unrecovered panic takes the whole test binary down, and then
// "which test failed" has no answer at all — the run reports a crashed package, so the mutation that
// caused it cannot be attributed to one guard. Recovering turns the same defect into an ordinary
// `--- FAIL:` line for exactly one test.
func recoveredPanic(call func()) (recovered any) {
	defer func() { recovered = recover() }()
	call()
	return recovered
}

// TestAuthenticateRefusesAnEmptyVerifiedChain pins the third operand of Authenticate's TLS check.
//
// The operand is not redundant with its two siblings: `request.TLS == nil` and
// `len(request.TLS.VerifiedChains) == 0` both pass for a ConnectionState whose outer slice holds one
// EMPTY chain, and the very next statement indexes `VerifiedChains[0][0]`. Without this operand the
// observed result is a panic — "index out of range [0] with length 0" — from inside Authenticate,
// not a 401. net/http recovers per connection, so a caller would see the connection dropped and the
// unauthorized counter would never move; nothing in the daemon would record the attempt.
//
// tls.ConnectionState.VerifiedChains is a public [][]*x509.Certificate and Authenticate takes an
// *http.Request, so any middleware, test harness or proxy shim that rebuilds ConnectionState can
// hand this shape over — it is reachable without crypto/tls ever producing it.
//
// Isolation: TLS is non-nil and the outer slice has exactly one element, so neither sibling operand
// can refuse; the empty inner chain is the only defect in this request.
func TestAuthenticateRefusesAnEmptyVerifiedChain(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)

	request := httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil)
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}
	if len(request.TLS.VerifiedChains) != 1 {
		t.Fatalf("fixture is not isolated: outer chains=%d — a sibling operand would refuse first",
			len(request.TLS.VerifiedChains))
	}

	var principal string
	var err error
	if recovered := recoveredPanic(func() { principal, err = authenticator.Authenticate(request) }); recovered != nil {
		t.Fatalf("DEFECT: Authenticate panicked on a verified-chain slice whose first chain is empty: %v — in the daemon net/http recovers this per connection, so the request is dropped rather than answered 401 and nothing counts it", recovered)
	}
	if err == nil {
		t.Fatalf("DEFECT: an empty verified chain authenticated as %q — no certificate was ever inspected", principal)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("empty verified chain error = %q, want %q", err, "request authentication failed")
	}
	if principal != "" {
		t.Fatalf("refused Authenticate returned principal %q, want empty", principal)
	}

	// The same input has to reach the middleware as a counted 401, because that — not the error
	// value — is what an operator sees.
	var unauthorized int
	authenticator.OnUnauthorized(func() { unauthorized++ })
	handler := authenticator.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	recorder := httptest.NewRecorder()
	emptyChain := httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil)
	emptyChain.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}
	if recovered := recoveredPanic(func() { handler.ServeHTTP(recorder, emptyChain) }); recovered != nil {
		t.Fatalf("DEFECT: Middleware panicked on an empty verified chain: %v", recovered)
	}
	if recorder.Code != http.StatusUnauthorized || unauthorized != 1 {
		t.Fatalf("empty verified chain: status=%d unauthorized=%d, want 401 and 1", recorder.Code, unauthorized)
	}

	// Anchor, not a gate: without it an Authenticate that refused every request would pass every
	// assertion above. A one-certificate chain of the same shape must still authenticate.
	principal, err = authenticator.Authenticate(authenticatedRequest(
		certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 51)))
	if err != nil || principal != "spiffe://regalia/workload/tx-signer" {
		t.Fatalf("Authenticate(one-certificate chain) = (%q, %v), want the principal and no error", principal, err)
	}
}

// TestAuthenticateRefusesACertificateWithNoSerialNumber pins the serial-number guard.
//
// x509.Certificate.SerialNumber is a *big.Int and Authenticate is handed a struct, so a nil there is
// an ordinary value, not a corrupt one. It does not panic: (*big.Int)(nil).String() returns the
// literal "<nil>", so with the guard mutated away the revocation lookup runs against the string
// "<nil>", matches nothing, and the observed result is ("spiffe://regalia/workload/tx-signer",
// <nil>) — from an authenticator whose revocation list is loaded and working. REVOCATION BECOMES
// SKIPPABLE BY OMITTING A FIELD, which is the one bypass the revocation file exists to prevent.
//
// Isolation: the validity window brackets now, the EKU is ClientAuth, the SAN is a canonical single
// URI, and the configured list holds serial 42 only — so it neither errors nor matches for this
// certificate. The nil serial is the only thing on this path that can refuse.
func TestAuthenticateRefusesACertificateWithNoSerialNumber(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", newRevocationList(t, "42"), func() time.Time { return now }, time.Minute)

	noSerial := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 43)
	noSerial.SerialNumber = nil
	if len(noSerial.URIs) != 1 || len(noSerial.ExtKeyUsage) == 0 {
		t.Fatalf("fixture is not isolated: URIs=%d EKU=%v — a later guard would refuse first", len(noSerial.URIs), noSerial.ExtKeyUsage)
	}

	principal, err := authenticator.Authenticate(authenticatedRequest(noSerial))
	if err == nil {
		t.Fatalf("DEFECT: a certificate with no serial number authenticated as %q — the revocation list can never match a certificate that has no serial to look up", principal)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("nil-serial certificate error = %q, want %q", err, "request authentication failed")
	}
	if principal != "" {
		t.Fatalf("refused Authenticate returned principal %q, want empty", principal)
	}

	// The list is live, and this is what makes the refusal above load-bearing rather than pedantic:
	// the SAME identity is refused when it carries the revoked serial. Without the guard, dropping
	// the field is a way around this row.
	revoked := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)
	if _, err := authenticator.Authenticate(authenticatedRequest(revoked)); err == nil {
		t.Fatal("fixture is not isolated: serial 42 is not actually revoked, so this authenticator proves nothing about the nil case")
	}

	// Anchor, not a gate: the same certificate with a serial that is NOT on the list must
	// authenticate, or this test would also pass against an Authenticate that refused everything.
	accepted := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 43)
	principal, err = authenticator.Authenticate(authenticatedRequest(accepted))
	if err != nil || principal != "spiffe://regalia/workload/tx-signer" {
		t.Fatalf("Authenticate(serial 43, not revoked) = (%q, %v), want the principal and no error", principal, err)
	}
	if accepted.SerialNumber == nil || accepted.SerialNumber.String() != "43" {
		t.Fatalf("anchor certificate serial = %v, want 43", accepted.SerialNumber)
	}
}

// TestAuthenticateRefusesACertificateWhoseURISANEntryIsNil pins the nil-candidate operand of
// canonicalURISAN.
//
// An earlier sweep called this operand unreachable. It is not. certificate.URIs is []*url.URL, so
// `URIs: []*url.URL{nil}` has length 1 and satisfies Authenticate's `len(certificate.URIs) != 1`
// check; principalURI is then nil and goes straight to canonicalURISAN. Without the operand the
// observed result is a nil pointer dereference inside canonicalURISAN — SIGSEGV at the
// `candidate.Scheme != prefix.Scheme` comparison — rather than ("", request authentication failed).
//
// Isolation: prefix comes from url.Parse of a non-empty scheme and host, so the `prefix == nil`,
// `prefix.Scheme == ""` and `prefix.Host == ""` siblings all pass; the nil candidate is the only
// operand in that disjunction that can return false before the first dereference.
func TestAuthenticateRefusesACertificateWhoseURISANEntryIsNil(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	prefix, err := url.Parse("spiffe://regalia/")
	if err != nil {
		t.Fatal(err)
	}
	if prefix.Scheme == "" || prefix.Host == "" {
		t.Fatalf("fixture is not isolated: prefix=%v — a sibling operand would return false first", prefix)
	}

	var canonical bool
	if recovered := recoveredPanic(func() { canonical = canonicalURISAN(nil, prefix) }); recovered != nil {
		t.Fatalf("DEFECT: canonicalURISAN(nil, %q) panicked: %v — Authenticate reaches this with a certificate whose URIs is []*url.URL{nil}", prefix, recovered)
	}
	if canonical {
		t.Fatal("DEFECT: canonicalURISAN(nil, prefix) = true — a certificate with no parsed SAN would be treated as canonical")
	}

	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	nilEntry := certificate(t, "", now.Add(-time.Hour), now.Add(time.Hour), 52)
	nilEntry.URIs = []*url.URL{nil}
	if len(nilEntry.URIs) != 1 {
		t.Fatalf("fixture is not isolated: len(URIs) = %d, Authenticate's URI-count guard would refuse first", len(nilEntry.URIs))
	}

	var principal string
	if recovered := recoveredPanic(func() { principal, err = authenticator.Authenticate(authenticatedRequest(nilEntry)) }); recovered != nil {
		t.Fatalf("DEFECT: Authenticate panicked on URIs=[]*url.URL{nil}: %v — a request whose SAN slot is present but nil takes the daemon's connection down instead of being refused", recovered)
	}
	if err == nil {
		t.Fatalf("DEFECT: a certificate whose only URI SAN entry is nil authenticated as %q", principal)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("nil URI SAN entry error = %q, want %q", err, "request authentication failed")
	}
	if principal != "" {
		t.Fatalf("refused Authenticate returned principal %q, want empty", principal)
	}

	// Anchor, not a gate: a real SAN against the same prefix must still be canonical and still
	// authenticate, or a canonicalURISAN that returned false for everything would pass the above.
	present, err := url.Parse("spiffe://regalia/workload/tx-signer")
	if err != nil {
		t.Fatal(err)
	}
	if !canonicalURISAN(present, prefix) {
		t.Fatalf("canonicalURISAN(%q, %q) = false, want true", present, prefix)
	}
	principal, err = authenticator.Authenticate(authenticatedRequest(
		certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 53)))
	if err != nil || principal != "spiffe://regalia/workload/tx-signer" {
		t.Fatalf("Authenticate(real SAN) = (%q, %v), want the principal and no error", principal, err)
	}
}

// TestAuthenticateRefusesTheBareTrustDomainAsAnIdentity pins the `candidate.Path != prefix.Path`
// conjunct of canonicalURISAN.
//
// This conjunct is what makes the trust domain a NAMESPACE rather than an identity.
// "spiffe://regalia/" has Path "/", which is exactly the prefix's path: it starts with the prefix
// and is already clean, so the two remaining conjuncts both hold and this one is the only thing that
// says no. With it widened the observed results are ("spiffe://regalia/", <nil>) from Authenticate
// AND an accepted policy whose grants are [{Principal:spiffe://regalia/ ObjectID:k Operation:sign}]
// from LoadPolicy — the same string becomes a principal on both the authentication and the
// authorization side, so a certificate naming only the trust domain matches a grant written for the
// trust domain.
//
// Isolation: scheme and host equal the prefix's, there is no userinfo, query, fragment, opaque part
// or RawPath, and path.Clean("/") == "/", so every sibling operand and both sibling conjuncts are
// satisfied. (The other spelling, "spiffe://regalia" with no trailing slash, is NOT isolated — its
// Path is "" and the strings.HasPrefix conjunct refuses it first — so it is deliberately not used
// here.)
func TestAuthenticateRefusesTheBareTrustDomainAsAnIdentity(t *testing.T) {
	const trustDomain = "spiffe://regalia/"
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

	prefix, err := url.Parse(trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := url.Parse(trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Path != prefix.Path {
		t.Fatalf("fixture is not isolated: candidate.Path=%q prefix.Path=%q — this test only means something when they are equal", candidate.Path, prefix.Path)
	}
	if !strings.HasPrefix(candidate.Path, prefix.Path) || path.Clean(candidate.Path) != candidate.Path {
		t.Fatalf("fixture is not isolated: HasPrefix=%v Clean(%q)=%q — a sibling conjunct would refuse first",
			strings.HasPrefix(candidate.Path, prefix.Path), candidate.Path, path.Clean(candidate.Path))
	}
	if candidate.RawPath != "" || candidate.RawQuery != "" || candidate.Fragment != "" || candidate.ForceQuery || candidate.Opaque != "" || candidate.User != nil {
		t.Fatalf("fixture is not isolated: RawPath=%q RawQuery=%q Fragment=%q ForceQuery=%v Opaque=%q",
			candidate.RawPath, candidate.RawQuery, candidate.Fragment, candidate.ForceQuery, candidate.Opaque)
	}
	if canonicalURISAN(candidate, prefix) {
		t.Fatalf("DEFECT: canonicalURISAN(%q, %q) = true — the trust domain is a namespace, not a workload", trustDomain, trustDomain)
	}

	authenticator := NewAuthenticator(trustDomain, nil, func() time.Time { return now }, time.Minute)
	principal, err := authenticator.Authenticate(authenticatedRequest(
		certificate(t, trustDomain, now.Add(-time.Hour), now.Add(time.Hour), 54)))
	if err == nil {
		t.Fatalf("DEFECT: a certificate whose only SAN is the bare trust domain authenticated as %q", principal)
	}
	if err.Error() != "request authentication failed" {
		t.Fatalf("bare trust domain error = %q, want %q", err, "request authentication failed")
	}
	if principal != "" {
		t.Fatalf("refused Authenticate returned principal %q, want empty", principal)
	}

	// The authorization side runs through the same predicate (LoadPolicy validates each principal
	// URI with canonicalURISAN), and it is the half that turns the accepted identity into access.
	const domainPolicy = `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/","grants":[{"objects":["k"],"operations":["sign"],"environments":["production"]}]}]}`
	policy, err := LoadPolicy(strings.NewReader(domainPolicy))
	if err == nil {
		t.Fatalf("DEFECT: LoadPolicy accepted the bare trust domain as a principal, granting %+v", policy.GrantedObjects())
	}
	const domainRefusal = `RBAC principal "spiffe://regalia/": URI is not a canonical workload identity under "spiffe://regalia/"`
	if err.Error() != domainRefusal {
		t.Fatalf("trust-domain policy error = %q, want %q — a different refusal leaves this one unproven", err, domainRefusal)
	}

	// Anchor, not a gate: a workload UNDER the trust domain must still authenticate and must still
	// load as a principal. The refusal is about the domain itself, not about the prefix.
	const workload = "spiffe://regalia/workload/tx-signer"
	principal, err = authenticator.Authenticate(authenticatedRequest(
		certificate(t, workload, now.Add(-time.Hour), now.Add(time.Hour), 55)))
	if err != nil || principal != workload {
		t.Fatalf("Authenticate(%q) = (%q, %v), want the principal and no error", workload, principal, err)
	}
	const workloadPolicy = `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/tx-signer","grants":[{"objects":["k"],"operations":["sign"],"environments":["production"]}]}]}`
	loaded, err := LoadPolicy(strings.NewReader(workloadPolicy))
	if err != nil {
		t.Fatalf("LoadPolicy(workload principal) = %v, want it to load", err)
	}
	if !loaded.Allowed(workload, "k", "sign", "production") {
		t.Fatalf("LoadPolicy(workload principal) granted %+v, want the sign grant", loaded.GrantedObjects())
	}
}

// TestMiddlewareExemptsBothHealthRoutesFromAuthentication pins the readiness half of the
// authentication bypass.
//
// The suite exercised only "/v1/health/live", so the sibling operand was untested even though the
// readiness route is the one wired up everywhere: hsm-host-role/defaults/main.yml sets
// kms_readiness_url to the /v1/health/ready endpoint, internal/audit/httpsink.go HEADs it, and
// internal/server/health.go serves it. With the readiness operand mutated away the observed results
// are: /v1/health/live -> status=200 body="READY-HANDLER-RAN" unauthorizedDelta=0, but
// /v1/health/ready -> status=401 body="" unauthorizedDelta=1. A kubelet probe carries no client
// certificate, so the pod is marked unready and taken out of service while every probe increments
// the unauthorized counter that exists to signal an attack.
//
// Isolation: the requests carry no TLS at all, so the exemption is the only thing that can produce a
// 200 here, and the unauthorized delta distinguishes "exempted" from "authenticated".
func TestMiddlewareExemptsBothHealthRoutesFromAuthentication(t *testing.T) {
	authenticator := NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute)
	var unauthorized int
	authenticator.OnUnauthorized(func() { unauthorized++ })
	handler := authenticator.Middleware(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("READY-HANDLER-RAN"))
	}))

	// A slice, not a map: map iteration order is randomised and two CI logs could not be diffed.
	for _, test := range []struct {
		name       string
		route      string
		wantStatus int
		wantBody   string
		wantDelta  int
	}{
		{"readiness probe", "/v1/health/ready", http.StatusOK, "READY-HANDLER-RAN", 0},
		{"liveness probe", "/v1/health/live", http.StatusOK, "READY-HANDLER-RAN", 0},
		// Anchors, not gates: without these a Middleware that exempted EVERY path would pass the two
		// rows above. The comparison is equality, so a route that merely starts with an exempt path
		// is still authenticated, and an operation route is still refused and still counted.
		//
		// BOTH prefix anchors are needed, one per operand. This test originally carried only the
		// readiness one, which left the liveness operand free to be widened from equality to a
		// prefix match without any test noticing — the two operands are siblings and an anchor on
		// one says nothing about the other. The asymmetry was in this table, not in the code:
		// auth.go compares with == for both routes.
		{"a route that only starts with the readiness path", "/v1/health/readyz", http.StatusUnauthorized, "", 1},
		{"a route that only starts with the liveness path", "/v1/health/livez", http.StatusUnauthorized, "", 1},
		{"an operation route", "/v1/operations/sign", http.StatusUnauthorized, "", 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := unauthorized
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, test.route, nil)
			if request.TLS != nil {
				t.Fatalf("fixture is not isolated: the probe carries TLS state %v", request.TLS)
			}
			handler.ServeHTTP(recorder, request)
			delta := unauthorized - before
			if recorder.Code != test.wantStatus || recorder.Body.String() != test.wantBody || delta != test.wantDelta {
				t.Fatalf("DEFECT: unauthenticated GET %s -> status=%d body=%q unauthorizedDelta=%d, want status=%d body=%q unauthorizedDelta=%d",
					test.route, recorder.Code, recorder.Body.String(), delta, test.wantStatus, test.wantBody, test.wantDelta)
			}
		})
	}
}

// TestCheckOnANilRevocationListIsANoOpNotAPanic pins the nil-receiver operand of Check.
//
// The revocation.go package comment states the contract this operand implements: "A nil
// *RevocationList, or a list whose path is empty, means 'revocation is not configured' — Check
// returns (false, nil) without touching the filesystem." Nothing tested it. The nearest test,
// TestRevocationNotConfiguredIsANoOp, passes nil to NewAuthenticator, where Authenticate's
// `if revocation := authenticator.revocation; revocation != nil` means Check is never entered at
// all — so the documented call has no coverage.
//
// Without the operand, `var r *RevocationList; r.Check("42")` panics with a nil pointer dereference
// at the sibling `r.path == ""` read on the very same line. This is an exported, documented entry
// point, and the crash is what a caller who follows the package comment gets.
//
// Isolation: the sibling operand `r.path == ""` is what the nil receiver would dereference, so a
// non-nil receiver cannot exercise this operand at all; the nil receiver is the whole fixture.
func TestCheckOnANilRevocationListIsANoOpNotAPanic(t *testing.T) {
	var list *RevocationList
	var revoked bool
	var err error
	if recovered := recoveredPanic(func() { revoked, err = list.Check("42") }); recovered != nil {
		t.Fatalf("DEFECT: (*RevocationList)(nil).Check(\"42\") panicked: %v — the package comment promises (false, nil) for a nil list", recovered)
	}
	if err != nil || revoked {
		t.Fatalf("(*RevocationList)(nil).Check(\"42\") = (%v, %v), want (false, <nil>)", revoked, err)
	}

	// Anchor, not a gate: a Check that returned (false, nil) for everything would pass the rows
	// above and never revoke anybody. A configured list must still answer both ways.
	configured := newRevocationList(t, "42")
	revoked, err = configured.Check("42")
	if err != nil || !revoked {
		t.Fatalf("configured list Check(\"42\") = (%v, %v), want (true, <nil>)", revoked, err)
	}
	revoked, err = configured.Check("43")
	if err != nil || revoked {
		t.Fatalf("configured list Check(\"43\") = (%v, %v), want (false, <nil>)", revoked, err)
	}
}

// TestLoadPolicyRefusesTrailingJSONDocuments pins the second-Decode check in LoadPolicy.
//
// json.Decoder is a STREAM: after the first document it will happily read another. The check is that
// the next Decode returns io.EOF, i.e. that there was nothing else in the file. Without it, the
// observed result for two concatenated documents is that LoadPolicy ACCEPTS, granted is
// [{Principal:spiffe://regalia/workload/a ObjectID:k1 Operation:sign}] and
// Allowed(b, k2, sign, production) is false — the second document is dropped in silence.
//
// The digest is what makes that worse than a dropped grant: it is computed over the whole file
// (sha256 of contents, not of the decoded document), so the accepted-policy digest and the sha256 of
// the two-document file are byte-identical. cmd/regalia-kms/preflight.go prints "RBAC policy loads,
// digest "+rbacPolicy.Digest(), and every audit record carries it, so the daemon would attest a file
// whose second half is not in force.
//
// Isolation: each document on its own is valid (schema_version 1, a canonical principal URI, a
// complete grant), so neither the schema check, the principal check nor compileGrant can refuse
// these inputs; the trailing-document check is the only refuser.
func TestLoadPolicyRefusesTrailingJSONDocuments(t *testing.T) {
	const documentA = `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/a","grants":[{"objects":["k1"],"operations":["sign"],"environments":["production"]}]}]}`
	const documentB = `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/b","grants":[{"objects":["k2"],"operations":["sign"],"environments":["production"]}]}]}`

	// Each half must load alone, or the refusals below would be about the halves rather than about
	// the concatenation.
	for _, half := range []string{documentA, documentB} {
		if _, err := LoadPolicy(strings.NewReader(half)); err != nil {
			t.Fatalf("fixture is not isolated: %s does not load on its own: %v", half, err)
		}
	}

	for _, test := range []struct {
		name  string
		input string
	}{
		{"two policy documents", documentA + "\n" + documentB + "\n"},
		{"a trailing bare value", documentA + "\nnull\n"},
		{"a trailing fragment", documentA + "\n}\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := LoadPolicy(strings.NewReader(test.input))
			if err == nil {
				t.Fatalf("DEFECT: LoadPolicy accepted a file holding more than one JSON document, granting %+v with digest %s — the digest covers the whole file while only the first document is in force",
					policy.GrantedObjects(), policy.Digest())
			}
			if err.Error() != "RBAC policy must contain exactly one JSON document" {
				t.Fatalf("LoadPolicy(%s) error = %q, want %q", test.name, err, "RBAC policy must contain exactly one JSON document")
			}
		})
	}

	// Anchor, not a gate: trailing whitespace after ONE document is not a second document, and a
	// LoadPolicy that refused every file would pass the rows above.
	t.Run("one document with trailing whitespace (anchor)", func(t *testing.T) {
		policy, err := LoadPolicy(strings.NewReader(documentA + "\n\n  \n"))
		if err != nil {
			t.Fatalf("LoadPolicy(one document + trailing whitespace) = %v, want it to load", err)
		}
		if !policy.Allowed("spiffe://regalia/workload/a", "k1", "sign", "production") {
			t.Fatalf("LoadPolicy(one document) granted %+v, want the sign grant", policy.GrantedObjects())
		}
	})
}

// TestLoadPolicyRefusesAnUnsupportedSchemaVersion pins the schema-version operand of LoadPolicy's
// support check.
//
// schema_version is the field an operator changes when the policy FORMAT changes, so a document
// declaring a version this code does not implement is one whose meaning this code does not know.
// With the operand mutated away it is interpreted under v1 rules anyway: the observed result for
// schema_version 99 is a non-nil *Policy with err <nil>, Ready() true,
// Allowed(spiffe://regalia/workload/probe, obj-a, unwrap, production) true and a digest the daemon
// prints at preflight — a policy written for some other version AUTHORIZES LIVE REQUESTS.
//
// Isolation: the sibling operand in the same `if` is `len(document.Principals) == 0`, and every row
// below carries a real principal with a real grant, so it cannot fire. The two operands share one
// message ("RBAC policy is empty or unsupported"), which is why the fixture — not the string — is
// what tells them apart; TestLoadPolicyRefusesAPolicyWithNoPrincipals is the mirror image.
func TestLoadPolicyRefusesAnUnsupportedSchemaVersion(t *testing.T) {
	document := func(version string) string {
		return `{"schema_version":` + version + `,"principals":[{"uri":"spiffe://regalia/workload/probe","grants":[{"objects":["obj-a"],"operations":["unwrap"],"environments":["production"]}]}]}`
	}

	for _, test := range []struct {
		name  string
		input string
	}{
		{"a later version", document("99")},
		{"the next version", document("2")},
		{"a negative version", document("-1")},
		// An absent schema_version decodes to 0, which is the same refusal: a file that never says
		// which format it is written in is not a v1 file.
		{"no version at all", `{"principals":[{"uri":"spiffe://regalia/workload/probe","grants":[{"objects":["obj-a"],"operations":["unwrap"],"environments":["production"]}]}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(test.input, `"uri":"spiffe://regalia/workload/probe"`) {
				t.Fatalf("fixture is not isolated: %s has no principal, so the sibling operand would refuse first", test.input)
			}
			policy, err := LoadPolicy(strings.NewReader(test.input))
			if err == nil {
				t.Fatalf("DEFECT: LoadPolicy accepted %s: Ready=%v Allowed(probe,obj-a,unwrap,production)=%v granted=%+v digest=%s — a policy declaring a schema this code does not implement is authorizing requests under v1 rules",
					test.name, policy.Ready(t.Context()),
					policy.Allowed("spiffe://regalia/workload/probe", "obj-a", "unwrap", "production"),
					policy.GrantedObjects(), policy.Digest())
			}
			if err.Error() != "RBAC policy is empty or unsupported" {
				t.Fatalf("LoadPolicy(%s) error = %q, want %q", test.name, err, "RBAC policy is empty or unsupported")
			}
			if policy != nil {
				t.Fatalf("refused LoadPolicy returned a non-nil policy granting %+v", policy.GrantedObjects())
			}
		})
	}

	// Anchor, not a gate: the identical document at schema_version 1 must load and must authorize,
	// or a LoadPolicy that refused every file would pass every row above.
	t.Run("schema_version 1 (anchor)", func(t *testing.T) {
		policy, err := LoadPolicy(strings.NewReader(document("1")))
		if err != nil {
			t.Fatalf("LoadPolicy(schema_version 1) = %v, want it to load", err)
		}
		if !policy.Ready(t.Context()) || !policy.Allowed("spiffe://regalia/workload/probe", "obj-a", "unwrap", "production") {
			t.Fatalf("LoadPolicy(schema_version 1): Ready=%v granted=%+v, want a ready policy granting the unwrap",
				policy.Ready(t.Context()), policy.GrantedObjects())
		}
	})
}

// TestLoadPolicyRefusesAPolicyWithNoPrincipals pins the empty-principals operand of the same check.
//
// This one does not widen authorization — with the operand mutated away the observed policy is
// non-nil but Ready() is false, GrantedObjects() is empty and every Allowed() denies, so the daemon
// still fails closed. The wrong answer is the ACCEPT/REFUSE DECISION itself: cmd/regalia-kms's
// preflight reports "RBAC policy loads, digest sha256:0e35540d236ef…" for a file that authorizes
// nobody, and the operator reads that as a working policy. An empty principals list is almost always
// a truncated or half-written file, and the moment to say so is at load.
//
// Isolation: schema_version is 1 in every row, so the sibling operand cannot fire — confirmed in the
// sweep's own run, where a schema_version 99 document was still refused under this mutation. The
// shared message is asserted anyway, because message-plus-nil-policy is what distinguishes "refused
// here" from "refused by the JSON decoder".
func TestLoadPolicyRefusesAPolicyWithNoPrincipals(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
	}{
		{"an empty principals list", `{"schema_version":1,"principals":[]}`},
		{"a null principals list", `{"schema_version":1,"principals":null}`},
		{"no principals key at all", `{"schema_version":1}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if !strings.Contains(test.input, `"schema_version":1`) {
				t.Fatalf("fixture is not isolated: %s does not declare schema_version 1, so the sibling operand would refuse first", test.input)
			}
			policy, err := LoadPolicy(strings.NewReader(test.input))
			if err == nil {
				t.Fatalf("DEFECT: LoadPolicy accepted %s: Ready=%v granted=%+v digest=%s — preflight would report this file as a policy that loads",
					test.name, policy.Ready(t.Context()), policy.GrantedObjects(), policy.Digest())
			}
			if err.Error() != "RBAC policy is empty or unsupported" {
				t.Fatalf("LoadPolicy(%s) error = %q, want %q", test.name, err, "RBAC policy is empty or unsupported")
			}
			if policy != nil {
				t.Fatalf("refused LoadPolicy returned a non-nil policy: Ready=%v granted=%+v", policy.Ready(t.Context()), policy.GrantedObjects())
			}
		})
	}

	// Anchor, not a gate: one principal is enough, and a LoadPolicy that refused every file would
	// pass every row above.
	t.Run("one principal (anchor)", func(t *testing.T) {
		policy, err := LoadPolicy(strings.NewReader(validPolicy))
		if err != nil {
			t.Fatalf("LoadPolicy(the shipped-shape policy) = %v, want it to load", err)
		}
		if !policy.Ready(t.Context()) {
			t.Fatalf("LoadPolicy(one principal): Ready=false, granted=%+v", policy.GrantedObjects())
		}
	})
}
