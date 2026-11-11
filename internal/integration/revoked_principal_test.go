package integration_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
)

// A REVOKED CLIENT CERTIFICATE NEVER REACHES THE TOKEN (threat model T01, epic #40 AC1).
//
// The unit tests show each link on its own: Authenticate refuses a revoked serial
// (internal/auth), the middleware answers 401 without calling the handler, and the handler never
// dispatches an unauthenticated request (internal/api). Nothing showed the chain: a request whose
// principal is GRANTED the operation, carrying a certificate whose serial is revoked, sent through
// the real middleware, handler, coordinator, policy, audit and backend manager, with the token's
// calls counted at the backend boundary.
//
// The principal is granted, so the only thing standing between it and the card is revocation:
// RBAC, policy and the CSR namespace all allow this request, as the control row shows.
func TestARevokedClientCertificateNeverReachesTheToken(t *testing.T) {
	csr := csrFor(t, "api.staging.internal")
	// call() presents serial 1 for every principal.
	for _, c := range []struct {
		name       string
		revoked    string
		wantStatus int
		wantCalls  bool
	}{
		// CONTROL, first: the same principal, certificate and request, with a list that does not
		// name serial 1, is served, and the card is used. Without it the refusal below would be
		// equally consistent with a stack that refuses everything.
		{"control: serial 1 not revoked", "99\n", http.StatusOK, true},
		{"serial 1 revoked", "99\n1\n", http.StatusUnauthorized, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "revoked-serials")
			if err := os.WriteFile(path, []byte(c.revoked), 0o600); err != nil {
				t.Fatal(err)
			}
			list, err := auth.NewRevocationList(path)
			if err != nil {
				t.Fatal(err)
			}
			s := buildStackWithRevocation(t, list)
			before := s.card.calls.Load()

			response := s.call(t, "/v1/operations/certificate-sign", "spiffe://regalia/workload/e2e",
				"e2e-ca", "e2e-pki", "7777777777777777", csr)

			used := s.card.calls.Load() - before
			if !c.wantCalls && used != 0 {
				t.Fatalf("DEFECT: a revoked client certificate reached the token %d time(s)", used)
			}
			if response.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", response.Code, c.wantStatus, response.Body.String())
			}
			if c.wantCalls && used == 0 {
				t.Fatal("the control request was served without the token: the counter does not see the token boundary, so a zero below would prove nothing")
			}
			if !c.wantCalls && response.Body.Len() != 0 {
				t.Fatalf("a revoked request got a body: %q", response.Body.String())
			}
		})
	}
}
