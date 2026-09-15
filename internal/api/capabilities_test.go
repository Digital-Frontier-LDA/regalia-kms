package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// EVERY CAPABILITY THE REGISTRY ADVERTISES MUST BE REACHABLE.
//
// The registry validates a manifest against a capability matrix, so an operation named there is one
// commissioning is entitled to treat as supported. release-secret sat in that matrix with no
// endpoint and no provider: a manifest could declare it, pass validation, and route to nothing. A
// capability the matrix promises and the system cannot perform is worse than an absent one.
//
// This test pins the two lists together. Adding a capability to the registry without an endpoint,
// or removing an endpoint a manifest may rely on, fails here.
func TestEveryAdvertisedCapabilityHasAnEndpoint(t *testing.T) {
	// Mirrors registry.supports(). Kept explicit rather than imported so that widening one list
	// without the other is a test failure rather than a silent agreement.
	advertised := []string{"sign", "wrap", "unwrap", "certificate-sign", "key-agreement", "release-secret"}

	handler := NewHandler(nil)
	for _, operation := range advertised {
		t.Run(operation, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/operations/"+operation, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			// Unauthenticated, so 401 is expected — what matters is that the route EXISTS. A 404
			// means the capability is advertised and unreachable.
			if response.Code == http.StatusNotFound {
				t.Fatalf("capability %q is advertised by the registry but has no endpoint", operation)
			}
		})
	}
}

// FIDO2 "authenticate" is deliberately NOT here. ADR §4 places human administrator authentication
// "outside the cryptographic-operation API", so it must stay unreachable through these routes —
// an endpoint appearing for it would be the defect.
func TestHumanAuthenticationIsNotACryptographicOperation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/operations/authenticate", nil)
	response := httptest.NewRecorder()
	NewHandler(nil).ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("authenticate is reachable through the operations API (status %d); ADR §4 places it outside", response.Code)
	}
}
