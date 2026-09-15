package api

import (
	"net/http"
	"testing"
)

// A RELEASE CANNOT BE BOUND TO A CONTEXT THE CALLER CHOSE.
//
// ENVELOPE.md requires the binding context to "be independently reconstructed by the KMS" and to
// "not be accepted as an unverified opaque client assertion". It was accepted as one: this handler
// decoded envelope_aad_base64 and the coordinator handed it to the hardware unchanged, so the
// context digest proved only that whoever held the envelope knew the string it was sealed with --
// never that the release matched the authorization that had just been granted.
//
// The context is now derived from the authorized route, exactly as the certificate profile is
// derived from the issuing configuration: there is nothing here for the client to select.
func TestReleaseSecretRefusesACallerSuppliedEnvelopeContext(t *testing.T) {
	const envelope = `eyJ2ZXJzaW9uIjoxfQ==`
	body := func(extra string) string {
		return `{"object_id":"deployment-api-token","context":{"environment":"production","purpose":"deployment-api","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"format":"regalia-envelope-v2","payload_base64":"` + envelope + `"` + extra + `}`
	}

	// Control: without the field the request reaches the coordinator. Without this, the assertion
	// below could hold for any reason at all.
	accepted := &fakeCoordinator{result: Result{OperationID: "018f0000-0000-7000-8000-000000000002", ContentType: "application/vnd.regalia.secret", Data: []byte("secret")}}
	if recorder := authenticated(t, NewHandler(accepted), http.MethodPost, "/v1/operations/release-secret", body("")); recorder.Code != http.StatusOK || accepted.calls != 1 {
		t.Fatalf("a well-formed release-secret request was not dispatched: %d calls=%d %s", recorder.Code, accepted.calls, recorder.Body.String())
	}

	refused := &fakeCoordinator{}
	recorder := authenticated(t, NewHandler(refused), http.MethodPost, "/v1/operations/release-secret", body(`,"envelope_aad_base64":"e30="`))
	if recorder.Code != http.StatusBadRequest || refused.calls != 0 {
		t.Fatalf("a caller-supplied binding context was accepted: response = %d calls=%d. The caller would then choose what the envelope is bound to, which is the whole of the protection.",
			recorder.Code, refused.calls)
	}
}
