package api

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// A RELEASED SECRET IS ZEROED ONCE THE RESPONSE HAS BEEN WRITTEN (#6 criterion 3).
//
// ServeHTTP ends with `defer zero(result.Data)`, and removing it left the whole module green (the #6
// acceptance audit, measured on b1219f1). The coordinator double here hands the handler a slice this
// test keeps, so the test can read that memory after ServeHTTP returns.
//
// The base64 string written into the JSON response is a Go string and cannot be zeroed. ENVELOPE.md
// already disclaims that class of copy, so it is not asserted here.
//
// Falsifier: delete `defer zero(result.Data)`. This test is the only failure in the package.
func TestAReleasedSecretIsZeroedOnceTheResponseIsWritten(t *testing.T) {
	const secret = "released-secret-value"
	released := []byte(secret)
	coordinator := &fakeCoordinator{result: Result{OperationID: "018f0000-0000-7000-8000-000000000002", ContentType: "application/vnd.regalia.secret", Data: released}}
	body := `{"object_id":"deployment-api-token","context":{"environment":"production","purpose":"deployment-api","expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"format":"regalia-envelope-v2","payload_base64":"eyJ2ZXJzaW9uIjoxfQ=="}`
	recorder := authenticated(t, NewHandler(coordinator), http.MethodPost, "/v1/operations/release-secret", body)
	if recorder.Code != http.StatusOK || coordinator.calls != 1 {
		t.Fatalf("control failed: the release was not served: %d calls=%d %s", recorder.Code, coordinator.calls, recorder.Body.String())
	}
	// Control: the response carries the secret, so the zeroing happened after the write, not before.
	if !strings.Contains(recorder.Body.String(), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("control failed: the response does not carry the released value: %s", recorder.Body.String())
	}
	if !bytes.Equal(released, make([]byte, len(released))) {
		t.Fatalf("the released secret is still in the handler's memory after the response: %q", released)
	}
}
