package operations

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

const (
	httpWrappedKey = "inert wrapped key"
	httpDataKey    = "01234567" + "89abcdef" + "01234567" + "89abcdef"
)

var httpEnvelopeOperations = []httpOperation{
	{"release-secret", "opaque", DataKeyContentType},
	{"seal-envelope", "opaque", DataKeyContentType},
}

func httpFixtureManifest(op httpOperation) string {
	kind, custody := "asymmetric-key", "direct-hardware"
	ageBound := ""
	bindings := fmt.Sprintf(`{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"fixture-hsm","object_id":"01","device_serial":"test-serial",
		"public_fingerprint":%q,"devaut_fingerprint":%q,"state":"active"}`,
		"sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
	if op.algorithm == "opaque" {
		kind, custody = "opaque-secret", "hardware-envelope"
		bindings = strings.TrimSuffix(bindings, "}") + `,"kek_algorithm":"rsa2048","kek_version":"v2"}`
		if op.name == "release-secret" {
			ageBound = `,"envelope_max_age_days":1`
			// The envelope selects a retired generation that is different from the active binding.
			bindings += fmt.Sprintf(`,{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"fixture-retired-hsm","object_id":"02",
				"public_fingerprint":%q,"state":"retired","kek_algorithm":"rsa2048","kek_version":"v1"}`,
				"sha256:"+strings.Repeat("c", 64))
		}
	}
	return fmt.Sprintf(`{"schema_version":1,"manifest_id":"http-fixture","generated_at":"2026-11-21T00:00:00Z","objects":[{
		"id":"http-object","name":"Fixture key","kind":%q,"classification":"critical","environment":"staging",
		"owner":"security","purpose":"http-test","custody":%q,"algorithm":%q,"operations":[%q],"policy_id":"http-policy",
		"bindings":[%s],
		"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},
		"rotation":{"maximum_age_days":365,"last_rotated":null%s},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}]}`,
		kind, custody, op.algorithm, op.name, bindings, ageBound)
}

func httpFixtureReleaseContext() []byte {
	return envelope.ReleaseContext("http-object", "http-test", "staging")
}

type httpEnvelopeWrapper struct{}

func (httpEnvelopeWrapper) Backend() string { return "nitrokey-pkcs11" }

func (httpEnvelopeWrapper) WrapKey(_ context.Context, _ envelope.KeyRef, dataKey, _ []byte) ([]byte, error) {
	if string(dataKey) != httpDataKey {
		return nil, fmt.Errorf("fixture wrapping key input differed")
	}
	return []byte(httpWrappedKey), nil
}

func (httpEnvelopeWrapper) UnwrapKey(_ context.Context, _ envelope.KeyRef, wrapped, _ []byte) ([]byte, error) {
	if string(wrapped) != httpWrappedKey {
		return nil, fmt.Errorf("fixture wrapped key marker differed")
	}
	return []byte(httpDataKey), nil
}

func httpEnvelopePayload(t *testing.T, op httpOperation, now time.Time) map[string]string {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString
	if op.name == "release-secret" {
		fixture, err := envelope.Seal(context.Background(), httpEnvelopeWrapper{},
			envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "http-object", Version: "v1"},
			"http-object", httpFixtureReleaseContext(), []byte(httpFixtureResult),
			bytes.NewReader(append([]byte(httpDataKey), []byte("fixture-nonc")...)), now.Add(-time.Minute))
		if err != nil {
			t.Fatalf("prepare the release envelope: %v", err)
		}
		encoded, err := fixture.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return map[string]string{"format": "regalia-envelope-v2", "payload_base64": b64(encoded)}
	}
	ciphertext, nonce, dataKey := assembleSealInputs(t, registry.Route{
		ObjectID: "http-object", Purpose: "http-test", Environment: "staging",
	}, []byte(httpFixtureResult))
	return map[string]string{"format": "regalia-envelope-v2", "ciphertext_base64": b64(ciphertext),
		"nonce_base64": b64(nonce), "data_key_base64": b64(dataKey)}
}

func (f *httpServingFixture) expectSuccess(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if f.op.algorithm != "opaque" {
		expectHTTPSuccess(t, response)
		return
	}
	var result struct {
		OperationID string `json:"operation_id"`
		ObjectID    string `json:"object_id"`
		ContentType string `json:"content_type"`
		Data        []byte `json:"result_base64"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != http.StatusOK ||
		result.OperationID == "" || result.ObjectID != "http-object" {
		t.Fatalf("%s same-route positive control: HTTP %d, %s (decode %v)", f.op.name, response.Code, response.Body, err)
	}
	if f.op.name == "release-secret" {
		if result.ContentType != "application/vnd.regalia.secret" || string(result.Data) != httpFixtureResult {
			t.Fatalf("release response content type=%q or plaintext != expected fixture marker", result.ContentType)
		}
		return
	}
	sealed, err := envelope.Parse(result.Data)
	if err != nil || result.ContentType != "application/vnd.regalia.envelope" {
		t.Fatalf("seal response content type=%q, parse=%v", result.ContentType, err)
	}
	expected := envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "http-object", Version: "v2"}
	if sealed.KEK != expected || string(sealed.WrappedDataKey) != httpWrappedKey {
		t.Fatalf("seal returned the wrong KEK or wrapping marker: KEK=%v", sealed.KEK)
	}
	var opened string
	err = sealed.Open(context.Background(), httpEnvelopeWrapper{}, httpFixtureReleaseContext(), func(plaintext []byte) error {
		opened = string(plaintext)
		return nil
	})
	if err != nil || opened != httpFixtureResult {
		t.Fatalf("seal response does not open under the fixture key and route context: %v", err)
	}
}
