package api

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// These pin the compatibility rules API.md states, so a change that would break a deployed client
// fails here rather than in production. Each one is a promise a client is entitled to build on.

// post sends an AUTHENTICATED request. Authentication happens before the body is parsed, so an
// unauthenticated request would stop at 401 and never exercise the parsing rules these tests are
// about — the test would pass without testing anything.
func post(t *testing.T, handler http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	identity, _ := url.Parse("spiffe://regalia/workload/compat")
	request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
	}}}}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "018f0000-0000-7000-8000-000000000001")
	request.Header.Set("Idempotency-Key", "018f0000000070008000000000000001")
	for key, value := range headers {
		if value == "" {
			request.Header.Del(key)
			continue
		}
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(handler).ServeHTTP(response, request)
	return response
}

// THE VERSION IS IN THE PATH, and only v1 exists. An unversioned or future path must not be served
// by the v1 handler: a client reaching /v2 must get 404, not v1 semantics under a v2 name.
func TestOnlyTheVersionedPathIsServed(t *testing.T) {
	handler := NewHandler(nil)
	for _, path := range []string{
		"/operations/sign", "/v2/operations/sign", "/v1/operations/", "/v1/sign",
		"/V1/operations/sign", "/v1/operations/sign/", "/v11/operations/sign",
	} {
		response := post(t, handler, path, `{}`, nil)
		if response.Code != http.StatusNotFound {
			t.Fatalf("%s returned %d; only /v1/operations/<name> is served", path, response.Code)
		}
	}
}

// REQUEST DOCUMENTS ARE CLOSED. An unknown field is an error, not something ignored: a typo in a
// security-relevant field must not become a silently dropped instruction.
func TestUnknownRequestFieldsAreRejectedNotIgnored(t *testing.T) {
	// ANCHORED ON A BODY THAT SUCCEEDS. The unknown field must be the ONLY difference, or the test
	// passes because the request was invalid for some other reason — which is exactly what an
	// earlier version of this test did: its baseline was already 400, so removing
	// DisallowUnknownFields from the handler did not fail it.
	const valid = `{"object_id":"production-sops","context":{"environment":"production",` +
		`"purpose":"sops-data-key","expires_at":"2099-01-01T00:00:00Z",` +
		`"nonce":"018f0000000070008000000000000001","subject":"sha256:context"},` +
		`"format":"regalia-envelope-v2","wrapped_data_key_base64":"d3JhcHBlZA==","envelope_aad_base64":"e30="}`

	baseline := post(t, NewHandler(&fakeCoordinator{result: Result{
		OperationID: "018f0000-0000-7000-8000-000000000002",
		ContentType: "application/octet-stream", Data: []byte("data-key"),
	}}), "/v1/operations/unwrap", valid, nil)
	if baseline.Code != http.StatusOK {
		t.Fatalf("baseline body is not accepted (%d): %s — the test below would prove nothing",
			baseline.Code, baseline.Body.String())
	}

	withUnknown := strings.Replace(valid, `"format":`, `"allow_export":true,"format":`, 1)
	response := post(t, NewHandler(&fakeCoordinator{}), "/v1/operations/unwrap", withUnknown, nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown request field: %s", response.Code, response.Body.String())
	}
}

func TestErrorDocumentShapeIsStable(t *testing.T) {
	// An AUTHENTICATED request with a malformed body, so the error comes from the handler — which
	// is what writes the documented error document. The middleware's 401 is a transport-level
	// refusal with no body, and asserting the shape on that would prove nothing about the contract.
	response := post(t, NewHandler(nil), "/v1/operations/sign", `{"object_id":`, nil)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("error body is not JSON: %q", response.Body.String())
	}
	for _, field := range []string{"request_id", "code", "message", "retryable"} {
		if _, present := document[field]; !present {
			t.Fatalf("error document is missing %q: %s", field, response.Body.String())
		}
	}
	if _, ok := document["retryable"].(bool); !ok {
		t.Fatalf("retryable is not a boolean: %s", response.Body.String())
	}
	if document["code"] != "INVALID_ARGUMENT" {
		t.Fatalf("code = %v, want INVALID_ARGUMENT", document["code"])
	}
	// Nothing beyond the documented shape: an error must not become a side channel by accretion.
	if len(document) != 4 {
		t.Fatalf("error document has %d fields, want exactly the 4 documented: %s", len(document), response.Body.String())
	}
}

// AN ERROR IS NOT A CHANNEL. The message is fixed per code and must not echo the request.
func TestErrorMessagesDoNotEchoTheRequest(t *testing.T) {
	handler := NewHandler(nil)
	secret := "s3cr3t-canary-value"
	body := `{"object_id":"` + secret + `","context":{"environment":"production","purpose":"` + secret + `",
	  "expires_at":"2030-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"payload_base64":"` + secret + `"}`
	response := post(t, handler, "/v1/operations/sign", body, nil)
	if strings.Contains(response.Body.String(), secret) {
		t.Fatalf("the error echoed request content: %s", response.Body.String())
	}
}

// THE IDEMPOTENCY KEY MUST EQUAL THE NONCE. Otherwise a client could retry under a fresh key and
// have a replayed request treated as new, which is the whole point of the durable nonce.
func TestIdempotencyKeyMustMatchTheNonce(t *testing.T) {
	handler := NewHandler(nil)
	body := `{"object_id":"k","context":{"environment":"production","purpose":"p",
	  "expires_at":"2030-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},
	  "content_type":"application/vnd.regalia.digest","payload_base64":"AAAA"}`
	response := post(t, handler, "/v1/operations/sign", body, map[string]string{"Idempotency-Key": "018f0000000070008000000000000002"})
	if response.Code == http.StatusOK {
		t.Fatal("a request whose idempotency key differs from its nonce was accepted")
	}
}

// REQUIRED HEADERS ARE REQUIRED, and their absence is a refusal rather than a default.
func TestMissingRequiredHeadersAreRefused(t *testing.T) {
	handler := NewHandler(nil)
	body := `{"object_id":"k","context":{"environment":"production","purpose":"p",
	  "expires_at":"2030-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},"payload_base64":"AAAA"}`
	for _, header := range []string{"X-Request-ID", "Idempotency-Key", "Content-Type"} {
		t.Run("missing "+header, func(t *testing.T) {
			response := post(t, handler, "/v1/operations/sign", body, map[string]string{header: ""})
			if response.Code == http.StatusOK {
				t.Fatalf("a request without %s was accepted", header)
			}
		})
	}
}

// ONLY POST IS SERVED, and the refusal advertises what is allowed.
func TestOperationsRejectNonPostAndAdvertiseAllow(t *testing.T) {
	handler := NewHandler(nil)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		request := httptest.NewRequest(method, "/v1/operations/sign", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s returned %d, want 405", method, response.Code)
		}
		if response.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("%s did not advertise Allow: POST", method)
		}
	}
}

// EACH OPERATION ACCEPTS EXACTLY ONE PAYLOAD FIELD. A sign request carrying a wrapped data key is
// an error, not a request with an ignored field — otherwise a client could believe it sent
// something the server never read.
func TestOperationsRejectPayloadFieldsBelongingToOtherOperations(t *testing.T) {
	cases := map[string]string{
		"sign with a wrapped data key":   `"wrapped_data_key_base64":"AAAA"`,
		"sign with a plaintext data key": `"plaintext_data_key_base64":"AAAA"`,
		"sign with an envelope format":   `"format":"regalia-envelope-v2"`,
	}
	handler := NewHandler(nil)
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			body := `{"object_id":"k","context":{"environment":"production","purpose":"p",
			  "expires_at":"2030-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},
			  "content_type":"application/vnd.regalia.digest","payload_base64":"AAAA",` + extra + `}`
			response := post(t, handler, "/v1/operations/sign", body, nil)
			if response.Code == http.StatusOK {
				t.Fatalf("sign accepted a field belonging to another operation (%s)", name)
			}
		})
	}
}

// THE OPENAPI SPEC AND THE HANDLER MUST NAME THE SAME SET for the format field. #213 was a drift:
// handler.validateRequest was tightened from "regalia-envelope-v1" to "regalia-envelope-v2"
// (handler.go:246, 251, 280, 289) and five const/enum values in api/openapi.json were missed.
// The OpenAPI doc is the contract a deployed client builds against: if it lists v1 and the
// handler accepts v2, every caller that follows the spec gets a clean 400 from a server whose
// validator is correct, and the API surface silently disagrees with its own contract.
//
// Two layers of falsification matter here:
//
//  1. The format values themselves: a schema lists v1 where the handler accepts v2. Falsified by
//     reverting one occurrence: the corresponding case names the wrong site.
//
//  2. The path's $ref: a path points at the wrong schema entirely. The pre-#213 release-secret
//     path had requestBody → UnwrapRequest (which requires wrapped_data_key_base64) while
//     handler.validateRequest:280 forbids it and API.md:31 says the operation takes
//     payload_base64. A by-name guard that iterates schemas would have happily validated
//     ReleaseSecretRequest while the path kept pointing at UnwrapRequest: the orphan check
//     passed and the contract a code generator actually reads stayed wrong. Falsified by
//     re-pointing one path at the wrong schema: the case names the wrong site, and the
//     resolved schema's format set disagrees with what the handler accepts.
//
// The assertion walks paths → requestBody → $ref → schema.properties.format. The handler's
// acceptance is mirrored from validateRequest in handler.go; both sides are sorted on
// comparison so the test does not care whether the spec uses const or enum.
func TestOpenAPISpecFormatFieldMatchesHandlerAcceptance(t *testing.T) {
	specPath := filepath.Join("..", "..", "api", "openapi.json")
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var spec struct {
		Paths map[string]struct {
			Post struct {
				RequestBody struct {
					Content struct {
						ApplicationJSON struct {
							Schema struct {
								Ref string `json:"$ref"`
							} `json:"schema"`
						} `json:"application/json"`
					} `json:"content"`
				} `json:"requestBody"`
			} `json:"post"`
		} `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Properties map[string]struct {
					Const string   `json:"const"`
					Enum  []string `json:"enum"`
				} `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	cases := []struct {
		path   string
		schema string
		want   []string
	}{
		{"/v1/operations/wrap", "WrapRequest", []string{"regalia-envelope-v2"}},
		{"/v1/operations/unwrap", "UnwrapRequest", []string{"regalia-envelope-v2", "sops-pgp"}},
		{"/v1/operations/seal-envelope", "SealEnvelopeRequest", []string{"regalia-envelope-v2"}},
		{"/v1/operations/release-secret", "ReleaseSecretRequest", []string{"regalia-envelope-v2"}},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			path, ok := spec.Paths[c.path]
			if !ok {
				t.Fatalf("path %q missing from openapi.json", c.path)
			}
			ref := path.Post.RequestBody.Content.ApplicationJSON.Schema.Ref
			if ref == "" {
				t.Fatalf("%s.requestBody.content.application/json.schema.$ref is empty", c.path)
			}
			const prefix = "#/components/schemas/"
			if !strings.HasPrefix(ref, prefix) {
				t.Fatalf("%s.requestBody $ref = %q, want %s<SchemaName>", c.path, ref, prefix)
			}
			resolved := strings.TrimPrefix(ref, prefix)
			if resolved != c.schema {
				t.Fatalf("%s.requestBody $ref = %q, resolves to schema %q, want %q — a code generator reading the spec builds a client against %s, not %s",
					c.path, ref, resolved, c.schema, resolved, c.schema)
			}
			schema, ok := spec.Components.Schemas[resolved]
			if !ok {
				t.Fatalf("%s.requestBody resolves to schema %q, but that schema is not in components.schemas", c.path, resolved)
			}
			formatField, present := schema.Properties["format"]
			if !present {
				t.Fatalf("%s.properties.format is missing — handler.validateRequest requires Format=\"regalia-envelope-v2\" for %s, so the spec must declare the field",
					c.schema, c.path)
			}
			var got []string
			if formatField.Const != "" {
				got = []string{formatField.Const}
			} else {
				got = formatField.Enum
			}
			sort.Strings(got)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s.properties.format = %v, want %v (handler.validateRequest accepts exactly this set)",
					c.schema, got, want)
			}
		})
	}
}
