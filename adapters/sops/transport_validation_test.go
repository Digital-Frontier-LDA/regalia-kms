package sopsadapter

import (
	"strings"
	"testing"
)

// validTransportRequest is the last check before bytes leave this process for the KMS. Two of its
// rules are security properties rather than hygiene:
//
//   The operation must match the ENDPOINT. Sending a request labelled "wrap" to
//   /v1/operations/unwrap would ask the KMS to unwrap what the caller meant to protect, and the
//   KMS authorises the endpoint it was called on.
//
//   The path must not escape its repository. Repository and path are recorded as the request's
//   provenance, and a path of "../../other/secrets.yaml" attributes one repository's decryption to
//   another in the audit trail.

func validRequest() Request {
	return Request{
		Operation: "wrap", ObjectID: "production-sops", Repository: "Org/infra",
		Path: "secrets/prod.sops.yaml", Environment: "production", Purpose: "sops-data-key",
		RequestID: "018f0000-0000-7000-8000-000000000001", IdempotencyKey: "018f0000000070008000000000000001",
		Data: []byte("payload"),
	}
}

const wrapEndpoint = "/v1/operations/wrap"

func TestTheValidRequestIsAccepted(t *testing.T) {
	if !validTransportRequest(validRequest(), wrapEndpoint) {
		t.Fatal("the baseline request is refused, so every refusal below would be refusing something already broken")
	}
	if len(validRequest().RequestID) != 36 {
		t.Fatalf("the fixture's request id is %d characters, not the 36 the rule wants", len(validRequest().RequestID))
	}
}

// TestTheOperationMustMatchTheEndpointItIsSentTo. The endpoint is what the KMS authorises against,
// so a mismatch is not a labelling error — it is asking for a different operation than the one
// whose authorisation was checked.
func TestTheOperationMustMatchTheEndpointItIsSentTo(t *testing.T) {
	for _, test := range []struct {
		operation string
		endpoint  string
		accepted  bool
	}{
		{"wrap", "/v1/operations/wrap", true},
		{"unwrap", "/v1/operations/unwrap", true},
		{"unwrap", "/v1/operations/wrap", false},
		{"wrap", "/v1/operations/unwrap", false},
		{"", "/v1/operations/wrap", false},
		{"", "/v1/operations/unwrap", false},
		// An endpoint this function does not name leaves the operation/endpoint PAIRING
		// unconstrained — and only that. Every other rule still applies: the operation must be
		// non-empty, and the identifying fields, the environment and the payload are all still
		// checked. Deliberate, because the pairing rules are named pairs rather than a general
		// allowlist, and pinned so the behaviour is a decision rather than a discovery.
		{"wrap", "/v1/operations/sign", true},
	} {
		operation := test.operation
		if operation == "" {
			operation = "no operation"
		}
		name := operation + " to " + test.endpoint
		// The endpoint contains slashes, and a slash in a t.Run name opens a nested subtest — which
		// makes -run filtering awkward and the output read as a tree that is not there. The
		// readable form goes in the failure message, where it costs nothing. The empty operation
		// gets a word for the same reason: "_to__v1_operations_wrap" names nothing.
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			request := validRequest()
			request.Operation = test.operation
			if got := validTransportRequest(request, test.endpoint); got != test.accepted {
				t.Fatalf("validTransportRequest(%s) = %v, want %v", name, got, test.accepted)
			}
		})
	}
}

// TestThePathMayNotLeaveItsRepository. Repository and path together are the provenance recorded for
// the operation, so a path that climbs out of the tree attributes one repository's decryption to
// another.
func TestThePathMayNotLeaveItsRepository(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
	}{
		{"a parent traversal", "../other/secrets.yaml"},
		{"a traversal in the middle", "secrets/../../other/secrets.yaml"},
		{"an absolute path", "/etc/secrets.yaml"},
		{"a bare parent", ".."},
		{"the current directory", "."},
		{"a backslash separator", `secrets\prod.sops.yaml`},
		{"an unclean path", "secrets//prod.sops.yaml"},
		{"a dot segment in the middle", "secrets/./prod.sops.yaml"},
		{"nothing at all", ""},
		{"longer than 256 bytes", strings.Repeat("a", 257)},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			request.Path = test.path
			if validTransportRequest(request, wrapEndpoint) {
				t.Fatalf("%s was accepted as a path: the repository recorded against this operation is not the one it touched", test.name)
			}
		})
	}
}

func TestTheIdentifyingFieldsMustMatchTheirShapes(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*Request)
	}{
		{"an object id with an uppercase letter", func(r *Request) { r.ObjectID = "Production-Sops" }},
		{"an object id that is too short", func(r *Request) { r.ObjectID = "ab" }},
		{"an object id starting with a hyphen", func(r *Request) { r.ObjectID = "-production" }},
		{"an empty object id", func(r *Request) { r.ObjectID = "" }},
		{"a repository with no owner", func(r *Request) { r.Repository = "infra" }},
		{"a repository with two slashes", func(r *Request) { r.Repository = "Org/group/infra" }},
		{"an empty repository", func(r *Request) { r.Repository = "" }},
		{"a purpose off the pattern", func(r *Request) { r.Purpose = "SOPS Data Key" }},
		{"an environment off the enum", func(r *Request) { r.Environment = "prod" }},
		{"no environment", func(r *Request) { r.Environment = "" }},
		{"a request id of the wrong length", func(r *Request) { r.RequestID = "too-short" }},
		{"no request id", func(r *Request) { r.RequestID = "" }},
		// strings.Repeat rather than a literal: a 15-character hex-looking string assigned to a
		// field named IdempotencyKey is what gitleaks' generic-api-key rule is for, and it fired on
		// it. The rule is right about the shape and wrong about this instance, and the fix is the
		// fixture -- .gitleaks.toml allowlists describe CONTENT, never paths, because a path entry
		// suppresses every finding in the file including the next real one. This also says "15"
		// instead of making the reader count.
		{"an idempotency key below 16", func(r *Request) { r.IdempotencyKey = strings.Repeat("a", 15) }},
		{"an idempotency key over 128", func(r *Request) { r.IdempotencyKey = strings.Repeat("a", 129) }},
		{"no payload", func(r *Request) { r.Data = nil }},
		{"an empty payload", func(r *Request) { r.Data = []byte{} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			test.apply(&request)
			if validTransportRequest(request, wrapEndpoint) {
				t.Fatalf("%s was accepted", test.name)
			}
		})
	}
}

// TestTheLengthBoundsAreInclusiveWhereTheyShouldBe, so the refusals above are shown to be about the
// bound rather than about the field being finicky.
func TestTheLengthBoundsAreInclusiveWhereTheyShouldBe(t *testing.T) {
	for _, test := range []struct {
		name  string
		apply func(*Request)
	}{
		{"an idempotency key of exactly 16", func(r *Request) { r.IdempotencyKey = strings.Repeat("a", 16) }},
		{"an idempotency key of exactly 128", func(r *Request) { r.IdempotencyKey = strings.Repeat("a", 128) }},
		{"a path of exactly 256 bytes", func(r *Request) { r.Path = strings.Repeat("a", 256) }},
		{"the shortest allowed object id", func(r *Request) { r.ObjectID = "abc" }},
		{"a single byte of payload", func(r *Request) { r.Data = []byte{0} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest()
			test.apply(&request)
			if !validTransportRequest(request, wrapEndpoint) {
				t.Fatalf("%s was refused: the bound is narrower than the rule says", test.name)
			}
		})
	}
}
