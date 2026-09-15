package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THE WIRE CONTRACT'S REFUSALS, EACH PROVEN TO BE LOAD-BEARING.
//
// Every guard exercised below was shown by a mutation sweep to be undetected: replaced with
// `if false && (<original>)` the whole module -- api, integration, operations, registry, server,
// telemetry and cmd/regalia-kms -- stayed green. They are the four refusals that stand between a
// caller and a signature: the required-header triple and the coordinator-failure normalisation in
// ServeHTTP, the trailing-document check in decodeRequest, and sign's content_type requirement in
// validateRequest.
//
// Two habits are load-bearing here and are followed in every test in this file.
//
// FIRST, EVERY TABLE ANCHORS ON A REQUEST THAT IS ACCEPTED AS WRITTEN. Without an accepted row a
// guard that refused EVERYTHING would pass the whole table, and a fixture that was already invalid
// for an unrelated reason would look like a refusal by the rule under test. That is not
// hypothetical in this package: compatibility_test.go's TestUnknownRequestFieldsAreRejectedNotIgnored
// carries the same warning because an earlier version of it had a 400 baseline and did not fail
// when DisallowUnknownFields was removed. TestMissingRequiredHeadersAreRefused is the live instance
// -- its body uses object_id "k" and purpose "p", both under identifierPattern's three-character
// minimum, so it is 400 no matter what the headers say and it detects nothing.
//
// SECOND, EVERY REFUSAL ROW NAMES SOMETHING SPECIFIC. The handler answers INVALID_ARGUMENT/400 for
// every boundary refusal on purpose, so "an error came back" distinguishes nothing here. Where the
// message is available -- validateRequest -- it is asserted by name. Where it is not, the rows
// assert the status, the machine-readable code, whether the coordinator was reached, and which
// request id came back: writeError substitutes the all-zero id when the header fails
// requestIDPattern, so the echoed id separates a request-id refusal from every other refusal on
// the same path.

// acceptedSignBody is a sign request that post() turns into a 200 with its default headers. Every
// part of it is deliberate: the nonce equals the Idempotency-Key post() sends (validateRequest
// refuses when they differ), object_id and purpose both clear identifierPattern's three-character
// minimum, and content_type is present because sign requires it.
const acceptedSignBody = `{"object_id":"production-signer",` +
	`"context":{"environment":"production","purpose":"sops-data-key",` +
	`"expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},` +
	`"content_type":"application/vnd.regalia.digest","payload_base64":"AAAAAAAA"}`

// signBodyWithoutContentType is acceptedSignBody with the content_type member deleted and nothing
// else changed, so the only thing that can refuse it is the rule that requires it.
const signBodyWithoutContentType = `{"object_id":"production-signer",` +
	`"context":{"environment":"production","purpose":"sops-data-key",` +
	`"expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},` +
	`"payload_base64":"AAAAAAAA"}`

const (
	// sentRequestID is the X-Request-ID post() sets; both resultDocument and errorDocument echo it.
	sentRequestID = "018f0000-0000-7000-8000-000000000001"
	// substitutedRequestID is what writeError puts in an error document when the header does not
	// match requestIDPattern. It is the fingerprint of "the request-id clause refused", because
	// every other refusal on this path echoes sentRequestID instead.
	substitutedRequestID = "00000000-0000-4000-8000-000000000000"
	// thirtySixDashes is the length of a UUID and none of its structure. It is what a caller that
	// pads a field to the right width sends, and audit.requestIDPattern (`^[0-9a-fA-F-]{36}$`)
	// accepts it, so this boundary is the only place it can be refused.
	thirtySixDashes = "------------------------------------"
)

// signingCoordinator returns a coordinator that succeeds, so a 400 in any test below is the
// handler's decision and never the coordinator's.
func signingCoordinator() *fakeCoordinator {
	return &fakeCoordinator{result: Result{
		OperationID: "018f0000-0000-7000-8000-000000000002",
		ContentType: "application/octet-stream",
		Data:        []byte("SIGNATURE-BYTES"),
	}}
}

func decodeErrorDocument(t *testing.T, response *httptest.ResponseRecorder) errorDocument {
	t.Helper()
	var document errorDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("body is not an error document: %q (%v)", response.Body.String(), err)
	}
	return document
}

func decodeResultDocument(t *testing.T, response *httptest.ResponseRecorder) resultDocument {
	t.Helper()
	var document resultDocument
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("body is not a result document: %q (%v)", response.Body.String(), err)
	}
	return document
}

// THE THREE REQUIRED HEADERS ARE CHECKED BEFORE THE BODY IS READ, AND EACH ONE MATTERS.
//
// ServeHTTP's guard is one disjunction over three clauses -- requestIDPattern, idempotencyPattern
// and isJSON -- and with the whole guard dead the handler SIGNS. Concretely, with
// `if false && (...)`, a POST /v1/operations/sign carrying no X-Request-ID and Content-Type:
// text/plain returns 200 with a real signature and `"request_id":""`: an audit record with no
// correlation id for an operation that happened.
//
// The two clauses this table is the sole detector for, one row each:
//
//   - requestIDPattern. Dead, an X-Request-ID of thirty-six dashes is accepted and echoed verbatim
//     in the success document (`"request_id":"------------------------------------"`). Nothing
//     downstream catches it: audit.go's requestIDPattern is `^[0-9a-fA-F-]{36}$`, which dashes
//     match, and policy.go only refuses the empty string. This boundary is the only UUID check.
//
//   - isJSON. Dead, a text/plain body is parsed as JSON and signed -- 200 with a signature. isJSON
//     has no other caller (grep: its definition and this guard), so the mutation also makes it
//     dead code that nothing notices.
//
//   - isJSON's own `err == nil`. It reads as an operand that cannot matter:
//     surely a parse failure leaves mediaType empty and the second conjunct already returns false.
//     Measured, that is wrong. mime.ParseMediaType returns ErrInvalidMediaParameter TOGETHER with
//     a fully populated media type when the media type is well-formed and only a parameter is not:
//
//     "application/json; charset=utf-8"           mediaType="application/json"  err=<nil>
//     "application/json; charset="                mediaType="application/json"  err=invalid media parameter
//     "application/json; =bad"                    mediaType="application/json"  err=invalid media parameter
//     "not a media type"                          mediaType=""                  err=expected slash
//
//     Only the middle rows flip the answer, and the charset=utf-8 ANCHOR above is the well-formed
//     parameter, so nothing here reached a malformed one. Without the operand a request whose
//     Content-Type the parser rejected is parsed as JSON and signed.
//
// The Idempotency-Key clause is NOT separately detectable and the "no Idempotency-Key" row below
// is documentation rather than a gate: with that clause alone dead, validateRequest still refuses
// because document.Context.Nonce != idempotencyKey, and a header short enough to fail
// idempotencyPattern must equal an equally short nonce, which validateRequest refuses too. The row
// is kept because the rule is real; it is honestly not what proves it.
func TestRequiredHeaderTripleIsRefusedOnAnOtherwiseAcceptedRequest(t *testing.T) {
	cases := []struct {
		name          string
		headers       map[string]string
		wantStatus    int
		wantRequestID string
	}{
		// ANCHOR. Without this row every refusal below is compatible with "sign is broken".
		{"the unmodified request", nil, http.StatusOK, sentRequestID},
		// ANCHOR. isJSON parses the media type rather than comparing the string, so a charset
		// parameter is not a refusal. This row is what fails if someone "simplifies" isJSON into
		// an equality test and breaks every client that sends the parameter.
		{"application/json with a charset parameter",
			map[string]string{"Content-Type": "application/json; charset=utf-8"}, http.StatusOK, sentRequestID},

		// GATE for requestIDPattern.
		{"no X-Request-ID at all",
			map[string]string{"X-Request-ID": ""}, http.StatusBadRequest, substitutedRequestID},
		{"an X-Request-ID of thirty-six dashes",
			map[string]string{"X-Request-ID": thirtySixDashes}, http.StatusBadRequest, substitutedRequestID},

		// GATE for isJSON.
		{"no Content-Type at all",
			map[string]string{"Content-Type": ""}, http.StatusBadRequest, sentRequestID},
		{"a text/plain Content-Type",
			map[string]string{"Content-Type": "text/plain"}, http.StatusBadRequest, sentRequestID},

		// GATE for isJSON's OWN `err == nil`, which the anchor above cannot reach. See the note
		// below the table: mime.ParseMediaType returns ErrInvalidMediaParameter TOGETHER with a
		// fully populated media type when the type is well-formed and only a parameter is not, so
		// this row is refused by `err == nil` alone and accepted without it.
		{"application/json with a malformed parameter",
			map[string]string{"Content-Type": "application/json; charset="}, http.StatusBadRequest, sentRequestID},

		// DOCUMENTATION, not a gate: see the note above the function. validateRequest's
		// nonce/header comparison refuses this row even with the header clause removed.
		{"no Idempotency-Key at all",
			map[string]string{"Idempotency-Key": ""}, http.StatusBadRequest, sentRequestID},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := signingCoordinator()
			response := post(t, NewHandler(coordinator), "/v1/operations/sign", acceptedSignBody, testCase.headers)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				if coordinator.calls != 1 {
					t.Fatalf("accepted request reached the coordinator %d times, want 1", coordinator.calls)
				}
				document := decodeResultDocument(t, response)
				if document.RequestID != testCase.wantRequestID || document.ObjectID != "production-signer" {
					t.Fatalf("result document = %#v, want request_id %q and object_id production-signer",
						document, testCase.wantRequestID)
				}
				return
			}
			// The claim is refusal AT THE BOUNDARY: a request refused after dispatch looks the
			// same from out here, and "the headers are checked before the body is read" is the
			// whole point of doing it in ServeHTTP.
			if coordinator.calls != 0 {
				t.Fatalf("a refused request reached the coordinator %d times", coordinator.calls)
			}
			document := decodeErrorDocument(t, response)
			if document.Code != "INVALID_ARGUMENT" {
				t.Fatalf("code = %q, want INVALID_ARGUMENT: %s", document.Code, response.Body.String())
			}
			if document.RequestID != testCase.wantRequestID {
				t.Fatalf("request_id = %q, want %q — the refusal came from a different rule than this row names",
					document.RequestID, testCase.wantRequestID)
			}
		})
	}
}

// A COORDINATOR FAILURE CHOOSES THE STATUS AND THE CODE, SO ITS RANGE IS CHECKED BEFORE USE.
//
// Failure.Status goes straight to writer.WriteHeader and Failure.Code straight into the error
// document, so the normalisation in ServeHTTP is the only thing keeping an internal error type
// from writing an arbitrary HTTP status. Each of its three range clauses is separately undetected
// today, and each has its own row below; TestCoordinatorFailureUsesStableSafeError does not
// substitute for any of them because its Failure carries Status 403 and Code "DENIED", which every
// clause admits.
//
// With the clause gone, concretely:
//
//   - `failure.Status < 400`: a Failure{Code: "DENIED", Status: 200} answers HTTP 200 OK carrying
//     an error document for an operation that was DENIED. A client that branches on the status --
//     which is what a status is for -- reads a denial as a success. Status 0 goes further and
//     panics net/http's checkWriteHeaderCode; 200 is used here because a panic is a coarser signal
//     than the wrong status and would make the row pass for the wrong reason.
//   - `failure.Status > 599`: a Failure{..., Status: 700} answers HTTP 700, which is not a status.
//     At 1000 the same path panics in checkWriteHeaderCode.
//   - `failure.Code == ""`: a Failure{Code: "", Status: 403} answers 403 with `"code":""`, while
//     the Error schema declares code required — a client switching on the code has nothing to
//     switch on.
func TestCoordinatorFailureOutsideTheErrorRangeIsNormalisedToInternal(t *testing.T) {
	cases := []struct {
		name          string
		failure       *Failure
		wantStatus    int
		wantCode      string
		wantRetryable bool
	}{
		// ANCHORS. A Failure inside the range passes through untouched, retryable included.
		// Without these the table would pass against a handler that answered 500 to everything.
		{"a denial inside the range", &Failure{Code: "DENIED", Status: http.StatusForbidden}, http.StatusForbidden, "DENIED", false},
		{"a retryable dependency failure", &Failure{Code: "DEPENDENCY_UNAVAILABLE", Status: http.StatusServiceUnavailable, Retryable: true}, http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", true},

		// GATES on the bounds themselves: both ends are INCLUSIVE, so these must pass through.
		// They are what fails if a fix for the rows below overshoots into `<= 400` or `>= 599`.
		{"the lowest admitted status", &Failure{Code: "DENIED", Status: 400}, 400, "DENIED", false},
		{"the highest admitted status", &Failure{Code: "UPSTREAM", Status: 599}, 599, "UPSTREAM", false},

		// GATES, one per undetected clause.
		{"a success status on a failure", &Failure{Code: "DENIED", Status: http.StatusOK}, http.StatusInternalServerError, "INTERNAL", false},
		{"a status above the HTTP range", &Failure{Code: "DENIED", Status: 700}, http.StatusInternalServerError, "INTERNAL", false},
		{"a failure with no code", &Failure{Code: "", Status: http.StatusForbidden}, http.StatusInternalServerError, "INTERNAL", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := &fakeCoordinator{err: testCase.failure}
			response := post(t, NewHandler(coordinator), "/v1/operations/sign", acceptedSignBody, nil)
			// Every row here must have REACHED the coordinator: this normalisation happens after
			// dispatch, so a row that stopped at the boundary would assert nothing about it.
			if coordinator.calls != 1 {
				t.Fatalf("the request never reached the coordinator (calls=%d), so the failure path was not exercised: %s",
					coordinator.calls, response.Body.String())
			}
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d for Failure%+v: %s",
					response.Code, testCase.wantStatus, *testCase.failure, response.Body.String())
			}
			document := decodeErrorDocument(t, response)
			if document.Code != testCase.wantCode {
				t.Fatalf("code = %q, want %q for Failure%+v", document.Code, testCase.wantCode, *testCase.failure)
			}
			if document.Retryable != testCase.wantRetryable {
				t.Fatalf("retryable = %v, want %v for Failure%+v", document.Retryable, testCase.wantRetryable, *testCase.failure)
			}
			if document.RequestID != sentRequestID {
				t.Fatalf("request_id = %q, want %q", document.RequestID, sentRequestID)
			}
		})
	}
}

// THE BODY IS EXACTLY ONE JSON DOCUMENT, AND THE SECOND Decode IS WHAT SAYS SO.
//
// decodeRequest decodes once into requestDocument and then decodes again, requiring io.EOF. With
// that second check dead, a body of `<valid sign request>{"object_id":"other-key"}` returns 200
// with a real signature -- and the signature is taken under the FIRST document's object_id,
// production-signer, while any parser that read the LAST document (a proxy, a log pipeline, a WAF)
// would report other-key. That is request smuggling inside a single body, and the operation the
// KMS performed is not the one an observer records.
//
// TestUnknownRequestFieldsAreRejectedNotIgnored does not cover this: it kills only the first
// Decode. DisallowUnknownFields sits one line above the guard tested here and applies to the
// members of a document, not to a document that follows one.
func TestABodyWithATrailingSecondDocumentIsRefused(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		// ANCHOR. The same bytes without a suffix are signed, so every refusal below is caused by
		// the suffix and by nothing else in the document.
		{"the document on its own", acceptedSignBody, http.StatusOK},
		// ANCHOR. The rule is "one DOCUMENT", not "no trailing bytes": json.Decoder skips trailing
		// whitespace and the second Decode still reports io.EOF. A client that ends its body with
		// a newline must not be refused.
		{"trailing whitespace and newlines", acceptedSignBody + "\n  \n", http.StatusOK},

		// GATES.
		{"a second complete document", acceptedSignBody + `{"object_id":"other-key"}`, http.StatusBadRequest},
		{"trailing bytes that are not JSON", acceptedSignBody + "zzzz", http.StatusBadRequest},
		// A bare `null` decodes into `any` without error, so a check written as "the second decode
		// produced no value" would let it through. The check is on io.EOF, and this row is what
		// distinguishes the two.
		{"a trailing JSON null", acceptedSignBody + "null", http.StatusBadRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := signingCoordinator()
			response := post(t, NewHandler(coordinator), "/v1/operations/sign", testCase.body, nil)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				if coordinator.calls != 1 {
					t.Fatalf("accepted body reached the coordinator %d times, want 1", coordinator.calls)
				}
				return
			}
			if coordinator.calls != 0 {
				t.Fatalf("a body with a trailing document was signed anyway: calls=%d, object_id=%q",
					coordinator.calls, coordinator.request.ObjectID)
			}
			if document := decodeErrorDocument(t, response); document.Code != "INVALID_ARGUMENT" {
				t.Fatalf("code = %q, want INVALID_ARGUMENT: %s", document.Code, response.Body.String())
			}
		})
	}
}

// SIGN REQUIRES A CONTENT TYPE, AND THE CLIENT IS THE ONLY ONE WHO CAN SAY WHAT IT SIGNED.
//
// validateRequest's sign case refuses `document.ContentType == ""` alongside the three fields that
// belong to other operations. The three fields are covered -- TestNoOperationAcceptsAnotherOperationsFields
// lists sign's forbidden set as format, plaintext_data_key_base64 and wrapped_data_key_base64 --
// and the missing content_type is not: no test in the package ever omits it, and
// validDocuments()["sign"] always sets it.
//
// With that clause dead the request is accepted and reaches the coordinator with ContentType "",
// where operations.Coordinator substitutes "application/vnd.regalia.data-key" for the empty string
// before the policy allowlist decision. So the effect is not a nil deref or an obvious 500: the
// caller omits the field and the KMS decides, on the caller's behalf and silently, which content
// type the policy engine is asked to authorise. That is the server choosing what it signed.
//
// Asserted at validateRequest rather than through the handler because the handler answers
// INVALID_ARGUMENT/400 for every refusal on this path -- the same reasoning validate_request_test.go
// states at its head -- so only here can the test name the rule that fired. The handler leg below
// adds the part validateRequest cannot show: that the refusal happens before dispatch.
func TestSignRefusesADocumentWithNoContentType(t *testing.T) {
	const principal = "spiffe://regalia/workload/x"

	// ANCHOR at the validateRequest level: the fixture is accepted as written, so the refusal
	// below is caused by clearing content_type and not by anything else in the document.
	document := validDocuments()["sign"]
	if _, err := validateRequest("sign", principal, "req-1", validNonce, document); err != nil {
		t.Fatalf("the sign fixture is not accepted as written (%v) — the refusal below would prove nothing", err)
	}

	document.ContentType = ""
	// Errorf rather than Fatalf, deliberately: with the clause removed BOTH this leg and the
	// handler leg below are detectors, and a Fatal here would end the test before the handler leg
	// ran, leaving half the claim unexercised in exactly the run that matters.
	switch _, err := validateRequest("sign", principal, "req-1", validNonce, document); {
	case err == nil:
		t.Error("sign accepted a document with no content_type: the KMS, not the caller, then decides what was signed")
	// NAME THE RULE. "invalid operation context" and "invalid operation payload" are the two
	// neighbouring refusals in this function and either would satisfy err != nil while leaving
	// this rule unproven.
	case !strings.Contains(err.Error(), "invalid sign request"):
		t.Errorf("error = %q, want %q — refused by a different rule, so this one is still unproven",
			err, "invalid sign request")
	}

	// ANCHOR at the handler level, and the evidence that content_type is carried through rather
	// than merely tolerated: without this, the 400 below is compatible with sign being unreachable.
	accepted := signingCoordinator()
	response := post(t, NewHandler(accepted), "/v1/operations/sign", acceptedSignBody, nil)
	if response.Code != http.StatusOK || accepted.calls != 1 {
		t.Fatalf("a well-formed sign request was not dispatched: %d calls=%d %s", response.Code, accepted.calls, response.Body.String())
	}
	if accepted.request.ContentType != "application/vnd.regalia.digest" {
		t.Fatalf("content type reaching the coordinator = %q, want the one the caller sent", accepted.request.ContentType)
	}

	// GATE at the handler level: the same body with the member deleted is refused, and is refused
	// BEFORE the coordinator sees an empty ContentType it would then fill in itself.
	refused := signingCoordinator()
	response = post(t, NewHandler(refused), "/v1/operations/sign", signBodyWithoutContentType, nil)
	if response.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a sign body with no content_type: %s", response.Code, response.Body.String())
	} else if document := decodeErrorDocument(t, response); document.Code != "INVALID_ARGUMENT" {
		t.Errorf("code = %q, want INVALID_ARGUMENT: %s", document.Code, response.Body.String())
	}
	if refused.calls != 0 {
		t.Errorf("a sign request with no content_type reached the coordinator with ContentType %q, which operations.Coordinator then fills in on the caller's behalf",
			refused.request.ContentType)
	}
}
