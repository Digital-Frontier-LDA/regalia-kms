package api

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// THREE MORE REFUSALS AT THE HTTP BOUNDARY, EACH ONE PROVEN UNDETECTED BEFORE THIS FILE EXISTED.
//
// guard_coverage_test.go covers the header triple, the coordinator-failure normalisation, the
// trailing-document check and sign's content_type. A second mutation sweep found three more guards
// in handler.go that could be replaced with `if false && (<original>)` while the whole module --
// api, internal, integration, operations, registry, server, cmd/regalia-kms -- stayed green:
//
//   - ServeHTTP's `handler.coordinator == nil` dependency check;
//   - validateRequest's envelope_aad guard, `err != nil || len(aad) > 12<<10`;
//   - validateRequest's seal-nonce guard, `err != nil || len(request.SealNonce) != 12`.
//
// THE TESTS BELOW ARE SPLIT BY OPERAND, NOT BY LINE. Each of the last two guards is a disjunction
// of two independent rules, and a test that mixed them could not say which half died. So the strict
// -base64 half and the length half of each guard get their own function: neutralising one operand
// fails exactly one test here, and neutralising the whole guard fails exactly the two tests that
// name its two halves. That is the finest attribution this shape admits.
//
// The two habits guard_coverage_test.go states at its head are followed here too. Every table
// carries a labelled ANCHOR that is ACCEPTED as written -- placed after the gates, per TESTING.md
// §18 -- so a guard that refused everything could not pass the table, and every refusal row names
// something more specific than "an error came back": the status, the machine-readable code, the
// retryable flag, whether the coordinator was reached, and what bytes reached it when it was. The
// handler answers one opaque message ("request failed") for every refusal on this path, so those
// values are the only distinguishing evidence available out here.

// postRecoveringAPanic is post() with a deliberate recover around it.
//
// It exists for one row -- the nil-coordinator gate -- and for one reason: with that guard removed
// the handler does not return an error, it dereferences a nil Coordinator interface and the process
// dies. An unrecovered panic takes the whole test binary with it, which would make every other
// result in this package unobservable in exactly the run that is meant to measure which single test
// detects the defect. Recovering turns that into an ordinary FAIL that can be attributed.
//
// A t.Fatal inside post() unwinds with runtime.Goexit rather than a panic, so it is not caught here
// and still ends the test as it should; only a real panic is converted.
func postRecoveringAPanic(t *testing.T, handler http.Handler, path, body string) (response *httptest.ResponseRecorder, panicked any) {
	t.Helper()
	func() {
		defer func() { panicked = recover() }()
		response = post(t, handler, path, body, nil)
	}()
	return response, panicked
}

// A HANDLER WITH NO COORDINATOR ANSWERS 503; IT DOES NOT CRASH THE PROCESS.
//
// `handler.coordinator == nil` is the last thing ServeHTTP checks before dispatch. With it dead the
// very next statement -- `result, err := handler.coordinator.Execute(request.Context(), input)` in
// ServeHTTP -- calls Execute through a nil interface value. The observed result of neutralising it
// is not a wrong status but a segmentation fault:
//
//	panic: runtime error: invalid memory address or nil pointer dereference
//	[signal SIGSEGV: segmentation violation code=0x2 addr=0x18]
//	...api.(*Handler).ServeHTTP
//
// In production that is one unauthenticated-shaped request away from taking down a KMS: the guard
// is what turns a missing dependency into a retryable 503 that a client can back off on.
//
// The gap is real rather than theoretical because NewHandler(nil) is the constructor five existing
// call sites already use -- compatibility_test.go and capabilities_test.go both build handlers that
// way -- and every one of them sends a request that is refused earlier (a 404 path, an
// unauthenticated request, a body with a two-character object_id), so none of them ever reaches
// this line. NewHandler and ServeHTTP are both exported, so any caller in any package can construct
// this input; it is not unreachable under TESTING.md §17.
//
// The message is the same opaque "request failed" every refusal on this path returns, so the rows
// assert the distinguishing values instead: the {Code, Status, Retryable} triple and the echoed
// request id.
func TestAHandlerWithNoCoordinatorAnswers503RatherThanPanicking(t *testing.T) {
	cases := []struct {
		name string
		// wireCoordinator distinguishes NewHandler(coordinator) from NewHandler(nil). It is a bool
		// rather than a *fakeCoordinator field on purpose: a nil *fakeCoordinator stored in a
		// Coordinator interface is NOT a nil interface, the guard would not fire, and the row would
		// exercise a different (and also real) trap.
		wireCoordinator bool
		body            string
		wantStatus      int
		wantCode        string
		wantRetryable   bool
	}{
		// GATE. This is the row the mutation kills.
		{"an otherwise accepted sign request", false, acceptedSignBody,
			http.StatusServiceUnavailable, "DEPENDENCY_UNAVAILABLE", true},

		// GATE on the ORDER, which is the other half of the rule: the dependency check sits AFTER
		// validation, so a malformed request is still the client's fault and still gets 400. Moving
		// the nil check to the top of ServeHTTP -- a plausible "fix" -- would answer 503 here and
		// tell a client with a broken body to retry forever.
		{"a request the boundary refuses, with no coordinator wired", false, signBodyWithoutContentType,
			http.StatusBadRequest, "INVALID_ARGUMENT", false},

		// ANCHOR. The same bytes with a coordinator wired are signed, so the 503 above is caused by
		// the missing dependency and not by the request being invalid.
		{"the same request with a coordinator wired", true, acceptedSignBody, http.StatusOK, "", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := signingCoordinator()
			handler := NewHandler(nil)
			if testCase.wireCoordinator {
				handler = NewHandler(coordinator)
			}

			response, panicked := postRecoveringAPanic(t, handler, "/v1/operations/sign", testCase.body)
			if panicked != nil {
				t.Fatalf("ServeHTTP panicked instead of refusing: %v — the nil-coordinator check is what stands between a missing dependency and a nil-interface call to Coordinator.Execute", panicked)
			}
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				if coordinator.calls != 1 {
					t.Fatalf("the anchor reached the coordinator %d times, want 1", coordinator.calls)
				}
				if document := decodeResultDocument(t, response); document.RequestID != sentRequestID {
					t.Fatalf("result request_id = %q, want %q", document.RequestID, sentRequestID)
				}
				return
			}
			document := decodeErrorDocument(t, response)
			if document.Code != testCase.wantCode {
				t.Fatalf("code = %q, want %q: %s", document.Code, testCase.wantCode, response.Body.String())
			}
			if document.Retryable != testCase.wantRetryable {
				t.Fatalf("retryable = %v, want %v — a missing dependency is worth retrying and a malformed request is not, and the flag is how a client tells them apart",
					document.Retryable, testCase.wantRetryable)
			}
			if document.RequestID != sentRequestID {
				t.Fatalf("request_id = %q, want %q — the refusal came from a different rule than this row names",
					document.RequestID, sentRequestID)
			}
		})
	}
}

// signBodyWithEnvelopeAAD is acceptedSignBody with an envelope_aad_base64 member appended and
// nothing else changed, so the only thing in the document that can refuse it is the aad. sign is
// used because it is one of the operations that ADMIT envelope_aad -- release-secret and
// seal-envelope refuse the member outright in validateRequest, one rule earlier, and a fixture
// built on either would be refused before the guard under test ever ran.
func signBodyWithEnvelopeAAD(encoded string) string {
	return strings.TrimSuffix(acceptedSignBody, "}") + `,"envelope_aad_base64":"` + encoded + `"}`
}

const (
	// illegalAAD is not base64 at all. Strict() returns zero bytes AND an error, so with the error
	// operand dead the coordinator is handed an EMPTY envelope AAD for a document that asked for a
	// non-empty one.
	illegalAAD = "!!!!"
	// nonCanonicalAAD is legal base64 to a plain decoder and illegal to a strict one: the final
	// quantum's unused bits are non-zero. Measured, not assumed -- see the precondition in
	// TestEnvelopeAADRefusesNonCanonicalBase64NotJustIllegalCharacters:
	//   base64.StdEncoding.DecodeString("QUJDRB==")          -> ("ABCD", nil)
	//   base64.StdEncoding.Strict().DecodeString("QUJDRB==") -> ("ABC",  illegal base64 data at input byte 6)
	nonCanonicalAAD = "QUJDRB=="
	// canonicalABC is the canonical encoding of the three bytes Strict() salvages from
	// nonCanonicalAAD before it errors. The two are different wire documents; with the error
	// operand dead they produce the SAME binding context.
	canonicalABC = "QUJD"
	// envelopeAADLimit is the bound in the guard, spelled the way the guard spells it.
	envelopeAADLimit = 12 << 10
)

// THE ENVELOPE BINDING CONTEXT MUST BE CANONICAL BASE64, NOT MERELY DECODABLE.
//
// This is the `err != nil` half of validateRequest's envelope_aad guard. Neutralising just that
// operand -- `if (false && err != nil) || len(aad) > 12<<10 {` -- leaves the length half live and
// turns both rows below from 400 into 200 with a dispatch, observed:
//
//	malformed aad     status=200 calls=1 aadLen=0 aad=""
//	non-canonical aad status=200 calls=1 aadLen=3 aad="ABC"
//
// Two separate defects, and the second is the serious one. base64.StdEncoding.Strict().DecodeString
// returns the bytes it managed to decode ALONGSIDE its error, so ignoring the error does not yield
// nothing -- it yields a TRUNCATED prefix. "QUJDRB==" is a document every non-strict decoder in the
// world reads as the four bytes "ABCD"; with this operand dead the KMS would bind three of them.
// And "QUJD", a completely different wire document, binds those same three bytes -- so two requests
// carrying different envelope contexts would be authenticated under one AAD. That is the whole
// point of a binding context defeated by a padding character.
//
// Nothing downstream re-derives it: EnvelopeAAD is carried on api.Request as bytes and used as the
// AAD, so this boundary is the only place the encoding is judged.
func TestEnvelopeAADRefusesNonCanonicalBase64NotJustIllegalCharacters(t *testing.T) {
	// PRECONDITIONS on the encoding library, not on the handler. They pin the claims the rows below
	// are named for -- "legal to a plain decoder", "strict salvages a truncated prefix", "collides
	// with a different document" -- so that a row cannot quietly become a test of ordinary garbage
	// input. They cannot foreclose the falsification runs (§18) because no mutation of handler.go
	// can change what encoding/base64 does.
	if plain, err := base64.StdEncoding.DecodeString(nonCanonicalAAD); err != nil || string(plain) != "ABCD" {
		t.Fatalf("plain StdEncoding on %q = (%q, %v), want (\"ABCD\", nil) — this row is only about Strict() if a plain decoder accepts it",
			nonCanonicalAAD, plain, err)
	}
	salvaged, err := base64.StdEncoding.Strict().DecodeString(nonCanonicalAAD)
	if err == nil {
		t.Fatalf("Strict() accepted %q, so there is nothing here for the guard to refuse", nonCanonicalAAD)
	}
	collides, _ := base64.StdEncoding.Strict().DecodeString(canonicalABC)
	if string(salvaged) != string(collides) {
		t.Fatalf("Strict() salvaged %q from %q and %q from %q; the collision this row is named for does not hold",
			salvaged, nonCanonicalAAD, collides, canonicalABC)
	}

	cases := []struct {
		name       string
		body       string
		wantStatus int
		wantAAD    string
	}{
		// GATES. Both are refusals the error operand and nothing else produces: each decodes to
		// FEWER than the 12 KiB the length operand admits, so with the error operand dead there is
		// no second rule left to stop them.
		{"an envelope_aad that is not base64 at all", signBodyWithEnvelopeAAD(illegalAAD), http.StatusBadRequest, ""},
		{"an envelope_aad with non-zero padding bits", signBodyWithEnvelopeAAD(nonCanonicalAAD), http.StatusBadRequest, ""},

		// ANCHOR. The canonical encoding of the bytes the row above collides with is ACCEPTED, and
		// reaches the coordinator as those exact bytes. Without this row the two refusals are
		// compatible with "envelope_aad is refused whenever it is present".
		{"the canonical encoding of the same bytes", signBodyWithEnvelopeAAD(canonicalABC), http.StatusOK, "ABC"},
		// ANCHOR. The member may also be absent: an empty string decodes to zero bytes with no
		// error, so an operation with no binding context must still be signed.
		{"no envelope_aad member at all", acceptedSignBody, http.StatusOK, ""},
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
					t.Fatalf("the anchor reached the coordinator %d times, want 1", coordinator.calls)
				}
				if string(coordinator.request.EnvelopeAAD) != testCase.wantAAD {
					t.Fatalf("envelope AAD reaching the coordinator = %q, want %q",
						coordinator.request.EnvelopeAAD, testCase.wantAAD)
				}
				return
			}
			// REFUSED AT THE BOUNDARY. A request refused after dispatch looks the same from out
			// here, and the claim is that the coordinator never sees a truncated binding context.
			if coordinator.calls != 0 {
				t.Fatalf("a document with an unusable envelope_aad was dispatched with AAD %q (%d bytes)",
					coordinator.request.EnvelopeAAD, len(coordinator.request.EnvelopeAAD))
			}
			if document := decodeErrorDocument(t, response); document.Code != "INVALID_ARGUMENT" {
				t.Fatalf("code = %q, want INVALID_ARGUMENT: %s", document.Code, response.Body.String())
			}
		})
	}
}

// THE ENVELOPE BINDING CONTEXT HAS A CEILING, AND IT IS INCLUSIVE.
//
// This is the `len(aad) > 12<<10` half of the same guard. Neutralising just that operand leaves the
// strict-base64 half live and admits an arbitrarily large caller-chosen binding context; the
// verifier's measurement was `aad of 12289 bytes: status=200 calls=1 aadLenReachingCoordinator=12289`
// against a pristine `status=400 calls=0`. The AAD is caller-supplied and travels into every AEAD
// call the operation makes, so an unbounded one is an unbounded allocation and an unbounded thing
// to hash, chosen by whoever can reach the endpoint.
//
// Kept separate from the strict-base64 test above so that a red here names the LENGTH rule: the two
// operands of this guard are independent, and one test covering both could not say which died.
func TestEnvelopeAADRefusesAContextOverItsTwelveKibibyteBound(t *testing.T) {
	cases := []struct {
		name       string
		aadBytes   int
		wantStatus int
	}{
		// GATE. One byte over. b64() encodes canonically, so the strict-base64 operand admits it
		// and the length operand is the only rule that can refuse it.
		{"one byte over the bound", envelopeAADLimit + 1, http.StatusBadRequest},

		// ANCHOR on the bound itself, which is INCLUSIVE: `> 12<<10`, not `>=`. This is the row
		// that fails if a fix for the gate above overshoots and starts refusing the largest legal
		// context, which would break a client that is inside the documented limit.
		{"exactly the bound", envelopeAADLimit, http.StatusOK},
		// ANCHOR. An ordinary small context is accepted, so the refusal above is about size.
		{"a sixteen-byte context", 16, http.StatusOK},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := signingCoordinator()
			body := signBodyWithEnvelopeAAD(b64(testCase.aadBytes))
			response := post(t, NewHandler(coordinator), "/v1/operations/sign", body, nil)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d for a %d-byte envelope_aad: %s",
					response.Code, testCase.wantStatus, testCase.aadBytes, response.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				if coordinator.calls != 1 {
					t.Fatalf("the anchor reached the coordinator %d times, want 1", coordinator.calls)
				}
				if len(coordinator.request.EnvelopeAAD) != testCase.aadBytes {
					t.Fatalf("envelope AAD reaching the coordinator = %d bytes, want %d",
						len(coordinator.request.EnvelopeAAD), testCase.aadBytes)
				}
				return
			}
			if coordinator.calls != 0 {
				t.Fatalf("an oversized envelope_aad was dispatched: %d bytes reached the coordinator",
					len(coordinator.request.EnvelopeAAD))
			}
			if document := decodeErrorDocument(t, response); document.Code != "INVALID_ARGUMENT" {
				t.Fatalf("code = %q, want INVALID_ARGUMENT: %s", document.Code, response.Body.String())
			}
		})
	}
}

// sealEnvelopeBody is a seal-envelope request whose ONLY variable is the nonce member.
//
// nonceMember is the raw JSON text to splice in, so that "the member is absent" and "the member is
// an empty string" can be two different wire documents rather than one. Everything else is fixed
// and valid: the format regalia-envelope-v2 the operation requires, a 32-byte data key, and a
// 17-byte ciphertext (16 is a GCM tag over no plaintext, so 17 is the smallest legal one). The two
// guards that follow the nonce guard in validateRequest therefore admit every body this builds, and
// a refusal can only be the nonce.
func sealEnvelopeBody(nonceMember string) string {
	return `{"object_id":"production-sops",` +
		`"context":{"environment":"production","purpose":"sops-data-key",` +
		`"expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},` +
		`"format":"regalia-envelope-v2",` +
		`"ciphertext_base64":"` + base64.StdEncoding.EncodeToString([]byte(sealCiphertextPlain)) + `",` +
		`"data_key_base64":"` + b64(32) + `"` + nonceMember + `}`
}

// nonceMemberFor renders the nonce member carrying an already-encoded value. Passing "" to
// sealEnvelopeBody instead omits the member entirely.
func nonceMemberFor(encoded string) string { return `,"nonce_base64":"` + encoded + `"` }

const (
	// sealCiphertextPlain is 17 bytes: one over the `len(data) < 17` floor, so the ciphertext guard
	// downstream of the nonce guard never fires for these fixtures.
	sealCiphertextPlain = "sealed-ciphertext"
	// canonicalNonce is base64("123456789012"), twelve bytes, the GCM nonce length.
	canonicalNonce = "MTIzNDU2Nzg5MDEy"
	// truncatingNonce is canonicalNonce followed by a quantum with non-zero padding bits. Measured,
	// not assumed -- see the precondition in TestSealEnvelopeRefusesANonceThatIsNotStrictBase64:
	//   base64.StdEncoding.DecodeString("MTIzNDU2Nzg5MDEyQR==")          -> ("123456789012A", nil)   13 bytes
	//   base64.StdEncoding.Strict().DecodeString("MTIzNDU2Nzg5MDEyQR==") -> ("123456789012",  error) 12 bytes
	// The salvaged prefix is exactly twelve bytes long, which is what makes this string a detector
	// for the ERROR operand: the length operand has nothing to object to.
	truncatingNonce = "MTIzNDU2Nzg5MDEyQR=="
	// illegalTailNonce is the same shape with an illegal character rather than bad padding bits.
	illegalTailNonce = "MTIzNDU2Nzg5MDEy!!"
)

// A SEAL NONCE MUST BE CANONICAL BASE64, BECAUSE THE SALVAGED PREFIX IS THE RIGHT LENGTH.
//
// This is the `err != nil` half of validateRequest's seal-nonce guard. It is the operand a reader
// is most likely to delete as redundant -- "the length check catches everything" -- and it does
// not, because Strict().DecodeString hands back the bytes it decoded BEFORE it failed. Both rows
// below decode to exactly twelve bytes with an error, so with the error operand dead
// (`...DecodeString(document.SealNonce); (false && err != nil) || len(request.SealNonce) != 12`)
// the length operand is satisfied and the request is dispatched.
//
// What that costs: "MTIzNDU2Nzg5MDEyQR==" is a document a plain base64 decoder reads as the
// THIRTEEN bytes "123456789012A". Client and KMS would disagree about the GCM nonce of a sealed
// envelope, and the KMS's copy is the one that goes into the approval payload an approver signs.
//
// envelope.SealAssembled is a downstream backstop for the LENGTH of the nonce, but it cannot help
// here: twelve bytes is twelve bytes, whichever twelve they are. This boundary is the only place
// the encoding is judged.
func TestSealEnvelopeRefusesANonceThatIsNotStrictBase64(t *testing.T) {
	// PRECONDITION on encoding/base64, not on the handler: the rows below are only detectors for
	// the error operand if the strict decoder salvages exactly twelve bytes from them. If Go ever
	// stopped returning partial output alongside the error, these rows would silently become
	// duplicates of the length test and this Fatal is what would say so.
	for _, encoded := range []string{truncatingNonce, illegalTailNonce} {
		salvaged, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err == nil {
			t.Fatalf("Strict() accepted %q, so there is nothing here for the error operand to refuse", encoded)
		}
		if len(salvaged) != 12 {
			t.Fatalf("Strict() salvaged %d bytes from %q, want 12 — the length operand would refuse this row and it would prove nothing about the error operand",
				len(salvaged), encoded)
		}
	}
	if plain, err := base64.StdEncoding.DecodeString(truncatingNonce); err != nil || len(plain) != 13 {
		t.Fatalf("plain StdEncoding on %q = (%d bytes, %v), want (13, nil) — the client/server disagreement this test is named for does not hold",
			truncatingNonce, len(plain), err)
	}

	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		// GATES. Both salvage twelve bytes, so the length operand admits them and only the error
		// operand can refuse them.
		{"a nonce with non-zero padding bits", sealEnvelopeBody(nonceMemberFor(truncatingNonce)), http.StatusBadRequest},
		{"a nonce with an illegal trailing character", sealEnvelopeBody(nonceMemberFor(illegalTailNonce)), http.StatusBadRequest},

		// DOCUMENTATION, not a gate for this operand, and labelled so no one reads it as one: a
		// nonce of "!!!!" salvages ZERO bytes, so the length operand refuses it too and it flips
		// only when the WHOLE guard dies. The rule is real; this row is honestly not what proves
		// the error half of it.
		{"a nonce that is not base64 at all", sealEnvelopeBody(nonceMemberFor("!!!!")), http.StatusBadRequest},

		// ANCHOR. The canonical twelve bytes are accepted and dispatched, so the refusals above are
		// caused by the encoding and not by seal-envelope being unreachable.
		{"the canonical twelve-byte nonce", sealEnvelopeBody(nonceMemberFor(canonicalNonce)), http.StatusOK},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := signingCoordinator()
			response := post(t, NewHandler(coordinator), "/v1/operations/seal-envelope", testCase.body, nil)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				if coordinator.calls != 1 {
					t.Fatalf("the anchor reached the coordinator %d times, want 1", coordinator.calls)
				}
				if string(coordinator.request.SealNonce) != "123456789012" {
					t.Fatalf("nonce reaching the coordinator = %q, want %q",
						coordinator.request.SealNonce, "123456789012")
				}
				if string(coordinator.request.SealCiphertext) != sealCiphertextPlain || len(coordinator.request.SealDataKey) != 32 {
					t.Fatalf("the rest of the assembled seal did not survive: ciphertext=%q dataKey=%d bytes",
						coordinator.request.SealCiphertext, len(coordinator.request.SealDataKey))
				}
				return
			}
			if coordinator.calls != 0 {
				t.Fatalf("a seal with an unusable nonce was dispatched carrying %d bytes (%x) — that nonce is what the approval payload is framed over",
					len(coordinator.request.SealNonce), coordinator.request.SealNonce)
			}
			if document := decodeErrorDocument(t, response); document.Code != "INVALID_ARGUMENT" {
				t.Fatalf("code = %q, want INVALID_ARGUMENT: %s", document.Code, response.Body.String())
			}
		})
	}
}

// A SEAL NONCE MUST BE TWELVE BYTES, AND AN ABSENT ONE IS NOT ZERO BYTES OF NONCE.
//
// This is the `len(request.SealNonce) != 12` half of the seal-nonce guard, and it was the entry a
// first pass guessed had no consequence. It has one. Neutralising just this operand
// (`...; err != nil || (false && len(request.SealNonce) != 12)`) leaves the decode-error operand
// live and produces, measured against a pristine 400/calls=0 on every row:
//
//	16-byte nonce   status=200 calls=1 nonceLen=16
//	 8-byte nonce   status=200 calls=1 nonceLen=8
//	absent nonce    status=200 calls=1 nonceLen=0
//
// The absent row is the one that refutes "nothing": a seal-envelope body that simply OMITS
// nonce_base64 decodes to zero bytes WITHOUT an error, so the decode operand has nothing to say,
// and the request is dispatched with a ZERO-LENGTH GCM nonce. operations.Coordinator then
// length-frames that nonce into the approval payload -- the digest a human approver signs -- so the
// approval covers a nonce the client never chose.
//
// envelope.SealAssembled would eventually refuse a wrong-length nonce, but it runs after RBAC,
// routing and an audit record for an operation that should never have been admitted, so the
// difference observable at this boundary (400 with no dispatch vs 200 with one) is real.
func TestSealEnvelopeRefusesAnAbsentOrWrongLengthNonce(t *testing.T) {
	cases := []struct {
		name       string
		body       string
		wantStatus int
	}{
		// GATES. Every one of these is canonical base64 that decodes without error, so the decode
		// operand admits them and only the length operand can refuse them.
		{"a sixteen-byte nonce", sealEnvelopeBody(nonceMemberFor(b64(16))), http.StatusBadRequest},
		{"an eight-byte nonce", sealEnvelopeBody(nonceMemberFor(b64(8))), http.StatusBadRequest},
		{"an eleven-byte nonce, one short", sealEnvelopeBody(nonceMemberFor(b64(11))), http.StatusBadRequest},
		{"an explicitly empty nonce member", sealEnvelopeBody(nonceMemberFor("")), http.StatusBadRequest},
		// A DIFFERENT WIRE DOCUMENT from the row above, and the sharpest one: the member is not
		// there at all, which is what a client that never learned about nonce_base64 sends.
		{"no nonce member at all", sealEnvelopeBody(""), http.StatusBadRequest},

		// ANCHOR. Exactly twelve bytes is accepted and dispatched, so the refusals above are about
		// the length and not about seal-envelope refusing everything.
		{"exactly twelve bytes", sealEnvelopeBody(nonceMemberFor(canonicalNonce)), http.StatusOK},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := signingCoordinator()
			response := post(t, NewHandler(coordinator), "/v1/operations/seal-envelope", testCase.body, nil)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				if coordinator.calls != 1 {
					t.Fatalf("the anchor reached the coordinator %d times, want 1", coordinator.calls)
				}
				if len(coordinator.request.SealNonce) != 12 {
					t.Fatalf("nonce reaching the coordinator = %d bytes, want 12", len(coordinator.request.SealNonce))
				}
				return
			}
			if coordinator.calls != 0 {
				t.Fatalf("a seal with a %d-byte nonce was dispatched — operations.Coordinator length-frames that nonce into the payload an approver signs",
					len(coordinator.request.SealNonce))
			}
			if document := decodeErrorDocument(t, response); document.Code != "INVALID_ARGUMENT" {
				t.Fatalf("code = %q, want INVALID_ARGUMENT: %s", document.Code, response.Body.String())
			}
		})
	}
}
