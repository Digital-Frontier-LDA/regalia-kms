package api

import (
	"encoding/base64"
	"strings"
	"testing"
)

// validateRequest is the outermost gate on caller input, and its per-operation rules are a security
// boundary rather than tidiness: each operation refuses the fields that belong to the others, so a
// caller cannot smuggle in a choice the server is supposed to be making. release-secret refusing
// envelope_aad is the clearest case — ENVELOPE.md requires the binding context to be reconstructed
// by the KMS, and a context the caller supplies proves only that the caller knows what it chose.
//
// Tested here rather than through the handler because the handler deliberately returns a stable
// error that does not echo the request, so at that level every refusal looks the same and a test
// cannot tell which rule fired.

const (
	validNonce   = "018f0000000070008000000000000001"
	validExpires = "2030-01-01T00:00:00Z"
)

func baseContext() contextDocument {
	return contextDocument{
		Environment: "production", Purpose: "sops-data-key",
		ExpiresAt: validExpires, Nonce: validNonce,
	}
}

func b64(size int) string {
	return base64.StdEncoding.EncodeToString(make([]byte, size))
}

// validDocuments is one accepted request per operation. Each must validate as written, or the
// refusal cases below would be refusals of an already-broken document.
func validDocuments() map[string]requestDocument {
	return map[string]requestDocument{
		"sign": {ObjectID: "prod-signer", Context: baseContext(),
			ContentType: "application/vnd.regalia.digest", Payload: b64(32)},
		"wrap": {ObjectID: "prod-signer", Context: baseContext(),
			Format: "regalia-envelope-v2", PlaintextDataKey: b64(32)},
		"unwrap": {ObjectID: "prod-signer", Context: baseContext(),
			Format: "regalia-envelope-v2", WrappedDataKey: b64(256)},
		"certificate-sign": {ObjectID: "prod-signer", Context: baseContext(), Payload: b64(512)},
		"key-agreement":    {ObjectID: "prod-signer", Context: baseContext(), Payload: b64(65)},
		"release-secret": {ObjectID: "prod-signer", Context: baseContext(),
			Format: "regalia-envelope-v2", Payload: b64(512)},
		"seal-envelope": {ObjectID: "prod-signer", Context: baseContext(),
			Format: "regalia-envelope-v2", SealCiphertext: b64(64), SealNonce: b64(12), SealDataKey: b64(32)},
	}
}

func TestEveryOperationHasAValidDocumentThatIsAccepted(t *testing.T) {
	for operation, document := range validDocuments() {
		t.Run(operation, func(t *testing.T) {
			if _, err := validateRequest(operation, "spiffe://regalia/workload/x", "req-1", validNonce, document); err != nil {
				t.Fatalf("the fixture for %s is not a valid request: %v — every refusal below would then be refusing something already broken",
					operation, err)
			}
		})
	}
}

// TestNoOperationAcceptsAnotherOperationsFields walks every operation against every field it must
// refuse, one field at a time, asserting the message names that operation. Asserting only "an
// error came back" would pass for a refusal by any of the other rules in this function.
func TestNoOperationAcceptsAnotherOperationsFields(t *testing.T) {
	set := map[string]func(*requestDocument){
		"format":                    func(d *requestDocument) { d.Format = "regalia-envelope-v2" },
		"content_type":              func(d *requestDocument) { d.ContentType = "application/octet-stream" },
		"payload_base64":            func(d *requestDocument) { d.Payload = b64(32) },
		"plaintext_data_key_base64": func(d *requestDocument) { d.PlaintextDataKey = b64(32) },
		"wrapped_data_key_base64":   func(d *requestDocument) { d.WrappedDataKey = b64(256) },
		"envelope_aad_base64":       func(d *requestDocument) { d.EnvelopeAAD = b64(16) },
	}
	forbidden := map[string][]string{
		"sign":             {"format", "plaintext_data_key_base64", "wrapped_data_key_base64"},
		"wrap":             {"content_type", "payload_base64", "wrapped_data_key_base64"},
		"unwrap":           {"content_type", "payload_base64", "plaintext_data_key_base64"},
		"certificate-sign": {"format", "content_type", "plaintext_data_key_base64", "wrapped_data_key_base64"},
		"key-agreement":    {"format", "content_type", "plaintext_data_key_base64", "wrapped_data_key_base64"},
		"release-secret":   {"content_type", "plaintext_data_key_base64", "wrapped_data_key_base64", "envelope_aad_base64"},
		"seal-envelope":    {"content_type", "payload_base64", "plaintext_data_key_base64", "wrapped_data_key_base64", "envelope_aad_base64"},
	}

	documents := validDocuments()
	// THE SETS, NOT THEIR SIZES. A count is exactly what a swap does not move: add one operation
	// and remove another and the totals still agree while an operation's rules go unexercised.
	// That is TESTING.md §16's failure written into the guard meant to prevent it.
	for operation := range documents {
		if _, ok := forbidden[operation]; !ok {
			t.Fatalf("operation %q has a fixture and no forbidden-field list, so nothing here exercises its exclusivity rules", operation)
		}
	}
	for operation := range forbidden {
		if _, ok := documents[operation]; !ok {
			t.Fatalf("operation %q has a forbidden-field list and no fixture, so its cases would all refuse a document that does not exist", operation)
		}
	}
	for operation, fields := range forbidden {
		if len(fields) == 0 {
			t.Fatalf("%s lists no forbidden fields, so it contributes no cases", operation)
		}
		for _, field := range fields {
			t.Run(operation+"/"+field, func(t *testing.T) {
				document := documents[operation]
				apply, ok := set[field]
				if !ok {
					t.Fatalf("no mutation defined for %q", field)
				}
				apply(&document)

				_, err := validateRequest(operation, "spiffe://regalia/workload/x", "req-1", validNonce, document)
				if err == nil {
					t.Fatalf("%s accepted %s, a field belonging to another operation: the caller chose something the server decides", operation, field)
				}
				want := "invalid " + operation + " request"
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("%s with %s: error = %q, want %q — refused by a different rule, so this one is still unproven",
						operation, field, err, want)
				}
			})
		}
	}
}

// TestTheFormatFieldIsNotFreeText. Where an operation requires a format it must be the exact one:
// an envelope operation that accepted any string would route bytes only one format can interpret.
func TestTheFormatFieldIsNotFreeText(t *testing.T) {
	documents := validDocuments()
	for operation, formats := range map[string][]string{
		// regalia-envelope-v1 is included as the refused predecessor of v2: a caller still
		// sending the pre-#206 wire format must get a clean format refusal at the API boundary
		// rather than the silent corruption of a frame whose magic byte is RGK\x01 instead of
		// RGK\x02. The handler is the first gate that names the wire encoding; keywrap.OpenFrame
		// is the second.
		"wrap":           {"", "regalia-envelope-v1", "sops-pgp"},
		"release-secret": {"", "regalia-envelope-v1", "sops-pgp"},
		"seal-envelope":  {"", "regalia-envelope-v1", "sops-pgp"},
		// unwrap is the one operation that admits two, and only these two.
		"unwrap": {"", "regalia-envelope-v1", "pkcs8"},
	} {
		for _, format := range formats {
			t.Run(operation+"/"+format, func(t *testing.T) {
				document := documents[operation]
				document.Format = format
				if _, err := validateRequest(operation, "spiffe://regalia/workload/x", "req-1", validNonce, document); err == nil {
					t.Fatalf("%s accepted format %q", operation, format)
				}
			})
		}
	}
	// The second admitted unwrap format, asserted so the refusals above are not read as "unwrap
	// takes exactly one".
	sopsUnwrap := documents["unwrap"]
	sopsUnwrap.Format = "sops-pgp"
	if _, err := validateRequest("unwrap", "spiffe://regalia/workload/x", "req-1", validNonce, sopsUnwrap); err != nil {
		t.Fatalf("unwrap refused sops-pgp, which it must admit: %v", err)
	}
}

// TestTheContextMustBeWellFormed. Every one of these is checked before any operation-specific rule,
// so a malformed context can never reach the switch.
func TestTheContextMustBeWellFormed(t *testing.T) {
	for name, mutate := range map[string]func(*requestDocument){
		"an unparseable expiry":       func(d *requestDocument) { d.Context.ExpiresAt = "soon" },
		"no expiry at all":            func(d *requestDocument) { d.Context.ExpiresAt = "" },
		"an object id with a slash":   func(d *requestDocument) { d.ObjectID = "prod/signer" },
		"an empty object id":          func(d *requestDocument) { d.ObjectID = "" },
		"an empty purpose":            func(d *requestDocument) { d.Context.Purpose = "" },
		"an environment off the enum": func(d *requestDocument) { d.Context.Environment = "prod" },
		"no environment":              func(d *requestDocument) { d.Context.Environment = "" },
		// Below the 16-character minimum. The rule is idempotencyPattern, ^[A-Za-z0-9_-]{16,128}$ --
		// NOT a UUID format, though every nonce this repository generates happens to be one. A test
		// name claiming UUIDv7 would send the next reader looking for a validator that is not there.
		"a nonce shorter than the minimum":    func(d *requestDocument) { d.Context.Nonce = "tooshort" },
		"a nonce with characters off the set": func(d *requestDocument) { d.Context.Nonce = "018f0000-0000-7000-8000-00000000!!!!" },
		"a subject over 256 bytes":            func(d *requestDocument) { d.Context.Subject = strings.Repeat("s", 257) },
	} {
		t.Run(name, func(t *testing.T) {
			document := validDocuments()["sign"]
			mutate(&document)
			_, err := validateRequest("sign", "spiffe://regalia/workload/x", "req-1", document.Context.Nonce, document)
			if err == nil {
				t.Fatalf("validateRequest accepted %s", name)
			}
			if !strings.Contains(err.Error(), "invalid operation context") {
				t.Fatalf("%s: error = %q, want the context refusal", name, err)
			}
		})
	}
}

// TestTheBodysNonceMustEqualTheIdempotencyHeader. Two places carry the replay nonce and they must
// agree: the header is what the durable replay journal keys on, and the body is what the signature
// and the audit record carry. A request whose halves disagree can be recorded under one nonce and
// replayed under the other.
func TestTheBodysNonceMustEqualTheIdempotencyHeader(t *testing.T) {
	document := validDocuments()["sign"]

	_, err := validateRequest("sign", "spiffe://regalia/workload/x", "req-1", "018f0000000070008000000000000002", document)
	if err == nil {
		t.Fatal("a request whose body nonce and Idempotency-Key disagree was accepted")
	}
	if !strings.Contains(err.Error(), "invalid operation context") {
		t.Fatalf("error = %q, want the context refusal", err)
	}
}

// TestThePayloadMustDecodeAndFitItsOperationsBound.
func TestThePayloadMustDecodeAndFitItsOperationsBound(t *testing.T) {
	for name, mutate := range map[string]func(*requestDocument){
		"not base64":                 func(d *requestDocument) { d.Payload = "!!!!" },
		"base64 with padding errors": func(d *requestDocument) { d.Payload = "QUJD" + "=" },
		"an empty payload":           func(d *requestDocument) { d.Payload = "" },
		"a payload over 1MiB":        func(d *requestDocument) { d.Payload = b64((1 << 20) + 1) },
	} {
		t.Run(name, func(t *testing.T) {
			document := validDocuments()["sign"]
			mutate(&document)
			_, err := validateRequest("sign", "spiffe://regalia/workload/x", "req-1", validNonce, document)
			if err == nil {
				t.Fatalf("validateRequest accepted %s", name)
			}
			if !strings.Contains(err.Error(), "invalid operation payload") {
				t.Fatalf("%s: error = %q, want the payload refusal", name, err)
			}
		})
	}
}
