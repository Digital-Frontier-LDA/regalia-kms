package api

import (
	"encoding/base64"
	"net/http"
	"testing"
)

// A SEAL DATA KEY THAT DOES NOT DECODE IS NOT A THIRTY-TWO-BYTE KEY THAT HAPPENS TO HAVE EXTRA.
//
// This is the `err != nil` half of the seal data-key guard in validateRequest:
//
//	if request.SealDataKey, err = base64...DecodeString(document.SealDataKey); err != nil || len(request.SealDataKey) != 32 {
//
// #237 recorded ten survivors for internal/api against a tree that no longer exists. Re-derived on
// current main the package has two, and this is the one nothing had examined.
//
// THE GUARD WAS COPIED AND THE TEST WAS NOT, which is the shape worth noticing. The seal NONCE guard
// one line above is the same construction -- decode, then check the length -- and both of its
// operands have detectors: TestSealEnvelopeRefusesANonceThatIsNotStrictBase64 for the error half and
// TestSealEnvelopeRefusesAnAbsentOrWrongLengthNonce for the length half. The data-key guard
// inherited the code and not the coverage. Measured: neutralising :321's length operand fails
// TestSealEnvelopeValidatesAndDispatches, so THAT half was covered; neutralising its error operand
// failed nothing at all until this file.
//
// WHY THE LENGTH OPERAND DOES NOT COVER IT. base64.DecodeString returns the bytes decoded BEFORE the
// error, so a canonical 44-character key followed by trailing garbage decodes to exactly 32 bytes
// AND returns an error. `len(...) != 32` is therefore false and only the error operand can refuse
// it. Measured with the operand neutralised, against a pristine 400/calls=0:
//
//	canonical + "!!!!"   status=200 calls=1 dataKeyLen=32
//	canonical + " "      status=200 calls=1 dataKeyLen=32
//
// NOTHING DOWNSTREAM CATCHES IT, which is what makes the difference observable here real rather than
// a duplicate of a deeper check. The coordinator is handed `request.SealDataKey` — the 32 decoded
// bytes — and never sees the wire string, so the malformation is erased by the decode. The document
// the API declared invalid is dispatched, and the audit record is written for an operation that
// should not have been admitted.
func TestSealEnvelopeRefusesADataKeyThatDoesNotDecode(t *testing.T) {
	cases := []struct {
		name       string
		dataKey    string
		wantStatus int
	}{
		// ANCHOR. Without it every refusal below is compatible with "seal-envelope is broken".
		{"a canonical thirty-two-byte key", b64(32), http.StatusOK},

		// GATES. Each decodes to exactly 32 bytes and returns an error, so the length operand
		// admits them and only the error operand can refuse them.
		{"a canonical key with trailing garbage", b64(32) + "!!!!", http.StatusBadRequest},
		{"a canonical key with a trailing space", b64(32) + " ", http.StatusBadRequest},

		// DOCUMENTATION, not a gate, and the row worth keeping precisely because it looks like one.
		// A raw newline inside a JSON string is invalid JSON, so decodeRequest refuses this body
		// before validateRequest runs — it is 400 whether the error operand is live or dead.
		// Anyone reaching for "\n" as the malformed-base64 fixture would conclude the guard works
		// while never having reached it.
		{"a canonical key with a trailing newline", b64(32) + "\n", http.StatusBadRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			coordinator := signingCoordinator()
			body := `{"object_id":"production-sops",` +
				`"context":{"environment":"production","purpose":"sops-data-key",` +
				`"expires_at":"2099-01-01T00:00:00Z","nonce":"018f0000000070008000000000000001"},` +
				`"format":"regalia-envelope-v2",` +
				`"ciphertext_base64":"` + base64.StdEncoding.EncodeToString([]byte(sealCiphertextPlain)) + `",` +
				`"data_key_base64":"` + testCase.dataKey + `"` + nonceMemberFor(canonicalNonce) + `}`
			response := post(t, NewHandler(coordinator), "/v1/operations/seal-envelope", body, nil)

			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if testCase.wantStatus == http.StatusOK {
				if coordinator.calls != 1 || len(coordinator.request.SealDataKey) != 32 {
					t.Fatalf("the anchor did not dispatch a 32-byte key: calls=%d len=%d",
						coordinator.calls, len(coordinator.request.SealDataKey))
				}
				return
			}
			// A REFUSAL THAT STILL DISPATCHED WOULD BE THE DEFECT. The status alone cannot
			// distinguish "refused" from "dispatched, then something later returned 400".
			if coordinator.calls != 0 {
				t.Fatalf("a refused document still reached the coordinator %d time(s) with a "+
					"%d-byte data key: the operation was admitted and audited", coordinator.calls,
					len(coordinator.request.SealDataKey))
			}
		})
	}
}
