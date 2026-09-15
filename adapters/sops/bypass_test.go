package sopsadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops/sopsrpc"
)

// This file pins the fail-closed posture of the SOPS adapter. Each test asserts
// that the adapter returns the same closed-circuit response ("KMS operation
// failed" or a pre-KMS reject) under one bypass condition, and never falls
// back to a local key, an env credential, or any other path. The discipline is
// the same as the revocation list work: a developer who removes a check must
// see the corresponding test fail with a clear DEFECT message before the
// change can land.
//
// SCOPE — what these tests do and do not prove.
//
// Tests 1–3 mock at the KMSClient interface (Wrap/Unwrap), so they prove the
// adapter does not *fabricate* a result when the client says no. They cannot
// see a bypass that lives below that interface — a fallback inside the real
// HTTPClient, or a path that never calls Wrap at all. Test 4 is the one that
// covers that surface, because it points a real client at a dead server and
// is doing more work than the other three.
//
// This file does NOT cover the bypass that matters most in a real SOPS
// deployment: SOPS never calls the adapter at all, because a `.sops.yaml`
// lists an age or PGP recipient alongside the KMS carrier and SOPS picks the
// one it can reach locally. No adapter test can catch that, because the
// adapter is not on the path. That bypass is covered by
// `kms/tools/sops_policy.py`, which requires exactly one carrier and refuses
// legacy recipient blocks. The two halves together are the centralization
// claim; separately, each looks stronger than it is.

// bypassMockKMS records calls and returns whatever the test wired. It is shared
// across all four bypass scenarios; the assertions differ, not the helper.
type bypassMockKMS struct {
	wrapResult   []byte
	unwrapResult []byte
	err          error
	wrapCalls    int
	unwrapCalls  int
}

func (client *bypassMockKMS) Wrap(_ context.Context, _ Request) ([]byte, error) {
	client.wrapCalls++
	return append([]byte(nil), client.wrapResult...), client.err
}

func (client *bypassMockKMS) Unwrap(_ context.Context, _ Request) ([]byte, error) {
	client.unwrapCalls++
	return append([]byte(nil), client.unwrapResult...), client.err
}

// TestEncryptFailsClosedWhenKMSUnreachable pins the wrap-side bypass posture
// for the network-down case. When the configured KMS client errors with a
// connection-style failure, the adapter MUST translate the error to "KMS
// operation failed" and return a nil response — never a default ciphertext,
// never a locally-derived key.
//
// Delete-fix scenario: in adapter.go Encrypt, replace the
// `errors.New("KMS operation failed")` line with `return &sopsrpc.EncryptResponse{Ciphertext: nil}, nil`
// or with a fallback that constructs a deterministic ciphertext from the input.
// The test catches both: a non-nil response is fail-open; a nil response with
// no error is also fail-open (the caller will write an empty ciphertext).
func TestEncryptFailsClosedWhenKMSUnreachable(t *testing.T) {
	client := &bypassMockKMS{err: errors.New("dial tcp 10.0.0.1:443: connect: connection refused")}
	server := New(client)
	response, err := server.Encrypt(context.Background(), &sopsrpc.EncryptRequest{Key: sopsKey(), Plaintext: []byte("01234567890123456789012345678901")})
	if err == nil {
		t.Fatalf("DEFECT: Encrypt() returned no error when KMS was unreachable — adapter fell back to a local ciphertext: response=%#v", response)
	}
	if response != nil {
		t.Fatalf("DEFECT: Encrypt() returned a non-nil response on KMS unreachable: %#v", response)
	}
	if err.Error() != "KMS operation failed" {
		t.Fatalf("Encrypt() error = %q, want %q — a different message suggests a fallback path that distinguishes unreachable from denied", err, "KMS operation failed")
	}
	if client.wrapCalls != 1 {
		t.Fatalf("KMS Wrap() call count = %d, want 1 — adapter must attempt the KMS exactly once and not retry silently", client.wrapCalls)
	}
}

// TestDecryptFailsClosedWhenKMSDenies pins the unwrap-side bypass posture for
// the denial case. A non-network error from KMS (RBAC denial, policy reject,
// backend unavailable) must produce the same nil-response / "KMS operation
// failed" outcome as the network-down case. The adapter cannot tell from a
// denial that the data key is unreachable, and must not infer one.
//
// Delete-fix scenario: in adapter.go Decrypt, after the client.Unwrap call,
// branch on err != nil and return success with an empty plaintext. The test
// catches because err would be nil and plaintext would be empty.
func TestDecryptFailsClosedWhenKMSDenies(t *testing.T) {
	client := &bypassMockKMS{err: errors.New("rbac denied: workload/release not authorized for production-sops")}
	server := New(client)
	response, err := server.Decrypt(context.Background(), &sopsrpc.DecryptRequest{Key: sopsKey(), Ciphertext: []byte("wrapped-envelope")})
	if err == nil {
		t.Fatalf("DEFECT: Decrypt() returned no error when KMS denied — adapter accepted a denied unwrap: response=%#v", response)
	}
	if response != nil {
		t.Fatalf("DEFECT: Decrypt() returned a non-nil response on KMS denial: %#v", response)
	}
	if err.Error() != "KMS operation failed" {
		t.Fatalf("Decrypt() error = %q, want %q — a different message suggests a denial-specific fallback path", err, "KMS operation failed")
	}
	if client.unwrapCalls != 1 {
		t.Fatalf("KMS Unwrap() call count = %d, want 1", client.unwrapCalls)
	}
}

// TestRejectsLegacyAWSCarrierBeforeKMS pins the legacy-recipient bypass
// posture. A SOPS request that sets the AWS `role` or `aws_profile` fields on
// the KMS carrier is asking the adapter to fall back to AWS IAM credentials —
// the very bypass centralization forbids. The adapter MUST reject such
// requests BEFORE the KMS client is consulted, so a misconfigured environment
// cannot use role/profile as a fallback when the KMS is down or denying.
//
// Delete-fix scenario: remove the Role/AwsProfile check in translate().
// The adapter passes the legacy carrier through to the KMS client; if KMS
// accepts (it should not — KMS knows it is not AWS), the test fails because
// (a) the adapter returns no error, and (b) the KMS client was called once.
func TestRejectsLegacyAWSCarrierBeforeKMS(t *testing.T) {
	for _, name := range []string{"role", "aws_profile"} {
		t.Run(name, func(t *testing.T) {
			client := &bypassMockKMS{wrapResult: []byte("wrapped-if-bypass-existed")}
			server := New(client)
			key := sopsKey()
			switch name {
			case "role":
				key.GetKmsKey().Role = "arn:aws:iam::000000000000:role/RegaliaBypass"
			case "aws_profile":
				key.GetKmsKey().AwsProfile = "default"
			}
			response, err := server.Encrypt(context.Background(), &sopsrpc.EncryptRequest{Key: key, Plaintext: []byte("01234567890123456789012345678901")})
			if err == nil {
				t.Fatalf("DEFECT: Encrypt() with legacy %s field returned no error — adapter accepted an AWS-credential fallback: response=%#v", name, response)
			}
			if response != nil {
				t.Fatalf("DEFECT: Encrypt() with legacy %s field returned a non-nil response: %#v", name, response)
			}
			// Encrypt/Decrypt wrap translate()'s error into a generic
			// "invalid SOPS key request" so a gRPC caller cannot probe for
			// which field was rejected (no oracle on the validator). The
			// strong pin here is wrapCalls == 0 — the bypass only works if
			// the request reaches KMS at all — and the error-message check
			// pins the oracle-prevention property: if the adapter ever
			// started surfacing the inner translate() error, this test would
			// catch it on the exact string match.
			if err.Error() != "invalid SOPS key request" {
				t.Fatalf("Encrypt() error = %q, want %q — inner translate() error leaked through, oracle on field-level validator", err, "invalid SOPS key request")
			}
			if client.wrapCalls != 0 {
				t.Fatalf("DEFECT: KMS was called %d time(s) for a legacy-recipient request — translate() must reject before the client is consulted", client.wrapCalls)
			}
		})
	}
}

// TestEnvCredentialsDoNotChangeFailClosedPosture pins the env-credential bypass
// posture. The adapter must never consult the process environment for
// credentials — AWS_ACCESS_KEY_ID, AWS_PROFILE, SOPS_AGE_KEY, SOPS_KMS_ARN,
// or any other variable. The test sets every look-real env variable a
// bypass might pick up, then points the adapter at an unreachable KMS, and
// asserts the adapter still returns "KMS operation failed" with a nil
// response. A developer who adds an env-driven fallback path will see this
// test fail: the bypass would either return a non-nil response (decrypt
// succeeded via env) or surface an env-specific error message.
//
// Delete-fix scenario: in adapter.go Encrypt, before the Wrap call, add
//
//	if env := os.Getenv("SOPS_AGE_KEY"); env != "" {
//	    plaintext, _ := ageDecrypt(env, request.Data)
//	    return &sopsrpc.EncryptResponse{Ciphertext: plaintext}, nil
//	}
//
// With SOPS_AGE_KEY set in this test, the bypass would fire, Encrypt would
// return success, and the test fails because err is nil.
func TestEnvCredentialsDoNotChangeFailClosedPosture(t *testing.T) {
	// Every env variable a bypass might plausibly consult. The values look real
	// so a substring or prefix check on the variable name would match.
	envVars := map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_PROFILE":           "regalia-bypass",
		"AWS_DEFAULT_REGION":    "us-east-1",
		"AWS_ROLE_ARN":          "arn:aws:iam::000000000000:role/RegaliaBypass",
		"SOPS_AGE_KEY":          "AGE-SECRET-KEY-1QFNGQEXAMPLERECEIVER",
		"SOPS_KMS_ARN":          "arn:aws:kms:us-east-1:000000000000:key/bypass",
		"SOPS_AWS_PROFILE":      "bypass-profile",
		"SOPS_FALLBACK_KEY":     "should-never-be-consulted",
	}
	for name, value := range envVars {
		t.Setenv(name, value)
	}

	// An httptest server that has been closed is unreachable. Pointing the
	// real HTTP client at it simulates KMS network-down without depending on
	// the SOPS package — if any code path bypasses KMS, it must do so before
	// this URL is consulted.
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	server.Close()

	client := NewHTTPClient(server.URL, server.Client(), func() time.Time { return time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC) })
	sopsServer := New(client)
	response, err := sopsServer.Encrypt(context.Background(), &sopsrpc.EncryptRequest{Key: sopsKey(), Plaintext: []byte("01234567890123456789012345678901")})
	if err == nil {
		t.Fatalf("DEFECT: Encrypt() succeeded with KMS unreachable and env credentials set — an env-driven bypass produced a ciphertext: response=%#v", response)
	}
	if response != nil {
		t.Fatalf("DEFECT: Encrypt() returned a non-nil response with env credentials set and KMS unreachable: %#v", response)
	}
	if err.Error() != "KMS operation failed" {
		t.Fatalf("Encrypt() error = %q, want %q — a different message proves an env-specific fallback path exists", err, "KMS operation failed")
	}

	// Reaffirm that the env variables are still set: nothing in the adapter
	// cleared them, and nothing in the failure path relied on their absence.
	// (If a developer added a t.Unsetenv or os.Unsetenv inside the adapter,
	// this assertion would catch the side effect — env vars are an operator
	// contract and must not be mutated by a request handler.)
	for name, want := range envVars {
		if got := os.Getenv(name); got != want {
			t.Fatalf("DEFECT: adapter mutated env var %q (got %q, want %q) — request handlers must not touch process environment", name, got, want)
		}
	}
}
