package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// THE SAME TABLE IS PINNED ON BOTH SIDES OF THE DIVERGENCE.
//
// "An https origin" is defined twice in this repository: here, for kms_url, and by
// audit.ValidateSinkURL in the kms module for the audit collector. They cannot share code — this is
// a separate module and that package is internal — and they disagreed on a trailing slash, so
// "https://kms.internal:8443/" configured the audit sink fine and refused to start this sidecar.
//
// TestSinkURLRuleMatchesTheAdapter in internal/audit pins the identical table on the other side. Two
// implementations of one rule cannot be deduplicated here, but they can both be held to the same
// cases, which is what turns a silent divergence into a failing test.
func TestKMSURLAcceptsExactlyTheOriginForms(t *testing.T) {
	accepted := []string{
		"https://kms.service.internal:8443",
		"https://kms.service.internal:8443/",
		"https://kms.internal",
	}
	rejected := []string{
		"http://kms.internal",                // not TLS
		"https://kms.internal/v1/operations", // a path: the client appends its own
		"https://user:pw@kms.internal",       // credentials in the URL
		"https://kms.internal?a=b",           // query
		"https://kms.internal#f",             // fragment
		"",                                   // empty
		// The other half of #237's operand sweep on the audit sink: the host operand had no row
		// on either side of this pair. It parses cleanly with an empty host, so every other
		// operand accepts it, and the client would then address "https:///v1/..." — a URL with
		// no host to reach.
		"https://",
	}
	for _, value := range accepted {
		if err := checkKMSURL(t, value); err != nil {
			t.Errorf("%q was rejected and the audit sink accepts it: the two definitions of an origin disagree again (%v)", value, err)
		}
	}
	for _, value := range rejected {
		if err := checkKMSURL(t, value); err == nil {
			t.Errorf("%q was accepted as an HTTPS origin", value)
		}
	}
}

// checkKMSURL runs one candidate through loadConfig — the function the binary actually calls on a
// file an operator wrote — rather than reaching past it to validate(). The two are equivalent for
// this rule today, and that is exactly why it is worth going the long way: if anyone ever
// normalises the URL in the loader before validation, a test that called validate() directly would
// keep passing while the binary's real answer changed. Pinning a rule to something adjacent to the
// code under test is the failure this whole pull request is about.
func checkKMSURL(t *testing.T, kmsURL string) error {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"ca.pem", "cert.pem", "key.pem"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	document, err := json.Marshal(config{
		SocketPath: filepath.Join(dir, "s.sock"), KMSURL: kmsURL, ServerName: "kms.service.internal",
		CAPath: filepath.Join(dir, "ca.pem"), CertificatePath: filepath.Join(dir, "cert.pem"),
		PrivateKeyPath: filepath.Join(dir, "key.pem"), Timeout: "15s",
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sidecar.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = loadConfig(path)
	return err
}
