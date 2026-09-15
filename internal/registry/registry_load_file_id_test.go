package registry

import (
	"bytes"
	"strings"
	"testing"
)

// COVERAGE GAPS IN THE LOADER'S STATIC INPUT CHECKS.
//
// The Load() entry path has five structural checks that no existing test exercises
// directly: the site-identifier guard (L387), the 2 MiB cap (L394), the JSON
// decode error (L400), the multi-document guard (L404), and the header
// incompleteness guard (L407). Each was a mutation survivor: removing it
// from the source left every other test in the package green.

// SITE NAMES REACH THE LOADER AS A PROCESS ARGUMENT.
//
// A typo in a deployment's -registry-site flag is indistinguishable from a
// typo in any other config value at the call site: only the loader can
// reject it before anything has been built around a string that doesn't
// match the identifier pattern. Without the guard, the loader accepts it and
// the comparison "binding.Site != site" later silently matches no binding.
func TestLoadRefusesANonIdentifierSiteName(t *testing.T) {
	body := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign",
		binding("sitea", "nitrokey-pkcs11", "hsm-1", "slot-1", "active")+","+
			binding("siteb", "nitrokey-pkcs11", "hsm-2", "slot-2", "standby")))

	for _, site := range []string{"SiteA", "lis bon", "sitea!", "ab", "", "-sitea", "sitea_"} {
		t.Run(site, func(t *testing.T) {
			if _, err := Load(strings.NewReader(body), site, &healthMap{states: map[string]bool{}}); err == nil {
				t.Fatalf("Load() accepted a non-identifier site %q", site)
			} else if !strings.Contains(err.Error(), "lowercase identifier") {
				t.Fatalf("err = %v, want it to mention the identifier refusal", err)
			}
		})
	}
}

// THE 2 MiB CAP IS A MEMORY BOUND ON A FILE THAT CAN GROW WITHOUT REVIEW.
//
// A manifest is a config file, not data: it is reviewed at commit time, but the
// daemon reads whatever registry_path points at. Without the cap, a runaway
// growth or a stray copy of a different document would be parsed in full and
// held in memory before any structural check fires.
//
// The oversize portion is trailing JSON whitespace, not noise: a payload of
// trailing `x`s would itself be a malformed second JSON document, and the
// multi-JSON guard would mask the size cap. Trailing whitespace keeps the
// document valid and isolates the size cap from the multi-document check.
func TestLoadRefusesAManifestLargerThanTwoMiB(t *testing.T) {
	pair := binding("sitea", "nitrokey-pkcs11", "hsm-1", "slot-1", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "hsm-2", "slot-2", "standby")
	base := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign", pair))
	trailing := strings.Repeat(" ", maxManifestBytes+1-len(base)+1)
	body := []byte(base + trailing)
	if _, err := Load(bytes.NewReader(body), "sitea", &healthMap{}); err == nil {
		t.Fatal("Load accepted a manifest over 2 MiB")
	} else if !strings.Contains(err.Error(), "exceeds 2 MiB") {
		t.Fatalf("err = %v, want it to mention the size cap", err)
	}
}

// A DECODE FAILURE MUST BE A DECODE FAILURE.
//
// Without L400's guard, the loader keeps the zero manifestDocument and every
// later check fires against it — header incompleteness, then multi-JSON, in
// that order. The first error an operator sees would name a different defect.
//
// The assertion pins the SPECIFIC error message — "decode registry" is the
// unique wrapper at L400 (other guards say "exceeds 2 MiB", "exactly one
// JSON document", "header is incomplete or unsupported", "lowercase
// identifier"). Without this discrimination, the test passes whether L400
// is in place or not: the downstream guards still refuse a zero document.
func TestLoadReportsMalformedJSONAsMalformed(t *testing.T) {
	_, err := Load(strings.NewReader(`{`), "sitea", &healthMap{})
	if err == nil {
		t.Fatal("Load accepted `{`")
	}
	if !strings.Contains(err.Error(), "decode registry") {
		t.Fatalf("err = %q, want it to mention the decode-registry refusal at L400; "+
			"without that guard the loader falls through to header-incomplete and the operator "+
			"sees the wrong defect", err)
	}
}

// A SECOND JSON VALUE IN THE FILE IS A DIFFERENT MANIFEST.
//
// Without L404's guard, json.Decoder.Decode returns io.EOF after the first
// document, which is the expected case — but the trailing check is the only
// one that catches a second value, and the file format is the daemon's
// contract, not json's.
func TestLoadRefusesMoreThanOneJSONDocument(t *testing.T) {
	body := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign",
		binding("sitea", "nitrokey-pkcs11", "hsm-1", "slot-1", "active"))) +
		manifest(object("second", "other-purpose", "secp256k1", "sign",
			binding("sitea", "nitrokey-pkcs11", "hsm-2", "slot-2", "active")))
	if _, err := Load(strings.NewReader(body), "sitea", &healthMap{}); err == nil {
		t.Fatal("Load accepted two JSON documents")
	} else if !strings.Contains(err.Error(), "exactly one JSON document") {
		t.Fatalf("err = %v, want it to mention the multi-document refusal", err)
	}
}

// HEADER FIELDS THE LOADER ASSUMES PRESENT.
//
// SchemaVersion, ManifestID, GeneratedAt, and len(Objects)>0 are read by
// every downstream field's validation. A zero on any of them means the
// loader has nothing to validate and the daemon would have nothing to route.
func TestLoadRefusesAnIncompleteHeader(t *testing.T) {
	cases := map[string]string{
		"no schema_version": `{"manifest_id":"x","generated_at":"2026-09-04T00:00:00Z","objects":[%s]}`,
		"no manifest_id":    `{"schema_version":1,"generated_at":"2026-09-04T00:00:00Z","objects":[%s]}`,
		"no generated_at":   `{"schema_version":1,"manifest_id":"x","objects":[%s]}`,
		"empty objects":     `{"schema_version":1,"manifest_id":"x","generated_at":"2026-09-04T00:00:00Z","objects":[]}`,
	}
	body := binding("sitea", "nitrokey-pkcs11", "hsm-1", "slot-1", "active") + "," +
		binding("siteb", "nitrokey-pkcs11", "hsm-2", "slot-2", "standby")
	obj := object("wallet-key", "cosmos-transaction", "secp256k1", "sign", body)
	for name, tmpl := range cases {
		t.Run(name, func(t *testing.T) {
			body := `{"schema_version":1,"manifest_id":"x","generated_at":"2026-09-04T00:00:00Z","objects":[` + obj + `]}`
			_ = body
			// Rebuild the manifest from the template with the obj substituted.
			raw := strings.Replace(tmpl, "%s", obj, 1)
			full := raw
			_ = full
			if _, err := Load(strings.NewReader(raw), "sitea", &healthMap{}); err == nil {
				t.Fatalf("Load accepted %s", name)
			} else if !strings.Contains(err.Error(), "header is incomplete or unsupported") {
				t.Fatalf("err = %v, want header-incomplete refusal", err)
			}
		})
	}
}
