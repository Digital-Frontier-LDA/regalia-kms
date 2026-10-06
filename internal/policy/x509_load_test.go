package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func x509JSONPolicy(t *testing.T, fixture x509ReservationFixture, mutate func(map[string]any)) []byte {
	t.Helper()
	profile := map[string]any{"id": "internal-ca-profile-v1", "issuer_der": fixture.issuerDER,
		"dns_suffixes": []string{"svc.test.invalid"}, "max_leaf_validity_seconds": int64(300),
		"max_crl_validity_seconds": int64(600), "leaf_per_day": uint64(1), "crl_per_day": uint64(1)}
	if mutate != nil {
		mutate(profile)
	}
	entry := map[string]any{"id": "internal-ca-policy-v1", "object_id": "synthetic-internal-ca",
		"purpose": "internal-pki", "environment": "development", "operation": "sign", "algorithm": "p256",
		"content_types": []string{"application/vnd.regalia.x509-tbs"}, "max_payload_bytes": 32 << 10,
		"max_future_seconds": 60, "x509": profile}
	encoded, err := json.Marshal(map[string]any{"schema_version": 1, "policies": []any{entry}})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestX509JSONProfileLoadsAndCompiles(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	input := x509JSONPolicy(t, fixture, nil)
	policies, digest, err := Load(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 || !reflect.DeepEqual(policies[0], fixture.policy()) {
		t.Fatalf("loaded X.509 policy = %#v, want %#v", policies, fixture.policy())
	}
	hash := sha256.Sum256(input)
	if digest != "sha256:"+hex.EncodeToString(hash[:]) {
		t.Fatalf("policy digest does not bind the exact profile document: %q", digest)
	}
	engine, err := New(policies, &reservationState{}, func() time.Time { return fixture.start })
	if err != nil || engine == nil {
		t.Fatalf("valid loaded X.509 policy did not compile: %v", err)
	}
}

func TestX509JSONLifetimeBoundsAreCheckedBeforeDurationConversion(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	for _, field := range []string{"max_leaf_validity_seconds", "max_crl_validity_seconds"} {
		for _, value := range []int64{-1, 0, 86401, math.MaxInt64} {
			input := x509JSONPolicy(t, fixture, func(profile map[string]any) { profile[field] = value })
			if _, _, err := Load(bytes.NewReader(input)); err == nil {
				t.Errorf("Load accepted %s=%d, permitting unsafe or overflowing duration conversion", field, value)
			}
		}
		for _, value := range []int64{1, 86400} {
			input := x509JSONPolicy(t, fixture, func(profile map[string]any) { profile[field] = value })
			policies, _, err := Load(bytes.NewReader(input))
			if err != nil {
				t.Errorf("Load refused bounded %s=%d: %v", field, value, err)
				continue
			}
			if _, err := New(policies, &reservationState{}, func() time.Time { return fixture.start }); err != nil {
				t.Errorf("compiler refused bounded %s=%d: %v", field, value, err)
			}
		}
	}
}

func TestX509JSONProfileRejectsUnknownFieldsAndInvalidTypes(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unknown nested field", func(p map[string]any) { p["allow_any_name"] = true }},
		{"invalid DER base64", func(p map[string]any) { p["issuer_der"] = "%%%" }},
		{"string lifetime", func(p map[string]any) { p["max_leaf_validity_seconds"] = "300" }},
		{"fractional lifetime", func(p map[string]any) { p["max_crl_validity_seconds"] = 600.5 }},
		{"negative quota", func(p map[string]any) { p["leaf_per_day"] = -1 }},
		{"missing leaf lifetime", func(p map[string]any) { delete(p, "max_leaf_validity_seconds") }},
		{"missing CRL lifetime", func(p map[string]any) { delete(p, "max_crl_validity_seconds") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := x509JSONPolicy(t, fixture, test.mutate)
			if _, _, err := Load(bytes.NewReader(input)); err == nil {
				t.Fatalf("Load accepted invalid X.509 profile: %s", input)
			}
		})
	}
	if _, _, err := Load(bytes.NewReader(x509JSONPolicy(t, fixture, nil))); err != nil {
		t.Fatalf("strict-profile controls also reject valid profile: %v", err)
	}
}

func TestX509CompilerRejectsUnsafePolicyBindings(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*Policy)
	}{
		{"production environment", func(p *Policy) { p.Environment = "production" }},
		{"alternate operation", func(p *Policy) { p.Operation = "wrap" }},
		{"alternate algorithm", func(p *Policy) { p.Algorithm = "rsa2048" }},
		{"opaque content fallback", func(p *Policy) { p.ContentTypes = append(p.ContentTypes, "application/octet-stream") }},
		{"wrong exclusive content", func(p *Policy) { p.ContentTypes = []string{"application/octet-stream"} }},
		{"oversized payload allowance", func(p *Policy) { p.MaxPayloadBytes = (32 << 10) + 1 }},
		{"mixed Cosmos domain", func(p *Policy) { p.Cosmos = &CosmosPolicy{} }},
		{"missing server profile", func(p *Policy) { p.X509 = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := fixture.policy()
			test.mutate(&profile)
			if _, err := New([]Policy{profile}, &reservationState{}, func() time.Time { return fixture.start }); err == nil {
				t.Fatalf("compiler accepted unsafe X.509 binding: %#v", profile)
			}
		})
	}
	if _, err := New([]Policy{fixture.policy()}, &reservationState{}, func() time.Time { return fixture.start }); err != nil {
		t.Fatalf("compiler guards also reject valid policy: %v", err)
	}
}

func TestX509CompilerRejectsOtherOperationBypassRegardlessOfPolicyOrder(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	profile := fixture.policy()
	bypass := profile
	bypass.ID, bypass.Operation, bypass.X509 = "generic-ca-bypass", "unwrap", nil
	bypass.ContentTypes = []string{"application/octet-stream"}
	for _, policies := range [][]Policy{{profile, bypass}, {bypass, profile}} {
		if _, err := New(policies, &reservationState{}, func() time.Time { return fixture.start }); err == nil {
			t.Fatal("another operation policy bypasses the same object's issuing profile")
		}
	}
	// A generic operation on a different object remains governed by its own
	// existing policy; the profile guard must be scoped to the CA object.
	bypass.ObjectID = "separate-data-key"
	if _, err := New([]Policy{profile, bypass}, &reservationState{}, func() time.Time { return fixture.start }); err != nil {
		t.Fatalf("CA profile guard blocked an unrelated object: %v", err)
	}
}

func TestX509JSONNullProfileCannotEnableUninspectedSigning(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	// Use a typed document to express the optional null without depending on
	// where its JSON object ends.
	var document map[string]any
	if err := json.Unmarshal(x509JSONPolicy(t, fixture, nil), &document); err != nil {
		t.Fatal(err)
	}
	entry := document["policies"].([]any)[0].(map[string]any)
	entry["x509"] = nil
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	policies, _, err := Load(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(policies, &reservationState{}, func() time.Time { return fixture.start }); err == nil {
		t.Fatal("null X.509 profile enabled complete-TBS signing without inspection policy")
	}
}
