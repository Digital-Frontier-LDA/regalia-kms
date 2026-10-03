package openbaopoc

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestNativeConfigurationIsExplicit(t *testing.T) {
	c := nativeFixtureConfig(newFixturePKI(t).config)
	for key := range c {
		missing := cloneConfig(c)
		delete(missing, key)
		if _, err := NewNative().SetConfig(context.Background(), wrappingConfig(missing)); err != errConfig {
			t.Fatal("missing required setting accepted", key)
		}
	}
	for _, change := range []struct{ key, value string }{
		{"purpose", "openbao-seal"}, {"key_version", "g1"}, {"historical_key_versions", "g1"},
		{"environment", "staging"}, {"environment", "production"}, {"timeout", "0s"}, {"timeout", "61s"},
		{"address", "http://kms.example"}, {"address", "https://kms.example/path"},
		{"address", "https://user:password@kms.example"}, {"kms_purpose", "bad purpose"},
	} {
		invalid := cloneConfig(c)
		invalid[change.key] = change.value
		if _, err := NewNative().SetConfig(context.Background(), wrappingConfig(invalid)); err != errConfig {
			t.Fatal("invalid native setting accepted", change.key)
		}
	}
	// OpenBao consumes reserved purpose; a map that only has it must fail closed.
	reserved := cloneConfig(c)
	delete(reserved, "kms_purpose")
	reserved["purpose"] = "openbao-seal"
	if _, err := NewNative().SetConfig(context.Background(), wrappingConfig(reserved)); err != errConfig {
		t.Fatal("reserved purpose substituted for kms_purpose")
	}
	w := configuredNative(t, c)
	if _, err := w.SetConfig(context.Background(), wrappingConfig(c)); err != errConfig {
		t.Fatal("configuration changed after initialization")
	}
	t.Setenv("KMS_URL", "https://untrusted.example")
	t.Setenv("REGALIA_KMS_PURPOSE", "other-purpose")
	if got := configuredNative(t, c); got.client.base != c["address"] || got.binding.Purpose != c["kms_purpose"] {
		t.Fatal("environment overrode explicit configuration")
	}
}

func TestNativeCallerDeadlineBoundsRequest(t *testing.T) {
	w := configuredNative(t, nativeFixtureConfig(newFixturePKI(t).config))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	w.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
		var doc versionedRequest
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		expires, err := time.Parse(time.RFC3339Nano, doc.Context.ExpiresAt)
		if err != nil || expires.After(deadline) {
			t.Fatal("KMS expiry exceeded caller deadline")
		}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	started := time.Now()
	if blob, err := w.Encrypt(ctx, []byte{1}); blob != nil || err != errOperation {
		t.Fatal("deadline failure returned a blob")
	}
	if time.Since(started) > time.Second {
		t.Fatal("deadline did not bound the operation")
	}
	if id, _ := w.KeyId(context.Background()); id != "" {
		t.Fatal("failed seal populated KeyId")
	}
}
