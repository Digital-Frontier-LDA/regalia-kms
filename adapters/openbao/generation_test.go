package openbaopoc

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

func configuredWrapper(t *testing.T, c map[string]string) *Wrapper {
	t.Helper()
	w := New()
	if _, err := w.SetConfig(context.Background(), wrappingConfig(c)); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestVersionedEnvelopePromotionAndRevocation(t *testing.T) {
	f := newKMSFixtureMode(t, true)
	ctx := context.Background()
	old := configuredWrapper(t, f.pki.config)
	oldID, _ := old.KeyId(ctx)
	aad := []byte("synthetic-root-key")
	plain := []byte("synthetic-versioned-payload")
	blob, err := old.Encrypt(ctx, plain, wrapping.WithAad(aad))
	if err != nil {
		t.Fatal(err)
	}
	if blob.KeyInfo.KeyId != "regalia-poc-v2:poc-seal-key:g1" {
		t.Fatal("generation absent from SDK key ID")
	}
	f.generations("retired", "active")
	// The registry chooses the new generation; a stale plugin must not mislabel it.
	if result, err := old.Encrypt(ctx, plain); err != errOperation || result != nil {
		t.Fatal("stale configuration accepted an unexpected server generation")
	}
	c := cloneConfig(f.pki.config)
	c["key_version"], c["historical_key_versions"] = "g2", "g1"
	current := configuredWrapper(t, c)
	currentID, _ := current.KeyId(ctx)
	if currentID == oldID {
		t.Fatal("promotion did not change SDK KeyId")
	}
	out, err := current.Decrypt(ctx, blob, wrapping.WithAad(aad), wrapping.WithKeyId(oldID))
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatal("retained generation did not decrypt after promotion", err)
	}
	clear(out)
	newBlob, err := current.Encrypt(ctx, plain, wrapping.WithAad(aad))
	if err != nil || newBlob.KeyInfo.KeyId != currentID {
		t.Fatal("new writes did not use promoted generation", err)
	}
	for _, part := range []string{"unknown-generation", "inner-generation", "relabeled-generation", "duplicate-inner-field", "frame-generation", "caller-aad", "requested-key", "raw-format"} {
		t.Run(part, func(t *testing.T) {
			bad := proto.Clone(blob).(*wrapping.BlobInfo)
			var frameData frame
			if json.Unmarshal(bad.Ciphertext, &frameData) != nil {
				t.Fatal("invalid fixture frame")
			}
			options := []wrapping.Option{wrapping.WithAad(aad)}
			backendFailures := f.audit.outcomes("release-secret", "backend-failed")
			switch part {
			case "unknown-generation":
				bad.KeyInfo.KeyId = "regalia-poc-v2:poc-seal-key:g404"
			case "inner-generation", "relabeled-generation":
				e, _ := envelope.Parse(frameData.WrappedKey)
				e.KEK.Version = "g2"
				frameData.WrappedKey, _ = e.Marshal()
				if part == "relabeled-generation" {
					bad.KeyInfo.KeyId, frameData.KeyID = currentID, currentID
				}
			case "frame-generation":
				frameData.KeyID = currentID
			case "duplicate-inner-field":
				frameData.WrappedKey = append([]byte(`{"version":2,`), frameData.WrappedKey[1:]...)
			case "caller-aad":
				options = []wrapping.Option{wrapping.WithAad([]byte("other-context"))}
			case "requested-key":
				options = append(options, wrapping.WithKeyId(currentID))
			case "raw-format":
				frameData.Version = 1
			}
			bad.Ciphertext, _ = json.Marshal(frameData)
			if out, err := current.Decrypt(ctx, bad, options...); err != errOperation || len(out) != 0 {
				t.Fatal("tampered generation/context released plaintext")
			}
			if part == "relabeled-generation" && f.audit.outcomes("release-secret", "backend-failed") <= backendFailures {
				t.Fatal("relabeling did not exercise the real generation's cryptographic boundary")
			}
		})
	}
	withoutHistory := cloneConfig(c)
	delete(withoutHistory, "historical_key_versions")
	before := f.audit.successful("release-secret")
	if out, err := configuredWrapper(t, withoutHistory).Decrypt(ctx, blob, wrapping.WithAad(aad)); err != errOperation || len(out) != 0 {
		t.Fatal("unlisted historical generation decrypted")
	}
	if f.audit.successful("release-secret") != before {
		t.Fatal("unlisted historical generation reached KMS release")
	}
	f.generations("revoked", "active")
	denials := f.audit.outcomes("release-secret", "denied-kek-revoked")
	if out, err := current.Decrypt(ctx, blob, wrapping.WithAad(aad)); err != errOperation || len(out) != 0 {
		t.Fatal("revoked generation decrypted")
	}
	if f.audit.outcomes("release-secret", "denied-kek-revoked") <= denials {
		t.Fatal("revocation did not reach the actual registry authorization boundary")
	}
	if out, err := current.Decrypt(ctx, newBlob, wrapping.WithAad(aad)); err != nil || !bytes.Equal(out, plain) {
		t.Fatal("revoking historical generation broke current data", err)
	}
}

func TestGenerationConfigurationIsExplicitAndBounded(t *testing.T) {
	pki := newFixturePKI(t)
	for _, tc := range []struct{ current, historical string }{
		{"", "g1"}, {"../g1", ""}, {"g 1", ""}, {strings.Repeat("a", 33), ""},
		{"g2", "g1,g1"}, {"g2", "g1,g2"}, {"g2", "g1,"}, {"g2", " g1"},
		{"g2", "g1/alias"}, {"g2", strings.Repeat("g1,", 17) + "g3"},
	} {
		c := cloneConfig(pki.config)
		if tc.current != "" {
			c["key_version"] = tc.current
		}
		if tc.historical != "" {
			c["historical_key_versions"] = tc.historical
		}
		if _, err := New().SetConfig(context.Background(), wrappingConfig(c)); err != errConfig {
			t.Fatal("invalid generation configuration accepted", tc)
		}
	}
}
